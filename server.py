#!/usr/bin/env python3
"""
Character Card Index Server
Monitors folders for character cards, indexes metadata, serves search API.
Auto-deletes prohibited content and detects duplicates.

Configuration via environment variables:
  CARD_DIRS           - Colon-separated list of directories to index
  CARD_HOST           - Host to bind to (default: 0.0.0.0)
  CARD_PORT           - Port to bind to (default: 8787)
  CARD_AUTO_DELETE    - Auto-delete prohibited content (default: true)
  CARD_DETECT_DUPES   - Detect duplicates (default: true)

Example:
  export CARD_DIRS="/data/cards/chub:/data/cards/booru"
  export CARD_PORT=8787
  python server.py
"""

import os
import sys
import re
import json
import base64
import struct
import hashlib
import asyncio
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from dataclasses import dataclass, asdict, field
from io import BytesIO

try:
    from PIL import Image
    import imagehash
    IMAGE_HASH_AVAILABLE = True
except ImportError:
    IMAGE_HASH_AVAILABLE = False
    logging.warning("imagehash/Pillow not installed - image duplicate detection disabled")
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent, FileMovedEvent

from fastapi import FastAPI, Query, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import uvicorn
import shutil

# Configuration from environment
CARD_DIRS = os.environ.get("CARD_DIRS", "/data/CharacterCards").split(":")
HOST = os.environ.get("CARD_HOST", "0.0.0.0")
PORT = int(os.environ.get("CARD_PORT", "8787"))
RECURSIVE = os.environ.get("CARD_RECURSIVE", "true").lower() == "true"
AUTO_DELETE_PROHIBITED = os.environ.get("CARD_AUTO_DELETE", "true").lower() == "true"
DETECT_DUPLICATES = os.environ.get("CARD_DETECT_DUPES", "true").lower() == "true"
NEXTCLOUD_USER = os.environ.get("NEXTCLOUD_USER", "")  # Nextcloud user to scan (optional)
INDEX_FILE = os.environ.get("CARD_INDEX_FILE", "/var/lib/card-index/index.json")  # Persistent index

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Prohibited content detection (blocked regardless of NSFW status)
BLOCKED_TAGS_EXACT = {
    "child", "children", "underage", "minor", "minors",
    "kid", "kids", "toddler", "infant", "preteen", "prepubescent",
    "young child", "little girl", "little boy", "cub", "cubs",
    "pedophilia", "pedo", "cp", "csam", "jailbait", "incest"
}
BLOCKED_PATTERNS = [re.compile(r'\bloli'), re.compile(r'\bshota'), re.compile(r'\brape')]

# Additional patterns for description scanning (word boundaries to reduce false positives)
BLOCKED_DESCRIPTION_PATTERNS = [
    re.compile(r'\b(underage|under-age|under age)\b', re.IGNORECASE),
    re.compile(r'\b(child|children|kid|kids)\b.*\b(sex|rape|nsfw|erotic|lewd)\b', re.IGNORECASE),
    re.compile(r'\b(sex|rape|nsfw|erotic|lewd)\b.*\b(child|children|kid|kids)\b', re.IGNORECASE),
    re.compile(r'\bloli\b', re.IGNORECASE),
    re.compile(r'\bshota\b', re.IGNORECASE),
    re.compile(r'\b(young|little)\s+(girl|boy)\b.*\b(sex|rape|nsfw|erotic|lewd)\b', re.IGNORECASE),
    re.compile(r'\bpedophil', re.IGNORECASE),
    re.compile(r'\bminor\b.*\b(sex|sexual|rape|erotic)\b', re.IGNORECASE),
    re.compile(r'\b(preteen|pre-teen)\b', re.IGNORECASE),
    re.compile(r'\bage\s*[:\-]?\s*([1-9]|1[0-7])\b', re.IGNORECASE),  # Age: 1-17
    re.compile(r'\b([1-9]|1[0-7])[-\s]*(years?|yrs?|y/?o)[-\s]*old\b', re.IGNORECASE),  # X years old / X-year-old (1-17)
]

# NSFW tag indicators
NSFW_TAGS = {
    "nsfw", "explicit", "adult", "18+", "mature", "r18", "r-18",
    "sexual", "erotic", "lewd", "smut", "porn", "hentai",
    "sex", "nude", "naked", "xxx", "fetish", "kink",
    "bdsm", "bondage", "dominatrix", "submissive",
    "slutty", "whore", "prostitute", "hooker",
    "breeding", "impregnation", "pregnancy kink",
    "incest", "taboo", "forbidden",
    "gore", "violence", "torture", "snuff",
    "rape", "non-con", "noncon", "dubcon", "dub-con",
    "futanari", "futa", "dickgirl",
    "furry", "kemono", "anthro",  # Often NSFW
    "monster", "tentacle", "oviposition", "vore",
    "femdom", "maledom", "cuckold", "ntr",
    "ahegao", "gangbang", "orgy", "threesome",
    "blowjob", "handjob", "footjob", "titjob",
    "anal", "oral", "creampie", "cumshot",
    "exhibitionist", "voyeur",
}

# NSFW patterns to search in descriptions
NSFW_DESCRIPTION_PATTERNS = [
    re.compile(r'\b(nsfw|explicit|18\+|adult only|mature content)\b', re.IGNORECASE),
    re.compile(r'\b(sex|sexual|erotic|lewd|smut)\b', re.IGNORECASE),
    re.compile(r'\b(fuck|cock|dick|penis|pussy|vagina|cunt|tits|breasts?|nipples?)\b', re.IGNORECASE),
    re.compile(r'\b(orgasm|climax|moan|cum|cumming|ejaculat)\b', re.IGNORECASE),
    re.compile(r'\b(nude|naked|strip|undress)\b', re.IGNORECASE),
    re.compile(r'\b(masturbat|fingering|handjob|blowjob|fellatio|cunnilingus)\b', re.IGNORECASE),
    re.compile(r'\b(bdsm|bondage|domination|submission|sadis|masochis)\b', re.IGNORECASE),
    re.compile(r'\b(rape|non-?con|forced|violated)\b', re.IGNORECASE),
    re.compile(r'\b(hentai|ahegao|tentacle|vore)\b', re.IGNORECASE),
    re.compile(r'\b(slut|whore|bitch|prostitut)\b', re.IGNORECASE),
    re.compile(r'\b(breed|impregnate|creampie|knocked up)\b', re.IGNORECASE),
    re.compile(r'\b(incest|step-?(mom|dad|sis|bro|mother|father|sister|brother))\b', re.IGNORECASE),
    re.compile(r'\bwill\s+(fuck|have sex|sleep with|breed)\b', re.IGNORECASE),
    re.compile(r'\b(sexually|intimately)\s+(aggressive|dominant|submissive)\b', re.IGNORECASE),
    re.compile(r'\bloves?\s+(sex|fucking|cock|dick|being fucked)\b', re.IGNORECASE),
    re.compile(r'\b(horny|aroused|turned on|in heat)\b', re.IGNORECASE),
]

def name_similarity(name1: str, name2: str) -> float:
    """Check if two names are similar enough to be considered the same character."""
    # Normalize names
    n1 = re.sub(r'[^a-z0-9\s]', '', name1.lower()).split()
    n2 = re.sub(r'[^a-z0-9\s]', '', name2.lower()).split()

    if not n1 or not n2:
        return 0.0

    # Check for common significant words (ignore short words like "the", "a", etc.)
    significant1 = {w for w in n1 if len(w) > 2}
    significant2 = {w for w in n2 if len(w) > 2}

    if not significant1 or not significant2:
        # Fall back to first word comparison
        return 1.0 if n1[0] == n2[0] else 0.0

    # Calculate overlap
    common = significant1 & significant2
    if common:
        return len(common) / min(len(significant1), len(significant2))

    return 0.0

def check_prohibited_tags(tags: List[str]) -> tuple[bool, set]:
    """Check if tags contain prohibited content. Returns (is_prohibited, matched_tags)."""
    tags_lower = [t.lower() for t in tags]
    blocked_found = set()

    for tag in tags_lower:
        # Check exact matches
        if tag in BLOCKED_TAGS_EXACT:
            blocked_found.add(tag)
        # Check pattern matches (loli, shota, rape variants)
        else:
            for pattern in BLOCKED_PATTERNS:
                if pattern.search(tag):
                    blocked_found.add(tag)
                    break

    return bool(blocked_found), blocked_found


def check_prohibited_description(description: str) -> tuple[bool, set]:
    """Check if description contains prohibited content. Returns (is_prohibited, matched_phrases)."""
    if not description:
        return False, set()

    blocked_found = set()

    for pattern in BLOCKED_DESCRIPTION_PATTERNS:
        match = pattern.search(description)
        if match:
            # Extract a snippet around the match for logging
            start = max(0, match.start() - 20)
            end = min(len(description), match.end() + 20)
            snippet = description[start:end].replace('\n', ' ')
            blocked_found.add(f"desc: ...{snippet}...")

    return bool(blocked_found), blocked_found


def check_prohibited_content(tags: List[str], description: str = "", first_mes: str = "") -> tuple[bool, set]:
    """Check tags and description for prohibited content. Returns (is_prohibited, matched_items)."""
    blocked_found = set()

    # Check tags
    tag_prohibited, tag_matches = check_prohibited_tags(tags)
    blocked_found.update(tag_matches)

    # Check description
    desc_prohibited, desc_matches = check_prohibited_description(description)
    blocked_found.update(desc_matches)

    # Check first message too
    first_mes_prohibited, first_mes_matches = check_prohibited_description(first_mes)
    blocked_found.update(first_mes_matches)

    return bool(blocked_found), blocked_found


def check_nsfw_content(tags: List[str], description: str = "", first_mes: str = "") -> bool:
    """Check if content should be marked as NSFW based on tags and description."""
    # Check tags
    tags_lower = {t.lower() for t in tags}
    if tags_lower & NSFW_TAGS:
        return True

    # Check description for NSFW patterns
    text_to_check = f"{description} {first_mes}"
    for pattern in NSFW_DESCRIPTION_PATTERNS:
        if pattern.search(text_to_check):
            return True

    return False

@dataclass
class CardEntry:
    file: str
    path: str
    folder: str
    name: str
    creator: str
    tags: List[str]
    nsfw: bool
    description_preview: str
    first_mes_preview: str
    indexed_at: str
    content_hash: str = ""  # Hash of character definition for duplicate detection
    image_hash: str = ""    # Perceptual hash of image for visual duplicate detection

class CardIndex:
    def __init__(self):
        self.cards: dict[str, CardEntry] = {}
        self.lock = asyncio.Lock()
        # Track prohibited deletions and duplicates
        self.prohibited_deleted: List[dict] = []
        self.duplicates: dict[str, List[str]] = {}  # content_hash -> [paths]
        self.content_hashes: dict[str, str] = {}  # content_hash -> first_path
        # Image-based duplicates
        self.image_duplicates: dict[str, List[str]] = {}  # image_hash -> [paths]
        self.image_hashes: dict[str, str] = {}  # image_hash -> first_path
        self.image_hash_objects: dict[str, 'imagehash.ImageHash'] = {}  # path -> hash object
        # Ignored duplicates (persisted) - set of frozensets of paths that are NOT duplicates
        self.ignored_duplicates: set[frozenset] = set()
        # Scan status
        self.scan_status = {"running": False, "progress": 0, "total": 0, "last_scan": None}

    def save_index(self, filepath: str = INDEX_FILE):
        """Save index to JSON file for persistence."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            data = {
                "version": 3,
                "saved_at": datetime.utcnow().isoformat(),
                "cards": {path: asdict(entry) for path, entry in self.cards.items()},
                "content_hashes": self.content_hashes,
                "image_hashes": self.image_hashes,
                "duplicates": self.duplicates,
                "image_duplicates": self.image_duplicates,
                "prohibited_deleted": self.prohibited_deleted[-1000:],  # Keep last 1000
                "ignored_duplicates": [list(s) for s in self.ignored_duplicates]  # Convert frozensets to lists for JSON
            }

            with open(filepath, 'w') as f:
                json.dump(data, f)

            logger.info(f"Saved index with {len(self.cards)} cards to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            return False

    def load_index(self, filepath: str = INDEX_FILE) -> bool:
        """Load index from JSON file."""
        try:
            if not os.path.exists(filepath):
                logger.info(f"No existing index file at {filepath}")
                return False

            with open(filepath, 'r') as f:
                data = json.load(f)

            # Load cards
            for path, entry_dict in data.get("cards", {}).items():
                # Verify file still exists
                if os.path.exists(path):
                    self.cards[path] = CardEntry(**entry_dict)

            # Load hashes and duplicates
            self.content_hashes = data.get("content_hashes", {})
            self.image_hashes = data.get("image_hashes", {})
            self.duplicates = data.get("duplicates", {})
            self.image_duplicates = data.get("image_duplicates", {})
            self.prohibited_deleted = data.get("prohibited_deleted", [])
            # Load ignored duplicates (convert lists back to frozensets)
            self.ignored_duplicates = {frozenset(paths) for paths in data.get("ignored_duplicates", [])}

            # Clean up any self-duplicates (bug fix)
            for hash_key in list(self.duplicates.keys()):
                paths = self.duplicates[hash_key]
                # Remove duplicates where path appears multiple times
                unique_paths = list(dict.fromkeys(paths))
                if len(unique_paths) < 2:
                    del self.duplicates[hash_key]
                else:
                    self.duplicates[hash_key] = unique_paths

            for hash_key in list(self.image_duplicates.keys()):
                paths = self.image_duplicates[hash_key]
                unique_paths = list(dict.fromkeys(paths))
                if len(unique_paths) < 2:
                    del self.image_duplicates[hash_key]
                else:
                    self.image_duplicates[hash_key] = unique_paths

            logger.info(f"Loaded index with {len(self.cards)} cards from {filepath} (saved {data.get('saved_at', 'unknown')})")
            return True
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return False

    def calculate_image_hash(self, filepath: str) -> Optional[str]:
        """Calculate perceptual hash of image for visual duplicate detection."""
        if not IMAGE_HASH_AVAILABLE:
            return None
        try:
            with Image.open(filepath) as img:
                # Use difference hash (fast and effective)
                phash = imagehash.dhash(img, hash_size=12)
                # Store the hash object for fuzzy matching
                self.image_hash_objects[filepath] = phash
                return str(phash)
        except Exception as e:
            logger.debug(f"Failed to hash image {filepath}: {e}")
            return None

    def find_similar_image(self, filepath: str, hash_obj, threshold: int = 12) -> Optional[str]:
        """Find an existing card with a similar image hash (within Hamming distance threshold)."""
        if not IMAGE_HASH_AVAILABLE:
            return None
        for existing_path, existing_hash in self.image_hash_objects.items():
            if existing_path == filepath:
                continue
            # Calculate Hamming distance
            distance = hash_obj - existing_hash
            if distance <= threshold:
                return existing_path
        return None

    def extract_metadata(self, filepath: str) -> Optional[dict]:
        """Extract chara metadata from PNG tEXt chunk."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            if data[:8] != b'\x89PNG\r\n\x1a\n':
                return None

            pos = 8
            while pos < len(data):
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]

                if chunk_type == b'tEXt':
                    chunk_data = data[pos+8:pos+8+length]
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        key = chunk_data[:null_pos]
                        value = chunk_data[null_pos+1:]
                        if key == b'chara':
                            decoded = json.loads(base64.b64decode(value))
                            return decoded

                if chunk_type == b'IEND':
                    break

                pos += 12 + length

            return None
        except Exception as e:
            logger.error(f"Error extracting metadata from {filepath}: {e}")
            return None

    def index_card(self, filepath: str, delete_prohibited: bool = True) -> Optional[CardEntry]:
        """Index a single card file. Returns None if prohibited/deleted or invalid."""
        metadata = self.extract_metadata(filepath)
        if not metadata:
            return None

        data = metadata.get("data", metadata)
        tags = data.get("tags", [])
        description = data.get("description", "")
        first_mes = data.get("first_mes", "")

        # Check for prohibited content in tags, description, and first message
        if AUTO_DELETE_PROHIBITED or delete_prohibited:
            is_prohibited, blocked_items = check_prohibited_content(tags, description, first_mes)
            if is_prohibited:
                logger.warning(f"PROHIBITED: {filepath} - Matches: {blocked_items}")
                self.prohibited_deleted.append({
                    "path": filepath,
                    "tags": list(blocked_items),
                    "deleted_at": datetime.utcnow().isoformat()
                })
                try:
                    os.remove(filepath)
                    logger.info(f"DELETED prohibited: {filepath}")
                except Exception as e:
                    logger.error(f"Failed to delete {filepath}: {e}")
                return None

        # Determine NSFW from tags and description content
        nsfw = check_nsfw_content(tags, description, first_mes)

        # Get folder name (chub/booru)
        folder = Path(filepath).parent.name
        filename = Path(filepath).name

        # Calculate content hash for duplicate detection
        content_hash = ""
        if DETECT_DUPLICATES:
            # Hash the core character definition
            hash_content = json.dumps({
                "name": data.get("name", ""),
                "description": description,
                "first_mes": first_mes,
                "personality": data.get("personality", ""),
                "scenario": data.get("scenario", "")
            }, sort_keys=True)
            content_hash = hashlib.md5(hash_content.encode()).hexdigest()

            # Check for content duplicates
            if content_hash in self.content_hashes:
                original_path = self.content_hashes[content_hash]
                # Don't mark as duplicate of itself
                if original_path != filepath:
                    if content_hash not in self.duplicates:
                        self.duplicates[content_hash] = [original_path]
                    if filepath not in self.duplicates[content_hash]:
                        self.duplicates[content_hash].append(filepath)
                        logger.info(f"CONTENT DUPLICATE: {filepath} matches {original_path}")
            else:
                self.content_hashes[content_hash] = filepath

        # Calculate image hash for visual duplicate detection
        image_hash = ""
        card_name = data.get("name", filename.replace(".png", ""))
        if IMAGE_HASH_AVAILABLE:
            image_hash = self.calculate_image_hash(filepath) or ""
            hash_obj = self.image_hash_objects.get(filepath)

            if image_hash and hash_obj:
                # First check exact match
                match_path = None
                match_key = image_hash

                if image_hash in self.image_hashes:
                    match_path = self.image_hashes[image_hash]
                else:
                    # Check for fuzzy match (Hamming distance <= 12)
                    similar_path = self.find_similar_image(filepath, hash_obj, threshold=12)
                    if similar_path:
                        match_path = similar_path
                        # Use the original's hash as the key for grouping
                        original_entry = self.cards.get(similar_path)
                        if original_entry and original_entry.image_hash:
                            match_key = original_entry.image_hash

                if match_path and match_path != filepath:
                    original_entry = self.cards.get(match_path)
                    original_name = original_entry.name if original_entry else ""

                    # Only count as duplicate if names are similar (>0.3 similarity)
                    if name_similarity(card_name, original_name) > 0.3:
                        if match_key not in self.image_duplicates:
                            self.image_duplicates[match_key] = [match_path]
                        if filepath not in self.image_duplicates[match_key]:
                            self.image_duplicates[match_key].append(filepath)
                            logger.info(f"IMAGE DUPLICATE: {filepath} ({card_name}) matches {match_path} ({original_name})")
                elif not match_path:
                    self.image_hashes[image_hash] = filepath

        entry = CardEntry(
            file=filename,
            path=filepath,
            folder=folder,
            name=data.get("name", filename.replace(".png", "")),
            creator=data.get("creator", "Unknown"),
            tags=tags,
            nsfw=nsfw,
            description_preview=description[:300] if description else "",
            first_mes_preview=first_mes[:300] if first_mes else "",
            indexed_at=datetime.utcnow().isoformat(),
            content_hash=content_hash,
            image_hash=image_hash
        )

        return entry

    async def add_card(self, filepath: str):
        """Add or update a card in the index."""
        if not filepath.lower().endswith('.png'):
            return

        entry = self.index_card(filepath)
        if entry:
            async with self.lock:
                self.cards[filepath] = entry
            logger.info(f"Indexed: {entry.name} ({entry.file})")

    async def remove_card(self, filepath: str):
        """Remove a card from the index."""
        async with self.lock:
            if filepath in self.cards:
                del self.cards[filepath]
                logger.info(f"Removed from index: {filepath}")

    async def full_scan(self, directories: List[str], recursive: bool = True):
        """Perform full scan of directories."""
        logger.info(f"Starting full index scan (recursive={recursive})...")
        count = 0
        processed = 0

        for directory in directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory not found: {directory}")
                continue

            if recursive:
                for root, dirs, files in os.walk(directory):
                    # Yield after each directory to keep server responsive
                    await asyncio.sleep(0)
                    for filename in files:
                        if filename.lower().endswith('.png'):
                            filepath = os.path.join(root, filename)
                            processed += 1
                            self.scan_status["progress"] = processed
                            entry = self.index_card(filepath)
                            if entry:
                                self.cards[filepath] = entry
                                count += 1
                                if count % 100 == 0:
                                    # Yield frequently to keep server responsive
                                    await asyncio.sleep(0)
                                if count % 5000 == 0:
                                    logger.info(f"Indexed {count} cards...")
            else:
                for filename in os.listdir(directory):
                    if filename.lower().endswith('.png'):
                        filepath = os.path.join(directory, filename)
                        processed += 1
                        self.scan_status["progress"] = processed
                        entry = self.index_card(filepath)
                        if entry:
                            self.cards[filepath] = entry
                            count += 1
                            if count % 100 == 0:
                                await asyncio.sleep(0)
                            if count % 5000 == 0:
                                logger.info(f"Indexed {count} cards...")

        logger.info(f"Full scan complete. Total cards indexed: {len(self.cards)}")

    def search(
        self,
        query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        nsfw: Optional[bool] = None,
        creator: Optional[str] = None,
        folder: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> tuple[List[CardEntry], int]:
        """Search the index with filters."""
        results = list(self.cards.values())

        # Filter by query (name, description)
        if query:
            query_lower = query.lower()
            results = [
                c for c in results
                if query_lower in c.name.lower()
                or query_lower in c.description_preview.lower()
                or query_lower in c.creator.lower()
            ]

        # Filter by tags
        if tags:
            tags_lower = [t.lower() for t in tags]
            results = [
                c for c in results
                if any(t.lower() in tags_lower for t in c.tags)
            ]

        # Filter by NSFW
        if nsfw is not None:
            results = [c for c in results if c.nsfw == nsfw]

        # Filter by creator
        if creator:
            creator_lower = creator.lower()
            results = [c for c in results if creator_lower in c.creator.lower()]

        # Filter by folder
        if folder:
            results = [c for c in results if c.folder == folder]

        total = len(results)

        # Paginate
        results = results[offset:offset + limit]

        return results, total


# File watcher handler
class CardFileHandler(FileSystemEventHandler):
    def __init__(self, index: CardIndex, loop: asyncio.AbstractEventLoop):
        self.index = index
        self.loop = loop

    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith('.png'):
            asyncio.run_coroutine_threadsafe(
                self.index.add_card(event.src_path), self.loop
            )

    def on_deleted(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.index.remove_card(event.src_path), self.loop
            )

    def on_moved(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.index.remove_card(event.src_path), self.loop
            )
            if event.dest_path.lower().endswith('.png'):
                asyncio.run_coroutine_threadsafe(
                    self.index.add_card(event.dest_path), self.loop
                )


# FastAPI app
app = FastAPI(title="Character Card Index", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

index = CardIndex()
observer = None

@app.on_event("startup")
async def startup():
    global observer

    # Try to load existing index first for instant availability
    if index.load_index():
        logger.info("Server ready with cached index, starting background rescan...")
    else:
        logger.info("No cached index, performing initial scan...")

    # Start file watcher immediately
    loop = asyncio.get_event_loop()
    handler = CardFileHandler(index, loop)
    observer = Observer()

    for directory in CARD_DIRS:
        if os.path.exists(directory):
            observer.schedule(handler, directory, recursive=RECURSIVE)
            logger.info(f"Watching directory: {directory} (recursive={RECURSIVE})")

    observer.start()

    # Run full scan in background (updates/verifies index)
    asyncio.create_task(background_scan())

async def background_scan():
    """Run full scan in background without blocking server startup."""
    # Small delay to let server finish starting
    await asyncio.sleep(0.1)

    try:
        index.scan_status["running"] = True
        index.scan_status["progress"] = 0
        index.scan_status["total"] = 0  # Will update as we scan

        logger.info(f"Background scan starting...")

        # Perform scan
        await index.full_scan(CARD_DIRS, recursive=RECURSIVE)

        index.scan_status["running"] = False
        index.scan_status["last_scan"] = datetime.utcnow().isoformat()

        # Save index after scan completes
        index.save_index()

    except Exception as e:
        logger.error(f"Background scan error: {e}")
        index.scan_status["running"] = False


@app.on_event("shutdown")
async def shutdown():
    # Save index on shutdown
    index.save_index()

    if observer:
        observer.stop()
        observer.join()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CardVault Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e; color: #eee; line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px; margin-bottom: 30px; border-radius: 12px;
        }
        header h1 { font-size: 2rem; margin-bottom: 10px; }
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin-bottom: 30px;
        }
        .stat-card {
            background: #16213e; padding: 20px; border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .stat-card h3 { font-size: 0.9rem; color: #888; margin-bottom: 5px; }
        .stat-card .value { font-size: 2rem; font-weight: bold; color: #667eea; }
        .stat-card.warning { border-left-color: #f39c12; }
        .stat-card.warning .value { color: #f39c12; }
        .stat-card.danger { border-left-color: #e74c3c; }
        .stat-card.danger .value { color: #e74c3c; }
        .stat-card.success { border-left-color: #2ecc71; }
        .stat-card.success .value { color: #2ecc71; }
        .section {
            background: #16213e; border-radius: 12px; padding: 25px;
            margin-bottom: 25px;
        }
        .section h2 {
            font-size: 1.3rem; margin-bottom: 20px; padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab {
            padding: 10px 20px; background: #0f3460; border: none;
            color: #fff; border-radius: 8px; cursor: pointer; transition: all 0.2s;
        }
        .tab:hover { background: #1a4a7a; }
        .tab.active { background: #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { color: #888; font-weight: 500; font-size: 0.85rem; text-transform: uppercase; }
        tr:hover { background: #1a3a5c; }
        .tag {
            display: inline-block; padding: 3px 8px; background: #0f3460;
            border-radius: 4px; font-size: 0.8rem; margin: 2px;
        }
        .tag.blocked { background: #e74c3c; }
        .btn {
            padding: 10px 20px; border: none; border-radius: 8px;
            cursor: pointer; font-weight: 500; transition: all 0.2s;
        }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5a6fd6; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-danger:hover { background: #c0392b; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .search-box {
            display: flex; gap: 10px; margin-bottom: 20px;
        }
        .search-box input {
            flex: 1; padding: 12px; background: #0f3460; border: 1px solid #333;
            border-radius: 8px; color: #fff; font-size: 1rem;
        }
        .search-box input:focus { outline: none; border-color: #667eea; }
        .card-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 15px;
        }
        .card {
            background: #0f3460; border-radius: 10px; overflow: hidden;
            cursor: pointer; transition: transform 0.2s;
        }
        .card:hover { transform: translateY(-5px); }
        .card img { width: 100%; aspect-ratio: 1; object-fit: cover; }
        .card-info { padding: 12px; }
        .card-info h4 { font-size: 0.95rem; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .card-info p { font-size: 0.8rem; color: #888; }
        .nsfw-badge {
            position: absolute; top: 8px; right: 8px; background: #e74c3c;
            padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;
        }
        .dupe-group {
            background: #0f3460; padding: 15px; border-radius: 8px; margin-bottom: 15px;
            position: relative;
        }
        .dupe-group h4 { margin-bottom: 10px; color: #f39c12; }
        .dupe-group .ignore-btn {
            position: absolute; top: 10px; right: 10px; background: #27ae60;
            border: none; color: white; padding: 5px 12px; border-radius: 6px;
            cursor: pointer; font-size: 0.85rem;
        }
        .dupe-group .ignore-btn:hover { background: #2ecc71; }
        .dupe-group .type-badge {
            display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 0.75rem; margin-left: 10px;
        }
        .dupe-group .type-badge.content { background: #667eea; }
        .dupe-group .type-badge.image { background: #e74c3c; }
        .dupe-cards {
            display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px;
        }
        .dupe-card {
            background: #1a1a2e; border-radius: 8px; overflow: hidden;
            width: 140px; position: relative;
        }
        .dupe-card img { width: 100%; aspect-ratio: 1; object-fit: cover; cursor: pointer; }
        .dupe-card .info { padding: 8px; font-size: 0.8rem; }
        .dupe-card .info h5 { margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .dupe-card .info p { margin: 2px 0 0; color: #888; font-size: 0.75rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .dupe-card .keep-badge {
            position: absolute; top: 5px; left: 5px; background: #2ecc71;
            padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;
        }
        .dupe-card .delete-btn {
            position: absolute; top: 5px; right: 5px; background: #e74c3c;
            border: none; color: white; width: 24px; height: 24px; border-radius: 50%;
            cursor: pointer; font-size: 0.9rem; display: flex; align-items: center;
            justify-content: center; opacity: 0.8; transition: opacity 0.2s;
        }
        .dupe-card .delete-btn:hover { opacity: 1; }
        .dupe-card.deleted { opacity: 0.3; pointer-events: none; }
        .dupe-card.deleted::after {
            content: 'DELETED'; position: absolute; top: 50%; left: 50%;
            transform: translate(-50%, -50%); background: #e74c3c; padding: 5px 10px;
            border-radius: 4px; font-weight: bold;
        }
        .dupe-path {
            font-family: monospace; font-size: 0.75rem; padding: 3px 8px;
            background: #1a1a2e; margin: 3px 0; border-radius: 4px; color: #666;
        }
        .loading { text-align: center; padding: 40px; color: #888; }
        .empty { text-align: center; padding: 40px; color: #666; }
        .actions { display: flex; gap: 10px; margin-top: 15px; }
        #toast {
            position: fixed; bottom: 20px; right: 20px; background: #2ecc71;
            padding: 15px 25px; border-radius: 8px; display: none; z-index: 1000;
        }
        #toast.error { background: #e74c3c; }
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8); display: none; z-index: 2000;
            justify-content: center; align-items: center; padding: 20px;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: #16213e; border-radius: 16px; max-width: 900px;
            width: 100%; max-height: 90vh; overflow-y: auto; position: relative;
        }
        .modal-close {
            position: absolute; top: 15px; right: 15px; background: #e74c3c;
            border: none; color: white; width: 36px; height: 36px; border-radius: 50%;
            cursor: pointer; font-size: 1.2rem; z-index: 10;
        }
        .modal-header {
            display: flex; gap: 20px; padding: 25px; border-bottom: 1px solid #333;
        }
        .modal-header img {
            width: 200px; height: 200px; object-fit: cover; border-radius: 12px;
            flex-shrink: 0;
        }
        .modal-header-info { flex: 1; }
        .modal-header-info h2 { font-size: 1.5rem; margin-bottom: 8px; }
        .modal-header-info .creator { color: #2ecc71; margin-bottom: 12px; }
        .modal-header-info .meta { color: #888; font-size: 0.9rem; }
        .modal-body { padding: 25px; }
        .modal-section { margin-bottom: 20px; }
        .modal-section h3 {
            font-size: 0.9rem; color: #888; text-transform: uppercase;
            margin-bottom: 8px; letter-spacing: 1px;
        }
        .modal-section-content {
            background: #0f3460; padding: 15px; border-radius: 8px;
            white-space: pre-wrap; font-size: 0.95rem; line-height: 1.6;
            max-height: 300px; overflow-y: auto;
        }
        .modal-tags { display: flex; flex-wrap: wrap; gap: 8px; }
        .modal-tags .tag { background: #667eea; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CardVault Dashboard</h1>
            <p>Character Card Index Server v2.0.0</p>
            <div style="margin-top:15px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                <button class="btn btn-primary" onclick="triggerRescan()" id="rescan-btn">
                    🔄 Rescan Index
                </button>
                <button class="btn btn-primary" onclick="triggerNextcloudScan()" id="nextcloud-btn">
                    ☁️ Refresh Nextcloud
                </button>
                <span id="scan-status" style="font-size:0.9rem;"></span>
            </div>
        </header>

        <div class="stats-grid" id="stats-grid">
            <div class="stat-card"><h3>Loading...</h3><div class="value">-</div></div>
        </div>

        <div class="tabs">
            <button class="tab active" data-tab="search">Search Cards</button>
            <button class="tab" data-tab="duplicates">Duplicates</button>
            <button class="tab" data-tab="prohibited">Prohibited Log</button>
            <button class="tab" data-tab="tags">Top Tags</button>
        </div>

        <div id="search" class="tab-content active">
            <div class="section">
                <h2>Search Cards</h2>
                <div class="search-box">
                    <input type="text" id="search-input" placeholder="Search by name, description, or creator...">
                    <button class="btn btn-primary" onclick="searchCards()">Search</button>
                </div>
                <div id="search-results" class="card-grid"></div>
                <div id="search-loading" class="loading" style="display:none;">Searching...</div>
            </div>
        </div>

        <div id="duplicates" class="tab-content">
            <div class="section">
                <h2>Duplicate Cards</h2>
                <p style="color:#888;margin-bottom:15px;">Cards with identical content (same name, description, first message, personality, scenario)</p>
                <div class="actions" style="margin-bottom:20px;">
                    <button class="btn btn-danger" onclick="cleanDuplicates('first')" id="clean-first-btn">
                        Delete Duplicates (Keep First)
                    </button>
                    <button class="btn btn-danger" onclick="cleanDuplicates('largest')" id="clean-largest-btn">
                        Delete Duplicates (Keep Largest)
                    </button>
                </div>
                <div id="duplicates-list"></div>
                <div id="duplicates-loading" class="loading">Loading duplicates...</div>
            </div>
        </div>

        <div id="prohibited" class="tab-content">
            <div class="section">
                <h2>Prohibited Content Log</h2>
                <p style="color:#888;margin-bottom:15px;">Cards that were automatically deleted due to prohibited tags</p>
                <div id="prohibited-list"></div>
                <div id="prohibited-loading" class="loading">Loading...</div>
            </div>
        </div>

        <div id="tags" class="tab-content">
            <div class="section">
                <h2>Top Tags</h2>
                <div id="tags-list"></div>
                <div id="tags-loading" class="loading">Loading tags...</div>
            </div>
        </div>
    </div>

    <div id="toast"></div>

    <div class="modal-overlay" id="card-modal" onclick="if(event.target===this)closeModal()">
        <div class="modal">
            <button class="modal-close" onclick="closeModal()">✕</button>
            <div class="modal-header">
                <img id="modal-img" src="" alt="">
                <div class="modal-header-info">
                    <h2 id="modal-name"></h2>
                    <div class="creator">by <span id="modal-creator"></span></div>
                    <div class="meta">
                        <span id="modal-nsfw" class="tag blocked" style="display:none;">NSFW</span>
                        <span id="modal-folder"></span>
                    </div>
                    <div class="modal-tags" id="modal-tags" style="margin-top:12px;"></div>
                </div>
            </div>
            <div class="modal-body">
                <div class="modal-section" id="section-description">
                    <h3>Description</h3>
                    <div class="modal-section-content" id="modal-description"></div>
                </div>
                <div class="modal-section" id="section-firstmes">
                    <h3>First Message</h3>
                    <div class="modal-section-content" id="modal-firstmes"></div>
                </div>
                <div class="modal-section" id="section-personality">
                    <h3>Personality</h3>
                    <div class="modal-section-content" id="modal-personality"></div>
                </div>
                <div class="modal-section" id="section-scenario">
                    <h3>Scenario</h3>
                    <div class="modal-section-content" id="modal-scenario"></div>
                </div>
                <div class="modal-section" id="section-mesbefore">
                    <h3>Example Messages</h3>
                    <div class="modal-section-content" id="modal-mesbefore"></div>
                </div>
                <div class="modal-section" id="section-path">
                    <h3>File Path</h3>
                    <div class="modal-section-content" id="modal-path" style="font-family:monospace;font-size:0.85rem;"></div>
                </div>
                <div style="margin-top:20px; display:flex; gap:10px; flex-wrap:wrap;">
                    <button class="btn btn-primary" id="modal-similar-btn" onclick="findSimilar()">🔍 Find Similar</button>
                    <button class="btn btn-danger" id="modal-delete-btn" onclick="deleteFromModal()">🗑️ Delete Card</button>
                </div>
                <div id="similar-results" style="margin-top:20px; display:none;">
                    <h3 style="color:#888; font-size:0.9rem; margin-bottom:12px;">SIMILAR CARDS</h3>
                    <div id="similar-cards" class="dupe-cards"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

        // Toast notification
        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.className = isError ? 'error' : '';
            toast.style.display = 'block';
            setTimeout(() => toast.style.display = 'none', 3000);
        }

        // Load stats
        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stats-grid').innerHTML = `
                    <div class="stat-card success">
                        <h3>Total Cards</h3>
                        <div class="value">${data.total_cards.toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <h3>SFW Cards</h3>
                        <div class="value">${data.sfw_count.toLocaleString()}</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>NSFW Cards</h3>
                        <div class="value">${data.nsfw_count.toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Unique Creators</h3>
                        <div class="value">${data.unique_creators.toLocaleString()}</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Content Dupes</h3>
                        <div class="value">${data.content_duplicate_groups}</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#e74c3c;">
                        <h3>Image Dupes ${data.image_hash_enabled ? '' : '(disabled)'}</h3>
                        <div class="value" style="color:#e74c3c;">${data.image_duplicate_groups}</div>
                    </div>
                    <div class="stat-card danger">
                        <h3>Prohibited Deleted</h3>
                        <div class="value">${data.prohibited_deleted}</div>
                    </div>
                `;
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }

        // Search cards
        async function searchCards() {
            const query = document.getElementById('search-input').value;
            const results = document.getElementById('search-results');
            const loading = document.getElementById('search-loading');

            results.innerHTML = '';
            loading.style.display = 'block';

            try {
                const res = await fetch(`/api/cards?q=${encodeURIComponent(query)}&limit=100`);
                const data = await res.json();
                loading.style.display = 'none';

                if (data.results.length === 0) {
                    results.innerHTML = '<div class="empty">No cards found</div>';
                    return;
                }

                results.innerHTML = data.results.map(card => `
                    <div class="card" style="position:relative;" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}" onclick="openCardEl(this)">
                        <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}"
                             alt="${card.name}" loading="lazy"
                             onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/><text x=%2250%22 y=%2250%22 text-anchor=%22middle%22 fill=%22%23666%22>?</text></svg>'">
                        ${card.nsfw ? '<span class="nsfw-badge">NSFW</span>' : ''}
                        <div class="card-info">
                            <h4>${card.name}</h4>
                            <p>${card.creator}</p>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                loading.style.display = 'none';
                results.innerHTML = '<div class="empty">Error loading cards</div>';
            }
        }

        // Load duplicates
        async function loadDuplicates() {
            const list = document.getElementById('duplicates-list');
            const loading = document.getElementById('duplicates-loading');

            try {
                const res = await fetch('/api/duplicates');
                const data = await res.json();
                loading.style.display = 'none';

                if (data.duplicates.length === 0) {
                    list.innerHTML = '<div class="empty">No duplicates found</div>';
                    return;
                }

                list.innerHTML = `
                    <p style="margin-bottom:15px;">
                        <span style="color:#667eea;">${data.content_duplicate_groups} content duplicates</span> |
                        <span style="color:#e74c3c;">${data.image_duplicate_groups} image duplicates</span> |
                        <span style="color:#f39c12;">${data.total_duplicate_files} extra files total</span>
                    </p>
                ` + data.duplicates.map((dupe, idx) => `
                    <div class="dupe-group" id="dupe-group-${idx}" data-paths="${encodeURIComponent(JSON.stringify(dupe.cards.map(c => c.path)))}">
                        <button class="ignore-btn" onclick="ignoreDuplicateGroup(${idx})">✓ Not a Duplicate</button>
                        <h4>${dupe.count} copies
                            <span class="type-badge ${dupe.type}">${dupe.type === 'content' ? '📄 Content Match' : '🖼️ Image Match'}</span>
                        </h4>
                        <div class="dupe-cards">
                            ${dupe.cards.map((card, i) => `
                                <div class="dupe-card" data-path="${encodeURIComponent(card.path)}" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                                    ${i === 0 ? '<span class="keep-badge">KEEP</span>' : ''}
                                    <button class="delete-btn" onclick="event.stopPropagation(); deleteCardEl(this.parentElement)" title="Delete this card">✕</button>
                                    <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}"
                                         onclick="openCardEl(this.parentElement)"
                                         onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'"
                                         loading="lazy">
                                    <div class="info">
                                        <h5>${card.name}</h5>
                                        <p>${card.creator}</p>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                        <div class="dupe-path" style="margin-top:8px;">${dupe.cards.map(c => c.path).join(' | ')}</div>
                    </div>
                `).join('');
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading duplicates</div>';
                console.error(e);
            }
        }

        // Helper to open card from element data attributes
        function openCardEl(el) {
            const folder = decodeURIComponent(el.dataset.folder);
            const file = decodeURIComponent(el.dataset.file);
            openCard(folder, file);
        }

        // Helper to delete card from element data attributes
        function deleteCardEl(el) {
            const path = decodeURIComponent(el.dataset.path);
            deleteCardByPath(path, el);
        }

        // Delete single card by path
        async function deleteCardByPath(path, card) {
            if (!confirm('Delete this card permanently?')) return;

            const btn = card.querySelector('.delete-btn');
            if (btn) {
                btn.disabled = true;
                btn.textContent = '...';
            }

            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
                const data = await res.json();

                if (data.success) {
                    card.classList.add('deleted');
                    showToast('Card deleted');
                    loadStats();
                } else {
                    showToast('Delete failed: ' + (data.detail || 'Unknown error'), true);
                    if (btn) {
                        btn.disabled = false;
                        btn.textContent = '✕';
                    }
                }
            } catch (e) {
                showToast('Delete error: ' + e.message, true);
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '✕';
                }
            }
        }

        // Delete single card (legacy, for search results)
        async function deleteCard(path, btn) {
            if (!confirm('Delete this card permanently?')) return;

            const card = btn.closest('.dupe-card');
            btn.disabled = true;
            btn.textContent = '...';

            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
                const data = await res.json();

                if (data.success) {
                    card.classList.add('deleted');
                    showToast('Card deleted');
                    loadStats();
                } else {
                    showToast('Delete failed: ' + (data.detail || 'Unknown error'), true);
                    btn.disabled = false;
                    btn.textContent = '✕';
                }
            } catch (e) {
                showToast('Delete error: ' + e.message, true);
                btn.disabled = false;
                btn.textContent = '✕';
            }
        }

        // Mark duplicate group as not-a-duplicate
        async function ignoreDuplicateGroup(idx) {
            const group = document.getElementById('dupe-group-' + idx);
            const paths = JSON.parse(decodeURIComponent(group.dataset.paths));
            const btn = group.querySelector('.ignore-btn');
            btn.disabled = true;
            btn.textContent = 'Saving...';

            try {
                const params = paths.map(p => 'paths=' + encodeURIComponent(p)).join('&');
                const res = await fetch('/api/duplicates/ignore?' + params, { method: 'POST' });
                const data = await res.json();

                if (res.ok) {
                    group.style.opacity = '0.3';
                    group.style.pointerEvents = 'none';
                    showToast('Marked as not a duplicate');
                    setTimeout(() => group.remove(), 1000);
                    loadStats();
                } else {
                    showToast('Failed: ' + (data.detail || 'Unknown error'), true);
                    btn.disabled = false;
                    btn.textContent = '✓ Not a Duplicate';
                }
            } catch (e) {
                showToast('Error: ' + e.message, true);
                btn.disabled = false;
                btn.textContent = '✓ Not a Duplicate';
            }
        }

        // Clean duplicates
        async function cleanDuplicates(keep) {
            if (!confirm(`Delete all duplicate files, keeping the ${keep} copy of each? This cannot be undone.`)) {
                return;
            }

            document.getElementById('clean-first-btn').disabled = true;
            document.getElementById('clean-largest-btn').disabled = true;

            try {
                const res = await fetch(`/api/duplicates/clean?keep=${keep}`, { method: 'DELETE' });
                const data = await res.json();
                showToast(`Deleted ${data.deleted_count} duplicate files`);
                loadDuplicates();
                loadStats();
            } catch (e) {
                showToast('Error cleaning duplicates', true);
            }

            document.getElementById('clean-first-btn').disabled = false;
            document.getElementById('clean-largest-btn').disabled = false;
        }

        // Load prohibited
        async function loadProhibited() {
            const list = document.getElementById('prohibited-list');
            const loading = document.getElementById('prohibited-loading');

            try {
                const res = await fetch('/api/prohibited');
                const data = await res.json();
                loading.style.display = 'none';

                if (data.deleted.length === 0) {
                    list.innerHTML = '<div class="empty">No prohibited cards have been deleted</div>';
                    return;
                }

                list.innerHTML = `
                    <p style="margin-bottom:15px;">Total deleted: ${data.total_deleted}</p>
                    <table>
                        <thead><tr><th>Path</th><th>Blocked Tags</th><th>Deleted At</th></tr></thead>
                        <tbody>
                            ${data.deleted.map(item => `
                                <tr>
                                    <td style="font-family:monospace;font-size:0.85rem;">${item.path}</td>
                                    <td>${item.tags.map(t => `<span class="tag blocked">${t}</span>`).join('')}</td>
                                    <td>${new Date(item.deleted_at).toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading prohibited log</div>';
            }
        }

        // Load tags
        async function loadTags() {
            const list = document.getElementById('tags-list');
            const loading = document.getElementById('tags-loading');

            try {
                const res = await fetch('/api/tags');
                const data = await res.json();
                loading.style.display = 'none';

                list.innerHTML = `
                    <table>
                        <thead><tr><th>Tag</th><th>Count</th></tr></thead>
                        <tbody>
                            ${data.tags.slice(0, 100).map(([tag, count]) => `
                                <tr>
                                    <td><span class="tag">${tag}</span></td>
                                    <td>${count.toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading tags</div>';
            }
        }

        // Search on Enter
        document.getElementById('search-input').addEventListener('keypress', e => {
            if (e.key === 'Enter') searchCards();
        });

        // Card detail modal
        let currentCardPath = '';

        function closeModal() {
            document.getElementById('card-modal').classList.remove('active');
            currentCardPath = '';
        }

        async function findSimilar() {
            if (!currentCardPath) return;

            const btn = document.getElementById('modal-similar-btn');
            const resultsDiv = document.getElementById('similar-results');
            const cardsDiv = document.getElementById('similar-cards');

            btn.disabled = true;
            btn.textContent = '🔍 Searching...';
            resultsDiv.style.display = 'none';

            try {
                const res = await fetch(`/api/cards/similar?path=${encodeURIComponent(currentCardPath)}&threshold=20`);
                const data = await res.json();

                if (data.similar.length === 0) {
                    cardsDiv.innerHTML = '<p style="color:#888;">No similar cards found</p>';
                } else {
                    cardsDiv.innerHTML = data.similar.map(card => `
                        <div class="dupe-card" data-path="${encodeURIComponent(card.path)}" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                            <button class="delete-btn" onclick="event.stopPropagation(); deleteCardEl(this.parentElement)" title="Delete">✕</button>
                            <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}"
                                 onclick="openCardEl(this.parentElement)"
                                 onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'"
                                 loading="lazy">
                            <div class="info">
                                <h5>${card.name}</h5>
                                <p>${card.creator}</p>
                                <p style="color:#667eea;font-size:0.7rem;">${card.reasons.join(', ')}</p>
                            </div>
                        </div>
                    `).join('');
                }

                resultsDiv.style.display = 'block';
                showToast(`Found ${data.similar.length} similar cards`);
            } catch (e) {
                showToast('Search error: ' + e.message, true);
            }

            btn.disabled = false;
            btn.textContent = '🔍 Find Similar';
        }

        async function deleteFromModal() {
            if (!currentCardPath) return;
            if (!confirm('Delete this card permanently?')) return;

            const btn = document.getElementById('modal-delete-btn');
            btn.disabled = true;
            btn.textContent = 'Deleting...';

            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(currentCardPath)}`, { method: 'DELETE' });
                const data = await res.json();

                if (data.success) {
                    showToast('Card deleted');
                    closeModal();
                    loadStats();
                    searchCards(); // Refresh search results
                    loadDuplicates();
                } else {
                    showToast('Delete failed', true);
                }
            } catch (e) {
                showToast('Delete error', true);
            }
            btn.disabled = false;
            btn.textContent = '🗑️ Delete Card';
        }

        async function openCard(folder, file) {
            const modal = document.getElementById('card-modal');
            modal.classList.add('active');

            // Set image immediately
            document.getElementById('modal-img').src = `/cards/${encodeURIComponent(folder)}/${encodeURIComponent(file)}`;
            document.getElementById('modal-name').textContent = 'Loading...';
            document.getElementById('modal-creator').textContent = '';
            document.getElementById('modal-tags').innerHTML = '';
            document.getElementById('similar-results').style.display = 'none';
            document.getElementById('similar-cards').innerHTML = '';

            try {
                const res = await fetch(`/api/cards/${encodeURIComponent(folder)}/${encodeURIComponent(file)}`);
                const data = await res.json();
                const entry = data.entry;
                const meta = data.full_metadata?.data || data.full_metadata || {};

                document.getElementById('modal-name').textContent = entry.name || meta.name || file;
                document.getElementById('modal-creator').textContent = entry.creator || meta.creator || 'Unknown';
                document.getElementById('modal-folder').textContent = entry.folder + '/' + entry.file;
                document.getElementById('modal-path').textContent = entry.path;
                currentCardPath = entry.path;

                // NSFW badge
                const nsfwBadge = document.getElementById('modal-nsfw');
                nsfwBadge.style.display = entry.nsfw ? 'inline-block' : 'none';

                // Tags
                const tags = entry.tags || meta.tags || [];
                document.getElementById('modal-tags').innerHTML = tags.slice(0, 20).map(t =>
                    `<span class="tag">${t}</span>`
                ).join('') + (tags.length > 20 ? `<span class="tag">+${tags.length - 20} more</span>` : '');

                // Content sections
                const desc = meta.description || entry.description_preview || '';
                const firstMes = meta.first_mes || entry.first_mes_preview || '';
                const personality = meta.personality || '';
                const scenario = meta.scenario || '';
                const mesExample = meta.mes_example || '';

                setSection('description', desc);
                setSection('firstmes', firstMes);
                setSection('personality', personality);
                setSection('scenario', scenario);
                setSection('mesbefore', mesExample);

            } catch (e) {
                document.getElementById('modal-name').textContent = 'Error loading card';
                console.error(e);
            }
        }

        function setSection(id, content) {
            const section = document.getElementById('section-' + id);
            const el = document.getElementById('modal-' + id);
            if (content && content.trim()) {
                section.style.display = 'block';
                el.textContent = content;
            } else {
                section.style.display = 'none';
            }
        }

        // Close modal on Escape
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeModal();
        });

        // Nextcloud scan
        async function triggerNextcloudScan() {
            const btn = document.getElementById('nextcloud-btn');
            const status = document.getElementById('nextcloud-status');

            btn.disabled = true;
            btn.textContent = '☁️ Scanning...';
            status.textContent = 'Scan in progress (this may take a while)...';
            status.style.color = '#f39c12';

            try {
                const res = await fetch('/api/nextcloud/scan', { method: 'POST' });
                const data = await res.json();

                if (data.success) {
                    status.textContent = '✓ Scan completed successfully';
                    status.style.color = '#2ecc71';
                    showToast('Nextcloud scan completed!');
                } else {
                    status.textContent = '✗ Scan failed: ' + (data.error || data.stderr || 'Unknown error');
                    status.style.color = '#e74c3c';
                    showToast('Nextcloud scan failed', true);
                }
            } catch (e) {
                status.textContent = '✗ Error: ' + e.message;
                status.style.color = '#e74c3c';
                showToast('Nextcloud scan error', true);
            }

            btn.disabled = false;
            btn.textContent = '☁️ Refresh Nextcloud';
        }

        // Index rescan
        async function triggerRescan() {
            const btn = document.getElementById('rescan-btn');
            btn.disabled = true;
            btn.textContent = '🔄 Starting...';

            try {
                const res = await fetch('/api/index/rescan', { method: 'POST' });
                if (res.ok) {
                    showToast('Rescan started');
                    checkScanStatus();
                } else {
                    const data = await res.json();
                    showToast(data.detail || 'Failed to start rescan', true);
                    btn.disabled = false;
                    btn.textContent = '🔄 Rescan Index';
                }
            } catch (e) {
                showToast('Error: ' + e.message, true);
                btn.disabled = false;
                btn.textContent = '🔄 Rescan Index';
            }
        }

        // Check scan status
        async function checkScanStatus() {
            try {
                const res = await fetch('/api/index/status');
                const data = await res.json();
                const status = document.getElementById('scan-status');
                const btn = document.getElementById('rescan-btn');

                if (data.scan_running) {
                    const pct = data.scan_total > 0 ? Math.round(data.scan_progress / data.scan_total * 100) : 0;
                    status.textContent = `Scanning... ${data.scan_progress}/${data.scan_total} (${pct}%)`;
                    status.style.color = '#f39c12';
                    btn.disabled = true;
                    btn.textContent = '🔄 Scanning...';
                    setTimeout(checkScanStatus, 2000); // Poll while scanning
                } else {
                    if (data.last_scan) {
                        status.textContent = `${data.cards_indexed} cards indexed`;
                        status.style.color = '#2ecc71';
                    }
                    btn.disabled = false;
                    btn.textContent = '🔄 Rescan Index';
                    loadStats(); // Refresh stats after scan
                }
            } catch (e) {
                console.error('Failed to check scan status:', e);
            }
        }

        // Check Nextcloud status on load
        async function checkNextcloudStatus() {
            try {
                const res = await fetch('/api/nextcloud/status');
                const data = await res.json();
                const status = document.getElementById('nextcloud-status');

                if (data.running) {
                    document.getElementById('nextcloud-btn').disabled = true;
                    status.textContent = 'Scan in progress...';
                    status.style.color = '#f39c12';
                } else if (data.last_scan) {
                    const lastScan = new Date(data.last_scan).toLocaleString();
                    status.textContent = 'Last scan: ' + lastScan;
                    status.style.color = '#888';
                }
            } catch (e) {}
        }

        // Initial load
        loadStats();
        loadDuplicates();
        loadProhibited();
        loadTags();
        searchCards();
        checkScanStatus();
        checkNextcloudStatus();
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the web dashboard."""
    return DASHBOARD_HTML

@app.get("/api/info")
async def api_info():
    return {
        "service": "Character Card Index",
        "version": "2.0.0",
        "total_cards": len(index.cards),
        "prohibited_deleted": len(index.prohibited_deleted),
        "duplicate_groups": len(index.duplicates),
        "config": {
            "auto_delete_prohibited": AUTO_DELETE_PROHIBITED,
            "detect_duplicates": DETECT_DUPLICATES
        },
        "endpoints": {
            "search": "/api/cards",
            "card_detail": "/api/cards/{folder}/{filename}",
            "card_image": "/cards/{folder}/{filename}",
            "stats": "/api/stats",
            "tags": "/api/tags",
            "prohibited": "/api/prohibited",
            "duplicates": "/api/duplicates",
            "clean_duplicates": "DELETE /api/duplicates/clean"
        }
    }

@app.get("/api/cards")
async def search_cards(
    q: Optional[str] = Query(None, description="Search query"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    nsfw: Optional[bool] = Query(None, description="Filter by NSFW"),
    creator: Optional[str] = Query(None, description="Filter by creator"),
    folder: Optional[str] = Query(None, description="Filter by folder (chub/booru)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Search character cards with filters."""
    tag_list = [t.strip() for t in tags.split(",")] if tags else None

    results, total = index.search(
        query=q,
        tags=tag_list,
        nsfw=nsfw,
        creator=creator,
        folder=folder,
        limit=limit,
        offset=offset
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": [asdict(c) for c in results]
    }

@app.get("/api/cards/{folder}/{filename}")
async def get_card(folder: str, filename: str):
    """Get full metadata for a specific card."""
    # Find the card
    for path, entry in index.cards.items():
        if entry.folder == folder and entry.file == filename:
            # Get full metadata from file
            metadata = index.extract_metadata(path)
            return {
                "entry": asdict(entry),
                "full_metadata": metadata
            }

    raise HTTPException(status_code=404, detail="Card not found")

@app.get("/cards/{folder}/{filename}")
async def serve_card_image(folder: str, filename: str):
    """Serve the actual card PNG file."""
    for path, entry in index.cards.items():
        if entry.folder == folder and entry.file == filename:
            return FileResponse(path, media_type="image/png")

    raise HTTPException(status_code=404, detail="Card not found")

@app.get("/api/stats")
async def get_stats():
    """Get index statistics."""
    all_tags = {}
    creators = {}
    nsfw_count = 0
    sfw_count = 0
    folders = {}

    for entry in index.cards.values():
        for tag in entry.tags:
            all_tags[tag] = all_tags.get(tag, 0) + 1
        creators[entry.creator] = creators.get(entry.creator, 0) + 1
        folders[entry.folder] = folders.get(entry.folder, 0) + 1
        if entry.nsfw:
            nsfw_count += 1
        else:
            sfw_count += 1

    # Sort tags by count
    top_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:100]
    top_creators = sorted(creators.items(), key=lambda x: x[1], reverse=True)[:50]

    return {
        "total_cards": len(index.cards),
        "nsfw_count": nsfw_count,
        "sfw_count": sfw_count,
        "unique_creators": len(creators),
        "unique_tags": len(all_tags),
        "prohibited_deleted": len(index.prohibited_deleted),
        "content_duplicate_groups": len([p for p in index.duplicates.values() if len(p) > 1]),
        "image_duplicate_groups": len([p for p in index.image_duplicates.values() if len(p) > 1]),
        "image_hash_enabled": IMAGE_HASH_AVAILABLE,
        "top_tags": top_tags,
        "top_creators": top_creators,
        "folders": folders
    }

@app.get("/api/tags")
async def get_tags():
    """Get all unique tags with counts."""
    all_tags = {}
    for entry in index.cards.values():
        for tag in entry.tags:
            all_tags[tag] = all_tags.get(tag, 0) + 1

    sorted_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)
    return {"tags": sorted_tags}

@app.get("/api/prohibited")
async def get_prohibited():
    """Get list of prohibited cards that were deleted."""
    return {
        "total_deleted": len(index.prohibited_deleted),
        "auto_delete_enabled": AUTO_DELETE_PROHIBITED,
        "deleted": index.prohibited_deleted[-100:]  # Last 100
    }

@app.get("/api/duplicates")
async def get_duplicates():
    """Get list of detected duplicate cards (content and image based)."""

    def get_card_info(path: str) -> dict:
        """Get card info for display."""
        entry = index.cards.get(path)
        if entry:
            return {
                "path": path,
                "name": entry.name,
                "creator": entry.creator,
                "folder": entry.folder,
                "file": entry.file,
                "nsfw": entry.nsfw
            }
        return {"path": path, "name": Path(path).stem, "creator": "Unknown", "folder": "", "file": Path(path).name, "nsfw": False}

    def is_ignored(paths: List[str]) -> bool:
        """Check if this duplicate group has been marked as not-a-duplicate.
        Only hides if EXACT same paths - any new file will show the group again."""
        path_set = frozenset(paths)
        # Only exact match - if new files added, show again
        return path_set in index.ignored_duplicates

    # Content-based duplicates
    content_dupes = []
    for content_hash, paths in index.duplicates.items():
        if len(paths) > 1:
            # Skip if marked as non-duplicate
            if is_ignored(paths):
                continue
            content_dupes.append({
                "type": "content",
                "hash": content_hash,
                "count": len(paths),
                "cards": [get_card_info(p) for p in paths]
            })

    # Image-based duplicates
    image_dupes = []
    for image_hash, paths in index.image_duplicates.items():
        if len(paths) > 1:
            # Filter paths to only include cards with similar names
            cards_info = [(p, get_card_info(p)) for p in paths if os.path.exists(p)]
            if len(cards_info) < 2:
                continue

            # Verify name similarity - group by similar names
            filtered_cards = [cards_info[0]]
            base_name = cards_info[0][1]["name"]
            for p, info in cards_info[1:]:
                if name_similarity(base_name, info["name"]) > 0.3:
                    filtered_cards.append((p, info))

            if len(filtered_cards) < 2:
                continue

            # Skip if already caught by content hash
            content_hashes_in_group = set()
            for p, _ in filtered_cards:
                entry = index.cards.get(p)
                if entry and entry.content_hash:
                    content_hashes_in_group.add(entry.content_hash)
            # Only add if not all same content hash (would be redundant)
            if len(content_hashes_in_group) > 1 or len(content_hashes_in_group) == 0:
                # Skip if marked as non-duplicate
                filtered_paths = [p for p, _ in filtered_cards]
                if is_ignored(filtered_paths):
                    continue
                image_dupes.append({
                    "type": "image",
                    "hash": image_hash,
                    "count": len(filtered_cards),
                    "cards": [info for _, info in filtered_cards]
                })

    # Combine and sort by count
    all_dupes = content_dupes + image_dupes
    all_dupes.sort(key=lambda x: x["count"], reverse=True)

    return {
        "content_duplicate_groups": len(content_dupes),
        "image_duplicate_groups": len(image_dupes),
        "total_duplicate_groups": len(all_dupes),
        "total_duplicate_files": sum(d["count"] - 1 for d in all_dupes),
        "detect_enabled": DETECT_DUPLICATES,
        "image_hash_enabled": IMAGE_HASH_AVAILABLE,
        "duplicates": all_dupes[:100]  # Top 100 groups
    }

@app.get("/api/cards/similar")
async def find_similar_cards(
    path: str = Query(None, description="Path to card to find similar to"),
    folder: str = Query(None, description="Folder of card"),
    file: str = Query(None, description="Filename of card"),
    threshold: int = Query(18, description="Image hash distance threshold (higher = more matches)")
):
    """Find cards similar to a given card (by image and/or name)."""
    # Find the source card
    source_entry = None
    source_path = path

    if path and path in index.cards:
        source_entry = index.cards[path]
    elif folder and file:
        for p, entry in index.cards.items():
            if entry.folder == folder and entry.file == file:
                source_entry = entry
                source_path = p
                break

    if not source_entry:
        raise HTTPException(status_code=404, detail="Source card not found")

    similar = []
    source_hash = index.image_hash_objects.get(source_path)

    for card_path, entry in index.cards.items():
        if card_path == source_path:
            continue

        similarity_score = 0
        match_reasons = []

        # Check name similarity
        name_sim = name_similarity(source_entry.name, entry.name)
        if name_sim > 0.3:
            similarity_score += name_sim * 50
            match_reasons.append(f"name ({int(name_sim*100)}%)")

        # Check image similarity
        if source_hash and IMAGE_HASH_AVAILABLE:
            card_hash = index.image_hash_objects.get(card_path)
            if card_hash:
                distance = source_hash - card_hash
                if distance <= threshold:
                    img_score = (threshold - distance) / threshold * 50
                    similarity_score += img_score
                    match_reasons.append(f"image (dist={distance})")

        # Check creator match
        if source_entry.creator.lower() == entry.creator.lower() and source_entry.creator.lower() != "unknown":
            similarity_score += 10
            match_reasons.append("same creator")

        if similarity_score > 20:
            similar.append({
                "path": card_path,
                "folder": entry.folder,
                "file": entry.file,
                "name": entry.name,
                "creator": entry.creator,
                "nsfw": entry.nsfw,
                "score": round(similarity_score, 1),
                "reasons": match_reasons
            })

    # Sort by score descending
    similar.sort(key=lambda x: x["score"], reverse=True)

    return {
        "source": {
            "path": source_path,
            "name": source_entry.name,
            "folder": source_entry.folder,
            "file": source_entry.file
        },
        "similar_count": len(similar),
        "similar": similar[:50]  # Top 50
    }


@app.post("/api/cards/upload")
async def upload_card(
    file: UploadFile = File(..., description="PNG character card file"),
    folder: str = Form(default="Uploads", description="Subfolder to save to")
):
    """Upload a character card to the server."""
    if not file.filename.lower().endswith('.png'):
        raise HTTPException(status_code=400, detail="Only PNG files are supported")

    # Use first configured directory as upload destination
    if not CARD_DIRS or not CARD_DIRS[0]:
        raise HTTPException(status_code=500, detail="No card directories configured")

    base_dir = CARD_DIRS[0]

    # Sanitize folder name
    safe_folder = "".join(c for c in folder if c.isalnum() or c in " -_").strip() or "Uploads"
    upload_dir = os.path.join(base_dir, safe_folder)

    try:
        os.makedirs(upload_dir, exist_ok=True)

        # Sanitize filename
        safe_filename = "".join(c for c in file.filename if c.isalnum() or c in " -_.").strip()
        if not safe_filename.lower().endswith('.png'):
            safe_filename += '.png'

        filepath = os.path.join(upload_dir, safe_filename)

        # Check if file already exists
        if os.path.exists(filepath):
            # Add number suffix
            base, ext = os.path.splitext(safe_filename)
            counter = 1
            while os.path.exists(filepath):
                safe_filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(upload_dir, safe_filename)
                counter += 1

        # Save the file
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"Uploaded card: {filepath}")

        # Index immediately (file watcher will also pick it up, but this is faster)
        entry = index.index_card(filepath, delete_prohibited=True)
        if entry:
            index.cards[filepath] = entry
            # Save index
            index.save_index()
            return {
                "success": True,
                "path": filepath,
                "folder": safe_folder,
                "file": safe_filename,
                "name": entry.name,
                "indexed": True
            }
        else:
            # File was deleted (prohibited) or has no valid metadata
            # Check if file still exists to determine reason
            if os.path.exists(filepath):
                # File exists but no metadata - delete it
                os.remove(filepath)
                return {
                    "success": False,
                    "detail": "Invalid character card: no embedded metadata found"
                }
            else:
                # File was deleted due to prohibited content
                return {
                    "success": False,
                    "detail": "Card rejected: prohibited content detected"
                }

    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/cards/delete")
async def delete_card(path: str = Query(..., description="Full path to the card file")):
    """Delete a single card file."""
    if not path:
        raise HTTPException(status_code=400, detail="Path required")

    try:
        if os.path.exists(path):
            os.remove(path)
            # Remove from index
            if path in index.cards:
                del index.cards[path]
            # Remove from duplicate tracking
            for hash_key, paths in list(index.duplicates.items()):
                if path in paths:
                    paths.remove(path)
            for hash_key, paths in list(index.image_duplicates.items()):
                if path in paths:
                    paths.remove(path)
            if path in index.image_hash_objects:
                del index.image_hash_objects[path]

            logger.info(f"Deleted card: {path}")
            return {"success": True, "deleted": path}
        else:
            raise HTTPException(status_code=404, detail="File not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete {path}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/duplicates/ignore")
async def ignore_duplicate_group(paths: List[str] = Query(..., description="Paths in the duplicate group to ignore")):
    """Mark a group of cards as NOT duplicates (persists between scans)."""
    if len(paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 paths")

    # Add to ignored set
    ignored_set = frozenset(paths)
    index.ignored_duplicates.add(ignored_set)

    # Save index to persist
    index.save_index()

    logger.info(f"Marked as non-duplicate: {paths}")
    return {"status": "Marked as non-duplicate", "paths": paths}


@app.delete("/api/duplicates/unignore")
async def unignore_duplicate_group(paths: List[str] = Query(..., description="Paths to remove from ignore list")):
    """Remove a group from the ignored duplicates list."""
    ignored_set = frozenset(paths)
    if ignored_set in index.ignored_duplicates:
        index.ignored_duplicates.remove(ignored_set)
        index.save_index()
        return {"status": "Removed from ignore list", "paths": paths}
    return {"status": "Not found in ignore list", "paths": paths}


@app.get("/api/duplicates/ignored")
async def get_ignored_duplicates():
    """Get list of ignored duplicate groups."""
    return {
        "count": len(index.ignored_duplicates),
        "ignored": [list(s) for s in index.ignored_duplicates]
    }


@app.delete("/api/duplicates/clean")
async def clean_duplicates(
    keep: str = Query("first", description="Which to keep: 'first' or 'largest'"),
    type: str = Query("all", description="Which duplicates to clean: 'content', 'image', or 'all'")
):
    """Delete duplicate files, keeping one copy of each."""
    if not DETECT_DUPLICATES:
        raise HTTPException(status_code=400, detail="Duplicate detection is disabled")

    deleted = []
    already_deleted = set()

    def clean_group(paths: List[str]):
        if len(paths) <= 1:
            return

        # Filter out already deleted
        valid_paths = [p for p in paths if p not in already_deleted and os.path.exists(p)]
        if len(valid_paths) <= 1:
            return

        # Decide which to keep
        if keep == "largest":
            paths_with_size = [(p, os.path.getsize(p)) for p in valid_paths]
            paths_with_size.sort(key=lambda x: x[1], reverse=True)
            keep_path = paths_with_size[0][0]
            delete_paths = [p for p, _ in paths_with_size[1:]]
        else:
            keep_path = valid_paths[0]
            delete_paths = valid_paths[1:]

        for path in delete_paths:
            try:
                if os.path.exists(path) and path not in already_deleted:
                    os.remove(path)
                    deleted.append(path)
                    already_deleted.add(path)
                    if path in index.cards:
                        del index.cards[path]
                    logger.info(f"Deleted duplicate: {path}")
            except Exception as e:
                logger.error(f"Failed to delete duplicate {path}: {e}")

    # Clean content duplicates
    if type in ["all", "content"]:
        for paths in index.duplicates.values():
            clean_group(paths)
        index.duplicates.clear()
        index.content_hashes.clear()

    # Clean image duplicates
    if type in ["all", "image"]:
        for paths in index.image_duplicates.values():
            clean_group(paths)
        index.image_duplicates.clear()
        index.image_hashes.clear()

    return {
        "deleted_count": len(deleted),
        "deleted_files": deleted[:100]
    }


# Nextcloud scan tracking
nextcloud_scan_status = {"running": False, "last_scan": None, "last_result": None}

@app.post("/api/nextcloud/scan")
async def trigger_nextcloud_scan(user: str = Query(None, description="Nextcloud user to scan (default: from config)")):
    """Trigger a Nextcloud file scan (snap-based)."""
    global nextcloud_scan_status

    if nextcloud_scan_status["running"]:
        raise HTTPException(status_code=409, detail="Scan already in progress")

    scan_user = user or NEXTCLOUD_USER
    nextcloud_scan_status["running"] = True

    try:
        # Run nextcloud.occ files:scan for snap-based install
        logger.info(f"Starting Nextcloud scan for user: {scan_user}")
        result = subprocess.run(
            ["sudo", "nextcloud.occ", "files:scan", scan_user],
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )

        nextcloud_scan_status["last_scan"] = datetime.utcnow().isoformat()
        nextcloud_scan_status["last_result"] = {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",  # Last 2000 chars
            "stderr": result.stderr[-1000:] if result.stderr else ""
        }

        if result.returncode == 0:
            logger.info(f"Nextcloud scan completed successfully")
        else:
            logger.error(f"Nextcloud scan failed: {result.stderr}")

        return nextcloud_scan_status["last_result"]

    except subprocess.TimeoutExpired:
        nextcloud_scan_status["last_result"] = {"success": False, "error": "Scan timed out after 1 hour"}
        raise HTTPException(status_code=504, detail="Scan timed out")
    except Exception as e:
        nextcloud_scan_status["last_result"] = {"success": False, "error": str(e)}
        logger.error(f"Nextcloud scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        nextcloud_scan_status["running"] = False

@app.get("/api/nextcloud/status")
async def get_nextcloud_status():
    """Get Nextcloud scan status."""
    return nextcloud_scan_status


@app.get("/api/index/status")
async def get_index_status():
    """Get index scan status."""
    return {
        "cards_indexed": len(index.cards),
        "scan_running": index.scan_status["running"],
        "scan_progress": index.scan_status["progress"],
        "scan_total": index.scan_status["total"],
        "last_scan": index.scan_status["last_scan"]
    }


@app.post("/api/index/rescan")
async def trigger_rescan():
    """Trigger a full rescan of all directories."""
    if index.scan_status["running"]:
        raise HTTPException(status_code=409, detail="Scan already in progress")

    asyncio.create_task(background_scan())
    return {"status": "Rescan started"}


@app.post("/api/index/save")
async def save_index_now():
    """Manually save the index to disk."""
    if index.save_index():
        return {"status": "Index saved", "cards": len(index.cards)}
    raise HTTPException(status_code=500, detail="Failed to save index")


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)

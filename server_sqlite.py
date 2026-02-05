#!/usr/bin/env python3
"""
Character Card Index Server - SQLite Edition
Monitors folders for character cards, indexes metadata, serves search API.
Auto-deletes prohibited content and detects duplicates.

Uses SQLite + FTS5 for fast full-text search at scale (200k+ cards).

Configuration via environment variables:
  CARD_DIRS           - Colon-separated list of directories to index
  CARD_HOST           - Host to bind to (default: 0.0.0.0)
  CARD_PORT           - Port to bind to (default: 8787)
  CARD_AUTO_DELETE    - Auto-delete prohibited content (default: true)
  CARD_DETECT_DUPES   - Detect duplicates (default: true)
  CARD_DB_FILE        - SQLite database file (default: /var/lib/card-index/cards.db)
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
import sqlite3
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict, field
from contextlib import contextmanager
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
NEXTCLOUD_USER = os.environ.get("NEXTCLOUD_USER", "")
DB_FILE = os.environ.get("CARD_DB_FILE", "/var/lib/card-index/cards.db")

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

# Additional patterns for description scanning
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
    re.compile(r'\bage\s*[:\-]?\s*([1-9]|1[0-7])\b', re.IGNORECASE),
    re.compile(r'\b([1-9]|1[0-7])[-\s]*(years?|yrs?|y/?o)[-\s]*old\b', re.IGNORECASE),
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
    "furry", "kemono", "anthro",
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
    n1 = re.sub(r'[^a-z0-9\s]', '', name1.lower()).split()
    n2 = re.sub(r'[^a-z0-9\s]', '', name2.lower()).split()

    if not n1 or not n2:
        return 0.0

    significant1 = {w for w in n1 if len(w) > 2}
    significant2 = {w for w in n2 if len(w) > 2}

    if not significant1 or not significant2:
        return 1.0 if n1[0] == n2[0] else 0.0

    common = significant1 & significant2
    if common:
        return len(common) / min(len(significant1), len(significant2))

    return 0.0


def check_prohibited_tags(tags: List[str]) -> Tuple[bool, set]:
    """Check if tags contain prohibited content."""
    tags_lower = [t.lower() for t in tags]
    blocked_found = set()

    for tag in tags_lower:
        if tag in BLOCKED_TAGS_EXACT:
            blocked_found.add(tag)
        else:
            for pattern in BLOCKED_PATTERNS:
                if pattern.search(tag):
                    blocked_found.add(tag)
                    break

    return bool(blocked_found), blocked_found


def check_prohibited_description(description: str) -> Tuple[bool, set]:
    """Check if description contains prohibited content."""
    if not description:
        return False, set()

    blocked_found = set()

    for pattern in BLOCKED_DESCRIPTION_PATTERNS:
        match = pattern.search(description)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(description), match.end() + 20)
            snippet = description[start:end].replace('\n', ' ')
            blocked_found.add(f"desc: ...{snippet}...")

    return bool(blocked_found), blocked_found


def check_prohibited_content(tags: List[str], description: str = "", first_mes: str = "") -> Tuple[bool, set]:
    """Check tags and description for prohibited content."""
    blocked_found = set()

    tag_prohibited, tag_matches = check_prohibited_tags(tags)
    blocked_found.update(tag_matches)

    desc_prohibited, desc_matches = check_prohibited_description(description)
    blocked_found.update(desc_matches)

    first_mes_prohibited, first_mes_matches = check_prohibited_description(first_mes)
    blocked_found.update(first_mes_matches)

    return bool(blocked_found), blocked_found


def check_nsfw_content(tags: List[str], description: str = "", first_mes: str = "") -> bool:
    """Check if content should be marked as NSFW."""
    tags_lower = {t.lower() for t in tags}
    if tags_lower & NSFW_TAGS:
        return True

    text_to_check = f"{description} {first_mes}"
    for pattern in NSFW_DESCRIPTION_PATTERNS:
        if pattern.search(text_to_check):
            return True

    return False


@dataclass
class CardEntry:
    """Card data structure - matches original API response format."""
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
    content_hash: str = ""
    image_hash: str = ""


class CardIndexDB:
    """SQLite-based card index with FTS5 full-text search."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._local = threading.local()

        # In-memory caches for image hash comparison (needed for fuzzy matching)
        self.image_hash_objects: Dict[str, Any] = {}

        # Scan status
        self.scan_status = {"running": False, "progress": 0, "total": 0, "last_scan": None}

        # Initialize database
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent read/write
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return self._local.conn

    @contextmanager
    def _cursor(self):
        """Context manager for database cursor."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def _init_db(self):
        """Initialize database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._cursor() as cur:
            # Main cards table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    file TEXT NOT NULL,
                    folder TEXT NOT NULL,
                    name TEXT NOT NULL,
                    creator TEXT DEFAULT 'Unknown',
                    tags TEXT DEFAULT '[]',
                    nsfw INTEGER DEFAULT 0,
                    description_preview TEXT DEFAULT '',
                    first_mes_preview TEXT DEFAULT '',
                    indexed_at TEXT NOT NULL,
                    content_hash TEXT DEFAULT '',
                    image_hash TEXT DEFAULT '',
                    file_mtime REAL DEFAULT 0
                )
            """)

            # FTS5 virtual table for full-text search
            cur.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cards_fts USING fts5(
                    name,
                    creator,
                    description_preview,
                    tags_text,
                    content='cards',
                    content_rowid='id',
                    tokenize='porter unicode61'
                )
            """)

            # Triggers to keep FTS in sync
            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS cards_ai AFTER INSERT ON cards BEGIN
                    INSERT INTO cards_fts(rowid, name, creator, description_preview, tags_text)
                    VALUES (new.id, new.name, new.creator, new.description_preview, new.tags);
                END
            """)

            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS cards_ad AFTER DELETE ON cards BEGIN
                    INSERT INTO cards_fts(cards_fts, rowid, name, creator, description_preview, tags_text)
                    VALUES ('delete', old.id, old.name, old.creator, old.description_preview, old.tags);
                END
            """)

            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS cards_au AFTER UPDATE ON cards BEGIN
                    INSERT INTO cards_fts(cards_fts, rowid, name, creator, description_preview, tags_text)
                    VALUES ('delete', old.id, old.name, old.creator, old.description_preview, old.tags);
                    INSERT INTO cards_fts(rowid, name, creator, description_preview, tags_text)
                    VALUES (new.id, new.name, new.creator, new.description_preview, new.tags);
                END
            """)

            # Prohibited deletions log
            cur.execute("""
                CREATE TABLE IF NOT EXISTS prohibited_deleted (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    deleted_at TEXT NOT NULL
                )
            """)

            # Ignored duplicates
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ignored_duplicates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    paths_hash TEXT UNIQUE NOT NULL,
                    paths TEXT NOT NULL
                )
            """)

            # Indexes for fast lookups
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_content_hash ON cards(content_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_image_hash ON cards(image_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_folder ON cards(folder)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_creator ON cards(creator)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_nsfw ON cards(nsfw)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_path ON cards(path)")

        logger.info(f"Database initialized at {self.db_path}")

    def _row_to_entry(self, row: sqlite3.Row) -> CardEntry:
        """Convert database row to CardEntry."""
        tags = json.loads(row['tags']) if row['tags'] else []
        return CardEntry(
            file=row['file'],
            path=row['path'],
            folder=row['folder'],
            name=row['name'],
            creator=row['creator'],
            tags=tags,
            nsfw=bool(row['nsfw']),
            description_preview=row['description_preview'],
            first_mes_preview=row['first_mes_preview'],
            indexed_at=row['indexed_at'],
            content_hash=row['content_hash'] or '',
            image_hash=row['image_hash'] or ''
        )

    def get_card_count(self) -> int:
        """Get total number of indexed cards."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cards")
            return cur.fetchone()[0]

    def get_card_by_path(self, path: str) -> Optional[CardEntry]:
        """Get card by file path."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM cards WHERE path = ?", (path,))
            row = cur.fetchone()
            return self._row_to_entry(row) if row else None

    def get_all_cards(self) -> Dict[str, CardEntry]:
        """Get all cards as dict (for compatibility)."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM cards")
            return {row['path']: self._row_to_entry(row) for row in cur.fetchall()}

    def card_exists(self, path: str) -> bool:
        """Check if card exists in index."""
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM cards WHERE path = ? LIMIT 1", (path,))
            return cur.fetchone() is not None

    def get_file_mtime(self, path: str) -> Optional[float]:
        """Get stored file modification time."""
        with self._cursor() as cur:
            cur.execute("SELECT file_mtime FROM cards WHERE path = ?", (path,))
            row = cur.fetchone()
            return row[0] if row else None

    def calculate_image_hash(self, filepath: str) -> Optional[str]:
        """Calculate perceptual hash of image."""
        if not IMAGE_HASH_AVAILABLE:
            return None
        try:
            with Image.open(filepath) as img:
                phash = imagehash.dhash(img, hash_size=12)
                self.image_hash_objects[filepath] = phash
                return str(phash)
        except Exception as e:
            logger.debug(f"Failed to hash image {filepath}: {e}")
            return None

    def find_similar_image(self, filepath: str, hash_obj, threshold: int = 12) -> Optional[str]:
        """Find existing card with similar image hash."""
        if not IMAGE_HASH_AVAILABLE:
            return None
        for existing_path, existing_hash in self.image_hash_objects.items():
            if existing_path == filepath:
                continue
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

    def add_prohibited_deleted(self, path: str, tags: List[str]):
        """Log a prohibited card deletion."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO prohibited_deleted (path, tags, deleted_at) VALUES (?, ?, ?)",
                (path, json.dumps(list(tags)), datetime.utcnow().isoformat())
            )

    def get_prohibited_deleted(self, limit: int = 100) -> List[dict]:
        """Get list of prohibited deleted cards."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT path, tags, deleted_at FROM prohibited_deleted ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            return [
                {"path": row[0], "tags": json.loads(row[1]), "deleted_at": row[2]}
                for row in cur.fetchall()
            ]

    def get_prohibited_count(self) -> int:
        """Get count of prohibited deletions."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM prohibited_deleted")
            return cur.fetchone()[0]

    def index_card(self, filepath: str, delete_prohibited: bool = True) -> Optional[CardEntry]:
        """Index a single card file."""
        metadata = self.extract_metadata(filepath)
        if not metadata:
            return None

        data = metadata.get("data", metadata)
        tags = data.get("tags", [])
        description = data.get("description", "")
        first_mes = data.get("first_mes", "")

        # Check for prohibited content
        if AUTO_DELETE_PROHIBITED or delete_prohibited:
            is_prohibited, blocked_items = check_prohibited_content(tags, description, first_mes)
            if is_prohibited:
                logger.warning(f"PROHIBITED: {filepath} - Matches: {blocked_items}")
                self.add_prohibited_deleted(filepath, blocked_items)
                try:
                    os.remove(filepath)
                    logger.info(f"DELETED prohibited: {filepath}")
                except Exception as e:
                    logger.error(f"Failed to delete {filepath}: {e}")
                return None

        # Determine NSFW
        nsfw = check_nsfw_content(tags, description, first_mes)

        folder = Path(filepath).parent.name
        filename = Path(filepath).name

        # Calculate content hash
        content_hash = ""
        if DETECT_DUPLICATES:
            hash_content = json.dumps({
                "name": data.get("name", ""),
                "description": description,
                "first_mes": first_mes,
                "personality": data.get("personality", ""),
                "scenario": data.get("scenario", "")
            }, sort_keys=True)
            content_hash = hashlib.md5(hash_content.encode()).hexdigest()

        # Calculate image hash
        image_hash = ""
        if IMAGE_HASH_AVAILABLE:
            image_hash = self.calculate_image_hash(filepath) or ""

        # Get file modification time
        try:
            file_mtime = os.path.getmtime(filepath)
        except:
            file_mtime = 0

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

        # Insert or update in database
        with self._cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO cards
                (path, file, folder, name, creator, tags, nsfw, description_preview,
                 first_mes_preview, indexed_at, content_hash, image_hash, file_mtime)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.path, entry.file, entry.folder, entry.name, entry.creator,
                json.dumps(entry.tags), int(entry.nsfw), entry.description_preview,
                entry.first_mes_preview, entry.indexed_at, entry.content_hash,
                entry.image_hash, file_mtime
            ))

        return entry

    async def add_card(self, filepath: str):
        """Add or update a card in the index."""
        if not filepath.lower().endswith('.png'):
            return

        entry = self.index_card(filepath)
        if entry:
            logger.info(f"Indexed: {entry.name} ({entry.file})")

    async def remove_card(self, filepath: str):
        """Remove a card from the index."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM cards WHERE path = ?", (filepath,))
            if cur.rowcount > 0:
                logger.info(f"Removed from index: {filepath}")

        # Also remove from image hash cache
        if filepath in self.image_hash_objects:
            del self.image_hash_objects[filepath]

    async def full_scan(self, directories: List[str], recursive: bool = True):
        """Perform full scan of directories."""
        logger.info(f"Starting full index scan (recursive={recursive})...")
        count = 0
        processed = 0

        # Get existing paths to detect removed files
        existing_paths = set()
        with self._cursor() as cur:
            cur.execute("SELECT path FROM cards")
            existing_paths = {row[0] for row in cur.fetchall()}

        found_paths = set()

        for directory in directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory not found: {directory}")
                continue

            if recursive:
                for root, dirs, files in os.walk(directory):
                    await asyncio.sleep(0)  # Yield to keep server responsive
                    for filename in files:
                        if filename.lower().endswith('.png'):
                            filepath = os.path.join(root, filename)
                            found_paths.add(filepath)
                            processed += 1
                            self.scan_status["progress"] = processed

                            # Check if file needs re-indexing
                            try:
                                file_mtime = os.path.getmtime(filepath)
                                stored_mtime = self.get_file_mtime(filepath)

                                if stored_mtime is not None and abs(file_mtime - stored_mtime) < 1:
                                    # File unchanged, skip
                                    count += 1
                                    continue
                            except:
                                pass

                            entry = self.index_card(filepath)
                            if entry:
                                count += 1
                                if count % 100 == 0:
                                    await asyncio.sleep(0)
                                if count % 5000 == 0:
                                    logger.info(f"Indexed {count} cards...")
            else:
                for filename in os.listdir(directory):
                    if filename.lower().endswith('.png'):
                        filepath = os.path.join(directory, filename)
                        found_paths.add(filepath)
                        processed += 1
                        self.scan_status["progress"] = processed

                        try:
                            file_mtime = os.path.getmtime(filepath)
                            stored_mtime = self.get_file_mtime(filepath)

                            if stored_mtime is not None and abs(file_mtime - stored_mtime) < 1:
                                count += 1
                                continue
                        except:
                            pass

                        entry = self.index_card(filepath)
                        if entry:
                            count += 1
                            if count % 100 == 0:
                                await asyncio.sleep(0)
                            if count % 5000 == 0:
                                logger.info(f"Indexed {count} cards...")

        # Remove cards that no longer exist on disk
        removed_paths = existing_paths - found_paths
        if removed_paths:
            logger.info(f"Removing {len(removed_paths)} cards no longer on disk...")
            with self._cursor() as cur:
                for path in removed_paths:
                    cur.execute("DELETE FROM cards WHERE path = ?", (path,))
                    if path in self.image_hash_objects:
                        del self.image_hash_objects[path]

        logger.info(f"Full scan complete. Total cards indexed: {self.get_card_count()}")

    def search(
        self,
        query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        nsfw: Optional[bool] = None,
        creator: Optional[str] = None,
        folder: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[CardEntry], int]:
        """Search the index with filters using FTS5."""

        conditions = []
        params = []

        # Use FTS5 for text search
        if query:
            # Escape special FTS5 characters and create search query
            safe_query = query.replace('"', '""')
            conditions.append("cards.id IN (SELECT rowid FROM cards_fts WHERE cards_fts MATCH ?)")
            # Use prefix search for partial matching
            params.append(f'"{safe_query}"*')

        # Tag filtering
        if tags:
            for tag in tags:
                conditions.append("cards.tags LIKE ?")
                params.append(f'%"{tag}"%')

        # NSFW filter
        if nsfw is not None:
            conditions.append("cards.nsfw = ?")
            params.append(int(nsfw))

        # Creator filter
        if creator:
            conditions.append("cards.creator LIKE ?")
            params.append(f'%{creator}%')

        # Folder filter
        if folder:
            conditions.append("cards.folder = ?")
            params.append(folder)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with self._cursor() as cur:
            # Get total count
            cur.execute(f"SELECT COUNT(*) FROM cards WHERE {where_clause}", params)
            total = cur.fetchone()[0]

            # Get paginated results
            cur.execute(
                f"SELECT * FROM cards WHERE {where_clause} ORDER BY indexed_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            results = [self._row_to_entry(row) for row in cur.fetchall()]

        return results, total

    def get_duplicates(self) -> Dict[str, List[str]]:
        """Get content hash duplicates."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT content_hash, GROUP_CONCAT(path, '|||') as paths
                FROM cards
                WHERE content_hash != ''
                GROUP BY content_hash
                HAVING COUNT(*) > 1
            """)
            return {
                row[0]: row[1].split('|||')
                for row in cur.fetchall()
            }

    def get_image_duplicates(self) -> Dict[str, List[str]]:
        """Get image hash duplicates."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT image_hash, GROUP_CONCAT(path, '|||') as paths
                FROM cards
                WHERE image_hash != ''
                GROUP BY image_hash
                HAVING COUNT(*) > 1
            """)
            return {
                row[0]: row[1].split('|||')
                for row in cur.fetchall()
            }

    def is_duplicate_ignored(self, paths: List[str]) -> bool:
        """Check if duplicate group is ignored."""
        paths_hash = hashlib.md5(json.dumps(sorted(paths)).encode()).hexdigest()
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM ignored_duplicates WHERE paths_hash = ?", (paths_hash,))
            return cur.fetchone() is not None

    def ignore_duplicate(self, paths: List[str]):
        """Mark duplicate group as ignored."""
        paths_hash = hashlib.md5(json.dumps(sorted(paths)).encode()).hexdigest()
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO ignored_duplicates (paths_hash, paths) VALUES (?, ?)",
                (paths_hash, json.dumps(paths))
            )

    def delete_card(self, path: str) -> bool:
        """Delete a card from disk and index."""
        try:
            if os.path.exists(path):
                os.remove(path)
            with self._cursor() as cur:
                cur.execute("DELETE FROM cards WHERE path = ?", (path,))
            if path in self.image_hash_objects:
                del self.image_hash_objects[path]
            return True
        except Exception as e:
            logger.error(f"Failed to delete {path}: {e}")
            return False

    def get_stats(self) -> dict:
        """Get index statistics."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cards")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM cards WHERE nsfw = 1")
            nsfw_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT creator) FROM cards")
            unique_creators = cur.fetchone()[0]

            cur.execute("SELECT folder, COUNT(*) FROM cards GROUP BY folder")
            folders = {row[0]: row[1] for row in cur.fetchall()}

            # Top creators
            cur.execute("""
                SELECT creator, COUNT(*) as cnt FROM cards
                GROUP BY creator ORDER BY cnt DESC LIMIT 50
            """)
            top_creators = [(row[0], row[1]) for row in cur.fetchall()]

        return {
            "total_cards": total,
            "nsfw_count": nsfw_count,
            "sfw_count": total - nsfw_count,
            "unique_creators": unique_creators,
            "folders": folders,
            "top_creators": top_creators
        }

    def get_all_tags(self) -> List[Tuple[str, int]]:
        """Get all tags with counts."""
        all_tags = {}
        with self._cursor() as cur:
            cur.execute("SELECT tags FROM cards")
            for row in cur.fetchall():
                tags = json.loads(row[0]) if row[0] else []
                for tag in tags:
                    all_tags[tag] = all_tags.get(tag, 0) + 1

        return sorted(all_tags.items(), key=lambda x: x[1], reverse=True)

    def save_index(self, filepath: str = None):
        """No-op for compatibility - SQLite auto-persists."""
        logger.info("Index auto-saved (SQLite)")
        return True

    def load_index(self, filepath: str = None) -> bool:
        """Check if database has data."""
        return self.get_card_count() > 0


# File watcher handler
class CardFileHandler(FileSystemEventHandler):
    def __init__(self, index: CardIndexDB, loop: asyncio.AbstractEventLoop):
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
app = FastAPI(title="Character Card Index", version="2.0.0-sqlite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

index = CardIndexDB()
observer = None


@app.on_event("startup")
async def startup():
    global observer

    card_count = index.get_card_count()
    if card_count > 0:
        logger.info(f"Server ready with {card_count} cards in database, starting background rescan...")
    else:
        logger.info("Empty database, performing initial scan...")

    # Start file watcher
    loop = asyncio.get_event_loop()
    handler = CardFileHandler(index, loop)
    observer = Observer()

    for directory in CARD_DIRS:
        if os.path.exists(directory):
            observer.schedule(handler, directory, recursive=RECURSIVE)
            logger.info(f"Watching directory: {directory} (recursive={RECURSIVE})")

    observer.start()

    # Run full scan in background
    asyncio.create_task(background_scan())


async def background_scan():
    """Run full scan in background."""
    await asyncio.sleep(0.1)

    try:
        index.scan_status["running"] = True
        index.scan_status["progress"] = 0
        index.scan_status["total"] = 0

        logger.info("Background scan starting...")
        await index.full_scan(CARD_DIRS, recursive=RECURSIVE)

        index.scan_status["running"] = False
        index.scan_status["last_scan"] = datetime.utcnow().isoformat()

    except Exception as e:
        logger.error(f"Background scan error: {e}")
        index.scan_status["running"] = False


@app.on_event("shutdown")
async def shutdown():
    if observer:
        observer.stop()
        observer.join()


# Dashboard HTML (same as original)
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
        .search-box { display: flex; gap: 10px; margin-bottom: 20px; }
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
        .dupe-cards { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
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
        .modal-header { display: flex; gap: 20px; padding: 25px; border-bottom: 1px solid #333; }
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
            <p>Character Card Index Server v2.0.0-sqlite</p>
            <div style="margin-top:15px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                <button class="btn btn-primary" onclick="triggerRescan()" id="rescan-btn">Rescan Index</button>
                <button class="btn btn-primary" onclick="triggerNextcloudScan()" id="nextcloud-btn">Refresh Nextcloud</button>
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
                <p style="color:#888;margin-bottom:15px;">Cards with identical content</p>
                <div class="actions" style="margin-bottom:20px;">
                    <button class="btn btn-danger" onclick="cleanDuplicates('first')" id="clean-first-btn">Delete Duplicates (Keep First)</button>
                    <button class="btn btn-danger" onclick="cleanDuplicates('largest')" id="clean-largest-btn">Delete Duplicates (Keep Largest)</button>
                </div>
                <div id="duplicates-list"></div>
                <div id="duplicates-loading" class="loading">Loading duplicates...</div>
            </div>
        </div>

        <div id="prohibited" class="tab-content">
            <div class="section">
                <h2>Prohibited Content Log</h2>
                <p style="color:#888;margin-bottom:15px;">Cards automatically deleted</p>
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
            <button class="modal-close" onclick="closeModal()">x</button>
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
                    <button class="btn btn-primary" id="modal-similar-btn" onclick="findSimilar()">Find Similar</button>
                    <button class="btn btn-danger" id="modal-delete-btn" onclick="deleteFromModal()">Delete Card</button>
                </div>
                <div id="similar-results" style="margin-top:20px; display:none;">
                    <h3 style="color:#888; font-size:0.9rem; margin-bottom:12px;">SIMILAR CARDS</h3>
                    <div id="similar-cards" class="dupe-cards"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.className = isError ? 'error' : '';
            toast.style.display = 'block';
            setTimeout(() => toast.style.display = 'none', 3000);
        }

        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stats-grid').innerHTML = `
                    <div class="stat-card success"><h3>Total Cards</h3><div class="value">${data.total_cards.toLocaleString()}</div></div>
                    <div class="stat-card"><h3>SFW Cards</h3><div class="value">${data.sfw_count.toLocaleString()}</div></div>
                    <div class="stat-card warning"><h3>NSFW Cards</h3><div class="value">${data.nsfw_count.toLocaleString()}</div></div>
                    <div class="stat-card"><h3>Unique Creators</h3><div class="value">${data.unique_creators.toLocaleString()}</div></div>
                    <div class="stat-card warning"><h3>Content Dupes</h3><div class="value">${data.content_duplicate_groups}</div></div>
                    <div class="stat-card" style="border-left-color:#e74c3c;"><h3>Image Dupes</h3><div class="value" style="color:#e74c3c;">${data.image_duplicate_groups}</div></div>
                    <div class="stat-card danger"><h3>Prohibited Deleted</h3><div class="value">${data.prohibited_deleted}</div></div>
                `;
            } catch (e) { console.error('Failed to load stats:', e); }
        }

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
                        <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" alt="${card.name}" loading="lazy"
                             onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/><text x=%2250%22 y=%2250%22 text-anchor=%22middle%22 fill=%22%23666%22>?</text></svg>'">
                        ${card.nsfw ? '<span class="nsfw-badge">NSFW</span>' : ''}
                        <div class="card-info"><h4>${card.name}</h4><p>${card.creator}</p></div>
                    </div>
                `).join('');
            } catch (e) {
                loading.style.display = 'none';
                results.innerHTML = '<div class="empty">Error loading cards</div>';
            }
        }

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
                list.innerHTML = `<p style="margin-bottom:15px;"><span style="color:#667eea;">${data.content_duplicate_groups} content duplicates</span> | <span style="color:#e74c3c;">${data.image_duplicate_groups} image duplicates</span></p>` + data.duplicates.map((dupe, idx) => `
                    <div class="dupe-group" id="dupe-group-${idx}" data-paths="${encodeURIComponent(JSON.stringify(dupe.cards.map(c => c.path)))}">
                        <button class="ignore-btn" onclick="ignoreDuplicateGroup(${idx})">Not a Duplicate</button>
                        <h4>${dupe.count} copies <span class="type-badge ${dupe.type}">${dupe.type === 'content' ? 'Content Match' : 'Image Match'}</span></h4>
                        <div class="dupe-cards">
                            ${dupe.cards.map((card, i) => `
                                <div class="dupe-card" data-path="${encodeURIComponent(card.path)}" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                                    ${i === 0 ? '<span class="keep-badge">KEEP</span>' : ''}
                                    <button class="delete-btn" onclick="event.stopPropagation(); deleteCardEl(this.parentElement)" title="Delete">x</button>
                                    <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" onclick="openCardEl(this.parentElement)" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'" loading="lazy">
                                    <div class="info"><h5>${card.name}</h5><p>${card.creator}</p></div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading duplicates</div>';
            }
        }

        function openCardEl(el) {
            const folder = decodeURIComponent(el.dataset.folder);
            const file = decodeURIComponent(el.dataset.file);
            openCard(folder, file);
        }

        function deleteCardEl(el) {
            const path = decodeURIComponent(el.dataset.path);
            deleteCardByPath(path, el);
        }

        async function deleteCardByPath(path, card) {
            if (!confirm('Delete this card permanently?')) return;
            const btn = card.querySelector('.delete-btn');
            if (btn) { btn.disabled = true; btn.textContent = '...'; }
            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    card.classList.add('deleted');
                    showToast('Card deleted');
                    loadStats();
                } else {
                    showToast('Delete failed', true);
                    if (btn) { btn.disabled = false; btn.textContent = 'x'; }
                }
            } catch (e) {
                showToast('Delete error', true);
                if (btn) { btn.disabled = false; btn.textContent = 'x'; }
            }
        }

        async function ignoreDuplicateGroup(idx) {
            const group = document.getElementById('dupe-group-' + idx);
            const paths = JSON.parse(decodeURIComponent(group.dataset.paths));
            const btn = group.querySelector('.ignore-btn');
            btn.disabled = true;
            btn.textContent = 'Saving...';
            try {
                const params = paths.map(p => 'paths=' + encodeURIComponent(p)).join('&');
                const res = await fetch('/api/duplicates/ignore?' + params, { method: 'POST' });
                if (res.ok) {
                    group.style.opacity = '0.3';
                    showToast('Marked as not a duplicate');
                    setTimeout(() => group.remove(), 1000);
                    loadStats();
                } else {
                    showToast('Failed', true);
                    btn.disabled = false;
                    btn.textContent = 'Not a Duplicate';
                }
            } catch (e) {
                showToast('Error', true);
                btn.disabled = false;
                btn.textContent = 'Not a Duplicate';
            }
        }

        async function cleanDuplicates(keep) {
            if (!confirm(`Delete all duplicate files, keeping the ${keep} copy?`)) return;
            document.getElementById('clean-first-btn').disabled = true;
            document.getElementById('clean-largest-btn').disabled = true;
            try {
                const res = await fetch(`/api/duplicates/clean?keep=${keep}`, { method: 'DELETE' });
                const data = await res.json();
                showToast(`Deleted ${data.deleted_count} duplicate files`);
                loadDuplicates();
                loadStats();
            } catch (e) { showToast('Error cleaning duplicates', true); }
            document.getElementById('clean-first-btn').disabled = false;
            document.getElementById('clean-largest-btn').disabled = false;
        }

        async function loadProhibited() {
            const list = document.getElementById('prohibited-list');
            const loading = document.getElementById('prohibited-loading');
            try {
                const res = await fetch('/api/prohibited');
                const data = await res.json();
                loading.style.display = 'none';
                if (data.deleted.length === 0) {
                    list.innerHTML = '<div class="empty">No prohibited cards deleted</div>';
                    return;
                }
                list.innerHTML = `<p style="margin-bottom:15px;">Total: ${data.total_deleted}</p><table><thead><tr><th>Path</th><th>Blocked Tags</th><th>Deleted At</th></tr></thead><tbody>${data.deleted.map(item => `<tr><td style="font-family:monospace;font-size:0.85rem;">${item.path}</td><td>${item.tags.map(t => `<span class="tag blocked">${t}</span>`).join('')}</td><td>${new Date(item.deleted_at).toLocaleString()}</td></tr>`).join('')}</tbody></table>`;
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading prohibited log</div>';
            }
        }

        async function loadTags() {
            const list = document.getElementById('tags-list');
            const loading = document.getElementById('tags-loading');
            try {
                const res = await fetch('/api/tags');
                const data = await res.json();
                loading.style.display = 'none';
                list.innerHTML = `<table><thead><tr><th>Tag</th><th>Count</th></tr></thead><tbody>${data.tags.slice(0, 100).map(([tag, count]) => `<tr><td><span class="tag">${tag}</span></td><td>${count.toLocaleString()}</td></tr>`).join('')}</tbody></table>`;
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading tags</div>';
            }
        }

        document.getElementById('search-input').addEventListener('keypress', e => { if (e.key === 'Enter') searchCards(); });

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
            btn.textContent = 'Searching...';
            resultsDiv.style.display = 'none';
            try {
                const res = await fetch(`/api/cards/similar?path=${encodeURIComponent(currentCardPath)}&threshold=20`);
                const data = await res.json();
                if (data.similar.length === 0) {
                    cardsDiv.innerHTML = '<p style="color:#888;">No similar cards found</p>';
                } else {
                    cardsDiv.innerHTML = data.similar.map(card => `
                        <div class="dupe-card" data-path="${encodeURIComponent(card.path)}" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                            <button class="delete-btn" onclick="event.stopPropagation(); deleteCardEl(this.parentElement)" title="Delete">x</button>
                            <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" onclick="openCardEl(this.parentElement)" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'" loading="lazy">
                            <div class="info"><h5>${card.name}</h5><p>${card.creator}</p><p style="color:#667eea;font-size:0.7rem;">${card.reasons.join(', ')}</p></div>
                        </div>
                    `).join('');
                }
                resultsDiv.style.display = 'block';
                showToast(`Found ${data.similar.length} similar cards`);
            } catch (e) { showToast('Search error', true); }
            btn.disabled = false;
            btn.textContent = 'Find Similar';
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
                    searchCards();
                    loadDuplicates();
                } else { showToast('Delete failed', true); }
            } catch (e) { showToast('Delete error', true); }
            btn.disabled = false;
            btn.textContent = 'Delete Card';
        }

        async function openCard(folder, file) {
            const modal = document.getElementById('card-modal');
            modal.classList.add('active');
            document.getElementById('modal-img').src = `/cards/${encodeURIComponent(folder)}/${encodeURIComponent(file)}`;
            document.getElementById('modal-name').textContent = 'Loading...';
            document.getElementById('modal-creator').textContent = '';
            document.getElementById('modal-tags').innerHTML = '';
            document.getElementById('similar-results').style.display = 'none';
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
                document.getElementById('modal-nsfw').style.display = entry.nsfw ? 'inline-block' : 'none';
                const tags = entry.tags || meta.tags || [];
                document.getElementById('modal-tags').innerHTML = tags.slice(0, 20).map(t => `<span class="tag">${t}</span>`).join('') + (tags.length > 20 ? `<span class="tag">+${tags.length - 20} more</span>` : '');
                setSection('description', meta.description || entry.description_preview || '');
                setSection('firstmes', meta.first_mes || entry.first_mes_preview || '');
                setSection('personality', meta.personality || '');
                setSection('scenario', meta.scenario || '');
                setSection('mesbefore', meta.mes_example || '');
            } catch (e) {
                document.getElementById('modal-name').textContent = 'Error loading card';
            }
        }

        function setSection(id, content) {
            const section = document.getElementById('section-' + id);
            const el = document.getElementById('modal-' + id);
            if (content && content.trim()) { section.style.display = 'block'; el.textContent = content; }
            else { section.style.display = 'none'; }
        }

        document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

        async function triggerNextcloudScan() {
            const btn = document.getElementById('nextcloud-btn');
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            try {
                const res = await fetch('/api/nextcloud/scan', { method: 'POST' });
                const data = await res.json();
                if (data.success) { showToast('Nextcloud scan completed!'); }
                else { showToast('Nextcloud scan failed', true); }
            } catch (e) { showToast('Nextcloud scan error', true); }
            btn.disabled = false;
            btn.textContent = 'Refresh Nextcloud';
        }

        async function triggerRescan() {
            const btn = document.getElementById('rescan-btn');
            btn.disabled = true;
            btn.textContent = 'Starting...';
            try {
                const res = await fetch('/api/index/rescan', { method: 'POST' });
                if (res.ok) { showToast('Rescan started'); checkScanStatus(); }
                else {
                    const data = await res.json();
                    showToast(data.detail || 'Failed', true);
                    btn.disabled = false;
                    btn.textContent = 'Rescan Index';
                }
            } catch (e) {
                showToast('Error', true);
                btn.disabled = false;
                btn.textContent = 'Rescan Index';
            }
        }

        async function checkScanStatus() {
            try {
                const res = await fetch('/api/index/status');
                const data = await res.json();
                const status = document.getElementById('scan-status');
                const btn = document.getElementById('rescan-btn');
                if (data.scan_running) {
                    status.textContent = `Scanning... ${data.scan_progress} processed`;
                    status.style.color = '#f39c12';
                    btn.disabled = true;
                    btn.textContent = 'Scanning...';
                    setTimeout(checkScanStatus, 2000);
                } else {
                    if (data.last_scan) { status.textContent = `${data.cards_indexed} cards indexed`; status.style.color = '#2ecc71'; }
                    btn.disabled = false;
                    btn.textContent = 'Rescan Index';
                    loadStats();
                }
            } catch (e) { console.error('Failed to check scan status:', e); }
        }

        loadStats();
        loadDuplicates();
        loadProhibited();
        loadTags();
        searchCards();
        checkScanStatus();
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
    duplicates = index.get_duplicates()
    return {
        "service": "Character Card Index",
        "version": "2.0.0-sqlite",
        "total_cards": index.get_card_count(),
        "prohibited_deleted": index.get_prohibited_count(),
        "duplicate_groups": len(duplicates),
        "config": {
            "auto_delete_prohibited": AUTO_DELETE_PROHIBITED,
            "detect_duplicates": DETECT_DUPLICATES,
            "database": DB_FILE
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
    folder: Optional[str] = Query(None, description="Filter by folder"),
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
    with index._cursor() as cur:
        cur.execute("SELECT * FROM cards WHERE folder = ? AND file = ?", (folder, filename))
        row = cur.fetchone()
        if row:
            entry = index._row_to_entry(row)
            metadata = index.extract_metadata(entry.path)
            return {
                "entry": asdict(entry),
                "full_metadata": metadata
            }

    raise HTTPException(status_code=404, detail="Card not found")


@app.get("/cards/{folder}/{filename}")
async def serve_card_image(folder: str, filename: str):
    """Serve the actual card PNG file."""
    with index._cursor() as cur:
        cur.execute("SELECT path FROM cards WHERE folder = ? AND file = ?", (folder, filename))
        row = cur.fetchone()
        if row:
            return FileResponse(row[0], media_type="image/png")

    raise HTTPException(status_code=404, detail="Card not found")


@app.get("/api/stats")
async def get_stats():
    """Get index statistics."""
    stats = index.get_stats()
    tags = index.get_all_tags()
    duplicates = index.get_duplicates()
    image_duplicates = index.get_image_duplicates()

    return {
        "total_cards": stats["total_cards"],
        "nsfw_count": stats["nsfw_count"],
        "sfw_count": stats["sfw_count"],
        "unique_creators": stats["unique_creators"],
        "unique_tags": len(tags),
        "prohibited_deleted": index.get_prohibited_count(),
        "content_duplicate_groups": len([p for p in duplicates.values() if len(p) > 1]),
        "image_duplicate_groups": len([p for p in image_duplicates.values() if len(p) > 1]),
        "image_hash_enabled": IMAGE_HASH_AVAILABLE,
        "top_tags": tags[:100],
        "top_creators": stats["top_creators"],
        "folders": stats["folders"]
    }


@app.get("/api/tags")
async def get_tags():
    """Get all unique tags with counts."""
    return {"tags": index.get_all_tags()}


@app.get("/api/prohibited")
async def get_prohibited():
    """Get list of prohibited cards that were deleted."""
    return {
        "total_deleted": index.get_prohibited_count(),
        "auto_delete_enabled": AUTO_DELETE_PROHIBITED,
        "deleted": index.get_prohibited_deleted(100)
    }


@app.get("/api/duplicates")
async def get_duplicates():
    """Get list of detected duplicate cards."""

    def get_card_info(path: str) -> dict:
        entry = index.get_card_by_path(path)
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

    # Content-based duplicates
    content_dupes = []
    for content_hash, paths in index.get_duplicates().items():
        if len(paths) > 1 and not index.is_duplicate_ignored(paths):
            content_dupes.append({
                "type": "content",
                "hash": content_hash,
                "count": len(paths),
                "cards": [get_card_info(p) for p in paths]
            })

    # Image-based duplicates
    image_dupes = []
    for image_hash, paths in index.get_image_duplicates().items():
        if len(paths) > 1:
            cards_info = [(p, get_card_info(p)) for p in paths if os.path.exists(p)]
            if len(cards_info) >= 2 and not index.is_duplicate_ignored([p for p, _ in cards_info]):
                # Verify name similarity
                filtered_cards = [cards_info[0]]
                base_name = cards_info[0][1]["name"]
                for p, info in cards_info[1:]:
                    if name_similarity(base_name, info["name"]) > 0.3:
                        filtered_cards.append((p, info))

                if len(filtered_cards) >= 2:
                    image_dupes.append({
                        "type": "image",
                        "hash": image_hash,
                        "count": len(filtered_cards),
                        "cards": [info for _, info in filtered_cards]
                    })

    all_dupes = content_dupes + image_dupes
    all_dupes.sort(key=lambda x: x["count"], reverse=True)

    return {
        "content_duplicate_groups": len(content_dupes),
        "image_duplicate_groups": len(image_dupes),
        "total_duplicate_groups": len(all_dupes),
        "total_duplicate_files": sum(d["count"] - 1 for d in all_dupes),
        "detect_enabled": DETECT_DUPLICATES,
        "image_hash_enabled": IMAGE_HASH_AVAILABLE,
        "duplicates": all_dupes[:100]
    }


@app.get("/api/cards/similar")
async def find_similar_cards(
    path: str = Query(None, description="Path to card"),
    folder: str = Query(None, description="Folder of card"),
    file: str = Query(None, description="Filename of card"),
    threshold: int = Query(18, description="Image hash threshold")
):
    """Find cards similar to a given card."""
    source_entry = None
    source_path = path

    if path:
        source_entry = index.get_card_by_path(path)
    elif folder and file:
        with index._cursor() as cur:
            cur.execute("SELECT * FROM cards WHERE folder = ? AND file = ?", (folder, file))
            row = cur.fetchone()
            if row:
                source_entry = index._row_to_entry(row)
                source_path = source_entry.path

    if not source_entry:
        raise HTTPException(status_code=404, detail="Source card not found")

    similar = []
    source_hash = index.image_hash_objects.get(source_path)

    # Get all cards for comparison
    all_cards = index.get_all_cards()

    for card_path, entry in all_cards.items():
        if card_path == source_path:
            continue

        similarity_score = 0
        match_reasons = []

        name_sim = name_similarity(source_entry.name, entry.name)
        if name_sim > 0.3:
            similarity_score += name_sim * 50
            match_reasons.append(f"name ({int(name_sim*100)}%)")

        if source_hash and IMAGE_HASH_AVAILABLE:
            card_hash = index.image_hash_objects.get(card_path)
            if card_hash:
                distance = source_hash - card_hash
                if distance <= threshold:
                    img_score = (threshold - distance) / threshold * 50
                    similarity_score += img_score
                    match_reasons.append(f"image (dist={distance})")

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

    similar.sort(key=lambda x: x["score"], reverse=True)

    return {
        "source": {
            "path": source_path,
            "name": source_entry.name,
            "folder": source_entry.folder,
            "file": source_entry.file
        },
        "similar_count": len(similar),
        "similar": similar[:50]
    }


@app.post("/api/cards/upload")
async def upload_card(
    file: UploadFile = File(..., description="PNG character card file"),
    folder: str = Form(default="Uploads", description="Subfolder to save to")
):
    """Upload a character card to the server."""
    if not file.filename.lower().endswith('.png'):
        raise HTTPException(status_code=400, detail="Only PNG files are supported")

    if not CARD_DIRS or not CARD_DIRS[0]:
        raise HTTPException(status_code=500, detail="No card directories configured")

    base_dir = CARD_DIRS[0]
    safe_folder = "".join(c for c in folder if c.isalnum() or c in " -_").strip() or "Uploads"
    upload_dir = os.path.join(base_dir, safe_folder)

    try:
        os.makedirs(upload_dir, exist_ok=True)
        safe_filename = "".join(c for c in file.filename if c.isalnum() or c in " -_.").strip()
        if not safe_filename.lower().endswith('.png'):
            safe_filename += '.png'

        filepath = os.path.join(upload_dir, safe_filename)

        if os.path.exists(filepath):
            base, ext = os.path.splitext(safe_filename)
            counter = 1
            while os.path.exists(filepath):
                safe_filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(upload_dir, safe_filename)
                counter += 1

        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"Uploaded card: {filepath}")

        entry = index.index_card(filepath, delete_prohibited=True)
        if entry:
            return {
                "success": True,
                "path": filepath,
                "folder": safe_folder,
                "file": safe_filename,
                "name": entry.name,
                "indexed": True
            }
        else:
            if os.path.exists(filepath):
                os.remove(filepath)
                return {"success": False, "detail": "Invalid character card: no embedded metadata found"}
            else:
                return {"success": False, "detail": "Card rejected: prohibited content detected"}

    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/cards/delete")
async def delete_card(path: str = Query(..., description="Full path to the card file")):
    """Delete a single card file."""
    if not path:
        raise HTTPException(status_code=400, detail="Path required")

    if index.delete_card(path):
        return {"success": True, "deleted": path}
    else:
        raise HTTPException(status_code=404, detail="File not found or delete failed")


@app.post("/api/duplicates/ignore")
async def ignore_duplicate_group(paths: List[str] = Query(..., description="Paths in the duplicate group")):
    """Mark a group of cards as NOT duplicates."""
    if len(paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 paths")

    index.ignore_duplicate(paths)
    logger.info(f"Marked as non-duplicate: {paths}")
    return {"status": "Marked as non-duplicate", "paths": paths}


@app.delete("/api/duplicates/clean")
async def clean_duplicates(
    keep: str = Query("first", description="Which to keep: 'first' or 'largest'"),
    type: str = Query("all", description="Which duplicates: 'content', 'image', or 'all'")
):
    """Delete duplicate files, keeping one copy of each."""
    if not DETECT_DUPLICATES:
        raise HTTPException(status_code=400, detail="Duplicate detection is disabled")

    deleted = []
    already_deleted = set()

    def clean_group(paths: List[str]):
        if len(paths) <= 1:
            return
        valid_paths = [p for p in paths if p not in already_deleted and os.path.exists(p)]
        if len(valid_paths) <= 1:
            return

        if keep == "largest":
            paths_with_size = [(p, os.path.getsize(p)) for p in valid_paths]
            paths_with_size.sort(key=lambda x: x[1], reverse=True)
            delete_paths = [p for p, _ in paths_with_size[1:]]
        else:
            delete_paths = valid_paths[1:]

        for path in delete_paths:
            if index.delete_card(path):
                deleted.append(path)
                already_deleted.add(path)
                logger.info(f"Deleted duplicate: {path}")

    if type in ["all", "content"]:
        for paths in index.get_duplicates().values():
            clean_group(paths)

    if type in ["all", "image"]:
        for paths in index.get_image_duplicates().values():
            clean_group(paths)

    return {"deleted_count": len(deleted), "deleted_files": deleted[:100]}


# Nextcloud scan tracking
nextcloud_scan_status = {"running": False, "last_scan": None, "last_result": None}


@app.post("/api/nextcloud/scan")
async def trigger_nextcloud_scan(user: str = Query(None, description="Nextcloud user to scan")):
    """Trigger a Nextcloud file scan."""
    global nextcloud_scan_status

    if nextcloud_scan_status["running"]:
        raise HTTPException(status_code=409, detail="Scan already in progress")

    scan_user = user or NEXTCLOUD_USER
    nextcloud_scan_status["running"] = True

    try:
        logger.info(f"Starting Nextcloud scan for user: {scan_user}")
        result = subprocess.run(
            ["sudo", "nextcloud.occ", "files:scan", scan_user],
            capture_output=True, text=True, timeout=3600
        )

        nextcloud_scan_status["last_scan"] = datetime.utcnow().isoformat()
        nextcloud_scan_status["last_result"] = {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-1000:] if result.stderr else ""
        }

        return nextcloud_scan_status["last_result"]

    except subprocess.TimeoutExpired:
        nextcloud_scan_status["last_result"] = {"success": False, "error": "Scan timed out"}
        raise HTTPException(status_code=504, detail="Scan timed out")
    except Exception as e:
        nextcloud_scan_status["last_result"] = {"success": False, "error": str(e)}
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
        "cards_indexed": index.get_card_count(),
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
    """Manually save the index (no-op for SQLite, auto-persists)."""
    return {"status": "Index auto-saved (SQLite)", "cards": index.get_card_count()}


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)

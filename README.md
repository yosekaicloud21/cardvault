# CardVault - Character Card Index Server

A FastAPI server that indexes character card PNGs, detects duplicates, filters prohibited content, and provides a searchable REST API with a web dashboard.

## Features

- **Full-text search** across character names, descriptions, and creators
- **Tag filtering** with NSFW/SFW options
- **Duplicate detection** using both content hash (MD5) and perceptual image hashing
- **Prohibited content filtering** with automatic deletion
- **Web dashboard** for browsing, searching, and managing cards
- **Index persistence** for instant startup
- **File watching** for real-time updates
- **Upload support** for adding new cards via API
- **Nextcloud integration** (optional) for triggering file scans

## Server Versions

CardVault includes two server implementations with identical APIs:

| | `server.py` (JSON) | `server_sqlite.py` (SQLite) |
|---|---|---|
| **Best for** | Small collections (<10k cards) | Large collections (10k-500k+ cards) |
| **Storage** | Single JSON file | SQLite database with FTS5 |
| **Search** | Linear scan (O(n)) | Full-text index (fast) |
| **Memory** | All cards loaded in RAM | On-disk with caching |
| **Startup** | Re-parses entire JSON | Instant (DB persists) |
| **Rescan** | Re-indexes everything | Only changed files (mtime check) |
| **During scan** | Web UI may be slow | Web UI stays responsive |

**Recommendation:** Use `server_sqlite.py` for collections over 10,000 cards.

## Quick Start

### 1. Clone and setup

```bash
git clone https://github.com/Starkka15/cardvault.git
cd cardvault

# Create virtual environment
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
nano .env
```

Set your card directories:
```
CARD_DIRS=/path/to/your/CharacterCards
CARD_PORT=8787
```

### 3. Run

**For small collections (JSON backend):**
```bash
./venv/bin/python server.py
```

**For large collections (SQLite backend - recommended):**
```bash
./venv/bin/python server_sqlite.py
```

Visit http://localhost:8787 to access the web dashboard.

## Production Setup (systemd)

```bash
# Copy files to /opt/card-index-server
sudo mkdir -p /opt/card-index-server
sudo cp server.py server_sqlite.py requirements.txt card-index.service .env /opt/card-index-server/

# Create index directory
sudo mkdir -p /var/lib/card-index

# Install service
sudo cp card-index.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable card-index
sudo systemctl start card-index
```

### Switching Between Server Versions

The systemd service runs `server.py` by default. To use the SQLite version for large collections:

```bash
# Option 1: Rename files
cd /opt/card-index-server
sudo mv server.py server_json.py
sudo mv server_sqlite.py server.py
sudo systemctl restart card-index

# Option 2: Edit the service file to point to server_sqlite.py
sudo nano /etc/systemd/system/card-index.service
# Change: ExecStart=... server.py  ->  ExecStart=... server_sqlite.py
sudo systemctl daemon-reload
sudo systemctl restart card-index
```

## API Endpoints

### Search & Browse
| Endpoint | Description |
|----------|-------------|
| `GET /` | Web dashboard |
| `GET /api/cards` | Search cards with filters |
| `GET /api/cards/{folder}/{filename}` | Get full card metadata |
| `GET /cards/{folder}/{filename}` | Get card PNG image |
| `GET /api/stats` | Index statistics |
| `GET /api/tags` | List all tags with counts |

### Management
| Endpoint | Description |
|----------|-------------|
| `POST /api/cards/upload` | Upload a new card |
| `DELETE /api/cards/delete` | Delete a card |
| `GET /api/duplicates` | Get duplicate groups |
| `DELETE /api/duplicates/clean` | Remove duplicates (keep one) |
| `POST /api/duplicates/ignore` | Mark group as non-duplicate |
| `GET /api/cards/similar` | Find similar cards |
| `GET /api/prohibited` | View deleted prohibited cards |

### Index Management
| Endpoint | Description |
|----------|-------------|
| `GET /api/index/status` | Scan status |
| `POST /api/index/rescan` | Trigger full rescan |
| `POST /api/nextcloud/scan` | Trigger Nextcloud file scan |

## Search Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `q` | Search query | `?q=vampire` |
| `tags` | Filter by tags (comma-separated) | `?tags=Female,Fantasy` |
| `nsfw` | Filter by NSFW status | `?nsfw=false` |
| `creator` | Filter by creator | `?creator=SomeCreator` |
| `folder` | Filter by folder | `?folder=chub` |
| `limit` | Results per page (max 200) | `?limit=50` |
| `offset` | Pagination offset | `?offset=100` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CARD_DIRS` | (required) | Colon-separated list of directories to index |
| `CARD_HOST` | `0.0.0.0` | Host to bind to |
| `CARD_PORT` | `8787` | Port to bind to |
| `CARD_AUTO_DELETE` | `true` | Auto-delete prohibited content |
| `CARD_DETECT_DUPES` | `true` | Enable duplicate detection |
| `CARD_INDEX_FILE` | `/var/lib/card-index/index.json` | Index persistence file (JSON version only) |
| `CARD_DB_FILE` | `/var/lib/card-index/cards.db` | SQLite database file (SQLite version only) |
| `NEXTCLOUD_USER` | (optional) | Nextcloud user for file scan integration |

### Large Collection Notes (SQLite version)

For collections with 100k+ files, you may need to increase the inotify watch limit:

```bash
# Check current limit
cat /proc/sys/fs/inotify/max_user_watches

# Increase temporarily
sudo sysctl fs.inotify.max_user_watches=524288

# Make permanent
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Web Dashboard

Access the dashboard at `http://your-server:8787/`

Features:
- **Search** - Full-text search with tag filtering
- **Duplicates** - View and manage duplicate cards
- **Prohibited Log** - View deleted prohibited content
- **Statistics** - Total cards, NSFW count, top tags/creators
- **Card Details** - Click any card to view full info and import

## Integration with PocketTavern

This server is designed to work with the PocketTavern Android app. Configure the CardVault URL in PocketTavern settings to:
- Browse your card collection on mobile
- Import cards to SillyTavern
- Upload characters from the app

## License

MIT

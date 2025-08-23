# PyBorg Path Configuration

PyBorg is designed to work seamlessly from any directory on your system. All paths are relative to the project directory by default.

## Default Directory Structure

When you clone PyBorg to any location, it creates this structure:

```
PyBorg/                    # Your project directory (anywhere on system)
├── data/                  # Data directory (auto-created)
│   ├── databases/         # SQLite databases
│   ├── logs/              # Log files
│   │   ├── irc_networks/  # Network-specific logs
│   │   ├── security/      # Security logs
│   │   └── website/       # Web interface logs
│   ├── bot_status/        # Bot status files
│   └── tmp/               # Temporary files
├── web/                   # Web interface
└── [other project files]
```

## Path Configuration Options

### Option 1: Default Relative Paths (Recommended)
PyBorg automatically uses relative paths from the project directory.

**No configuration needed!** Just run:
```bash
python bot_v2.py
```

### Option 2: Custom Paths via Setup Script
Use the interactive setup to configure custom paths:

```bash
python setup.py
# Choose "Use custom data directory" when prompted
```

### Option 3: Environment Variables
Set custom paths via environment variables:

```bash
export BOT_DATA_DIR="/custom/data/path"
export BOT_WEB_DIR="/custom/web/path"
python bot_v2.py
```

### Option 4: .env File
Add to your `.env` file:
```
BOT_DATA_DIR=/custom/data/path
BOT_WEB_DIR=/custom/web/path
BOT_DATABASE_DIR=/custom/database/path
BOT_LOG_DIR=/custom/log/path
```

## Portable Installation

PyBorg is completely portable:

1. **Copy anywhere**: Move the entire PyBorg folder to any location
2. **No absolute paths**: Everything is relative or configurable
3. **Auto-creation**: All directories are created automatically
4. **User permissions**: Works with any user account

## Examples

### Home Directory Installation
```bash
cd ~
git clone <repo-url> PyBorg
cd PyBorg
python setup.py
python bot_v2.py
```

### System-wide Installation
```bash
cd /opt
sudo git clone <repo-url> pyborg
cd pyborg
sudo python setup.py
# Configure custom paths during setup
python bot_v2.py
```

### Development Installation
```bash
cd ~/projects
git clone <repo-url> pyborg-dev
cd pyborg-dev
python setup.py
python bot_v2.py
```

### Multiple Instances
Run multiple PyBorg instances from different directories:

```bash
# Instance 1
cd ~/pyborg-network1
python bot_v2.py network1

# Instance 2  
cd ~/pyborg-network2
python bot_v2.py network2
```

## Path Resolution Priority

PyBorg resolves paths in this order:

1. **Environment variables** (highest priority)
2. **Project directory + relative paths** (default)
3. **Current working directory fallback** (lowest priority)

## Troubleshooting

### Permission Issues
```bash
# Fix directory permissions
chmod -R 755 data/
chmod -R 664 data/databases/
```

### Path Verification
Check current path configuration:
```bash
python -c "from core.paths import log_path_configuration; log_path_configuration()"
```

### Reset to Defaults
Remove custom paths from `.env`:
```bash
# Remove these lines from .env if present:
# BOT_DATA_DIR=...
# BOT_WEB_DIR=...
# BOT_DATABASE_DIR=...
# BOT_LOG_DIR=...
```

## Web Interface Paths

The web interface automatically detects the data directory location. No additional configuration needed for most setups.

For custom web server configurations, ensure PHP can access:
- `data/databases/` (read/write)
- `data/logs/` (read)
- `data/bot_status/` (read/write)

## Cross-Platform Compatibility

PyBorg paths work on:
- **Linux**: `/home/user/pyborg/`
- **Windows**: `C:\Users\User\pyborg\`
- **macOS**: `/Users/user/pyborg/`
- **Docker**: `/app/pyborg/`

All path handling is done through Python's `pathlib` for cross-platform compatibility.
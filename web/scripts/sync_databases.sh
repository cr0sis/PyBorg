#!/bin/bash
# Sync PyBorg databases to web-accessible location
# Configure these paths for your setup

# Default paths (change these for your installation)
SOURCE_DIR="$(dirname "$(dirname "$(dirname "$(realpath "$0")")")")"
DEST_DIR="$(dirname "$(realpath "$0")")/../data"
WEB_USER="www-data"  # Change to your web server user (www-data, apache, nginx, etc.)

# Create destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

echo "Syncing PyBorg databases..."
echo "Source: $SOURCE_DIR"
echo "Destination: $DEST_DIR"
echo ""

# Load configuration to get network name
if [ -f "$SOURCE_DIR/.env" ]; then
    source "$SOURCE_DIR/.env"
    NETWORK_NAME=${NETWORK_NAME:-example}
else
    NETWORK_NAME="example"
fi

# Copy database file if it exists and is newer
db="${NETWORK_NAME}_bot.db"
SOURCE_FILE="$SOURCE_DIR/data/$db"
DEST_FILE="$DEST_DIR/$db"

if [ -f "$SOURCE_FILE" ]; then
    # Check if source is newer or destination doesn't exist
    if [ ! -f "$DEST_FILE" ] || [ "$SOURCE_FILE" -nt "$DEST_FILE" ]; then
        echo "Syncing $db..."
        cp "$SOURCE_FILE" "$DEST_FILE"
        
        # Try to set web server ownership (may require sudo)
        if command -v chown &> /dev/null && id "$WEB_USER" &> /dev/null; then
            chown "$WEB_USER:$WEB_USER" "$DEST_FILE" 2>/dev/null || echo "  Warning: Could not change ownership (run with sudo if needed)"
        fi
        chmod 644 "$DEST_FILE"
        echo "  ✅ $db synced successfully"
    else
        echo "  ⏭️  $db is already up to date"
    fi
else
    echo "  ❌ $db not found at $SOURCE_FILE"
fi

echo ""
echo "Database sync completed at $(date)"
#!/bin/bash
# Sync PyBorg logs to web-accessible location

# Default paths (change these for your installation)
SOURCE_DIR="$(dirname "$(dirname "$(dirname "$(realpath "$0")")")")/logs"
DEST_DIR="$(dirname "$(realpath "$0")")/../data/logs"

# Create destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

echo "Syncing PyBorg logs..."
echo "Source: $SOURCE_DIR"
echo "Destination: $DEST_DIR"
echo ""

# Load configuration to get network name
PYBORG_DIR="$(dirname "$(dirname "$(dirname "$(realpath "$0")")")")"
if [ -f "$PYBORG_DIR/.env" ]; then
    source "$PYBORG_DIR/.env"
    NETWORK_NAME=${NETWORK_NAME:-example}
else
    NETWORK_NAME="example"
fi

# Copy log files if they exist and are newer
for log_type in main errors startup; do
    log="${NETWORK_NAME}_${log_type}.log"
    SOURCE_FILE="$SOURCE_DIR/$log"
    DEST_FILE="$DEST_DIR/$log"
    
    if [ -f "$SOURCE_FILE" ]; then
        # Check if source is newer or destination doesn't exist
        if [ ! -f "$DEST_FILE" ] || [ "$SOURCE_FILE" -nt "$DEST_FILE" ]; then
            echo "Syncing $log..."
            if cp "$SOURCE_FILE" "$DEST_FILE"; then
                chmod 644 "$DEST_FILE" 2>/dev/null || true
                echo "  ✅ Successfully synced $log"
            else
                echo "  ❌ Failed to sync $log"
            fi
        else
            echo "  ⏭️  $log is already up to date"
        fi
    else
        echo "  ❌ Source file $SOURCE_FILE does not exist"
    fi
done

echo ""
echo "Log sync completed at $(date)"
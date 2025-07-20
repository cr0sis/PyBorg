#!/bin/bash
# Sync bot databases to web-accessible location

SOURCE_DIR="/home/cr0/cr0bot"
DEST_DIR="/var/www/html/data"

# Create destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Copy database files if they exist and are newer
for db in rizon_bot.db libera_bot.db; do
    SOURCE_FILE="$SOURCE_DIR/$db"
    DEST_FILE="$DEST_DIR/$db"
    
    if [ -f "$SOURCE_FILE" ]; then
        # Check if source is newer or destination doesn't exist
        if [ ! -f "$DEST_FILE" ] || [ "$SOURCE_FILE" -nt "$DEST_FILE" ]; then
            echo "Syncing $db..."
            cp "$SOURCE_FILE" "$DEST_FILE"
            chown www-data:www-data "$DEST_FILE"
            chmod 644 "$DEST_FILE"
        fi
    fi
done

echo "Database sync completed at $(date)"
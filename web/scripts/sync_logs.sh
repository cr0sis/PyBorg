#!/bin/bash
# Sync bot logs to web-accessible location

SOURCE_DIR="/home/cr0/cr0bot/logs"
DEST_DIR="/var/www/html/data/logs"

# Create destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Copy log files if they exist and are newer
for log in rizon_bot.log libera_bot.log rizon_errors.log libera_errors.log rizon_startup.log libera_startup.log; do
    SOURCE_FILE="$SOURCE_DIR/$log"
    DEST_FILE="$DEST_DIR/$log"
    
    if [ -f "$SOURCE_FILE" ]; then
        # Check if source is newer or destination doesn't exist
        if [ ! -f "$DEST_FILE" ] || [ "$SOURCE_FILE" -nt "$DEST_FILE" ]; then
            echo "Syncing $log..."
            if cp "$SOURCE_FILE" "$DEST_FILE"; then
                chmod 644 "$DEST_FILE" 2>/dev/null || true
                echo "Successfully synced $log"
            else
                echo "Failed to sync $log"
            fi
        else
            echo "$log is already up to date"
        fi
    else
        echo "Source file $SOURCE_FILE does not exist"
    fi
done

echo "Log sync completed at $(date)"
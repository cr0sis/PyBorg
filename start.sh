#!/bin/bash
# Start PyBorg IRC Bot
# Run the setup script first if this is your first time: python3 scripts/setup.py

set -e

# Check if configuration exists
if [ ! -f ".env" ]; then
    echo "❌ No .env file found!"
    echo "🔧 Run the setup wizard first: python3 scripts/setup.py"
    exit 1
fi

# Get network name from environment or use default
source .env
NETWORK_NAME=${NETWORK_NAME:-example}

echo "🚀 Starting PyBorg IRC Bot for network: $NETWORK_NAME"

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
fi

# Start the bot
echo "🤖 Launching bot..."
python3 bot.py "$NETWORK_NAME"
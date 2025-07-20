#!/bin/bash
# Launch PyBorg IRC bots in separate screen sessions for monitoring

set -e

echo "🚀 Launching PyBorg IRC bots in screen sessions..."

# Check if screen is installed
if ! command -v screen &> /dev/null; then
    echo "❌ Error: 'screen' is not installed"
    echo "Install with: sudo apt install screen (Ubuntu/Debian) or brew install screen (macOS)"
    exit 1
fi

# Check if configuration exists
if [ ! -f ".env" ]; then
    echo "❌ No .env file found!"
    echo "🔧 Run the setup wizard first: python3 scripts/setup.py"
    exit 1
fi

# Load configuration
source .env
NETWORK_NAME=${NETWORK_NAME:-example}

# Function to check if screen session exists
session_exists() {
    screen -list | grep -q "$1"
}

# Kill existing session if it exists
if session_exists "pyborg-$NETWORK_NAME"; then
    echo "🔄 Stopping existing $NETWORK_NAME bot session..."
    screen -S "pyborg-$NETWORK_NAME" -X quit 2>/dev/null || true
    sleep 2
fi

# Launch bot in detached screen session
echo "📺 Starting $NETWORK_NAME bot in screen session 'pyborg-$NETWORK_NAME'..."
screen -dmS "pyborg-$NETWORK_NAME" bash -c "
    echo '🤖 PyBorg IRC Bot - $(date)'
    echo 'Network: $NETWORK_NAME'
    echo '========================='
    if [ -d 'venv' ]; then
        echo 'Activating virtual environment...'
        source venv/bin/activate
    fi
    python3 bot.py $NETWORK_NAME
"

# Wait for session to fully start
sleep 3

echo ""
echo "✅ PyBorg IRC bot launched in screen session!"
echo ""
echo "📊 Active screen sessions:"
screen -list | grep "pyborg-" || echo "  No PyBorg sessions found"
echo ""
echo "🔍 Monitor session:"
echo "   screen -r pyborg-$NETWORK_NAME     # Attach to bot"
echo ""
echo "⌨️  Screen controls (when attached):"
echo "   Ctrl+A, D               # Detach (leave running)"
echo "   Ctrl+A, K               # Kill session"
echo "   Ctrl+A, ?               # Help"
echo ""
echo "📋 Quick commands:"
echo "   ./monitor_screens.sh    # Show all sessions"
echo "   ./stop_screens.sh       # Stop bot session"
echo ""
echo "🎉 PyBorg is now running in the background!"
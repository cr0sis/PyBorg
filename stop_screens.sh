#!/bin/bash
# Stop PyBorg IRC bot screen sessions

echo "🛑 Stopping PyBorg IRC Bot Sessions"
echo "=================================="

# Check if screen is installed
if ! command -v screen &> /dev/null; then
    echo "❌ Error: 'screen' is not installed"
    exit 1
fi

# Function to check if screen session exists
session_exists() {
    screen -list | grep -q "$1"
}

# Load configuration if available
if [ -f ".env" ]; then
    source .env
    NETWORK_NAME=${NETWORK_NAME:-example}
else
    NETWORK_NAME="example"
fi

STOPPED_COUNT=0

# Stop all PyBorg sessions
echo "🔍 Looking for PyBorg screen sessions..."
for session in $(screen -list | grep "pyborg-" | awk '{print $1}' | cut -d. -f2 2>/dev/null || true); do
    if session_exists "$session"; then
        echo "🔄 Stopping session: $session"
        screen -S "$session" -X quit 2>/dev/null || true
        STOPPED_COUNT=$((STOPPED_COUNT + 1))
    fi
done

# Wait for sessions to close
if [ $STOPPED_COUNT -gt 0 ]; then
    echo "⏳ Waiting for sessions to close..."
    sleep 3
fi

# Verify all sessions are stopped
echo ""
echo "📊 Final Status:"
REMAINING_SESSIONS=$(screen -list | grep "pyborg-" || true)

if [ -n "$REMAINING_SESSIONS" ]; then
    echo "⚠️  Some sessions may still be running:"
    echo "$REMAINING_SESSIONS"
    echo ""
    echo "💡 If sessions won't stop, try:"
    echo "   screen -wipe                    # Clean up dead sessions"
    echo "   pkill -f 'python.*bot.py'      # Force kill Python bot processes"
else
    echo "✅ All PyBorg sessions stopped successfully!"
fi

echo ""
echo "📋 Quick commands:"
echo "   ./launch_screens.sh     # Start bot sessions again"
echo "   ./monitor_screens.sh    # Check session status"

if [ $STOPPED_COUNT -gt 0 ]; then
    echo ""
    echo "🎉 Stopped $STOPPED_COUNT PyBorg session(s)"
fi
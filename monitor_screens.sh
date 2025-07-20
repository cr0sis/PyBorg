#!/bin/bash
# Monitor PyBorg IRC bot screen sessions

echo "📊 PyBorg IRC Bot Status Monitor"
echo "================================"
echo ""

# Check if screen is installed
if ! command -v screen &> /dev/null; then
    echo "❌ Error: 'screen' is not installed"
    echo "Install with: sudo apt install screen (Ubuntu/Debian) or brew install screen (macOS)"
    exit 1
fi

# Load configuration if available
if [ -f ".env" ]; then
    source .env
    NETWORK_NAME=${NETWORK_NAME:-example}
else
    NETWORK_NAME="example"
fi

# Show all PyBorg screen sessions
echo "🔍 Active PyBorg Sessions:"
PYBORG_SESSIONS=$(screen -list | grep "pyborg-" || true)

if [ -n "$PYBORG_SESSIONS" ]; then
    echo "$PYBORG_SESSIONS"
    echo ""
    
    # Show recent activity for each session
    for session in $(screen -list | grep "pyborg-" | awk '{print $1}' | cut -d. -f2); do
        echo "📋 Recent activity for $session:"
        echo "   Last 5 lines from session:"
        # Try to capture recent output (this may not work on all systems)
        screen -S "$session" -X hardcopy /tmp/pyborg_output.tmp 2>/dev/null || true
        if [ -f /tmp/pyborg_output.tmp ]; then
            tail -5 /tmp/pyborg_output.tmp 2>/dev/null | sed 's/^/     /' || echo "     No recent output captured"
            rm -f /tmp/pyborg_output.tmp
        else
            echo "     Output capture not available on this system"
        fi
        echo ""
    done
else
    echo "  No PyBorg sessions running"
    echo ""
fi

echo "🔧 Management Commands:"
echo "   ./launch_screens.sh     # Start bot in screen session"
echo "   ./stop_screens.sh       # Stop all bot sessions"
echo "   screen -r pyborg-$NETWORK_NAME    # Attach to bot session"
echo ""

echo "📈 System Status:"
echo "   Date: $(date)"
echo "   Uptime: $(uptime | awk -F',' '{print $1}' | awk '{print $3,$4}')"
echo "   Load: $(uptime | awk -F'load average:' '{print $2}')"

# Check log files if they exist
if [ -d "logs" ]; then
    echo ""
    echo "📁 Recent Log Files:"
    find logs -name "*.log" -type f -mtime -1 2>/dev/null | head -5 | while read logfile; do
        echo "   $logfile ($(stat -c%y "$logfile" 2>/dev/null | cut -d' ' -f1-2 || echo "unknown date"))"
    done
fi
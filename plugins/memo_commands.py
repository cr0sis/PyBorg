"""
Memo/tell functionality for IRC bot
Allows users to leave messages for other users that are delivered when they next speak
"""

import logging
from datetime import datetime
from core.plugin_system import command
from core.database import BotDatabase
from core.config import get_config

logger = logging.getLogger(__name__)

def get_network_config(msg):
    """Get network-specific config based on command prefix"""
    network = 'libera' if msg["message"].startswith('~') else 'rizon'
    return get_config(network)

def format_memo_message(user, memo):
    """Format a memo message in nibblr style with proper coloring"""
    from datetime import timezone
    
    # Handle different timestamp formats from SQLite
    created_time_str = memo['created_time']
    if isinstance(created_time_str, str):
        # Parse SQLite timestamp (which is in UTC)
        try:
            # SQLite CURRENT_TIMESTAMP is in UTC format
            created_time = datetime.strptime(created_time_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                # Handle other formats
                created_time = datetime.fromisoformat(created_time_str.replace('Z', ''))
            except ValueError:
                # Fallback - use current time
                created_time = datetime.now()
    else:
        # Already a datetime object
        created_time = created_time_str
    
    # Use UTC for both timestamps to avoid timezone issues
    from datetime import timezone
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    
    # SQLite CURRENT_TIMESTAMP stores in UTC, so created_time is already UTC
    time_diff = now_utc - created_time
    
    # Calculate total seconds for more accurate time
    total_seconds = int(time_diff.total_seconds())
    
    if time_diff.days > 0:
        if time_diff.days == 1:
            time_ago = "1 day ago"
        else:
            time_ago = f"{time_diff.days} days ago"
    elif total_seconds >= 3600:
        hours = total_seconds // 3600
        if hours == 1:
            time_ago = "1 hour ago"
        else:
            time_ago = f"{hours} hours ago"
    elif total_seconds >= 60:
        minutes = total_seconds // 60
        if minutes == 1:
            time_ago = "1 minute ago"
        else:
            time_ago = f"{minutes} minutes ago"
    elif total_seconds >= 1:
        if total_seconds == 1:
            time_ago = "1 second ago"
        else:
            time_ago = f"{total_seconds} seconds ago"
    else:
        time_ago = "just now"
    
    # Format in nibblr style: white brackets, purple time
    return f"{user}: <{memo['from_user']}> {memo['message']} \x0300(\x0306{time_ago}\x0300)\x03"

@command(
    pattern=r'memo\((\w+)\)\s+(.+)',
    description="Leave a memo for someone (delivered when they next speak)",
    usage="memo(username) message",
    category="utilities"
)
def memo_command(msg):
    """Leave a memo for another user"""
    try:
        # Get network and database
        network = 'libera' if msg["message"].startswith('~') else 'rizon'
        db = BotDatabase(f"{network}_bot.db")
        
        # Extract target user and message from the regex groups
        import re
        config = get_network_config(msg)
        pattern = config.COMMAND_PREFIX + r'memo\((\w+)\)\s+(.+)'
        match = re.search(pattern, msg["message"])
        
        if not match:
            return f"Usage: {config.COMMAND_PREFIX}memo(username) message"
        
        target_user = match.group(1)
        memo_message = match.group(2)
        from_user = msg["user"]
        channel = msg["channel"]
        
        # Allow memos to self (removed restriction)
        
        # Check if target user already has too many pending memos (limit: 10)
        existing_count = db.get_memo_count(target_user)
        if existing_count >= 10:
            return f"{target_user} already has {existing_count} pending memos. Ask them to check their messages!"
        
        # Add the memo to database
        memo_id = db.add_memo(from_user, target_user, memo_message, channel)
        
        if memo_id:
            total_memos = existing_count + 1
            return f"📝 Memo saved for {target_user}! They now have {total_memos} pending message(s)."
        else:
            return "❌ Failed to save memo. Please try again."
            
    except Exception as e:
        logger.error(f"Error in memo command: {e}")
        return "❌ Error saving memo. Please try again."

@command(
    pattern=r'checkmemos$',
    description="Check your pending memos manually",
    category="utilities"
)
def check_memos_command(msg):
    """Manually check pending memos"""
    try:
        # Get network and database
        network = 'libera' if msg["message"].startswith('~') else 'rizon'
        db = BotDatabase(f"{network}_bot.db")
        
        user = msg["user"]
        
        # Get pending memos
        pending_memos = db.get_pending_memos(user)
        
        if not pending_memos:
            return "📭 You have no pending memos."
        
        # Format and return memos using helper function
        messages = []
        for memo in pending_memos:
            messages.append(format_memo_message(user, memo))
        
        # Mark memos as delivered
        delivered_count = db.mark_memos_delivered(user)
        
        return messages
        
    except Exception as e:
        logger.error(f"Error in check memos command: {e}")
        return "❌ Error retrieving memos. Please try again."

def check_and_deliver_memos(msg, bot=None):
    """
    Check if a user has pending memos and deliver them
    This should be called whenever a user speaks (not for commands)
    """
    try:
        # Skip if this is a command message
        config_rizon = get_config('rizon')
        config_libera = get_config('libera')
        
        if (msg["message"].startswith(config_rizon.COMMAND_PREFIX) or 
            msg["message"].startswith(config_libera.COMMAND_PREFIX)):
            return None
        
        # Get network and database
        network = msg.get("network", 'rizon')
        db = BotDatabase(f"{network}_bot.db")
        
        user = msg["user"]
        
        # Get pending memos
        pending_memos = db.get_pending_memos(user)
        
        if not pending_memos:
            return None
        
        # Prepare delivery messages using helper function
        messages = []
        for memo in pending_memos:
            messages.append(format_memo_message(user, memo))
        
        # Mark memos as delivered
        delivered_count = db.mark_memos_delivered(user)
        
        return messages
        
    except Exception as e:
        logger.error(f"Error delivering memos: {e}")
        return None

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
    
    # Register the memo delivery function to be called on every message
    plugin_manager.register_message_handler(check_and_deliver_memos)
    

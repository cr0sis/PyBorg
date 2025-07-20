"""
Reminder system with flexible time parsing
Supports various time formats like "5 minutes", "1h30m", "tomorrow at 2pm", etc.
"""

import re
import asyncio
import logging
from datetime import datetime, timedelta, time as dt_time
from typing import Optional, Tuple
from core.plugin_system import command
from core.database import BotDatabase

logger = logging.getLogger(__name__)

class TimeParser:
    """Parse flexible time formats into datetime objects"""
    
    def __init__(self):
        # Time unit mappings
        self.units = {
            'second': 1, 'seconds': 1, 'sec': 1, 'secs': 1, 's': 1,
            'minute': 60, 'minutes': 60, 'min': 60, 'mins': 60, 'm': 60,
            'hour': 3600, 'hours': 3600, 'hr': 3600, 'hrs': 3600, 'h': 3600,
            'day': 86400, 'days': 86400, 'd': 86400,
            'week': 604800, 'weeks': 604800, 'w': 604800,
            'month': 2592000, 'months': 2592000, 'mo': 2592000,
            'year': 31536000, 'years': 31536000, 'y': 31536000
        }
        
        # Natural language mappings
        self.natural_times = {
            'now': 0,
            'tonight': self._tonight_offset,
            'tomorrow': 86400,
            'next week': 604800,
            'next month': 2592000,
            'next year': 31536000
        }
    
    def _tonight_offset(self):
        """Calculate seconds until 8 PM today or tomorrow if past 8 PM"""
        now = datetime.now()
        tonight = now.replace(hour=20, minute=0, second=0, microsecond=0)
        if now >= tonight:
            tonight += timedelta(days=1)
        return int((tonight - now).total_seconds())
    
    def parse_time_string(self, time_str: str) -> Optional[datetime]:
        """Parse a time string into a datetime object"""
        time_str = time_str.lower().strip()
        base_time = datetime.now()
        
        # Handle "in X" format
        if time_str.startswith('in '):
            time_str = time_str[3:]
        
        # Try natural language first
        for phrase, offset in self.natural_times.items():
            if phrase in time_str:
                if callable(offset):
                    offset = offset()
                return base_time + timedelta(seconds=offset)
        
        # Handle "tomorrow at TIME" format
        if 'tomorrow' in time_str and 'at' in time_str:
            match = re.search(r'at\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?', time_str)
            if match:
                hour = int(match.group(1))
                minute = int(match.group(2)) if match.group(2) else 0
                ampm = match.group(3)
                
                if ampm == 'pm' and hour != 12:
                    hour += 12
                elif ampm == 'am' and hour == 12:
                    hour = 0
                
                tomorrow = base_time + timedelta(days=1)
                return tomorrow.replace(hour=hour, minute=minute, second=0, microsecond=0)
        
        # Handle "at TIME" format for today
        if time_str.startswith('at '):
            match = re.search(r'at\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?', time_str)
            if match:
                hour = int(match.group(1))
                minute = int(match.group(2)) if match.group(2) else 0
                ampm = match.group(3)
                
                if ampm == 'pm' and hour != 12:
                    hour += 12
                elif ampm == 'am' and hour == 12:
                    hour = 0
                
                target_time = base_time.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if target_time <= base_time:
                    target_time += timedelta(days=1)
                return target_time
        
        # Parse relative time formats
        total_seconds = 0
        
        # Handle formats like "1h30m", "2 hours 30 minutes", "5min", etc.
        patterns = [
            r'(\d+)\s*h(?:ours?)?\s*(\d+)\s*m(?:in(?:utes?)?)?',  # 1h30m, 1 hour 30 minutes
            r'(\d+)\s*d(?:ays?)?\s*(\d+)\s*h(?:ours?)?',  # 1d2h, 1 day 2 hours
            r'(\d+)\s*([a-z]+)',  # 5 minutes, 2h, 3d, etc.
        ]
        
        # Try compound format first (1h30m)
        compound_match = re.search(patterns[0], time_str)
        if compound_match:
            hours = int(compound_match.group(1))
            minutes = int(compound_match.group(2))
            total_seconds = hours * 3600 + minutes * 60
        else:
            # Try day+hour format
            day_hour_match = re.search(patterns[1], time_str)
            if day_hour_match:
                days = int(day_hour_match.group(1))
                hours = int(day_hour_match.group(2))
                total_seconds = days * 86400 + hours * 3600
            else:
                # Find all individual time components
                for match in re.finditer(patterns[2], time_str):
                    value = int(match.group(1))
                    unit = match.group(2)
                    
                    if unit in self.units:
                        total_seconds += value * self.units[unit]
        
        if total_seconds > 0:
            return base_time + timedelta(seconds=total_seconds)
        
        return None

class ReminderSystem:
    """Manages reminders and background checking"""
    
    def __init__(self, bot):
        self.bot = bot
        self.parser = TimeParser()
        self.check_task = None
        self.running = False
        
        # Initialize database connection once
        import os
        # Default to rizon for reminder checker since it needs a default
        self.db = BotDatabase("rizon_bot.db")
    
    def start_checker(self):
        """Start the background reminder checker"""
        if not self.running:
            self.running = True
            self.check_task = asyncio.create_task(self._reminder_loop())
    
    def stop_checker(self):
        """Stop the background reminder checker"""
        self.running = False
        if self.check_task:
            self.check_task.cancel()
    
    async def _reminder_loop(self):
        """Background loop to check for due reminders"""
        while self.running:
            try:
                await self._check_reminders()
                await asyncio.sleep(5)  # Check every 5 seconds for better accuracy
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in reminder loop: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _check_reminders(self):
        """Check for and send due reminders"""
        try:
            now = datetime.now()
            
            # Get due reminders using existing database connection
            due_reminders = self.db.get_due_reminders(now)
            
            for reminder in due_reminders:
                user = reminder['user']
                channel = reminder['channel']
                message = reminder['message']
                reminder_id = reminder['id']
                
                # Send reminder
                remind_msg = f"{user}: ⏰ Reminder: {message}"
                await self.bot.safe_send(channel, remind_msg)
                
                # Mark as completed
                self.db.complete_reminder(reminder_id)
                
                logger.info(f"Sent reminder to {user} in {channel}: {message}")
                
        except Exception as e:
            logger.error(f"Error checking reminders: {e}")

# Global reminder system instance
reminder_system = None

@command(
    pattern=r'remind\(([^)]+)\)\s*(.+)',
    description="Set a reminder with flexible time format",
    usage="remind(time) message (e.g., remind(5 minutes) check pizza, remind(1h30m) meeting)",
    category="utility",
    requires_bot=True
)
async def set_reminder(msg, bot=None):
    """Set a reminder with flexible time parsing"""
    global reminder_system
    
    # Initialize reminder system if not already done
    if not reminder_system:
        reminder_system = ReminderSystem(bot)
        reminder_system.start_checker()
    
    try:
        import re
        
        # Extract time and message from the new format: remind(time) message
        pattern = r'remind\(([^)]+)\)\s*(.+)'
        match = re.search(pattern, msg["message"])
        
        if not match:
            # Get network-specific prefix
            from core.config import get_config
            network = 'libera' if msg["message"].startswith('~') else 'rizon'
            config = get_config(network)
            prefix = config.COMMAND_PREFIX
            
            return [
                "❌ Invalid reminder format.",
                f"Usage: {prefix}remind(time) message",
                f"Examples: {prefix}remind(5 minutes) check pizza",
                f"         {prefix}remind(1h30m) meeting starts",
                f"         {prefix}remind(tomorrow at 2pm) call dentist"
            ]
        
        time_part = match.group(1).strip()
        message_part = match.group(2).strip()
        
        if not time_part or not message_part:
            # Get network-specific prefix
            from core.config import get_config
            network = 'libera' if msg["message"].startswith('~') else 'rizon'
            config = get_config(network)
            prefix = config.COMMAND_PREFIX
            
            return [
                "❌ Both time and message are required.",
                f"Usage: {prefix}remind(time) message"
            ]
        
        # Parse the time
        parser = TimeParser()
        target_time = parser.parse_time_string(time_part)
        
        if not target_time:
            return f"❌ Could not understand time format: '{time_part}'"
        
        # Check if time is in the past
        if target_time <= datetime.now():
            return "❌ Reminder time must be in the future"
        
        # Store reminder in database (reuse existing connection if available)
        if reminder_system and hasattr(reminder_system, 'db'):
            db = reminder_system.db
        else:
            import os
            network = 'libera' if msg["message"].startswith('~') else 'rizon'
            db = BotDatabase(f"{network}_bot.db")
        
        reminder_id = db.add_reminder(
            user=msg["user"],
            channel=msg["channel"],
            message=message_part,
            remind_time=target_time
        )
        
        # Format time for display with better precision
        time_diff = target_time - datetime.now()
        total_seconds = int(time_diff.total_seconds())
        
        if total_seconds < 60:
            time_str = f"in {total_seconds} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            if seconds > 0:
                time_str = f"in {minutes}m {seconds}s"
            else:
                time_str = f"in {minutes} minutes"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            if minutes > 0:
                time_str = f"in {hours}h {minutes}m"
            else:
                time_str = f"in {hours} hours"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            if hours > 0:
                time_str = f"in {days}d {hours}h"
            else:
                time_str = f"in {days} days"
        
        return f"✅ Reminder set for {target_time.strftime('%Y-%m-%d %H:%M')} ({time_str}): {message_part}"
        
    except Exception as e:
        logger.error(f"Error setting reminder: {e}")
        return f"❌ Error setting reminder: {e}"

@command(
    pattern=r'reminders$',
    description="List your active reminders",
    category="utility"
)
def list_reminders(msg):
    """List user's active reminders"""
    try:
        # Reuse existing database connection if available
        global reminder_system
        if reminder_system and hasattr(reminder_system, 'db'):
            db = reminder_system.db
        else:
            import os
            network = 'libera' if msg["message"].startswith('~') else 'rizon'
            db = BotDatabase(f"{network}_bot.db")
        
        reminders = db.get_user_reminders(msg["user"])
        
        if not reminders:
            return "📝 You have no active reminders."
        
        response = ["📝 Your active reminders:"]
        for i, reminder in enumerate(reminders, 1):
            remind_time = datetime.fromisoformat(reminder['remind_time'])
            time_diff = remind_time - datetime.now()
            total_seconds = int(time_diff.total_seconds())
            
            if total_seconds < 60:
                time_str = f"in {total_seconds}s"
            elif total_seconds < 3600:
                minutes = total_seconds // 60
                seconds = total_seconds % 60
                if seconds > 0:
                    time_str = f"in {minutes}m {seconds}s"
                else:
                    time_str = f"in {minutes}m"
            elif total_seconds < 86400:
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                if minutes > 0:
                    time_str = f"in {hours}h {minutes}m"
                else:
                    time_str = f"in {hours}h"
            else:
                days = total_seconds // 86400
                hours = (total_seconds % 86400) // 3600
                if hours > 0:
                    time_str = f"in {days}d {hours}h"
                else:
                    time_str = f"in {days}d"
            
            response.append(f"{i}. {reminder['message']} ({time_str})")
        
        return response
        
    except Exception as e:
        logger.error(f"Error listing reminders: {e}")
        return f"❌ Error listing reminders: {e}"

@command(
    pattern=r'cancelreminder\s+(\d+)',
    description="Cancel a reminder by number (use 'reminders' to see numbers)",
    usage="cancelreminder <number>",
    category="utility"
)
def cancel_reminder(msg):
    """Cancel a specific reminder"""
    try:
        reminder_num = int(msg["message"].split()[1])
        
        # Reuse existing database connection if available
        global reminder_system
        if reminder_system and hasattr(reminder_system, 'db'):
            db = reminder_system.db
        else:
            import os
            network = 'libera' if msg["message"].startswith('~') else 'rizon'
            db = BotDatabase(f"{network}_bot.db")
        
        reminders = db.get_user_reminders(msg["user"])
        
        if not reminders or reminder_num < 1 or reminder_num > len(reminders):
            return f"❌ Invalid reminder number. Use 'reminders' to see your active reminders."
        
        reminder = reminders[reminder_num - 1]
        db.complete_reminder(reminder['id'])
        
        return f"✅ Cancelled reminder: {reminder['message']}"
        
    except (IndexError, ValueError):
        return "❌ Please specify a valid reminder number."
    except Exception as e:
        logger.error(f"Error cancelling reminder: {e}")
        return f"❌ Error cancelling reminder: {e}"

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
    logger.info("Reminder commands plugin loaded")
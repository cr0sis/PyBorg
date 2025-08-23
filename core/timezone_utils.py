"""
Timezone utilities for IRC bot
Centralizes timezone handling for consistent time reporting
"""

from datetime import datetime
import zoneinfo

# Set timezone to Europe/London (handles BST/GMT automatically)
UK_TZ = zoneinfo.ZoneInfo('Europe/London')

def now_uk():
    """Get current time in UK timezone (Europe/London)"""
    return datetime.now(UK_TZ)

def format_uk_time(dt=None, format_str='%Y-%m-%d %H:%M:%S %Z'):
    """Format time in UK timezone"""
    if dt is None:
        dt = now_uk()
    elif dt.tzinfo is None:
        # Assume naive datetime is UTC and convert to UK
        dt = dt.replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(UK_TZ)
    elif dt.tzinfo != UK_TZ:
        # Convert to UK timezone
        dt = dt.astimezone(UK_TZ)
    
    return dt.strftime(format_str)

def uk_timestamp():
    """Get current UK time as formatted string"""
    return format_uk_time()
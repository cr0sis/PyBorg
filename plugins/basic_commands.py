"""Basic utility commands for the IRC bot."""

import json
import logging
import os
import random
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

import requests
import lightstreamer.client
from lightstreamer.client import SubscriptionListener, LightstreamerClient, Subscription

from core.config import get_config
from core.database import BotDatabase
from core.plugin_system import command, admin_command

logger = logging.getLogger(__name__)

class ISSDataListener(SubscriptionListener):
    """Listener for ISS Live data updates."""
    
    def __init__(self, event: threading.Event) -> None:
        self.event: threading.Event = event
        self.value: Optional[float] = None
    
    def onItemUpdate(self, update) -> None:
        """Handle incoming data updates from ISS Live stream."""
        value = update.getValue("Value")
        if value:
            try:
                self.value = float(value)
            except ValueError:
                self.value = None
            self.event.set()

def update_json_log(new_value: float) -> List[Dict[str, Any]]:
    """Update JSON log file with new tank level value.
    
    Args:
        new_value: New tank level value to log
        
    Returns:
        Updated list of log entries
    """
    log_file = "tank_levels.json"
    timestamp = datetime.now().isoformat()
    log_entry = {"timestamp": timestamp, "value": new_value}
    
    try:
        with open(log_file, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = []
    
    data.append(log_entry)
    
    # Keep only the last 100 entries to prevent file from growing too large
    if len(data) > 100:
        data = data[-100:]
    
    with open(log_file, "w") as file:
        json.dump(data, file, indent=2)
    
    return data

def analyze_trend(data: List[Dict[str, Any]]) -> str:
    if len(data) < 2:
        return "Not enough data to determine a trend."
    
    latest = data[-1]
    previous = data[-2]
    
    if latest["value"] > previous["value"]:
        return "Astronauts are pissing piss."
    elif latest["value"] < previous["value"]:
        return "Astronauts are drinking piss."
    else:
        return "No astronaut is thirsty or pissing, tank level stable."

@command(
    pattern=r'piss',
    description="Get current space piss tank levels from ISS Live",
    category="fun"
)
def piss(msg) -> str:
    """Get current space piss tank levels from ISS Live API."""
    try:
        got_value = threading.Event()
        listener = ISSDataListener(got_value)
        client = LightstreamerClient("https://push.lightstreamer.com", "ISSLIVE")
        subscription = Subscription(
            mode="MERGE",
            items=["NODE3000005"],
            fields=["Value"]
        )
        subscription.addListener(listener)
        client.subscribe(subscription)
        client.connect()
        got_value.wait(timeout=10)
        client.disconnect()
        
        if listener.value is not None:
            data = update_json_log(listener.value)
            trend = analyze_trend(data)
            return f"Current space piss tank level is: {listener.value:.1f}%. {trend}"
        else:
            return "No data received within timeout."
    except Exception as e:
        logger.error(f"Error getting space piss tank data: {e}")
        return f"Error retrieving space piss tank data: {e}"

@command(
    pattern=r'\.bots$',
    description="Report bot presence",
    category="meta"
)
def report_in(msg):
    """Report that this is a bot"""
    return "PyBorg IRC bot reporting in - https://github.com/your-username/PyBorg"

@command(
    pattern=r'time$',
    description="Get current time",
    category="utility"
)
def check_time(msg):
    """Get current time"""
    from core.timezone_utils import now_uk
    return f"Current time: {now_uk().strftime('%H:%M:%S %Z')}"

@command(
    pattern=r'date',
    description="Get current date",
    usage="date [format]",
    category="utility"
)
def check_date(msg):
    """Get current date, optionally with custom format"""
    message_parts = msg["message"].split()
    
    if len(message_parts) > 1:
        # Custom format requested
        try:
            from core.timezone_utils import now_uk
            date_format = " ".join(message_parts[1:])
            return now_uk().strftime(date_format)
        except ValueError as e:
            return f"Invalid date format: {e}"
    
    from core.timezone_utils import now_uk
    return f"Current date: {now_uk().strftime('%Y-%m-%d %Z')}"

@command(
    pattern=r'random\s+(.+)',
    description="Pick random item from comma-separated list",
    usage="random item1, item2, item3",
    category="utility"
)
def random_choice(msg):
    """Pick a random item from a comma-separated list"""
    message = msg["message"]
    import re
    
    match = re.search(r'random\s+(.+)', message)
    if not match:
        return "Usage: random item1, item2, item3"
    
    items_text = match.group(1)
    items = [item.strip() for item in items_text.split(',')]
    
    if len(items) < 2:
        return "Please provide at least 2 items separated by commas"
    
    choice = random.choice(items)
    return f"Random choice: {choice}"

@command(
    pattern=r'lenny$',
    description="Display lenny face",
    category="fun"
)
def lenny(msg):
    """Return the classic lenny face"""
    return "( ͡° ͜ʖ ͡°)"

@command(
    pattern=r'calc\s+(.+)',
    description="Simple calculator (be careful with eval!)",
    usage="calc 2 + 2",
    category="utility"
)
def calculator(msg):
    """Simple calculator using eval (restricted)"""
    message = msg["message"]
    import re
    
    match = re.search(r'calc\s+(.+)', message)
    if not match:
        return "Usage: calc <expression>"
    
    expression = match.group(1)
    
    # Basic safety check - only allow numbers, operators, parentheses
    allowed_chars = set('0123456789+-*/().^ ')
    if not all(c in allowed_chars for c in expression):
        return "Invalid characters in expression. Only numbers and basic operators allowed."
    
    try:
        # Replace ^ with ** for exponentiation
        expression = expression.replace('^', '**')
        result = eval(expression)
        return f"Result: {result}"
    except ZeroDivisionError:
        return "Error: Division by zero"
    except Exception as e:
        return f"Error: Invalid expression"


@command(
    pattern=r'help(?:\s+(.+))?',
    description="Show help for commands",
    usage="help [command]",
    category="meta"
)
def show_help(msg):
    """Show help for commands"""
    # This will be implemented when we integrate with the plugin manager
    return "Help system is being rebuilt. Please suck my balls!"

@command(
    pattern=r'stats$',
    description="Show bot statistics",
    category="meta"
)
def get_stats(msg):
    """Get bot statistics"""
    # TODO: Implement with database
    uptime = time.time() - start_time if 'start_time' in globals() else 0
    hours = int(uptime // 3600)
    minutes = int((uptime % 3600) // 60)
    
    return f"Bot uptime: {hours}h {minutes}m"

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    # Store start time for stats
    global start_time
    start_time = time.time()
    
    # Auto-register all commands in this module
    auto_register_commands(plugin_manager, sys.modules[__name__])
    

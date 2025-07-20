"""Basic utility commands for the IRC bot"""

import time
import random
import logging
import json
import threading
import os
from datetime import datetime
from core.plugin_system import command, admin_command
from core.database import BotDatabase
from core.config import get_config
import requests
import lightstreamer.client
from lightstreamer.client import SubscriptionListener, LightstreamerClient, Subscription

logger = logging.getLogger(__name__)

class SubListener(SubscriptionListener):
    def __init__(self, event):
        self.event = event
        self.value = None
    
    def onItemUpdate(self, update):
        value = update.getValue("Value")
        if value:
            try:
                self.value = float(value)
            except ValueError:
                self.value = None
            self.event.set()

def update_json_log(new_value):
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

def analyze_trend(data):
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
def piss(msg):
    """Get current space piss tank levels from ISS Live API - exactly as original"""
    try:
        got_value = threading.Event()
        listener = SubListener(got_value)
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
        logger.error(f"Error getting piss tank data: {e}")
        return f"Error retrieving space piss tank data: {e}"

@command(
    pattern=r'\.bots$',
    description="Report bot presence",
    category="meta"
)
def report_in(msg):
    """Report that this is a bot"""
    return "PyBorg bot reporting in - https://github.com/cr0sis/cr0bot"

@command(
    pattern=r'time$',
    description="Get current time",
    category="utility"
)
def check_time(msg):
    """Get current time"""
    return f"Current time: {datetime.now().strftime('%H:%M:%S')}"

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
            date_format = " ".join(message_parts[1:])
            return datetime.now().strftime(date_format)
        except ValueError as e:
            return f"Invalid date format: {e}"
    
    return f"Current date: {datetime.now().strftime('%Y-%m-%d')}"

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

@admin_command(
    pattern=r'restart$',
    description="Restart the bot (admin only)",
    category="admin"
)
def restart_bot(msg):
    """Restart the bot - handled in main bot loop"""
    # This is handled specially in the main bot code
    return "Restarting bot..."

@admin_command(
    pattern=r'reload$',
    description="Reload all plugins without restarting (admin only)",
    category="admin"
)
def reload_plugins(msg):
    """Reload all plugins - handled in main bot loop"""
    # This is handled specially in the main bot code
    return "Reloading all plugins..."

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
    
    logger.info("Basic commands plugin loaded")

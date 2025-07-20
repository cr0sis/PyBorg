"""Server and player status commands"""

import logging
import json
import os
import requests
from datetime import datetime
from core.plugin_system import command

logger = logging.getLogger(__name__)

@command(
    pattern=r'lastdeath$',
    description="Get last death from log",
    category="server"
)
def pull_last_death(msg):
    """Pull last death from server log"""
    try:
        log_path = "last_death.json"
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                data = json.load(f)
                return f"💀 Last death: {data.get('message', 'No deaths recorded')}"
        else:
            return "💀 No death log found"
    except Exception as e:
        logger.error(f"Death log error: {e}")
        return "💀 Death log unavailable"

@command(
    pattern=r'players$',
    description="Get current online players",
    category="server"
)
def get_current_players(msg):
    """Get current online players"""
    try:
        # This would connect to a Minecraft server
        # Using placeholder for now
        return "👥 Players: Feature coming soon (needs server connection)"
    except Exception as e:
        logger.error(f"Players error: {e}")
        return "👥 Player list unavailable"

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
    logger.info("Server commands plugin loaded")
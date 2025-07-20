import os
import logging
from typing import List, Optional
from dotenv import load_dotenv

class ConfigError(Exception):
    """Raised when configuration is invalid or missing"""
    pass

class BotConfig:
    """Centralized configuration management with validation"""
    
    def __init__(self, network_name: str = "default"):
        load_dotenv()
        self.network_name = network_name
        self._validate_environment()
        self._load_config()
    
    def _validate_environment(self):
        """Validate required environment variables are present"""
        # Only GEMINI_API_KEY is required for AI features (optional)
        # No required vars for basic IRC functionality
        pass
    
    def _load_config(self):
        """Load configuration based on network"""
        # Network-specific configurations
        network_configs = {
            "example": {
                "host": "irc.example.com",
                "port": 6667,
                "nick": "PyBorg",
                "user": "PyBorg PyBorg PyBorg :PyBorg IRC Bot",
                "channels": ["#general", "#bot-testing"],
                "command_prefix": "!",
                "ai_trigger": "!speak"
            }
        }
        
        # Default to example if network not specified
        config = network_configs.get(self.network_name, network_configs["example"])
        
        # Core IRC settings
        self.HOST = config["host"]
        self.PORT = config["port"]
        self.NICK = config["nick"]
        self.USER = config["user"]
        self.CHANNELS = config["channels"]
        self.COMMAND_PREFIX = config["command_prefix"]
        self.AI_TRIGGER = config["ai_trigger"]
        self.NETWORK = self.network_name  # Add network identifier
        
        # Authentication (optional)
        self.NICKSERV_PASSWORD = os.getenv('NICKSERV_PASSWORD')
        
        # API Keys (optional)
        self.GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
        self.TWITCH_CLIENT_ID = os.getenv('TWITCH_CLIENT_ID')
        self.TWITCH_CLIENT_SECRET = os.getenv('TWITCH_CLIENT_SECRET')
        
        # Bot behavior settings
        self.RATE_LIMIT_MESSAGES = int(os.getenv('RATE_LIMIT_MESSAGES', '4'))
        self.RATE_LIMIT_PERIOD = int(os.getenv('RATE_LIMIT_PERIOD', '8'))
        self.MAX_CHAT_CONTEXT = int(os.getenv('MAX_CHAT_CONTEXT', '20'))
        self.MAX_CONVERSATION_HISTORY = int(os.getenv('MAX_CONVERSATION_HISTORY', '3'))
        
        # Auto-rejoin settings
        self.AUTO_REJOIN = os.getenv('AUTO_REJOIN', 'true').lower() == 'true'
        self.REJOIN_DELAY = int(os.getenv('REJOIN_DELAY', '5'))  # seconds
        
        # Logging configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.LOG_FORMAT = os.getenv('LOG_FORMAT', 
                                   '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Database settings
        self.DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{self.network_name}_bot.db')
        
    def get_log_file_path(self, log_type: str = "main") -> str:
        """Get path for log files"""
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        return os.path.join(log_dir, f'{self.network_name}_{log_type}.log')

# Convenience function to get network-specific config
def get_config(network_name: str = "example") -> BotConfig:
    """Get configuration for specified network"""
    return BotConfig(network_name)
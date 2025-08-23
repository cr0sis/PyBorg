import os
import json
import logging
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv
from pathlib import Path
from .paths import get_config_path

class ConfigError(Exception):
    """Raised when configuration is invalid or missing"""
    pass

class BotConfig:
    """Centralized configuration management with validation"""
    
    def __init__(self, network_name: str = "default"):
        load_dotenv(get_config_path('.env'))
        self.network_name = network_name
        self._validate_environment()
        self._load_config()
    
    def _validate_environment(self):
        """Validate required environment variables are present"""
        required_vars = ['GEMINI_API_KEY']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            raise ConfigError(f"Missing required environment variables: {missing_vars}")
    
    def _load_networks_config(self) -> Dict[str, Any]:
        """Load networks configuration from JSON file"""
        config_file = os.getenv('NETWORKS_CONFIG_FILE', 'networks.json')
        config_path = get_config_path(config_file)
        
        if not Path(config_path).exists():
            raise ConfigError(f"Networks configuration file not found: {config_path}. "
                            f"Please copy networks.example.json to {config_file} and configure your networks.")
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in networks configuration file: {e}")
        except Exception as e:
            raise ConfigError(f"Error loading networks configuration: {e}")
    
    def _load_config(self):
        """Load configuration based on network from networks.json"""
        # Load networks configuration from file
        networks_config = self._load_networks_config()
        
        # Get network-specific config or use first available network as default
        if self.network_name not in networks_config['networks']:
            available_networks = list(networks_config['networks'].keys())
            if not available_networks:
                raise ConfigError("No networks defined in networks configuration")
            self.network_name = available_networks[0]
            logging.warning(f"Network '{self.network_name}' not found, using '{self.network_name}' instead")
        
        config = networks_config['networks'][self.network_name]
        default_settings = networks_config.get('default_settings', {})
        
        # Core IRC settings
        self.HOST = config["host"]
        self.PORT = config.get("port", 6697)
        self.USE_SSL = config.get("use_ssl", True)
        self.NICK = config["nickname"]
        self.USER = config.get("realname", f"{config['nickname']} IRC Bot")
        self.CHANNELS = config["channels"]
        self.COMMAND_PREFIX = config["command_prefix"]
        self.AI_TRIGGER = f"{config['command_prefix']}speak"
        self.NETWORK = self.network_name
        self.NETWORK_DISPLAY_NAME = config.get("name", self.network_name.title())
        
        # Network-specific delays
        self.RECONNECT_DELAY = config.get("reconnect_delay", 30)
        self.AUTH_JOIN_DELAY = config.get("auth_join_delay", 5)
        
        # Authentication
        self.NICKSERV_PASSWORD = os.getenv('NICKSERV_PASSWORD')
        
        # API Keys
        self.GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
        self.TWITCH_CLIENT_ID = os.getenv('TWITCH_CLIENT_ID')
        self.TWITCH_CLIENT_SECRET = os.getenv('TWITCH_CLIENT_SECRET')
        
        # Bot behavior settings (environment > default_settings > hardcoded defaults)
        self.RATE_LIMIT_MESSAGES = int(os.getenv('RATE_LIMIT_MESSAGES', 
                                               str(default_settings.get('rate_limit_messages', 6))))
        self.RATE_LIMIT_PERIOD = int(os.getenv('RATE_LIMIT_PERIOD',
                                             str(default_settings.get('rate_limit_period', 30))))
        self.MAX_CHAT_CONTEXT = int(os.getenv('MAX_CHAT_CONTEXT',
                                            str(default_settings.get('ai_context_limit', 10))))
        self.MAX_CONVERSATION_HISTORY = int(os.getenv('MAX_CONVERSATION_HISTORY', '3'))
        self.MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH',
                                              str(default_settings.get('max_message_length', 400))))
        self.COMMAND_COOLDOWN = int(os.getenv('COMMAND_COOLDOWN',
                                            str(default_settings.get('command_cooldown', 2))))
        
        # Load database configuration overrides
        self._load_database_config()
        
        # Auto-rejoin settings
        self.AUTO_REJOIN = os.getenv('AUTO_REJOIN', 'true').lower() == 'true'
        self.REJOIN_DELAY = int(os.getenv('REJOIN_DELAY', '5'))  # seconds
        
        # Logging configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 
                                 default_settings.get('log_level', 'INFO')).upper()
        self.LOG_FORMAT = os.getenv('LOG_FORMAT', 
                                   '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Database settings
        from .paths import get_database_path
        default_db_path = get_database_path(f'{self.network_name}_bot.db')
        self.DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{default_db_path}')
        
        # Monitoring settings
        self.ENABLE_METRICS = os.getenv('ENABLE_METRICS', 'false').lower() == 'true'
        self.METRICS_PORT = int(os.getenv('METRICS_PORT', '8000'))
        
        # Trusted users for admin commands
        self.TRUSTED_USERS = self._parse_trusted_users()
    
    def _parse_trusted_users(self) -> List[tuple]:
        """Parse trusted users from environment or use defaults"""
        trusted_env = os.getenv('TRUSTED_USERS')
        if trusted_env:
            # Format: "nick1:hostmask1,nick2:hostmask2"
            pairs = trusted_env.split(',')
            return [(pair.split(':')[0], pair.split(':')[1]) for pair in pairs if ':' in pair]
        
        # Default trusted users
        return [
            ("admin", r".*@example\.com$"),
            ("admin", r".*@user/?admin$")
        ]
    
    def _load_database_config(self):
        """Load configuration overrides from database"""
        try:
            from .database import BotDatabase
            db = BotDatabase(f"{self.network_name}_bot.db")
            
            # Mapping of database settings to config attributes
            config_mapping = {
                'rate_limit_messages': ('RATE_LIMIT_MESSAGES', int),
                'rate_limit_period': ('RATE_LIMIT_PERIOD', int),
                'max_chat_context': ('MAX_CHAT_CONTEXT', int),
                'max_conversation_history': ('MAX_CONVERSATION_HISTORY', int),
                'auto_rejoin': ('AUTO_REJOIN', bool),
                'rejoin_delay': ('REJOIN_DELAY', int),
                'auth_join_delay': ('AUTH_JOIN_DELAY', int),
                'channels': ('CHANNELS', list),
                'command_prefix': ('COMMAND_PREFIX', str),
            }
            
            for db_setting, (attr_name, value_type) in config_mapping.items():
                current_value = getattr(self, attr_name)
                db_value = db.get_config(self.network_name, db_setting, current_value)
                
                # Only update if database value is different
                if db_value != current_value:
                    setattr(self, attr_name, db_value)
                    
        except Exception as e:
            # Don't crash if database config loading fails
            # The bot will continue with environment/default values
            pass
    
    def refresh_config(self):
        """Reload configuration from database"""
        self._load_database_config()
    
    def get_command_patterns(self):
        """Get command patterns with correct prefix for this network"""
        # This will be populated by the plugin system
        return []
    
    def validate(self):
        """Validate configuration is complete and valid"""
        if not self.HOST:
            raise ConfigError("IRC host not configured")
        if not self.CHANNELS:
            raise ConfigError("No channels configured")
        if not self.GEMINI_API_KEY:
            raise ConfigError("Gemini API key not configured")
        
        # Reduced verbosity - removed config validation logging message
        return True

# Global config instances
rizon_config = None
libera_config = None

def get_config(network: str = "rizon") -> BotConfig:
    """Get configuration instance for specified network"""
    global rizon_config, libera_config
    
    if network == "rizon":
        if rizon_config is None:
            rizon_config = BotConfig("rizon")
        return rizon_config
    elif network == "libera":
        if libera_config is None:
            libera_config = BotConfig("libera")
        return libera_config
    else:
        raise ConfigError(f"Unknown network: {network}")
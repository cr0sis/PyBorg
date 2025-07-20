#!/usr/bin/env python3
"""
PyBorg Setup Script
Interactive configuration for first-time bot setup
"""

import os
import sys
import getpass
from pathlib import Path

def print_banner():
    """Print welcome banner"""
    print("""
🤖 PyBorg Setup Wizard 🤖
==========================

Welcome to PyBorg! This wizard will help you configure your IRC bot.
You can run this script again anytime to update your configuration.

Let's get started!
""")

def get_input(prompt, default=None, required=True, secret=False):
    """Get user input with optional default and validation"""
    while True:
        if default:
            display_prompt = f"{prompt} [{default}]: "
        else:
            display_prompt = f"{prompt}: "
        
        if secret:
            value = getpass.getpass(display_prompt)
        else:
            value = input(display_prompt).strip()
        
        if not value and default:
            return default
        elif not value and required:
            print("❌ This field is required. Please enter a value.")
            continue
        elif not value and not required:
            return ""
        else:
            return value

def get_boolean(prompt, default=True):
    """Get yes/no input"""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        elif response in ['y', 'yes', 'true', '1']:
            return True
        elif response in ['n', 'no', 'false', '0']:
            return False
        else:
            print("❌ Please enter y/yes or n/no")

def get_number(prompt, default=None, min_val=None, max_val=None):
    """Get numeric input with validation"""
    while True:
        try:
            if default is not None:
                value = input(f"{prompt} [{default}]: ").strip()
                if not value:
                    return default
            else:
                value = input(f"{prompt}: ").strip()
            
            num = int(value)
            
            if min_val is not None and num < min_val:
                print(f"❌ Value must be at least {min_val}")
                continue
            
            if max_val is not None and num > max_val:
                print(f"❌ Value must be at most {max_val}")
                continue
                
            return num
            
        except ValueError:
            print("❌ Please enter a valid number")

def configure_network():
    """Configure IRC network settings"""
    print("\n📡 IRC Network Configuration")
    print("=" * 30)
    
    network_name = get_input("Network name (for identification)", "mynetwork")
    
    print("\n🌐 Server Settings:")
    host = get_input("IRC server hostname", "irc.example.com")
    port = get_number("IRC server port", 6667, 1, 65535)
    ssl = get_boolean("Use SSL/TLS connection", False)
    
    print("\n🤖 Bot Identity:")
    nick = get_input("Bot nickname", "PyBorg")
    realname = get_input("Bot real name", "PyBorg IRC Bot", required=False)
    username = get_input("Bot username (ident)", "pyborg", required=False) or nick.lower()
    
    print("\n📺 Channels:")
    print("Enter channels to join (one per line, press Enter on empty line to finish):")
    channels = []
    while True:
        channel = input("Channel: ").strip()
        if not channel:
            break
        if not channel.startswith('#'):
            channel = '#' + channel
        channels.append(channel)
    
    if not channels:
        channels = ["#general"]
        print("ℹ️ No channels specified, defaulting to #general")
    
    command_prefix = get_input("Command prefix", "!")
    
    return {
        'network_name': network_name,
        'host': host,
        'port': port,
        'ssl': ssl,
        'nick': nick,
        'username': username,
        'realname': realname,
        'channels': channels,
        'command_prefix': command_prefix
    }

def configure_authentication():
    """Configure authentication settings"""
    print("\n🔐 Authentication (Optional)")
    print("=" * 30)
    
    use_nickserv = get_boolean("Do you want to register/identify with NickServ", False)
    nickserv_password = ""
    
    if use_nickserv:
        nickserv_password = get_input("NickServ password", secret=True, required=False)
    
    return {
        'nickserv_password': nickserv_password
    }

def configure_features():
    """Configure optional features"""
    print("\n✨ Optional Features")
    print("=" * 20)
    
    # AI Features
    enable_ai = get_boolean("Enable AI chat features (requires Google Gemini API)", False)
    gemini_api_key = ""
    
    if enable_ai:
        print("\n🧠 AI Configuration:")
        print("You'll need a Google Gemini API key from: https://makersuite.google.com/")
        gemini_api_key = get_input("Gemini API key", secret=True, required=False)
    
    # Web Interface
    enable_web = get_boolean("Enable web interface", True)
    
    # Bot Behavior
    print("\n⚙️ Bot Behavior:")
    auto_rejoin = get_boolean("Auto-rejoin channels when kicked", True)
    rejoin_delay = 5
    if auto_rejoin:
        rejoin_delay = get_number("Delay before rejoining (seconds)", 5, 1, 60)
    
    rate_limit_messages = get_number("Rate limit: messages per period", 4, 1, 20)
    rate_limit_period = get_number("Rate limit: period (seconds)", 8, 1, 60)
    
    return {
        'enable_ai': enable_ai,
        'gemini_api_key': gemini_api_key,
        'enable_web': enable_web,
        'auto_rejoin': auto_rejoin,
        'rejoin_delay': rejoin_delay,
        'rate_limit_messages': rate_limit_messages,
        'rate_limit_period': rate_limit_period
    }

def configure_admin():
    """Configure admin users"""
    print("\n👑 Admin Configuration (Optional)")
    print("=" * 35)
    
    print("Enter admin usernames (one per line, press Enter on empty line to finish):")
    admin_users = []
    while True:
        user = input("Admin username: ").strip()
        if not user:
            break
        admin_users.append(user)
    
    print("\\nEnter admin hostmasks (one per line, press Enter on empty line to finish):")
    print("Example: *!*@your.hostname.com")
    admin_hostmasks = []
    while True:
        hostmask = input("Admin hostmask: ").strip()
        if not hostmask:
            break
        admin_hostmasks.append(hostmask)
    
    return {
        'admin_users': admin_users,
        'admin_hostmasks': admin_hostmasks
    }

def generate_config_files(config):
    """Generate configuration files"""
    print("\n📄 Generating Configuration Files")
    print("=" * 35)
    
    # Create .env file
    env_content = f"""# PyBorg Environment Configuration
# Generated by setup.py

# Network Configuration
NETWORK_NAME={config['network']['network_name']}

# Authentication (optional)
NICKSERV_PASSWORD={config['auth']['nickserv_password']}

# API Keys (optional)
GEMINI_API_KEY={config['features']['gemini_api_key']}

# Bot Behavior
AUTO_REJOIN={'true' if config['features']['auto_rejoin'] else 'false'}
REJOIN_DELAY={config['features']['rejoin_delay']}
RATE_LIMIT_MESSAGES={config['features']['rate_limit_messages']}
RATE_LIMIT_PERIOD={config['features']['rate_limit_period']}

# Admin Users (comma-separated)
ADMIN_USERS={','.join(config['admin']['admin_users'])}
ADMIN_HOSTMASKS={','.join(config['admin']['admin_hostmasks'])}

# Logging
LOG_LEVEL=INFO
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    # Update config.py with network configuration
    config_content = f"""import os
import logging
from typing import List, Optional
from dotenv import load_dotenv

class ConfigError(Exception):
    \"\"\"Raised when configuration is invalid or missing\"\"\"
    pass

class BotConfig:
    \"\"\"Centralized configuration management with validation\"\"\"
    
    def __init__(self, network_name: str = "{config['network']['network_name']}"):
        load_dotenv()
        self.network_name = network_name
        self._validate_environment()
        self._load_config()
    
    def _validate_environment(self):
        \"\"\"Validate required environment variables are present\"\"\"
        # Only GEMINI_API_KEY is required for AI features (optional)
        # No required vars for basic IRC functionality
        pass
    
    def _load_config(self):
        \"\"\"Load configuration based on network\"\"\"
        # Network-specific configurations
        network_configs = {{
            "{config['network']['network_name']}": {{
                "host": "{config['network']['host']}",
                "port": {config['network']['port']},
                "nick": "{config['network']['nick']}",
                "user": "{config['network']['username']} {config['network']['username']} {config['network']['username']} :{config['network']['realname']}",
                "channels": {config['network']['channels']},
                "command_prefix": "{config['network']['command_prefix']}",
                "ai_trigger": "{config['network']['command_prefix']}speak"
            }}
        }}
        
        # Default to configured network if network not specified
        config = network_configs.get(self.network_name, network_configs["{config['network']['network_name']}"])
        
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
        self.DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{{self.network_name}}_bot.db')
        
    def get_log_file_path(self, log_type: str = "main") -> str:
        \"\"\"Get path for log files\"\"\"
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        return os.path.join(log_dir, f'{{self.network_name}}_{{log_type}}.log')

# Convenience function to get network-specific config
def get_config(network_name: str = "{config['network']['network_name']}") -> BotConfig:
    \"\"\"Get configuration for specified network\"\"\"
    return BotConfig(network_name)
"""
    
    with open('core/config.py', 'w') as f:
        f.write(config_content)
    
    # Create start script
    start_script = f"""#!/bin/bash
# PyBorg Start Script

echo "🚀 Starting PyBorg..."
python3 bot.py {config['network']['network_name']}
"""
    
    with open('start.sh', 'w') as f:
        f.write(start_script)
    
    os.chmod('start.sh', 0o755)
    
    print("✅ Generated configuration files:")
    print("   - .env (environment variables)")
    print("   - core/config.py (updated network config)")
    print("   - start.sh (startup script)")

def main():
    """Main setup function"""
    print_banner()
    
    try:
        # Change to PyBorg directory
        script_dir = Path(__file__).parent.parent
        os.chdir(script_dir)
        
        # Collect configuration
        config = {
            'network': configure_network(),
            'auth': configure_authentication(), 
            'features': configure_features(),
            'admin': configure_admin()
        }
        
        # Generate files
        generate_config_files(config)
        
        print(f"""
🎉 Setup Complete! 🎉

Your PyBorg bot is now configured for the '{config['network']['network_name']}' network.

Next steps:
1. Review the generated .env file
2. Install dependencies: pip3 install -r requirements.txt
3. Start your bot: ./start.sh

For help and documentation, see: README.md

Happy botting! 🤖
""")
        
    except KeyboardInterrupt:
        print("\\n\\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\\n❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
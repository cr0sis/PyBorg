"""
Path configuration system for PyBorg.
Centralizes all file path handling with environment variable support.
"""

import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Base paths from environment with sensible defaults
# Use current directory as base for PyBorg standalone version
BASE_DIR = Path(os.getenv('BOT_BASE_DIR', Path(__file__).parent.parent))
DATA_DIR = Path(os.getenv('BOT_DATA_DIR', BASE_DIR / 'data'))
WEB_DIR = Path(os.getenv('BOT_WEB_DIR', BASE_DIR / 'web'))

# Subdirectories
DATABASE_DIR = Path(os.getenv('BOT_DATABASE_DIR', DATA_DIR / 'databases'))
LOG_DIR = Path(os.getenv('BOT_LOG_DIR', DATA_DIR / 'logs'))
PLUGIN_DIR = Path(os.getenv('BOT_PLUGIN_DIR', BASE_DIR / 'plugins'))
CONFIG_DIR = Path(os.getenv('BOT_CONFIG_DIR', BASE_DIR))

# Ensure critical directories exist
def ensure_directories():
    """Create necessary directories if they don't exist."""
    directories = [DATABASE_DIR, LOG_DIR, PLUGIN_DIR]
    
    for dir_path in directories:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured directory exists: {dir_path}")
        except PermissionError:
            logger.error(f"Permission denied creating directory: {dir_path}")
            raise
        except Exception as e:
            logger.error(f"Failed to create directory {dir_path}: {e}")
            raise

# Helper functions for path resolution
def get_database_path(filename: str) -> Path:
    """Get absolute path for database file."""
    return DATABASE_DIR / filename

def get_log_path(filename: str) -> Path:
    """Get absolute path for log file."""
    return LOG_DIR / filename

def get_config_path(filename: str) -> Path:
    """Get absolute path for config file."""
    return CONFIG_DIR / filename

def get_network_log_dir(network: str) -> Path:
    """Get network-specific log directory."""
    network_log_dir = LOG_DIR / 'irc_networks' / network
    network_log_dir.mkdir(parents=True, exist_ok=True)
    return network_log_dir

def get_network_log_path(network: str, filename: str) -> Path:
    """Get absolute path for network-specific log file."""
    return get_network_log_dir(network) / filename

def get_data_dir() -> Path:
    """Get the data directory path."""
    return DATA_DIR

# Logging for path configuration
def log_path_configuration():
    """Log current path configuration for debugging."""
    logger.info("Path configuration:")
    logger.info(f"  BASE_DIR: {BASE_DIR}")
    logger.info(f"  DATA_DIR: {DATA_DIR}")
    logger.info(f"  DATABASE_DIR: {DATABASE_DIR}")
    logger.info(f"  LOG_DIR: {LOG_DIR}")
    logger.info(f"  PLUGIN_DIR: {PLUGIN_DIR}")
    logger.info(f"  CONFIG_DIR: {CONFIG_DIR}")
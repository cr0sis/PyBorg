import logging
import logging.handlers
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
import zoneinfo
from .paths import get_network_log_dir, get_network_log_path

# Set timezone to Europe/London
UK_TZ = zoneinfo.ZoneInfo('Europe/London')

class UKTimeFormatter(logging.Formatter):
    """Custom formatter that converts UTC log times to UK time"""
    
    def formatTime(self, record, datefmt=None):
        # Convert the log record time to UK timezone
        dt = datetime.fromtimestamp(record.created, tz=UK_TZ)
        if datefmt:
            return dt.strftime(datefmt)
        else:
            return dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    
class BotLogger:
    """Centralized logging configuration for the IRC bot"""
    
    def __init__(self, network_name: str = "default", log_level: str = "INFO"):
        self.network_name = network_name
        self.log_level = getattr(logging, log_level.upper())
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging with file rotation and structured output"""
        # Use centralized log directory
        log_dir = get_network_log_dir(self.network_name)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)
        
        # Clear any existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Console handler with plain output (no colors)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        console_formatter = UKTimeFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S %Z'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            get_network_log_path(self.network_name, f"{self.network_name}_bot.log"),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        # Use plain formatter for file logs (no colors)
        file_formatter = UKTimeFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S %Z'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
        # Error file handler for errors and above
        error_handler = logging.handlers.RotatingFileHandler(
            get_network_log_path(self.network_name, f"{self.network_name}_errors.log"),
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        root_logger.addHandler(error_handler)
        
        # Reduced verbosity - removed startup logging message

def setup_logging(network_name: str = "default", log_level: str = "INFO"):
    """Setup logging for the bot"""
    return BotLogger(network_name, log_level)

# Context manager for function-specific logging
class FunctionLogger:
    """Context manager for adding function-specific context to logs"""
    
    def __init__(self, logger, function_name: str, **context):
        self.logger = logger
        self.function_name = function_name
        self.context = context
    
    def __enter__(self):
        context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
        self.logger.debug(f"Entering {self.function_name}({context_str})")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.logger.error(f"Exception in {self.function_name}: {exc_val}")
        else:
            self.logger.debug(f"Exiting {self.function_name}")

def log_function_call(logger):
    """Decorator to automatically log function calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with FunctionLogger(logger, func.__name__, args=len(args), kwargs=list(kwargs.keys())):
                return func(*args, **kwargs)
        return wrapper
    return decorator
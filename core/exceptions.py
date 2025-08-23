"""Custom exceptions for the IRC bot"""

class BotError(Exception):
    """Base exception for bot-related errors"""
    pass

class ConfigurationError(BotError):
    """Raised when configuration is invalid"""
    pass

class ConnectionError(BotError):
    """Raised when IRC connection fails"""
    pass

class CommandError(BotError):
    """Raised when command execution fails"""
    pass

class APIError(BotError):
    """Raised when external API calls fail"""
    def __init__(self, message: str, api_name: str = None, status_code: int = None):
        super().__init__(message)
        self.api_name = api_name
        self.status_code = status_code

class DatabaseError(BotError):
    """Raised when database operations fail"""
    pass

class RateLimitError(BotError):
    """Raised when rate limits are exceeded"""
    pass
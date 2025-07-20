"""Plugin system for IRC bot commands"""

import re
import logging
import inspect
import importlib
import importlib.util
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass
from pathlib import Path
from .exceptions import CommandError

logger = logging.getLogger(__name__)

@dataclass
class CommandInfo:
    """Information about a registered command"""
    name: str
    pattern: str
    handler: Callable
    description: str
    usage: str
    category: str = "general"
    requires_bot: bool = False
    admin_only: bool = False
    rate_limit: Optional[float] = None

class PluginManager:
    """Manages command plugins and their registration"""
    
    def __init__(self, command_prefix: str = "!"):
        self.command_prefix = command_prefix
        self.commands: Dict[str, CommandInfo] = {}
        self.categories: Dict[str, List[str]] = {}
        self.compiled_patterns: List[tuple] = []
        self.message_handlers: List[Callable] = []
    
    def register_command(self, 
                        pattern: str, 
                        handler: Callable,
                        name: str = None,
                        description: str = "No description available",
                        usage: str = None,
                        category: str = "general",
                        requires_bot: bool = False,
                        admin_only: bool = False,
                        rate_limit: Optional[float] = None):
        """Register a command with the plugin system"""
        
        if name is None:
            name = handler.__name__
        
        if usage is None:
            usage = f"{self.command_prefix}{name}"
        
        # Ensure pattern starts with command prefix if it's a simple command
        if not pattern.startswith('^'):
            if not pattern.startswith(self.command_prefix):
                pattern = f"^{re.escape(self.command_prefix)}{pattern}"
            else:
                pattern = f"^{re.escape(pattern)}"
        
        cmd_info = CommandInfo(
            name=name,
            pattern=pattern,
            handler=handler,
            description=description,
            usage=usage,
            category=category,
            requires_bot=requires_bot,
            admin_only=admin_only,
            rate_limit=rate_limit
        )
        
        self.commands[name] = cmd_info
        
        # Add to category
        if category not in self.categories:
            self.categories[category] = []
        self.categories[category].append(name)
        
        # Compile pattern for performance
        try:
            compiled_pattern = re.compile(pattern)
            self.compiled_patterns.append((compiled_pattern, cmd_info))
            logger.debug(f"Registered command '{name}' with pattern '{pattern}'")
        except re.error as e:
            logger.error(f"Invalid regex pattern for command '{name}': {e}")
    
    def register_message_handler(self, handler: Callable):
        """Register a function to be called on every message"""
        self.message_handlers.append(handler)
        logger.debug(f"Registered message handler: {handler.__name__}")
    
    def handle_message(self, msg, bot=None):
        """Call all registered message handlers"""
        results = []
        for handler in self.message_handlers:
            try:
                result = handler(msg, bot)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error in message handler {handler.__name__}: {e}")
        return results
    
    def find_command(self, message: str) -> Optional[CommandInfo]:
        """Find matching command for a message"""
        for pattern, cmd_info in self.compiled_patterns:
            if pattern.search(message):
                return cmd_info
        return None
    
    def get_commands_by_category(self, category: str = None) -> Dict[str, List[CommandInfo]]:
        """Get commands grouped by category"""
        if category:
            return {category: [self.commands[name] for name in self.categories.get(category, [])]}
        
        result = {}
        for cat, cmd_names in self.categories.items():
            result[cat] = [self.commands[name] for name in cmd_names]
        return result
    
    def get_help_text(self, command_name: str = None) -> str:
        """Generate help text for commands"""
        if command_name:
            if command_name in self.commands:
                cmd = self.commands[command_name]
                return f"{cmd.usage} - {cmd.description}"
            return f"Command '{command_name}' not found"
        
        # Generate full help
        help_lines = [f"Available commands (prefix: {self.command_prefix}):"]
        
        for category, commands in self.get_commands_by_category().items():
            if commands:
                help_lines.append(f"\n{category.title()}:")
                for cmd in commands:
                    help_lines.append(f"  {cmd.usage} - {cmd.description}")
        
        return "\n".join(help_lines)
    
    def load_plugins_from_directory(self, plugin_dir: str):
        """Load all plugins from a directory"""
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            logger.warning(f"Plugin directory {plugin_dir} does not exist")
            return
        
        for plugin_file in plugin_path.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                # Add the plugin directory to Python path for core imports
                import sys
                import os
                bot_dir = os.path.dirname(os.path.dirname(__file__))
                plugin_dir = str(plugin_path)
                
                if bot_dir not in sys.path:
                    sys.path.insert(0, bot_dir)
                if plugin_dir not in sys.path:
                    sys.path.insert(0, plugin_dir)
                
                # Import the plugin module directly
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, str(plugin_file))
                module = importlib.util.module_from_spec(spec)
                
                # Set the module in sys.modules to help with imports
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                
                # Look for setup function
                if hasattr(module, 'setup_plugin'):
                    module.setup_plugin(self)
                    logger.info(f"Loaded plugin: {plugin_file.stem}")
                else:
                    logger.warning(f"Plugin {plugin_file.stem} has no setup_plugin function")
                    
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file.stem}: {e}")

# Decorators for easy command registration
def command(pattern: str = None, 
           name: str = None,
           description: str = "No description available",
           usage: str = None,
           category: str = "general",
           requires_bot: bool = False,
           admin_only: bool = False,
           rate_limit: Optional[float] = None):
    """Decorator to register a function as a command"""
    def decorator(func):
        # Store command metadata on the function
        func._command_pattern = pattern or func.__name__
        func._command_name = name or func.__name__
        func._command_description = description
        func._command_usage = usage
        func._command_category = category
        func._command_requires_bot = requires_bot
        func._command_admin_only = admin_only
        func._command_rate_limit = rate_limit
        return func
    return decorator

def admin_command(pattern: str = None, **kwargs):
    """Decorator for admin-only commands"""
    kwargs['admin_only'] = True
    return command(pattern, **kwargs)

def bot_command(pattern: str = None, **kwargs):
    """Decorator for commands that require bot instance"""
    kwargs['requires_bot'] = True
    return command(pattern, **kwargs)

# Auto-registration helper
def auto_register_commands(plugin_manager: PluginManager, module):
    """Automatically register all decorated commands in a module"""
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and hasattr(obj, '_command_pattern'):
            plugin_manager.register_command(
                pattern=obj._command_pattern,
                handler=obj,
                name=obj._command_name,
                description=obj._command_description,
                usage=obj._command_usage,
                category=obj._command_category,
                requires_bot=obj._command_requires_bot,
                admin_only=obj._command_admin_only,
                rate_limit=obj._command_rate_limit
            )

# Global plugin manager instances
rizon_plugins = None
libera_plugins = None

def get_plugin_manager(network: str, command_prefix: str) -> PluginManager:
    """Get plugin manager instance for specified network"""
    global rizon_plugins, libera_plugins
    
    if network == "rizon":
        if rizon_plugins is None:
            rizon_plugins = PluginManager(command_prefix)
        return rizon_plugins
    elif network == "libera":
        if libera_plugins is None:
            libera_plugins = PluginManager(command_prefix)
        return libera_plugins
    else:
        raise ValueError(f"Unknown network: {network}")
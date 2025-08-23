#!/usr/bin/env python3
"""
Enhanced IRC Bot with professional architecture
Supports multiple networks with different command prefixes
"""

import asyncio
import time
import re
import os
import sys
import signal
import logging
import json
import glob
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List, Union
from pathlib import Path

# Core imports
from core.config import get_config, ConfigError
from core.logging_config import setup_logging
from core.database import BotDatabase
from core.plugin_system import get_plugin_manager
from core.exceptions import BotError, ConnectionError, CommandError
from core.paths import ensure_directories, log_path_configuration

class RateLimiter:
    """Token bucket rate limiter for controlling message flow."""
    
    def __init__(self, rate: int, per: int) -> None:
        self.rate: int = rate
        self.per: int = per
        self.allowance: float = float(rate)
        self.last_check: float = time.time()

    def allowed(self) -> bool:
        now = time.time()
        self.allowance += (now - self.last_check) * (self.rate / self.per)
        self.last_check = now
        
        if self.allowance > self.rate:
            self.allowance = self.rate
        
        if self.allowance < 1.0:
            return False
        
        self.allowance -= 1.0
        return True

class AsyncIRCBot:
    """Professional async IRC bot with plugin support and multi-network capability."""
    
    def __init__(self, network: str = "rizon") -> None:
        self.network: str = network
        self.config = get_config(network)
        self.logger: logging.Logger = logging.getLogger(f"bot.{network}")
        
        # Connection state
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected: bool = False
        self.welcomed: bool = False
        self.identified: bool = False
        self.nickserv_attempts: int = 0
        self.last_identify_time: float = 0
        
        # Core components
        self.rate_limiter: RateLimiter = RateLimiter(
            self.config.RATE_LIMIT_MESSAGES, 
            self.config.RATE_LIMIT_PERIOD
        )
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.queue_processor_task: Optional[asyncio.Task] = None
        self.database: BotDatabase = BotDatabase(f"{network}_bot.db")
        self.plugin_manager = get_plugin_manager(network, self.config.COMMAND_PREFIX)
        
        # Chat context for AI - stores last message from each user
        self.chat_context: Dict[str, str] = {}
        
        # Fallback commands if plugin system fails
        self.fallback_commands: List[str] = []
        
        # Load plugins
        self._load_plugins()
        
        # Add fallback commands if plugins failed to load
        if len(self.plugin_manager.commands) == 0:
            self._load_fallback_commands()
        
        # Configuration refresh task
        self.config_refresh_task: Optional[asyncio.Task] = None
        
        # Legacy migration code removed - migration completed
    
    def _load_plugins(self) -> None:
        """Load all plugins from the plugin directory."""
        try:
            # Plugins are now loaded automatically by get_plugin_manager
            command_count = len(self.plugin_manager.commands)
            self.logger.info(f"Loaded {command_count} commands")
        except Exception as e:
            self.logger.error(f"Error loading plugins: {e}")
    
    def _reload_plugins(self) -> None:
        """Reload all plugins and core modules by clearing and reloading."""
        try:
            import sys
            import importlib
            
            self._clear_plugin_state()
            self._reload_core_modules(sys, importlib)
            self._recreate_database_instance()
            self._reload_plugin_modules(sys, importlib)
            self._load_fresh_plugins()
            
        except Exception as e:
            self.logger.error(f"Error reloading plugins: {e}")
            raise
    
    def _clear_plugin_state(self) -> None:
        """Clear existing plugin commands and patterns."""
        self.plugin_manager.commands.clear()
        self.plugin_manager.categories.clear()
        self.plugin_manager.compiled_patterns.clear()
    
    def _reload_core_modules(self, sys, importlib) -> None:
        """Reload core system modules."""
        core_modules = ['core.database', 'core.config', 'core.plugin_system']
        for module_name in core_modules:
            if module_name in sys.modules:
                importlib.reload(sys.modules[module_name])
                self.logger.debug(f"Reloaded core module: {module_name}")
    
    def _recreate_database_instance(self) -> None:
        """Recreate the database instance after module reload."""
        if hasattr(self, 'database'):
            from core.database import BotDatabase
            db_path = (
                self.database.db_path 
                if hasattr(self.database, 'db_path') 
                else f"{self.config.NETWORK.lower()}_bot.db"
            )
            self.database = BotDatabase(db_path)
            self.logger.debug(f"Recreated database instance: {db_path}")
    
    def _reload_plugin_modules(self, sys, importlib) -> None:
        """Reload all plugin modules from the plugin directory."""
        from core.paths import PLUGIN_DIR
        
        if not PLUGIN_DIR.exists():
            self.logger.warning(f"Plugin directory not found: {PLUGIN_DIR}")
            return
        
        # Find and reload all plugin modules
        plugin_modules = []
        for py_file in PLUGIN_DIR.glob("*.py"):
            if py_file.name.startswith("__"):
                continue
            module_name = f"plugins.{py_file.stem}"
            plugin_modules.append(module_name)
        
        # Reload each plugin module
        for module_name in plugin_modules:
            if module_name in sys.modules:
                try:
                    importlib.reload(sys.modules[module_name])
                    self.logger.debug(f"Reloaded plugin module: {module_name}")
                except Exception as e:
                    self.logger.error(f"Failed to reload {module_name}: {e}")
    
    def _load_fresh_plugins(self) -> None:
        """Load fresh plugin instances after modules have been reloaded."""
        from core.plugin_system import get_plugin_manager
        import core.plugin_system
        
        # Reset the global plugin manager for this network to force creation of new instance
        if self.config.NETWORK in core.plugin_system._plugin_managers:
            del core.plugin_system._plugin_managers[self.config.NETWORK]
        
        # Get a fresh plugin manager instance
        self.plugin_manager = get_plugin_manager(self.config.NETWORK, self.config.COMMAND_PREFIX)
        
        # Reload the database instance for the plugin manager
        if hasattr(self, 'database'):
            self.plugin_manager.database = self.database
        
        # Log the result
        command_count = len(self.plugin_manager.commands)
        self.logger.info(f"Fresh plugins loaded: {command_count} commands registered")
            
    
    def _load_fallback_commands(self) -> None:
        """Load fallback commands if plugin system fails."""
        self.logger.info("Loading fallback commands...")
        
        try:
            import simple_commands
            
            command_prefix = re.escape(self.config.COMMAND_PREFIX)
            commands = [
                (rf'^{command_prefix}piss', simple_commands.piss),
                (rf'^\.bots$', simple_commands.report_in),
                (rf'^{command_prefix}time$', simple_commands.check_time),
                (rf'^{command_prefix}date', simple_commands.check_date),
                (rf'^{command_prefix}random\s+', simple_commands.random_choice),
                (rf'^{command_prefix}calc\s+', simple_commands.calculator),
                (rf'^{command_prefix}lenny$', simple_commands.lenny),
                (rf'^{command_prefix}roll7$', simple_commands.roll_dice2),
                (rf'^{command_prefix}temp$', simple_commands.get_temp),
                (rf'^{command_prefix}help', simple_commands.show_help),
            ]
            
            # Compile patterns for command processing
            self.fallback_commands = [
                (re.compile(pattern), handler) 
                for pattern, handler in commands
            ]
            self.logger.info(f"Loaded {len(commands)} fallback commands")
            
        except Exception as e:
            self.logger.error(f"Failed to load fallback commands: {e}")
            self.fallback_commands = []
    
    # Legacy migration method removed
    
    async def connect(self):
        """Connect to IRC server"""
        try:
            self.logger.info(f"Connecting to {self.config.HOST}:{self.config.PORT}")
            self.reader, self.writer = await asyncio.open_connection(
                self.config.HOST, self.config.PORT
            )
            self.connected = True
            
            # Start message queue processor
            self.queue_processor_task = asyncio.create_task(self.process_message_queue())
            
            # Start configuration refresh task (check every 30 seconds)
            self.config_refresh_task = asyncio.create_task(self.config_refresh_loop())
            
            # Send initial IRC commands
            await self.send_raw(f"USER {self.config.USER}\r\n")
            await self.send_raw(f"NICK {self.config.NICK}\r\n")
            
            self.logger.info("Connected successfully")
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Failed to connect: {e}")
    
    async def send_raw(self, message: str):
        """Send raw message to IRC server"""
        if self.writer:
            self.writer.write(message.encode("utf-8"))
            await self.writer.drain()
    
    async def send_message(self, target: str, message: str):
        """Send PRIVMSG to target"""
        await self.send_raw(f"PRIVMSG {target} :{message}\r\n")
    
    async def safe_send(self, target: str, message):
        """Queue messages for rate-limited sending"""
        if isinstance(message, str):
            await self.message_queue.put((target, message))
        elif isinstance(message, list):
            for msg in message:
                await self.message_queue.put((target, str(msg)))
    
    def _log_chat_message(self, message: str):
        """Log chat messages with simplified format (no function name/line number)"""
        self._log_simple(message)
        
    def _log_simple(self, message: str, level: str = "INFO"):
        """Log messages with simplified format (no function name/line number)"""
        from core.timezone_utils import uk_timestamp
        timestamp = uk_timestamp()
        
        # Plain log entry without colors
        log_entry = f"{timestamp} - bot.{self.network} - {level} - {message}"
        
        # Write directly to log file to avoid function name/line number
        from core.paths import get_network_log_path
        log_file = get_network_log_path(self.network, f"{self.network}_bot.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
            
        # Also write to console (plain text)
        print(log_entry)
    
    async def process_message_queue(self):
        """Process queued messages with rate limiting"""
        while self.connected:
            try:
                # Wait for a message in the queue
                target, message = await asyncio.wait_for(
                    self.message_queue.get(), timeout=1.0
                )
                
                # Wait for rate limiter to allow sending
                while not self.rate_limiter.allowed():
                    await asyncio.sleep(0.1)  # Check every 100ms
                
                # Send the message
                clean_message = self.clean_irc_formatting(message)
                self._log_simple(f"🤖 [{target}] <{self.config.NICK}> {clean_message}")
                await self.send_message(target, message)
                
            except asyncio.TimeoutError:
                # No messages in queue, continue
                continue
            except Exception as e:
                self.logger.error(f"Error processing message queue: {e}")
                await asyncio.sleep(1)  # Wait before retrying
    
    async def config_refresh_loop(self):
        """Periodically refresh configuration from database"""
        while self.connected:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                # Refresh configuration
                old_rate_messages = self.config.RATE_LIMIT_MESSAGES
                old_rate_period = self.config.RATE_LIMIT_PERIOD
                
                self.config.refresh_config()
                
                # Update rate limiter if rate limits changed
                if (self.config.RATE_LIMIT_MESSAGES != old_rate_messages or 
                    self.config.RATE_LIMIT_PERIOD != old_rate_period):
                    
                    self.rate_limiter = RateLimiter(
                        self.config.RATE_LIMIT_MESSAGES,
                        self.config.RATE_LIMIT_PERIOD
                    )
                    self.logger.info(f"Updated rate limits: {self.config.RATE_LIMIT_MESSAGES} msgs/{self.config.RATE_LIMIT_PERIOD}s")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error refreshing config: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def join_channels(self):
        """Join configured channels"""
        self.logger.info(f"Attempting to join {len(self.config.CHANNELS)} channels: {self.config.CHANNELS}")
        for channel in self.config.CHANNELS:
            self.logger.debug(f"Sending JOIN command for {channel}")
            await self.send_raw(f"JOIN {channel}\r\n")
            await asyncio.sleep(0.5)  # Small delay between joins
        self.logger.info("All JOIN commands sent")
    
    async def identify_with_nickserv(self):
        """Handle NickServ identification"""
        current_time = time.time()
        
        # Prevent spamming NickServ
        if current_time - self.last_identify_time < 5:  # Wait at least 5 seconds between attempts
            return
            
        if self.config.NICKSERV_PASSWORD and self.nickserv_attempts < 3:
            self.nickserv_attempts += 1
            self.last_identify_time = current_time
            self.logger.debug(f"Sending IDENTIFY command to NickServ (attempt {self.nickserv_attempts})")
            await self.send_raw(f"PRIVMSG NickServ :IDENTIFY {self.config.NICKSERV_PASSWORD}\r\n")
            self._log_simple(f"🔐 Sent NickServ IDENTIFY command (attempt {self.nickserv_attempts})")
            
            # Set a timeout to proceed anyway if no response
            if self.nickserv_attempts == 1:
                asyncio.create_task(self._nickserv_timeout())
        else:
            if self.nickserv_attempts >= 3:
                self.logger.warning("⚠️ Max NickServ attempts reached, proceeding with authentication delay")
            else:
                self.logger.info("ℹ️ No NickServ password configured, skipping identification")
            self.identified = True
            if self.welcomed:
                self.logger.info(f"⏳ Waiting {self.config.AUTH_JOIN_DELAY} seconds before joining channels to prevent IP exposure")
                await asyncio.sleep(self.config.AUTH_JOIN_DELAY)
                self.logger.info("🏁 Proceeding to join channels after authentication delay")
                await self.join_channels()
    
    async def _nickserv_timeout(self):
        """Timeout for NickServ identification"""
        await asyncio.sleep(15)  # Wait 15 seconds for NickServ response
        if not self.identified and self.welcomed:
            self.logger.warning("⏰ NickServ identification timeout, proceeding with authentication delay")
            self.identified = True
            self.logger.info(f"⏳ Waiting {self.config.AUTH_JOIN_DELAY} seconds before joining channels to prevent IP exposure")
            await asyncio.sleep(self.config.AUTH_JOIN_DELAY)
            self.logger.info("🏁 Proceeding to join channels after authentication delay")
            await self.join_channels()
    
    def clean_irc_formatting(self, text: str) -> str:
        """Remove IRC color codes and formatting characters"""
        # Remove mIRC color codes (^C followed by optional foreground[,background])
        text = re.sub(r'\x03(?:\d{1,2}(?:,\d{1,2})?)?', '', text)
        
        # Remove other IRC formatting codes
        text = re.sub(r'[\x02\x1f\x16\x0f\x1d]', '', text)  # Bold, underline, reverse, reset, italics
        
        # Remove any remaining control characters except newlines and tabs
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        
        return text.strip()

    def parse_message(self, line: str) -> Optional[Dict[str, str]]:
        """Parse IRC message line"""
        # Standard IRC message format: :nick!user@host COMMAND target :message
        match = re.search(r":(.*)!~?(.*) (.*) (.*) :(.*)", line)
        if match:
            return {
                'user': match.group(1),
                'hostmask': match.group(2),
                'type': match.group(3),
                'channel': match.group(4),
                'message': match.group(5),
                'network': self.config.NETWORK  # Add network info for plugins
            }
        return None
    
    def is_admin_user(self, user: str, hostmask: str) -> bool:
        """Check if user is authorized for admin commands"""
        self.logger.debug(f"Checking admin access for user='{user}', hostmask='{hostmask}'")
        for admin_nick, admin_hostmask_pattern in self.config.TRUSTED_USERS:
            self.logger.debug(f"  Comparing against: nick='{admin_nick}', pattern='{admin_hostmask_pattern}'")
            if user == admin_nick and re.match(admin_hostmask_pattern, hostmask):
                self.logger.debug(f"  ✅ Match found! User '{user}' with hostmask '{hostmask}' is admin")
                return True
        self.logger.debug(f"  ❌ No match found for user '{user}' with hostmask '{hostmask}'")
        return False
    
    def should_ignore_message(self, message: Dict[str, str]) -> bool:
        """Check if message should be ignored"""
        ignored_nicks = ["Global", "nibblrjr", "nibblrjr1"]
        ignored_hostmasks = ["thinkin.bout.those.beans"]
        
        if message["user"] in ignored_nicks:
            return True
        
        if any(ignored in message["hostmask"] for ignored in ignored_hostmasks):
            self.logger.debug(f"Ignoring message from: {message['hostmask']}")
            return True
        
        return False
    
    async def add_to_chat_context(self, user: str, message: str):
        """Add message to chat context for AI - stores only last message per user"""
        # Store only the last message from each user
        self.chat_context[user] = message
        
        # Optional: limit total number of users tracked to prevent memory growth
        if len(self.chat_context) > self.config.MAX_CHAT_CONTEXT:
            # Remove the oldest entry (first key in dict maintains insertion order in Python 3.7+)
            oldest_user = next(iter(self.chat_context))
            del self.chat_context[oldest_user]
    
    async def handle_temperature_conversion(self, text: str, channel: str):
        """Handle automatic temperature conversion"""
        # Skip temperature conversion for #bakedbeans channel
        if channel.lower() == "#bakedbeans":
            return False
            
        temp_matches = re.findall(r'(?<!\S)(-?\d{1,3}(?:\.\d+)?)([cCfF])(?=\s|$)', text)
        if len(temp_matches) == 1:
            value_str, unit = temp_matches[0]
            value = float(value_str)
            
            if unit.lower() == 'c':
                converted = value * 9 / 5 + 32
                reply = f"{value:.1f}°C = {converted:.1f}°F"
            else:
                converted = (value - 32) * 5 / 9
                reply = f"{value:.1f}°F = {converted:.1f}°C"
            
            await self.safe_send(channel, reply)
            return True
        return False
    
    async def handle_link_tracking(self, text: str, user: str, channel: str):
        """Handle automatic link tracking"""
        url_pattern = re.compile(r'https?://\S+', re.IGNORECASE)
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            original = self.database.check_and_store_link(user, url, channel)
            if original:
                if user == "Morteh":
                    reply = f"Link originally shared by Morteh just now, not {original['user']} on {original['timestamp']}"
                else:
                    reply = f"Link originally shared by {original['user']} on {original['timestamp']}"
                await self.safe_send(channel, reply)
    
    async def handle_command(self, message: Dict[str, str]):
        """Handle command execution"""
        text = message["message"].strip()
        
        # Special case: restart command
        if text == f"{self.config.COMMAND_PREFIX}restart":
            if self.is_admin_user(message["user"], message["hostmask"]):
                await self.safe_send(message["channel"], "Restarting the bot...")
                self.restart_bot()
                return
            else:
                await self.safe_send(message["channel"], "Access denied")
                return
        
        # Special case: reload command  
        if text == f"{self.config.COMMAND_PREFIX}reload":
            if self.is_admin_user(message["user"], message["hostmask"]):
                await self.safe_send(message["channel"], "Reloading all plugins...")
                try:
                    old_count = len(self.plugin_manager.commands)
                    self._reload_plugins()
                    new_count = len(self.plugin_manager.commands)
                    await self.safe_send(message["channel"], f"✅ Plugins reloaded! Commands: {old_count} → {new_count}")
                except Exception as e:
                    self.logger.error(f"Plugin reload failed: {e}")
                    await self.safe_send(message["channel"], f"❌ Plugin reload failed: {e}")
                return
            else:
                await self.safe_send(message["channel"], "Access denied")
                return
        
        # Find matching command from plugin system
        cmd_info = self.plugin_manager.find_command(text)
        
        # If no plugin command found, try fallback commands
        if not cmd_info and self.fallback_commands:
            for pattern, handler in self.fallback_commands:
                if pattern.search(text):
                    try:
                        response = handler(message)
                        if response:
                            await self.safe_send(message["channel"], response)
                    except Exception as e:
                        self.logger.error(f"Fallback command failed: {e}")
                    return
            return
        
        if not cmd_info:
            return
        
        # Check admin permissions
        if cmd_info.admin_only and not self.is_admin_user(message["user"], message["hostmask"]):
            await self.safe_send(message["channel"], "Access denied")
            return
        
        import time
        import psutil
        import os
        
        # Performance tracking
        start_time = time.time()
        start_memory = 0
        try:
            process = psutil.Process(os.getpid())
            start_memory = process.memory_info().rss / 1024 / 1024  # MB
        except:
            pass
        
        try:
            # Execute command
            if cmd_info.requires_bot:
                response = await cmd_info.handler(message, self)
            else:
                response = cmd_info.handler(message)
            
            # Calculate performance metrics
            execution_time = int((time.time() - start_time) * 1000)  # milliseconds
            memory_usage = 0
            try:
                end_memory = process.memory_info().rss / 1024 / 1024
                memory_usage = end_memory - start_memory
            except:
                pass
            
            # Log successful command usage with metrics
            self.database.log_command_usage(
                cmd_info.name, message["user"], message["channel"],
                success=True, execution_time_ms=execution_time,
                memory_usage_mb=memory_usage,
                rate_limited=not self.rate_limiter.allowed()
            )
            
            if response:
                await self.safe_send(message["channel"], response)
                
        except Exception as e:
            # Calculate performance metrics for failed command
            execution_time = int((time.time() - start_time) * 1000)
            memory_usage = 0
            try:
                end_memory = process.memory_info().rss / 1024 / 1024
                memory_usage = end_memory - start_memory
            except:
                pass
            
            self.logger.error(f"Command {cmd_info.name} failed: {e}")
            self.database.log_command_usage(
                cmd_info.name, message["user"], message["channel"], 
                success=False, error=str(e), execution_time_ms=execution_time,
                memory_usage_mb=memory_usage,
                rate_limited=not self.rate_limiter.allowed()
            )
            await self.safe_send(message["channel"], "Command failed")
    
    async def handle_message(self, message: Dict[str, str]):
        """Handle incoming IRC message"""
        if self.should_ignore_message(message):
            return
        
        text = message["message"].strip()
        
        # Check if this is a command (starts with prefix)
        is_command = text.startswith(self.config.COMMAND_PREFIX)
        
        # Only add non-command messages to chat context for AI
        # This prevents "!speak" from overwriting the user's actual message
        # Also ignore py-ctcp user
        if not is_command and message["user"] != "py-ctcp":
            await self.add_to_chat_context(message["user"], text)
        
        # Handle temperature conversion
        if await self.handle_temperature_conversion(text, message["channel"]):
            return
        
        # Handle link tracking
        await self.handle_link_tracking(text, message["user"], message["channel"])
        
        # Call plugin message handlers (for memos, etc.)
        message_handler_results = self.plugin_manager.handle_message(message, self)
        for result in message_handler_results:
            if result:
                if isinstance(result, list):
                    for msg in result:
                        await self.safe_send(message["channel"], msg)
                else:
                    await self.safe_send(message["channel"], result)
        
        # Handle commands
        await self.handle_command(message)
    
    async def handle_server_message(self, line: str):
        """Handle IRC server messages and numerics"""
        parts = line.split()
        
        if len(parts) >= 2:
            # Welcome message
            if parts[1] == "001":
                self.welcomed = True
                self._log_simple("✅ Received IRC welcome message (001)")
                return
            
            # End of MOTD
            elif parts[1] in ["376", "422"]:
                self._log_simple("✅ End of MOTD received, ready to proceed")
                self.logger.debug(f"NickServ password configured: {bool(self.config.NICKSERV_PASSWORD)}")
                if self.config.NICKSERV_PASSWORD:
                    self._log_simple("🔐 Starting NickServ identification...")
                    await self.identify_with_nickserv()
                else:
                    self.logger.info("🏁 No NickServ password, proceeding with authentication delay")
                    self.identified = True
                    self.logger.info(f"⏳ Waiting {self.config.AUTH_JOIN_DELAY} seconds before joining channels to prevent IP exposure")
                    await asyncio.sleep(self.config.AUTH_JOIN_DELAY)
                    self.logger.info("🏁 Proceeding to join channels after authentication delay")
                    await self.join_channels()
                return
            
            # Nick in use
            elif parts[1] == "433":
                self.logger.warning("⚠️ Nick in use, trying with underscore")
                await self.send_raw(f"NICK {self.config.NICK}_\r\n")
                return
                
            # Join confirmations
            elif parts[1] == "332":  # Topic
                channel = parts[3]
                self.logger.info(f"📋 Topic for {channel}: {' '.join(parts[4:])}")
                return
            elif parts[1] == "333":  # Topic info
                return
            elif parts[1] == "353":  # Names list
                channel = parts[4] if len(parts) > 4 else "unknown"
                self.logger.debug(f"👥 Names list for {channel}")
                return
            elif parts[1] == "366":  # End of names
                channel = parts[3] if len(parts) > 3 else "unknown"
                self._log_simple(f"✅ Successfully joined {channel}")
                return
        
        # Handle JOIN messages
        if " JOIN " in line and self.config.NICK in line:
            channel = line.split(" JOIN ")[-1].strip().lstrip(":")
            self._log_simple(f"🎉 Confirmed join to {channel}")
            return
        
        # Handle KICK messages
        if " KICK " in line:
            await self.handle_kick_message(line)
            return
        
        # Handle NickServ messages (only from actual NickServ)
        if "NickServ!" in line and ("PRIVMSG" in line or "NOTICE" in line):
            self.logger.debug(f"📨 NickServ message: {line}")
            line_lower = line.lower()
            if any(phrase in line_lower for phrase in 
                   ["you are now identified", "password accepted", "you are successfully identified"]):
                self.identified = True
                self._log_simple("✅ Successfully identified with NickServ")
                if self.welcomed:
                    self.logger.info(f"⏳ Waiting {self.config.AUTH_JOIN_DELAY} seconds before joining channels to prevent IP exposure")
                    await asyncio.sleep(self.config.AUTH_JOIN_DELAY)
                    self.logger.info("🏁 Proceeding to join channels after authentication delay")
                    await self.join_channels()
            elif any(phrase in line_lower for phrase in 
                    ["identify via", "this nickname is registered", "please choose a different nick"]):
                if not self.identified:  # Only identify if not already identified
                    self._log_simple("🔐 NickServ requesting identification")
                    await self.identify_with_nickserv()
            elif "your nick isn't registered" in line_lower or "isn't registered" in line_lower:
                self.logger.info("ℹ️ Nick is not registered, proceeding with authentication delay")
                self.identified = True
                if self.welcomed:
                    self.logger.info(f"⏳ Waiting {self.config.AUTH_JOIN_DELAY} seconds before joining channels to prevent IP exposure")
                    await asyncio.sleep(self.config.AUTH_JOIN_DELAY)
                    self.logger.info("🏁 Proceeding to join channels after authentication delay")
                    await self.join_channels()
    
    async def handle_kick_message(self, line: str):
        """Handle KICK messages and auto-rejoin if we were kicked"""
        # KICK message format: :nick!user@host KICK #channel target :reason
        parts = line.split()
        if len(parts) >= 4:
            channel = parts[2]
            kicked_nick = parts[3]
            
            # Extract kicker and reason
            kicker = ""
            reason = ""
            if line.startswith(":"):
                kicker_part = line.split()[0][1:]  # Remove leading :
                if "!" in kicker_part:
                    kicker = kicker_part.split("!")[0]
            
            if ":" in line and len(parts) >= 5:
                reason_start = line.find(":", 1)  # Find second :
                if reason_start != -1:
                    reason = line[reason_start + 1:].strip()
            
            if kicked_nick.lower() == self.config.NICK.lower():
                # We were kicked!
                self.logger.warning(f"🚫 Kicked from {channel} by {kicker}" + (f" (reason: {reason})" if reason else ""))
                
                # Check if auto-rejoin is enabled and this is a configured channel (case-insensitive)
                channel_lower = channel.lower()
                configured_channels_lower = [ch.lower() for ch in self.config.CHANNELS]
                if self.config.AUTO_REJOIN and channel_lower in configured_channels_lower:
                    self.logger.info(f"🔄 Auto-rejoining {channel} in {self.config.REJOIN_DELAY} seconds...")
                    await asyncio.sleep(self.config.REJOIN_DELAY)
                    try:
                        await self.send_raw(f"JOIN {channel}\r\n")
                        self.logger.info(f"📤 Sent rejoin command for {channel}")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to rejoin {channel}: {e}")
                elif not self.config.AUTO_REJOIN:
                    self.logger.info(f"ℹ️ Auto-rejoin disabled, not rejoining {channel}")
                else:
                    self.logger.info(f"ℹ️ Not rejoining {channel} (not in configured channels)")
            else:
                # Someone else was kicked
                self.logger.info(f"👢 {kicked_nick} was kicked from {channel} by {kicker}" + (f" (reason: {reason})" if reason else ""))
    
    async def ping_monitor(self):
        """Monitor connection health"""
        last_pong_time = time.time()
        pong_timeout = 300  # 5 minutes
        
        while self.connected:
            await asyncio.sleep(30)  # Check every 30 seconds
            if time.time() - last_pong_time > pong_timeout:
                self.logger.warning("No PONG received, connection may be dead")
                break
    
    def restart_bot(self):
        """Restart the bot process"""
        self.logger.info("Restarting bot...")
        try:
            if self.writer:
                self.writer.close()
        except Exception:
            pass
        # Use os.execv with the correct python path and arguments
        python_path = sys.executable
        args = [python_path] + sys.argv
        self.logger.info(f"Executing: {python_path} with args: {args}")
        os.execv(python_path, args)
    
    async def bot_loop(self):
        """Main bot message processing loop"""
        buffer = ""
        last_pong_time = time.time()
        
        # Start ping monitor
        ping_task = asyncio.create_task(self.ping_monitor())
        
        try:
            while self.connected:
                try:
                    # Read data with timeout
                    data = await asyncio.wait_for(self.reader.read(4096), timeout=1.0)
                    if not data:
                        self.logger.warning("Connection closed by server")
                        break
                    
                    buffer += data.decode("utf-8", errors="ignore")
                    
                    # Process complete lines
                    while "\r\n" in buffer:
                        line, buffer = buffer.split("\r\n", 1)
                        self.logger.debug(f"← {line}")
                        
                        # Handle PING
                        if line.startswith("PING"):
                            pong_target = line.split()[1]
                            await self.send_raw(f"PONG {pong_target}\r\n")
                            last_pong_time = time.time()
                            self.logger.debug("Sent PONG reply")
                            continue
                        
                        # Handle server messages
                        await self.handle_server_message(line)
                        
                        # Handle user messages
                        message = self.parse_message(line)
                        if message and message['type'] == 'PRIVMSG':
                            # Log all chat messages for web interface viewing (cleaned)
                            clean_message = self.clean_irc_formatting(message['message'])
                            # Log chat messages with simplified format (no function name/line number)
                            self._log_chat_message(f"💬 [{message['channel']}] <{message['user']}> {clean_message}")
                            try:
                                await self.handle_message(message)
                            except Exception as e:
                                self.logger.error(f"Error handling message: {e}")
                
                except asyncio.TimeoutError:
                    # Check for manual commands during timeout periods
                    await self.check_manual_commands()
                    
                    # Check for expired scramble games
                    if hasattr(self.plugin_manager, 'cleanup_expired_scramble_games'):
                        messages = self.plugin_manager.cleanup_expired_scramble_games()
                        for msg_info in messages:
                            await self.safe_send(msg_info['channel'], msg_info['message'])
                    
                    continue
                except Exception as e:
                    self.logger.error(f"Error in bot loop: {e}")
                    break
        
        finally:
            ping_task.cancel()
            try:
                await ping_task
            except asyncio.CancelledError:
                pass
            
            # Clean up queue processor task
            if self.queue_processor_task:
                self.queue_processor_task.cancel()
                try:
                    await self.queue_processor_task
                except asyncio.CancelledError:
                    pass
    
    async def check_manual_commands(self):
        """Check for manual commands from admin panel"""
        from core.paths import DATA_DIR
        command_dir = DATA_DIR / "tmp" / "bot_commands"
        
        # Create the directory if it doesn't exist
        command_dir.mkdir(parents=True, exist_ok=True)
        
        if not command_dir.exists():
            return
        
        # Look for any command files for this network
        command_pattern = str(command_dir / f"{self.network}_manual_command_*.txt")
        command_files = glob.glob(command_pattern)
        
        for command_file in command_files:
            try:
                with open(command_file, 'r') as f:
                    command_data = json.loads(f.read())
                
                command = command_data.get('command', '').strip()
                timestamp = command_data.get('timestamp', '')
                source = command_data.get('source', 'unknown')
                
                if command:
                    self.logger.info(f"🎛️  Processing manual command from {source}: {command}")
                    
                    # Fix PRIVMSG and NOTICE commands to include proper IRC formatting
                    if command.startswith(('PRIVMSG ', 'NOTICE ')):
                        parts = command.split(' ', 2)
                        if len(parts) >= 3:
                            cmd, target, message = parts
                            # Add ':' before message if not already present
                            if not message.startswith(':'):
                                command = f"{cmd} {target} :{message}"
                    
                    # Send the raw IRC command
                    await self.send_raw(f"{command}\r\n")
                    
                    self.logger.info(f"📤 Manual command sent: {command}")
                
                # Remove the command file after processing
                os.remove(command_file)
                
            except Exception as e:
                self.logger.error(f"Error processing manual command: {e}")
                # Remove the file even if there was an error to prevent repeated failures
                try:
                    os.remove(command_file)
                except PermissionError:
                    # If we can't delete due to permissions, rename it to prevent infinite loop
                    try:
                        os.rename(command_file, f"{command_file}.failed")
                        self.logger.warning(f"Could not delete command file due to permissions, renamed to .failed")
                    except:
                        self.logger.error(f"Could not delete or rename command file: {command_file}")
                except Exception as delete_error:
                    self.logger.error(f"Failed to clean up command file: {delete_error}")

async def main():
    """Main entry point"""
    # Determine network from command line or environment
    network = sys.argv[1] if len(sys.argv) > 1 else os.getenv('IRC_NETWORK', 'rizon')
    
    # Initialize path system
    ensure_directories()
    
    # Setup logging
    setup_logging(network)
    logger = logging.getLogger(f"main.{network}")
    
    # Log path configuration for debugging
    log_path_configuration()
    
    try:
        # Validate configuration
        config = get_config(network)
        config.validate()
        
        logger.info(f"Starting IRC bot for {network} network")
        
        # Create and start bot
        bot = AsyncIRCBot(network)
        
        # Signal handlers
        def signal_handler(sig, frame):
            logger.info("Interrupt received, shutting down")
            try:
                if bot.writer:
                    bot.writer.close()
            except Exception:
                pass
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start bot
        await bot.connect()
        await bot.bot_loop()
        
    except ConfigError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
PyBorg - A modern, plugin-based IRC bot
"""

import asyncio
import time
import re
import logging
import os
import sys
from typing import Dict, Optional, List
from core.config import get_config, ConfigError
from core.database import BotDatabase
from core.plugin_system import PluginManager
from core.exceptions import CommandError

class PyBorg:
    """Main IRC bot class with modern async architecture"""
    
    def __init__(self, network: str = "example"):
        # Initialize configuration
        try:
            self.config = get_config(network)
        except ConfigError as e:
            print(f"Configuration error: {e}")
            sys.exit(1)
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger(f"bot.{network}")
        self.logger.info(f"Initializing PyBorg for {network} network")
        
        # Core components
        self.db = BotDatabase(f"{network}_bot.db")
        self.plugin_manager = PluginManager(self.config.COMMAND_PREFIX)
        
        # Connection state
        self.reader = None
        self.writer = None
        self.connected = False
        self.welcomed = False
        self.identified = False
        self.running = False
        
        # Rate limiting
        self.last_message_times = []
        
        # NickServ handling
        self.nickserv_attempts = 0
        self.max_nickserv_attempts = 3
        self.last_identify_time = 0
        self.identify_cooldown = 30
        
        # Chat context for AI
        self.chat_context = {}
        
        # Load plugins
        self.load_plugins()
    
    def setup_logging(self):
        """Configure logging for the bot"""
        log_level = getattr(logging, self.config.LOG_LEVEL, logging.INFO)
        
        # Create logs directory
        log_file = self.config.get_log_file_path("main")
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format=self.config.LOG_FORMAT,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def load_plugins(self):
        """Load all bot plugins"""
        import importlib
        import pkgutil
        
        plugins_loaded = 0
        
        try:
            # Import plugins package
            import plugins
            
            # Discover and load all plugins
            for finder, name, ispkg in pkgutil.iter_modules(plugins.__path__, plugins.__name__ + "."):
                try:
                    module = importlib.import_module(name)
                    if hasattr(module, 'setup_plugin'):
                        module.setup_plugin(self.plugin_manager)
                        plugins_loaded += 1
                        self.logger.debug(f"Loaded plugin: {name}")
                    else:
                        self.logger.warning(f"Plugin {name} has no setup_plugin function")
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {name}: {e}")
        
        except ImportError:
            self.logger.warning("No plugins package found")
        
        self.logger.info(f"Loaded {plugins_loaded} plugin(s), {len(self.plugin_manager.commands)} command(s) registered")
    
    async def connect(self):
        """Connect to IRC server"""
        try:
            self.logger.info(f"Connecting to {self.config.HOST}:{self.config.PORT}")
            self.reader, self.writer = await asyncio.open_connection(
                self.config.HOST, self.config.PORT
            )
            self.connected = True
            self.logger.info("Connected successfully")
            
            # Send IRC handshake
            await self.send_raw(f"NICK {self.config.NICK}\\r\\n")
            await self.send_raw(f"USER {self.config.USER}\\r\\n")
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise
    
    async def send_raw(self, message: str):
        """Send raw IRC message"""
        if self.writer:
            # Fix escaped characters
            message = message.replace("\\r\\n", "\r\n")
            self.writer.write(message.encode('utf-8'))
            await self.writer.drain()
    
    async def send_message(self, target: str, message: str):
        """Send PRIVMSG to target"""
        await self.send_raw(f"PRIVMSG {target} :{message}\r\n")
    
    async def safe_send(self, target: str, message):
        """Rate-limited message sending"""
        # Simple rate limiting
        current_time = time.time()
        self.last_message_times = [t for t in self.last_message_times if current_time - t < self.config.RATE_LIMIT_PERIOD]
        
        if len(self.last_message_times) >= self.config.RATE_LIMIT_MESSAGES:
            self.logger.warning("Rate limit exceeded, dropping message")
            return
        
        self.last_message_times.append(current_time)
        
        if isinstance(message, str):
            await self.send_message(target, message)
        elif isinstance(message, list):
            for msg in message:
                await self.send_message(target, str(msg))
                await asyncio.sleep(0.5)  # Delay between multiple messages
    
    async def join_channels(self):
        """Join configured channels"""
        self.logger.info(f"Attempting to join {len(self.config.CHANNELS)} channels: {self.config.CHANNELS}")
        for channel in self.config.CHANNELS:
            self.logger.debug(f"Sending JOIN command for {channel}")
            await self.send_raw(f"JOIN {channel}\\r\\n")
            await asyncio.sleep(0.5)  # Small delay between joins
        self.logger.info("All JOIN commands sent")
    
    async def identify_with_nickserv(self):
        """Identify with NickServ if password is configured"""
        if not self.config.NICKSERV_PASSWORD:
            return
        
        current_time = time.time()
        if current_time - self.last_identify_time < self.identify_cooldown:
            return
        
        if self.nickserv_attempts < self.max_nickserv_attempts:
            self.nickserv_attempts += 1
            self.last_identify_time = current_time
            self.logger.debug(f"Sending IDENTIFY command to NickServ (attempt {self.nickserv_attempts})")
            await self.send_raw(f"PRIVMSG NickServ :IDENTIFY {self.config.NICKSERV_PASSWORD}\\r\\n")
            self.logger.info(f"🔐 Sent NickServ IDENTIFY command (attempt {self.nickserv_attempts})")
            
            # Set a timeout to proceed anyway if no response
            if self.nickserv_attempts == 1:
                asyncio.create_task(self._nickserv_timeout())
        else:
            if self.nickserv_attempts >= 3:
                self.logger.warning("⚠️ Max NickServ attempts reached, proceeding without identification")
            else:
                self.logger.info("ℹ️ No NickServ password configured, skipping identification")
            self.identified = True
            if self.welcomed:
                await self.join_channels()
    
    async def _nickserv_timeout(self):
        """Timeout for NickServ identification"""
        await asyncio.sleep(15)  # Wait 15 seconds for NickServ response
        if not self.identified and self.welcomed:
            self.logger.warning("⏰ NickServ identification timeout, proceeding to join channels")
            self.identified = True
            await self.join_channels()
    
    def clean_irc_formatting(self, text: str) -> str:
        """Remove IRC color codes and formatting characters"""
        # Remove mIRC color codes (^C followed by optional foreground[,background])
        text = re.sub(r'\\x03(?:\\d{1,2}(?:,\\d{1,2})?)?', '', text)
        # Remove bold (^B), underline (^U), reverse (^R), italic (^I), reset (^O)
        text = re.sub(r'[\\x02\\x1f\\x16\\x1d\\x0f]', '', text)
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
        # This can be configured via environment variables or config
        admin_users = os.getenv('ADMIN_USERS', '').split(',')
        admin_hostmasks = os.getenv('ADMIN_HOSTMASKS', '').split(',')
        
        return (user.lower() in [u.lower().strip() for u in admin_users if u.strip()] or
                any(hostmask.endswith(mask.strip()) for mask in admin_hostmasks if mask.strip()))
    
    async def add_to_chat_context(self, user: str, message: str):
        """Add message to chat context for AI"""
        if user not in self.chat_context:
            self.chat_context[user] = []
        
        self.chat_context[user].append({
            'message': message,
            'timestamp': time.time()
        })
        
        # Keep only recent messages
        cutoff_time = time.time() - 300  # 5 minutes
        self.chat_context[user] = [
            msg for msg in self.chat_context[user] 
            if msg['timestamp'] > cutoff_time
        ][-self.config.MAX_CHAT_CONTEXT:]
    
    def should_ignore_message(self, message: Dict[str, str]) -> bool:
        """Check if message should be ignored"""
        # Ignore messages from self
        if message["user"].lower() == self.config.NICK.lower():
            return True
        
        # Ignore private messages
        if not message["channel"].startswith("#"):
            return True
        
        return False
    
    async def handle_command(self, message: Dict[str, str]):
        """Handle command execution"""
        text = message["message"].strip()
        
        # Find matching command
        cmd_info = self.plugin_manager.find_command(text)
        if not cmd_info:
            return
        
        # Check admin requirements
        if cmd_info.admin_only and not self.is_admin_user(message["user"], message["hostmask"]):
            await self.safe_send(message["channel"], "❌ Admin access required")
            return
        
        try:
            # Execute command
            if cmd_info.requires_bot:
                if asyncio.iscoroutinefunction(cmd_info.handler):
                    result = await cmd_info.handler(message, self)
                else:
                    result = cmd_info.handler(message, self)
            else:
                if asyncio.iscoroutinefunction(cmd_info.handler):
                    result = await cmd_info.handler(message)
                else:
                    result = cmd_info.handler(message)
            
            # Send response
            if result:
                await self.safe_send(message["channel"], result)
                
        except Exception as e:
            self.logger.error(f"Command {cmd_info.name} failed: {e}")
            await self.safe_send(message["channel"], "❌ Command failed")
    
    async def handle_message(self, message: Dict[str, str]):
        """Handle incoming IRC message"""
        if self.should_ignore_message(message):
            return
        
        text = message["message"].strip()
        
        # Add to chat context for AI
        await self.add_to_chat_context(message["user"], text)
        
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
                        await self.send_raw(f"JOIN {channel}\\r\\n")
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
    
    async def handle_server_message(self, line: str):
        """Handle IRC server messages and numerics"""
        parts = line.split()
        
        if len(parts) >= 2:
            # Welcome message
            if parts[1] == "001":
                self.welcomed = True
                self.logger.info("✅ Received IRC welcome message (001)")
                return
            
            # End of MOTD
            elif parts[1] in ["376", "422"]:
                self.logger.info("✅ End of MOTD received, ready to proceed")
                self.logger.debug(f"NickServ password configured: {bool(self.config.NICKSERV_PASSWORD)}")
                if self.config.NICKSERV_PASSWORD:
                    self.logger.info("🔐 Starting NickServ identification...")
                    await self.identify_with_nickserv()
                else:
                    self.logger.info("🏁 No NickServ password, proceeding to join channels")
                    self.identified = True
                    await self.join_channels()
                return
            
            # Nick in use
            elif parts[1] == "433":
                self.logger.warning("⚠️ Nick in use, trying with underscore")
                new_nick = self.config.NICK + "_"
                await self.send_raw(f"NICK {new_nick}\\r\\n")
                return
            
            # Topic or names list end
            elif parts[1] in ["332", "333", "353", "366"]:
                if parts[1] == "332":  # Topic
                    channel = parts[3] if len(parts) > 3 else "unknown"
                    topic = " ".join(parts[4:]).lstrip(":")
                    self.logger.info(f"📋 Topic for {channel}: :{topic}")
                elif parts[1] == "366":  # End of names
                    channel = parts[3] if len(parts) > 3 else "unknown"
                    self.logger.info(f"✅ Successfully joined {channel}")
                return
        
        # Handle JOIN messages
        if " JOIN " in line and self.config.NICK in line:
            channel = line.split(" JOIN ")[-1].strip().lstrip(":")
            self.logger.info(f"🎉 Confirmed join to {channel}")
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
                self.logger.info("✅ Successfully identified with NickServ")
                if self.welcomed:
                    self.logger.info("🏁 Proceeding to join channels after identification")
                    await self.join_channels()
            elif any(phrase in line_lower for phrase in 
                    ["identify via", "this nickname is registered", "please choose a different nick"]):
                if not self.identified:  # Only identify if not already identified
                    self.logger.info("🔐 NickServ requesting identification")
                    await self.identify_with_nickserv()
            elif "your nick isn't registered" in line_lower or "isn't registered" in line_lower:
                self.logger.info("ℹ️ Nick is not registered, proceeding without identification")
                self.identified = True
                if self.welcomed:
                    await self.join_channels()
    
    async def ping_monitor(self):
        """Monitor connection health"""
        last_pong_time = time.time()
        pong_timeout = 300  # 5 minutes
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if we haven't received a PONG in too long
                if current_time - last_pong_time > pong_timeout:
                    self.logger.warning("⚠️ PING timeout, connection may be dead")
                    break
                
                # Send PING every 60 seconds
                if current_time - last_pong_time > 60:
                    await self.send_raw(f"PING :{self.config.HOST}\\r\\n")
                    self.logger.debug("📤 Sent PING")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in ping monitor: {e}")
                break
    
    async def run(self):
        """Main bot loop"""
        self.running = True
        self.logger.info("🚀 Starting PyBorg...")
        
        try:
            await self.connect()
            
            # Start ping monitor
            ping_task = asyncio.create_task(self.ping_monitor())
            
            # Main message processing loop
            while self.running and self.connected:
                try:
                    # Read line with timeout
                    line_bytes = await asyncio.wait_for(
                        self.reader.readline(), 
                        timeout=30.0
                    )
                    
                    if not line_bytes:
                        self.logger.warning("⚠️ Received empty line, connection may be closed")
                        break
                    
                    line = line_bytes.decode('utf-8', errors='ignore').strip()
                    
                    if line:
                        # Handle PING/PONG
                        if line.startswith("PING"):
                            pong_response = line.replace("PING", "PONG")
                            await self.send_raw(f"{pong_response}\\r\\n")
                            self.logger.debug("📨 Received PING, sent PONG")
                            continue
                        
                        # Handle server messages
                        await self.handle_server_message(line)
                        
                        # Handle user messages
                        message = self.parse_message(line)
                        if message and message['type'] == 'PRIVMSG':
                            # Log all chat messages for web interface viewing (cleaned)
                            clean_message = self.clean_irc_formatting(message['message'])
                            self.logger.info(f"💬 [{message['channel']}] <{message['user']}> {clean_message}")
                            try:
                                await self.handle_message(message)
                            except Exception as e:
                                self.logger.error(f"Error handling message: {e}")
                
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    self.logger.error(f"Error in bot loop: {e}")
                    break
        
        finally:
            self.running = False
            ping_task.cancel()
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
            self.logger.info("🛑 PyBorg stopped")

def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print("Usage: python bot.py <network>")
        print("Example: python bot.py example")
        sys.exit(1)
    
    network = sys.argv[1]
    bot = PyBorg(network)
    
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        print("\\n🛑 Bot stopped by user")
    except Exception as e:
        print(f"❌ Bot crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
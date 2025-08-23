#!/usr/bin/env python3
"""
Real-time Bot Status Monitor
Replaces cron-based status updates with real-time event-driven monitoring
"""

import os
import sys
import time
import json
import sqlite3
import psutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Optional, List
import threading
import signal

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import BotConfig
from core.paths import get_data_path

class RealtimeStatusMonitor:
    def __init__(self):
        self.running = False
        self.monitor_interval = 5  # Check every 5 seconds instead of every minute
        self.last_status = {}
        self.event_db_path = get_data_path("databases", "realtime_events.db")
        self.status_dir = get_data_path("bot_status")
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.event_db_path), exist_ok=True)
        os.makedirs(self.status_dir, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Initialize event database
        self.init_event_database()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def setup_logging(self):
        """Setup logging for the status monitor"""
        log_file = get_data_path("logs", "status_monitor.log")
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def init_event_database(self):
        """Initialize the event database if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.event_db_path)
            cursor = conn.cursor()
            
            # Create events table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS realtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    source_table TEXT,
                    source_id INTEGER,
                    timestamp INTEGER DEFAULT (strftime("%s", "now")),
                    consumed INTEGER DEFAULT 0,
                    session_id TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bot_status_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network TEXT NOT NULL,
                    status TEXT NOT NULL,
                    pid INTEGER,
                    uptime INTEGER DEFAULT 0,
                    timestamp INTEGER DEFAULT (strftime("%s", "now")),
                    change_type TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize event database: {e}")
            raise
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def get_bot_processes(self) -> Dict[str, Optional[Dict]]:
        """Get current bot processes using multiple detection methods"""
        processes = {}
        
        for network in ['rizon', 'libera']:
            processes[network] = self.check_bot_process(network)
        
        return processes
    
    def check_bot_process(self, network: str) -> Optional[Dict]:
        """Check if a specific bot process is running"""
        try:
            # Method 1: Check for python process with bot_v2.py and network argument
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    if proc.info['cmdline'] and len(proc.info['cmdline']) >= 3:
                        # Look for: python bot_v2.py [network]
                        # Exclude SCREEN sessions by checking the process name and command line
                        if (proc.info['name'] != 'screen' and
                            'python' in proc.info['cmdline'][0] and 
                            'bot_v2.py' in proc.info['cmdline'][1] and 
                            network in proc.info['cmdline'][2] and
                            'SCREEN' not in ' '.join(proc.info['cmdline'])):
                            
                            uptime = int(time.time() - proc.info['create_time'])
                            
                            return {
                                'pid': proc.info['pid'],
                                'uptime': uptime,
                                'status': 'online',
                                'start_time': proc.info['create_time']
                            }
                except (psutil.NoSuchProcess, psutil.AccessDenied, IndexError):
                    continue
            
            # Method 2: Check screen sessions
            try:
                result = subprocess.run(['screen', '-list'], capture_output=True, text=True)
                if f"{network}-bot" in result.stdout:
                    self.logger.info(f"Found screen session for {network} but no direct process")
                    return {
                        'pid': None,
                        'uptime': 0,
                        'status': 'screen_session',
                        'start_time': None
                    }
            except subprocess.SubprocessError:
                pass
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking {network} bot process: {e}")
            return None
    
    def generate_status_event(self, network: str, status_data: Dict, change_type: str = 'status_change'):
        """Generate a real-time status event"""
        try:
            conn = sqlite3.connect(self.event_db_path)
            cursor = conn.cursor()
            
            # Insert into bot_status_events
            cursor.execute('''
                INSERT INTO bot_status_events (network, status, pid, uptime, change_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                network,
                status_data['status'],
                status_data.get('pid'),
                status_data.get('uptime', 0),
                change_type
            ))
            
            # Generate real-time event
            event_data = json.dumps({
                'network': network,
                'status': status_data['status'],
                'pid': status_data.get('pid'),
                'uptime': status_data.get('uptime', 0),
                'timestamp': int(time.time()),
                'change_type': change_type,
                'formatted_uptime': self.format_uptime(status_data.get('uptime', 0))
            })
            
            cursor.execute('''
                INSERT INTO realtime_events (event_type, data, source_table)
                VALUES (?, ?, ?)
            ''', ('bot_status_change', event_data, 'bot_status_events'))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Generated status event for {network}: {change_type}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate status event for {network}: {e}")
    
    def format_uptime(self, seconds: int) -> str:
        """Format uptime in human readable format"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds//60}m {seconds%60}s"
        elif seconds < 86400:
            return f"{seconds//3600}h {(seconds%3600)//60}m"
        else:
            return f"{seconds//86400}d {(seconds%86400)//3600}h"
    
    def update_status_files(self, processes: Dict[str, Optional[Dict]]):
        """Update JSON status files for backward compatibility"""
        for network, process_info in processes.items():
            status_file = os.path.join(self.status_dir, f"{network}_status.json")
            
            if process_info:
                status_data = {
                    "status": process_info['status'],
                    "pid": process_info['pid'],
                    "uptime": process_info['uptime'],
                    "last_update": int(time.time())
                }
            else:
                status_data = {
                    "status": "offline",
                    "pid": None,
                    "uptime": 0,
                    "last_update": int(time.time())
                }
            
            try:
                with open(status_file, 'w') as f:
                    json.dump(status_data, f, indent=2)
                
                # Set permissions for web server access
                os.chmod(status_file, 0o644)
                
            except Exception as e:
                self.logger.error(f"Failed to update status file for {network}: {e}")
    
    def check_for_status_changes(self, current_processes: Dict[str, Optional[Dict]]):
        """Check for status changes and generate events"""
        for network, current_info in current_processes.items():
            last_info = self.last_status.get(network)
            
            # Determine current status
            if current_info is None:
                current_status = "offline"
                current_pid = None
                current_uptime = 0
            else:
                current_status = current_info['status']
                current_pid = current_info.get('pid')
                current_uptime = current_info.get('uptime', 0)
            
            # Determine last status
            if last_info is None:
                last_status = "unknown"
                last_pid = None
            else:
                last_status = last_info['status']
                last_pid = last_info.get('pid')
            
            # Check for status changes
            status_changed = last_status != current_status
            pid_changed = last_pid != current_pid
            
            if status_changed or pid_changed:
                change_type = 'status_change'
                
                if last_status == "offline" and current_status == "online":
                    change_type = 'bot_started'
                elif last_status == "online" and current_status == "offline":
                    change_type = 'bot_stopped'
                elif pid_changed and current_status == "online":
                    change_type = 'bot_restarted'
                
                self.logger.info(f"Status change detected for {network}: {last_status} -> {current_status} ({change_type})")
                
                # Generate event
                status_data = {
                    'status': current_status,
                    'pid': current_pid,
                    'uptime': current_uptime
                }
                self.generate_status_event(network, status_data, change_type)
    
    def run(self):
        """Main monitoring loop"""
        self.running = True
        self.logger.info("Starting real-time bot status monitor...")
        
        while self.running:
            try:
                # Get current bot processes
                current_processes = self.get_bot_processes()
                
                # Check for changes and generate events
                self.check_for_status_changes(current_processes)
                
                # Update status files for backward compatibility
                self.update_status_files(current_processes)
                
                # Update last status
                self.last_status = current_processes.copy()
                
                # Log current status
                online_bots = sum(1 for info in current_processes.values() if info and info['status'] == 'online')
                self.logger.debug(f"Status check complete: {online_bots}/2 bots online")
                
                # Sleep until next check
                time.sleep(self.monitor_interval)
                
            except KeyboardInterrupt:
                self.logger.info("Received keyboard interrupt, shutting down...")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitor_interval)
        
        self.logger.info("Real-time bot status monitor stopped")

def main():
    """Main entry point"""
    monitor = RealtimeStatusMonitor()
    try:
        monitor.run()
    except Exception as e:
        logging.error(f"Fatal error in status monitor: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
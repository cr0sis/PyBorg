"""Database layer with SQLite backend for bot persistence"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, List, Any, Optional
from .exceptions import DatabaseError

logger = logging.getLogger(__name__)

class BotDatabase:
    """SQLite database wrapper for bot data persistence"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Links tracking table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS links (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE NOT NULL,
                        user TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        channel TEXT
                    )
                ''')
                
                # User scores for games
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_scores (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        game_type TEXT NOT NULL,
                        score INTEGER DEFAULT 0,
                        best_score INTEGER DEFAULT 0,
                        games_played INTEGER DEFAULT 0,
                        last_played DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user, game_type)
                    )
                ''')
                
                # AI conversation history
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS conversation_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        message TEXT NOT NULL,
                        response TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        context TEXT
                    )
                ''')
                
                # Bot statistics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS bot_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        stat_name TEXT UNIQUE NOT NULL,
                        stat_value TEXT NOT NULL,
                        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Command usage tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS command_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        command TEXT NOT NULL,
                        user TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT TRUE,
                        error_message TEXT
                    )
                ''')
                
                # UNO game leaderboard
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS uno_leaderboard (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT UNIQUE NOT NULL,
                        wins INTEGER DEFAULT 0,
                        games_played INTEGER DEFAULT 0,
                        total_cards_played INTEGER DEFAULT 0,
                        avg_cards_per_game REAL DEFAULT 0.0,
                        last_game DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Reminders table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reminders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        message TEXT NOT NULL,
                        remind_time DATETIME NOT NULL,
                        created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                        completed BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Breakout high scores table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS breakout_scores (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        player_name TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        level_reached INTEGER NOT NULL,
                        date_played DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Memo/tell messages table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS memos (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        from_user TEXT NOT NULL,
                        to_user TEXT NOT NULL,
                        message TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                        delivered BOOLEAN DEFAULT FALSE,
                        delivered_time DATETIME NULL
                    )
                ''')
                
                conn.commit()
                logger.debug("Database initialized successfully")
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize database: {e}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            if conn:
                conn.close()
    
    # Link tracking methods
    def check_and_store_link(self, user: str, url: str, channel: str = None) -> Optional[Dict[str, Any]]:
        """Check if link exists and store if new. Returns original info if duplicate."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if link exists
                cursor.execute('SELECT user, timestamp FROM links WHERE url = ?', (url.lower(),))
                existing = cursor.fetchone()
                
                if existing:
                    if existing['user'] == user:
                        return None  # Same user, no notification needed
                    return {
                        'user': existing['user'],
                        'timestamp': existing['timestamp']
                    }
                
                # Store new link
                cursor.execute(
                    'INSERT INTO links (url, user, channel) VALUES (?, ?, ?)',
                    (url.lower(), user, channel)
                )
                conn.commit()
                return None
                
        except sqlite3.Error as e:
            logger.error(f"Error in link tracking: {e}")
            return None
    
    # User scores methods
    def get_user_score(self, user: str, game_type: str = "bet7") -> Dict[str, Any]:
        """Get user's score for a specific game"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT * FROM user_scores WHERE user = ? AND game_type = ?',
                    (user, game_type)
                )
                result = cursor.fetchone()
                
                if result:
                    return dict(result)
                return {
                    'user': user,
                    'game_type': game_type,
                    'score': 0,
                    'best_score': 0,
                    'games_played': 0
                }
                
        except sqlite3.Error as e:
            logger.error(f"Error getting user score: {e}")
            return {'user': user, 'score': 0, 'best_score': 0, 'games_played': 0}
    
    def update_user_score(self, user: str, score_change: int, game_type: str = "bet7"):
        """Update user's score for a specific game"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get current score
                current = self.get_user_score(user, game_type)
                new_score = current['score'] + score_change
                new_best = max(current['best_score'], new_score) if new_score > 0 else current['best_score']
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_scores 
                    (user, game_type, score, best_score, games_played, last_played)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (user, game_type, new_score, new_best, current['games_played'] + 1))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error updating user score: {e}")
    
    def get_leaderboard(self, game_type: str = "bet7", limit: int = 10) -> List[Dict[str, Any]]:
        """Get leaderboard for a specific game"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user, score, best_score, games_played 
                    FROM user_scores 
                    WHERE game_type = ? 
                    ORDER BY score DESC 
                    LIMIT ?
                ''', (game_type, limit))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting leaderboard: {e}")
            return []
    
    # AI conversation methods
    def store_conversation(self, user: str, message: str, response: str = None, context: str = None):
        """Store AI conversation for context building"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO conversation_history (user, message, response, context)
                    VALUES (?, ?, ?, ?)
                ''', (user, message, response, json.dumps(context) if context else None))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error storing conversation: {e}")
    
    def get_conversation_history(self, user: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent conversation history for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT message, response, timestamp, context
                    FROM conversation_history 
                    WHERE user = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (user, limit))
                
                history = []
                for row in cursor.fetchall():
                    item = dict(row)
                    if item['context']:
                        try:
                            item['context'] = json.loads(item['context'])
                        except json.JSONDecodeError:
                            item['context'] = None
                    history.append(item)
                
                return history
                
        except sqlite3.Error as e:
            logger.error(f"Error getting conversation history: {e}")
            return []
    
    def clear_conversation_history(self, user: str):
        """Clear conversation history for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM conversation_history WHERE user = ?', (user,))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error clearing conversation history: {e}")
    
    # Command usage tracking
    def log_command_usage(self, command: str, user: str, channel: str, success: bool = True, error: str = None):
        """Log command usage for analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO command_usage (command, user, channel, success, error_message)
                    VALUES (?, ?, ?, ?, ?)
                ''', (command, user, channel, success, error))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error logging command usage: {e}")
    
    def get_command_stats(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get command usage statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT command, COUNT(*) as usage_count,
                           SUM(CASE WHEN success THEN 1 ELSE 0 END) as success_count,
                           SUM(CASE WHEN success THEN 0 ELSE 1 END) as error_count
                    FROM command_usage 
                    WHERE timestamp >= datetime('now', '-{} days')
                    GROUP BY command
                    ORDER BY usage_count DESC
                '''.format(days))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting command stats: {e}")
            return []
    
    # Bot statistics
    def set_stat(self, name: str, value: Any):
        """Set a bot statistic"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO bot_stats (stat_name, stat_value, last_updated)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (name, str(value)))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error setting stat: {e}")
    
    def get_stat(self, name: str, default: Any = None) -> Any:
        """Get a bot statistic"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT stat_value FROM bot_stats WHERE stat_name = ?', (name,))
                result = cursor.fetchone()
                
                if result:
                    return result['stat_value']
                return default
                
        except sqlite3.Error as e:
            logger.error(f"Error getting stat: {e}")
            return default
    
    # UNO game leaderboard methods
    def update_uno_stats(self, player: str, position: int, cards_left: int, points: int):
        """Update UNO stats for a player"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if player exists
                cursor.execute('SELECT * FROM uno_leaderboard WHERE user = ?', (player,))
                result = cursor.fetchone()
                
                if result:
                    # Update existing player
                    new_games = result['games_played'] + 1
                    new_wins = result['wins'] + (1 if position == 1 else 0)
                    new_total_cards = result['total_cards_played'] + cards_left
                    new_avg_cards = new_total_cards / new_games
                    
                    cursor.execute('''
                        UPDATE uno_leaderboard 
                        SET wins = ?, games_played = ?, total_cards_played = ?, 
                            avg_cards_per_game = ?, last_game = CURRENT_TIMESTAMP
                        WHERE user = ?
                    ''', (new_wins, new_games, new_total_cards, new_avg_cards, player))
                else:
                    # Insert new player
                    wins = 1 if position == 1 else 0
                    cursor.execute('''
                        INSERT INTO uno_leaderboard 
                        (user, wins, games_played, total_cards_played, avg_cards_per_game, last_game)
                        VALUES (?, ?, 1, ?, ?, CURRENT_TIMESTAMP)
                    ''', (player, wins, cards_left, cards_left))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error updating UNO stats: {e}")
            raise DatabaseError(f"Failed to update UNO stats: {e}")
    
    def get_uno_leaderboard(self, limit: int = 10) -> List[Dict]:
        """Get UNO leaderboard"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user as player, wins, games_played as games,
                           CAST(wins AS REAL) / games_played as win_rate,
                           avg_cards_per_game,
                           (CAST(wins AS REAL) / games_played * 100) as win_percentage,
                           (games_played - wins) * 1.0 + avg_cards_per_game * 0.1 as avg_position
                    FROM uno_leaderboard 
                    WHERE games_played > 0
                    ORDER BY win_rate DESC, avg_cards_per_game ASC
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting UNO leaderboard: {e}")
            return []
    
    # Reminder methods
    def add_reminder(self, user: str, channel: str, message: str, remind_time: datetime) -> int:
        """Add a new reminder and return its ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO reminders (user, channel, message, remind_time)
                    VALUES (?, ?, ?, ?)
                ''', (user, channel, message, remind_time.isoformat()))
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding reminder: {e}")
            raise DatabaseError(f"Failed to add reminder: {e}")
    
    def get_due_reminders(self, current_time: datetime) -> List[Dict[str, Any]]:
        """Get all reminders that are due"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, user, channel, message, remind_time
                    FROM reminders
                    WHERE remind_time <= ? AND completed = FALSE
                    ORDER BY remind_time ASC
                ''', (current_time.isoformat(),))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting due reminders: {e}")
            return []
    
    def get_user_reminders(self, user: str) -> List[Dict[str, Any]]:
        """Get all active reminders for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, channel, message, remind_time, created_time
                    FROM reminders
                    WHERE user = ? AND completed = FALSE
                    ORDER BY remind_time ASC
                ''', (user,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting user reminders: {e}")
            return []
    
    def complete_reminder(self, reminder_id: int) -> bool:
        """Mark a reminder as completed"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE reminders 
                    SET completed = TRUE 
                    WHERE id = ?
                ''', (reminder_id,))
                conn.commit()
                return cursor.rowcount > 0
                
        except sqlite3.Error as e:
            logger.error(f"Error completing reminder: {e}")
            return False
    
    # Memo/tell methods
    def add_memo(self, from_user: str, to_user: str, message: str, channel: str) -> int:
        """Add a new memo for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO memos (from_user, to_user, message, channel)
                    VALUES (?, ?, ?, ?)
                ''', (from_user, to_user.lower(), message, channel))
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding memo: {e}")
            raise DatabaseError(f"Failed to add memo: {e}")
    
    def get_pending_memos(self, user: str) -> List[Dict]:
        """Get all pending memos for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, from_user, message, channel, created_time
                    FROM memos
                    WHERE to_user = ? AND delivered = FALSE
                    ORDER BY created_time ASC
                ''', (user.lower(),))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting pending memos: {e}")
            return []
    
    def mark_memos_delivered(self, user: str) -> int:
        """Mark all pending memos for a user as delivered"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE memos 
                    SET delivered = TRUE, delivered_time = CURRENT_TIMESTAMP
                    WHERE to_user = ? AND delivered = FALSE
                ''', (user.lower(),))
                conn.commit()
                return cursor.rowcount
                
        except sqlite3.Error as e:
            logger.error(f"Error marking memos as delivered: {e}")
            return 0
    
    def get_memo_count(self, user: str) -> int:
        """Get count of pending memos for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) as count
                    FROM memos
                    WHERE to_user = ? AND delivered = FALSE
                ''', (user.lower(),))
                
                result = cursor.fetchone()
                return result['count'] if result else 0
                
        except sqlite3.Error as e:
            logger.error(f"Error getting memo count: {e}")
            return 0
    
    def cleanup_old_reminders(self, days_old: int = 30) -> int:
        """Remove completed reminders older than specified days"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cutoff_date = (datetime.now() - timedelta(days=days_old)).isoformat()
                cursor.execute('''
                    DELETE FROM reminders 
                    WHERE completed = TRUE AND created_time < ?
                ''', (cutoff_date,))
                conn.commit()
                return cursor.rowcount
                
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up reminders: {e}")
            return 0
    
    # Breakout high scores methods
    def add_breakout_score(self, player_name: str, score: int, level_reached: int) -> int:
        """Add a new breakout score and return its ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO breakout_scores (player_name, score, level_reached)
                    VALUES (?, ?, ?)
                ''', (player_name, score, level_reached))
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error adding breakout score: {e}")
            raise DatabaseError(f"Failed to add breakout score: {e}")
    
    def get_breakout_high_scores(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top breakout high scores"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT player_name, score, level_reached, date_played
                    FROM breakout_scores
                    ORDER BY score DESC, level_reached DESC
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting breakout high scores: {e}")
            return []

# Migration functions for existing JSON data
def migrate_json_to_db(json_file: str, db: BotDatabase, data_type: str):
    """Migrate data from JSON files to database"""
    import os
    
    if not os.path.exists(json_file):
        logger.info(f"JSON file {json_file} not found, skipping migration")
        return
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        if data_type == "dice_rolls":
            # Migrate bet7 scores
            if 'scores' in data:
                for user, score in data['scores'].items():
                    db.update_user_score(user, score, "bet7")
            
            if 'best_scores' in data:
                for user, best_score in data['best_scores'].items():
                    # Update best score separately
                    with db.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            UPDATE user_scores 
                            SET best_score = ? 
                            WHERE user = ? AND game_type = ?
                        ''', (best_score, user, "bet7"))
                        conn.commit()
        
        elif data_type == "links":
            # Migrate links data if it's a dict with timestamp info
            for url, (user, timestamp) in data.items():
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR IGNORE INTO links (url, user, timestamp)
                        VALUES (?, ?, ?)
                    ''', (url, user, timestamp))
                    conn.commit()
        
        logger.info(f"Successfully migrated {json_file} to database")
        
        # Backup original file
        backup_file = f"{json_file}.backup"
        os.rename(json_file, backup_file)
        logger.info(f"Original file backed up to {backup_file}")
        
    except Exception as e:
        logger.error(f"Error migrating {json_file}: {e}")
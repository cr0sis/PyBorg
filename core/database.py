"""Database layer with SQLite backend for bot persistence"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, List, Any, Optional
from pathlib import Path
from .exceptions import DatabaseError
from .paths import get_database_path

logger = logging.getLogger(__name__)

class BotDatabase:
    """SQLite database wrapper for bot data persistence"""
    
    def __init__(self, db_path: str):
        # Use centralized path system if relative path provided
        if not Path(db_path).is_absolute():
            self.db_path = str(get_database_path(db_path))
        else:
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
                
                # Enhanced command usage tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS command_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        command TEXT NOT NULL,
                        user TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT TRUE,
                        error_message TEXT,
                        -- Performance tracking
                        execution_time_ms INTEGER DEFAULT 0,
                        memory_usage_mb REAL DEFAULT 0,
                        -- User behavior
                        user_is_new BOOLEAN DEFAULT FALSE,
                        session_command_count INTEGER DEFAULT 1,
                        time_since_last_command_sec INTEGER DEFAULT 0,
                        -- Network tracking
                        network_latency_ms INTEGER DEFAULT 0,
                        rate_limited BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # UNO game leaderboard with expanded stats
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS uno_leaderboard (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT UNIQUE NOT NULL,
                        wins INTEGER DEFAULT 0,
                        games_played INTEGER DEFAULT 0,
                        total_cards_played INTEGER DEFAULT 0,
                        avg_cards_per_game REAL DEFAULT 0.0,
                        last_game DATETIME DEFAULT CURRENT_TIMESTAMP,
                        -- Card Strategy Stats
                        wild_cards_played INTEGER DEFAULT 0,
                        plus4_cards_played INTEGER DEFAULT 0,
                        plus2_cards_played INTEGER DEFAULT 0,
                        skip_cards_played INTEGER DEFAULT 0,
                        reverse_cards_played INTEGER DEFAULT 0,
                        -- Defensive Stats
                        successful_uno_calls INTEGER DEFAULT 0,
                        caught_no_uno INTEGER DEFAULT 0,
                        successful_challenges INTEGER DEFAULT 0,
                        failed_challenges INTEGER DEFAULT 0,
                        times_challenged INTEGER DEFAULT 0,
                        -- Performance Stats
                        fastest_game_seconds INTEGER DEFAULT 0,
                        longest_game_seconds INTEGER DEFAULT 0,
                        total_game_time_seconds INTEGER DEFAULT 0,
                        largest_hand_size INTEGER DEFAULT 0,
                        comeback_wins INTEGER DEFAULT 0,
                        uno_wins INTEGER DEFAULT 0,
                        -- Streak Stats
                        current_win_streak INTEGER DEFAULT 0,
                        longest_win_streak INTEGER DEFAULT 0,
                        -- Color Preferences (counts)
                        red_cards_played INTEGER DEFAULT 0,
                        blue_cards_played INTEGER DEFAULT 0,
                        green_cards_played INTEGER DEFAULT 0,
                        yellow_cards_played INTEGER DEFAULT 0,
                        -- Social & Timing Stats
                        games_this_week INTEGER DEFAULT 0,
                        games_this_month INTEGER DEFAULT 0,
                        weekend_games INTEGER DEFAULT 0,
                        weekday_games INTEGER DEFAULT 0
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
                
                # Pass the Pigs game states
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS pigs_games (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        channel TEXT NOT NULL,
                        game_state TEXT NOT NULL,  -- JSON of game state
                        current_player TEXT,
                        turn_score INTEGER DEFAULT 0,
                        join_timer_start DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(channel)
                    )
                ''')
                
                # Pass the Pigs leaderboard with expanded stats
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS pigs_leaderboard (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT UNIQUE NOT NULL,
                        wins INTEGER DEFAULT 0,
                        games_played INTEGER DEFAULT 0,
                        total_score INTEGER DEFAULT 0,
                        highest_game_score INTEGER DEFAULT 0,
                        highest_turn_score INTEGER DEFAULT 0,
                        pig_outs INTEGER DEFAULT 0,
                        oinkers INTEGER DEFAULT 0,
                        last_game DATETIME DEFAULT CURRENT_TIMESTAMP,
                        -- Risk Analytics
                        total_rolls INTEGER DEFAULT 0,
                        total_banks INTEGER DEFAULT 0,
                        avg_rolls_before_bank REAL DEFAULT 0.0,
                        risk_tolerance_score REAL DEFAULT 0.0,
                        -- Streak Stats
                        current_win_streak INTEGER DEFAULT 0,
                        longest_win_streak INTEGER DEFAULT 0,
                        current_no_pigout_streak INTEGER DEFAULT 0,
                        longest_no_pigout_streak INTEGER DEFAULT 0,
                        -- Position Frequency Stats
                        sides_rolled INTEGER DEFAULT 0,
                        razorbacks_rolled INTEGER DEFAULT 0,
                        trotters_rolled INTEGER DEFAULT 0,
                        snouters_rolled INTEGER DEFAULT 0,
                        leaning_jowlers_rolled INTEGER DEFAULT 0,
                        double_positions INTEGER DEFAULT 0,
                        double_razorback INTEGER DEFAULT 0,
                        double_trotter INTEGER DEFAULT 0,
                        double_snouter INTEGER DEFAULT 0,
                        double_leaning_jowler INTEGER DEFAULT 0,
                        -- Performance Stats
                        fastest_win_seconds INTEGER DEFAULT 0,
                        longest_game_seconds INTEGER DEFAULT 0,
                        total_game_time_seconds INTEGER DEFAULT 0,
                        comeback_wins INTEGER DEFAULT 0,
                        close_wins INTEGER DEFAULT 0,
                        -- Banking Behavior (score ranges when banking)
                        banks_under_10 INTEGER DEFAULT 0,
                        banks_10_to_20 INTEGER DEFAULT 0,
                        banks_20_to_30 INTEGER DEFAULT 0,
                        banks_over_30 INTEGER DEFAULT 0,
                        -- Turn Efficiency
                        total_turns INTEGER DEFAULT 0,
                        successful_turns INTEGER DEFAULT 0,
                        -- Social Stats
                        games_this_week INTEGER DEFAULT 0,
                        games_this_month INTEGER DEFAULT 0,
                        weekend_games INTEGER DEFAULT 0,
                        weekday_games INTEGER DEFAULT 0
                    )
                ''')
                
                # User behavior analytics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        total_commands INTEGER DEFAULT 0,
                        total_sessions INTEGER DEFAULT 1,
                        avg_session_length_min REAL DEFAULT 0,
                        favorite_command TEXT,
                        favorite_channel TEXT,
                        most_active_hour INTEGER DEFAULT 12,
                        commands_this_week INTEGER DEFAULT 0,
                        commands_this_month INTEGER DEFAULT 0,
                        longest_absence_days INTEGER DEFAULT 0,
                        UNIQUE(user)
                    )
                ''')
                
                # Channel analytics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS channel_analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        channel TEXT NOT NULL,
                        total_commands INTEGER DEFAULT 0,
                        unique_users INTEGER DEFAULT 0,
                        most_popular_command TEXT,
                        peak_activity_hour INTEGER DEFAULT 12,
                        most_active_user TEXT,
                        avg_commands_per_day REAL DEFAULT 0,
                        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(channel)
                    )
                ''')
                
                # System performance analytics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_performance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        avg_command_time_ms REAL DEFAULT 0,
                        peak_memory_mb REAL DEFAULT 0,
                        commands_per_minute REAL DEFAULT 0,
                        error_rate_percent REAL DEFAULT 0,
                        active_users INTEGER DEFAULT 0,
                        uptime_minutes INTEGER DEFAULT 0,
                        connection_events INTEGER DEFAULT 0,
                        rate_limit_hits INTEGER DEFAULT 0
                    )
                ''')
                
                # AI conversation analytics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ai_analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        conversation_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                        messages_in_conversation INTEGER DEFAULT 1,
                        avg_response_length INTEGER DEFAULT 0,
                        conversation_duration_min REAL DEFAULT 0,
                        topics TEXT,  -- JSON array of detected topics/keywords
                        sentiment_score REAL DEFAULT 0,  -- Simple sentiment analysis
                        user_satisfaction REAL DEFAULT 0,  -- Based on continued engagement
                        channel TEXT NOT NULL
                    )
                ''')
                
                # Game session analytics  
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS game_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        game_type TEXT NOT NULL,  -- 'uno', 'pigs', etc
                        session_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                        session_end DATETIME,
                        duration_minutes REAL DEFAULT 0,
                        player_count INTEGER DEFAULT 1,
                        players TEXT,  -- JSON array of player names
                        channel TEXT NOT NULL,
                        winner TEXT,
                        abandoned BOOLEAN DEFAULT FALSE,
                        total_turns INTEGER DEFAULT 0,
                        avg_turn_time_sec REAL DEFAULT 0
                    )
                ''')
                
                # Bot configuration settings
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS bot_config (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        network TEXT NOT NULL,  -- 'rizon', 'libera'
                        setting_name TEXT NOT NULL,
                        setting_value TEXT NOT NULL,
                        setting_type TEXT DEFAULT 'string',  -- 'string', 'int', 'float', 'bool', 'json'
                        description TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(network, setting_name)
                    )
                ''')
                
                # Scramble game results for detailed statistics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scramble_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        word TEXT NOT NULL,
                        solve_time_seconds REAL NOT NULL,
                        points_earned INTEGER NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        channel TEXT
                    )
                ''')
                
                # Riddle game results for detailed statistics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS riddle_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        answer TEXT NOT NULL,
                        solve_time_seconds REAL NOT NULL,
                        points_earned INTEGER NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        channel TEXT
                    )
                ''')
                
                # Bean images table for user-submitted bean pictures
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS bean_images (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE NOT NULL,
                        added_by TEXT NOT NULL,
                        added_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                        channel TEXT,
                        description TEXT,
                        view_count INTEGER DEFAULT 0,
                        last_viewed DATETIME
                    )
                ''')
                
                conn.commit()
                logger.debug("Database initialized successfully")
                
                # Clear error statistics on bot restart for clean analytics
                logger.debug("Clearing error statistics for fresh start")
                cursor.execute("UPDATE command_usage SET success = 1, error_message = NULL WHERE success = 0")
                conn.commit()
                logger.debug("Error statistics cleared")
                
                # Upgrade existing database schema
                self._upgrade_database_schema(conn)
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize database: {e}")
    
    def _upgrade_database_schema(self, conn):
        """Upgrade existing database schema with new columns"""
        cursor = conn.cursor()
        
        try:
            # Get existing UNO columns
            cursor.execute("PRAGMA table_info(uno_leaderboard)")
            existing_uno_cols = {row[1] for row in cursor.fetchall()}
            
            # Add missing UNO columns
            uno_new_columns = [
                ('wild_cards_played', 'INTEGER DEFAULT 0'),
                ('plus4_cards_played', 'INTEGER DEFAULT 0'),
                ('plus2_cards_played', 'INTEGER DEFAULT 0'),
                ('skip_cards_played', 'INTEGER DEFAULT 0'),
                ('reverse_cards_played', 'INTEGER DEFAULT 0'),
                ('successful_uno_calls', 'INTEGER DEFAULT 0'),
                ('caught_no_uno', 'INTEGER DEFAULT 0'),
                ('successful_challenges', 'INTEGER DEFAULT 0'),
                ('failed_challenges', 'INTEGER DEFAULT 0'),
                ('times_challenged', 'INTEGER DEFAULT 0'),
                ('fastest_game_seconds', 'INTEGER DEFAULT 0'),
                ('longest_game_seconds', 'INTEGER DEFAULT 0'),
                ('total_game_time_seconds', 'INTEGER DEFAULT 0'),
                ('largest_hand_size', 'INTEGER DEFAULT 0'),
                ('comeback_wins', 'INTEGER DEFAULT 0'),
                ('uno_wins', 'INTEGER DEFAULT 0'),
                ('current_win_streak', 'INTEGER DEFAULT 0'),
                ('longest_win_streak', 'INTEGER DEFAULT 0'),
                ('red_cards_played', 'INTEGER DEFAULT 0'),
                ('blue_cards_played', 'INTEGER DEFAULT 0'),
                ('green_cards_played', 'INTEGER DEFAULT 0'),
                ('yellow_cards_played', 'INTEGER DEFAULT 0'),
                ('games_this_week', 'INTEGER DEFAULT 0'),
                ('games_this_month', 'INTEGER DEFAULT 0'),
                ('weekend_games', 'INTEGER DEFAULT 0'),
                ('weekday_games', 'INTEGER DEFAULT 0')
            ]
            
            for col_name, col_def in uno_new_columns:
                if col_name not in existing_uno_cols:
                    cursor.execute(f"ALTER TABLE uno_leaderboard ADD COLUMN {col_name} {col_def}")
                    logger.debug(f"Added UNO column: {col_name}")
            
            # Get existing Pigs columns
            cursor.execute("PRAGMA table_info(pigs_leaderboard)")
            existing_pigs_cols = {row[1] for row in cursor.fetchall()}
            
            # Add missing Pigs columns
            pigs_new_columns = [
                ('total_rolls', 'INTEGER DEFAULT 0'),
                ('total_banks', 'INTEGER DEFAULT 0'),
                ('avg_rolls_before_bank', 'REAL DEFAULT 0.0'),
                ('risk_tolerance_score', 'REAL DEFAULT 0.0'),
                ('current_win_streak', 'INTEGER DEFAULT 0'),
                ('longest_win_streak', 'INTEGER DEFAULT 0'),
                ('current_no_pigout_streak', 'INTEGER DEFAULT 0'),
                ('longest_no_pigout_streak', 'INTEGER DEFAULT 0'),
                ('sides_rolled', 'INTEGER DEFAULT 0'),
                ('razorbacks_rolled', 'INTEGER DEFAULT 0'),
                ('trotters_rolled', 'INTEGER DEFAULT 0'),
                ('snouters_rolled', 'INTEGER DEFAULT 0'),
                ('leaning_jowlers_rolled', 'INTEGER DEFAULT 0'),
                ('double_positions', 'INTEGER DEFAULT 0'),
                ('double_razorback', 'INTEGER DEFAULT 0'),
                ('double_trotter', 'INTEGER DEFAULT 0'),
                ('double_snouter', 'INTEGER DEFAULT 0'),
                ('double_leaning_jowler', 'INTEGER DEFAULT 0'),
                ('fastest_win_seconds', 'INTEGER DEFAULT 0'),
                ('longest_game_seconds', 'INTEGER DEFAULT 0'),
                ('total_game_time_seconds', 'INTEGER DEFAULT 0'),
                ('comeback_wins', 'INTEGER DEFAULT 0'),
                ('close_wins', 'INTEGER DEFAULT 0'),
                ('banks_under_10', 'INTEGER DEFAULT 0'),
                ('banks_10_to_20', 'INTEGER DEFAULT 0'),
                ('banks_20_to_30', 'INTEGER DEFAULT 0'),
                ('banks_over_30', 'INTEGER DEFAULT 0'),
                ('total_turns', 'INTEGER DEFAULT 0'),
                ('successful_turns', 'INTEGER DEFAULT 0'),
                ('games_this_week', 'INTEGER DEFAULT 0'),
                ('games_this_month', 'INTEGER DEFAULT 0'),
                ('weekend_games', 'INTEGER DEFAULT 0'),
                ('weekday_games', 'INTEGER DEFAULT 0')
            ]
            
            for col_name, col_def in pigs_new_columns:
                if col_name not in existing_pigs_cols:
                    cursor.execute(f"ALTER TABLE pigs_leaderboard ADD COLUMN {col_name} {col_def}")
                    logger.debug(f"Added Pigs column: {col_name}")
            
            conn.commit()
            logger.debug("Database schema upgrade completed")
            
        except sqlite3.Error as e:
            logger.warning(f"Database schema upgrade error (non-critical): {e}")
    
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
                new_total_score = current['score'] + score_change
                # For best_score, compare this single game's points to the previous best single game
                new_best = max(current['best_score'], score_change) if score_change > 0 else current['best_score']
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_scores 
                    (user, game_type, score, best_score, games_played, last_played)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (user, game_type, new_total_score, new_best, current['games_played'] + 1))
                
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
    
    def save_scramble_result(self, user: str, word: str, solve_time: float, points: int, channel: str = None):
        """Save a scramble game result"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scramble_results (user, word, solve_time_seconds, points_earned, channel)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user, word, solve_time, points, channel))
                conn.commit()
                logger.debug(f"Saved scramble result: {user} solved '{word}' in {solve_time:.1f}s for {points} points")
                
        except sqlite3.Error as e:
            logger.error(f"Error saving scramble result: {e}")
    
    def get_scramble_stats(self, user: str) -> Dict[str, Any]:
        """Get detailed scramble statistics for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get basic stats from user_scores
                cursor.execute('''
                    SELECT score, best_score, games_played 
                    FROM user_scores 
                    WHERE user = ? AND game_type = ?
                ''', (user, "scramble"))
                basic_stats = cursor.fetchone()
                
                if not basic_stats:
                    return {
                        'total_score': 0,
                        'best_score': 0,
                        'games_played': 0,
                        'average_time': 0.0,
                        'average_score': 0.0
                    }
                
                # Get average solve time from detailed results
                cursor.execute('''
                    SELECT AVG(solve_time_seconds) as avg_time, COUNT(*) as games_count
                    FROM scramble_results 
                    WHERE user = ? AND points_earned > 0
                ''', (user,))
                time_stats = cursor.fetchone()
                
                avg_time = time_stats[0] if time_stats and time_stats[0] else 0.0
                avg_score = basic_stats[0] / basic_stats[2] if basic_stats[2] > 0 else 0.0
                
                return {
                    'total_score': basic_stats[0],
                    'best_score': basic_stats[1],
                    'games_played': basic_stats[2],
                    'average_time': avg_time,
                    'average_score': avg_score
                }
                
        except sqlite3.Error as e:
            logger.error(f"Error getting scramble stats: {e}")
            return {'total_score': 0, 'best_score': 0, 'games_played': 0, 'average_time': 0.0, 'average_score': 0.0}
    
    def save_riddle_result(self, user: str, answer: str, solve_time: float, points: int, channel: str = None):
        """Save a riddle game result"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO riddle_results (user, answer, solve_time_seconds, points_earned, channel)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user, answer, solve_time, points, channel))
                conn.commit()
                logger.debug(f"Saved riddle result: {user} solved '{answer}' in {solve_time:.1f}s for {points} points")
                
        except sqlite3.Error as e:
            logger.error(f"Error saving riddle result: {e}")
    
    def get_riddle_stats(self, user: str) -> Dict[str, Any]:
        """Get detailed riddle statistics for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get total points, solve count, best time, current streak
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_wins,
                        SUM(points_earned) as total_points,
                        MIN(solve_time_seconds) as best_time,
                        AVG(solve_time_seconds) as avg_time,
                        AVG(points_earned) as avg_points
                    FROM riddle_results 
                    WHERE user = ?
                ''', (user,))
                stats = cursor.fetchone()
                
                if not stats or stats[0] == 0:
                    return {
                        'total_wins': 0,
                        'total_points': 0,
                        'best_time': 0,
                        'avg_time': 0,
                        'avg_points': 0,
                        'current_streak': 0
                    }
                
                # Calculate current streak (consecutive days with wins)
                cursor.execute('''
                    SELECT DATE(timestamp) as solve_date
                    FROM riddle_results 
                    WHERE user = ?
                    ORDER BY timestamp DESC
                ''', (user,))
                dates = [row[0] for row in cursor.fetchall()]
                
                # Calculate streak
                current_streak = 0
                if dates:
                    from datetime import datetime, timedelta
                    today = datetime.now().date()
                    current_date = today
                    
                    for date_str in dates:
                        solve_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                        if solve_date == current_date:
                            current_streak += 1
                            current_date -= timedelta(days=1)
                        elif solve_date == current_date + timedelta(days=1):
                            # Yesterday, continue streak
                            current_streak += 1
                            current_date = solve_date - timedelta(days=1)
                        else:
                            break
                
                return {
                    'total_wins': stats[0],
                    'total_points': stats[1] or 0,
                    'best_time': stats[2] or 0,
                    'avg_time': stats[3] or 0,
                    'avg_points': stats[4] or 0,
                    'current_streak': current_streak
                }
                
        except sqlite3.Error as e:
            logger.error(f"Error getting riddle stats: {e}")
            return {'total_wins': 0, 'total_points': 0, 'best_time': 0, 'avg_time': 0, 'avg_points': 0, 'current_streak': 0}
    
    def get_riddle_leaderboard(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get riddle leaderboard by total points"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        user,
                        COUNT(*) as wins,
                        SUM(points_earned) as total_points,
                        MIN(solve_time_seconds) as best_time
                    FROM riddle_results 
                    GROUP BY user
                    ORDER BY total_points DESC, wins DESC
                    LIMIT ?
                ''', (limit,))
                
                return [
                    {
                        'user': row[0],
                        'wins': row[1],
                        'total_points': row[2],
                        'best_time': row[3]
                    }
                    for row in cursor.fetchall()
                ]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting riddle leaderboard: {e}")
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
    
    def get_recent_speak_conversations(self, limit: int = 6) -> List[Dict[str, Any]]:
        """Get recent !speak conversations from all users for context"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user, message, response, timestamp
                    FROM conversation_history 
                    WHERE message != 'context_response'
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                conversations = []
                for row in rows:
                    conversations.append({
                        'user': row[0],
                        'message': row[1],
                        'response': row[2],
                        'timestamp': row[3]
                    })
                
                # Return in chronological order (oldest first)
                return list(reversed(conversations))
                
        except sqlite3.Error as e:
            logger.error(f"Error getting recent conversations: {e}")
            return []
    
    # Command usage tracking
    def log_command_usage(self, command: str, user: str, channel: str, success: bool = True, error: str = None,
                         execution_time_ms: int = 0, memory_usage_mb: float = 0, 
                         network_latency_ms: int = 0, rate_limited: bool = False):
        """Log enhanced command usage for comprehensive analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if this is a new user
                cursor.execute('''
                    SELECT COUNT(*) FROM command_usage WHERE user = ?
                ''', (user,))
                user_is_new = cursor.fetchone()[0] == 0
                
                # Get session command count (commands in last 30 minutes)
                cursor.execute('''
                    SELECT COUNT(*) FROM command_usage 
                    WHERE user = ? AND timestamp > datetime('now', '-30 minutes')
                ''', (user,))
                session_command_count = cursor.fetchone()[0] + 1
                
                # Get time since last command
                cursor.execute('''
                    SELECT timestamp FROM command_usage 
                    WHERE user = ? ORDER BY timestamp DESC LIMIT 1
                ''', (user,))
                last_command = cursor.fetchone()
                time_since_last = 0
                if last_command:
                    last_time = datetime.fromisoformat(last_command[0])
                    time_since_last = int((datetime.now() - last_time).total_seconds())
                
                # Insert enhanced command usage
                cursor.execute('''
                    INSERT INTO command_usage (
                        command, user, channel, success, error_message,
                        execution_time_ms, memory_usage_mb, user_is_new,
                        session_command_count, time_since_last_command_sec,
                        network_latency_ms, rate_limited
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (command, user, channel, success, error, execution_time_ms,
                      memory_usage_mb, user_is_new, session_command_count, 
                      time_since_last, network_latency_ms, rate_limited))
                
                # Update user analytics
                self._update_user_analytics(cursor, user, channel, command)
                
                # Update channel analytics  
                self._update_channel_analytics(cursor, channel, user, command)
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error logging command usage: {e}")
    
    def _update_user_analytics(self, cursor, user: str, channel: str, command: str):
        """Update user analytics data"""
        try:
            # Insert or update user analytics
            cursor.execute('''
                INSERT OR IGNORE INTO user_analytics (user, favorite_channel, favorite_command)
                VALUES (?, ?, ?)
            ''', (user, channel, command))
            
            cursor.execute('''
                UPDATE user_analytics SET
                    last_seen = CURRENT_TIMESTAMP,
                    total_commands = total_commands + 1,
                    commands_this_week = commands_this_week + 1,
                    commands_this_month = commands_this_month + 1
                WHERE user = ?
            ''', (user,))
            
        except sqlite3.Error as e:
            logger.error(f"Error updating user analytics: {e}")
    
    def _update_channel_analytics(self, cursor, channel: str, user: str, command: str):
        """Update channel analytics data"""
        try:
            # Insert or update channel analytics
            cursor.execute('''
                INSERT OR IGNORE INTO channel_analytics (channel, most_active_user, most_popular_command)
                VALUES (?, ?, ?)
            ''', (channel, user, command))
            
            cursor.execute('''
                UPDATE channel_analytics SET
                    total_commands = total_commands + 1,
                    last_activity = CURRENT_TIMESTAMP
                WHERE channel = ?
            ''', (channel,))
            
        except sqlite3.Error as e:
            logger.error(f"Error updating channel analytics: {e}")

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
    
    # Pass the Pigs game methods
    def save_pigs_game(self, channel: str, game_state: str, current_player: str = None, 
                       turn_score: int = 0, join_timer_start: datetime = None):
        """Save Pass the Pigs game state"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO pigs_games 
                    (channel, game_state, current_player, turn_score, join_timer_start, last_activity)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (channel, game_state, current_player, turn_score, join_timer_start))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error saving pigs game: {e}")
            raise DatabaseError(f"Failed to save pigs game: {e}")
    
    def get_pigs_game(self, channel: str) -> Optional[Dict[str, Any]]:
        """Get Pass the Pigs game state for channel"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT game_state, current_player, turn_score, join_timer_start, 
                           created_at, last_activity
                    FROM pigs_games 
                    WHERE channel = ?
                ''', (channel,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        'game_state': result[0],
                        'current_player': result[1], 
                        'turn_score': result[2],
                        'join_timer_start': result[3],
                        'created_at': result[4],
                        'last_activity': result[5]
                    }
                return None
                
        except sqlite3.Error as e:
            logger.error(f"Error getting pigs game: {e}")
            return None
    
    def delete_pigs_game(self, channel: str):
        """Delete Pass the Pigs game for channel"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM pigs_games WHERE channel = ?', (channel,))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error deleting pigs game: {e}")
    
    def update_pigs_stats(self, player: str, game_data: dict):
        """Update Pass the Pigs player statistics with comprehensive tracking
        
        Args:
            player: Player name
            game_data: Dictionary containing:
                - game_score: Final game score
                - turn_score: Score from this turn
                - won: Whether player won
                - pig_out: Whether player pig-outed
                - oinker: Whether player got an oinker
                - positions_rolled: List of positions rolled this turn
                - rolls_this_turn: Number of rolls this turn
                - banked: Whether player banked this turn
                - bank_score: Score when banking
                - game_duration_seconds: Game duration
                - comeback_win: Whether this was a comeback win
                - close_win: Whether this was a close win (margin < 10)
                - was_behind: Whether player was behind before winning
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get current stats
                cursor.execute('''
                    SELECT * FROM pigs_leaderboard WHERE user = ?
                ''', (player,))
                
                result = cursor.fetchone()
                if result:
                    stats = dict(result)
                else:
                    # Initialize new player stats
                    stats = {
                        'wins': 0, 'games_played': 0, 'total_score': 0, 'highest_game_score': 0,
                        'highest_turn_score': 0, 'pig_outs': 0, 'oinkers': 0, 'total_rolls': 0,
                        'total_banks': 0, 'avg_rolls_before_bank': 0.0, 'risk_tolerance_score': 0.0,
                        'current_win_streak': 0, 'longest_win_streak': 0, 'current_no_pigout_streak': 0,
                        'longest_no_pigout_streak': 0, 'sides_rolled': 0, 'razorbacks_rolled': 0,
                        'trotters_rolled': 0, 'snouters_rolled': 0, 'leaning_jowlers_rolled': 0,
                        'double_positions': 0, 'double_razorback': 0, 'double_trotter': 0, 
                        'double_snouter': 0, 'double_leaning_jowler': 0, 'fastest_win_seconds': 0, 'longest_game_seconds': 0,
                        'total_game_time_seconds': 0, 'comeback_wins': 0, 'close_wins': 0,
                        'banks_under_10': 0, 'banks_10_to_20': 0, 'banks_20_to_30': 0,
                        'banks_over_30': 0, 'total_turns': 0, 'successful_turns': 0,
                        'games_this_week': 0, 'games_this_month': 0, 'weekend_games': 0, 'weekday_games': 0
                    }
                
                # Update basic stats
                won = game_data.get('won', False)
                pig_out = game_data.get('pig_out', False)
                oinker = game_data.get('oinker', False)
                game_score = game_data.get('game_score', 0)
                turn_score = game_data.get('turn_score', 0)
                game_ended = game_data.get('game_ended', False)
                
                stats['wins'] += 1 if won else 0
                # Only increment games_played when a game actually ends (win or explicit game_ended flag)
                if won or game_ended:
                    stats['games_played'] += 1
                stats['total_score'] += game_score
                stats['highest_game_score'] = max(stats['highest_game_score'], game_score)
                stats['highest_turn_score'] = max(stats['highest_turn_score'], turn_score)
                stats['pig_outs'] += 1 if pig_out else 0
                stats['oinkers'] += 1 if oinker else 0
                
                # Update streak stats
                if won:
                    stats['current_win_streak'] += 1
                    stats['longest_win_streak'] = max(stats['longest_win_streak'], stats['current_win_streak'])
                else:
                    stats['current_win_streak'] = 0
                
                if not pig_out:
                    stats['current_no_pigout_streak'] += 1
                    stats['longest_no_pigout_streak'] = max(stats['longest_no_pigout_streak'], stats['current_no_pigout_streak'])
                else:
                    stats['current_no_pigout_streak'] = 0
                
                # Update position frequency stats
                positions_rolled = game_data.get('positions_rolled', [])
                # Handle positions_rolled as [pos1, pos2] format (single roll)
                if len(positions_rolled) == 2 and isinstance(positions_rolled[0], str):
                    pos1, pos2 = positions_rolled
                    stats['sides_rolled'] += [pos1, pos2].count('side')
                    stats['razorbacks_rolled'] += [pos1, pos2].count('razorback')
                    stats['trotters_rolled'] += [pos1, pos2].count('trotter')
                    stats['snouters_rolled'] += [pos1, pos2].count('snouter')
                    stats['leaning_jowlers_rolled'] += [pos1, pos2].count('leaning_jowler')
                    if pos1 == pos2 and pos1 != 'side':  # Double positions (except pig out)
                        stats['double_positions'] += 1
                        # Track specific double positions
                        if pos1 == 'razorback':
                            stats['double_razorback'] += 1
                        elif pos1 == 'trotter':
                            stats['double_trotter'] += 1
                        elif pos1 == 'snouter':
                            stats['double_snouter'] += 1
                        elif pos1 == 'leaning_jowler':
                            stats['double_leaning_jowler'] += 1
                # Handle positions_rolled as list of tuples (multiple rolls)
                elif positions_rolled:
                    for position_pair in positions_rolled:
                        if isinstance(position_pair, (list, tuple)) and len(position_pair) == 2:
                            pos1, pos2 = position_pair
                            stats['sides_rolled'] += [pos1, pos2].count('side')
                            stats['razorbacks_rolled'] += [pos1, pos2].count('razorback')
                            stats['trotters_rolled'] += [pos1, pos2].count('trotter')
                            stats['snouters_rolled'] += [pos1, pos2].count('snouter')
                            stats['leaning_jowlers_rolled'] += [pos1, pos2].count('leaning_jowler')
                            if pos1 == pos2 and pos1 != 'side':  # Double positions (except pig out)
                                stats['double_positions'] += 1
                                # Track specific double positions
                                if pos1 == 'razorback':
                                    stats['double_razorback'] += 1
                                elif pos1 == 'trotter':
                                    stats['double_trotter'] += 1
                                elif pos1 == 'snouter':
                                    stats['double_snouter'] += 1
                                elif pos1 == 'leaning_jowler':
                                    stats['double_leaning_jowler'] += 1
                
                # Update risk and banking stats
                rolls_this_turn = game_data.get('rolls_this_turn', 0)
                banked = game_data.get('banked', False)
                bank_score = game_data.get('bank_score', 0)
                
                stats['total_rolls'] += rolls_this_turn
                stats['total_turns'] += 1
                
                if banked:
                    stats['total_banks'] += 1
                    stats['successful_turns'] += 1
                    
                    # Banking behavior tracking
                    if bank_score < 10:
                        stats['banks_under_10'] += 1
                    elif bank_score < 20:
                        stats['banks_10_to_20'] += 1
                    elif bank_score < 30:
                        stats['banks_20_to_30'] += 1
                    else:
                        stats['banks_over_30'] += 1
                
                # Calculate risk tolerance (average rolls before banking)
                if stats['total_banks'] > 0:
                    stats['avg_rolls_before_bank'] = stats['total_rolls'] / stats['total_banks']
                    # Risk tolerance score (0-100, higher = more risk-taking)
                    stats['risk_tolerance_score'] = min(100, stats['avg_rolls_before_bank'] * 20)
                
                # Update timing stats
                game_duration = game_data.get('game_duration_seconds', 0)
                if game_duration > 0:
                    stats['total_game_time_seconds'] += game_duration
                    if won:
                        if stats['fastest_win_seconds'] == 0 or game_duration < stats['fastest_win_seconds']:
                            stats['fastest_win_seconds'] = game_duration
                    stats['longest_game_seconds'] = max(stats['longest_game_seconds'], game_duration)
                
                # Update performance stats
                if game_data.get('comeback_win', False):
                    stats['comeback_wins'] += 1
                if game_data.get('close_win', False):
                    stats['close_wins'] += 1
                
                # Update social/timing stats
                from datetime import datetime
                now = datetime.now()
                is_weekend = now.weekday() >= 5  # Saturday = 5, Sunday = 6
                
                stats['games_this_week'] += 1
                stats['games_this_month'] += 1
                if is_weekend:
                    stats['weekend_games'] += 1
                else:
                    stats['weekday_games'] += 1
                
                # Build the complete UPDATE query with all new columns
                update_sql = '''
                    INSERT OR REPLACE INTO pigs_leaderboard 
                    (user, wins, games_played, total_score, highest_game_score, 
                     highest_turn_score, pig_outs, oinkers, total_rolls, total_banks,
                     avg_rolls_before_bank, risk_tolerance_score, current_win_streak,
                     longest_win_streak, current_no_pigout_streak, longest_no_pigout_streak,
                     sides_rolled, razorbacks_rolled, trotters_rolled, snouters_rolled,
                     leaning_jowlers_rolled, double_positions, double_razorback, double_trotter,
                     double_snouter, double_leaning_jowler, fastest_win_seconds,
                     longest_game_seconds, total_game_time_seconds, comeback_wins,
                     close_wins, banks_under_10, banks_10_to_20, banks_20_to_30,
                     banks_over_30, total_turns, successful_turns, games_this_week,
                     games_this_month, weekend_games, weekday_games, last_game)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                '''
                
                cursor.execute(update_sql, (
                    player, stats['wins'], stats['games_played'], stats['total_score'],
                    stats['highest_game_score'], stats['highest_turn_score'], stats['pig_outs'],
                    stats['oinkers'], stats['total_rolls'], stats['total_banks'],
                    stats['avg_rolls_before_bank'], stats['risk_tolerance_score'],
                    stats['current_win_streak'], stats['longest_win_streak'],
                    stats['current_no_pigout_streak'], stats['longest_no_pigout_streak'],
                    stats['sides_rolled'], stats['razorbacks_rolled'], stats['trotters_rolled'],
                    stats['snouters_rolled'], stats['leaning_jowlers_rolled'], stats['double_positions'],
                    stats['double_razorback'], stats['double_trotter'], stats['double_snouter'], stats['double_leaning_jowler'],
                    stats['fastest_win_seconds'], stats['longest_game_seconds'],
                    stats['total_game_time_seconds'], stats['comeback_wins'], stats['close_wins'],
                    stats['banks_under_10'], stats['banks_10_to_20'], stats['banks_20_to_30'],
                    stats['banks_over_30'], stats['total_turns'], stats['successful_turns'],
                    stats['games_this_week'], stats['games_this_month'], stats['weekend_games'],
                    stats['weekday_games']
                ))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error updating pigs stats: {e}")
    
    def get_pigs_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get Pass the Pigs leaderboard"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user, wins, games_played, total_score, highest_game_score, 
                           highest_turn_score, pig_outs, oinkers, last_game
                    FROM pigs_leaderboard 
                    ORDER BY wins DESC, highest_game_score DESC, total_score DESC
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting pigs leaderboard: {e}")
            return []
    
    def get_comprehensive_pigs_stats(self, player: str) -> dict:
        """Get comprehensive Pass the Pigs statistics for a player"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM pigs_leaderboard WHERE user = ?
                ''', (player,))
                
                result = cursor.fetchone()
                if not result:
                    return {}
                
                stats = dict(result)
                
                # Calculate derived stats
                if stats['games_played'] > 0:
                    stats['win_rate'] = (stats['wins'] / stats['games_played']) * 100
                    stats['avg_game_score'] = stats['total_score'] / stats['games_played']
                    stats['avg_game_duration'] = stats['total_game_time_seconds'] / stats['games_played'] if stats['total_game_time_seconds'] > 0 else 0
                else:
                    stats['win_rate'] = 0
                    stats['avg_game_score'] = 0
                    stats['avg_game_duration'] = 0
                
                if stats['total_turns'] > 0:
                    stats['success_rate'] = (stats['successful_turns'] / stats['total_turns']) * 100
                    stats['pig_out_rate'] = (stats['pig_outs'] / stats['total_turns']) * 100
                else:
                    stats['success_rate'] = 0
                    stats['pig_out_rate'] = 0
                
                # Position analysis
                total_pigs_rolled = (stats['sides_rolled'] + stats['razorbacks_rolled'] + 
                                   stats['trotters_rolled'] + stats['snouters_rolled'] + 
                                   stats['leaning_jowlers_rolled'])
                
                if total_pigs_rolled > 0:
                    stats['position_percentages'] = {
                        'side': (stats['sides_rolled'] / total_pigs_rolled) * 100,
                        'razorback': (stats['razorbacks_rolled'] / total_pigs_rolled) * 100,
                        'trotter': (stats['trotters_rolled'] / total_pigs_rolled) * 100,
                        'snouter': (stats['snouters_rolled'] / total_pigs_rolled) * 100,
                        'leaning_jowler': (stats['leaning_jowlers_rolled'] / total_pigs_rolled) * 100
                    }
                else:
                    stats['position_percentages'] = {}
                
                # Banking analysis
                total_banks = (stats['banks_under_10'] + stats['banks_10_to_20'] + 
                              stats['banks_20_to_30'] + stats['banks_over_30'])
                
                if total_banks > 0:
                    stats['banking_behavior'] = {
                        'conservative': ((stats['banks_under_10'] + stats['banks_10_to_20']) / total_banks) * 100,
                        'moderate': (stats['banks_20_to_30'] / total_banks) * 100,
                        'aggressive': (stats['banks_over_30'] / total_banks) * 100
                    }
                else:
                    stats['banking_behavior'] = {}
                
                return stats
                
        except sqlite3.Error as e:
            logger.error(f"Error getting comprehensive pigs stats: {e}")
            return {}
    
    def update_uno_stats(self, player: str, game_data: dict):
        """Update UNO player statistics with comprehensive tracking
        
        Args:
            player: Player name
            game_data: Dictionary containing game statistics
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get current stats or initialize
                cursor.execute('SELECT * FROM uno_leaderboard WHERE user = ?', (player,))
                result = cursor.fetchone()
                
                if result:
                    stats = dict(result)
                else:
                    # Initialize new player
                    stats = {col: 0 for col in [
                        'wins', 'games_played', 'total_cards_played', 'avg_cards_per_game',
                        'wild_cards_played', 'plus4_cards_played', 'plus2_cards_played',
                        'skip_cards_played', 'reverse_cards_played', 'successful_uno_calls',
                        'caught_no_uno', 'successful_challenges', 'failed_challenges',
                        'times_challenged', 'fastest_game_seconds', 'longest_game_seconds',
                        'total_game_time_seconds', 'largest_hand_size', 'comeback_wins',
                        'uno_wins', 'current_win_streak', 'longest_win_streak',
                        'red_cards_played', 'blue_cards_played', 'green_cards_played',
                        'yellow_cards_played', 'games_this_week', 'games_this_month',
                        'weekend_games', 'weekday_games'
                    ]}
                
                # Update basic stats
                won = game_data.get('won', False)
                cards_played = game_data.get('cards_played', 0)
                game_duration = game_data.get('game_duration_seconds', 0)
                
                stats['games_played'] += 1
                stats['wins'] += 1 if won else 0
                stats['total_cards_played'] += cards_played
                
                # Update card-specific stats
                stats['wild_cards_played'] += game_data.get('wild_cards_played', 0)
                stats['plus4_cards_played'] += game_data.get('plus4_cards_played', 0)
                stats['plus2_cards_played'] += game_data.get('plus2_cards_played', 0)
                stats['skip_cards_played'] += game_data.get('skip_cards_played', 0)
                stats['reverse_cards_played'] += game_data.get('reverse_cards_played', 0)
                
                # Update color preferences
                stats['red_cards_played'] += game_data.get('red_cards_played', 0)
                stats['blue_cards_played'] += game_data.get('blue_cards_played', 0)
                stats['green_cards_played'] += game_data.get('green_cards_played', 0)
                stats['yellow_cards_played'] += game_data.get('yellow_cards_played', 0)
                
                # Update defensive stats
                stats['successful_uno_calls'] += game_data.get('successful_uno_calls', 0)
                stats['caught_no_uno'] += game_data.get('caught_no_uno', 0)
                stats['successful_challenges'] += game_data.get('successful_challenges', 0)
                stats['failed_challenges'] += game_data.get('failed_challenges', 0)
                stats['times_challenged'] += game_data.get('times_challenged', 0)
                
                # Update performance stats
                max_hand_size = game_data.get('max_hand_size', 0)
                stats['largest_hand_size'] = max(stats['largest_hand_size'], max_hand_size)
                
                if game_data.get('comeback_win', False):
                    stats['comeback_wins'] += 1
                if game_data.get('uno_win', False):  # Won by playing last card
                    stats['uno_wins'] += 1
                
                # Update timing stats
                if game_duration > 0:
                    stats['total_game_time_seconds'] += game_duration
                    if won:
                        if stats['fastest_game_seconds'] == 0 or game_duration < stats['fastest_game_seconds']:
                            stats['fastest_game_seconds'] = game_duration
                    stats['longest_game_seconds'] = max(stats['longest_game_seconds'], game_duration)
                
                # Update streak stats
                if won:
                    stats['current_win_streak'] += 1
                    stats['longest_win_streak'] = max(stats['longest_win_streak'], stats['current_win_streak'])
                else:
                    stats['current_win_streak'] = 0
                
                # Calculate avg cards per game
                if stats['games_played'] > 0:
                    stats['avg_cards_per_game'] = stats['total_cards_played'] / stats['games_played']
                
                # Update social/timing stats
                from datetime import datetime
                now = datetime.now()
                is_weekend = now.weekday() >= 5
                
                stats['games_this_week'] += 1
                stats['games_this_month'] += 1
                if is_weekend:
                    stats['weekend_games'] += 1
                else:
                    stats['weekday_games'] += 1
                
                # Build complete UPDATE query
                update_sql = '''
                    INSERT OR REPLACE INTO uno_leaderboard 
                    (user, wins, games_played, total_cards_played, avg_cards_per_game,
                     wild_cards_played, plus4_cards_played, plus2_cards_played, 
                     skip_cards_played, reverse_cards_played, successful_uno_calls,
                     caught_no_uno, successful_challenges, failed_challenges, times_challenged,
                     fastest_game_seconds, longest_game_seconds, total_game_time_seconds,
                     largest_hand_size, comeback_wins, uno_wins, current_win_streak,
                     longest_win_streak, red_cards_played, blue_cards_played, 
                     green_cards_played, yellow_cards_played, games_this_week,
                     games_this_month, weekend_games, weekday_games, last_game)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                '''
                
                cursor.execute(update_sql, (
                    player, stats['wins'], stats['games_played'], stats['total_cards_played'],
                    stats['avg_cards_per_game'], stats['wild_cards_played'], stats['plus4_cards_played'],
                    stats['plus2_cards_played'], stats['skip_cards_played'], stats['reverse_cards_played'],
                    stats['successful_uno_calls'], stats['caught_no_uno'], stats['successful_challenges'],
                    stats['failed_challenges'], stats['times_challenged'], stats['fastest_game_seconds'],
                    stats['longest_game_seconds'], stats['total_game_time_seconds'], stats['largest_hand_size'],
                    stats['comeback_wins'], stats['uno_wins'], stats['current_win_streak'],
                    stats['longest_win_streak'], stats['red_cards_played'], stats['blue_cards_played'],
                    stats['green_cards_played'], stats['yellow_cards_played'], stats['games_this_week'],
                    stats['games_this_month'], stats['weekend_games'], stats['weekday_games']
                ))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error updating UNO stats: {e}")

    # Comprehensive Analytics Methods
    def get_user_analytics(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get comprehensive user behavior analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        ua.user,
                        ua.total_commands,
                        ua.commands_this_week,
                        ua.commands_this_month,
                        ua.favorite_command,
                        ua.favorite_channel,
                        ua.most_active_hour,
                        ua.first_seen,
                        ua.last_seen,
                        -- Performance metrics from command_usage
                        ROUND(AVG(cu.execution_time_ms), 2) as avg_execution_time,
                        COUNT(DISTINCT cu.command) as unique_commands_used,
                        COUNT(CASE WHEN cu.success = 0 THEN 1 END) as error_count,
                        COUNT(*) as total_recent_commands
                    FROM user_analytics ua
                    LEFT JOIN command_usage cu ON ua.user = cu.user 
                        AND cu.timestamp > datetime('now', '-{} days')
                    GROUP BY ua.user
                    ORDER BY ua.total_commands DESC
                '''.format(days))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting user analytics: {e}")
            return []

    def get_channel_analytics(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get comprehensive channel analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        ca.channel,
                        ca.total_commands,
                        ca.most_popular_command,
                        ca.most_active_user,
                        ca.peak_activity_hour,
                        ca.last_activity,
                        -- Recent activity metrics
                        COUNT(cu.id) as commands_last_30_days,
                        COUNT(DISTINCT cu.user) as unique_users_30_days,
                        ROUND(AVG(cu.execution_time_ms), 2) as avg_command_time,
                        COUNT(CASE WHEN cu.success = 0 THEN 1 END) as error_count_30_days
                    FROM channel_analytics ca
                    LEFT JOIN command_usage cu ON ca.channel = cu.channel 
                        AND cu.timestamp > datetime('now', '-{} days')
                    GROUP BY ca.channel
                    ORDER BY ca.total_commands DESC
                '''.format(days))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting channel analytics: {e}")
            return []

    def get_performance_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """Get system performance analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Command performance metrics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_commands,
                        ROUND(AVG(execution_time_ms), 2) as avg_execution_time,
                        MAX(execution_time_ms) as max_execution_time,
                        MIN(execution_time_ms) as min_execution_time,
                        ROUND(AVG(memory_usage_mb), 2) as avg_memory_usage,
                        MAX(memory_usage_mb) as peak_memory_usage,
                        COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                        COUNT(CASE WHEN rate_limited = 1 THEN 1 END) as rate_limit_hits,
                        COUNT(DISTINCT user) as unique_users,
                        COUNT(DISTINCT channel) as active_channels
                    FROM command_usage 
                    WHERE timestamp > datetime('now', '-{} hours')
                '''.format(hours))
                
                performance = dict(cursor.fetchone())
                
                # Error rate calculation
                if performance['total_commands'] > 0:
                    performance['error_rate_percent'] = round(
                        (performance['error_count'] / performance['total_commands']) * 100, 2
                    )
                else:
                    performance['error_rate_percent'] = 0
                
                # Commands per hour
                performance['commands_per_hour'] = round(performance['total_commands'] / hours, 1)
                
                return performance
                
        except sqlite3.Error as e:
            logger.error(f"Error getting performance analytics: {e}")
            return {}

    def get_ai_analytics(self, days: int = 7) -> Dict[str, Any]:
        """Get AI conversation analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # AI command usage from command_usage table
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_ai_commands,
                        COUNT(DISTINCT user) as unique_ai_users,
                        ROUND(AVG(execution_time_ms), 2) as avg_response_time,
                        COUNT(CASE WHEN success = 0 THEN 1 END) as ai_errors
                    FROM command_usage 
                    WHERE command LIKE '%speak%' OR command LIKE '%ai%' OR command LIKE '%chat%'
                        AND timestamp > datetime('now', '-{} days')
                '''.format(days))
                
                ai_stats = dict(cursor.fetchone())
                
                # Conversation history analytics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_conversations,
                        COUNT(DISTINCT user) as unique_conversation_users,
                        ROUND(AVG(LENGTH(message)), 1) as avg_message_length,
                        ROUND(AVG(LENGTH(response)), 1) as avg_response_length
                    FROM conversation_history 
                    WHERE timestamp > datetime('now', '-{} days')
                '''.format(days))
                
                conv_stats = dict(cursor.fetchone())
                ai_stats.update(conv_stats)
                
                return ai_stats
                
        except sqlite3.Error as e:
            logger.error(f"Error getting AI analytics: {e}")
            return {}

    def get_game_analytics(self, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive game analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                analytics = {}
                
                # UNO game analytics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_uno_players,
                        SUM(games_played) as total_uno_games,
                        ROUND(AVG(games_played), 1) as avg_games_per_player,
                        ROUND(AVG(avg_cards_per_game), 1) as avg_cards_per_game,
                        MAX(longest_win_streak) as longest_win_streak,
                        SUM(comeback_wins) as total_comeback_wins,
                        ROUND(AVG(total_game_time_seconds / NULLIF(games_played, 0)), 1) as avg_game_duration_sec
                    FROM uno_leaderboard
                    WHERE last_game > datetime('now', '-{} days')
                '''.format(days))
                
                analytics['uno'] = dict(cursor.fetchone())
                
                # Pigs game analytics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_pigs_players,
                        SUM(games_played) as total_pigs_games,
                        ROUND(AVG(games_played), 1) as avg_games_per_player,
                        MAX(highest_game_score) as highest_score,
                        SUM(pig_outs) as total_pig_outs,
                        SUM(oinkers) as total_oinkers,
                        ROUND(AVG(total_rolls / NULLIF(games_played, 0)), 1) as avg_rolls_per_game,
                        ROUND(SUM(total_banks) * 100.0 / NULLIF(SUM(total_rolls), 0), 1) as banking_percentage
                    FROM pigs_leaderboard
                    WHERE last_game > datetime('now', '-{} days')
                '''.format(days))
                
                analytics['pigs'] = dict(cursor.fetchone())
                
                return analytics
                
        except sqlite3.Error as e:
            logger.error(f"Error getting game analytics: {e}")
            return {}

    def get_top_performers(self, metric: str = 'total_commands', limit: int = 10) -> List[Dict[str, Any]]:
        """Get top performing users by various metrics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                valid_metrics = {
                    'total_commands': 'ua.total_commands',
                    'commands_this_week': 'ua.commands_this_week', 
                    'avg_execution_time': 'AVG(cu.execution_time_ms)',
                    'error_rate': 'COUNT(CASE WHEN cu.success = 0 THEN 1 END) * 100.0 / COUNT(*)',
                    'unique_commands': 'COUNT(DISTINCT cu.command)'
                }
                
                if metric not in valid_metrics:
                    metric = 'total_commands'
                
                cursor.execute('''
                    SELECT 
                        ua.user,
                        ua.total_commands,
                        ua.commands_this_week,
                        ROUND(AVG(cu.execution_time_ms), 2) as avg_execution_time,
                        COUNT(DISTINCT cu.command) as unique_commands_used,
                        ROUND(COUNT(CASE WHEN cu.success = 0 THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0), 1) as error_rate
                    FROM user_analytics ua
                    LEFT JOIN command_usage cu ON ua.user = cu.user 
                        AND cu.timestamp > datetime('now', '-30 days')
                    GROUP BY ua.user
                    ORDER BY {} DESC
                    LIMIT ?
                '''.format(valid_metrics[metric]), (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting top performers: {e}")
            return []

    def log_ai_conversation(self, user: str, channel: str, message_count: int = 1, 
                          avg_response_length: int = 0, duration_min: float = 0, topics: List[str] = None):
        """Log AI conversation analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO ai_analytics 
                    (user, channel, messages_in_conversation, avg_response_length, 
                     conversation_duration_min, topics)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user, channel, message_count, avg_response_length, duration_min, 
                      json.dumps(topics) if topics else None))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error logging AI conversation: {e}")

    def log_game_session(self, game_type: str, channel: str, players: List[str], 
                        duration_minutes: float = 0, winner: str = None, 
                        abandoned: bool = False, total_turns: int = 0):
        """Log game session analytics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                avg_turn_time = duration_minutes * 60 / max(total_turns, 1) if total_turns > 0 else 0
                
                cursor.execute('''
                    INSERT INTO game_sessions 
                    (game_type, channel, session_end, duration_minutes, player_count,
                     players, winner, abandoned, total_turns, avg_turn_time_sec)
                    VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
                ''', (game_type, channel, duration_minutes, len(players), 
                      json.dumps(players), winner, abandoned, total_turns, avg_turn_time))
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Error logging game session: {e}")

    # Bot configuration management methods
    def set_config(self, network: str, setting_name: str, setting_value: Any, 
                   setting_type: str = 'string', description: str = None):
        """Set a configuration value for a specific network"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Convert value to string for storage
                if setting_type == 'json':
                    value_str = json.dumps(setting_value)
                elif setting_type == 'bool':
                    value_str = '1' if setting_value else '0'
                else:
                    value_str = str(setting_value)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO bot_config 
                    (network, setting_name, setting_value, setting_type, description, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (network.lower(), setting_name, value_str, setting_type, description))
                
                conn.commit()
                logger.info(f"Config updated: {network}.{setting_name} = {setting_value}")
                
        except sqlite3.Error as e:
            logger.error(f"Error setting config {network}.{setting_name}: {e}")
            raise DatabaseError(f"Failed to set config: {e}")
    
    def get_config(self, network: str, setting_name: str, default_value: Any = None) -> Any:
        """Get a configuration value for a specific network"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT setting_value, setting_type FROM bot_config 
                    WHERE network = ? AND setting_name = ?
                ''', (network.lower(), setting_name))
                
                result = cursor.fetchone()
                if not result:
                    return default_value
                
                value_str, setting_type = result
                
                # Convert string back to appropriate type
                if setting_type == 'int':
                    return int(value_str)
                elif setting_type == 'float':
                    return float(value_str)
                elif setting_type == 'bool':
                    return value_str == '1'
                elif setting_type == 'json':
                    return json.loads(value_str)
                else:
                    return value_str
                    
        except (sqlite3.Error, ValueError, json.JSONDecodeError) as e:
            logger.error(f"Error getting config {network}.{setting_name}: {e}")
            return default_value
    
    def get_all_config(self, network: str = None) -> Dict[str, Dict]:
        """Get all configuration settings, optionally for a specific network"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if network:
                    cursor.execute('''
                        SELECT setting_name, setting_value, setting_type, description, updated_at
                        FROM bot_config WHERE network = ?
                        ORDER BY setting_name
                    ''', (network.lower(),))
                else:
                    cursor.execute('''
                        SELECT network, setting_name, setting_value, setting_type, description, updated_at
                        FROM bot_config ORDER BY network, setting_name
                    ''')
                
                config = {}
                for row in cursor.fetchall():
                    if network:
                        name, value_str, setting_type, description, updated_at = row
                        # Convert value to appropriate type
                        if setting_type == 'int':
                            value = int(value_str)
                        elif setting_type == 'float':
                            value = float(value_str)
                        elif setting_type == 'bool':
                            value = value_str == '1'
                        elif setting_type == 'json':
                            value = json.loads(value_str)
                        else:
                            value = value_str
                        
                        config[name] = {
                            'value': value,
                            'type': setting_type,
                            'description': description,
                            'updated_at': updated_at
                        }
                    else:
                        net, name, value_str, setting_type, description, updated_at = row
                        if net not in config:
                            config[net] = {}
                        
                        # Convert value to appropriate type
                        if setting_type == 'int':
                            value = int(value_str)
                        elif setting_type == 'float':
                            value = float(value_str)
                        elif setting_type == 'bool':
                            value = value_str == '1'
                        elif setting_type == 'json':
                            value = json.loads(value_str)
                        else:
                            value = value_str
                        
                        config[net][name] = {
                            'value': value,
                            'type': setting_type,
                            'description': description,
                            'updated_at': updated_at
                        }
                
                return config
                
        except (sqlite3.Error, ValueError, json.JSONDecodeError) as e:
            logger.error(f"Error getting all config: {e}")
            return {}
    
    def delete_config(self, network: str, setting_name: str):
        """Delete a configuration setting"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM bot_config WHERE network = ? AND setting_name = ?
                ''', (network.lower(), setting_name))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    logger.info(f"Config deleted: {network}.{setting_name}")
                    return True
                else:
                    logger.warning(f"Config not found: {network}.{setting_name}")
                    return False
                    
        except sqlite3.Error as e:
            logger.error(f"Error deleting config {network}.{setting_name}: {e}")
            return False

    # Bean images methods
    def add_bean_image(self, url: str, added_by: str, channel: str = None, description: str = None) -> int:
        """Add a new bean image URL and return its ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO bean_images (url, added_by, channel, description)
                    VALUES (?, ?, ?, ?)
                ''', (url, added_by, channel, description))
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.IntegrityError:
            logger.warning(f"Bean image already exists: {url}")
            return -1  # URL already exists
        except sqlite3.Error as e:
            logger.error(f"Error adding bean image: {e}")
            raise DatabaseError(f"Failed to add bean image: {e}")
    
    def get_random_bean_image(self) -> Optional[Dict[str, Any]]:
        """Get a random bean image and increment its view count"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get a random bean image
                cursor.execute('''
                    SELECT id, url, added_by, description, view_count
                    FROM bean_images 
                    ORDER BY RANDOM() 
                    LIMIT 1
                ''')
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                bean_data = dict(result)
                
                # Update view count and last viewed time
                cursor.execute('''
                    UPDATE bean_images 
                    SET view_count = view_count + 1, last_viewed = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (bean_data['id'],))
                
                conn.commit()
                return bean_data
                
        except sqlite3.Error as e:
            logger.error(f"Error getting random bean image: {e}")
            return None
    
    def get_bean_image_count(self) -> int:
        """Get total count of bean images"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) as count FROM bean_images')
                result = cursor.fetchone()
                return result['count'] if result else 0
                
        except sqlite3.Error as e:
            logger.error(f"Error getting bean image count: {e}")
            return 0
    
    def get_user_bean_images(self, user: str) -> List[Dict[str, Any]]:
        """Get all bean images added by a specific user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, url, added_time, description, view_count
                    FROM bean_images 
                    WHERE added_by = ?
                    ORDER BY added_time DESC
                ''', (user,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting user bean images: {e}")
            return []

# Legacy JSON migration code removed - migration completed
"""Riddle commands for the IRC bot using external API"""

import requests
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List, Set
from core.plugin_system import command
from core.database import BotDatabase
from core.timezone_utils import now_uk

logger = logging.getLogger(__name__)

class RiddleGame:
    def __init__(self):
        self.active_riddles: Dict[str, Tuple[str, str, datetime, Set[str]]] = {}  # channel -> (riddle, answer, start_time, keywords)
        self.api_url = "https://riddles-api.vercel.app/random"
        # Common words to ignore when extracting keywords
        self.stop_words = {
            'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
            'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'that', 'the',
            'to', 'was', 'will', 'with', 'the', 'this', 'these', 'those',
            'they', 'them', 'their', 'what', 'which', 'who', 'when', 'where',
            'why', 'how', 'all', 'would', 'could', 'should', 'may', 'might',
            'must', 'can', 'could', 'do', 'does', 'did', 'have', 'had', 'has',
            'make', 'made', 'see', 'saw', 'seen', 'very', 'just', 'only',
            'some', 'any', 'one', 'two', 'three', 'four', 'five', 'you', 'your'
        }
    
    def extract_keywords(self, answer: str) -> Set[str]:
        """Extract important keywords from the answer"""
        # Clean the answer - remove punctuation and lowercase
        clean_answer = re.sub(r'[^\w\s]', ' ', answer.lower())
        words = clean_answer.split()
        
        # Filter out stop words and short words
        keywords = set()
        for word in words:
            if len(word) > 2 and word not in self.stop_words:
                keywords.add(word.lower())  # Ensure lowercase
                # Also add singular/plural variants
                if word.endswith('s'):
                    keywords.add(word[:-1].lower())  # Remove 's' for potential singular
                else:
                    keywords.add((word + 's').lower())  # Add 's' for potential plural
        
        # For short answers, be more lenient
        if len(keywords) < 2 and words:
            # Add any word longer than 1 character
            for word in words:
                if len(word) > 1:
                    keywords.add(word.lower())
        
        return keywords
        
    def fetch_riddle(self) -> Tuple[str, str]:
        """Fetch a riddle from the API"""
        try:
            response = requests.get(self.api_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('riddle', ''), data.get('answer', '')
            else:
                logger.error(f"API returned status {response.status_code}")
                return None, None
        except requests.RequestException as e:
            logger.error(f"Error fetching riddle: {e}")
            return None, None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing riddle JSON: {e}")
            return None, None
    
    def start_riddle(self, channel: str) -> str:
        """Start a new riddle in the channel"""
        # Check if there's already an active riddle
        if channel in self.active_riddles:
            _, _, start_time, _ = self.active_riddles[channel]
            # Allow new riddle after 10 minutes
            if (now_uk() - start_time).total_seconds() < 600:
                return f"There's already an active riddle: {self.active_riddles[channel][0]}"
        
        riddle, answer = self.fetch_riddle()
        if not riddle or not answer:
            return "Sorry, couldn't fetch a riddle right now. Try again!"
        
        # Extract keywords from answer
        keywords = self.extract_keywords(answer)
        logger.info(f"Riddle answer: {answer}, Keywords: {keywords}")
        
        self.active_riddles[channel] = (riddle, answer, now_uk(), keywords)
        return f"Riddle: {riddle}"
    
    def check_guess(self, channel: str, guess: str, nick: str, db: Optional[BotDatabase] = None) -> Optional[str]:
        """Check if a guess contains the key concepts"""
        if channel not in self.active_riddles:
            logger.debug(f"No active riddle in channel: {channel}")
            logger.debug(f"Active channels: {list(self.active_riddles.keys())}")
            return None
            
        riddle, answer, start_time, keywords = self.active_riddles[channel]
        
        # Clean the guess - ensure lowercase for case-insensitive matching
        clean_guess = re.sub(r'[^\w\s]', ' ', guess.lower())
        guess_words = set(word.lower() for word in clean_guess.split() if word)
        
        # Log for debugging
        logger.debug(f"Checking guess '{guess}' against keywords: {keywords}")
        logger.debug(f"Guess words: {guess_words}")
        
        # Check for keyword matches
        matches = keywords.intersection(guess_words)
        logger.debug(f"Matches found: {matches}")
        
        # If we match at least one important keyword (or exact answer)
        if matches or answer.lower() in guess.lower():
            # Calculate solve time and points
            solve_time = (now_uk() - start_time).total_seconds()
            
            # Points based on speed: 100 base - seconds taken (min 10 points)
            points = max(10, int(100 - solve_time))
            
            # Bonus for very fast solves
            if solve_time < 10:
                points += 50  # Speed bonus
            elif solve_time < 30:
                points += 20
            
            del self.active_riddles[channel]
            
            # Save to database
            if db:
                try:
                    db.save_riddle_result(nick, answer, solve_time, points, channel)
                except Exception as e:
                    logger.error(f"Failed to save riddle result: {e}")
            
            # Build response message
            response = f"✓ Correct, {nick}! Answer: {answer} | "
            response += f"Time: {int(solve_time)}s | Points: +{points}"
            
            return response
        
        return None
    
    def reveal_answer(self, channel: str) -> str:
        """Reveal the answer to the current riddle"""
        if channel not in self.active_riddles:
            return "No active riddle. Start one with: riddle"
            
        riddle, answer, _, keywords = self.active_riddles[channel]
        del self.active_riddles[channel]
        return f"Answer: {answer}"
    
    def get_current(self, channel: str) -> str:
        """Get the current riddle"""
        if channel not in self.active_riddles:
            return "No active riddle. Start one with: riddle"
            
        riddle, _, start_time, _ = self.active_riddles[channel]
        elapsed = int((now_uk() - start_time).total_seconds())
        
        # Auto-cleanup old riddles (after 10 minutes)
        if elapsed > 600:
            del self.active_riddles[channel]
            return "Previous riddle expired. Start a new one with: riddle"
            
        # Show time elapsed
        minutes = elapsed // 60
        seconds = elapsed % 60
        return f"Current riddle ({minutes}m {seconds}s ago): {riddle}"

# Global game instance
riddle_game = RiddleGame()

@command(
    pattern=r'riddle$',
    description="Get a riddle to discuss",
    category="games"
)
def riddle(msg):
    """Start a new riddle"""
    channel = msg.get("channel", "unknown")
    return riddle_game.start_riddle(channel)

@command(
    pattern=r'riddle\.answer$',
    description="Reveal the answer",
    category="games"
)
def riddle_answer(msg):
    """Reveal the answer"""
    channel = msg.get("channel", "unknown")
    return riddle_game.reveal_answer(channel)

@command(
    pattern=r'riddle\.current$',
    description="Show current riddle",
    category="games"
)
def riddle_current(msg):
    """Get current riddle"""
    channel = msg.get("channel", "unknown")
    return riddle_game.get_current(channel)

@command(
    pattern=r'riddle\.stats(?:\s+(.+))?$',
    description="Show riddle stats for a player",
    usage="riddle.stats [nick]",
    category="games",
    requires_bot=True
)
async def riddle_stats(msg, bot=None):
    """Show riddle statistics for a player"""
    try:
        logger.debug(f"riddle_stats called with bot={bot}, msg={msg}")
        if not bot:
            return "Bot object not available"
        if not hasattr(bot, 'database'):
            return "Database not available on bot"
        if not bot.database:
            return "Database is None"
        
        parts = msg["message"].split(maxsplit=1)
        target_nick = parts[1] if len(parts) > 1 else msg.get("user", msg.get("nick", "unknown"))
        logger.debug(f"Getting stats for: {target_nick}")
    except Exception as e:
        logger.error(f"Error in riddle_stats setup: {e}")
        return f"Setup error: {e}"
    
    try:
        stats = bot.database.get_riddle_stats(target_nick)
        if not stats or stats['total_wins'] == 0:
            return f"No riddle stats for {target_nick}"
        
        wins = stats['total_wins']
        points = stats['total_points']
        streak = stats['current_streak']
        best_time = stats['best_time']
        
        response = f"📊 {target_nick}: {points} pts | {wins} wins"
        if streak > 1:
            response += f" | 🔥{streak} streak"
        if best_time > 0:
            response += f" | ⚡{int(best_time)}s best"
        
        return response
    except Exception as e:
        logger.error(f"Error getting riddle stats: {e}")
        return "Error retrieving stats"

@command(
    pattern=r'riddle\.top$',
    description="Show riddle leaderboard",
    category="games",
    requires_bot=True
)
async def riddle_leaderboard(msg, bot=None):
    """Show top riddle solvers"""
    if not bot or not bot.database:
        return "Leaderboard not available"
    
    try:
        # Get top players by total points
        results = bot.database.get_riddle_leaderboard(5)
        
        if not results:
            return "No riddle stats yet!"
        
        entries = []
        for i, player_data in enumerate(results, 1):
            user = player_data['user']
            points = player_data['total_points']
            wins = player_data['wins']
            entry = f"{i}. {user} ({points}pts/{wins}w)"
            entries.append(entry)
        
        return "🏆 Top riddlers: " + " | ".join(entries)
    except Exception as e:
        logger.error(f"Error getting leaderboard: {e}")
        return "Error retrieving leaderboard"

@command(
    pattern=r'riddle\.fastest$',
    description="Show fastest riddle solves",
    category="games",
    requires_bot=True
)
async def riddle_fastest(msg, bot=None):
    """Show fastest riddle solve times"""
    if not bot or not bot.database:
        return "Stats not available"
    
    try:
        # Get players with best times from leaderboard
        results = bot.database.get_riddle_leaderboard(10)  # Get more to sort by time
        
        if not results:
            return "No speed records yet!"
        
        # Filter and sort by best time
        speed_records = []
        for player_data in results:
            if player_data['best_time'] > 0:
                speed_records.append((player_data['user'], player_data['best_time']))
        
        # Sort by best time (fastest first)
        speed_records.sort(key=lambda x: x[1])
        
        if not speed_records:
            return "No speed records yet!"
        
        entries = []
        for i, (player, best_time) in enumerate(speed_records[:5], 1):
            entries.append(f"{i}. {player} ({int(best_time)}s)")
            
        return "⚡ Fastest solves: " + " | ".join(entries)
    except Exception as e:
        logger.error(f"Error getting fastest times: {e}")
        return "Error retrieving records"

def check_riddle_answers(msg, bot=None):
    """Check messages for potential riddle answers"""
    channel = msg.get("channel", "unknown")
    message = msg.get("message", "").strip()
    nick = msg.get("user", "unknown")
    
    # Skip if message is a command
    if message.startswith(('!', '~', '.')):
        return None
    
    # Check if this could be an answer (at least 2 chars)
    if len(message) > 1:
        # Log for debugging
        if channel in riddle_game.active_riddles:
            logger.debug(f"Checking riddle answer from {nick}: {message[:50]}")
        result = riddle_game.check_guess(channel, message, nick, bot.database if bot else None)
        if result:
            logger.info(f"Riddle solved by {nick} with: {message}")
        return result
    
    return None

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    # Auto-register all commands in this module
    auto_register_commands(plugin_manager, sys.modules[__name__])
    
    # Register the answer checker as a general message handler
    plugin_manager.register_message_handler(check_riddle_answers)
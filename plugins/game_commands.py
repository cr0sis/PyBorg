"""Game commands for the IRC bot including bet7 and dice rolling"""

import random
import json
import logging
import os
import time
import requests
from datetime import datetime
from core.plugin_system import command
from core.database import BotDatabase

logger = logging.getLogger(__name__)

def fix_nick(name):
    """Add zero-width character to avoid highlights"""
    if len(name) > 1:
        return name[0] + "\u200B" + name[1:]
    return name

def read_json_file(filename):
    """Read JSON file with fallback"""
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error reading {filename}: {e}")
    
    # Return default structure
    return {
        'scores': {},
        'best_scores': {},
        'lowest_score': 7,
        'lowest_score_user': None
    }

def write_json_file(filename, data):
    """Write JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error writing {filename}: {e}")

@command(
    pattern=r'roll7$',
    description="Roll 7 dice (lowest sum wins)",
    category="games"
)
def roll_dice2(msg):
    """Roll 7 dice - exactly as original"""
    u = msg["user"]
    m = msg["message"]
    dice = []  # Initialize an empty list to store the dice rolls
    render = ""
    
    for i in range(7):
        roll = random.randint(1, 6)
        dice.append(roll)
        if roll == 1:
            col = "\x0313,15"
        else:
            col = "\x0301,15"
        if i == 0:
            render += col + " " + str(roll)
        elif i == 6:
            render += "-" + col + str(roll) + " "
        else:
            render += "-" + col + str(roll)
    
    newrecord = False
    sum_dice = sum(dice)
    
    # Read data from JSON file
    data = read_json_file('dice_rolls.json')
    
    # Initialize missing fields
    if 'total_rolls' not in data:
        data['total_rolls'] = 0
    if 'lowest_score' not in data:
        data['lowest_score'] = 42  # Maximum possible with 7 dice
    if 'lowest_score_user' not in data:
        data['lowest_score_user'] = None
    if 'best_scores' not in data:
        data['best_scores'] = {}
    
    # Increment total number of rolls
    data['total_rolls'] += 1
    
    # Update lowest score and user with lowest score
    if sum_dice < data['lowest_score']:
        data['lowest_score'] = sum_dice
        data['lowest_score_user'] = u
        newrecord = True
    
    # Update best score for current user
    if u not in data['best_scores'] or sum_dice < data['best_scores'][u]:
        data['best_scores'][u] = sum_dice
    
    # Write updated data to JSON file
    write_json_file('dice_rolls.json', data)
    
    render = [render + "\x03 " + u + "\x03 rolled: \x0307 " + str(sum_dice)]
    if not newrecord:
        return render
    else:
        render.append("omg " + u + " broke the record!!")
        return render

@command(
    pattern=r'bet7',
    description="Play bet7 dice game (lowest roll wins)",
    usage="bet7 to join/start game",
    category="games"
)
def bet7(msg):
    """Bet7 game - exactly as original"""
    u = msg["user"]
    data = read_json_file('dice_rolls.json')
    player1 = u
    
    if "player2" in data:
        if data["player2"] == u:
            return f"{u} you already joined the game, please wait for another player to join"
        else:
            player2 = data["player2"]
            # Roll the dice for both players
            roll1 = roll_dice2({"user": player1, "message": ""})
            roll2 = roll_dice2({"user": player2, "message": ""})
            # Extract the sum of the dice rolls from the returned response
            sum1 = int(roll1[0].split(" ")[-1])
            sum2 = int(roll2[0].split(" ")[-1])
            
            # Determine the winner and return the result
            if sum1 < sum2:
                result = f"{player1} wins with a roll of {sum1}! {player2} rolled {sum2}."
                winner = player1
                winner_score = sum1
                loser_score = sum2
            elif sum2 < sum1:
                result = f"{player2} wins with a roll of {sum2}! {player1} rolled {sum1}."
                winner = player2
                winner_score = sum2
                loser_score = sum1
            else:
                result = f"It's a tie! Both players rolled {sum1}."
                winner = None
                winner_score = sum1
                loser_score = sum2
            
            # Clear out the players from the file
            data.pop("player2", None)
            newrecord1 = False
            newrecord2 = False
            
            # Update lowest score and user with lowest score
            if sum1 < data['lowest_score']:
                data['lowest_score'] = sum1
                data['lowest_score_user'] = player1
                newrecord1 = True
            if sum2 < data['lowest_score']:
                data['lowest_score'] = sum2
                data['lowest_score_user'] = player2
                newrecord2 = True
            
            # Update best score for current user
            if player1 not in data['best_scores'] or sum1 < data['best_scores'][player1]:
                data['best_scores'][player1] = sum1
                newrecord1 = True
            if player2 not in data['best_scores'] or sum2 < data['best_scores'][player2]:
                data['best_scores'][player2] = sum2
                newrecord2 = True
            
            # Update scores
            if 'scores' not in data:
                data['scores'] = {}
            if player1 not in data['scores']:
                data['scores'][player1] = 0
            if player2 not in data['scores']:
                data['scores'][player2] = 0
            
            # Winner gets points, loser loses points
            if winner:
                if winner == player1:
                    data['scores'][player1] += 10
                    data['scores'][player2] -= 5
                else:
                    data['scores'][player2] += 10
                    data['scores'][player1] -= 5
            
            # Write updated data to JSON file
            write_json_file('dice_rolls.json', data)
            
            if newrecord1:
                result += " omg " + player1 + " broke the record!!"
            if newrecord2:
                result += " omg " + player2 + " broke the record!!"
            
            return result
    else:
        # First player joining
        data["player2"] = u
        write_json_file('dice_rolls.json', data)
        return f"{u} joined the game! Waiting for another player to !bet7"

@command(
    pattern=r'bet7\.top$',
    description="Show bet7 money leaderboard",
    category="games"
)
def bet7top(msg):
    """Show bet7 money leaderboard"""
    data = read_json_file('dice_rolls.json')
    all_money = data.get('scores', {})
    
    if not all_money:
        return "No bet7 scores yet!"
    
    top_score_list = []
    scores = []
    
    for user in all_money:
        top_score_list.append((user, all_money[user]))
    
    top_score_list.sort(key=lambda x: x[1], reverse=True)
    
    for name, score in top_score_list[:10]:  # Top 10
        if score < 0:
            scores.append("{} : -£{}".format(fix_nick(name), abs(score)))
        else:
            scores.append("{} : £{}".format(fix_nick(name), score))
    
    return scores

@command(
    pattern=r'topscores$',
    description="Show bet7 best dice scores",
    category="games"
)
def top_scores(msg):
    """Show best dice roll scores"""
    data = read_json_file('dice_rolls.json')
    best_scores = data.get('best_scores', {})
    
    if not best_scores:
        return "No best scores yet!"
    
    top_score_list = []
    scores = []
    
    for user in best_scores:
        top_score_list.append((user, best_scores[user]))
    
    top_score_list.sort(key=lambda x: x[1])  # Lower is better
    
    for name, score in top_score_list[:10]:  # Top 10
        scores.append("{} : {}".format(fix_nick(name), score))
    
    return scores

@command(
    pattern=r'bet7\.owned$',
    description="Show your bet7 score",
    category="games"
)
def get_user_score(msg):
    """Get user's bet7 score"""
    user = msg["user"]
    data = read_json_file('dice_rolls.json')
    
    money_score = data.get('scores', {}).get(user, 0)
    best_score = data.get('best_scores', {}).get(user, "N/A")
    
    if money_score < 0:
        money_str = f"-£{abs(money_score)}"
    else:
        money_str = f"£{money_score}"
    
    return f"{user}: {money_str} | Best roll: {best_score}"

# Global game state for word scramble
scramble_games = {}

def calculate_scramble_score(time_taken):
    """Calculate scramble score based on time taken.
    Max 100 points for instant solve, down to 0 for 100+ seconds"""
    if time_taken >= 100:
        return 0
    return max(0, 100 - int(time_taken))

def get_network_from_msg(msg):
    """Get network name from message context"""
    # Try to get network from message context first
    if 'network' in msg:
        return msg['network']
    
    # Fallback: Try to determine network from bot instance or command prefix
    # This requires the bot or plugin manager to provide network context
    if hasattr(msg, 'bot') and hasattr(msg.bot, 'network'):
        return msg.bot.network
    
    # Last fallback: get from plugin manager context if available
    import inspect
    frame = inspect.currentframe()
    try:
        # Look for plugin_manager in calling context
        while frame:
            if 'plugin_manager' in frame.f_locals:
                pm = frame.f_locals['plugin_manager']
                if hasattr(pm, 'network'):
                    return pm.network
            frame = frame.f_back
    finally:
        del frame
    
    # Ultimate fallback: return None to indicate unknown network
    return None

def get_command_prefix(msg):
    """Get command prefix for the current network context"""
    # Try to get from message context
    if 'command_prefix' in msg:
        return msg['command_prefix']
    
    # Try to get from bot configuration
    if hasattr(msg, 'bot') and hasattr(msg.bot, 'config'):
        return msg.bot.config.COMMAND_PREFIX
    
    # Try to determine from message content as fallback
    message = msg.get("message", "")
    if message:
        for prefix in ['!', '~', '?', '.', ',', '>', '<']:
            if message.startswith(prefix):
                return prefix
    
    # Ultimate fallback
    return '!'

def get_random_word():
    """Get a random word from API with fallback to hardcoded words"""
    # Fallback words in case API fails
    fallback_words = [
        "python", "computer", "internet", "programming", "discord", "twitch", "github", 
        "database", "function", "variable", "algorithm", "keyboard", "monitor", "software",
        "server", "client", "socket", "thread", "process", "memory", "buffer", "parser",
        "compiler", "debugger", "network", "protocol", "packet", "router", "switch",
        "firewall", "tunnel", "bridge", "gateway", "proxy", "cache", "cookie", "session"
    ]
    
    try:
        # Try different word lengths (5-8 letters)
        word_length = random.choice([5, 6, 7, 8])
        
        # Use Datamuse API with spelling pattern for exact length
        pattern = "?" * word_length  # ????? for 5 letters, etc.
        url = f"https://api.datamuse.com/words?sp={pattern}&max=500"
        
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            words_data = response.json()
            if words_data:
                # Filter for common words (those with high frequency scores tend to be more common)
                valid_words = [w['word'] for w in words_data if w['word'].isalpha()]
                if valid_words:
                    word = random.choice(valid_words).lower()
                    logger.info(f"Got word from API: {word} ({len(word)} letters)")
                    return word
        
        # If API fails, use fallback
        logger.warning("API failed, using fallback word list")
        return random.choice(fallback_words).lower()
        
    except Exception as e:
        logger.error(f"Error getting word from API: {e}")
        return random.choice(fallback_words).lower()

@command(
    pattern=r'scramble$',
    description="Word scramble game - guess the unscrambled word",
    category="games"
)
def scramble_start(msg):
    """Start a word scramble game"""
    channel = msg.get("channel", msg.get("target", ""))
    if not channel:
        return "Error: Could not determine channel"
    
    # Get random word from API
    word = get_random_word()
    
    # Make sure word is scrambled differently than original
    max_attempts = 10
    attempts = 0
    while attempts < max_attempts:
        jumbled = ''.join(random.sample(word, len(word)))
        if jumbled.lower() != word.lower():
            break
        attempts += 1
    
    # If we couldn't scramble it differently, just use the original (rare edge case)
    if jumbled.lower() == word.lower():
        jumbled = word[::-1]  # Reverse as last resort
    
    # Store the game state with timestamp and network
    scramble_games[channel] = {
        'word': word,
        'jumbled': jumbled,
        'starter': msg['user'],
        'start_time': time.time(),
        'network': get_network_from_msg(msg)  # Store network when game starts
    }
    
    return f"🔤 Word Scramble: Unscramble this word: {jumbled.upper()}"

@command(
    pattern=r'scramble\.end$',
    description="End the current word scramble game",
    category="games"
)
def scramble_end(msg):
    """End the current scramble game"""
    channel = msg.get("channel", msg.get("target", ""))
    if not channel:
        return "Error: Could not determine channel"
    
    if channel not in scramble_games:
        return "No active scramble game in this channel"
    
    game = scramble_games[channel]
    word = game['word']
    del scramble_games[channel]
    
    return f"🔤 Game ended! The word was: {word.upper()}"

@command(
    pattern=r'scramble\.top$',
    description="Show scramble game leaderboard",
    category="games"
)
def scramble_leaderboard(msg):
    """Show scramble game leaderboard"""
    try:
        network = get_network_from_msg(msg)
        db = BotDatabase(f"{network}_bot.db")
        leaderboard = db.get_leaderboard("scramble", 10)
        
        if not leaderboard:
            prefix = get_command_prefix(msg)
            return f"No scramble scores yet! Play {prefix}scramble to get on the board"
        
        scores = []
        for i, entry in enumerate(leaderboard, 1):
            user = fix_nick(entry['user'])
            score = entry['score']
            games = entry['games_played']
            scores.append(f"{i}. {user}: {score} pts ({games} games)")
        
        return ["🏆 Scramble Leaderboard:"] + scores
        
    except Exception as e:
        logger.error(f"Error getting scramble leaderboard: {e}")
        return "Error getting scramble leaderboard"

@command(
    pattern=r'scramble\.stats$',
    description="Show your scramble game stats",
    category="games"
)
def scramble_stats(msg):
    """Show user's scramble stats"""
    try:
        network = get_network_from_msg(msg)
        db = BotDatabase(f"{network}_bot.db")
        stats = db.get_scramble_stats(msg['user'])
        
        if stats['games_played'] == 0:
            return f"{msg['user']}: No scramble games played yet"
        
        total = stats['total_score']
        best = stats['best_score']
        games = stats['games_played']
        avg_score = stats['average_score']
        avg_time = stats['average_time']
        
        return f"{msg['user']}: {total} total pts | Best: {best} pts | Games: {games} | Avg: {avg_score:.1f} pts | Avg time: {avg_time:.1f}s"
        
    except Exception as e:
        logger.error(f"Error getting scramble stats: {e}")
        return "Error getting scramble stats"

def cleanup_expired_scramble_games(bot=None):
    """Periodic cleanup of expired scramble games - returns messages to send"""
    messages_to_send = []
    channels_to_clean = []
    
    # Check all active games
    for channel, game in scramble_games.items():
        if time.time() - game['start_time'] > 120:  # 120 seconds = 2 minutes
            correct_word = game['word']
            channels_to_clean.append(channel)
            messages_to_send.append({
                'channel': channel,
                'message': f"⏰ Time's up! The word was '{correct_word.upper()}' - Nobody guessed it!"
            })
    
    # Clean up expired games
    for channel in channels_to_clean:
        del scramble_games[channel]
    
    return messages_to_send

def check_scramble_answer(msg, bot=None):
    """Message handler to check for scramble answers"""
    channel = msg.get("channel", msg.get("target", ""))
    if not channel or channel not in scramble_games:
        return None  # No active game
    
    game = scramble_games[channel]
    
    message_text = msg.get('message', '').strip()
    
    # Ignore commands (starting with ! or ~)
    if message_text.startswith('!') or message_text.startswith('~'):
        return None
    
    user_guess = message_text.lower()
    correct_word = game['word']
    
    # Check if the guess matches the word
    if user_guess == correct_word:
        # Calculate score based on time taken
        time_taken = time.time() - game['start_time']
        score = calculate_scramble_score(time_taken)
        
        # Update database with the win
        try:
            network = game['network']  # Use network stored when game started
            db = BotDatabase(f"{network}_bot.db")
            
            # Save detailed result
            channel = msg.get("channel", msg.get("target", ""))
            db.save_scramble_result(msg['user'], correct_word, time_taken, score, channel)
            
            # Update user scores (total and best single game)
            db.update_user_score(msg['user'], score, "scramble")
            
            logger.info(f"Updated scramble score for {msg['user']}: +{score} points ({time_taken:.1f}s)")
        except Exception as e:
            logger.error(f"Failed to update scramble score: {e}")
        
        del scramble_games[channel]  # End the game
        
        if score > 0:
            return f"🎉 {msg['user']} got it! The word was '{correct_word.upper()}' - {score} points ({time_taken:.1f}s)!"
        else:
            return f"🎉 {msg['user']} got it! The word was '{correct_word.upper()}' - No points (too slow, but well done!)"
    
    return None  # Not a correct answer, don't respond

@command(
    pattern=r'stats$',
    description="Show bot statistics",
    category="info"
)
def get_stats(msg):
    """Get bot statistics - exactly as original"""
    try:
        data = read_json_file('dice_rolls.json')
        total_rolls = data.get('total_rolls', 0)
        lowest_score = data.get('lowest_score', 42)
        lowest_score_user = data.get('lowest_score_user', 'Nobody')
        
        message = f"Total rolls: {total_rolls} Best roll: {lowest_score_user} with {lowest_score}"
        return message
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return "Stats unavailable"

@command(
    pattern=r'chk$',
    description="Check elapsed time (placeholder)",
    category="utility"
)
def elapsed_time(msg):
    """Elapsed time check"""
    return "⏰ Elapsed time check: Feature coming soon"

@command(
    pattern=r'rds',
    description="RDS status check (placeholder)",
    category="utility"
)
def rds(msg):
    """RDS status"""
    return "📡 RDS status: Feature coming soon"

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    # Register commands
    auto_register_commands(plugin_manager, sys.modules[__name__])
    
    # Register message handler for scramble game
    plugin_manager.register_message_handler(check_scramble_answer)
    
    # Store cleanup function reference for bot to call periodically
    plugin_manager.cleanup_expired_scramble_games = cleanup_expired_scramble_games

"""Game commands for the IRC bot including bet7 and dice rolling"""

import random
import json
import logging
import os
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

@command(
    pattern=r'ginger$',
    description="Word jumble game",
    category="games"
)
def jumble(msg):
    """Simple word jumble"""
    words = ["python", "computer", "internet", "programming", "discord", "twitch", "github"]
    word = random.choice(words)
    jumbled = ''.join(random.sample(word, len(word)))
    return f"Unscramble this word: {jumbled}"

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
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
    logger.info("Game commands plugin loaded")
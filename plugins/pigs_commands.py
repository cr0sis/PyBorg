"""
Pass the Pigs game plugin for PyBorg
Simplified working version based on PyBorg implementation
"""

import asyncio
import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from core.plugin_system import command
from core.database import BotDatabase
import logging

logger = logging.getLogger(__name__)

# Game state management
active_games = {}
join_timers = {}

class PigsGame:
    """Pass the Pigs game logic - simplified working version"""
    
    # Scoring positions
    POSITIONS = {
        'side': 0,          # Lying on side (no dots visible)
        'razorback': 5,     # Lying on back (dots up)
        'trotter': 5,       # Standing upright
        'snouter': 10,      # On snout and front legs
        'leaning_jowler': 15 # On snout, front leg and ear
    }
    
    # Double positions (same position on both pigs)
    DOUBLE_MULTIPLIER = 4  # Individual score * 4
    
    def __init__(self, channel: str):
        self.channel = channel
        self.players = []
        self.scores = {}
        self.current_player_idx = 0
        self.turn_score = 0
        self.game_started = False
        self.target_score = 100
        self.created_at = datetime.now()
        
    def add_player(self, player: str) -> bool:
        """Add player to game if not already joined"""
        if player not in self.players:
            self.players.append(player)
            self.scores[player] = 0
            return True
        return False
    
    def get_current_player(self) -> Optional[str]:
        """Get current player's name"""
        if not self.players or not self.game_started:
            return None
        return self.players[self.current_player_idx]
    
    def next_player(self):
        """Move to next player"""
        self.current_player_idx = (self.current_player_idx + 1) % len(self.players)
        self.turn_score = 0
    
    def roll_pigs(self) -> Tuple[str, str, int, str]:
        """
        Roll the pigs and return position names, score, and result message
        Returns: (pig1_position, pig2_position, score, result_message)
        """
        # Weighted random positions - adjusted for better game balance
        position_weights = {
            'side': 45,           # More common to increase pig out risk
            'razorback': 25,      # Common  
            'trotter': 15,        # Less common
            'snouter': 10,        # Rare
            'leaning_jowler': 5   # Very rare
        }
        
        def weighted_choice():
            total = sum(position_weights.values())
            r = random.randint(1, total)
            cumulative = 0
            for position, weight in position_weights.items():
                cumulative += weight
                if r <= cumulative:
                    return position
            return 'side'  # fallback
        
        pig1 = weighted_choice()
        pig2 = weighted_choice()
        
        # Check for special conditions first
        if pig1 == 'side' and pig2 == 'side':
            # Check for Oinker first (rare - 1 in 200 chance when both on side)
            if random.randint(1, 200) == 1:
                return pig1, pig2, -999, "\x0304💀 OINKER!\x03 You lose ALL your points! Game over!"
            # Otherwise it's always a pig out when both are on sides
            return pig1, pig2, 0, "\x0304💥 PIG OUT!\x03 Both pigs on opposite sides! Turn score lost!"
        
        # Check for Piggy Back (1 in 500 chance) - instant elimination
        if random.randint(1, 500) == 1:
            return pig1, pig2, -1000, "\x0304🔄 PIGGY BACK!\x03 One pig landed on the other! You're eliminated!"
        
        # Normal scoring
        if pig1 == pig2 and pig1 != 'side':
            # Double position - multiply by 4
            score = self.POSITIONS[pig1] * self.DOUBLE_MULTIPLIER
            result = f"\x0309✨ DOUBLE {pig1.upper().replace('_', ' ')}!\x03 +{score} points"
        else:
            # Different positions or one/both on side
            score = self.POSITIONS[pig1] + self.POSITIONS[pig2]
            positions = []
            if self.POSITIONS[pig1] > 0:
                positions.append(pig1.replace('_', ' '))
            if self.POSITIONS[pig2] > 0:
                positions.append(pig2.replace('_', ' '))
            result = f"\x0309🎯 {' + '.join(positions)}\x03 = +{score} points"
        
        return pig1, pig2, score, result
    
    def add_turn_score(self, score: int) -> bool:
        """Add score to current turn. Returns False if game should end"""
        if score == -999:  # Oinker
            self.scores[self.get_current_player()] = 0
            return False
        elif score == -1000:  # Piggy Back
            # Remove player from game
            current_player = self.get_current_player()
            self.players.remove(current_player)
            del self.scores[current_player]
            if len(self.players) <= 1:
                return False
            # Adjust current player index
            if self.current_player_idx >= len(self.players):
                self.current_player_idx = 0
            return True
        elif score == 0:  # Pig Out
            self.turn_score = 0
            return True
        else:
            self.turn_score += score
            return True
    
    def bank_turn_score(self) -> bool:
        """Bank current turn score and check for win
        
        Returns True if player reaches 100+ points after banking (wins immediately)
        Returns False if player has not yet reached 100 points (game continues)
        """
        current_player = self.get_current_player()
        self.scores[current_player] += self.turn_score
        won = self.scores[current_player] >= self.target_score  # Win at 100+ points
        if not won:
            self.next_player()
        return won
    
    def get_standings(self, final=False) -> str:
        """Get current game standings"""
        if not self.scores:
            return "\x0304⚠️ No game data available\x03"
        
        # Validate scores dictionary structure before processing
        validated_scores = {}
        for key, value in self.scores.items():
            if isinstance(key, str) and isinstance(value, (int, float)):
                validated_scores[key] = int(value)
            else:
                logger.warning(f"Invalid score entry skipped: {key}={value} (types: {type(key)}, {type(value)})")
        
        if not validated_scores:
            return "\x0304⚠️ No valid game data available\x03"
            
        sorted_players = sorted(validated_scores.items(), key=lambda x: x[1], reverse=True)
        header = "\x0302🏆 Final standings:\x03" if final else "\x0302🏆 Current Standings:\x03"
        standings = [header]
        
        for i, (player, score) in enumerate(sorted_players, 1):
            marker = "\x0308👑\x03" if i == 1 else f"{i}."
            current = "" if final else (" ← \x0304CURRENT\x03" if player == self.get_current_player() else "")
            standings.append(f"{marker} {player}: {score} points{current}")
        return "\n".join(standings)
    
    def to_dict(self) -> dict:
        """Serialize game state to dictionary"""
        return {
            'channel': self.channel,
            'players': self.players,
            'scores': self.scores,
            'current_player_idx': self.current_player_idx,
            'turn_score': self.turn_score,
            'game_started': self.game_started,
            'target_score': self.target_score,
            'created_at': self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        """Deserialize game state from dictionary"""
        game = cls(data['channel'])
        game.players = data.get('players', [])
        
        # Validate and clean scores dictionary
        scores = data.get('scores', {})
        cleaned_scores = {}
        for key, value in scores.items():
            if isinstance(key, str) and isinstance(value, (int, float)):
                cleaned_scores[key] = int(value)  # Ensure integer scores
            else:
                logger.warning(f"Invalid score entry: {key}={value} (types: {type(key)}, {type(value)})")
        game.scores = cleaned_scores
        
        game.current_player_idx = data.get('current_player_idx', 0)
        game.turn_score = data.get('turn_score', 0)
        game.game_started = data.get('game_started', False)
        game.target_score = data.get('target_score', 100)
        game.created_at = datetime.fromisoformat(data.get('created_at', datetime.now().isoformat()))
        return game

async def handle_cpu_turn(bot, channel, game, db):
    """Handle CPU player turn with simple AI logic"""
    await asyncio.sleep(2)  # Add delay to make it feel natural
    
    # Simple CPU strategy:
    # - Roll at least once
    # - Bank if turn score >= 20 OR total score + turn score >= 100
    # - Keep rolling if turn score < 15 and total score < 80
    # - Take some risk if behind by more than 30 points
    
    cpu_total = game.scores.get("🤖CPU", 0)
    human_players = [p for p in game.players if p != "🤖CPU"]
    max_human_score = max([game.scores.get(p, 0) for p in human_players]) if human_players else 0
    behind_by = max_human_score - cpu_total
    
    # Decide whether to roll or bank
    should_bank = False
    
    if game.turn_score == 0:
        # Must roll at least once
        should_bank = False
    elif cpu_total + game.turn_score >= 100:
        # Can win by banking
        should_bank = True
    elif game.turn_score >= 25:
        # Conservative: bank high turn scores
        should_bank = True
    elif game.turn_score >= 15 and behind_by < 20:
        # Bank moderate scores when not far behind
        should_bank = True
    elif game.turn_score >= 10 and cpu_total >= 80:
        # Near end game, be more conservative
        should_bank = True
    elif behind_by > 40 and game.turn_score < 20:
        # Take more risks when far behind
        should_bank = False
    else:
        # Default: keep rolling with low turn scores
        should_bank = False
    
    if should_bank and game.turn_score > 0:
        await cpu_bank_points(bot, channel, game, db)
    else:
        await cpu_roll_pigs(bot, channel, game, db)

async def cpu_roll_pigs(bot, channel, game, db):
    """CPU rolls the pigs"""
    await bot.safe_send(channel, f"\x0308🤖 CPU rolls the pigs...\x03")
    await asyncio.sleep(1)
    
    pig1, pig2, score, result = game.roll_pigs()
    
    # Track CPU roll statistics
    cpu_roll_data = {
        'game_score': game.scores.get("🤖CPU", 0),
        'turn_score': 0,
        'won': False,
        'pig_out': False,
        'oinker': False,
        'positions_rolled': [pig1, pig2],
        'rolls_this_turn': 1,
        'banked': False,
        'bank_score': 0,
        'game_duration_seconds': 0,
        'comeback_win': False,
        'close_win': False,
        'was_behind': False,
        'game_ended': False
    }
    
    # ALWAYS update CPU roll statistics
    try:
        db.update_pigs_stats("🤖CPU", cpu_roll_data)
    except Exception as e:
        logger.error(f"Failed to update CPU pigs roll stats: {e}")
    
    # Send result
    await bot.safe_send(channel, f"\x0308🎲 CPU rolled:\x03 {result}")
    
    if score == 0:  # Pig Out
        game.turn_score = 0
        game.next_player()
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         game.get_current_player(), game.turn_score)
        
        # Update CPU pig out statistics
        cpu_roll_data['pig_out'] = True
        cpu_roll_data['turn_score'] = 0  # Turn score lost due to pig out
        try:
            db.update_pigs_stats("🤖CPU", cpu_roll_data)
        except Exception as e:
            logger.error(f"Failed to update CPU pigs pig out stats: {e}")
        
        human_player = game.get_current_player()
        if human_player != "🤖CPU":
            prefix = bot.config.COMMAND_PREFIX
            await bot.send_raw(f"NOTICE {human_player} :\x0302🎯 Your turn!\x03 Type {prefix}pigs to roll!\r\n")
    
    elif score == -999:  # Oinker
        game.scores["🤖CPU"] = 0
        db.delete_pigs_game(channel)
        await bot.safe_send(channel, "\x0304💀 CPU is eliminated! You win!\x03")
        
        # Send final standings
        standings_lines = game.get_standings(final=True).split('\n')
        for line in standings_lines:
            if line.strip():
                await bot.safe_send(channel, line)
    
    elif score == -1000:  # Piggy Back
        game.players.remove("🤖CPU")
        del game.scores["🤖CPU"]
        if len(game.players) <= 1:
            if game.players:
                winner = game.players[0]
                await bot.safe_send(channel, f"\x0309🏆 {winner} wins by CPU elimination!\x03")
            db.delete_pigs_game(channel)
        else:
            if game.current_player_idx >= len(game.players):
                game.current_player_idx = 0
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
    
    else:  # Normal points
        game.add_turn_score(score)
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         game.get_current_player(), game.turn_score)
        
        current_total = game.scores["🤖CPU"] + game.turn_score
        await bot.safe_send(channel, 
            f"\x0309🤖 CPU turn total: {game.turn_score}, potential score: {current_total}\x03")
        
        # Schedule next CPU action after a brief delay
        asyncio.create_task(delayed_cpu_action(bot, channel, game, db))

async def cpu_bank_points(bot, channel, game, db):
    """CPU banks its points"""
    banked_score = game.turn_score
    won = game.bank_turn_score()
    
    if won:
        final_score = game.scores["🤖CPU"]
        await bot.safe_send(channel, 
            f"\x0304🤖 CPU banked {banked_score} points and wins with {final_score} points!\x03")
        
        # Send final standings
        standings_lines = game.get_standings(final=True).split('\n')
        for line in standings_lines:
            if line.strip():
                await bot.safe_send(channel, line)
        
        db.delete_pigs_game(channel)
    else:
        # Track CPU banking statistics
        cpu_bank_data = {
            'game_score': game.scores["🤖CPU"],
            'turn_score': banked_score,
            'won': False,
            'pig_out': False,
            'oinker': False,
            'positions_rolled': [],
            'rolls_this_turn': 0,
            'banked': True,
            'bank_score': banked_score,
            'game_duration_seconds': 0,
            'comeback_win': False,
            'close_win': False,
            'was_behind': False,
            'game_ended': False
        }
        try:
            db.update_pigs_stats("🤖CPU", cpu_bank_data)
        except Exception as e:
            logger.error(f"Failed to update CPU pigs banking stats: {e}")
        
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         game.get_current_player(), game.turn_score)
        await bot.safe_send(channel, 
            f"\x0309🤖 CPU banked {banked_score} points! Total: {game.scores['🤖CPU']} points\x03")
        
        human_player = game.get_current_player()
        if human_player != "🤖CPU":
            prefix = bot.config.COMMAND_PREFIX
            await bot.send_raw(f"NOTICE {human_player} :\x0302🎯 Your turn!\x03 Type {prefix}pigs to roll!\r\n")

async def delayed_cpu_action(bot, channel, game, db):
    """Delay before CPU takes next action"""
    await asyncio.sleep(3)  # Give time to see the result
    
    # Re-fetch game state in case it was modified
    game_data = db.get_pigs_game(channel)
    if game_data:
        try:
            game_state = json.loads(game_data['game_state'])
            current_game = PigsGame.from_dict(game_state)
            if current_game.game_started and current_game.get_current_player() == "🤖CPU":
                await handle_cpu_turn(bot, channel, current_game, db)
        except Exception:
            pass

async def delayed_cpu_start(bot, channel, game, db):
    """Delay before CPU starts its first turn"""
    await asyncio.sleep(2)  # Brief delay after game start
    await handle_cpu_turn(bot, channel, game, db)

@command(
    pattern=r'pigs\b(?:\s+(.*))?',
    description="Play Pass the Pigs dice game - start/join/play",
    category="games",
    requires_bot=True
)
async def pigs_command(msg, bot):
    """Single command for all Pass the Pigs game actions"""
    channel = msg['channel']
    user = msg['user']
    
    # Extract action from message using regex pattern
    import re
    message_text = msg['message']
    match = re.search(r'pigs\b(?:\s+(.*))?', message_text)
    action = match.group(1).strip() if match and match.group(1) is not None else None
    
    db = bot.database
    
    # Check for existing game
    game_data = db.get_pigs_game(channel)
    game = None
    if game_data:
        try:
            game_state = json.loads(game_data['game_state'])
            game = PigsGame.from_dict(game_state)
            logger.debug(f"Loaded game state for {channel}: players={game.players}, turn_score={game.turn_score}, current_player_idx={game.current_player_idx}")
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Corrupted game data for {channel}: {e}")
            # Corrupted game data, delete it
            db.delete_pigs_game(channel)
            game = None
    
    # No existing game - start a new one
    if not game:
        game = PigsGame(channel)
        game.add_player(user)
        timer_start = datetime.now()
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         None, 0, timer_start)
        
        prefix = bot.config.COMMAND_PREFIX
        await bot.safe_send(channel, 
            f"\x0309🎲 {user} started a Pass the Pigs game!\x03 "
            f"Type {prefix}pigs to join! Game starts in 30 seconds...")
        
        # Set up timer to auto-start game
        async def auto_start_game():
            await asyncio.sleep(30)
            game_data = db.get_pigs_game(channel)
            if game_data:
                try:
                    game_state = json.loads(game_data['game_state'])
                    current_game = PigsGame.from_dict(game_state)
                    if not current_game.game_started:
                        if len(current_game.players) >= 2:
                            current_game.game_started = True
                            db.save_pigs_game(channel, json.dumps(current_game.to_dict()), 
                                            current_game.get_current_player(), current_game.turn_score)
                            await bot.safe_send(channel, 
                                f"\x0309🎮 Game started!\x03 {current_game.get_current_player()}'s turn!")
                        elif len(current_game.players) == 1:
                            # Add CPU player and start game
                            current_game.add_player("🤖CPU")
                            current_game.game_started = True
                            db.save_pigs_game(channel, json.dumps(current_game.to_dict()), 
                                            current_game.get_current_player(), current_game.turn_score)
                            
                            first_player = current_game.get_current_player()
                            await bot.safe_send(channel, 
                                f"\x0309🎮 Game started against CPU!\x03 {first_player}'s turn!")
                            
                            # If CPU goes first, start its turn
                            if first_player == "🤖CPU":
                                asyncio.create_task(delayed_cpu_start(bot, channel, current_game, db))
                        else:
                            db.delete_pigs_game(channel)
                            await bot.safe_send(channel, "\x0304😞 Not enough players. Game cancelled!\x03")
                except Exception:
                    pass
        
        asyncio.create_task(auto_start_game())
        return
    
    # Game exists - handle different scenarios
    if not game.game_started:
        # Still in join phase
        if user not in game.players:
            if game.add_player(user):
                db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                                 game.get_current_player(), game.turn_score)
                await bot.safe_send(channel, 
                    f"\x0309👋 {user} joined!\x03 Players: {', '.join(game.players)}")
            else:
                await bot.safe_send(channel, f"\x0304❌ {user}, you're already in the game!\x03")
        else:
            await bot.safe_send(channel, f"\x0308⏳ {user}, waiting for more players or game to start...\x03")
        return
    
    # Game is active
    current_player = game.get_current_player()
    
    # Handle special actions
    if action and action.lower() in ['quit', 'leave', 'end']:
        if user == current_player or len(game.players) <= 2:
            # End the game
            db.delete_pigs_game(channel)
            await bot.safe_send(channel, f"\x0304🐷 Pass the Pigs game ended by {user}.\x03")
            return
    
    
    # Handle CPU turn
    if current_player == "🤖CPU":
        await handle_cpu_turn(bot, channel, game, db)
        return
    
    # Game actions for current player only
    if user != current_player:
        await bot.safe_send(channel, 
            f"\x0308⏳ It's {current_player}'s turn! Wait your turn, {user}.\x03")
        return
    
    # Remove bank action from pigs command - now handled by separate !bank command
    if action and action.lower() in ['bank', 'stop', 'pass']:
        prefix = bot.config.COMMAND_PREFIX
        await bot.safe_send(channel, 
            f"\x0308💡 Use {prefix}bank to bank your points!\x03")
        return
    
    # Rolling the pigs (default action)
    try:
        roll_result = game.roll_pigs()
        if len(roll_result) != 4:
            logger.error(f"roll_pigs returned {len(roll_result)} values instead of 4: {roll_result}")
            await bot.safe_send(channel, "\x0304❌ Game error occurred\x03")
            return
        pig1, pig2, score, result = roll_result
        logger.debug(f"Roll result for {user}: pig1={pig1}, pig2={pig2}, score={score}")
    except Exception as e:
        logger.error(f"Error in roll_pigs: {e}")
        await bot.safe_send(channel, "\x0304❌ Game error occurred\x03")
        return
    
    # Prepare roll data (will be updated based on outcome)
    roll_data = {
        'game_score': game.scores.get(user, 0),
        'turn_score': 0,  # Will be updated for special cases
        'won': False,
        'pig_out': False,
        'oinker': False,
        'positions_rolled': [pig1, pig2],
        'rolls_this_turn': 1,  # This single roll
        'banked': False,
        'bank_score': 0,
        'game_duration_seconds': 0,
        'comeback_win': False,
        'close_win': False,
        'was_behind': False,
        'game_ended': False
    }
    
    # ALWAYS update roll statistics for every roll attempt
    try:
        db.update_pigs_stats(user, roll_data)
    except Exception as e:
        logger.error(f"Failed to update pigs roll stats: {e}")
        # Don't fail the game for stats errors
    
    # Send roll result - use channel for dramatic events, NOTICE for normal rolls
    if score in [0, -999, -1000]:  # Pig Out, Oinker, or Piggy Back - make these public
        await bot.safe_send(channel, f"\x0308🎲 {user} rolled:\x03 {result}")
    else:  # Normal rolls - keep private
        await bot.send_raw(f"NOTICE {user} :\x0308🎲 You rolled:\x03 {result}\r\n")
    
    # Handle special results
    if score == 0:  # Pig Out
        # Reset turn score and advance to next player
        game.turn_score = 0
        game.next_player()
        
        # Save game state immediately after pig out
        try:
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
        except Exception as e:
            logger.error(f"Failed to save game state after pig out: {e}")
            await bot.safe_send(channel, "\x0304⚠️ Game state save error after pig out\x03")
            return
        
        # Update pig out specific statistics
        roll_data['pig_out'] = True
        roll_data['turn_score'] = game.turn_score  # Save turn score before reset
        try:
            db.update_pigs_stats(user, roll_data)
        except Exception as e:
            logger.error(f"Failed to update pigs pig out stats: {e}")
        
        # Check if it's now CPU's turn
        current_player = game.get_current_player()
        if current_player == "🤖CPU":
            asyncio.create_task(delayed_cpu_start(bot, channel, game, db))
        else:
            prefix = bot.config.COMMAND_PREFIX
            await bot.send_raw(f"NOTICE {current_player} :\x0302🎯 Your turn!\x03 Type {prefix}pigs to roll!\r\n")
        
    elif score == -999:  # Oinker
        game.scores[user] = 0
        
        # Update roll data for oinker
        roll_data['oinker'] = True
        roll_data['game_score'] = 0
        roll_data['game_ended'] = True
        db.update_pigs_stats(user, roll_data)
        
        # Update stats for other players (game incomplete)
        for player in game.players:
            if player != user:
                player_data = {
                    'game_score': game.scores[player],
                    'turn_score': 0,
                    'won': False,
                    'pig_out': False,
                    'oinker': False,
                    'positions_rolled': [],
                    'rolls_this_turn': 0,
                    'banked': False,
                    'bank_score': 0,
                    'game_duration_seconds': 0,
                    'comeback_win': False,
                    'close_win': False,
                    'was_behind': False,
                    'game_ended': True  # Game ended due to oinker
                }
                db.update_pigs_stats(player, player_data)
        
        # Increment total games counter
        current_total = int(db.get_stat('pigs_total_games', 0))
        db.set_stat('pigs_total_games', current_total + 1)
        
        db.delete_pigs_game(channel)
        await bot.safe_send(channel, 
            f"\x0304💀 {user} is eliminated!\x03 Game over!")
        
        # Send final standings line by line
        standings_lines = game.get_standings(final=True).split('\n')
        for line in standings_lines:
            if line.strip():  # Skip empty lines
                await bot.safe_send(channel, line)
        
    elif score == -1000:  # Piggy Back
        game.players.remove(user)
        del game.scores[user]
        if len(game.players) <= 1:
            if game.players:
                winner = game.players[0]
                
                # Update winner stats for elimination win
                winner_data = {
                    'game_score': game.scores[winner],
                    'turn_score': 0,
                    'won': True,
                    'pig_out': False,
                    'oinker': False,
                    'positions_rolled': [],
                    'rolls_this_turn': 0,
                    'banked': False,
                    'bank_score': 0,
                    'game_duration_seconds': 0,
                    'comeback_win': False,
                    'close_win': False,
                    'was_behind': False
                }
                db.update_pigs_stats(winner, winner_data)
                
                # Update stats for eliminated player
                eliminated_data = {
                    'game_score': 0,  # They were eliminated
                    'turn_score': 0,
                    'won': False,
                    'pig_out': False,
                    'oinker': False,
                    'positions_rolled': [],
                    'rolls_this_turn': 0,
                    'banked': False,
                    'bank_score': 0,
                    'game_duration_seconds': 0,
                    'comeback_win': False,
                    'close_win': False,
                    'was_behind': False,
                    'game_ended': True  # Game ended due to elimination
                }
                db.update_pigs_stats(user, eliminated_data)
                
                # Increment total games counter
                current_total = int(db.get_stat('pigs_total_games', 0))
                db.set_stat('pigs_total_games', current_total + 1)
                
                await bot.safe_send(channel, 
                    f"\x0309🏆 {winner} wins by elimination!\x03")
            
            # Delete game from database with better error handling
            try:
                db.delete_pigs_game(channel)
            except Exception as e:
                logger.error(f"Failed to delete pigs game for {channel}: {e}")
                # Don't re-raise - game is over, just log the error
        else:
            if game.current_player_idx >= len(game.players):
                game.current_player_idx = 0
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
            
            # Check if it's now CPU's turn
            current_player = game.get_current_player()
            if current_player == "🤖CPU":
                asyncio.create_task(delayed_cpu_start(bot, channel, game, db))
            else:
                prefix = bot.config.COMMAND_PREFIX
                await bot.safe_send(channel, 
                    f"\x0302🎯 {current_player}'s turn!\x03 Type {prefix}pigs to roll!")
        
    else:  # Normal points
        game.add_turn_score(score)
        
        # Track the normal roll
        roll_data['turn_score'] = score
        
        # Save game state immediately after updating turn score
        try:
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
        except Exception as e:
            logger.error(f"Failed to save game state after roll: {e}")
            await bot.safe_send(channel, "\x0304⚠️ Game state save error - please try again\x03")
            return
        
        # Roll stats already updated above, no need for duplicate call
        
        current_total = game.scores[user] + game.turn_score
        prefix = bot.config.COMMAND_PREFIX
        await bot.send_raw(f"NOTICE {user} :\x0309💫 Turn total: {game.turn_score}\x03 | "
                           f"\x0302Potential score: {current_total}\x03 | "
                           f"Type {prefix}pigs to roll again or {prefix}bank to bank points!\r\n")

@command(
    pattern=r'bank',
    description="Bank your points in Pass the Pigs game",
    category="games",
    requires_bot=True
)
async def bank_pigs_command(msg, bot):
    """Bank points during Pass the Pigs game"""
    channel = msg['channel']
    user = msg['user']
    
    db = bot.database
    
    # Check for existing game
    game_data = db.get_pigs_game(channel)
    if not game_data:
        await bot.safe_send(channel, "\x0308❌ No Pass the Pigs game is currently active!\x03")
        return
    
    try:
        game_state = json.loads(game_data['game_state'])
        game = PigsGame.from_dict(game_state)
        
        if not game.game_started:
            await bot.safe_send(channel, "\x0308⏳ Game hasn't started yet!\x03")
            return
        
        current_player = game.get_current_player()
        if user != current_player:
            await bot.safe_send(channel, 
                f"\x0308⏳ It's {current_player}'s turn! Wait your turn, {user}.\x03")
            return
        
        if game.turn_score == 0:
            await bot.safe_send(channel, 
                "\x0308💡 You need to roll first before banking!\x03")
            return
        
        # Bank the points
        banked_score = game.turn_score
        won = game.bank_turn_score()
        
        if won:
            # Player won! Update database stats
            final_score = game.scores[user]
            
            # Determine if this was a comeback or close win
            other_scores = [item[1] for item in game.scores.items() if item[0] != user]
            max_other_score = max(other_scores) if other_scores else 0
            was_behind = any(score > final_score - banked_score for score in other_scores)
            close_win = (final_score - max_other_score) < 10
            
            # Update winner stats
            game_data = {
                'game_score': final_score,
                'turn_score': banked_score,
                'won': True,
                'pig_out': False,
                'oinker': False,
                'positions_rolled': [],
                'rolls_this_turn': 0,
                'banked': True,
                'bank_score': banked_score,
                'game_duration_seconds': 0,  # Could calculate if needed
                'comeback_win': was_behind,
                'close_win': close_win,
                'was_behind': was_behind
            }
            db.update_pigs_stats(user, game_data)
            
            # Update stats for other players (losses)
            for player in game.players:
                if player != user:
                    player_data = {
                        'game_score': game.scores[player],
                        'turn_score': 0,
                        'won': False,
                        'pig_out': False,
                        'oinker': False,
                        'positions_rolled': [],
                        'rolls_this_turn': 0,
                        'banked': False,
                        'bank_score': 0,
                        'game_duration_seconds': 0,
                        'comeback_win': False,
                        'close_win': False,
                        'was_behind': False,
                        'game_ended': True  # Game ended, player lost
                    }
                    db.update_pigs_stats(player, player_data)
            
            # Increment total games counter
            current_total = int(db.get_stat('pigs_total_games', 0))
            db.set_stat('pigs_total_games', current_total + 1)
            
            await bot.safe_send(channel, 
                f"\x0309🏆 {user} banked {banked_score} points and wins with {final_score} points!\x03")
            
            # Send final standings line by line
            standings_lines = game.get_standings(final=True).split('\n')
            for line in standings_lines:
                if line.strip():  # Skip empty lines
                    await bot.safe_send(channel, line)
            
            # Delete game from database with better error handling
            try:
                db.delete_pigs_game(channel)
            except Exception as e:
                logger.error(f"Failed to delete pigs game for {channel}: {e}")
                # Don't re-raise - game is over, just log the error
        else:
            # Game continues - track banking statistics - DON'T COUNT AS ROLL
            bank_data = {
                'game_score': game.scores[user],
                'turn_score': banked_score,
                'won': False,
                'pig_out': False,
                'oinker': False,
                'positions_rolled': [],
                'rolls_this_turn': 0,  # Banking doesn't count as a roll
                'banked': True,
                'bank_score': banked_score,
                'game_duration_seconds': 0,
                'comeback_win': False,
                'close_win': False,
                'was_behind': False,
                'game_ended': False
            }
            try:
                db.update_pigs_stats(user, bank_data)
            except Exception as e:
                logger.error(f"Failed to update pigs banking stats for {user}: {e}")
            
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
            await bot.safe_send(channel, 
                f"\x0309💰 {user} banked {banked_score} points!\x03 Total: {game.scores[user]} points")
            
            # Check if it's now CPU's turn
            current_player = game.get_current_player()
            if current_player == "🤖CPU":
                asyncio.create_task(delayed_cpu_start(bot, channel, game, db))
            else:
                prefix = bot.config.COMMAND_PREFIX
                await bot.send_raw(f"NOTICE {current_player} :\x0302🎯 Your turn!\x03 Type {prefix}pigs to roll!\r\n")
    
    except (json.JSONDecodeError, KeyError):
        await bot.safe_send(channel, "\x0304❌ Game data corrupted. Please start a new game.\x03")
        db.delete_pigs_game(channel)

@command(
    pattern=r'pigsquit',
    description="Quit the current Pass the Pigs game",
    category="games",
    requires_bot=True
)
async def pigsquit_command(msg, bot):
    """Quit the current Pass the Pigs game"""
    channel = msg['channel']
    user = msg['user']
    
    db = bot.database
    
    game_data = db.get_pigs_game(channel)
    if not game_data:
        await bot.safe_send(channel, "\x0308❌ No Pass the Pigs game is currently active!\x03")
        return
    
    db.delete_pigs_game(channel)
    await bot.safe_send(channel, f"\x0304🐷 Pass the Pigs game ended by {user}.\x03")

@command(
    pattern=r'pigshelp',
    description="Show Pass the Pigs game rules and commands",
    category="games",
    requires_bot=True
)
async def pigshelp_command(msg, bot):
    """Show detailed Pass the Pigs help"""
    channel = msg['channel']
    user = msg['user']
    prefix = bot.config.COMMAND_PREFIX
    
    # Send condensed help via NOTICE to avoid rate limiting
    help_text = [
        "\x0302🐷 Pass the Pigs:\x03 First to 100 points wins! \x0302Scoring:\x03 Side=0, Razorback/Trotter=5, Snouter=10, Leaning Jowler=15, Doubles=4x",
        "\x0302⚠️ Events:\x03 Pig Out (opposite sides)=lose turn, Oinker (rare)=lose all points, Piggy Back (super rare)=eliminated",
        f"\x0302🎮 Commands:\x03 {prefix}pigs (start/join/roll), {prefix}bank (bank points), {prefix}pigs status, {prefix}pigsquit, {prefix}pigstats"
    ]
    
    for line in help_text:
        await bot.send_raw(f"NOTICE {user} :{line}\r\n")

@command(
    pattern=r'pigstats(?:\s+(.*))?',
    description="View Pass the Pigs leaderboard or personal statistics",
    category="games",
    requires_bot=True
)
async def pigstats_command(msg, bot):
    """Show Pass the Pigs statistics - leaderboard or personal stats"""
    channel = msg['channel']
    user = msg['user']
    
    # Extract target user from message
    import re
    message_text = msg['message']
    match = re.search(r'pigstats(?:\s+(.*))?', message_text)
    target_user = match.group(1).strip() if match and match.group(1) else None
    
    db = bot.database
    
    if target_user:
        # Show personal stats for specific user
        leaderboard = db.get_pigs_leaderboard(100)  # Get enough to find the user
        user_stats = None
        user_rank = None
        
        for i, player in enumerate(leaderboard, 1):
            if player['user'].lower() == target_user.lower():
                user_stats = player
                user_rank = i
                break
        
        if not user_stats:
            await bot.safe_send(channel, f"\x0308📊 No Pass the Pigs stats found for {target_user}\x03")
            return
        
        # Calculate basic derived stats and send condensed via NOTICE
        win_rate = (user_stats['wins'] / user_stats['games_played'] * 100) if user_stats['games_played'] > 0 else 0
        
        stats_line = f"\x0302🐷 {user_stats['user']}:\x03 Rank #{user_rank}, {user_stats['wins']}/{user_stats['games_played']} wins ({win_rate:.1f}%), Best: {user_stats['highest_game_score']}pts, Pig Outs: {user_stats['pig_outs']}, Rolls: {user_stats['total_rolls']}"
        
        await bot.send_raw(f"NOTICE {user} :{stats_line}\r\n")
    else:
        # Show condensed leaderboard via NOTICE
        leaderboard = db.get_pigs_leaderboard(10)
        if leaderboard:
            # Create condensed leaderboard entries
            entries = []
            for i, player in enumerate(leaderboard, 1):
                win_rate = (player['wins'] / player['games_played'] * 100) if player['games_played'] > 0 else 0
                entries.append(f"{i}. {player['user']} ({player['wins']}W/{win_rate:.0f}%/{player['highest_game_score']}pts)")
            
            # Send in chunks of 3-4 players per line to avoid rate limiting
            header = "\x0302🏆 Pass the Pigs Leaderboard:\x03"
            await bot.send_raw(f"NOTICE {user} :{header}\r\n")
            
            for i in range(0, len(entries), 3):
                chunk = entries[i:i+3]
                line = " | ".join(chunk)
                await bot.send_raw(f"NOTICE {user} :{line}\r\n")
        else:
            await bot.send_raw(f"NOTICE {user} :\x0308📊 No games played yet!\x03\r\n")

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    # Games will now persist across bot restarts - players can resume games
    
    # Auto-register all commands in this module
    auto_register_commands(plugin_manager, sys.modules[__name__])
    

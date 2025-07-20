"""
Pass the Pigs game plugin for PyBorg
Implements the complete Pass the Pigs dice game with official rules
"""

import asyncio
import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from core.plugin_system import command
from core.database import BotDatabase

# Game state management
active_games = {}
join_timers = {}

class PigsGame:
    """Pass the Pigs game logic"""
    
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
        # Weighted random positions based on real pig dice probabilities
        position_weights = {
            'side': 35,           # Most common
            'razorback': 30,      # Common  
            'trotter': 20,        # Less common
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
            # Check if opposite sides (Pig Out) - 50% chance when both on side
            if random.choice([True, False]):
                return pig1, pig2, 0, "🐷💥 **PIG OUT!** Both pigs on opposite sides! Turn score lost!"
        
        # Check for Oinker (extremely rare - 1 in 1000 chance when both on side)
        if pig1 == 'side' and pig2 == 'side' and random.randint(1, 1000) == 1:
            return pig1, pig2, -999, "🐷💀 **OINKER!** You lose ALL your points! Game over!"
        
        # Check for Piggy Back (1 in 2000 chance) - instant elimination
        if random.randint(1, 2000) == 1:
            return pig1, pig2, -1000, "🐷🔄 **PIGGY BACK!** One pig landed on the other! You're eliminated!"
        
        # Normal scoring
        if pig1 == pig2 and pig1 != 'side':
            # Double position - multiply by 4
            score = self.POSITIONS[pig1] * self.DOUBLE_MULTIPLIER
            result = f"🐷✨ **DOUBLE {pig1.upper().replace('_', ' ')}!** +{score} points"
        else:
            # Different positions or one/both on side
            score = self.POSITIONS[pig1] + self.POSITIONS[pig2]
            if score == 0:
                result = f"🐷😐 Both pigs on their sides - no points this roll"
            else:
                positions = []
                if self.POSITIONS[pig1] > 0:
                    positions.append(pig1.replace('_', ' '))
                if self.POSITIONS[pig2] > 0:
                    positions.append(pig2.replace('_', ' '))
                result = f"🐷🎯 {' + '.join(positions)} = +{score} points"
        
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
    
    def get_standings(self) -> str:
        """Get current game standings"""
        sorted_players = sorted(self.scores.items(), key=lambda x: x[1], reverse=True)
        standings = ["🏆 **Current Standings:**"]
        for i, (player, score) in enumerate(sorted_players, 1):
            marker = "👑" if i == 1 else f"{i}."
            current = " ← **CURRENT**" if player == self.get_current_player() else ""
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
        game.players = data['players']
        game.scores = data['scores']
        game.current_player_idx = data['current_player_idx']
        game.turn_score = data['turn_score']
        game.game_started = data['game_started']
        game.target_score = data['target_score']
        game.created_at = datetime.fromisoformat(data['created_at'])
        return game

@command(
    pattern=r'pigs(?:\s+(.*))?',
    description="Play Pass the Pigs dice game - !pigs to start/join/play",
    category="games",
    requires_bot=True
)
async def pigs_command(msg, bot):
    """Single command for all Pass the Pigs game actions"""
    channel = msg['channel']
    user = msg['user']
    args = msg.get('args', [])
    action = args[0] if args else None
    
    db = BotDatabase(f"data/{bot.config.NETWORK}_bot.db")
    
    # Check for existing game
    game_data = db.get_pigs_game(channel)
    game = None
    if game_data:
        try:
            game_state = json.loads(game_data['game_state'])
            game = PigsGame.from_dict(game_state)
            
            # Check if join timer expired (30 seconds)
            if not game.game_started and game_data['join_timer_start']:
                timer_start = datetime.fromisoformat(game_data['join_timer_start'])
                if datetime.now() - timer_start > timedelta(seconds=30):
                    if len(game.players) >= 2:
                        # Start the game
                        game.game_started = True
                        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                                        game.get_current_player(), game.turn_score)
                        await bot.safe_send(channel, 
                            f"🐷🎮 **Pass the Pigs game started!** "
                            f"{game.get_current_player()}'s turn - type `!pigs` to roll!")
                        await bot.safe_send(channel, game.get_standings())
                        return
                    else:
                        # Not enough players, cancel game
                        db.delete_pigs_game(channel)
                        await bot.safe_send(channel, 
                            "🐷😞 Not enough players joined. Game cancelled!")
                        return
        except (json.JSONDecodeError, KeyError) as e:
            # Corrupted game data, delete it
            db.delete_pigs_game(channel)
            game = None
    
    # No existing game - start a new one
    if not game:
        game = PigsGame(channel)
        game.add_player(user)
        
        # Start 30-second join timer
        timer_start = datetime.now()
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         None, 0, timer_start)
        
        await bot.safe_send(channel, 
            f"🐷🎲 **{user} started a Pass the Pigs game!** "
            f"Type `!pigs` to join! Game starts in 30 seconds...")
        await bot.safe_send(channel, 
            "🎯 **Goal:** First to 100 points wins! "
            "🐷 **Rules:** Roll pigs for points, but watch out for Pig Outs and Oinkers!")
        
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
                                f"🐷🎮 **Game started!** {current_game.get_current_player()}'s turn!")
                            await bot.safe_send(channel, current_game.get_standings())
                        else:
                            db.delete_pigs_game(channel)
                            await bot.safe_send(channel, "🐷😞 Not enough players. Game cancelled!")
                except Exception:
                    pass
        
        asyncio.create_task(auto_start_game())
        return
    
    # Game exists - handle different scenarios
    if not game.game_started:
        # Still in join phase
        if user not in game.players:
            if game.add_player(user):
                db.save_pigs_game(channel, json.dumps(game.to_dict()))
                await bot.safe_send(channel, 
                    f"🐷👋 **{user} joined!** Players: {', '.join(game.players)}")
                
                # If second player joined, restart the timer
                if len(game.players) == 2:
                    timer_start = datetime.now()
                    db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                                    None, 0, timer_start)
                    await bot.safe_send(channel, 
                        "🐷⏱️ **Second player joined! Timer reset - 30 seconds for more players...**")
                    
                    # Cancel old timer and start new one
                    async def auto_start_game_reset():
                        await asyncio.sleep(30)
                        game_data = db.get_pigs_game(channel)
                        if game_data:
                            try:
                                game_state = json.loads(game_data['game_state'])
                                current_game = PigsGame.from_dict(game_state)
                                if not current_game.game_started:
                                    current_game.game_started = True
                                    db.save_pigs_game(channel, json.dumps(current_game.to_dict()), 
                                                    current_game.get_current_player(), current_game.turn_score)
                                    await bot.safe_send(channel, 
                                        f"🐷🎮 **Game started!** {current_game.get_current_player()}'s turn!")
                                    await bot.safe_send(channel, current_game.get_standings())
                            except Exception:
                                pass
                    
                    asyncio.create_task(auto_start_game_reset())
            else:
                await bot.safe_send(channel, f"🐷❌ {user}, you're already in the game!")
        else:
            await bot.safe_send(channel, f"🐷⏳ {user}, waiting for more players or game to start...")
        return
    
    # Game is active
    current_player = game.get_current_player()
    
    # Handle special actions
    if action and action.lower() in ['quit', 'leave', 'end']:
        if user == current_player or len(game.players) <= 2:
            # End the game
            db.delete_pigs_game(channel)
            await bot.safe_send(channel, f"🐷👋 **Game ended by {user}!**")
            return
        else:
            await bot.safe_send(channel, f"🐷❌ Only {current_player} or admin can end the game!")
            return
    
    if action and action.lower() in ['standings', 'scores', 'status']:
        await bot.safe_send(channel, game.get_standings())
        if current_player:
            await bot.safe_send(channel, 
                f"🎯 **{current_player}'s turn** | Turn score: {game.turn_score} | "
                f"Type `!pigs` to roll or `!pigs bank` to bank points!")
        return
    
    if action and action.lower() == 'leaderboard':
        leaderboard = db.get_pigs_leaderboard(10)
        if leaderboard:
            lines = ["🏆 **Pass the Pigs Leaderboard:**"]
            for i, player in enumerate(leaderboard, 1):
                lines.append(
                    f"{i}. **{player['user']}** - "
                    f"{player['wins']} wins, {player['highest_game_score']} best game, "
                    f"{player['pig_outs']} pig-outs"
                )
            await bot.safe_send(channel, "\n".join(lines))
        else:
            await bot.safe_send(channel, "🐷📊 No games played yet!")
        return
    
    # Game actions for current player only
    if user != current_player:
        await bot.safe_send(channel, 
            f"🐷⏳ It's {current_player}'s turn! Wait your turn, {user}.")
        return
    
    # Banking points
    if action and action.lower() in ['bank', 'stop', 'pass']:
        if game.turn_score == 0:
            await bot.safe_send(channel, "🐷❌ No points to bank! Roll first.")
            return
        
        won = game.bank_turn_score()
        if won:
            # Game won!
            winner = current_player
            final_score = game.scores[winner]
            
            # Update statistics for all players
            for player in game.players:
                player_score = game.scores[player]
                db.update_pigs_stats(player, player_score, game.turn_score if player == winner else 0, 
                                   won=(player == winner))
            
            db.delete_pigs_game(channel)
            
            await bot.safe_send(channel, 
                f"🐷🏆 **{winner} WINS with {final_score} points!** 🎉")
            await bot.safe_send(channel, game.get_standings())
        else:
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
            await bot.safe_send(channel, 
                f"🐷💰 **{user} banked {game.turn_score} points!** "
                f"Total: {game.scores[user]} points")
            await bot.safe_send(channel, 
                f"🎯 **{game.get_current_player()}'s turn!** Type `!pigs` to roll!")
        return
    
    # Rolling the pigs (default action)
    pig1, pig2, score, result = game.roll_pigs()
    
    await bot.safe_send(channel, 
        f"🐷🎲 **{user} rolled:** {result}")
    
    # Handle special results
    if score == 0:  # Pig Out
        game.turn_score = 0
        game.next_player()
        db.update_pigs_stats(user, game.scores[user], 0, pig_out=True)
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         game.get_current_player(), game.turn_score)
        await bot.safe_send(channel, 
            f"🎯 **{game.get_current_player()}'s turn!** Type `!pigs` to roll!")
        
    elif score == -999:  # Oinker
        game.scores[user] = 0
        db.update_pigs_stats(user, 0, 0, oinker=True)
        db.delete_pigs_game(channel)
        await bot.safe_send(channel, 
            f"💀 **{user} is eliminated!** Game over!")
        await bot.safe_send(channel, game.get_standings())
        
    elif score == -1000:  # Piggy Back
        game.players.remove(user)
        del game.scores[user]
        if len(game.players) <= 1:
            if game.players:
                winner = game.players[0]
                db.update_pigs_stats(winner, game.scores[winner], 0, won=True)
                await bot.safe_send(channel, 
                    f"🏆 **{winner} wins by elimination!**")
            db.delete_pigs_game(channel)
        else:
            if game.current_player_idx >= len(game.players):
                game.current_player_idx = 0
            db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                             game.get_current_player(), game.turn_score)
            await bot.safe_send(channel, 
                f"🎯 **{game.get_current_player()}'s turn!** Type `!pigs` to roll!")
        
    else:  # Normal points
        game.add_turn_score(score)
        db.save_pigs_game(channel, json.dumps(game.to_dict()), 
                         game.get_current_player(), game.turn_score)
        
        current_total = game.scores[user] + game.turn_score
        await bot.safe_send(channel, 
            f"💫 **Turn total: {game.turn_score}** | "
            f"**Potential score: {current_total}** | "
            f"Type `!pigs` to roll again or `!pigs bank` to bank points!")
        
        # Check if player can win by banking
        if current_total >= game.target_score:
            await bot.safe_send(channel, 
                f"🏆 **{user} can WIN by banking!** Type `!pigs bank` now!")

def setup_plugin(plugin_manager):
    """Register the pigs command"""
    from core.plugin_system import auto_register_commands
    import sys
    auto_register_commands(plugin_manager, sys.modules[__name__])
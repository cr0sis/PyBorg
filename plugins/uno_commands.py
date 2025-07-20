"""
Original UNO game implementation restored verbatim from backup_legacy_files
This preserves all the original game logic, notifications, and user experience
"""

import random
import os
import json
import asyncio
from datetime import datetime, timedelta
import logging
from core.plugin_system import command
from core.database import BotDatabase
from core.config import get_config

logger = logging.getLogger(__name__)

def get_network_config(msg):
    """Get network-specific config based on command prefix"""
    network = 'libera' if msg["message"].startswith('~') else 'rizon'
    return get_config(network)

class IRCColors:
    WHITE = "\x0300"
    BLACK = "\x0301"
    BLUE = "\x0302"
    GREEN = "\x0303"
    RED = "\x0304"
    BROWN = "\x0305"
    PURPLE = "\x0306"
    ORANGE = "\x0307"
    YELLOW = "\x0308"
    LIGHT_GREEN = "\x0309"
    TEAL = "\x0310"
    LIGHT_CYAN = "\x0311"
    LIGHT_BLUE = "\x0312"
    PINK = "\x0313"
    GREY = "\x0314"
    LIGHT_GREY = "\x0315"
    RESET = "\x03"
    BOLD = "\x02"
    UNDERLINE = "\x1F"
    ITALIC = "\x1D"

class UNOGame:
    def __init__(self, channel, starter):
        self.channel = channel
        self.starter = starter  # Who started the game
        self.players = {}  # {username: [cards]}
        self.turn_order = []
        self.current_player = 0
        self.direction = 1  # 1 for forward, -1 for reverse
        self.current_card = None
        self.current_colour = None
        self.deck = []
        self.discard_pile = []
        self.game_active = False
        self.waiting_for_players = False
        self.start_time = None
        self.drawn_this_turn = False
        self.max_players = 8
        self.created_time = datetime.now()
        self.auto_shutdown_task = None
        self.bot_instance = None
        self.create_deck()

    def create_deck(self):
        colors = ['red', 'blue', 'green', 'yellow']
        # Number cards (0-9)
        for color in colors:
            for number in range(10):
                if number == 0:
                    self.deck.append(f"{color}_{number}")
                else:
                    self.deck.append(f"{color}_{number}")
                    self.deck.append(f"{color}_{number}")  # Two of each except 0

        # Action cards (Skip, Reverse, Draw Two)
        for color in colors:
            for action in ['skip', 'reverse', 'draw2']:
                self.deck.append(f"{color}_{action}")
                self.deck.append(f"{color}_{action}")

        # Wild cards
        for _ in range(4):
            self.deck.append("wild_wild")
            self.deck.append("wild_draw4")

        random.shuffle(self.deck)

    def reshuffle_deck(self):
        """Reshuffle discard pile back into deck when deck runs out"""
        if len(self.deck) == 0 and len(self.discard_pile) > 1:
            # Keep the top card, shuffle the rest back
            top_card = self.discard_pile.pop()
            self.deck = self.discard_pile.copy()
            self.discard_pile = [top_card]
            random.shuffle(self.deck)
            return True
        return False

    def draw_card(self):
        """Safely draw a card, reshuffling if needed"""
        if not self.deck:
            if not self.reshuffle_deck():
                # Emergency deck if everything fails
                self.create_deck()

        if self.deck:
            return self.deck.pop()
        return None

    def format_card(self, card, force_played_color=False):
        """Format card with proper colors. force_played_color only for played wild cards."""
        parts = card.split('_')
        colour = parts[0]
        card_type = parts[1]

        # Wild cards should normally be purple, except when explicitly showing played color
        if colour == 'wild':
            if force_played_color and hasattr(self, 'current_colour') and self.current_colour:
                # Only use chosen color when explicitly requested (for played card display)
                display_colour = self.current_colour
            else:
                # Default: wild cards are always purple in hand and most displays
                display_colour = 'wild'
        else:
            display_colour = colour

        # Colour mapping
        if display_colour == 'red':
            colour_code = IRCColors.RED
        elif display_colour == 'blue':
            colour_code = IRCColors.BLUE
        elif display_colour == 'green':
            colour_code = IRCColors.GREEN
        elif display_colour == 'yellow':
            colour_code = IRCColors.YELLOW
        elif display_colour == 'wild':
            colour_code = IRCColors.PURPLE
        else:
            colour_code = IRCColors.WHITE

        # Format the card display
        if card_type.isdigit():
            display = f"[{card_type}]"
        elif card_type == 'skip':
            display = "[S]"
        elif card_type == 'reverse':
            display = "[R]"
        elif card_type == 'draw2':
            display = "[D2]"
        elif card_type == 'wild':
            display = "[W]"
        elif card_type == 'draw4':
            display = "[WD4]"
        else:
            display = f"[{card_type}]"

        return f"{colour_code}{display}{IRCColors.RESET}"

    def format_played_wild_card(self, card):
        """Format a wild card that was just played, showing it in the chosen color"""
        return self.format_card(card, force_played_color=True)

    def format_current_card(self):
        """Format the current card, showing wild cards in their active color"""
        if self.current_card and self.current_card.startswith('wild_') and self.current_colour:
            # Current card display should show chosen color for wild cards
            return self.format_card(self.current_card, force_played_color=True)
        return self.format_card(self.current_card)

    def card_to_play_format(self, card):
        """Convert card to format used in play command"""
        parts = card.split('_')
        color = parts[0]
        card_type = parts[1]

        if card_type.isdigit():
            return f"{color[0].upper()}{card_type}"
        elif card_type == 'skip':
            return f"{color[0].upper()}S"
        elif card_type == 'reverse':
            return f"{color[0].upper()}R"
        elif card_type == 'draw2':
            return f"{color[0].upper()}D2"
        elif card_type == 'wild':
            return "W"
        elif card_type == 'draw4':
            return "WD4"

        return card

    def parse_play_command(self, play_text):
        """Convert play command to internal card format"""
        play_text = play_text.upper().strip()

        # Wild cards
        if play_text == "W":
            return "wild_wild"
        elif play_text == "WD4":
            return "wild_draw4"

        # Color cards
        if len(play_text) >= 2:
            color_map = {'R': 'red', 'B': 'blue', 'G': 'green', 'Y': 'yellow'}
            color_char = play_text[0]
            rest = play_text[1:]

            if color_char in color_map:
                color = color_map[color_char]

                if rest.isdigit():
                    return f"{color}_{rest}"
                elif rest == 'S':
                    return f"{color}_skip"
                elif rest == 'R':
                    return f"{color}_reverse"
                elif rest == 'D2':
                    return f"{color}_draw2"

        return None

    def deal_cards(self):
        for player in self.players:
            self.players[player] = []
            for _ in range(7):
                card = self.draw_card()
                if card:
                    self.players[player].append(card)

    def can_play_card(self, card):
        if not self.current_card:
            return True

        parts = card.split('_')
        current_parts = self.current_card.split('_')

        # Wild cards can always be played
        if parts[0] == 'wild':
            return True

        # Same color or same number/action
        if parts[0] == current_parts[0] or parts[1] == current_parts[1]:
            return True

        # Can play on wild cards if color matches
        if current_parts[0] == 'wild' and parts[0] == self.current_colour:
            return True

        return False

    def get_player_cards_string(self, player):
        if player not in self.players:
            return ""

        cards = self.players[player]
        # Sort cards by value for consistent display
        sorted_cards = sorted(cards, key=lambda card: self.get_card_sort_value(card))
        formatted_cards = [self.format_card(card) for card in sorted_cards]
        return " ".join(formatted_cards)

    def get_card_sort_value(self, card):
        # Sort order: numbers (0-9), then action cards, then wild cards
        if card.startswith('wild_'):
            return 100 + (0 if card == 'wild_normal' else 1)

        color, value = card.split('_')
        color_order = {'red': 0, 'blue': 1, 'green': 2, 'yellow': 3}

        if value.isdigit():
            return color_order.get(color, 0) * 20 + int(value)
        elif value == 'skip':
            return color_order.get(color, 0) * 20 + 10
        elif value == 'reverse':
            return color_order.get(color, 0) * 20 + 11
        elif value == 'draw2':
            return color_order.get(color, 0) * 20 + 12
        else:
            return color_order.get(color, 0) * 20 + 13

    def next_player(self):
        self.current_player = (self.current_player + self.direction) % len(self.turn_order)
        self.drawn_this_turn = False
        return None

    async def send_current_player_cards(self, bot):
        if bot:
            current_user = self.turn_order[self.current_player]
            cards_str = self.get_player_cards_string(current_user)
            await bot.send_raw(f"NOTICE {current_user} :Your UNO cards: {cards_str}\r\n")

    def calculate_card_value(self, card):
        """Calculate point value of a card for scoring"""
        parts = card.split('_')
        card_type = parts[1]

        if card_type.isdigit():
            return int(card_type)
        elif card_type in ['skip', 'reverse', 'draw2']:
            return 20
        elif card_type in ['wild', 'draw4']:
            return 50
        return 0

    def calculate_player_score(self, player):
        """Calculate total score for a player's remaining cards"""
        if player not in self.players:
            return 0

        total = 0
        for card in self.players[player]:
            total += self.calculate_card_value(card)
        return total

    def get_final_standings(self):
        """Get final standings with scores for all players"""
        standings = []
        for player in self.players:
            score = self.calculate_player_score(player)
            cards_left = len(self.players[player])
            standings.append({
                'player': player,
                'score': score,
                'cards_left': cards_left
            })

        # Sort by score (ascending - lower is better)
        standings.sort(key=lambda x: x['score'])
        print(f"DEBUG: Final standings calculated: {standings}")
        return standings

    def get_game_status_message(self):
        """Get the current game status message showing whose turn it is and current card"""
        if not self.game_active or not self.turn_order:
            return ""
        
        current_player = self.turn_order[self.current_player]
        return f"Current player: {IRCColors.BOLD}{current_player}{IRCColors.RESET} - Current card: {self.format_current_card()}"
    
    def start_auto_shutdown_timer(self, bot):
        """Start 30-second auto-shutdown timer if no one joins"""
        self.bot_instance = bot
        if self.auto_shutdown_task:
            self.auto_shutdown_task.cancel()
        self.auto_shutdown_task = asyncio.create_task(self._auto_shutdown_countdown())
    
    def cancel_auto_shutdown_timer(self):
        """Cancel the auto-shutdown timer when someone joins"""
        if self.auto_shutdown_task:
            self.auto_shutdown_task.cancel()
            self.auto_shutdown_task = None
    
    async def _auto_shutdown_countdown(self):
        """Internal countdown for auto-shutdown"""
        try:
            await asyncio.sleep(30)  # Wait 30 seconds
            
            # Check if still waiting for players and only starter is in game
            if self.waiting_for_players and len(self.players) == 1:
                global uno_game
                if self.bot_instance:
                    await self.bot_instance.safe_send(self.channel, 
                        f"⏰ UNO game timed out - no one joined {self.starter}'s game within 30 seconds. Game cancelled.")
                uno_game = None  # Clear the global game
                
        except asyncio.CancelledError:
            # Timer was cancelled (someone joined)
            pass
        except Exception as e:
            logger.error(f"Error in auto-shutdown countdown: {e}")

# UNO Leaderboard Management using Database
def load_total_games_count(network='rizon'):
    """Load total games count from database"""
    try:
        db = BotDatabase(f"{network}_bot.db")
        leaderboard_data = db.get_uno_leaderboard(limit=1000)  # Get all players to count total games
        total_games = sum(player['games'] for player in leaderboard_data)
        return total_games
    except Exception as e:
        logger.error(f"Error loading total games count: {e}")
        return 0

def load_uno_leaderboard(network='rizon'):
    """Load UNO leaderboard from database"""
    try:
        db = BotDatabase(f"{network}_bot.db")
        leaderboard_data = db.get_uno_leaderboard(limit=1000)  # Get all players

        leaderboard = {}
        for player_data in leaderboard_data:
            player = player_data['player'].lower()  # Normalize for storage
            leaderboard[player] = {
                'total_score': int(player_data.get('total_cards_played', 0)),  # Use total cards as score
                'games_played': int(player_data['games']),
                'wins': int(player_data['wins']),
                'display_name': player_data['player']  # Keep original capitalization
            }

        return leaderboard
    except Exception as e:
        logger.error(f"Error loading UNO leaderboard: {e}")
        return {}

def save_uno_leaderboard(leaderboard, total_games=None):
    """Save UNO leaderboard to database (no longer needed as updates are direct)"""
    # This function is kept for compatibility but database updates are handled directly
    # in update_uno_leaderboard via database.update_uno_stats()
    pass

def update_uno_leaderboard(game_results, network='rizon'):
    """Update leaderboard with game results using database"""
    try:
        db = BotDatabase(f"{network}_bot.db")

        for i, result in enumerate(game_results):
            player = result['player']
            cards_left = result['cards_left']
            score = result['score']  # Points from remaining cards
            position = i + 1  # 1st place, 2nd place, etc.

            # Update database with UNO game result
            # Position 1 = winner, cards_left = final cards remaining, score = points penalty
            db.update_uno_stats(player, position, cards_left, score)

        logger.info(f"Updated UNO leaderboard for {len(game_results)} players")

    except Exception as e:
        logger.error(f"Error updating UNO leaderboard: {e}")

# Global UNO game instance
uno_game = None

@command(
    pattern=r'uno$',
    description="Start a new UNO game",
    category="games",
    requires_bot=True
)
async def start_uno_game(msg, bot=None):
    global uno_game

    # Get network-specific config
    config = get_network_config(msg)
    prefix = config.COMMAND_PREFIX

    if uno_game and (uno_game.game_active or uno_game.waiting_for_players):
        return f"A game is already in progress! Use {prefix}join to join or wait for it to finish."

    starter = msg["user"]
    uno_game = UNOGame(msg["channel"], starter)
    uno_game.waiting_for_players = True
    uno_game.start_time = datetime.now()

    # Add the person who started the game
    uno_game.players[starter] = []
    
    # Start 30-second auto-shutdown timer
    uno_game.start_auto_shutdown_timer(bot)

    return [
        f"{IRCColors.BOLD}{IRCColors.GREEN}🎮 UNO GAME STARTED! 🎮{IRCColors.RESET}",
        f"Started by {starter}. Type {IRCColors.BOLD}{prefix}join{IRCColors.RESET} to join the game!",
        f"When ready, {starter} can use {IRCColors.BOLD}{prefix}start{IRCColors.RESET} to begin the game.",
        f"Use {IRCColors.BOLD}{prefix}unohelp{IRCColors.RESET} for commands and rules.",
        f"⏰ Game will auto-cancel in 30 seconds if no one joins."
    ]

@command(
    pattern=r'join$',
    description="Join an UNO game waiting for players",
    category="games",
    requires_bot=True
)
async def join_uno_game(msg, bot=None):
    global uno_game
    
    # DEBUG: Log that join command was called
    logger.info(f"JOIN COMMAND CALLED by {msg.get('user', 'unknown')} in {msg.get('channel', 'unknown')}")

    # Get network-specific config
    config = get_network_config(msg)
    prefix = config.COMMAND_PREFIX

    if not uno_game or not uno_game.waiting_for_players:
        return f"No game waiting for players. Use {prefix}uno to start a new game."

    player = msg["user"]
    if player in uno_game.players:
        return f"{player}, you're already in the game!"

    if len(uno_game.players) >= uno_game.max_players:
        return f"Game is full! Maximum {uno_game.max_players} players allowed."

    uno_game.players[player] = []
    player_count = len(uno_game.players)
    
    # Cancel auto-shutdown timer since someone joined
    if player_count == 2:  # First person to join after starter
        uno_game.cancel_auto_shutdown_timer()

    return f"{player} joined the game! ({player_count}/{uno_game.max_players} players)"

@command(
    pattern=r'start$',
    description="Start the UNO round (game starter only)",
    category="games",
    requires_bot=True
)
async def start_uno_round_manual(msg, bot=None):
    """Manual start command - only the game starter can use this"""
    global uno_game
    
    # DEBUG: Log that start command was called
    logger.info(f"START COMMAND CALLED by {msg.get('user', 'unknown')} in {msg.get('channel', 'unknown')}")

    if not uno_game or not uno_game.waiting_for_players:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"No game waiting to start. Use {prefix}uno to start a new game."

    player = msg["user"]
    if player != uno_game.starter:
        return f"Only {uno_game.starter} (who started the game) can begin the round!"

    if len(uno_game.players) < 2:
        return "Need at least 2 players to start!"

    return await start_uno_round(bot)

async def start_uno_round(bot=None):
    global uno_game
    
    # DEBUG: Log that start_uno_round was called
    logger.info(f"START_UNO_ROUND CALLED with bot: {bot is not None}")

    if not uno_game or len(uno_game.players) < 2:
        return "Need at least 2 players to start!"

    # Set up the game
    uno_game.waiting_for_players = False
    uno_game.game_active = True
    uno_game.turn_order = list(uno_game.players.keys())
    random.shuffle(uno_game.turn_order)
    
    # Cancel auto-shutdown timer since game is starting
    uno_game.cancel_auto_shutdown_timer()

    # Deal cards
    uno_game.deal_cards()

    # Set starting card
    while True:
        starting_card = uno_game.draw_card()
        if starting_card and not starting_card.startswith('wild_'):
            uno_game.current_card = starting_card
            uno_game.current_colour = starting_card.split('_')[0]
            break

    # Pick random starting player
    uno_game.current_player = random.randint(0, len(uno_game.turn_order) - 1)

    # Send cards to players via NOTICE
    if bot:
        for player in uno_game.players:
            cards_str = uno_game.get_player_cards_string(player)
            await bot.send_raw(f"NOTICE {player} :Your UNO cards: {cards_str}\r\n")

    messages = [
        f"{IRCColors.BOLD}{IRCColors.GREEN}🎮 UNO GAME BEGINS! 🎮{IRCColors.RESET}",
        f"Players: {', '.join(uno_game.turn_order)}",
        f"Starting card: {uno_game.format_current_card()}",
        f"📩 Cards have been sent to all players via private notice!",
        uno_game.get_game_status_message()
    ]

    return messages

@command(
    pattern=r'play\s+(.+)',
    description="Play a card in UNO (e.g., play R5, play BS, play WD4 red)",
    usage="play <card> [color]",
    category="games",
    requires_bot=True
)
async def play_uno_card(msg, bot=None):
    global uno_game

    if not uno_game or not uno_game.game_active:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"No active game! Use {prefix}uno to start a new game."

    player = msg["user"]
    if player not in uno_game.players:
        return f"{player}, you're not in this game!"

    if uno_game.turn_order[uno_game.current_player] != player:
        current_player = uno_game.turn_order[uno_game.current_player]
        return f"It's {current_player}'s turn, not yours!"

    # Parse the play command
    parts = msg["message"].split()
    if len(parts) < 2:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"Usage: {prefix}play <card> [color] (e.g., {prefix}play R5, {prefix}play BS, {prefix}play WD4 red)"

    play_text = parts[1]
    chosen_colour = None

    # Check if wild card with color specified
    if len(parts) >= 3 and play_text.upper() in ["W", "WD4"]:
        colour_text = parts[2].lower()
        if colour_text in ['red', 'blue', 'green', 'yellow']:
            chosen_colour = colour_text
        else:
            return "Invalid color! Use red, blue, green, or yellow."

    card_to_play = uno_game.parse_play_command(play_text)

    if not card_to_play:
        return "Invalid card format! Use R5, BS, GR, WD4, etc."

    # Check if wild card needs color
    if card_to_play.startswith('wild_') and not chosen_colour:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"Wild cards need a color! Use: {prefix}play WD4 red (or blue/green/yellow)"

    # Check if player has the card
    if card_to_play not in uno_game.players[player]:
        if bot:
            cards_str = uno_game.get_player_cards_string(player)
            await bot.send_raw(f"NOTICE {player} :You don't have that card! Your UNO cards: {cards_str}\r\n")
        return "You don't have that card!"

    # Check if card can be played
    if not uno_game.can_play_card(card_to_play):
        return f"Can't play that card! Current card: {uno_game.format_current_card()}"

    # Play the card
    uno_game.players[player].remove(card_to_play)
    uno_game.current_card = card_to_play
    uno_game.discard_pile.append(card_to_play)

    # Show wild cards in chosen color for played message, regular cards normal
    if card_to_play.startswith('wild_') and chosen_colour:
        played_card_display = uno_game.format_played_wild_card(card_to_play)
    else:
        played_card_display = uno_game.format_card(card_to_play)

    messages = [f"{player} played {played_card_display}"]

    # Handle wild cards
    if card_to_play.startswith('wild_'):
        uno_game.current_colour = chosen_colour
        messages.append(f"Colour changed to {chosen_colour}")
    else:
        uno_game.current_colour = card_to_play.split('_')[0]

    # Handle special cards
    card_type = card_to_play.split('_')[1]

    if card_type == 'skip':
        # Skip the next player by advancing twice
        uno_game.next_player()  # Move to next player
        skipped_player = uno_game.turn_order[uno_game.current_player]
        uno_game.next_player()  # Skip them
        messages.append(f"{skipped_player} was skipped!")
    elif card_type == 'reverse':
        if len(uno_game.turn_order) == 2:
            # In 2-player games, reverse gives the current player another turn
            messages.append("Reverse in 2-player: You get another turn!")
            # Don't call next_player() - current player keeps their turn
        else:
            # Normal reverse - change direction and go to previous player
            uno_game.direction *= -1
            messages.append("Direction reversed!")
            uno_game.next_player()  # Move to the previous player (now next due to direction change)
    elif card_type == 'draw2':
        # Next player draws 2 cards and loses their turn
        uno_game.next_player()
        next_player = uno_game.turn_order[uno_game.current_player]
        drawn_cards = []
        for _ in range(2):
            card = uno_game.draw_card()
            if card:
                uno_game.players[next_player].append(card)
                drawn_cards.append(card)

        # Show the drawn cards to the affected player via NOTICE
        if bot and drawn_cards:
            cards_display = ', '.join([uno_game.format_card(card) for card in drawn_cards])
            await bot.send_raw(f"NOTICE {next_player} :You were forced to draw: {cards_display}\r\n")

        messages.append(f"{next_player} draws 2 cards and loses their turn!")
        uno_game.next_player()  # Skip their turn
    elif card_type == 'draw4':
        # Next player draws 4 cards and loses their turn
        uno_game.next_player()
        next_player = uno_game.turn_order[uno_game.current_player]
        drawn_cards = []
        for _ in range(4):
            card = uno_game.draw_card()
            if card:
                uno_game.players[next_player].append(card)
                drawn_cards.append(card)

        # Show the drawn cards to the affected player via NOTICE
        if bot and drawn_cards:
            cards_display = ', '.join([uno_game.format_card(card) for card in drawn_cards])
            await bot.send_raw(f"NOTICE {next_player} :You were forced to draw: {cards_display}\r\n")

        messages.append(f"{next_player} draws 4 cards and loses their turn!")
        uno_game.next_player()  # Skip their turn

    # Check for win or UNO
    if len(uno_game.players[player]) == 0:
        # Game over - calculate final standings
        standings = uno_game.get_final_standings()

        messages.append(f"{IRCColors.BOLD}{IRCColors.YELLOW}🎉 {player} WINS! 🎉{IRCColors.RESET}")
        messages.append(f"{IRCColors.BOLD}{IRCColors.GREEN}🏆 FINAL STANDINGS 🏆{IRCColors.RESET}")

        place_emojis = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣"]

        for i, standing in enumerate(standings):
            emoji = place_emojis[i] if i < len(place_emojis) else f"{i+1}."
            messages.append(f"{emoji} {standing['player']}: {standing['score']} points ({standing['cards_left']} cards)")

        # Update leaderboard
        try:
            config = get_network_config(msg)
            network = 'libera' if msg["message"].startswith('~') else 'rizon'
            update_uno_leaderboard(standings, network)
            prefix = config.COMMAND_PREFIX
            messages.append(f"{IRCColors.BOLD}📊 Leaderboard updated! Use {prefix}unoleaderboard to see rankings{IRCColors.RESET}")
        except Exception as e:
            print(f"Error updating leaderboard: {e}")

        uno_game.game_active = False
        uno_game = None
        return messages
    elif len(uno_game.players[player]) == 1:
        messages.append(f"{IRCColors.YELLOW}{player} has UNO! (1 card left){IRCColors.RESET}")

    # Move to next player (unless already handled by special cards)
    if card_type not in ['skip', 'reverse', 'draw2', 'draw4']:
        uno_game.next_player()

    # Send cards to current player
    if bot:
        await uno_game.send_current_player_cards(bot)

    # Show current game status
    messages.append(uno_game.get_game_status_message())

    return messages

@command(
    pattern=r'draw$',
    description="Draw a card from the deck",
    category="games",
    requires_bot=True
)
async def draw_uno_card(msg, bot=None):
    global uno_game

    if not uno_game or not uno_game.game_active:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"No active game! Use {prefix}uno to start a new game."

    player = msg["user"]
    if player not in uno_game.players:
        return f"{player}, you're not in this game!"

    if uno_game.turn_order[uno_game.current_player] != player:
        current_player = uno_game.turn_order[uno_game.current_player]
        return f"It's {current_player}'s turn, not yours!"

    if uno_game.drawn_this_turn:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"You already drew a card this turn! Play a card or {prefix}pass."

    drawn_card = uno_game.draw_card()
    if drawn_card:
        uno_game.players[player].append(drawn_card)
        uno_game.drawn_this_turn = True

        # Show the drawn card to the player via NOTICE
        if bot:
            card_display = uno_game.format_card(drawn_card)
            await bot.send_raw(f"NOTICE {player} :You drew: {card_display}\r\n")

        # Show game state after drawing
        return [
            f"{player} drew a card.",
            uno_game.get_game_status_message()
        ]
    else:
        return "Error: Could not draw a card from the deck."

@command(
    pattern=r'pass$',
    description="Pass your turn (only after drawing a card)",
    category="games",
    requires_bot=True
)
async def pass_uno_turn(msg, bot=None):
    global uno_game

    if not uno_game or not uno_game.game_active:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"No active game! Use {prefix}uno to start a new game."

    player = msg["user"]
    if player not in uno_game.players:
        return f"{player}, you're not in this game!"

    if uno_game.turn_order[uno_game.current_player] != player:
        current_player = uno_game.turn_order[uno_game.current_player]
        return f"It's {current_player}'s turn, not yours!"

    if not uno_game.drawn_this_turn:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"You must draw a card first before passing! Use {prefix}draw"

    # Move to next player
    uno_game.next_player()

    # Send cards to current player
    if bot:
        await uno_game.send_current_player_cards(bot)

    # Show current game status
    return [
        f"{player} passed their turn.",
        uno_game.get_game_status_message()
    ]

@command(
    pattern=r'cards$',
    description="Show your UNO cards (sent privately)",
    category="games",
    requires_bot=True
)
async def show_uno_cards(msg, bot=None):
    global uno_game

    if not uno_game or not uno_game.game_active:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"No active game! Use {prefix}uno to start a new game."

    player = msg["user"]
    if player not in uno_game.players:
        return f"{player}, you're not in this game!"

    if bot:
        cards_str = uno_game.get_player_cards_string(player)
        await bot.send_raw(f"NOTICE {player} :Your UNO cards: {cards_str}\r\n")

    return f"📩 {player}, your cards have been sent via private notice!"

@command(
    pattern=r'status$',
    description="Show current UNO game status",
    category="games"
)
async def show_uno_status(msg, bot=None):
    global uno_game

    if not uno_game:
        config = get_network_config(msg)
        prefix = config.COMMAND_PREFIX
        return f"No active game! Use {prefix}uno to start a new game."

    if uno_game.waiting_for_players:
        players_list = ', '.join(uno_game.players.keys())
        return [
            f"🎮 UNO Game waiting for players:",
            f"Players ({len(uno_game.players)}/{uno_game.max_players}): {players_list}",
            f"Started by: {uno_game.starter}"
        ]
    elif uno_game.game_active:
        current_player = uno_game.turn_order[uno_game.current_player]
        player_count = []
        for player in uno_game.turn_order:
            card_count = len(uno_game.players[player])
            if player == current_player:
                player_count.append(f"{IRCColors.BOLD}{player}{IRCColors.RESET} ({card_count})")
            else:
                player_count.append(f"{player} ({card_count})")

        return [
            f"🎮 UNO Game in progress:",
            f"Players: {', '.join(player_count)}",
            f"Current card: {uno_game.format_current_card()}",
            f"Current player: {IRCColors.BOLD}{current_player}{IRCColors.RESET}"
        ]
    else:
        return "Game state unknown."

@command(
    pattern=r'quit$',
    description="Quit the current UNO game",
    category="games",
    requires_bot=True
)
async def quit_uno_game(msg, bot=None):
    global uno_game

    if not uno_game:
        return "No active game to quit."

    player = msg["user"]
    if player not in uno_game.players:
        return f"{player}, you're not in this game!"

    # Remove player from game
    del uno_game.players[player]

    if uno_game.waiting_for_players:
        if len(uno_game.players) == 0:
            uno_game = None
            return f"{player} left the game. Game cancelled due to no players."
        else:
            # If the starter left, assign a new starter
            if player == uno_game.starter:
                uno_game.starter = list(uno_game.players.keys())[0]
                return f"{player} left the game. {uno_game.starter} is now the game starter."
            return f"{player} left the game. ({len(uno_game.players)} players remaining)"

    elif uno_game.game_active:
        # Remove from turn order
        if player in uno_game.turn_order:
            player_index = uno_game.turn_order.index(player)
            uno_game.turn_order.remove(player)

            # Adjust current player index if needed
            if player_index < uno_game.current_player:
                uno_game.current_player -= 1
            elif player_index == uno_game.current_player:
                # If it was their turn, keep the same index (next player)
                if uno_game.current_player >= len(uno_game.turn_order):
                    uno_game.current_player = 0

        # Check if game should continue
        if len(uno_game.players) < 2:
            winner = list(uno_game.players.keys())[0] if uno_game.players else None
            uno_game = None
            if winner:
                return f"{player} left the game. {winner} wins by default!"
            else:
                return f"{player} left the game. Game ended."
        else:
            if uno_game.turn_order:
                return [
                    f"{player} left the game.",
                    uno_game.get_game_status_message()
                ]
            else:
                uno_game = None
                return f"{player} left the game. Game ended due to error."

    return f"{player} left the game."

@command(
    pattern=r'unohelp$',
    description="Show UNO game help and rules",
    category="games",
    requires_bot=True
)
async def show_uno_help(msg, bot=None):
    # Get network-specific config
    config = get_network_config(msg)
    prefix = config.COMMAND_PREFIX

    return [
        f"{IRCColors.BOLD}{IRCColors.GREEN}🎮 UNO Game Commands:{IRCColors.RESET}",
        f"{IRCColors.BOLD}{prefix}uno{IRCColors.RESET} - Start a new game",
        f"{IRCColors.BOLD}{prefix}join{IRCColors.RESET} - Join a game waiting for players",
        f"{IRCColors.BOLD}{prefix}start{IRCColors.RESET} - Begin the game (starter only)",
        f"{IRCColors.BOLD}{prefix}play <card>{IRCColors.RESET} - Play a card (e.g., {prefix}play R5, {prefix}play BS, {prefix}play WD4 red)",
        f"{IRCColors.BOLD}{prefix}draw{IRCColors.RESET} - Draw a card from deck",
        f"{IRCColors.BOLD}{prefix}pass{IRCColors.RESET} - Pass turn (after drawing)",
        f"{IRCColors.BOLD}{prefix}cards{IRCColors.RESET} - See your cards (private)",
        f"{IRCColors.BOLD}{prefix}status{IRCColors.RESET} - Show game status",
        f"{IRCColors.BOLD}{prefix}quit{IRCColors.RESET} - Leave the current game",
        f"{IRCColors.BOLD}{prefix}unoleaderboard{IRCColors.RESET} - Show leaderboard",
        "",
        f"{IRCColors.BOLD}Card Format:{IRCColors.RESET} R5=Red 5, BS=Blue Skip, GR=Green Reverse, YD2=Yellow Draw 2, W=Wild, WD4=Wild Draw 4",
        f"{IRCColors.BOLD}Wild Cards:{IRCColors.RESET} Must specify color: {prefix}play WD4 red"
    ]

@command(
    pattern=r'unoleaderboard$',
    description="Show UNO game leaderboard",
    category="games"
)
def show_uno_leaderboard(msg):
    # Get network-specific config
    config = get_network_config(msg)
    try:
        # Get correct network database
        network = 'libera' if msg["message"].startswith('~') else 'rizon'
        db = BotDatabase(f"{network}_bot.db")
        leaderboard_data = db.get_uno_leaderboard(limit=10)

        if not leaderboard_data:
            return "No UNO games played yet! Start a game to begin building the leaderboard."

        messages = [f"{IRCColors.BOLD}{IRCColors.GREEN}🏆 UNO LEADERBOARD 🏆{IRCColors.RESET}"]

        for i, player_data in enumerate(leaderboard_data):
            player = player_data['player']
            games = player_data['games']
            wins = player_data['wins']
            avg_cards = player_data.get('avg_cards_per_game', 0)
            win_rate = player_data.get('win_rate', 0) * 100

            place = ["🥇", "🥈", "🥉"][i] if i < 3 else f"{i+1}."
            messages.append(f"{place} {player}: {avg_cards:.1f} avg cards ({games} games, {wins} wins, {win_rate:.1f}%)")

        # Calculate total games across all players in database
        all_players = db.get_uno_leaderboard(limit=1000)
        total_games = sum(player['games'] for player in all_players)
        messages.append(f"📊 Total games played: {total_games}")

        return messages

    except Exception as e:
        logger.error(f"Error showing UNO leaderboard: {e}")
        return "Error loading leaderboard data."

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys

    auto_register_commands(plugin_manager, sys.modules[__name__])
    logger.info("Restored UNO commands plugin loaded")

# PyBorg 🤖

A modern, plugin-based IRC bot written in Python with async architecture, AI integration, and a complete **UNO card game** as its flagship feature.

## Features ✨

- **Modern Architecture**: Built with Python 3.8+ asyncio for high performance
- **Plugin System**: Modular command system with easy plugin development
- **AI Integration**: Google Gemini AI for intelligent chat responses
- **Multi-Network**: Support for multiple IRC networks simultaneously
- **Database Persistence**: SQLite database with automatic migrations
- **Web Interface**: HTML5 games, leaderboards, and bot management
- **Auto-Rejoin**: Automatically rejoins channels when kicked
- **Rate Limiting**: Built-in flood protection
- **Memo System**: Leave messages for users delivered when they speak
- **UNO Card Game**: Complete multiplayer UNO with leaderboards and statistics
- **Games**: Dice games, breakout, and more
- **Rich Commands**: Weather, ISS tracking, server monitoring, and utilities

## Quick Start 🚀

### 1. Clone and Setup
```bash
git clone https://github.com/cr0sis/PyBorg.git
cd PyBorg
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Or use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
pip install -r requirements.txt
```

### 3. Configure Your Bot
```bash
# Run the interactive setup wizard
python3 scripts/setup.py
```

The setup wizard will guide you through:
- IRC network configuration
- Bot identity and channels
- Optional features (AI, web interface)
- Authentication settings
- Admin users

### 4. Start Your Bot
```bash
# Use the generated start script
./start.sh

# Or run directly
python3 bot.py your_network_name
```

## 🃏 UNO Card Game - The Main Attraction

PyBorg's flagship feature is a **complete multiplayer UNO card game** that runs entirely in IRC channels. Challenge friends, climb leaderboards, and enjoy classic UNO action with IRC-style formatting and colors.

### Game Features
- **Multiplayer Support**: 2-10 players per game
- **Complete UNO Rules**: Draw 2, Wild +4, Skip, Reverse, Color changes
- **Smart AI**: Handles all game logic, card validation, and turn management
- **Visual Cards**: IRC color-coded cards for easy recognition
- **Statistics Tracking**: Wins, games played, cards per game averages
- **Global Leaderboards**: Cross-network rankings and achievements
- **Auto-Save**: Games persist through bot restarts

### Quick UNO Guide
```
!uno                    # Start a new game
!join                   # Join an existing game  
!hand                   # View your cards (private message)
!play <card>           # Play a card (e.g., !play r5, !play wild)
!draw                   # Draw a card from deck
!pass                   # Pass your turn (after drawing)
!cards <player>        # Check how many cards a player has
!unoleaderboard        # View top players and statistics
!unohelp              # Full command reference
!leave                 # Leave current game
!endgame              # End game (admin/starter only)
```

### UNO Card Examples
- **Number Cards**: `r5` (Red 5), `b2` (Blue 2), `g9` (Green 9), `y7` (Yellow 7)
- **Action Cards**: `rskip` (Red Skip), `bdraw2` (Blue Draw 2), `greverse` (Green Reverse)
- **Wild Cards**: `wild` (Wild), `wild4` (Wild Draw 4)

### Sample Game Flow
```
<PyBorg> 🃏 UNO Game Started! Players: Alice, Bob, Carol
<PyBorg> 📋 Turn Order: Alice → Bob → Carol
<PyBorg> 🎯 Current Card: [🔴5] | Alice's turn (7 cards)
<Alice> !play r3
<PyBorg> ✅ Alice played [🔴3] | Bob's turn (7 cards)  
<Bob> !play b3
<PyBorg> ✅ Bob played [🔵3] | Carol's turn (6 cards)
<Carol> !play wild red
<PyBorg> 🌈 Carol played [WILD] → RED | Alice's turn (5 cards)
```

### Leaderboard & Statistics
The UNO system tracks comprehensive statistics:
- **Win/Loss Ratios**: Track your success rate
- **Cards Per Game**: Average efficiency metrics  
- **Total Games**: Lifetime game participation
- **Recent Activity**: Last game timestamps
- **Global Rankings**: See who's the ultimate UNO champion

View stats anytime with `!unoleaderboard` to see the top players across all networks!

## Configuration ⚙️

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Network Configuration
NETWORK_NAME=mynetwork

# Authentication (optional)
NICKSERV_PASSWORD=your_password

# API Keys (optional)
GEMINI_API_KEY=your_gemini_key

# Bot Behavior
AUTO_REJOIN=true
REJOIN_DELAY=5
RATE_LIMIT_MESSAGES=4
RATE_LIMIT_PERIOD=8

# Admin Users
ADMIN_USERS=your_nick,admin_nick
ADMIN_HOSTMASKS=*!*@your.hostname.com
```

### Network Configuration

Edit `core/config.py` to add networks:

```python
network_configs = {
    "mynetwork": {
        "host": "irc.example.com",
        "port": 6667,
        "nick": "PyBorg",
        "user": "PyBorg PyBorg PyBorg :PyBorg IRC Bot",
        "channels": ["#general", "#bots"],
        "command_prefix": "!"
    }
}
```

## Commands 🎮

### Basic Commands
- `!help` - Show available commands
- `!time` - Current time and date
- `!calc <expression>` - Calculator
- `!weather <location>` - Weather information
- `!roll <dice>` - Roll dice (e.g., !roll 2d6)

### AI & Chat
- `!speak <message>` - Chat with AI
- `!clear` - Clear AI conversation history
- `!memo(username) message` - Leave a memo for a user

### Games
- `!uno` - Start UNO card game
- `!roll7` - Roll 7 dice game
- `!bet7 <amount>` - Betting dice game
- `!unoleaderboard` - Show UNO rankings

### Utilities
- `!links` - Show recent channel links
- `!stats` - Show bot statistics
- `!piss` - ISS position and tank levels
- `!temp` - Server temperature (if supported)

### Admin Commands
- `!reload` - Reload bot plugins
- `!admin` - Admin management commands

## Plugin Development 🔧

Creating plugins is easy! Here's a basic example:

```python
from core.plugin_system import command

@command(
    pattern=r'hello',
    description="Say hello",
    category="examples"
)
def hello_command(msg):
    return f"Hello {msg['user']}!"

@command(
    pattern=r'async_example',
    description="Async command example", 
    requires_bot=True
)
async def async_command(msg, bot):
    await bot.safe_send(msg['channel'], "This is async!")
    return "Command completed"

def setup_plugin(plugin_manager):
    from core.plugin_system import auto_register_commands
    import sys
    auto_register_commands(plugin_manager, sys.modules[__name__])
```

### Plugin Categories
- `basic` - Core utilities
- `games` - Gaming commands  
- `ai` - AI and chat features
- `api` - External API integrations
- `admin` - Administrative commands

## Web Interface 🌐

PyBorg includes a web interface with:

- **Games**: Breakout, Mars Colony strategy game
- **Leaderboards**: UNO rankings and game statistics  
- **Admin Panel**: Bot management and monitoring
- **API Endpoints**: RESTful APIs for bot data

Access at `http://localhost:8080` (if enabled)

## Database 💾

PyBorg uses SQLite for data persistence:

- **Commands**: Usage statistics and history
- **Games**: UNO leaderboards, scores, and rankings
- **Memos**: User-to-user message system
- **Links**: Channel link tracking
- **AI**: Conversation history and context

## Architecture 🏗️

```
PyBorg/
├── core/               # Core framework
│   ├── config.py       # Configuration management
│   ├── database.py     # Database layer
│   ├── plugin_system.py # Plugin architecture
│   └── exceptions.py   # Custom exceptions
├── plugins/            # Command plugins
│   ├── basic_commands.py
│   ├── game_commands.py
│   ├── ai_commands.py
│   └── ...
├── web/                # Web interface
├── scripts/            # Utility scripts
├── logs/               # Log files
├── data/               # Database files
└── bot.py              # Main bot application
```

## Requirements 📋

- **Python**: 3.8 or higher
- **OS**: Linux, macOS, Windows
- **Memory**: 128MB+ RAM
- **Storage**: 100MB+ free space

### Optional Dependencies
- **Google Gemini API**: For AI features
- **GPIO**: For temperature monitoring (Raspberry Pi)
- **OpenCV**: For image processing commands

## Deployment 🚀

### Systemd Service (Linux)

Create `/etc/systemd/system/pyborg.service`:

```ini
[Unit]
Description=PyBorg IRC Bot
After=network.target

[Service]
Type=simple
User=pyborg
WorkingDirectory=/path/to/PyBorg
ExecStart=/path/to/PyBorg/start.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable pyborg
sudo systemctl start pyborg
```

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["python3", "bot.py", "mynetwork"]
```

### Screen/Tmux

```bash
# Using screen
screen -dmS pyborg python3 bot.py mynetwork

# Using tmux  
tmux new-session -d -s pyborg 'python3 bot.py mynetwork'
```

## Contributing 🤝

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Follow the existing code style (use `black` formatter)
5. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest

# Format code
black .

# Lint code
flake8 .
```

## Troubleshooting 🔧

### Common Issues

**Bot won't connect:**
- Check network/firewall settings
- Verify IRC server and port
- Check SSL/TLS settings

**Commands not working:**
- Verify command prefix configuration
- Check plugin loading in logs
- Ensure proper permissions

**Database errors:**
- Check file permissions
- Verify disk space
- Review database file location

**AI not responding:**
- Verify GEMINI_API_KEY in .env
- Check API quota/billing
- Review network connectivity


### Log Files

Check logs in the `logs/` directory:
- `networkname_main.log` - General bot activity
- `networkname_errors.log` - Error messages

### Debug Mode

Enable debug logging:
```bash
LOG_LEVEL=DEBUG python3 bot.py mynetwork
```

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support 💬

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Ask questions in GitHub Discussions
- **IRC**: Join `#pyborg` on your favorite network

## Acknowledgments 🙏

- Built with Python's excellent `asyncio` library
- Powered by Google Gemini AI
- Inspired by classic IRC bots like Eggdrop and Supybot
- Thanks to the IRC community for decades of chat protocols

---

Happy botting! 🤖✨

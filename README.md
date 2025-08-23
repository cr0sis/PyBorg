# PyBorg - Multi-Network IRC Bot

A powerful, extensible Python IRC bot with web interface, AI integration, games, and comprehensive monitoring. Supports multiple IRC networks simultaneously with individual configurations.

## Features

- **Multi-Network Support**: Connect to any IRC network with individual configs
- **Interactive Games**: UNO, word scramble, roulette, 8-ball, and more  
- **AI Integration**: Chat with Gemini AI (`!speak` command)
- **Web Dashboard**: Real-time monitoring, user management, game scores
- **Security**: 2FA, encrypted sessions, intrusion detection
- **Analytics**: Command usage, user activity, performance metrics
- **Plugin System**: Easy command development and registration
- **Auto-Database**: SQLite databases created automatically
- **Rich Logging**: Structured logs with rotation and monitoring

## Quick Start

### 1. Prerequisites

- Python 3.9+
- Node.js 14+ (for web interface)
- SQLite3

### 2. Installation

```bash
git clone <your-repo-url>
cd PyBorg
pip install -r requirements.txt
```

**Note**: PyBorg works from any directory on your system. All data and configurations are stored relative to the project directory by default. See [PATH_CONFIGURATION.md](PATH_CONFIGURATION.md) for advanced path options.

### 3. Configuration

Run the interactive setup script:
```bash
python setup.py
```

Or configure manually:

#### Configure Environment Variables
```bash
cp .env.example .env
# Edit .env with your API keys:
# GEMINI_API_KEY=your_key_here
# TWITCH_CLIENT_ID=optional
# TWITCH_CLIENT_SECRET=optional
# NICKSERV_PASSWORD=optional
```

#### Configure Networks
```bash
cp networks.example.json networks.json
# Edit networks.json with your IRC networks
```

Example `networks.json`:
```json
{
  "networks": {
    "freenode": {
      "name": "Freenode",
      "host": "irc.libera.chat",
      "port": 6697,
      "use_ssl": true,
      "command_prefix": "!",
      "nickname": "PyBorg",
      "realname": "PyBorg IRC Bot",
      "channels": ["#bottest"],
      "reconnect_delay": 30,
      "auth_join_delay": 5
    }
  },
  "default_settings": {
    "rate_limit_messages": 6,
    "rate_limit_period": 30,
    "max_message_length": 400,
    "command_cooldown": 2,
    "ai_context_limit": 10,
    "log_level": "INFO"
  }
}
```

### 4. Run the Bot

```bash
# Start bot for specific network
python bot_v2.py freenode

# Or use the default first network in config
python bot_v2.py
```

### 5. Web Interface (Optional)

The bot includes a PHP web interface for monitoring and administration:

1. Configure your web server to serve the `web/` directory
2. Ensure PHP has access to the data directories
3. Visit `/admin_styled.php` for the admin interface

## Commands

### Core Commands
- `!help` - Show available commands
- `!speak <message>` - Chat with AI
- `!time` - Current time
- `!dice` - Roll dice
- `!8ball <question>` - Magic 8-ball

### Games
- `!uno` - Start UNO game
- `!scramble` - Word scramble game  
- `!roulette` - Russian roulette
- `!leaderboard` - Game scores

### Utilities
- `!memo <user> <message>` - Leave message
- `!weather <location>` - Weather info
- `!remind <time> <message>` - Set reminder

## Architecture

### Core Components

- **`bot_v2.py`** - Main IRC bot with async message handling
- **`core/config.py`** - Dynamic network configuration management
- **`core/database.py`** - Auto-creating SQLite database wrapper
- **`core/plugin_system.py`** - Plugin loading and command dispatch
- **`plugins/`** - Command plugins (games, AI, utilities, etc.)
- **`web/`** - PHP web interface with real-time monitoring

### Database Structure

Databases are created automatically per network:
- `{network}_bot.db` - Bot data (scores, commands, analytics)
- `users.db` - Web interface users and authentication
- All tables use `CREATE TABLE IF NOT EXISTS`

### Plugin Development

Create new commands easily:

```python
from core.plugin_system import command

@command(
    pattern=r'hello',
    description="Say hello",
    category="general"
)
def hello_command(msg, bot=None):
    user = msg.get('user', 'someone')
    return f"Hello, {user}!"

def setup_plugin(plugin_manager):
    # Auto-registration happens via decorator
    pass
```

## Configuration Options

### Environment Variables
- `GEMINI_API_KEY` - Required for AI features
- `NICKSERV_PASSWORD` - IRC authentication
- `TWITCH_CLIENT_ID/SECRET` - Twitch integration
- `LOG_LEVEL` - Logging verbosity (DEBUG, INFO, WARNING, ERROR)
- `NETWORKS_CONFIG_FILE` - Custom networks config path

### Network Configuration
Each network supports:
- Custom command prefixes
- SSL/non-SSL connections
- Individual channel lists
- Reconnection delays
- Rate limiting settings

### Default Settings
Global defaults applied to all networks:
- Rate limiting (6 messages per 30 seconds)
- Message length limits (400 chars)
- Command cooldowns (2 seconds)
- AI context limits (10 messages)

## Security Features

- **Input Sanitization**: SQL injection and XSS protection
- **Rate Limiting**: Prevents spam and abuse
- **2FA Support**: TOTP authentication for web interface
- **Encrypted Sessions**: Secure web session management
- **Audit Logging**: Comprehensive security event logging
- **IP Binding**: Session security and intrusion detection

## Troubleshooting

### Common Issues

1. **"Networks configuration file not found"**
   - Copy `networks.example.json` to `networks.json`
   - Configure your IRC networks

2. **"Missing required environment variables"**
   - Copy `.env.example` to `.env`
   - Add your `GEMINI_API_KEY`

3. **Database errors**
   - Ensure write permissions to `data/databases/`
   - Databases are created automatically

4. **Connection failures**
   - Verify IRC server details in `networks.json`
   - Check SSL settings and ports
   - Review logs in `data/logs/`

### Logging

Logs are organized by network and component:
- `data/logs/irc_networks/{network}/` - Bot logs
- `data/logs/security/` - Security events
- `data/logs/website/` - Web interface logs

## Development

### Project Structure
```
PyBorg/
├── bot_v2.py              # Main bot entry point
├── setup.py               # Interactive setup wizard
├── test_setup.py         # Setup validation script
├── core/                  # Core bot functionality
│   ├── config.py         # Configuration management
│   ├── database.py       # Database operations
│   ├── plugin_system.py  # Plugin loading
│   └── paths.py          # Path management
├── plugins/              # Bot commands
│   ├── ai_commands.py    # AI integration
│   ├── game_commands.py  # Interactive games
│   ├── basic_commands.py # Utility commands
│   └── ...
├── web/                  # Web interface
│   ├── admin_styled.php  # Main admin panel
│   ├── api/              # REST API endpoints
│   ├── css/              # Stylesheets
│   └── js/               # JavaScript
├── data/                 # Data directory
│   ├── databases/        # SQLite databases
│   └── logs/             # Log files
├── networks.json         # Network configuration
└── .env                  # Environment variables
```

### Adding New Commands
1. Create function with `@command` decorator
2. Add to existing plugin file or create new one
3. Implement `setup_plugin()` function
4. Bot auto-loads on startup

### Testing
```bash
pytest                           # Run all tests
pytest --cov=core --cov=plugins # With coverage
pytest -m "not slow"            # Skip slow tests
```

### Code Quality
```bash
black .                    # Format code
flake8                     # Lint code
mypy core/ plugins/        # Type checking
```

## Deployment

### Production Deployment
```bash
# Manual per-network
python bot_v2.py network1 &
python bot_v2.py network2 &
```

### Docker (Community)
Community Docker images may be available - check repository releases.

### Systemd Service
Create service files for automatic startup and management.

## API Reference

### REST API Endpoints
- `GET /api/bot_status.php` - Bot status
- `GET /api/realtime_events.php` - SSE event stream
- `POST /api/bot_config.php` - Configuration management
- `GET /api/uno_leaderboard.php` - Game statistics

### Plugin API
- `@command()` decorator for commands
- `BotDatabase` class for data persistence
- Message context with user, channel, network info
- Rate limiting and admin controls

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Support

- Documentation: Check this README and code comments
- Bug Reports: Use GitHub Issues
- Feature Requests: Use GitHub Issues
- Development: Fork and submit PRs

## Credits

Built with love by the IRC community. Special thanks to all contributors and plugin developers.
"""API and web-based commands for the IRC bot"""

import requests
import logging
import json
import os
import random
from datetime import datetime
from bs4 import BeautifulSoup
from core.plugin_system import command

logger = logging.getLogger(__name__)

@command(
    pattern=r'weather',
    description="Get weather information",
    usage="weather <location>",
    category="api"
)
def weather(msg):
    """Get weather information"""
    try:
        parts = msg["message"].split(" ", 1)
        if len(parts) < 2:
            return "Usage: weather <location>"
        
        location = parts[1].strip()
        # This would need a weather API key - returning placeholder for now
        return f"Weather for {location}: Feature coming soon (needs weather API key)"
    except Exception as e:
        logger.error(f"Weather error: {e}")
        return "Weather service unavailable"

@command(
    pattern=r'hats',
    description="Check if Twitch streamer is online",
    usage="hats <username>",
    category="api"
)
def twitch(msg):
    """Check Twitch stream status"""
    try:
        parts = msg["message"].split()
        if len(parts) < 2:
            return "Hats allowed always. hats <username> to check stream"
        
        username = parts[1]
        client_id = os.getenv('TWITCH_CLIENT_ID')
        client_secret = os.getenv('TWITCH_CLIENT_SECRET')
        
        if not client_id or not client_secret:
            return f"Twitch API not configured"
        
        # Get OAuth token
        token_url = "https://id.twitch.tv/oauth2/token"
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        token_response = requests.post(token_url, data=token_data)
        
        if token_response.status_code != 200:
            return f"Failed to get Twitch API token"
        
        access_token = token_response.json()["access_token"]
        
        # Check stream status
        stream_url = f"https://api.twitch.tv/helix/streams?user_login={username}"
        headers = {
            "Client-ID": client_id,
            "Authorization": f"Bearer {access_token}"
        }
        
        response = requests.get(stream_url, headers=headers)
        
        if response.status_code != 200:
            return f"Failed to check stream status"
        
        data = response.json()
        if len(data["data"]) > 0:
            return f'{username} is online! https://www.twitch.tv/{username}'
        else:
            # Add zero-width character to avoid highlights
            fixed_name = username[0] + "\u200B" + username[1:] if len(username) > 1 else username
            return f'{fixed_name} is offline.'
            
    except Exception as e:
        logger.error(f"Twitch error: {e}")
        return "Twitch service unavailable"

@command(
    pattern=r'iss$',
    description="Get current ISS location",
    category="api"
)
def ISS(msg):
    """Get International Space Station location"""
    try:
        response = requests.get("http://api.open-notify.org/iss-now.json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            lat = data['iss_position']['latitude']
            lon = data['iss_position']['longitude']
            timestamp = data['timestamp']
            dt = datetime.fromtimestamp(timestamp)
            return f"ISS is currently at {lat}°, {lon}° (as of {dt.strftime('%H:%M:%S')})"
        else:
            return "ISS tracking unavailable"
    except Exception as e:
        logger.error(f"ISS error: {e}")
        return "ISS service unavailable"

@command(
    pattern=r'dog$',
    description="Get random dog picture",
    category="api"
)
def dogs(msg):
    """Get random dog picture"""
    try:
        response = requests.get("https://dog.ceo/api/breeds/image/random", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return f"🐕 {data['message']}"
        else:
            return "Dog service unavailable"
    except Exception as e:
        logger.error(f"Dog API error: {e}")
        return "Woof! Service unavailable"

@command(
    pattern=r'cat$',
    description="Get random cat picture",
    category="api"
)
def cat(msg):
    """Get random cat picture"""
    try:
        response = requests.get("https://api.thecatapi.com/v1/images/search", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return f"🐱 {data[0]['url']}"
        else:
            return "Cat service unavailable"
    except Exception as e:
        logger.error(f"Cat API error: {e}")
        return "Meow! Service unavailable"

@command(
    pattern=r'fox$',
    description="Get random fox picture",
    category="api"
)
def fox(msg):
    """Get random fox picture"""
    try:
        response = requests.get("https://randomfox.ca/floof/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return f"🦊 {data['image']}"
        else:
            return "Fox service unavailable"
    except Exception as e:
        logger.error(f"Fox API error: {e}")
        return "Fox service unavailable"

@command(
    pattern=r'duck$',
    description="Get random duck picture",
    category="api"
)
def duck(msg):
    """Get random duck picture"""
    try:
        response = requests.get("https://random-d.uk/api/random", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return f"🦆 {data['url']}"
        else:
            return "Duck service unavailable"
    except Exception as e:
        logger.error(f"Duck API error: {e}")
        return "Quack! Service unavailable"

@command(
    pattern=r'bankhol$',
    description="Get UK bank holidays",
    category="api"
)
def bankhol(msg):
    """Get UK bank holidays"""
    try:
        response = requests.get("https://www.gov.uk/api/bank-holidays", timeout=10)
        if response.status_code == 200:
            data = response.json()
            events = data['england-and-wales']['events'][:3]  # Next 3 holidays
            holidays = []
            for event in events:
                holidays.append(f"{event['title']}: {event['date']}")
            return f"Next UK bank holidays: " + " | ".join(holidays)
        else:
            return "Bank holiday service unavailable"
    except Exception as e:
        logger.error(f"Bank holiday error: {e}")
        return "Bank holiday service unavailable"

@command(
    pattern=r'moon$',
    description="Get current moon phase",
    category="api"
)
def get_moon_emoji(msg):
    """Get current moon phase emoji"""
    try:
        from astral import moon
        phase = moon.phase(datetime.now())
        
        # Convert moon phase to emoji
        moon_emojis = ["🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"]
        emoji_index = int(phase / 3.69)  # 8 phases over ~29.5 days
        if emoji_index >= len(moon_emojis):
            emoji_index = len(moon_emojis) - 1
            
        phase_names = ["New Moon", "Waxing Crescent", "First Quarter", "Waxing Gibbous", 
                      "Full Moon", "Waning Gibbous", "Last Quarter", "Waning Crescent"]
        
        return f"{moon_emojis[emoji_index]} {phase_names[emoji_index]} (phase: {phase:.1f})"
    except Exception as e:
        logger.error(f"Moon phase error: {e}")
        return "🌙 Moon phase unavailable"

@command(
    pattern=r'sun$',
    description="Get sunrise/sunset times",
    category="api"
)
def sun(msg):
    """Get sunrise/sunset information"""
    try:
        # This would need location API - placeholder for now
        return "🌅 Sunrise/sunset times: Feature coming soon (needs location API)"
    except Exception as e:
        logger.error(f"Sun times error: {e}")
        return "Sun times unavailable"

@command(
    pattern=r'gdq$',
    description="Get Games Done Quick information",
    category="api"
)
def gdq(msg):
    """Get GDQ information"""
    try:
        # This would scrape GDQ website - placeholder for now
        return "🎮 GDQ info: Feature coming soon"
    except Exception as e:
        logger.error(f"GDQ error: {e}")
        return "GDQ service unavailable"

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
    logger.info("API commands plugin loaded")
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
            
            # Try to reverse geocode the coordinates to get location name
            try:
                # First try OpenStreetMap Nominatim
                url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}"
                headers = {'User-Agent': 'PyBorg IRC Bot/1.0'}  # Nominatim requires user agent
                geo_response = requests.get(url, headers=headers, timeout=5)
                geo_data = geo_response.json()
                
                if 'address' in geo_data and 'country' in geo_data['address']:
                    location_name = geo_data['address']['country']
                    # Add more specific location if available
                    if 'state' in geo_data['address']:
                        location_name = f"{geo_data['address']['state']}, {location_name}"
                    elif 'region' in geo_data['address']:
                        location_name = f"{geo_data['address']['region']}, {location_name}"
                    return f"ISS flying over: {location_name} (as of {dt.strftime('%H:%M:%S')})"
            except Exception as geo_error:
                # If primary geocoding fails, try fallback service
                try:
                    fallback_url = f"https://geocode.xyz/{lat},{lon}?json=1"
                    fallback_response = requests.get(fallback_url, timeout=5)
                    fallback_data = fallback_response.json()
                    
                    if 'suggestion' in fallback_data and 'subregion' in fallback_data['suggestion']:
                        location_name = fallback_data['suggestion']['subregion']
                        return f"ISS flying over: {location_name} (as of {dt.strftime('%H:%M:%S')})"
                except:
                    pass  # Fall through to coordinates display
            
            # If reverse geocoding fails or returns ocean, show coordinates
            return f"ISS position: {lat}°, {lon}° (likely over ocean, as of {dt.strftime('%H:%M:%S')})"
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
    pattern=r'bird$',
    description="Get random bird picture",
    category="api"
)
def bird(msg):
    """Get random bird picture"""
    try:
        # Use Flickr's public feed API for bird images
        # This doesn't require authentication and provides high-quality bird photos
        params = {
            'tags': 'bird,birds,wildlife,birdphotography,ornithology',
            'tagmode': 'any',
            'format': 'json',
            'nojsoncallback': '1'
        }
        
        response = requests.get(
            "https://api.flickr.com/services/feeds/photos_public.gne",
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if 'items' in data and data['items']:
                # Get a random item from the feed
                import random
                item = random.choice(data['items'])
                
                # Extract the larger image URL (change _m to _b for bigger size)
                image_url = item['media']['m']
                # Replace _m with _b for a larger image
                image_url = image_url.replace('_m.jpg', '_b.jpg')
                
                # Get the title for context
                title = item.get('title', 'Bird photo')
                # Clean up the title if it's too long
                if len(title) > 50:
                    title = title[:47] + "..."
                
                return f"🐦 {title}: {image_url}"
            else:
                # Fallback to the original API if Flickr fails
                headers = {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
                fallback_response = requests.get(
                    "https://some-random-api.com/animal/bird",
                    headers=headers,
                    timeout=5
                )
                if fallback_response.status_code == 200:
                    fallback_data = fallback_response.json()
                    if 'image' in fallback_data:
                        return f"🐦 {fallback_data['image']}"
                
                return "No bird images available"
        else:
            # Try fallback API
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
            fallback_response = requests.get(
                "https://some-random-api.com/animal/bird",
                headers=headers,
                timeout=5
            )
            if fallback_response.status_code == 200:
                fallback_data = fallback_response.json()
                if 'image' in fallback_data:
                    return f"🐦 {fallback_data['image']}"
            
            return "Bird service unavailable"
    except Exception as e:
        logger.error(f"Bird API error: {e}")
        return "Tweet! Service unavailable"

@command(
    pattern=r'birdfact$',
    description="Get random bird fact",
    category="api"
)
def birdfact(msg):
    """Get random bird fact"""
    try:
        headers = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        response = requests.get("https://some-random-api.com/animal/bird", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'fact' in data:
                return f"🐦 Bird fact: {data['fact']}"
            else:
                return "No bird facts available"
        else:
            return "Bird fact service unavailable"
    except Exception as e:
        logger.error(f"Bird fact API error: {e}")
        return "Bird fact service unavailable"

@command(
    pattern=r'addbean',
    description="Add a bean image URL to the database",
    usage="addbean <url> [description]",
    category="api",
    requires_bot=True
)
async def addbean(msg, bot=None):
    """Add a bean image URL to the database"""
    try:
        parts = msg["message"].split(" ", 2)
        if len(parts) < 2:
            return "Usage: addbean <url> [description]"
        
        url = parts[1].strip()
        description = parts[2] if len(parts) > 2 else None
        
        # Basic URL validation
        if not (url.startswith('http://') or url.startswith('https://')):
            return "Please provide a valid URL starting with http:// or https://"
        
        # Add to database
        result = bot.database.add_bean_image(url, msg["user"], msg.get("channel"), description)
        
        if result == -1:
            return "🫘 That bean URL is already in the database!"
        else:
            count = bot.database.get_bean_image_count()
            return f"🫘 Bean added successfully! Database now has {count} delicious beans."
            
    except Exception as e:
        logger.error(f"Add bean error: {e}")
        return "🫘 Failed to add bean - please try again"

@command(
    pattern=r'beans$',
    description="Get random bean picture from database",
    category="api",
    requires_bot=True
)
async def beans(msg, bot=None):
    """Get random bean picture from database"""
    try:
        # Try to get a bean from the database first
        bean_data = bot.database.get_random_bean_image()
        
        if bean_data:
            # We have a bean from the database!
            response = f"🫘 {bean_data['url']}"
            
            # Add attribution if available
            if bean_data.get('added_by'):
                response += f" (added by {bean_data['added_by']}"
                if bean_data.get('view_count', 0) > 1:
                    response += f", viewed {bean_data['view_count']} times"
                response += ")"
            
            # Add description if available
            if bean_data.get('description'):
                response += f" - {bean_data['description']}"
                
            return response
        else:
            # No beans in database, provide helpful message
            count = bot.database.get_bean_image_count()
            return f"🫘 No beans in database yet! Use '!addbean <url>' or '~addbean <url>' to add some delicious bean pictures. Current count: {count}"
            
    except Exception as e:
        logger.error(f"Beans error: {e}")
        return "🫘 Bean service unavailable"

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

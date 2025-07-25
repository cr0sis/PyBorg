"""AI and conversational commands for the IRC bot"""

import logging
import google.generativeai as genai
import os
from core.plugin_system import command

logger = logging.getLogger(__name__)

# Configure Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

@command(
    pattern=r'speak',
    description="Chat with AI (Gemini)",
    usage="speak <message> or just 'speak' to respond to recent chat",
    category="ai",
    requires_bot=True
)
async def ai_chat_gemini_with_context(msg, bot=None):
    """AI chat using Google Gemini with context - returns list for multi-line responses"""
    try:
        # Get database connection
        from core.database import BotDatabase
        import tempfile
        import os
        
        # Get network name from command prefix
        network = 'libera' if msg["message"].startswith('~') else 'rizon'
        db = BotDatabase(f"{network}_bot.db")
        
        # Get conversation history from database
        conversation_history_list = db.get_conversation_history(msg["user"], limit=3)
        conversation_history = {}
        conversation_history[msg["user"]] = []
        for item in conversation_history_list:
            if item['message']:
                conversation_history[msg["user"]].append(f"User: {item['message']}")
            if item['response']:
                conversation_history[msg["user"]].append(f"Bot: {item['response']}")
        
        # Get chat context from bot instance
        chat_context = bot.chat_context if bot and hasattr(bot, 'chat_context') else []
        
        logging.info(f"AI chat request from {msg['user']}: {msg['message']}")
        m = msg["message"]
        user = msg["user"]
        parts = m.split(" ", 1)

        # Check if user provided input or wants to respond to recent chat
        if len(parts) < 2 or not parts[1].strip():
            # No input provided - respond to recent conversation
            if not chat_context:
                # Get network-specific prefix
                from core.config import get_config
                network = 'libera' if msg["message"].startswith('~') else 'rizon'
                config = get_config(network)
                prefix = config.COMMAND_PREFIX
                return f"No recent conversation to respond to. Use: {prefix}speak <your message>"

            # Use recent chat context as the topic to respond to
            recent_chat = "\n".join(chat_context[-5:])  # Last 5 messages
            prompt_mode = "context_response"
            user_input = None
        else:
            # User provided input
            user_input = parts[1].strip()
            prompt_mode = "direct_response"

        # Initialize user's conversation history if needed
        if user not in conversation_history:
            conversation_history[user] = []

        # Add user input to personal history if provided
        if user_input:
            conversation_history[user].append(f"User: {user_input}")
            if len(conversation_history[user]) > 3:
                conversation_history[user] = conversation_history[user][-3:]

        model = genai.GenerativeModel('gemini-1.5-pro')
        recent_chat = "\n".join(chat_context[-10:]) if chat_context else "No recent chat"
        personal_history = "\n".join(conversation_history[user])

        # Get AI prompt from environment or use default
        from core.config import BotConfig
        config = BotConfig()
        
        if prompt_mode == "context_response":
            # Respond to recent conversation
            context_prompt = os.getenv('GEMINI_CONTEXT_PROMPT', """You are a helpful AI assistant in an IRC channel.
You provide thoughtful responses to ongoing conversations.
Keep responses conversational and relevant to the recent chat.
Don't introduce yourself or mention that you're an AI unless asked.

Recent channel chat:
{recent_chat}

Look at the recent conversation and provide a relevant comment, insight, or response that continues the discussion naturally. Don't just summarize - add something meaningful to the conversation.

Bot:""")
            prompt = context_prompt.format(recent_chat=recent_chat)
        else:
            # Direct response to user input
            direct_prompt = os.getenv('GEMINI_DIRECT_PROMPT', """You are a helpful AI assistant in an IRC channel.
You provide thoughtful and helpful responses to user questions.
Keep responses conversational and informative.
Don't introduce yourself or mention that you're an AI unless asked.

Recent channel chat:
{recent_chat}

Your conversation with {user}:
{personal_history}

User: {user_input}

Bot:""")
            prompt = direct_prompt.format(recent_chat=recent_chat, user=user, personal_history=personal_history, user_input=user_input)

        generation_config = genai.types.GenerationConfig(
            temperature=0.7,
            top_p=0.8,
            top_k=30,
            max_output_tokens=1500,  # Increased for multi-line responses
        )

        logging.info(f"Sending prompt to Gemini...")
        response = model.generate_content(prompt, generation_config=generation_config)
        ai_response = response.text.strip()

        # Split response into lines for IRC
        lines = ai_response.split('\n')
        processed_lines = []

        for line in lines:
            line = line.strip()
            if line:  # Skip empty lines
                # If line is too long, split it
                if len(line) > 400:
                    words = line.split()
                    current_line = ""
                    for word in words:
                        if len(current_line + " " + word) <= 400:
                            current_line += " " + word if current_line else word
                        else:
                            if current_line:
                                processed_lines.append(current_line)
                            current_line = word
                    if current_line:
                        processed_lines.append(current_line)
                else:
                    processed_lines.append(line)

        # Limit to reasonable number of lines to avoid spam
        if len(processed_lines) > 11:
            processed_lines = processed_lines[:11]

        # Store in database
        full_response = "\n".join(processed_lines)
        db.store_conversation(user, user_input or "context_response", full_response)

        logging.info(f"AI response generated: {len(processed_lines)} lines")
        return processed_lines  # Return as list for multi-line handling

    except Exception as e:
        error_msg = str(e) if str(e) else f"Unknown error: {type(e).__name__}"
        logging.error(f"AI error: {error_msg}")
        return [f"AI error: {error_msg}"]

@command(
    pattern=r'speakclear$',
    description="Clear your AI conversation history",
    category="ai"
)
def clear_ai_history(msg):
    """Clear AI conversation history for the user"""
    try:
        from core.database import BotDatabase
        import os
        
        network = 'libera' if msg["message"].startswith('~') else 'rizon'
        db = BotDatabase(f"{network}_bot.db")
        
        user = msg["user"]
        db.clear_conversation_history(user)
        return f"{user}: Your AI conversation history has been cleared."
    except Exception as e:
        logging.error(f"Error clearing AI history: {e}")
        return "Error clearing conversation history."

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
    logger.info("AI commands plugin loaded")
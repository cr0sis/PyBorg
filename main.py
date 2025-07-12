#!/usr/bin/env python3 -u
import config
import utility
import socket
import time
import re
import json
import os
import sys
import logging
import signal
from datetime import datetime
import functools

print = functools.partial(print, flush=True)
sys.stdout.reconfigure(line_buffering=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

IGNORED_NICKS = {"Global", "nibblrjr", "nibblrjr1"}
IGNORED_HOSTMASKS = {"thinkin.bout.those beans"}


def parse_message(line):
    pattern = re.compile(
        r":(?P<user>.*?)\!\~?(?P<hostmask>.*?) (?P<type>\S+) (?P<channel>\S+) :(?P<message>.*)"
    )
    match = pattern.search(line)
    if match:
        return match.groupdict()
    return False


def should_ignore_message(message):
    if message["user"] in IGNORED_NICKS:
        return True
    if any(hostmask in message["hostmask"] for hostmask in IGNORED_HOSTMASKS):
        logging.info(f"Ignoring message from hostmask: {message['hostmask']}")
        return True
    return False


def load_links(filename="links.json"):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            return json.load(file)
    return {}


def save_links(links, filename="links.json"):
    with open(filename, "w") as file:
        json.dump(links, file, indent=4)


def check_and_store_link(user, link, filename="links.json"):
    links = load_links(filename)
    link_lower = link.lower()

    if link_lower in links:
        original_user, original_time = links[link_lower]
        if user == original_user:
            return None
        if user == "Morteh":
            return f"Link originally shared by Morteh just now, not {original_user} on {original_time}"
        else:
            return f"Link originally shared by {original_user} on {original_time}"

    current_time = datetime.now().strftime("%d-%m-%Y at %H:%M:%S")
    links[link_lower] = (user, current_time)
    save_links(links, filename)
    return None


def convert_temperature(text):
    temp_matches = re.findall(r"(-?\d+(?:\.\d+)?)([cCfF])", text)
    if len(temp_matches) != 1:
        return None
    value_str, unit = temp_matches[0]
    value = float(value_str)
    if unit.lower() == "c":
        converted = value * 9 / 5 + 32
        return f"{value:.1f}°C = {converted:.1f}°F"
    else:
        converted = (value - 32) * 5 / 9
        return f"{value:.1f}°F = {converted:.1f}°C"


class IRCBot:
    def __init__(self):
        self.s = None
        self.connected = False
        self.joined = False
        self.last_pong_time = time.time()
        self.pong_timeout = 300

    def connect(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((config.HOST, config.PORT))
            self.connected = True
            self.s.send(("USER {}\r\n".format(config.USER)).encode("utf-8"))
            self.s.send(("NICK {}\r\n".format(config.NICK)).encode("utf-8"))
            logging.info("Connected to IRC server")
        except Exception as e:
            logging.error(f"Failed to connect: {e}")
            self.connected = False

    def join_channels(self):
        if not self.connected:
            return
        self.s.send(("PASS {}\r\n".format(config.PASS)).encode("utf-8"))
        for channel in config.CHANNELS:
            self.s.send(("JOIN {}\r\n".format(channel)).encode("utf-8"))
        logging.info("Joined channels")

    def restart_bot(self):
        logging.info("Restarting bot...")
        self.joined = False
        if self.s:
            self.s.close()
        os.execv(sys.executable, ["python3"] + sys.argv)

    def restart_on_crash(self):
        logging.error("Bot crashed. Restarting...")
        self.restart_bot()

    def should_ignore(self, message):
        return should_ignore_message(message)

    import config
import utility
import socket
import time
import re
import json
import os
import sys
import signal
import logging
from datetime import datetime
import functools

print = functools.partial(print, flush=True)
sys.stdout.reconfigure(line_buffering=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class RateLimiter:
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()

    def allowed(self):
        now = time.time()
        self.allowance += (now - self.last_check) * (self.rate / self.per)
        self.last_check = now
        if self.allowance > self.rate:
            self.allowance = self.rate
        if self.allowance < 1.0:
            return False
        self.allowance -= 1.0
        return True

TRUSTED_RESTART = [
    ("cr0sis", r".*@cr0s\.is$")
]

def is_authorised_restart(user, hostmask):
    return any(user == nick and re.match(mask_pat, hostmask) for nick, mask_pat in TRUSTED_RESTART)

def parse_message(line):
    res = re.search(r":(.*)!~?(.*) (.*) (.*) :(.*)", line)
    if res:
        return {
            'user': res.group(1),
            'hostmask': res.group(2),
            'type': res.group(3),
            'channel': res.group(4),
            'message': res.group(5)
        }
    return False

def load_links(filename='links.json'):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return {}

def save_links(links, filename='links.json'):
    with open(filename, 'w') as file:
        json.dump(links, file, indent=4)

def check_and_store_link(user, link, filename='links.json'):
    links = load_links(filename)
    link = link.lower()
    if link in links:
        original_user, original_time = links[link]
        if user == original_user:
            return None
        if user == "Morteh":
            return f"Link originally shared by Morteh just now, not {original_user} on {original_time}"
        else:
            return f"Link originally shared by {original_user} on {original_time}"
    current_time = datetime.now().strftime('%d-%m-%Y at %H:%M:%S')
    links[link] = (user, current_time)
    save_links(links, filename)
    return None

def should_ignore_message(message):
    ignored_nicks = ["Global", "nibblrjr", "nibblrjr1"]
    ignored_hostmasks = ["thinkin.bout.those.beans"]
    if message["user"] in ignored_nicks:
        return True
    if any(ignored_hostmask in message["hostmask"] for ignored_hostmask in ignored_hostmasks):
        logging.info(f"Ignoring message from: {message['hostmask']}")
        return True
    return False

class IRCBot:
    def __init__(self):
        self.s = socket.socket()
        self.limiter = RateLimiter(4, 8)  # 4 messages per 8 seconds
        self.connected = False

    def connect(self):
        try:
            self.s.connect((config.HOST, config.PORT))
            self.connected = True
            self.s.send((f"USER {config.USER}\n").encode("utf-8"))
            self.s.send((f"NICK {config.NICK}\n").encode("utf-8"))
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            self.connected = False

    def safe_chat(self, text, channel):
        if self.limiter.allowed():
            utility.chat(self.s, text, channel)

    def join_channels(self):
        self.s.send((f"PASS {config.PASS}\r\n").encode("utf-8"))
        for channel in config.CHANNELS:
            self.s.send((f"JOIN {channel}\r\n").encode("utf-8"))

    def restart_bot(self):
        logging.info("Restarting bot…")
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.s.close()
        os.execv(sys.executable, ['python3'] + sys.argv)

    def handle_message(self, message):
        if should_ignore_message(message):
            return

        text = message["message"].strip()

        if text == "!restart" and is_authorised_restart(message["user"], message["hostmask"]):
            self.safe_chat("Restarting the bot...", message["channel"])
            self.restart_bot()
            return

        # ── temperature conversion ───────────────────────────────
        temp_matches = re.findall(r'(?<!\S)(-?\d{1,3}(?:\.\d+)?)([cCfF])(?=\s|$|[!?;,.\)])', text)
        if len(temp_matches) == 1:
            value_str, unit = temp_matches[0]
            value = float(value_str)
            if unit.lower() == 'c':
                converted = value * 9 / 5 + 32
                reply = f"{value:.1f}°C = {converted:.1f}°F"
            else:
                converted = (value - 32) * 5 / 9
                reply = f"{value:.1f}°F = {converted:.1f}°C"
            self.safe_chat(reply, message["channel"])
            return

        # ── link deduplication ───────────────────────────────────
        url_pattern = re.compile(r'https?://\S+', re.IGNORECASE)
        urls = re.findall(url_pattern, text)
        for url in urls:
            reply = check_and_store_link(message["user"], url)
            if reply:
                self.safe_chat(reply, message["channel"])

        # ── other commands ───────────────────────────────────────
        for pattern in config.COMMANDS:
            if re.search(pattern[0], text):
                self.safe_chat(pattern[1](message), message["channel"])
                break


    def bot_loop(self):
        buffer = ""
        joined = False
        last_pong_time = time.time()
        pong_timeout = 300

        while self.connected:
            try:
                data = self.s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    continue
                buffer += data
                while "\r\n" in buffer:
                    line, buffer = buffer.split("\r\n", 1)
                    print(line)
                    if line.startswith("PING"):
                        self.s.send(("PONG " + line.split()[1] + "\r\n").encode("utf-8"))
                        last_pong_time = time.time()
                        if not joined:
                            self.join_channels()
                            joined = True
                        continue
                    message = parse_message(line)
                    if message:
                        try:
                            self.handle_message(message)
                        except Exception as e:
                            logging.error(f"Error in message handler: {e}")

                if time.time() - last_pong_time > pong_timeout:
                    logging.warning("No PONG in 5 min. Reconnecting…")
                    self.restart_bot()

            except socket.error as e:
                logging.error(f"Socket error: {e}")
                self.restart_bot()
            except Exception as e:
                logging.exception("Unhandled exception")
                self.restart_bot()

bot = IRCBot()

def signal_handler(sig, frame):
    logging.info("Interrupt received, shutting down.")
    try:
        if bot.s:
            bot.s.shutdown(socket.SHUT_RDWR)
            bot.s.close()
    except Exception:
        pass
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    try:
        bot.connect()
        bot.bot_loop()
    except Exception as e:
        logging.exception("Fatal crash:")


    def bot_loop(self):
        buffer = ""
        while self.connected:
            try:
                data = self.s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    continue

                buffer += data
                while "\r\n" in buffer:
                    line, buffer = buffer.split("\r\n", 1)
                    logging.debug(f"Received line: {line}")

                    if line.startswith("PING"):
                        self.s.send(("PONG " + line.split()[1] + "\r\n").encode("utf-8"))
                        self.last_pong_time = time.time()
                        if not self.joined:
                            self.join_channels()
                            self.joined = True
                        continue

                    message = parse_message(line)
                    if message:
                        self.handle_message(message)

                # Check pong timeout
                if time.time() - self.last_pong_time > self.pong_timeout:
                    logging.warning("No PONG received for 5 minutes. Reconnecting...")
                    self.s.close()
                    self.restart_bot()

            except socket.timeout:
                logging.warning("Socket timeout occurred.")
                self.restart_bot()
            except socket.error as e:
                logging.error(f"Socket error: {e}")
                self.restart_bot()
            except Exception as e:
                logging.error(f"Unhandled exception: {e}", exc_info=True)
                self.restart_on_crash()


def signal_handler(sig, frame):
    logging.info("Shutdown signal received. Closing socket...")
    try:
        bot.s.close()
    except Exception:
        pass
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    bot = IRCBot()
    bot.connect()
    try:
        bot.bot_loop()
    except Exception as e:
        logging.error(f"EXCEPTION: {e}", exc_info=True)

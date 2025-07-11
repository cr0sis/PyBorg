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

    def handle_message(self, message):
        if self.should_ignore(message):
            return

        logging.info(f"{message['user']}: {message['message']}")

        # Temperature conversion
        reply = convert_temperature(message["message"])
        if reply:
            utility.chat(self.s, reply, message["channel"])
            return

        # Check links
        url_pattern = re.compile(r"https?://\S+", re.IGNORECASE)
        urls = re.findall(url_pattern, message["message"])
        for url in urls:
            reply = check_and_store_link(message["user"], url)
            if reply:
                utility.chat(self.s, reply, message["channel"])

        # Restart command
        if message["user"] == "cr0sis" and message["message"].strip() == "!restart":
            utility.chat(self.s, "Restarting the bot...", message["channel"])
            self.restart_bot()

        # Match commands
        for pattern, func in config.COMMANDS:
            if re.search(pattern, message["message"]):
                utility.chat(self.s, func(message), message["channel"])
                break

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

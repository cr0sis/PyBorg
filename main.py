#!/usr/bin/env python
import config
import utility
import socket
import time
import re

CHAT_MSG = re.compile(r"^:\w+!\w+@\w+\.tmi\.twitch\.tv PRIVMSG #\w+ :")

try:
    s = socket.socket()
    s.connect((config.HOST, config.PORT))
    s.send("NICK {}\r\n".format(config.NICK).encode("utf-8"))
    s.send("PASS {}\r\n".format(config.PASS).encode("utf-8"))
    s.send("USER {}\r\n".format(config.USER).encode("utf-8"))
    s.send("JOIN {}\r\n".format(config.CHAN).encode("utf-8"))
    connected = True #Socket succefully connected
except Exception as e:
    print(str(e))
    connected = False #Socket failed to connect

def deEmojify(response):
    regrex_pattern = re.compile(pattern = "["
        u"\u2018-\u2019"          # quotations
        u"\U0001F600-\U0001F64F"  # emoticons
        u"\U0001F300-\U0001F5FF"  # symbols & pictographs
        u"\U0001F680-\U0001F6FF"  # transport & map symbols
        u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
                           "]+", flags = re.UNICODE)
    return regrex_pattern.sub(r'',response)

def bot_loop():
    while connected:
        response = s.recv(1024).decode("utf-8")
        if response[0:4] == "PING":
            print(response)
	    s.send("PONG" + response.split() [ 1  ] + "\r\n".encode("utf-8"))
            print("Pong")
        else:
            username = re.search(r"\w+", response).group(0) 
            message = CHAT_MSG.sub("", response)
            print(username + ": " + (deEmojify(response)))
            for pattern in config.COMMANDS:
                if re.search(pattern[0], message):
                    utility.chat(s, pattern[1])
                    break
        time.sleep(1 / config.RATE)
if __name__ == "__main__":
    bot_loop()

#!/usr/bin/env python3
import config
import utility
import socket
import time
import re

CHAT_MSG = re.compile(r"^:\w+!\w+@\w+\.tmi\.twitch\.tv PRIVMSG #\w+ :")

try:
    s = socket.socket()
    s.connect((config.HOST, config.PORT))
    s.send(("NICK {}\r\n".format(config.NICK)).encode("utf-8"))
    s.send(("PASS {}\r\n".format(config.PASS)).encode("utf-8"))
    s.send(("USER {}\r\n".format(config.USER)).encode("utf-8"))
    s.send(("JOIN {}\r\n".format(config.CHAN)).encode("utf-8"))
    connected = True #Socket succefully connected

except Exception as e:
    print(str(e))
    connected = False #Socket failed to connect

def bot_loop():
    while connected:
        try:
            response = s.recv(1024).decode("utf-8")
        except Exception as e:
            print("An error occurred while receiving a message:", str(e))
            break
        if response[0:4] == "PING":
            print(response)
            s.send(("PONG " + response.split()[1] + "\r\n").encode("utf-8"))
            print("Pong")
        else:
            username = re.search(r"\w+", response).group(0)
            response = response.rstrip("\r\n")
            message = CHAT_MSG.sub("", response)
            print((username + ": " + response).encode("utf-8"))
            for pattern in config.COMMANDS:
                if re.search(pattern[0], message):
                    utility.chat(s, pattern[1](username, message))
                    break
        time.sleep(1 / config.RATE)
if __name__ == "__main__":
    try:
        bot_loop()
    except Exception as e:
        print(str(e))

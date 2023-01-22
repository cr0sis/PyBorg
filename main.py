#!/usr/bin/env python3
import config
import utility
import socket
import time
import re

try:
    s = socket.socket()
    s.connect((config.HOST, config.PORT))
    connected = True #Socket succefully connected
    s.send(("USER {}\n".format(config.USER)).encode("utf-8"))
    s.send(("NICK {}\n".format(config.NICK)).encode("utf-8"))

except Exception as e:
    print(str(e))
    print('there has been a problemo')
    connected = False #Socket failed to connect

def parse_message(line):
    res = re.search(r":(.*)\!\~?(.*) (.*) (.*) :(.*)", line)
    if(res != None):
        m = {
          'user': res.group(1),
          'hostmask': res.group(2),
          'type': res.group(3),
          'channel': res.group(4),
          'message': res.group(5)
        }

        return m
    else:
        return False

def bot_loop():
    joined = False
    while connected:
        # try:
        response = s.recv(1024).decode("utf-8")
        print(response)
        if response[0:4] == "PING":
            print("PONG " + response.split()[1] + "\r\n")
            s.send(("PONG " + response.split()[1] + "\r\n").encode("utf-8"))
            if (joined == False):
                s.send(("PASS {}\r\n".format(config.PASS)).encode("utf-8"))
                for channel in config.CHANNELS:
                  s.send(("JOIN {}\r\n".format(channel)).encode("utf-8"))
                  joined = True
        else:
            response = response.rstrip("\r\n")
            message = parse_message(response)
#           print(message.encode("utf-8"))
            if(message != False):
                print((message["user"] + ": " + message["message"]).encode("utf-8"))
                for pattern in config.COMMANDS:
                    if re.search(pattern[0], message["message"]):
                        utility.chat(s, pattern[1](message), message["channel"])
                        break
      
if __name__ == "__main__":
    try:
        bot_loop()
    except Exception as e:
        print("EXCEPTION: ", str(e))

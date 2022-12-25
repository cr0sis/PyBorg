import config
import socket
import time
import random
from datetime import date

def chat(sock, msg):
    """
    Send a chat message to the server.
    Keyword arguments:
    sock -- the socket over which to send the message
    msg  -- the message to be sent
    """
    sock.send(("PRIVMSG {} :{}\r\n".format(config.CHAN, msg)).encode("UTF-8"))

def report_in(u, m):
    return "Reporting *hic* in! [" + u'\U0001F40D' + "] https://cr0s.is/cr0bot.php"

def check_time(u, m):
    curr_time = time.strftime("%H:%M:%S", time.localtime())
    return curr_time


def check_date(u, m):
    today = date.today()
    d2 = today.strftime("%B %d, %Y")
    return d2

def jumble(word, m):
    word = str("GINGER")
    word = list(word)  # Convert the word to a list of characters
    random.shuffle(word)  # Shuffle the list of characters
    return ''.join(word)  # Join the list of characters back into a string and return it


def roll_dice(u, m):
    dice = [] # Initialize an empty list to store the dice rolls
    for i in range(7):
        roll = random.randint(1, 6)
        if roll == 1:
            dice.append("\x0313,15" + str(roll)) # Append the rolled value with IRC color codes for white background and pink text
        else:
            dice.append("\x0301,15" + str(roll)) # Append the rolled value with IRC color codes for white background and black text
        dice_str = " ".join(dice)
        int_dice = [int(x[6:]) for x in dice] # Remove the IRC color codes and convert to integer
        if i == 6:
            sum_dice = sum(int_dice)
            dice_str = "\x0301,15-".join(dice)
            return dice_str + "\x03 " + u + "\x03 rolled: \x0307" + str(sum_dice)

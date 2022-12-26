import config
import socket
import time
import random
import datetime
from gpiozero import CPUTemperature
import requests
import json
import ISS_Info

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

def temp(u, m):
    cpu = CPUTemperature()
    return "Temp: " + str(round(cpu.temperature, 1)) + "°C"


def check_date(u, m):
    today = date.today()
    d2 = today.strftime("%B %d, %Y")
    return d2 
'''
def check_date(u, m):
    today = date.today()
    d2 = today.strftime("%B %d, %Y")
    # Split the string into a list of words
    words = m.split()
    # Get the 5th word
    fifth_word = words[4]
    return d2 + fifth_word
'''

def random_choice(u, m):
    try:
        # Split the string into a list of words
        words = m.split()
        # Get the part of the list that contains the words before the | character
        first_option = words[4]
        # Get the part of the list that contains the words after the | character
        second_option = words[6]
        chosen_string = random.choice([first_option, second_option])
        return chosen_string
    except Exception as e:
        print(str(e))
        return "Not enough parameters: !random word | word"


def jumble(u, m):
    word = str("GINGER")
    word = list(word)  # Convert the word to a list of characters
    random.shuffle(word)  # Shuffle the list of characters
    return ''.join(word)  # Join the list of characters back into a string and return it

def ISS(u, m):
    location = ISS_Info.iss_current_loc()
    latitude = location['iss_position']['latitude']
    longitude = location['iss_position']['longitude']
    url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}"
    response = requests.get(url)
    data = response.json()
    try:
        return "Flying over: " + (data["address"]["country"])
    except Exception as e:
        return "Not over land, current lat,lon: " + str(latitude) + "," + str(longitude)
        #return "Flying over the: " + get_ocean(latitude, longitude)
        print(str(e))

def dogs(u, m):
    url = "https://dog.ceo/api/breeds/image/random"
    response = requests.get(url)
    data = response.json()
    try:
        return data["message"]
    except Exception as e:
        return str(e)

def fox(u, m):
    url = "https://randomfox.ca/floof/"
    response = requests.get(url)
    data = response.json()
    try:
        return data["image"]
    except Exception as e:
        return str(e)

def duck(u, m):
    url = "https://random-d.uk/api/random"
    response = requests.get(url)
    data = response.json()
    try:
        return data["url"]
    except Exception as e:
        return str(e)

def bankhol(u, m):
    response = requests.get('https://www.gov.uk/bank-holidays.json')
    data = response.json()
    now = datetime.datetime.now()
    next_holiday = None
    for holiday in data['england-and-wales']['events']:
        holiday_date = datetime.datetime.strptime(holiday['date'], '%Y-%m-%d')
        if holiday_date > now:
            next_holiday = holiday
            break
    if next_holiday:
        return (f'The next bank holiday is {next_holiday["title"]} on {next_holiday["date"]} {next_holiday["notes"]}')
    else:
        return 'There are no more bank holidays this year.'

'''
def get_ocean(latitude, longitude):
  if -90 <= float(latitude) <= 90 and -180 <= float(longitude) <= 180:
    if -90 <= float(latitude) <= -60:
      return "Southern Ocean"
    elif -60 < float(latitude) <= -30:
      return "Atlantic Ocean"
    elif -30 < float(latitude) <= 30:
      if -180 <= float(longitude) <= -60:
        return "Atlantic Ocean"
      elif -60 < float(longitude) <= 60:
        return "Indian Ocean"
      elif 60 < float(longitude) <= 180:
        return "Pacific Ocean"
    elif 30 < float(latitude) <= 90:
      return "Arctic Ocean"
  return
'''
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

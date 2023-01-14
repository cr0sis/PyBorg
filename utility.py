import config
import socket
import time
import random
import datetime
from datetime import date
from gpiozero import CPUTemperature
from datetime import datetime
import requests
import json
import ISS_Info
import os
from bs4 import BeautifulSoup
from astral import moon

headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '3600',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
    }

def chat(sock, msg, channel):
    if(type(msg) == str):
        sock.send(("PRIVMSG {} :{}\r\n".format(channel, msg)).encode("UTF-8"))
    elif(type(msg) == list):
        for m in msg:
            sock.send(("PRIVMSG {} :{}\r\n".format(channel, m)).encode("UTF-8"))
    time.sleep(1 / config.RATE)

def sun(msg):
    sun_list = ["🌞"]
    sun = True
    sun_list.append("Core temp: 15.5m°C Surface temp: 5'500°C Age:" + "\x02\x1D " + "OLD")
    return sun_list

def report_in(msg):
    return "Reporting *hic* in! [" + u'\U0001F40D' + "] https://cr0s.is/cr0bot.php"

def check_time(msg):
    curr_time = time.strftime("%H:%M:%S", time.localtime())
    return curr_time

def temp(msg):
    cpu = CPUTemperature()
    return "Temp: " + str(round(cpu.temperature, 1)) + "°C"

def check_date(msg):
    today = date.today()
    d2 = today.strftime("%B %d, %Y")

def gdq(msg):
    url="https://taskinoz.com/gdq/api/"
    response=requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    text=soup.get_text()
    return text

counter = 0
def get_moon_emoji(msg):
    global counter
    counter+=1
    phase_list=[]
    phase = moon.phase(datetime.now())
    phaser = round(phase, 2)
    phase = str(phaser)
    messages = [
        "Everybody look at the moon, everybody seein' the moon, the moon is bright, he's milky white, everybody look at the moon, uh!",
        "Heey! I did a song! Jupiter, I did a song! You ain't got one! Heey! Oh, I feel sick.",
        "When you are the moon, there is a person people say is the sun. I saw the sun once, and he came past me, really fast. And it was an, it was called, the, an eclipse. And he came fast! But as he came past, I, I licked his back.",
        "The average composition of the lunar surface by weight is roughly 43% oxygen, 20% silicon, 19% magnesium, 10% iron, 3% calcium, 3% aluminum, 0.42% chromium, 0.18% titanium and 0.12% manganese",
        "Daytime temperatures on the sunny side of the moon reach 273 degrees F (134 Celsius); on the night side, it gets as cold as minus 243 F (minus 153 C)",
        "Average distance from Earth: 238,855 miles (384,400 km)",
        "The moon is the fifth largest natural satellite in the Solar System, and the largest among planetary satellites relative to the size of the planet that it orbits.",
        "Perigee (closest approach to Earth): 225,700 miles (363,300 km)",
        "Apogee (farthest distance from Earth): 252,000 miles (405,500 km)",
        "Orbit circumference: 1,499,618.58 miles (2,413,402 km)",
        "Mean orbit velocity: 2,287 mph (3,680.5 kph)",
        "The most widely-accepted explanation is that the Moon was created when a rock the size of Mars slammed into Earth, shortly after the solar system began forming about 4.5 billion years ago.",
        "There is water on the moon in the form of ice trapped within dust and minerals on and under the surface. It has been detected on areas of the lunar surface that are in permanent shadow and are therefore very cold, enabling the ice to survive. The water on the Moon was likely delivered to the surface by comets.",
        "The moon very likely has a very small core, just 1% to 2% of the moon's mass and roughly 420 miles (680 km) wide. It likely consists mostly of iron, but may also contain large amounts of sulfur and other elements.",
        "The moon's rocky mantle is about 825 miles (1,330 km) thick and made up of dense rocks rich in iron and magnesium.",
        "The moon has only a very thin atmosphere, so a layer of dust — or a footprint — can sit undisturbed for centuries.",
        "From Earth, both the Sun and the Moon look about same size. In fact the Moon is 400 times smaller than the Sun, but also 400 times closer to Earth.",
        "The Moon is moving approximately 3.8 cm away from our planet every year.",
        "And he doesn't know I licked his back! All in his yellow suit!... I'm the moon.",
        "One time, I saw a man looking at me, yes, with his eyes. And then, he, he picked up a tube. And he looked, in the tube, and he made the moon big, inside the tube. The moon big inside a tube! ",
        "Here's a poem, from the Moon. Neil Armstrong, walking on my face. Buzz Aldrin, walking on my face. And the third one is a space man, walking on my face. All on the surfaces, and they're looking at all of the stuff that the moon has got.",
        "And some say, Old Gregg is like a, a big fish finger, but big! Like um, like a garage. As big as a garage. Imagine that fish finger, when you can see it is as big as a garage, oh! It isn't small, it's the big one! Like that.",
        "When you are the moon, the best form you can be is a full moon. And then the half moon... he's all right. But the full moon is the famous moon. And then three-quarters, eh, no one gives a sh*t about him. When does he come, two days in, to the calendar month? He's useless. Full moon. The moon. The main moon.",
]

    if phaser < 1.84566:
        phase_list=[u'\U0001F311' + " {" + phase + "} Total eclipse"]
    elif phaser < 5.53699:
        phase_list=[u'\U0001F312' + " {" + phase + "} Waxing crescent"]
    elif phaser < 9.22831:
        phase_list=[u'\U0001F313' + " {" + phase + "} First quarter"]
    elif phaser < 12.91963:
        phase_list=[u'\U0001F314' + " {" + phase + "} Waxing gibbous"]
    elif phaser < 16.61096:
        phase_list=[u'\U0001F315' + " {" + phase + "} Fuuull mooooon"]
    elif phaser < 20.30228:
        phase_list=[u'\U0001F316' + " {" + phase + "} Waning gibbous"]
    elif phaser < 23.99361:
        phase_list=[u'\U0001F317' + " {" + phase + "} Last quarter"]
    elif phaser < 27.68493:
        phase_list=[u'\U0001F318' + " {" + phase + "} Waning crescent"]
    else:
        phase_list=[u'\U0001F311' + " {" + phase + "} Total eclipse"]

    if counter == 7:
        counter = 0
        message_list=[random.choice(messages)]
        phase_list.append("".join(message_list))

    return phase_list

def report_in(msg):
    return "Reporting *hic* in! [" + u'\U0001F40D' + "] https://cr0s.is/cr0bot.php"

def check_time(msg):
    curr_time = time.strftime("%H:%M:%S", time.localtime())
    return curr_time

def temp(msg):
    cpu = CPUTemperature()
    return "Temp: " + str(round(cpu.temperature, 1)) + "°C"

def check_date(msg):
    today = date.today()
    d2 = today.strftime("%B %d, %Y")
    return d2

def random_choice(msg):
    u = msg["user"]
    m = msg["message"]
    try:
        # Split the string into a list of words
        words = m.split()
        # Get the part of the list that contains the words before the | character
        first_option = words[1]
        # Get the part of the list that contains the words after the | character
        second_option = words[3]
        chosen_string = random.choice([first_option, second_option])
        return chosen_string
    except Exception as e:
        print(str(e))
        return "Not enough parameters: !random word | word"

def jumble(msg):
    word = str("GINGER")
    word = list(word)  # Convert the word to a list of characters
    random.shuffle(word)  # Shuffle the list of characters
    return ''.join(word)  # Join the list of characters back into a string and return it

def ISS(msg):
    location = ISS_Info.iss_current_loc()
    latitude = location['iss_position']['latitude']
    longitude = location['iss_position']['longitude']
    url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}"
    response = requests.get(url)
    data = response.json()
    try:
        return "Flying over: " + (data["address"]["country"])
    except Exception as e:
        url = f"https://geocode.xyz/{latitude},{longitude}?json=1"
        response = requests.get(url)
        data = response.json()
        try:
            return "Flying over: " + (data["suggestion"]["subregion"])
        except Exception as e:
            return "Ocean info not found. Pos: " + str(latitude) + "," + str(longitude)
            print(str(e))

def lenny(msg):
    return (f"( ͡° ͜ʖ ͡°)")

def dogs(msg):
    url = "https://dog.ceo/api/breeds/image/random"
    response = requests.get(url)
    data = response.json()
    try:
        return data["message"]
    except Exception as e:
        return str(e)

def fox(msg):
    url = "https://randomfox.ca/floof/"
    response = requests.get(url)
    data = response.json()
    try:
        return data["image"]
    except Exception as e:
        return str(e)

def duck(msg):
    url = "https://random-d.uk/api/random"
    response = requests.get(url)
    data = response.json()
    try:
        return data["url"]
    except Exception as e:
        return str(e)

def bankhol(msg):
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

def read_json_file(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

def write_json_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

def get_stats(msg):
    data = read_json_file('dice_rolls.json')
    total_rolls = data['total_rolls']
    lowest_score = data['lowest_score']
    lowest_score_user = data['lowest_score_user']
    best_scores = data['best_scores']
    message = f"Total rolls: {total_rolls} Best roll: {lowest_score_user} with {lowest_score}\n"
    return message

def roll_dice(msg):
    u=msg["user"]
    m=msg["message"]
    dice=[] # Initialize an empty list to store the dice rolls
    for i in range(7):
        roll=random.randint(1, 6)
        if roll==1:
            dice.append("\x0313,15" + str(roll))
        else:
            dice.append("\x0301,15" + str(roll))
        dice_str=" ".join(dice)
        int_dice=[int(x[6:]) for x in dice]
        if i==6:
            newrecord=False
            sum_dice=sum(int_dice)
            dice_str="\x0301,15-".join(dice)

            # Read data from JSON file
            data = read_json_file('dice_rolls.json')

            # Increment total number of rolls
            data['total_rolls'] += 1

            # Update lowest score and user with lowest score
            if sum_dice < data['lowest_score']:
                data['lowest_score'] = sum_dice
                data['lowest_score_user'] = u
                newrecord=True
            # Update best score for current user
            if u not in data['best_scores'] or sum_dice < data['best_scores'][u]:
                data['best_scores'][u] = sum_dice

            # Write updated data to JSON file
            write_json_file('dice_rolls.json', data)
            dice_list = [dice_str + "\x03 " + u + "\x03 rolled: \x0307" + str(sum_dice)]
            if not newrecord:
                return dice_list
            else:
                dice_list.append("omg " + u + " broke the record!!")
                return dice_list

import utility
HOST = "irc.server.chat"
PORT = 6667
NICK = "yourbot"                                    #
PASS = 'derp'
USER = "yourbot@hisname 0 * hisname"
CHAN = "#chan"
RATE = (20/30)                                # messages per seccond
COMMANDS = [
    [r':\.bots$', utility.report_in],
    [r':~roll7$', utility.roll_dice],
    [r':~time$', utility.check_time], 
    [r':~ginger$', utility.jumble],
    [r':~date$', utility.check_date],
    [r':~temp$', utility.temp],
    [r':~iss$', utility.ISS],
    [r':~random', utility.random_choice],
    [r':~dog$', utility.dogs],
    [r':~fox$', utility.fox],
    [r':~duck$', utility.duck],
    [r':~bankhol$', utility.bankhol],
]

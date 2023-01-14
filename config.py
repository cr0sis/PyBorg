import utility
HOST = "irc.server.chat"
PORT = 6667
NICK = "yourbot"                                    #
PASS = 'derp'
USER = "yourbot@hisname 0 * hisname"
CHANNELS = ["#channel1", "#channel2"]
RATE = (20/30)                                # messages per seccond
COMMANDS = [
    [r'^\.bots$', utility.report_in],
    [r'^~gdq$', utility.gdq],
    [r'^~roll7$', utility.roll_dice],
    [r'^~time$', utility.check_time],
    [r'^~ginger$', utility.jumble],
    [r'^~date$', utility.check_date],
    [r'^~temp$', utility.temp],
    [r'^~iss$', utility.ISS],
    [r'^~random', utility.random_choice],
    [r'^~dog$', utility.dogs],
    [r'^~fox$', utility.fox],
    [r'^~duck$', utility.duck],
    [r'^~bankhol$', utility.bankhol],
    [r'^~stats$', utility.get_stats],
    [r'^~moon$', utility.get_moon_emoji],
    [r'^~lenny$', utility.lenny],
    [r'^~sun$', utility.sun],
]

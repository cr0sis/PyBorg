HOST = "irc.server.chat"
PORT = 6667
NICK = "yourbot"                                    #
PASS = 'derp'
USER = "yourbot@hisname 0 * hisname"
CHAN = "#chan"
RATE = 0.6                                # messages per seccond
COMMANDS = [
    [r':\.bots\r\n$', utility.report_in],
    [r':!roll7\r\n$', utility.roll_dice],
    [r':!time\r\n$', utility.check_time], 
    [r':!ginger\r\n$', utility.jumble],
    [r':!date\r\n$', utility.check_date],
]

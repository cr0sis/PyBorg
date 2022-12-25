HOST = "irc.libera.chat"
PORT = 6667
NICK = "cr0bot"                                    #
PASS = 'derp'
USER = "cr0bot@cr0sis 0 * timothy"
CHAN = "#bakedbeans"
RATE = 0.6                                # messages per seccond
COMMANDS = [
    [r':\.bots\r\n$', utility.report_in],
    [r':!roll7\r\n$', utility.roll_dice],
    [r':!time\r\n$', utility.check_time], 
    [r':!ginger\r\n$', utility.jumble],
    [r':!date\r\n$', utility.check_date],
]

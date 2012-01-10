########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   www.thehackademy.fr                                                #
#   Copyright © 2012                                                   #
#   Authors: SAKAROV, Madhatter, mont29, Luxerails, PauseKawa, fred,   #
#   afranck64, Tyrtamos.                                               #
#   Contact: cyprium@thehackademy.fr, sakarov@thehackademy.fr,         #
#   madhatter@thehackademy.fr, mont29@thehackademy.fr,                 #
#   irc.thehackademy.fr #cyprium, irc.thehackademy.fr #hackademy       #
#                                                                      #
#   Cyprium is free software: you can redistribute it and/or modify    #
#   it under the terms of the GNU General Public License as published  #
#   by the Free Software Foundation, either version 3 of the License,  #
#   or any later version.                                              #
#                                                                      #
#   This program is distributed in the hope that it will be useful,    #
#   but without any warranty; without even the implied warranty of     #
#   merchantability or fitness for a particular purpose. See the       #
#   GNU General Public License for more details.                       #
#                                                                      #
#   The terms of the GNU General Public License is detailed in the     #
#   COPYING attached file. If not, see : http://www.gnu.org/licenses   #
#                                                                      #
########################################################################

import app.ui
import sys


class UI(app.ui.UI):
    """CLI UI class.
       NOTE: All those functions might return None, in addition
             to some expected data...
    """

    ###########################################################################
    # Helpers (for compatibility...).
    ###########################################################################
    @staticmethod
    def cprint(*objs, sep=' ', end='\n', file=sys.stdout):
        codec = file.encoding
        if not codec:
            # Security check/fallback,
            # some IDE give no encoding to their stdout. :(
            codec = "ascii"
        sep = sep.encode(codec, "replace")
        objs = [str(obj).encode(codec, "replace") for obj in objs]
        end = end.encode(codec, "replace")
        if hasattr(file, "buffer"):
            file.buffer.write(sep.join(objs) + end)
        else:
            file.write(sep.join(objs) + end)
        file.flush()

    @staticmethod
    def cinput(msg):
        UI.cprint(msg, end="")
        ret = input("")
        UI.cprint("")
        return ret

    @classmethod
    def _getch_unix(cl, echo=False):
        import tty
        import termios
        _fd = sys.stdin.fileno()
        _old_settings = termios.tcgetattr(_fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(_fd, termios.TCSADRAIN, _old_settings)
        if echo:
            cl.cprint(ch, end="")
        return ch

    @classmethod
    def _getch_win(cl, echo=False):
        import msvcrt
        import time
        while not msvcrt.kbhit():
            time.sleep(0.1)
        if echo:
            return msvcrt.getwche()
        return msvcrt.getwch()

    if sys.platform == 'win32':
        _getch = _getch_win
    else:
        _getch = _getch_unix

    ###########################################################################
    # Simple message.
    ###########################################################################
    def message(self, message="", level=app.ui.UI.INFO):
        """Print a message to the user, with some formatting given
           the level value.
        """
        if level == app.ui.UI.WARNING:
            message = "".join(("WARNING: ", message))
        elif level == app.ui.UI.ERROR:
            message = "".join(("ERROR: ", message))
        elif level == app.ui.UI.FATAL:
            message = "".join(("FATAL ERROR: ", message))
        self.cprint(message, "\n")

    ###########################################################################
    # Text input.
    ###########################################################################
    def get_data(self, message="", sub_type=app.ui.UI.STRING, completion=None):
        """Get some data from the user.
           Will ensure data is valid given sub_type, and call
           completion callback if user hits <tab>.
           completion(data_already_entered=None)
        """
        while 1:
            data = self.cinput(message)
            if sub_type == app.ui.UI.LOWER:
                t_data = data.lower()
                if t_data != data:
                    self.message("Your input has been converted to lower case: {}"
                                 "".format(t_data))
                    data = t_data
            elif sub_type == app.ui.UI.UPPER:
                t_data = data.upper()
                if t_data != data:
                    self.message("Your input has been converted to upper case: {}"
                                 "".format(t_data))
                    data = t_data
            elif sub_type == self.INT:
                try:
                    return int(data)
                except:
                    msg = "Could not convert {} to an integer".format(data)
                    options = [("retry", "$retry", ""),
                               ("abort", "or *abort", "")]
                    answ = self.get_choice(msg, options, start_opt="(",
                                           end_opt=")", oneline=True)
                    if answ == "retry":
                        continue
                    return
            elif sub_type == self.FLOAT:
                try:
                    return float(data)
                except:
                    msg = "Could not convert {} to a float".format(data)
                    options = [("retry", "$retry", ""),
                               ("abort", "or *abort", "")]
                    answ = self.get_choice(msg, options, start_opt="(",
                                           end_opt=")", oneline=True)
                    if answ == "retry":
                        continue
                    return
            return data

    ###########################################################################
    # Menu.
    ###########################################################################
    def get_choice(self, message="", options=[], start_opt="", end_opt="",
                   oneline=False):
        """Gives some choices to the user, and get its answer."""
        # Parse the options...
        msg_chc = []
        chc_map = {}
        do_default = False
        for c in options:
            name = c[1]
            key_idx = name.find('*')
            if key_idx < 0:
                key_idx = name.find('$')
                if key_idx >= 0:
                    do_default = True
            # If no '*' or '$' found, considered as "static label".
            if key_idx >= 0:
                key = name[key_idx + 1].lower()
                name = name[:key_idx] + '(' + key.upper() + ')' + \
                       name[key_idx + 2:]
                if do_default:
                    if "" in chc_map:
                        self.message("Option {} wants to be default, while "
                                     "we already have one!"
                                     "".format(name), self.WARNING)
                        continue
                    chc_map[""] = c[0]
                    name = " ".join((name, "[default]"))
                    do_default = False
                if key in chc_map:
                    self.message("Option {} wants the already used '{}' key!"
                                 "".format(name, key), self.WARNING)
                    continue
                chc_map[key] = c[0]
            if c[2]:
                msg_chc.append("{} ({})".format(name, c[2]))
            else:
                msg_chc.append(name)

        if oneline:
            txt_msg = "".join((start_opt, ", ".join(msg_chc), end_opt))
            if message:
                message = " ".join((message, txt_msg))
            else:
                message = txt_msg
            message = "".join((message, ": "))
        else:
            txt_msg = "".join((start_opt, "\n    ".join(msg_chc), end_opt))
            if message:
                message = ":\n    ".join((message, txt_msg))
            else:
                message = txt_msg
            message = "".join((message, "\n"))

        # TODO: use a getch()-like!
        r = self.cinput(message).lower()
        while r not in chc_map:
            r = self.cinput("Invalid choice, please try again: ").lower()

        return chc_map[r]

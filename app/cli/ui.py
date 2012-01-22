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

    CLI_BOLD = "\x1b[1m"
    CLI_RED = "\x1b[31m"
    CLI_YELLOW = "\x1b[33m"
    CLI_CLEAR = "\x1b[0m"

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
            message = "".join((self.CLI_BOLD, self.CLI_YELLOW, "WARNING: ",
                               self.CLI_CLEAR, message))
        elif level == app.ui.UI.ERROR:
            message = "".join((self.CLI_BOLD, self.CLI_RED, "ERROR: ",
                               self.CLI_CLEAR, message))
        elif level == app.ui.UI.FATAL:
            message = "".join((self.CLI_BOLD, self.CLI_RED, "FATAL ERROR: ",
                               self.CLI_CLEAR, message))
        self.cprint(message, "\n")

    ###########################################################################
    # Text input.
    ###########################################################################
    def get_data(self, message="", sub_type=app.ui.UI.STRING, allow_void=False,
                 completion=None, completion_kwargs={},
                 validate=None, validate_kwargs={}):
        """
        Get some data from the user.
        Will ensure data is valid given sub_type, and call
        If allow_void is True, return None or "" in case user types nothing,
        (else print a menu).
        completion callback if user hits <tab>.
            completion(data_already_entered=None, **completion_kwargs)
            must return a list of (complete) possible data.
            NOT YET IMPLEMENTED!
        validate callback to check entry is valid:
            validate(data=None, **validate_kwargs)
            must return a tupple (valid, "valid_msg", "invalid_msg")
        """
        while 1:
            data = self.cinput(message)
            while not data:
                if allow_void:
                    return None
                elif validate:
                    if validate(data, **validate_kwargs)[0]:
                        return data
                msg = "Nothing typed".format(data)
                options = [("retry", "$retry", ""),
                           ("abort", "or *abort", "")]
                answ = self.get_choice(msg, options, oneline=True)
                if answ == "retry":
                    data = self.cinput(message)
                else:
                    return None

            # Validate sub-types.
            if sub_type == app.ui.UI.LOWER:
                t_data = data.lower()
                if t_data != data:
                    self.message("Your input has been converted to lowercase: "
                                 "{}".format(t_data))
                    data = t_data
            elif sub_type == app.ui.UI.UPPER:
                t_data = data.upper()
                if t_data != data:
                    self.message("Your input has been converted to uppercase: "
                                 "{}".format(t_data))
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

            # Call given validating callback, if any.
            if validate:
                vald = validate(data, **validate_kwargs)
                if vald[0]:
                    if vald[1]:
                        self.message(vald[1])
                else:
                    self.message(vald[2] or "Invalid entry")
                    continue  # Go back to beginning!

            # Return valid data!
            return data

    ###########################################################################
    # Menu.
    ###########################################################################
    @ staticmethod
    def _get_key(txt):
        default = False
        key_start = txt.find('*')
        key_end = -1
        if key_start < 0:
            key_start = txt.find('$')
            if key_start >= 0:
                default = True
                key_end = txt[key_start + 2:].find('$')
            else:
                return (txt, "", "", False)
        else:
            key_end = txt[key_start + 2:].find('*')
        if key_end >= 0:
            key_end += key_start + 2
            return (txt[:key_start], txt[key_start + 1:key_end],
                    txt[key_end + 1:], default)
        return (txt[:key_start], txt[key_start + 1:key_start + 2],
                txt[key_start + 2:], default)

    def get_choice(self, message="", options=[], start_opt="", end_opt="",
                   oneline=False, multichoices=None):
        """Gives some choices to the user, and get its answer."""
        # Parse the options...
        msg_chc = []
        chc_map = {}
        do_default = False
        for c in options:
            name = c[1]
            start, key, end, do_default = self._get_key(name)
            if key:
                name = start + '[' + key + ']' + end
                if key.lower() in chc_map:
                    self.message("Option {} wants the already used '{}' key!"
                                 "".format(name, key.lower()), self.WARNING)
                    continue
                if do_default:
                    if "" in chc_map:
                        self.message("Option {} wants to be default, while "
                                     "we already have one!"
                                     "".format(name), self.WARNING)
                        continue
                    chc_map[""] = c[0]
                    name = " ".join((name, "(default)"))
                    do_default = False
                chc_map[key.lower()] = c[0]
            # If no key, considered as "static label".
            else:
                name = start
            if c[2]:
                msg_chc.append("{} ({})".format(name, c[2]))
            else:
                msg_chc.append(name)

        mc = ""
        if isinstance(multichoices, str):
            mc = "(multiple choices possible, '{}'-separated)" \
                 "".format(multichoices)
        if oneline:
            txt_msg = "".join((start_opt, ", ".join(msg_chc), mc, end_opt))
            if message:
                message = " ".join((message, txt_msg))
            else:
                message = txt_msg
            message = "".join((message, ": "))
        else:
            txt_msg = "".join((start_opt, "\n    ".join(msg_chc), end_opt))
            if mc:
                message = " ".join(message, mc)
            message = ":\n    ".join((message, txt_msg))
            message = "".join((message, "\n"))

        # TODO: use a getch()-like!
        key = self.cinput(message).lower()
        if mc:
            ret = key.split(multichoices)
            while set(ret) > set(chc_map.keys()):
                if key == "+m":
                    key = self.cinput(message).lower()
                else:
                    key = self.cinput("Invalid choice(s), please try "
                                      "(or show [+m]enu) again: ").lower()
                ret = key.split(multichoices)
            return [chc_map[k] for k in ret]
        else:
            while key not in chc_map:
                if key == "+m":
                    key = self.cinput(message).lower()
                else:
                    key = self.cinput("Invalid choice, please try "
                                      "(or show [+m]enu) again: ").lower()
            return chc_map[key]

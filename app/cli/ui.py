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

class UI(app.ui.UI):
    """Base, "None" UI class (also used as "interface").
       NOTE: All those functions might return None, in addition
             to some expected data...
    """

    def __init__(self):
        pass

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
        print(message, "\n")

    def get_data(self, message="", sub_type=None, completion=None):
        """Get some data from the user.
           Will ensure data is valid given sub_type, and call
           completion callback if user hits <tab>.
           completion(data_already_entered=None)
        """
        return input(message)
        print("")

    def get_choice(self, message="", options=[], oneline=False):
        """Gives some choices to the user, and get its answer."""
        # Parse the options...
        msg_chc = []
        chc_map = {}
        for c in options:
            name = c[1]
            key_idx = name.find('*')
            # If no '*' found, considered as "static label".
            if key_idx >= 0:
                key = name[key_idx + 1].lower()
                name = name[:key_idx] + '(' + key.upper() + ')' + name[key_idx+2:]
                if key in chc_map:
                    ui.message("Option {} wants the already used '{}' key!".format(name, key), ui.WARNING)
                    continue
                chc_map[key] = c[0]
            if c[2]:
                msg_chc.append("{} ({})".format(name, c[2]))
            else:
                msg_chc.append(name)

        if oneline:
            if message:
                message = " ".join((message, " ".join(msg_chc)))
            else:
                message = " ".join(msg_chc)
            message = "".join((message, ": "))
        else:
            if message:
                message = ":\n    ".join((message, "\n    ".join(msg_chc)))
            else:
                message = "\n".join(msg_chc)
            message = "".join((message, "\n"))

        # TODO: use a getch()-like!
        r = input(message)
        while r not in chc_map:
            r = input("Invalid choice, please try again: ")

        print("")
        return chc_map[r.lower()]

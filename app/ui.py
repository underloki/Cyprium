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

class UI:
    """Base, "None" UI class (also used as "interface").
       NOTE: All those functions might return None, in addition
             to some expected data...
    """

    # "defines" of messages levels.
    INFO = 0
    WARNING = 1
    ERROR = 2
    FATAL = 3

    # Sub-types of get_data.
    STRING = None  # Default...
    PATH = 1  # Check is format-valid, and autocompletion?

    def __init__(self):
        pass

    def message(self, message="", level=INFO):
        """Print a message to the user, with some formatting given
           the level value.
        """
        pass

    def get_data(self, message="", sub_type=None, completion=None):
        """Get some data from the user.
           Will ensure data is valid given sub_type, and call
           completion callback if user hits <tab>.
           completion(data_already_entered=None)
        """
        pass

    def get_choice(self, message="", choices=[]):
        """Gives some choices to the user, and get its answer."""
        pass

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


import os


# The path to cyprium!
ROOT_DIR = os.path.dirname(__file__)


###############################################################################
### kernel.

## Dics.

# The path for zip archive containing language dics to use.
HUNSPELL_ZIP_DICS = os.path.join(ROOT_DIR, "kernel", "dics.zip")


## Cache settings.

# Use disk cache to save processed versions of heavy data which creation is CPU-intensive.
# Used e.g. by language-words code (hunspell.py and matchdic.py).
# Warning: these files will take quite some room (currently ~60Mo).
CCH_USE = True

# Where to store cache files.
CCH_BASE_DIR = os.path.join(ROOT_DIR, ".cache")

# Hash algo to use as cache id.
CHC_HASH_TYPE = "sha512"


###############################################################################
### UI.

# The pause between each draw of splash info, at launch time (in ms).
UI_SPLASH_DELAY = 1000


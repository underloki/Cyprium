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


import sys
import itertools

__pf__ = sys.platform
if __pf__ == 'win32':
    if sys.getwindowsversion().platform == 2:
        winpf = ' (NT/2000/XP/x64)'
    else:
        winpf = ''
    __pf__ = 'Windows' + winpf
elif __pf__ == 'cygwin':
    __pf__ = 'Windows/Cygwin'
elif __pf__ == 'linux2':
    __pf__ = 'Linux'
elif __pf__ == 'os2':
    __pf__ = 'OS/2'
elif __pf__ == 'os2emx':
    __pf__ = 'OS/2 EMX'
elif __pf__ == 'darwin':
    __pf__ = 'Mac OS X'
else:
    __pf__ = '?'

major, minor, micro, _, _ = sys.version_info
__pytver__ = '{}.{}.{}'.format(major, minor, micro)


def grouper(n, iterable, fillvalue=None):
    """Return an iterator of n-length chunks of iterable.
       grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    """
    args = [iter(iterable)] * n
    return itertools.zip_longest(fillvalue=fillvalue, *args)

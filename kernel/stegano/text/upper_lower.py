#! /usr/bin/python3

########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   www.thehackademy.fr                                                #
#   Copyright Â© 2012                                                   #
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
import os
import string
import itertools

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/01/21"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Upper-Lower =====

Upper-Lower is a steganographic tool which simply hides a short sentence
into the letters of a bigger text. Alowed chars in text are strict lowercase
chars. Digits, spaces and ponctuation are also allowed.

This obviously implies that the hiding text must have at least 8 times
more letters + 1 as the length of the text to hide.
They are two modes:
    0: use lower-case as 0, upper-case as 1
    1: use lower-case as 1, upper-case as 0

Example:
    hide("welcome to all of you to thehackademy.fr!","2012", mode=1) ==>
        'WelCOme To alL Of you to THehaCkaDEmy.Fr!'
    hide("welcome to all of you to thehackademy.fr!","2012", mode=0) ==>
        'wELcoME tO ALl oF YOU TO thEHAcKAdeMY.fR!'

    unhide('wELcoME tO ALl oF YOU TO thEHAcKAdeMY.fR!') ==>
        'tha'


Cyprium.Upper-Lower version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)

_MODES = ['0', '1']
_NOT_ASCII_LOWER_ORDS = (225, 224, 226, 228, 233, 232,
    234, 237, 236, 238, 243, 242, 244, 246,
    250, 249, 251, 252)
_NOT_ASCII = str(bytes(_NOT_ASCII_LOWER_ORDS).decode("latin-1"))
_LOWER_CASES = _NOT_ASCII + string.ascii_lowercase


def _count_letters(text):
    """count the number of letters in text"""
    res = 0
    for c in _LOWER_CASES:
        res += text.count(c)
    return res


def do_hide(text, data, mode=1):
    """hide a text in another text"""
    res = []
    if mode==1:
        res.append(text[0].upper())
    else:
        res.append(text[0])
    index = 1
    mode = _MODES[mode]
    for c in data:
        bits = bin(ord(c))[2:].rjust(8,'0')
        for i in range(8):
            while (text[index] not in _LOWER_CASES):
                res.append(text[index])
                index += 1
            if bits[i]==mode:
                res.append(text[index].upper())
            else:
                res.append(text[index])
            index += 1
    length = len(text)
    while (index<length):
        res.append(text[index])
        index += 1
    return res


def hide(text, data, mode=0):
    """Just a wrapper around do_hide, with some checks."""
    if not data:
        raise ValueError("No data to hide given!")
    elif not text:
        raise ValueError("No text into which to hide given!")
    #should probably rise an error.
    if mode not in (0,1):
        mode = 0
    nb_letters = _count_letters(text)
    #times 8 while we encrypt 1 octect with 8 letters
    #1 bit for the header (mode)
    if len(data) * 8 + 1 > nb_letters:
        raise ValueError("Hiding text not long enough (needs at least {} "
                         "alphabetic letters, only have {} currently)!"
                         "".format(len(data)*8 +1,nb_letters))
    # Check for unallowed chars
    c_text = set(text)
    c_allowed = set(_LOWER_CASES + string.digits +
        string.punctuation + " ")
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only lowercase "
                         "letters, digits and punctuation is allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return "".join(do_hide(text, data, mode))


def do_unhide(text, mode=0):
    chars = []
    bits = ''
    for c in text:
        if c.isalpha():
            if c.islower():
                bits += _MODES[(mode+1)%2]
            else:
                bits += _MODES[mode]
            if len(bits)==8:
                if bits==_MODES[(mode+1)%2]*8:
                    break
                chars.append(chr(int(bits, 2)))
                bits = ''
    return "".join(chars)


def unhide(text):
    """Just a wrapper around do_unhide (no checks currently)."""
    if not text:
        raise ValueError("No text into which to hide given!")
    #check the mode, pos[0]
    if text[0].isupper():
        mode = 1
    else:
        mode = 0
    return do_unhide(text[1:], mode)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Hide/unhide a word or short sentence "
                                     "into the spaces of a long text (which "
                                     "hence must have as much spaces as the "
                                     "number of letters in data to hide).")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('hide', help="Hide data in text.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text into which "
                                  "hide the data.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the stegano text.")
    hide_parser.add_argument('-d', '--data',
                             help="The data to hide into the text.")

    unhide_parser = sparsers.add_parser('unhide',
                                        help="Unhide data from text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text with "
                                    "hidden data.")

    sparsers.add_parser('about', help="About Upper-Lower")

    args = parser.parse_args()

    if args.command == "hide":
        try:
            args.ofile.write(hide(args.ifile.read().strip(), args.data))
        except Exception as e:
            if utils.DEBUG:
                raise e
            print(e, "\n\n")
        finally:
            args.ifile.close()
            args.ofile.close()
        return

    elif args.command == "unhide":
        try:
            print(unhide(args.ifile.read()))
        except Exception as e:
            if utils.DEBUG:
                raise e
            print(e, "\n\n")
        finally:
            args.ifile.close()
        return

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()
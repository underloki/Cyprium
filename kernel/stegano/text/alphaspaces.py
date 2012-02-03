#! /usr/bin/python3

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
__date__ = "2012/01/10"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About AlphaSpaces =====
AlphaSpaces is a steganographic tool which simply hides a short sentence
into the spaces of a bigger text.

This obviously implies that the hiding text must have at least as many spaces
as letters to hide!

Example:
    Input text to hide data into: “This is a quite simple steganographic tool”
    Data to hide: “stegano”
    Hidden data: “This                   is                    a     """ \
                 """quite       simple steganographic              tool”

Note: That type of steganography is mostly useful for web content, as html
browsers never show more than one space between words, it is invisible on
screen. But obviously, easy to see if you have a look at the raw html code!


Cyprium.AlphaSpaces version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


def _get_spaces(text):
    ret = []
    curr = 0
    for c in text:
        if c == ' ':
            curr += 1
        elif curr:
            ret.append(curr)
            curr = 0
    return ret


def do_hide(text, data):
    text = text.split()
    # List of spaces of varying length (code).
    list_spaces = list(map(lambda x: ' ' * (ord(x) - 96), data))
    # Add "END OF DATA" marker.
    if len(text) > len(list_spaces) + 1:
        list_spaces.append(' ' * 27)
    # Get iterator of tuples (word, spaces).
    new_words = itertools.zip_longest(text, list_spaces, fillvalue=' ')
    # Join everything back into a single str (note we must get rid of
    # trailing space!).
    return "".join(("".join((w[0], w[1])) for w in new_words)).rstrip()


def hide(text, data):
    """Just a wrapper around do_hide, with some checks."""
    if not data:
        raise ValueError("No data to hide given!")
    if len(data) > len(text.split()):
        raise ValueError("Hiding text not long enough (needs at least {} "
                         "spaces, only have {} currently)!"
                         "".format(len(data), len(text.split())))
    # Check for unallowed chars…
    c_text = set(data)
    c_allowed = set(string.ascii_lowercase)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only lowercase "
                         "strict ASCII chars are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_hide(text, data)


def do_unhide(text):
    chars = []
    for sp in _get_spaces(text):
        # 27 is 'NULL' char,  i.e. end of data!
        if sp == 27:
            break
        elif 0 < sp < 27:
            chars.append(string.ascii_lowercase[sp - 1])
    return "".join(chars)


def unhide(text):
    """Just a wrapper around do_unhide (no checks currently)."""
    return do_unhide(text)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Hide/unhide a word or short sentence "
                                     "into the spaces of a long text (which "
                                     "hence must have as much spaces as the "
                                     "number of letters in data to hide).")
    parser.add_argument('--debug', action="store_true", default=False,
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

    sparsers.add_parser('about', help="About AlphaSpaces…")

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

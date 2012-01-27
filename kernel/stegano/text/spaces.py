#! /usr/bin/python3

########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   www.thehackademy.fr                                                #
#   Copyright ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â© 2012                                                   #
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
import re

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/01/27"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Spaces =====

Spaces is a steganographic tool which simply hides a short sentence
into the letters of a bigger text. Alowed chars in text are strict lowercase
chars. Digits, spaces and ponctuation are also allowed.

This obviously implies that the hiding text must have at least 8 times
more letters + 1 as the length of the text to hide.
The mode give what one space represent:
    mode 0: " "==0, "  "==1
    mode 1: " "==1, "  "==0

Example:
    hide('a b c d e f g h i j k l m n o p q r s t u v w x y z',"YOU")
        ==> 'a b c  d e  f  g h i  j k  l m n  o  p  q  r s  t u  v w  x y  z'
    unhide('a b c  d e f  g  h i  j k  l m n o  p q  r s t u v w x y z')
        ==> 'ME'


Cyprium.Spaces version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


def do_hide(words, data, mode=0):
    """hide a text in another text"""
    res = []
    res.append(words[0])
    res.append(MAP[mode])
    #index = 1, we have already added words[0]
    index = 1
    c_mode = str(mode)
    for c in data:
        bits = bin(ord(c))[2:].rjust(8,'0')
        for i in range(8):
            res.append(words[index])
            if bits[i]==c_mode:
                res.append(MAP[mode])
            else:
                res.append(MAP[(mode+1)%2])
            index += 1
    length = len(words)
    res.append(MAP[mode].join(words[index:length]))
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

    words = re.split(" +", text)
    nb_words = len(words)
    #times 8 while we encrypt 1 octect with 8 letters
    #1 bit for the header (mode)
    #1 word for to close
    if len(data) * 8 + 2 > nb_words:
        raise ValueError("Hiding text not long enough (needs at least {} "
                         "words, only have {} currently)!"
                         "".format(len(data)*8 +2,nb_words))
    return "".join(do_hide(words, data, mode))

txt = "a b  c d  bad d wew  d s ee  d e d  d   e d  d e  d d  d   d a d  d q  dd  d da d"

MAP = [" ", "  "]
R_MAP = {0:{" ":'0',"  ":'1'},1:{" ":'1', "  ":'0'}}
#mode=0: " "==0
#mode=1: " "==1



def do_unhide(text):
    """unhide a spaces-encoded text!"""
    res = []
    lst = re.findall('  | ', text)
    mode = MAP.index(lst[0])
    index = 1
    length = len(lst)
    bits = ""
    for elt in lst[1:]:
        bit = R_MAP[mode][elt]
        bits += bit
        if len(bits)==8:
            if bits=="00000000":
                break
            res.append(int(bits,2))
            bits = ""
    return res


def unhide(text):
    """Just a wrapper around do_unhide (no checks currently)."""
    if not text:
        raise ValueError("No text into which to hide given!")
    if re.search("   ",text):
        raise ValueError("Bad space-text")
    #check the mode, pos[0]
    return "".join(chr(c) for c in do_unhide(text))


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

    sparsers.add_parser('about', help="About Spaces")

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
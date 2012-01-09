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

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/01/08"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"===== About Celldrawer =====\n\n" \
"Celldrawer encrypts/deciphers “celldrawer” code.\n\n "\
"This code only accepts lowercase ASCII letters, and represents them by\n" \
"phone digits (#*0123456789), so that each code “draws” its letter on a\n" \
"4×3 phone keyboard.\n\n" \
"            2  \n" \
"          4   6\n" \
"          7 8 9\n" \
"E.G.: A:  *   #\n\n" \
"Cyprium.Celldrawer version {} ({}).\n" \
"Licence GPL3\n" \
"software distributed on the site: http://thehackademy.fr\n\n" \
"Current execution context:\n" \
"    Operating System: {}\n" \
"    Python version: {}" \
"".format(__version__, __date__, utils.__pf__, utils.__pytver__)


EDICT = {"a": "*74269#8",
         "b": "*741236589#0",
         "c": "32470#",
         "d": "*7412690",
         "e": "321457*0#",
         "f": "*741238",
         "g": "32147*0#98",
         "h": "147*369#8",
         "i": "12358*0#",
         "j": "123580*",
         "k": "147*538#",
         "l": "147*0#",
         "m": "*7415369#",
         "n": "*74158#963",
         "o": "*7412369#0",
         "p": "*74123698",
         "q": "#96321478",
         "r": "*7412368#",
         "s": "324590*",
         "t": "123580",
         "u": "147*0#963",
         "v": "1470963",
         "w": "147*8#963",
         "x": "158#*3",
         "y": "15380",
         "z": "12357*0#",
         " ": ""}

DDICT = {v: k for k, v in EDICT.items()}


def do_encrypt(text):
    """Function to convert some text to "celldrawer" text."""
    return ' '.join([EDICT[c] for c in text])


def encrypt(text):
    """Just a wrapper around do_encrypt, with some checks."""
    import string
    if not text:
        raise Exception("no text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(string.ascii_lowercase)
    c_allowed.add(' ')
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only lowercase strict "
                        "ASCII chars are allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_encrypt(text)


def do_decipher(text):
    """Function to convert “celldrawer” text into clear text."""
    words = []
    # Double spaces = word sep ("real" space).
    for w in text.split('  '):
        # Remove any additional "outside" spaces…
        w.rstrip().lstrip()
        chars = []
        for c in w.split(' '):
            if c not in DDICT:
                raise Exception("The \"{}\" code is not a valid celldrawer one"
                                "".format(c))
            chars.append(DDICT[c])
        words.append(''.join(chars))
    return ' '.join(words)


def decipher(text):
    """Just a wrapper around do_decipher, with some checks."""
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = {' ', '*', '#',
                 '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only phone digits are "
                        "allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decipher(text)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decipher some text in "
                                     "celldrawer code.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('encrypt', help="Encryptcode text in "
                                                      "celldrawer.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "celldrawer.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the celldrawer "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to encrypt in celldrawer.")

    unhide_parser = sparsers.add_parser('decipher',
                                        help="Decipher celldrawer to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from celldrawer.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the deciphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data', help="The text to decipher.")

    sparsers.add_parser('about', help="About Celldrawer…")

    args = parser.parse_args()

    if args.command == "encrypt":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = encrypt(data)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            print(e, "\n\n")
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return 0

    elif args.command == "decipher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decipher(data)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            print(e, "\n\n")
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return 0

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

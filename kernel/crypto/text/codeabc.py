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
"""===== About CodeABC =====

CodeABD cyphers/decyphers the phone keyboard code.

This code only accepts lowercase ASCII letters and space, and represents
them by phone codes like 0 for space, 111 for 'c', 5 for 'j', etc.

Cyprium.CodeABC version {} ({}).
Copyright Jean-Paul Vidal alias \"Tyrtamos\" 2012
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


MAP = {'a': '2',
       'b': '22',
       'c': '222',
       'd': '3',
       'e': '33',
       'f': '333',
       'g': '4',
       'h': '44',
       'i': '444',
       'j': '5',
       'k': '55',
       'l': '555',
       'm': '6',
       'n': '66',
       'o': '666',
       'p': '7',
       'q': '77',
       'r': '777',
       's': '7777',
       't': '8',
       'u': '88',
       'v': '888',
       'w': '9',
       'x': '99',
       'y': '999',
       'z': '9999',
       ' ': '0'}

R_MAP = utils.revert_dict(MAP)


#############################################################################
def do_cypher(text):
    """Cypher text with codeABC allowed chars: [a..z] + space."""
    return ' '.join([MAP[c] for c in text])


def cypher(text):
    """Wrapper around do_cypher, making some checks."""
    import string
    if not text:
        raise Exception("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(MAP.keys())
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only space and "
                        "lowercase strict ASCII chars are allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_cypher(text)


#############################################################################
def do_decypher(text):
    """Decypher text using codeABC"""
    return ''.join([R_MAP[c] for c in text.split()])


def decypher(text):
    """Wrapper around do_decypher, making some checks."""
    if not text:
        raise Exception("No text given!")
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' '}
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only space and "
                        "digits are allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    # Check for invalid codes...
    c_text = set(text.split())
    c_allowed = set(R_MAP.keys())
    if not (c_text <= c_allowed):
        raise Exception("Text contains invalid codeABC codes: '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decypher(text)


def main():
    # Treating direct script call with args
    # Args retrieval
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher a text according to "
                                     "cell phones' keyboard.\n"
                                     "Example: 'c' => '222'.\n"
                                     "Allowed chars: a..z + space.")

    sparsers = parser.add_subparsers(dest="command")

    cypher_parser = sparsers.add_parser('cypher', help="Cypher text.")
    cypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                help="A file containing the text to cypher.")
    cypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                help="A file into which write the cyphered "
                                     "text.")
    cypher_parser.add_argument('-d', '--data', help="The text to cypher.")

    decypher_parser = sparsers.add_parser('decypher', help="Decypher text.")
    decypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to "
                                      "decypher.")
    decypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    decypher_parser.add_argument('-d', '--data', help="The text to decypher.")

    sparsers.add_parser('about', help="About codeABC…")

    args = parser.parse_args()

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data)
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
        return

    elif args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decypher(data)
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
        return

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

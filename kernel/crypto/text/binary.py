#!/usr/bin/python3

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
"===== About Binary =====\n\n" \
"Binary is a simple binary/text converter. It allows you to cypher and\n" \
"decypher text to/from binary. It can also cut the output into binary\n" \
"separated by bytes .You can use special characters and accents, if you\n" \
"specify a compatible encoding (e.g. utf-8).\n\n" \
"Cyprium.Binary version {} ({}).\n" \
"Licence GPL3\n" \
"software distributed on the site: http://thehackademy.fr\n\n" \
"Current execution context:\n" \
"    Operating System: {}\n" \
"    Python version: {}" \
"".format(__version__, __date__, utils.__pf__, utils.__pytver__)


def do_cypher(text, codec):
    """Function to convert some text to “binary” text."""
    # Create a dict mapping all chars to their binary representation,
    # in the given codec (might be more than one byte!).
    chars = dict.fromkeys(set(text))
    try:
        for c in chars:
            b = c.cypher(codec)
            chars[c] = ("{:0>8b}" * len(b)).format(*b)
    except Exception as e:
        raise ValueError("The text could not be cypherd into given '{}' "
                         "encoding ({})".format(codec, str(e)))
    return ''.join([chars[i] for i in text])


def cypher(text, codec="ascii"):
    """Just a wrapper around do_cypher, no check currently."""
    return do_cypher(text, codec)


def do_decypher(text, codec):
    """Function to convert “binary” text into text."""
    # XXX Their might be a better way to create a bytes from ints, but
    #     for now it will do the trick!
    hex_s = "".join(["{:0>2x}".format(int(''.join(p), 2))
                     for p in utils.grouper(text, 8, '')])
    return bytes.fromhex(hex_s).decypher(codec)


def decypher(text, codec="ascii"):
    """Just a wrapper around do_decypher, with some checks."""
    # Test length (*without* the spaces!).
    text = text.replace(' ', '')
    if len(text) % 8 != 0:
        raise ValueError("No integer number of bytes, please add some digits, "
                         "to get a total length multiple of 8.")
    # Only {'0', '1'} allowed!
    c_data = set(text)
    c_allowed = {'0', '1'}
    if not (c_data <= c_allowed):
        raise ValueError("Only binary digits and spaces are allowed, no '{}'!"
                         .format("', '".join(sorted(c_data - c_allowed))))
    return do_decypher(text, codec)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some text in binary form.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('cypher', help="Cypher data in binary.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "binary.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the “binary” text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to cypher in binary.")
    hide_parser.add_argument('-c', '--codec', default="ascii",
                             help="The codec to cypher in binary.")

    unhide_parser = sparsers.add_parser('decypher',
                                        help="Decypher binary to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from binary.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the decypherd "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The binary text to decypher.")
    unhide_parser.add_argument('-c', '--codec', default="ascii",
                               help="The codec to decypher from binary.")

    sparsers.add_parser('about', help="About Binary…")

    args = parser.parse_args()

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.codec)
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
            out = decypher(data, args.codec)
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

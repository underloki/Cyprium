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

__version__ = "0.1.0"
__date__ = "2012/04/27"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Gray =====
Gray code is another way to represent binary numbers, so that going from
one number to the next only needs one digit switch.

For example, “7” is “00111” in standard binary, and “00100” in Gray code,
while “8” is “01000” in binary and “01100” in Gray. As you can see, going
from 7 to 8 implies four digit changes with standard binary, while only
one in Gray code.

Historically, Gray code has been very important when binary data were still
handled by many mechanical hardware (like switches…), as it allowed less
usage of those switches, and a better synchronization (with mechanical
devices, it’s quite hard to get them switching exactly at the same time).

This tool allows you to “cypher” some text into some binary form of Gray code.

Indeed, each word length gives a different Gray code – usual (traditional)
words were of 3, 4 or 5 bits, but you can use any length you like…


Cyprium.Gray version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


DEFAULT = utils.UTF8
ASCII = utils.ASCII


def bin2gray_n(n):
    """
    Generates a mapping (binary code: gray code (text)), for words of length n.
    """
    fmt = "{{:0>{}b}}".format(n)
    return {i: fmt.format((i >> 1) ^ i) for i in range(2**n)}


def gray2bin_n(n):
    """
    Generates a mapping (gray code (text): binary code (text)),
    for words of length n.
    """
    fmt = "{{:0>{}b}}".format(n)
    return {fmt.format((i >> 1) ^ i): fmt.format(i) for i in range(2**n)}


def do_cypher(text, codec=DEFAULT, lengths=(8,), sep=""):
    """
    Function to convert some text to Gray code.
    """
    mapp = {n: bin2gray_n(n) for n in lengths}
    # Simpler to pass by a a textual representation of binary data... :/
    bytes = "".join("{:0>8b}".format(c) for c in text.encode(codec))

    ret = []
    for n in lengths:
        ret.append(sep.join(mapp[n][int("".join(c), 2)]
                            for c in utils.grouper(bytes, n, '0')))
    return ret


def cypher(text, codec=DEFAULT, lengths=(8,), sep=""):
    """Just a wrapper around do_cypher, with some checks."""
    # Check that text can be encoded with that codec.
    chars = set(text)
    try:
        cdc = codec
        "".join(chars).encode(cdc)
    except Exception as e:
        raise ValueError("The text could not be cyphered into given '{}' "
                         "encoding ({})".format(cdc, str(e)))
    return do_cypher(text, codec, lengths, sep)


def do_decypher(text, codec=DEFAULT, length=8):
    """
    Function to convert Gray code into text.
    Note: expect "unspaced" binary text as input!
    """
    mapp = gray2bin_n(length)

    bytes = "".join(mapp[chunk] for chunk in utils.grouper2(text, length))
    # We want to get back to real bytes, hence stripping down dummy '0' we
    # added at encode time to get an integer number of length-words.
    new_len = len(bytes)
    new_len -= new_len % 8
    bytes = bytes[:new_len]
    # And now, convert those textual bytes back to real bytes!
    bytes = utils.int8_to_bytes(int(c, 2) for c in utils.grouper2(bytes, 8))
    return bytes.decode(codec)


def decypher(text, codec=DEFAULT, length=8):
    """Just a wrapper around do_decypher, with some checks."""
    # Test length (*without* the spaces!).
    text = text.replace(' ', '')
    c_data = set(text)

    if len(text) % length != 0:
        raise ValueError("No integer number of bytes, please add some "
                         "bits, to get a total length multiple of {}."
                         "".format(length))
    # Get allowed digits.
    c_allowed = utils.get_allowed_digits(2)
    if not (c_data <= c_allowed):
        raise ValueError("Only binary digits and spaces are allowed, no '{}'!"
                         .format("', '".join(sorted(c_data - c_allowed))))
    return do_decypher(text, codec, length)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    import argparse
    parser = argparse.ArgumentParser(description="Cypher/decypher some text "
                                                 "in Gray code.")
    parser.add_argument('--debug', action="store_true", default=False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher', help="Cypher data.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data',
                         help="The text to cypher.")
    cparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="The codec to use for cyphering.")
    cparser.add_argument('-l', '--lengths', nargs="*", type=int,
                         default=(8,),
                         help="Which word length(s) to use for gray code "
                              "(defaults to 8, one byte).")

    dparser = sparsers.add_parser('decypher', help="Decypher data.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="The codec to use for decyphering.")
    dparser.add_argument('-l', '--length', type=int,
                         default=8,
                         help="Which word length is the Gray code "
                              "(defaults to 8, one byte).")

    sparsers.add_parser('about', help="About Gray…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.codec, args.lengths)
            out = "\n".join(out)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            if utils.DEBUG:
                raise e
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
            out = decypher(data, args.codec, args.length)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            if utils.DEBUG:
                raise e
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

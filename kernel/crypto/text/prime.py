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

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils


PRIMES = tuple(utils.all_primes(1000))

BASE_MIN = 1
BASE_MAX = len(PRIMES) - 26


__version__ = "0.5.1"
__date__ = "2012/01/25"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Prime =====
Prime allows you to cypher and decypher texts using prime numbers below 1000.

Allowed chars are: strict ASCII lowercase and space.

The cypher method takes an optional “base” (defaults to 1), which represent
the nth prime number to be used to encode 'a':
    base 1 ==> A = 2, B = 3, C = 5, …
    base 2 ==> A = 3, B = 5, C = 7, …

Base can be in [{}, {}].

E.g. with “a prime pair”:
    base 1: 2  53 61 23 41 11  53 2 23 61
    base 101: 547  641 647 599 617 571  641 547 599 647


Cyprium.Prime version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(BASE_MIN, BASE_MAX,
           __version__, __date__, utils.__pf__, utils.__pytver__)


def do_cypher(text, base=1):
    """Cypher a word in Prime code,from given base."""
    # Let’s rather build a dict, will be much quicker with long texts.
    maps = {k: str(PRIMES[v + base - 1])  # -1 because first base is 1...
            for v, k in enumerate(string.ascii_lowercase)}
    maps[' '] = ''
    return " ".join((maps[c] for c in text))


def cypher(text, base=1):
    """Just a wrapper around do_cypher"""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars.
    c_text = set(text)
    c_allowed = set(string.ascii_lowercase) | {' '}
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only strict ASCII "
                         "lowercase-chars and spaces): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    # Check for invalid base.
    if BASE_MIN > base > BASE_MAX:
        raise ValueError("The base must be a digit in [{}, {}]."
                         "".format(BASE_MIN, BASE_MAX))
    return do_cypher(text, base)


def do_decypher(text, base=1):
    """Decypher a Prime-coded text."""
    # Let’s rather build a dict, will be much quicker with long texts.
    maps = {str(PRIMES[k + base - 1]): v
            for k, v in enumerate(string.ascii_lowercase)}
    maps[''] = ' '
    # split(' ') to get empty string for double spaces.
    return "".join((maps[c] for c in text.split(' ')))


def decypher(text, base=1):
    """Just a wrapper around do_decypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed = set("0123456789 ")
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only digits "
                         "and spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    # Check for invalid base.
    if BASE_MIN > base > BASE_MAX:
        raise ValueError("The base must be a digit in [{}, {}]."
                         "".format(BASE_MIN, BASE_MAX))
    # Check for invalid codes (numbers).
    c_codes = {int(i) for i in set(text.split())}
    c_allowed = set(PRIMES[base - 1:base + 26])
    if not (c_codes <= c_allowed):
        raise ValueError("Text contains unallowed codes for given base {}: "
                         "'{}'!"
                         .format(base,
                                 "', '".join((str(i) for i in
                                              sorted(c_codes - c_allowed)))))
    return do_decypher(text, base)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some text in "
                                     "prime code.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher', help="Encrypt text in prime.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-b', '--base', type=int, default=1,
                         help="Which base to use to cypher the text "
                              "(1: A = 2; 2: A = 3; 3: A = 5; etc.).")

    dparser = sparsers.add_parser('decypher', help="Decypher prime to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-b', '--base', type=int, default=1,
                         help="Which base to use to decypher the text "
                              "(1: 5 = C; 2: 5 = B; 3: 5 = A; etc.).")

    sparsers.add_parser('about', help="About Prime.")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.base)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            if utils.DEBUG:
                raise e
            raise e
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return

    if args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decypher(data, args.base)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            if utils.DEBUG:
                raise e
            raise e
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

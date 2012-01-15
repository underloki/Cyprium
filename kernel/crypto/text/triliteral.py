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

__version__ = "0.5.0"
__date__ = "2012/01/13"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Triliteral =====

Triliteral is a cryptographic tool which can cypher text in the triliteral
code, which is a base-three encoding using A, B and C as digits.

Cypher input can be any string containing ASCII lowercase letters only
(no spaces), decypher input must be an integer number of groups of three
(A,B,C) digits.

That tool also has an optional trick, called “base”: you can choose which
letter to use as “first code”, so that, if e.g. you choose a base of 4,
the first code (AAA) is used by 'e', AAB by 'f', etc., and cycling back to CBC
for 'a', CCA for 'b', and so on. The default base  (AAA for 'a') being 1.

Cyprium.Biliteral version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


# No static MAP, as we generate one based on the “base” arg...
# However, we need a set of all possible triliteral codes, for decyphering
# checks.
CHARS = string.ascii_lowercase
CODES = {utils.num_to_base(v, ('A', 'B', 'C'), 3) for v in range(len(CHARS))}


def do_cypher(text, base=1):
    """
    Cypher message to triliteral (with optional base, shift)
    'd' --> ABA (base 0), 'd' --> CBC (base 7)
    """
    base -= 1
    MAP = {k: utils.num_to_base((v - base) % 26, ('A', 'B', 'C'), 3)
                                for v, k in enumerate(CHARS)}
    return "".join((MAP[c] for c in text))


def cypher(text, base=1):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(CHARS)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only lowercase "
                         "strict ASCII chars are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_cypher(text, base=base)


def do_decypher(text, base=1):
    """
    Decypher message to triliteral (with optional base, shift)
    ABA --> 'd' (base 0), ABA --> 'j' (base 7)
    """
    base -= 1
    R_MAP = {utils.num_to_base((k - base) % 26, ('A', 'B', 'C'), 3): v
                               for k, v in enumerate(CHARS)}
    return "".join((R_MAP[c] for c in utils.grouper2(text, 3)))


def decypher(text, base=1):
    """Just a wrapper around do_decypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = {'A', 'B', 'C'}
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only A and B "
                         "are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    # Check for length.
    if len(text) % 3:
        raise ValueError("Text must contains an integer number of groups of "
                         "three chars (current length: {})…"
                         "".format(len(text)))
    # Check for valid triliteral codes.
    c_text = {c for c in utils.grouper2(text, 3)}
    c_allowed = CODES
    if not (c_text <= c_allowed):
        raise ValueError("Text contains invalid triliteral codes: '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decypher(text, base=base)


def test():
    print("Start test...")
    txt = "".join(list(CHARS) * 10)
    for b in range(1, 27):
        coded = cypher(txt, b)
        decoded = decypher(coded, b)
        if txt != decoded:
            raise Exception("Test error, text and decoded(coded) text are "
                            "not the same!")
    print("...Success")


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some lowercase-"
                                     "no-space text to/from triliteral"
                                     "code.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cypher_parser = sparsers.add_parser('cypher', help="Cypher text in "
                                                       "triliteral.")
    cypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert to "
                                    "triliteral.")
    cypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the triliteral "
                                    "text.")
    cypher_parser.add_argument('-d', '--data',
                               help="The text to cypher in triliteral.")
    cypher_parser.add_argument('-b', '--base', type=int, default=1,
                               help="The base of triliteral cyphering."
                                    "(e -> ABB in base 0, e -> AAA in base 4)")

    uncypher_parser = sparsers.add_parser('decypher',
                                          help="Decypher triliteral to text.")
    uncypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to convert "
                                      "from triliteral.")
    uncypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    uncypher_parser.add_argument('-d', '--data',
                                 help="The text to decypher.")
    uncypher_parser.add_argument('-b', '--base', type=int, default=0,
                                 help="The base of triliteral cyphering."
                                      "(AAA -> a in base 0, AAA -> e in "
                                      "base 4)")

    sparsers.add_parser('about', help="About Triliteral…")
    sparsers.add_parser('test', help="Run a small auto-test.")

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
            print(e, "\n\n")
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return 0

    elif args.command == "decypher":
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

    elif args.command == "test":
        test()
        return


if __name__ == "__main__":
    main()

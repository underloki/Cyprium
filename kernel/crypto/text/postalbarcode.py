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

__version__ = "0.2.0"
__date__ = "2012/01/11"
__python__ = "3.x"  # Required Python version
__about__ = """
===== About PostalBarcode =====

Postal bar code allows you to cypher and decypher a number into that bar code.

You can use digits only.

You can get either the original code (with pipes and dots), or the more widely
used “classical” version (with pipes and spaces), either in straight or
reversed order. Cyphered digits are space-separated.

Example : “3141592654”:
org stght:
    “⋅|||⋅| ⋅|⋅||| |⋅⋅||| ⋅|⋅||| |⋅|⋅|| |||⋅⋅| ⋅||⋅|| |⋅||⋅| |⋅|⋅|| |⋅⋅|||”
org rev:
    “|⋅⋅||| |⋅|⋅|| |⋅||⋅| ⋅||⋅|| |||⋅⋅| |⋅|⋅|| ⋅|⋅||| |⋅⋅||| ⋅|⋅||| ⋅|||⋅|”
cls straight:
    “ ||| |  | ||| |  |||  | ||| | | || |||  |  || || | || | | | || |  |||”
cls rev:
    “|  ||| | | || | || |  || || |||  | | | ||  | ||| |  |||  | |||  ||| |”

Note: Output order is always that one (original straight, original reversed,
classical straight, classical reversed), whatever are the chosen options.

Cyprium.PostalBarcode version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


CHAR1 = '|'
CHAR2 = '⋅'
CHAR3 = ' '

# Cyphering dict, "original" method.
# XXX Not using CHARx here, for sake of readability!
O_MAP = {'0': "⋅⋅||||",
         '1': "⋅|⋅|||",
         '2': "⋅||⋅||",
         '3': "⋅|||⋅|",
         '4': "|⋅⋅|||",
         '5': "|⋅|⋅||",
         '6': "|⋅||⋅|",
         '7': "||⋅⋅||",
         '8': "||⋅|⋅|",
         '9': "|||⋅⋅|"}

# Cyphering dict, "classical" method (spaces instead of points).
C_MAP = {k: v.replace('⋅', ' ') for k, v in O_MAP.items()}

# Decyphering dict, "original" method.
RO_MAP = utils.revert_dict(O_MAP)

# Decyphering dict, "classical" method.
RC_MAP = utils.revert_dict(C_MAP)


def do_cypher(text, m_org=True, m_cls=False, o_stght=True, o_rev=False):
    """Function to convert some text to postal barcode.
       Returns a list of 1 to 4 str, based on options' values:
           [org, reversed_org, cls, reversed_cls].
    """
    ret = []
    if m_org:
        if o_stght:
            ret.append(" ".join((O_MAP[n] for n in text)))
        if o_rev:
            ret.append(" ".join((O_MAP[n] for n in reversed(text))))
    if m_cls:
        if o_stght:
            ret.append(" ".join((C_MAP[n] for n in text)))
        if o_rev:
            ret.append(" ".join((C_MAP[n] for n in reversed(text))))
    return ret


def cypher(text, m_org=True, m_cls=False, o_stght=True, o_rev=False):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise Exception("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(O_MAP.keys())
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only digits are "
                        "allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_cypher(text, m_org=m_org, m_cls=m_cls,
                     o_stght=o_stght, o_rev=o_rev)


def do_decypher(text, o_stght=True, o_rev=False):
    """Function to convert postal barcode text into clear text.
       Note that method (original or classical) is auto-detected,
       but you still need to provide the desired order(s).
       Returns a list of one or two decyphered texts:
           [o_stght, o_rev]
    """
    ret = []
    if CHAR2 in text:
        # Original method.
        m = RO_MAP
    else:
        # Classical method.
        m = RC_MAP
    lcar = []
    for code in utils.grouper2(text, 6, 1):
        lcar.append(m[code])
    if o_stght:
        ret.append("".join(lcar))
    if o_rev:
        ret.append("".join(reversed(lcar)))
    return ret


def decypher(text, o_stght=True, o_rev=False):
    """Wrapper around do_decypher, making some checks."""
    if not text:
        raise Exception("No text given!")
    # Check length...
    if ((len(text) + 1) % 7):
        raise Exception("Text has a wrong length (must be a multiple of "
                        "seven minus one (current length: {})."
                        "".format(len(text)))
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed1 = {CHAR1, CHAR2, ' '}
    c_allowed2 = {CHAR1, CHAR3, ' '}
    if not (c_text <= c_allowed1 or c_text <= c_allowed2):
        raise Exception("Text contains unallowed chars (only pipes and "
                        "spaces/dots chars are allowed): '{}' or '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed1)),
                                  "', '".join(sorted(c_text - c_allowed2))))
    # Check for invalid codes...
    c_text = set(utils.grouper2(text, 6, 1))
    if CHAR2 in text:
        c_allowed = set(RO_MAP.keys())
    else:
        c_allowed = set(RC_MAP.keys())
    if not (c_text <= c_allowed):
        raise Exception("Text contains unknown codes: '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decypher(text, o_stght=o_stght, o_rev=o_rev)


def test():
    print("Start test...")
    txt = "".join(list(O_MAP.keys()) * 10)
    coded = cypher(txt)[0]
    decoded = decypher(coded)[0]
    if txt != decoded:
        raise Exception("Test error, text and decoded(coded) text are "\
                        "not the same!")
    coded = cypher(txt, m_org=False, m_cls=True, o_stght=False, o_rev=True)[0]
    decoded = decypher(coded, o_stght=False, o_rev=True)[0]
    if txt != decoded:
        raise Exception("Test error, text and decoded(coded) text are "\
                        "not the same!")
    print("...Success")


def main():
    # Treating direct script call with args
    # Args retrieval
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decrypt a number according to"
                                     "to Postal bar code.\n"
                                     "allowed chars: digits.")

    sparsers = parser.add_subparsers(dest="command")

    cypher_parser = sparsers.add_parser('cypher', help="Cypher text.")
    cypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                help="A file containing the text to cypher.")
    cypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                help="A file into which write the cyphered "
                                     "text.")
    cypher_parser.add_argument('-d', '--data', help="The text to cypher.")
    cypher_parser.add_argument('-g', '--original', action="store_false",
                               default=True, help="Do not output original "
                                                  "version.")
    cypher_parser.add_argument('-c', '--classical', action="store_true",
                               default=False, help="Output classical version.")
    cypher_parser.add_argument('-s', '--straight', action="store_false",
                               default=True, help="Do not output straight "
                                                  "order.")
    cypher_parser.add_argument('-r', '--reversed', action="store_true",
                               default=False, help="Output reversed order.")

    decypher_parser = sparsers.add_parser('decypher', help="Decypher text.")
    decypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to "
                                      "decypher.")
    decypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    decypher_parser.add_argument('-d', '--data', help="The text to decypher.")
    decypher_parser.add_argument('-s', '--straight', action="store_false",
                                 default=True, help="Do not output straight "
                                                    "order.")
    decypher_parser.add_argument('-r', '--reversed', action="store_true",
                                 default=False, help="Output reversed order.")

    sparsers.add_parser('about', help="About PostalBarcode…")
    sparsers.add_parser('test', help="Run a small auto-test.")

    args = parser.parse_args()

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, m_org=args.original, m_cls=args.classical,
                         o_stght=args.straight, o_rev=args.reversed)
            if args.ofile:
                for l in out:
                    args.ofile.write(l)
                    args.ofile.write("\n")
            else:
                print(*out, sep="\n")
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
            out = decypher(data, o_stght=args.straight, o_rev=args.reversed)
            if args.ofile:
                for l in out:
                    args.ofile.write(l)
                    args.ofile.write("\n")
            else:
                print(*out, sep="\n")
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

    elif args.command == "test":
        test()
        return


if __name__ == "__main__":
    main()

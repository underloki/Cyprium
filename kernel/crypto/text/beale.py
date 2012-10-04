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
import random
import re

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.1.0"
__date__ = "2012/10/02"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Beale =====
This cyphering is rather simple, though nearly impossible to hack without the key.

It simply takes each letter of the text to cypher, finds a word in the key starting with the same letter, and output
this word’s index in the key. This implies it can only cypher letters (converted to upper-ASCII chars), everything
else is dropped/lost.

Historically, Beale is the name of the man who invented this cyphering, see wikipedia for more details!

E.g. with both above paragraphs as key, “Beale” could be cyphered as “49, 43, 41, 21, 44”,
“49, 43, 12, 37, 44”, “49, 44, 22, 47, 43”, etc.

Obviously, you have to feature a key containing all the letters (i.e. words which first letters…)
needed by the data to cypher, and preferably several times, to get a better cyphering.

Please note that this tool uses a pseudo-random way of choosing an index for a given letter, driven by a seed number.
This means that you will always get the same result for the same data/key/seed triple. Change the seed and you’ll
get a different result!

Cyprium.Beale version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)

VALID_CHARSET = set(string.ascii_uppercase) | {' '}

# Used to adapt dics, for hacking.
DIC_CHARSET = utils.WE2UASCII_CHARSET
DIC_CHARMAP = utils.WE2UASCII_CHARMAP
TRANSLATE = str.maketrans(DIC_CHARMAP)


def key2mapp(key):
    """
    Return a mapping {first letter: list indices and index: letter} from key text.
    """
    regex = re.compile("\w+")
    key = key.translate(TRANSLATE)
    mapp = {}
    idx = 1
    for w in regex.findall(key):
        if w[0] not in string.digits:
            mapp.setdefault(w[0], []).append(idx)
            mapp[idx] = w[0]
            idx += 1
    return mapp

def do_cypher(text, mapp, seed=0):
    """
    Cypher message to beale code.
    mapp must be a mapping {uppercaseletter: listofnumbers}. All chars not in
    mapp are simply ignored!
    Always output the same result for same text/mapp/seed.
    """
    random.seed(seed)
    return tuple(random.choice(mapp[c]) for c in text.upper() if c in mapp)


def cypher(text, key, seed=0):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    text = text.translate(TRANSLATE)
    text = re.sub("\W", "", text)
    c_text = set(text)
    c_allowed = set(string.ascii_uppercase) | {' '}
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only chars and "
                         "spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))

    mapp = key2mapp(key)
    c_key = set(c for c in mapp.keys() if c in c_allowed)
    if not (c_text <= c_key):
        raise ValueError("The key does not contain all needed chars, '{}' are "
                         "missing!"
                         "".format("', '".join(sorted(c_text - c_key))))

    return " ".join(str(n) for n in do_cypher(text, mapp, seed))


def do_decypher(numbers, mapp):
    """
    Decypher message from beale.
    Expects pre-processed data (text-> list of numbers, key -> mapping {number: letter}).
    """
    return "".join(mapp[n] for n in numbers)


def decypher(text, key):
    """Just a wrapper around do_decypher, with some checks/pre-process."""
    if not text:
        raise ValueError("No text given!")
    # Only extract numbers!
    regex = re.compile("\d+")
    numbers = tuple(int(n) for n in regex.findall(text))
    c_numbers = set(numbers)

    mapp = key2mapp(key)
    c_key = set(n for n in mapp.keys() if isinstance(n, int))
    if not (c_numbers <= c_key):
        raise ValueError("Looks like you got the wrong key, pal! Those words’ indices are out of bound: '{}'!"
                         "".format("', '".join(str(n) for n in sorted(c_numbers - c_key))))

    return do_decypher(numbers, mapp)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some text to/from Beale code.")
    parser.add_argument('--debug', action="store_true", default=False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher', help="Cypher text in Beale’s code.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-k', '--key',
                         help="The cyphering key, see about help for details.")
    cparser.add_argument('-K', '--keyfile', type=argparse.FileType('r'),
                         help="A file containing the cyphering key.")
    cparser.add_argument('-s', '--seed', type=int, default=None,
                         help="The seed of the random choice of words for a given letter. "
                              "A same text/key/seed is guaranteed to always give the same cyphering!")

    dparser = sparsers.add_parser('decypher',
                                          help="Decypher Beale to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to convert "
                                      "from Beale.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    dparser.add_argument('-d', '--data',
                                 help="The text to decypher.")
    dparser.add_argument('-k', '--key',
                         help="The decyphering key, see about help for details.")
    dparser.add_argument('-K', '--keyfile', type=argparse.FileType('r'),
                         help="A file containing the decyphering key.")

    sparsers.add_parser('about', help="About Beale…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            key = args.key
            if args.keyfile:
                key = args.keyfile.read()
            out = ", ".join(str(n) for n in cypher(data, key, args.seed))
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
            if args.keyfile:
                args.keyfile.close()
        return 0

    elif args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            key = args.key
            if args.keyfile:
                key = args.keyfile.read()
            out = decypher(data, key)
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
            if args.keyfile:
                args.keyfile.close()
        return 0

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

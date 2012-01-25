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

__version__ = "0.6.0"
__date__ = "2012/01/21"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Octopus =====

Octopus is a simple numbers/text converter. It allows you to cypher and
decypher text to/from binary, octal, decimal or hexadecimal.

It can also cut the output into bytes separated by spaces.

You can use special characters and accents, if you specify a compatible
encoding (e.g. default one, utf-8).

You can also choose ASCII 7bit to get binary encoded over 7 bits instead
of 8.

Cyprium.Octopus version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


ASCII7 = "ascii7"
ASCII = "ascii"
DEFAULT = "utf-8"

N_DIGITS = {2: 8, 8: 3, 10: 3, 16: 2}
D_ALLOWED = utils.BASE_DIGITS_ALLOWED


def do_cypher(text, codec=DEFAULT, bases=(2,), sep=""):
    """
    Function to convert some text to binary/octal/decimal/hexadecimal text.
    """
    # Create a dict mapping all chars to their binary representation,
    # in the given codec (might be more than one byte!).
    n_digits = {k: v for k, v in N_DIGITS.items()}
    if codec == ASCII7:
        codec = ASCII
        n_digits[2] = 7

    ret = []
    MAP = dict.fromkeys(text)
    if 2 in bases:
        for c in MAP:
            b = c.encode(codec)
            MAP[c] = (sep.join(("{{:0>{}b}}".format(n_digits[2]),) *
                               len(b))).format(*b)
        ret.append(sep.join((MAP[c] for c in text)))
    if 8 in bases:
        for c in MAP:
            b = c.encode(codec)
            MAP[c] = (sep.join(("{{:0>{}o}}".format(n_digits[8]),) *
                               len(b))).format(*b)
        ret.append(sep.join((MAP[c] for c in text)))
    if 10 in bases:
        for c in MAP:
            b = c.encode(codec)
            MAP[c] = (sep.join(("{{:0>{}d}}".format(n_digits[10]),) *
                               len(b))).format(*b)
        ret.append(sep.join((MAP[c] for c in text)))
    if 16 in bases:
        for c in MAP:
            b = c.encode(codec)
            MAP[c] = (sep.join(("{{:0>{}X}}".format(n_digits[16]),) *
                               len(b))).format(*b)
        ret.append(sep.join((MAP[c] for c in text)))
    return ret


def cypher(text, codec=DEFAULT, bases=(2,), sep=""):
    """Just a wrapper around do_cypher, with some checks."""
    # Check that text can be encoded with that codec.
    chars = set(text)
    try:
        cdc = codec
        if cdc == ASCII7:
            cdc = ASCII
        "".join(chars).encode(cdc)
    except Exception as e:
        raise ValueError("The text could not be cyphered into given '{}' "
                         "encoding ({})".format(cdc, str(e)))
    # Check for valid bases.
    b_data = set(bases)
    b_allowed = set(N_DIGITS.keys())
    if not (b_data <= b_allowed):
        raise ValueError("Only {} bases are allowed, no '{}'!"
                         .format(sorted(N_DIGITS.keys()),
                                 "', '".join(b_data - b_allowed)))
    return do_cypher(text, codec, bases, sep)


def do_decypher(text, codec=DEFAULT, base=2):
    """
    Function to convert binary/octal/decimal/hexadecimal text into text.
    Note: expect "unspaced" text as input!
    """
    n_digits = {k: v for k, v in N_DIGITS.items()}
    if codec == ASCII7:
        codec = ASCII
        n_digits[2] = 7

    if base != 16:
        ints = (int(''.join(p), base)
                for p in utils.grouper(text, n_digits[base], ''))
        byts = utils.int8_to_bytes(ints)
    else:
        byts = bytes.fromhex(text)
    return byts.decode(codec)


def decypher(text, codec=DEFAULT, base=None):
    """Just a wrapper around do_decypher, with some checks."""
    if base and base not in N_DIGITS:
        raise ValueError("Invalid base value ({})!.".format(base))

    # Test length (*without* the spaces!).
    text = text.replace(' ', '')
    c_data = set(text)
    base_names = {2: "binary", 8: "octal", 10: "decimal", 16: "hexadecimal"}

    n_digits = {k: v for k, v in N_DIGITS.items()}
    if codec == ASCII7:
        n_digits[2] = 7

    if base is None:
        base = utils.base_autodetect(text, n_digits,
                                     sorted(n_digits.keys(), reverse=True))

    if len(text) % n_digits[base] != 0:
        raise ValueError("No integer number of bytes, please add some "
                         "digits, to get a total length multiple of {}."
                         "".format(n_digits[base]))
    # Get allowed digits.
    c_allowed = utils.get_allowed_digits(base)
    if not (c_data <= c_allowed):
        raise ValueError("Only {} digits and spaces are allowed, no '{}'!"
                         .format(base_names[base],
                                 "', '".join(sorted(c_data - c_allowed))))
    return do_decypher(text, codec, base)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    # Helper func.
    _bases = {'b': 2, 'o': 8, 'd': 10, 'x': 16}
    def _2ibase(b):
        return _bases.get(b, None)

    import argparse
    parser = argparse.ArgumentParser(description="Cypher/decypher some text "
                                                 "in binary/octal/decimal/"
                                                 "hexadecimal form.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher', help="Cypher data in binary/octal/"
                                                 "decimal/hexadecimal.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data',
                         help="The text to cypher.")
    cparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="The codec to use for cyphering.")
    cparser.add_argument('-a7', '--ascii7', action="store_true",
                         help="Use ASCII codec for cyphering, and output "
                              "7-bits “bytes” in binary (overrides --codec).")
    cparser.add_argument('-b', '--bases', nargs="*", type=_2ibase,
                         choices=_bases.values(), default=(2,),
                         help="In which base(s) ouput the cyphered text "
                              "([b]inary, [o]ctal, [d]ecimal, he[x]adecimal, "
                              "default to binary if none chosen).")

    dparser = sparsers.add_parser('decypher',
                                        help="Decypher binary to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="The codec to use for decyphering.")
    dparser.add_argument('-a7', '--ascii7', action="store_true",
                         help="Use ASCII codec for decyphering, assuming "
                              "7-bits “bytes” (overrides --codec).")
    dparser.add_argument('-b', '--base', type=_2ibase,
                         choices=_bases.values(), default=None,
                         help="In which base(s) ouput the cyphered text "
                              "([b]inary, [o]ctal, [d]ecimal, he[x]adecimal, "
                              "default for auto-detection).")

    sparsers.add_parser('about', help="About Octopus…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            if args.ascii7:
                args.codec = ASCII7
            out = cypher(data, args.codec, args.bases)
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
            if args.ascii7:
                args.codec = ASCII7
            out = decypher(data, args.codec, args.base)
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

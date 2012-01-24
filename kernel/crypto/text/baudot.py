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


__version__ = "0.5.1"
__date__ = "2012/01/24"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Baudot =====
Baudot allows you to cypher and decypher some text using Baudot codes.

Allowed chars are: upper-case alphabetic letters, spaces
digits, and the symbols : '!\x00£"$\'&)(\n\r,/.-;:=x06?'
they are three modes:
0 : binary output
1 : octal output
2 : hexa output
with text="THA 12.":
    cypher(txt, 0) = '11111 00001 00101 11000 00100 11011 11101 11001 00111'
    cypher(txt, 1) = '037 001 005 030 004 033 035 031 007'
    cypher(txt, 2) = '1F 01 05 18 04 1B 1D 19 07'
Cyprium.Baudot version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr
Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


L_MODE = 31
S_MODE = 27

L_MAP = {'a': 3,   # 00011
         'b': 25,  # 11001
         'c': 14,  # 01110
         'd': 9,   # 01001
         'e': 1,   # 00001
         'f': 13,  # 01101
         'g': 26,  # 11010
         'h': 20,  # 10100
         'i': 6,   # 00110
         'j': 11,  # 01011
         'k': 15,  # 01111
         'l': 18,  # 10010
         'm': 28,  # 11100
         'n': 12,  # 01100
         'o': 24,  # 11000
         'p': 22,  # 10110
         'q': 23,  # 10111
         'r': 10,  # 01010
         's': 5,   # 00101
         't': 16,  # 10000
         'u': 7,   # 00111
         'v': 14,  # 01110
         'w': 19,  # 10011
         'x': 29,  # 11101
         'y': 21,  # 10101
         'z': 17,  # 10001
         ' ': 4,   # 00100
         '\n': 2,  # 00010  NOTE: using only LF for new lines.
         '\0': 0}  # 00000  NOTE: should never be used in python.
#        CR: 8     # 01000

S_MAP = {'0': 22,  # 10110
         '1': 23,  # 10111
         '2': 19,  # 10011
         '3': 1,   # 00001
         '4': 10,  # 01010
         '5': 16,  # 10000
         '6': 21,  # 10101
         '7': 7,   # 00111
         '8': 6,   # 00110
         '9': 24,  # 11000
         '-': 3,   # 00011
         '\'': 5,  # 00101
         ',': 12,  # 01100
         '!': 13,  # 01101
         ':': 14,  # 01110
         '(': 15,  # 01111
         '+': 17,  # 10001
         ')': 18,  # 10010
         '£': 20,  # 10100
         '?': 25,  # 11001
         '&': 26,  # 11010
         '.': 28,  # 11100
         '/': 29,  # 11101
         '=': 30,  # 11110
         ' ': 4,   # 00100
         '\n': 2,  # 00010  NOTE: using only LF for new lines.
         '\0': 0}  # 00000  NOTE: should never be used in python.
#        WRU: 9    # 01001
#        BELL: 11  # 01011
#        CR: 8     # 01000


ALLOWED_CHARS = sorted(set(L_MAP.keys()) | set(S_MAP.keys()))


# Now, create the four bases mappings.
# Number of digits, in each base.
N_DIGITS = {2: 5, 8: 2, 10: 2, 16: 2}

# Mappings, for each base.
MAPS = {}
for b in N_DIGITS.keys():
    _b = utils.BASE_DIGITS_ALLOWED[:b]
    _l_m = {k: utils.num_to_base(v, _b, N_DIGITS[b]) for k, v in L_MAP.items()}
    _s_m = {k: utils.num_to_base(v, _b, N_DIGITS[b]) for k, v in S_MAP.items()}
    _m = _l_m.copy()
    _m.update(_s_m)
    MAPS[b] = {L_MODE: utils.num_to_base(L_MODE, _b, N_DIGITS[b]),
               S_MODE: utils.num_to_base(S_MODE, _b, N_DIGITS[b]),
               "MAP": _m,
               "RMAP": {L_MODE: utils.revert_dict(_l_m),
                        S_MODE: utils.revert_dict(_s_m)}}
del _l_m
del _s_m
del _m


def _get_mode(c):
    """Return mode of a given char, assuming it is a valid one!"""
    if c in L_MAP:
        return L_MODE
    else:
        return S_MODE


def do_cypher_bin(txt):
    lst = []
    mode = get_mode(txt[0])
    lst.append(mode)
    for c in txt:
        if mode!= get_mode(c):
            mode = get_mode(c)
            lst.append(mode)
        lst.append(MAP[c])
    return lst


def do_cypher(text, bases=(2,)):
    """Cypher some text in baudot code, in given base."""
    ret = []
    for base in sorted(set(bases)):
        l = []
        maps = MAPS[base]
        prev_mode = None
        for c in text:
            mode = maps[_get_mode(c)]
            if mode != prev_mode:
                l.append(mode)
                prev_mode = mode
            l.append(maps["MAP"][c])
        ret.append("".join(l))
    return ret


def cypher(text, bases=(2,)):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed = set(ALLOWED_CHARS)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only strict ASCII "
                         "lowercase chars, digits  and some symbols): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    # Check for valid bases.
    b_data = set(bases)
    b_allowed = set(N_DIGITS.keys())
    if not (b_data <= b_allowed):
        raise ValueError("Only {} bases are allowed, no '{}'!"
                         .format(sorted(N_DIGITS.keys()),
                                 "', '".join(b_data - b_allowed)))
    return do_cypher(text, bases)


def do_decypher(text, base=2):
    """
    Function to convert binary/octal/decimal/hexadecimal baudot text into text.
    Note: expect "unspaced" text as input!
    """
    ret = []
    maps = MAPS[base]
    # This makes mandatory the first byte is a mode switch
    # XXX Use rather a default (letters?) one?
    mode = None
    for c in utils.grouper(text, N_DIGITS[base], ''):
        c = "".join(c)
        if c == maps[L_MODE]:
            mode = L_MODE
        elif c == maps[S_MODE]:
            mode = S_MODE
        else:
            ret.append(maps["RMAP"][mode][c])
    return "".join(ret)


def decypher(text, base=None):
    """Just a wrapper around do_decypher, with some checks."""
    if base and base not in N_DIGITS:
        raise ValueError("Invalid base value ({})!.".format(base))

    if not text:
        raise ValueError("No text given!")
    # Test length (*without* the spaces!).
    text = text.replace(' ', '')
    c_data = set(text)
    base_names = {2: "binary", 8: "octal", 10: "decimal", 16: "hexadecimal"}

    if base is None:
        base = utils.base_autodetect(text, N_DIGITS,
                                     sorted(N_DIGITS.keys(), reverse=True))

    if (len(text) % N_DIGITS[base]) != 0:
        raise ValueError("No integer number of bytes, please add some "
                         "digits, to get a total length multiple of {}."
                         "".format(N_DIGITS[base]))
    # Get allowed digits.
    c_allowed = utils.get_allowed_digits(base)
    if not (c_data <= c_allowed):
        raise ValueError("Only {} digits and spaces are allowed, no '{}'!"
                         .format(base_names[base],
                                 "', '".join(sorted(c_data - c_allowed))))
    return do_decypher(text, base)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    # Helper func.
    _bases = {'b': 2, 'o': 8, 'd': 10, 'x': 16}
    def _2ibase(b):
        return _bases.get(b, None)

    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some text in binary/"
                                     "octal/decimal/hexadecimal Baudot code.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher', help="Encrypt text in Baudot.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-b', '--bases', nargs="*", type=_2ibase,
                         choices=_bases.values(), default=(2,),
                         help="In which base(s) ouput the cyphered text "
                              "([b]inary, [o]ctal, [d]ecimal, he[x]adecimal, "
                              "default to binary if none chosen).")

    dparser = sparsers.add_parser('decypher', help="Decypher Baudot to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-b', '--base', type=_2ibase,
                         choices=_bases.values(), default=None,
                         help="In which base(s) ouput the cyphered text "
                              "([b]inary, [o]ctal, [d]ecimal, he[x]adecimal, "
                              "default for auto-detection).")

    sparsers.add_parser('about', help="About Baudot")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.bases)
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
        return

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

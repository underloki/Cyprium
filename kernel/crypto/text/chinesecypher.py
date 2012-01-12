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

__version__ = "0.1.0"
__date__ = "2012/01/10"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About ChineseCipher =====

ChineseCipher allows you to cypher and decypher ASCII lowercase text
into Chinese or Samurai (or their digit version) ciphers.

Note that the space-char is cyphered with 2 spaces.

For example, “the hackademy”:
    Chinese: “————||||| ——||| ——  ——||| — —|| ———|| — —||| —— ———|||| ——————”
    Samurai: “||||————— ||——— ||  ||——— | |—— |||—— | |——— || |||———— ||||||”
    Digits:  “45 23 20  23 10 12 32 10 13 20 34 60”

Cyprium.ChineseCipher version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


# Reference vowel first, then shift from that vowel.
MAP = {'a': (1, 0),
       'b': (1, 1),
       'c': (1, 2),
       'd': (1, 3),
       'e': (2, 0),
       'f': (2, 1),
       'g': (2, 2),
       'h': (2, 3),
       'i': (3, 0),
       'j': (3, 1),
       'k': (3, 2),
       'l': (3, 3),
       'm': (3, 4),
       'n': (3, 5),
       'o': (4, 0),
       'p': (4, 1),
       'q': (4, 2),
       'r': (4, 3),
       's': (4, 4),
       't': (4, 5),
       'u': (5, 0),
       'v': (5, 1),
       'w': (5, 2),
       'x': (5, 3),
       'y': (6, 0),
       'z': (6, 1)}

R_MAP = utils.revert_dict(MAP)


# To allow easy change of chars if needed...
CHAR1 = "—"
CHAR2 = "|"


def code_to_chinese(code):
    return "".join([CHAR1] * code[0] + [CHAR2] * code[1])


def code_to_samurai(code):
    return "".join([CHAR2] * code[0] + [CHAR1] * code[1])


def code_to_digits(code):
    return "".join((str(c) for c in code))


MAP_CHINESE = {k: code_to_chinese(v) for k, v in MAP.items()}
R_MAP_CHINESE = utils.revert_dict(MAP_CHINESE)

MAP_SAMURAI = {k: code_to_samurai(v) for k, v in MAP.items()}
R_MAP_SAMURAI = utils.revert_dict(MAP_SAMURAI)

MAP_DIGITS = {k: code_to_digits(v) for k, v in MAP.items()}
R_MAP_DIGITS = utils.revert_dict(MAP_DIGITS)


def do_cypher(text, chinese=False, samurai=False, digits=False):
    """Function to convert some text to Chinese cipher.
       Returns the asked variants.
    """
    enc_w = [w for w in text.split()]
    ret = []
    if chinese:
        lst = []
        for w in enc_w:
            lst.append(" ".join((MAP_CHINESE[c] for c in w)))
        ret.append("  ".join(lst))
    if samurai:
        lst = []
        for w in enc_w:
            lst.append(" ".join((MAP_SAMURAI[c] for c in w)))
        ret.append("  ".join(lst))
    if digits:
        lst = []
        for w in enc_w:
            lst.append(" ".join((MAP_DIGITS[c] for c in w)))
        ret.append("  ".join(lst))
    return ret


def cypher(text, chinese=False, samurai=False, digits=False):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise Exception("no text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(MAP.keys())
    c_allowed.add(' ')
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only ASCII lowercase "
                        "chars are allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_cypher(text, chinese=chinese, samurai=samurai, digits=digits)


def do_decypher(text):
    """Function to convert Braille us-437 text into clear text."""
    words = text.split('  ')
    chars = []

    is_chinese = is_samurai = False
    # Chinese version.
    c_test = words[0].rstrip()[0]
    if c_test == '—':
        is_chinese = True
    # Samurai version.
    elif c_test == '|':
        is_samurai = True
    # Else assume digits version!

    for w in words:
        w_chars = w.split()
        if is_chinese:
            chars += [R_MAP_CHINESE[c] for c in w_chars]
        elif is_samurai:
            chars += [R_MAP_SAMURAI[c] for c in w_chars]
        else:
            chars += [R_MAP_DIGITS[c] for c in w_chars]
        chars.append(' ')
    del chars[-1]  # Remove last space!
    return "".join(chars)


def decypher(text):
    """Wrapper around do_decypher, making some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars/codes...
    c_text = set(text.split())
    c_allowed_c = set(R_MAP_CHINESE.keys())
    c_allowed_s = set(R_MAP_SAMURAI.keys())
    c_allowed_d = set(R_MAP_DIGITS.keys())
    if c_text & c_allowed_c:
        # Some Chinese codes present, assume this is this cipher.
        if not (c_text <= c_allowed_c):
            raise ValueError("Text contains invalid Chinese cipher codes: "
                             "'{}'".format("', '".join(sorted(c_text -
                                                              c_allowed_c))))
    elif c_text & c_allowed_s:
        # Some Samurai codes present, assume this is this cipher.
        if not (c_text <= c_allowed_s):
            raise ValueError("Text contains invalid Samurai cipher codes: "
                             "'{}'".format("', '".join(sorted(c_text -
                                                              c_allowed_s))))
    elif c_text & c_allowed_d:
        # Some Chinese digit codes present, assume this is this cipher.
        if not (c_text <= c_allowed_d):
            raise ValueError("Text contains invalid Chinese cipher codes "
                             "(digits version): '{}'"
                             "".format("', '".join(sorted(c_text -
                                                          c_allowed_c))))
    else:
        # Nothing to see with this cipher!
        raise ValueError("Text contains no Chinese cipher codes!")
    return do_decypher(text)


def test():
    print("Start test...")
    for i in MAP.keys():
        txt = " ".join(list(MAP.keys()) * 10)
        chinese, samurai, digits = cypher(txt, chinese=True, samurai=True,
                                          digits=True)
        dec_c = decypher(chinese)
        dec_s = decypher(samurai)
        dec_d = decypher(digits)
        if txt != dec_c:
            raise Exception("Test error, text and decoded(chinese-coded) " \
                            "text are not the same!")
        if txt != dec_s:
            raise Exception("Test error, text and decoded(samurai-coded) " \
                            "text are not the same!")
        if txt != dec_d:
            raise Exception("Test error, text and decoded(digits-coded) " \
                            "text are not the same!")
    print("...Success")


def main():
    # Treating direct script call with args
    # Args retrieval
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decrypt a text according to"
                                     "to Chinese cipher.\n"
                                     "You can get the Chinese, Samurai and/or "
                                     "digits versions.\n")

    sparsers = parser.add_subparsers(dest="command")

    cypher_parser = sparsers.add_parser('cypher', help="Cypher text.")
    cypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                help="A file containing the text to cypher.")
    cypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                help="A file into which write the cyphered "
                                     "text.")
    cypher_parser.add_argument('-d', '--data', help="The text to cypher.")
    cypher_parser.add_argument('-c', '--chinese', action="store_true",
                                help="Output chinese version.")
    cypher_parser.add_argument('-s', '--samurai', action="store_true",
                                help="Output samurai version.")
    cypher_parser.add_argument('-g', '--digits', action="store_true",
                                help="Output digits version.")

    decypher_parser = sparsers.add_parser('decypher', help="Decypher text.")
    decypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to "
                                      "decypher.")
    decypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    decypher_parser.add_argument('-d', '--data', help="The text to decypher.")

    sparsers.add_parser('about', help="About ChineseChiper…")
    sparsers.add_parser('test', help="Run a small auto-test.")

    args = parser.parse_args()

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, chinese=args.chinese, samurai=args.samurai,
                          digits=args.digits)
            if args.ofile:
                args.ofile.write(out)
            else:
                print("\n".join(out))
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

    elif args.command == "test":
        test()
        return


if __name__ == "__main__":
    main()

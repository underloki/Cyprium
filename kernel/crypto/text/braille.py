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
__date__ = "2012/01/09"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Braille =====

Braille allows you to cypher and decypher text into informatic-Braille
us-437 (on 8 dots).

You can use all chars from the cp1252 charset (Windows 8bit encoding).

Example : “Hello world” → “125 15 123 123 135  2456 135 1235 123 145”

Note that the space-char is cyphered with 2 spaces.

Cyprium.Braille version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


# This table is using english US-437, based on cp1252 encoding.
# NOTE: the french CDFR1252 uses the same charset, but different Braille codes.
MAP = {'\x00': '478',       # NUL, null
       '\x01': '178',       # SOH, start of heading
       '\x02': '1278',      # STX, start of text
       '\x03': '1478',      # ETX, end of text
       '\x04': '14578',     # EOT, end of transmission
       '\x05': '1578',      # ENQ, enquiry
       '\x06': '12478',     # ACK, acknowledge
       '\x07': '124578',    # BEL, bell
       '\x08': '12578',     # BS,  backspace
       '\x09': '2478',      # HT,  horizontal tabulation
       '\x0A': '24578',     # LF,  line feed
       '\x0B': '1378',      # VT,  vertical tabulation
       '\x0C': '12378',     # FF,  form feed
       '\x0D': '13478',     # CR,  carriage return
       '\x0E': '134578',    # SO,  shift out
       '\x0F': '13578',     # SI,  shift in
       '\x10': '123478',    # DLE, data link escape
       '\x11': '1234578',   # DC1, device control 1
       '\x12': '123578',    # DC2, device control 2
       '\x13': '23478',     # DC3, device control 3
       '\x14': '234578',    # DC4, device control 4
       '\x15': '13678',     # NAK, negative acknowledge
       '\x16': '123678',    # SYN, synchronous idle
       '\x17': '245678',    # ETB, end of transmission block
       '\x18': '134678',    # CAN, cancel
       '\x19': '1345678',   # EM,  end of medium
       '\x1A': '135678',    # SUB, substitute
       '\x1B': '24678',     # ESC, escape
       '\x1C': '125678',    # FS,  file separator
       '\x1D': '1245678',   # GS,  group separator
       '\x1E': '4578',      # RS,  record separator
       '\x1F': '45678',     # US,  unit separator
       ' ': '',
       '!': '2346',
       '"': '5',
       '#': '3456',
       '$': '1246',
       '%': '146',
       '&': '12346',
       '\'': '3',
       '(': '12356',
       ')': '23456',
       '*': '16',
       '+': '346',
       ',': '6',
       '-': '36',
       '.': '46',
       '/': '34',
       '0': '356',
       '1': '2',
       '2': '23',
       '3': '25',
       '4': '256',
       '5': '26',
       '6': '235',
       '7': '2356',
       '8': '236',
       '9': '35',
       ':': '156',
       ';': '56',
       '<': '126',
       '=': '123456',
       '>': '345',
       '?': '1456',
       '@': '47',
       'A': '17',
       'B': '127',
       'C': '147',
       'D': '1457',
       'E': '157',
       'F': '1247',
       'G': '12457',
       'H': '1257',
       'I': '247',
       'J': '2457',
       'K': '137',
       'L': '1237',
       'M': '1347',
       'N': '13457',
       'O': '1357',
       'P': '12347',
       'Q': '123457',
       'R': '12357',
       'S': '2347',
       'T': '23457',
       'U': '1367',
       'V': '12367',
       'W': '24567',
       'X': '13467',
       'Y': '134567',
       'Z': '13567',
       '[': '2467',
       '\\': '12567',
       ']': '124567',
       '^': '457',
       '_': '4567',
       '`': '4',
       'a': '1',
       'b': '12',
       'c': '14',
       'd': '145',
       'e': '15',
       'f': '124',
       'g': '1245',
       'h': '125',
       'i': '24',
       'j': '245',
       'k': '13',
       'l': '123',
       'm': '134',
       'n': '1345',
       'o': '135',
       'p': '1234',
       'q': '12345',
       'r': '1235',
       's': '234',
       't': '2345',
       'u': '136',
       'v': '1236',
       'w': '2456',
       'x': '1346',
       'y': '13456',
       'z': '1356',
       '{': '246',
       '|': '1256',
       '}': '12456',
       '~': '45',
       '\x7F': '456',
       '€': '123467',
#      NA: '12568',
       '‚': '1268',
       'ƒ': '1678',
       '„': '3458',
       '…': '123568',
       '†': '345678',
       '‡': '1234678',
       'ˆ': '12678',
       '‰': '12468',
       'Š': '23468',
       '‹': '124568',
       'Œ': '14678',
#      NA: '348',
       'Ž': '567',
#      NA: '34567',
#      NA: '238',
       '‘': '34578',
       '’': '3457',
       '“': '145678',
       '”': '2468',
       '•': '3468',
       '–': '15678',
       '—': '234568',
       '˜': '134568',
       '™': '358',
       'š': '2368',
       '›': '58',
       'œ': '467',
#      NA: '468',
       'ž': '2357',
       'Ÿ': '124678',
       ' ': '168',
       '¡': '1468',
       '¢': '14568',
       '£': '1568',
       '¤': '13458',
       '¥': '2567',
       '¦': '1258',
       '§': '2458',
       '¨': '38',
       '©': '14567',
       'ª': '25678',
       '«': '12368',
       '¬': '1368',
       '\xAD': '367',       # SHY, trait d'union conditionnel
       '®': '1235678',
       '¯': '2345678',
       '°': '78',
       '±': '3678',
       '²': '235678',
       '³': '237',
       '´': '13568',
       'µ': '268',
       '¶': '24568',
       '·': '368',
       '¸': '148',
       '¹': '123567',
       'º': '1234568',
       '»': '12458',
       '¼': '2678',
       '½': '4678',
       '¾': '34678',
       '¿': '278',
       'À': '378',
       'Á': '27',
       'Â': '138',
       'Ã': '2367',
       'Ä': '67',
       'Å': '12467',
       'Æ': '68',
       'Ç': '267',
       'È': '2378',
       'É': '23567',
       'Ê': '8',
       'Ë': '123458',
       'Ì': '1248',
       'Í': '2578',
       'Î': '5678',
       'Ï': '167',
       'Ð': '57',
       'Ñ': '3467',
       'Ò': '28',
       'Ó': '1238',
       'Ô': '248',
       'Õ': '123468',
       'Ö': '1358',
       '×': '12358',
       'Ø': '3567',
       'Ù': '678',
       'Ú': '257',
       'Û': '12345678',
       'Ü': '1267',
       'Ý': '23678',
       'Þ': '35678',
       'ß': '234567',
       'à': '18',
       'á': '34568',
       'â': '258',
       'ã': '12348',
       'ä': '357',
       'å': '2348',
       'æ': '1348',
       'ç': '23458',
       'è': '2358',
       'é': '2568',
       'ê': '3568',
       'ë': '1458',
       'ì': '234678',
       'í': '23467',
       'î': '158',
       'ï': '578',
       'ð': '23568',
       'ñ': '23578',
       'ò': '458',
       'ó': '568',
       'ô': '347',
       'õ': '1567',
       'ö': '3478',
       '÷': '3578',
       'ø': '4568',
       'ù': '48',
       'ú': '37',
       'û': '1467',
       'ü': '13468',
       'ý': '128',
       'þ': '1234567',
       'ÿ': '7'}

R_MAP = utils.revert_dict(MAP)


def do_cypher(text):
    """Function to convert some text to Braille us-437 text (cp1252)."""
    return " ".join([MAP[c] for c in text])


def cypher(text):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise Exception("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(MAP.keys())
    if not (c_text <= c_allowed):
        raise Exception("Text contains unallowed chars (only chars in cp1252 "
                        "[Windows 8bit charset] are allowed): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_cypher(text)


def do_decypher(text):
    """Function to convert Braille us-437 text into clear text."""
    chars = []
    for w in text.split('  '):
        w_chars = w.split()
        chars += [R_MAP[c] for c in w_chars]
        chars.append(' ')
    del chars[-1]  # Remove last space!
    return "".join(chars)


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
        raise Exception("Text contains invalid Braille us-437 codes: '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decypher(text)


def test():
    print("Start test...")
    for i in MAP.keys():
        txt = "".join(list(MAP.keys()) * 10)
        coded = cypher(txt)
        decoded = decypher(coded)
        if txt != decoded:
            raise Exception("Test error, text and decoded(coded) text are "\
                            "not the same!")
    print("...Success")


def main():
    # Treating direct script call with args
    # Args retrieval
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decrypt a text according to"
                                     "to informatic Braille code us-437.\n"
                                     "example: 'the' ==> ''2345 125 15'.\n"
                                     "allowed chars: cp1252 charset.")

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

    sparsers.add_parser('about', help="About Braille…")
    sparsers.add_parser('test', help="Run a small auto-test.")

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

    elif args.command == "test":
        test()
        return


if __name__ == "__main__":
    main()

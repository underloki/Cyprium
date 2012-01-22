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
__date__ = "2012/01/14"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Baudot =====
Baudot allows you to cypher and decrypt textes in the
baudot-code.
Allows chars are: upper-case alphabetic letters, spaces
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

MAP_CHARS = {
    ' ': '00100',
    'A': '11000',
    'B': '10011',
    'C': '01110',
    'D': '10010',
    'E': '10000',
    'F': '10110',
    'G': '01011',
    'H': '00101',
    'I': '01100',
    'J': '11010',
    'K': '11110',
    'L': '01001',
    'M': '00111',
    'N': '00110',
    'O': '00011',
    'P': '01101',
    'Q': '11101',
    'R': '01011',
    'S': '10100',
    'T': '00001',
    'U': '11100',
    'V': '01111',
    'W': '11001',
    'X': '10111',
    'Y': '10101',
    'Z': '10001'}
MAP_DIGITS = {
    '0': '01101',
    '1': '11101',
    '2': '11001',
    '3': '10000',
    '4': '01010',
    '5': '00001',
    '6': '10101',
    '7': '11100',
    '8': '01100',
    '9': '00011'}
MAP_SYMBOLS = {
    '\x00': '00000',
    '\r': '00010',
    '\n': '01000',
    'x06': '10100',
    '!': '10110',
    '"': '10001',
    '$': '10010',
    '&': '01011',
    "'": '11010',
    '(': '11111',
    ')': '01001',
    ',': '00110',
    '-': '11000',
    '.': '00111',
    '/': '10111',
    ':': '01110',
    ';': '01111',
    '=': '00100',
    '?': '10011',
    '£': '00101'}
LETTER_MODE = "11111"
DIGIT_MODE = "11011"
MAP = dict(MAP_CHARS)
MAP.update(MAP_DIGITS)
MAP.update(MAP_SYMBOLS)
R_MAP = {LETTER_MODE: {}, DIGIT_MODE: {} }
R_MAP[LETTER_MODE].update({v:k for k,v in MAP_CHARS.items()})
R_MAP[DIGIT_MODE].update({v:k for k,v in MAP_DIGITS.items()})
R_MAP[DIGIT_MODE].update({v:k for k,v in MAP_SYMBOLS.items()})

def get_mode(c):
    if c in MAP_CHARS:
        return LETTER_MODE
    else:
        return DIGIT_MODE

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

def do_cypher (txt, base=2):
    res = lst = do_cypher_bin(txt)
    if base==8:
        res = [oct(int(i,2))[2:].rjust(3, "0") for i in lst]
    elif base == 16:
        res = [hex(int(i,2))[2:].rjust(2, "0").upper() for i in lst]
    return res

def cypher(text, mode=0):
    """Just a wrapper around do_cypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    if mode==1:
        base = 8
    elif mode==2:
        base = 16
    else:
        base = 2
    # Check for unallowed charsâ€¦
    c_text = set(text)
    c_allowed = set("".join(MAP_CHARS))
    c_allowed.update(set("".join(MAP_DIGITS)) | set("".join(MAP_SYMBOLS)))
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only strict ASCII "
                         "uppercase-chars, digits  and some symbols): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return " ".join(do_cypher(text, base))

def do_decypher_bin(lst):
    """Decypher text in baudot code.
       Returns the decyphered text
    """
    res = []
    mode = lst[0]
    for item in lst:
        if item in (LETTER_MODE, DIGIT_MODE):
            mode = item
            continue
        res.append(R_MAP[mode][item])
    return res

def do_decypher(txt):
    lst = txt.split()
    mode = len(lst[0])
    if mode==2:
        lst = [bin(int(i,16))[2:].rjust(5,"0") for i in lst]
    elif mode==3:
        lst = [bin(int(i,8))[2:].rjust(5,"0") for i in lst]
    elif mode==5:
        pass
    else:
        raise Exception("False Baudot-cyphered text!")
    return do_decypher_bin(lst)

def decypher(text):
    """Just a wrapper around do_decypher, with some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed = set("0123456789 ABCDEF")
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only digits "
                         "ABCDEF and spaces): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    try:
        res = do_decypher(text)
    except Exception as err:
        raise ValueError("Text contains bad Baudot representations!")
    return "".join(do_decypher(text))

def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decypher some text in "
                                     "baudot code.")
    sparsers = parser.add_subparsers(dest="command")
    hide_parser = sparsers.add_parser('cypher', help="Encrypt text in "
                                                     "baudot.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "baudot.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the baudot "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to cypher in baudot.")
    unhide_parser = sparsers.add_parser('decypher',
                                        help="Decypher baudot to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from baudot.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the decyphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The text to decypher.")
    sparsers.add_parser('about', help="About Baudot")
    args = parser.parse_args()
    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data)
            text = out
            b_text = ""
            if args.ofile:
                args.ofile.write(text)
                if b_text:
                    args.ofile.write("\n\n")
                    args.ofile.write(b_text)
            else:
                print(text)
        except Exception as e:
            raise e
#            print(e, "\n\n")
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
            out = decypher(data)
            if args.ofile:
                args.ofile.write(out)
            else:
                print("\n".join(utils.format_multiwords(out)))
        except Exception as e:
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

if __name__ == "__main__":
    main()
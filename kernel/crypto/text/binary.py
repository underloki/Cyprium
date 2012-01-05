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

import sys, itertools
from textwrap import wrap

DICT = {'\x00': '00000000', '\x83': '10000011', '\x04': '00000100',
'\x87': '10000111', '\x08': '00001000', '\x8b': '10001011', '\x0c': '00001100',
'\x8f': '10001111', '\x10': '00010000', '\x93': '10010011', '\x14': '00010100',
'\x97': '10010111', '\x18': '00011000', '\x9b': '10011011', '\x1c': '00011100',
'\x9f': '10011111', ' ': '00100000', '£': '10100011', '$': '00100100',
'§': '10100111', '(': '00101000', '«': '10101011', ',': '00101100',
'¯': '10101111', '0': '00110000', '³': '10110011', '4': '00110100',
'·': '10110111', '8': '00111000', '»': '10111011', '<': '00111100',
'¿': '10111111', '@': '01000000', 'Ã': '11000011', 'D': '01000100',
'Ç': '11000111', 'H': '01001000', 'Ë': '11001011', 'L': '01001100',
'Ï': '11001111', 'P': '01010000', 'Ó': '11010011', 'T': '01010100',
'×': '11010111', 'X': '01011000', 'Û': '11011011', '\\': '01011100',
'ß': '11011111', '`': '01100000', 'ã': '11100011', 'd': '01100100',
'ç': '11100111', 'h': '01101000', 'ë': '11101011', 'l': '01101100',
'ï': '11101111', 'p': '01110000', 'ó': '11110011', 't': '01110100',
'÷': '11110111', 'x': '01111000', 'û': '11111011', '|': '01111100',
'ÿ': '11111111', '\x80': '10000000', '\x03': '00000011', '\x84': '10000100',
'\x07': '00000111', '\x88': '10001000', '\x0b': '00001011', '\x8c': '10001100',
'\x0f': '00001111', '\x90': '10010000', '\x13': '00010011', '\x94': '10010100',
'\x17': '00010111', '\x98': '10011000', '\x1b': '00011011', '\x9c': '10011100',
'\x1f': '00011111', '\xa0': '10100000', '#': '00100011', '¤': '10100100',
"'": '00100111', '¨': '10101000', '+': '00101011', '¬': '10101100',
'/': '00101111', '°': '10110000', '3': '00110011', '´': '10110100',
'7': '00110111', '¸': '10111000', ';': '00111011', '¼': '10111100',
'?': '00111111', 'À': '11000000', 'C': '01000011', 'Ä': '11000100',
'G': '01000111', 'È': '11001000', 'K': '01001011', 'Ì': '11001100',
'O': '01001111', 'Ð': '11010000', 'S': '01010011', 'Ô': '11010100',
'W': '01010111', 'Ø': '11011000', '[': '01011011', 'Ü': '11011100',
'_': '01011111', 'à': '11100000', 'c': '01100011', 'ä': '11100100',
'g': '01100111', 'è': '11101000', 'k': '01101011', 'ì': '11101100',
'o': '01101111', 'ð': '11110000', 's': '01110011', 'ô': '11110100',
'w': '01110111', 'ø': '11111000', '{': '01111011', 'ü': '11111100',
'\x7f': '01111111', '\x81': '10000001', '\x02': '00000010', '\x85': '10000101',
'\x06': '00000110', '\x89': '10001001', '\n': '00001010', '\x8d': '10001101',
'\x0e': '00001110', '\x91': '10010001', '\x12': '00010010', '\x95': '10010101',
'\x16': '00010110', '\x99': '10011001', '\x1a': '00011010', '\x9d': '10011101',
'\x1e': '00011110', '¡': '10100001', '"': '00100010', '¥': '10100101',
'&': '00100110', '©': '10101001', '*': '00101010', '\xad': '10101101',
'.': '00101110', '±': '10110001', '2': '00110010', 'µ': '10110101',
'6': '00110110', '¹': '10111001', ':': '00111010', '½': '10111101',
'>': '00111110', 'Á': '11000001', 'B': '01000010', 'Å': '11000101',
'F': '01000110', 'É': '11001001', 'J': '01001010', 'Í': '11001101',
'N': '01001110', 'Ñ': '11010001', 'R': '01010010', 'Õ': '11010101',
'V': '01010110', 'Ù': '11011001', 'Z': '01011010', 'Ý': '11011101',
'^': '01011110', 'á': '11100001', 'b': '01100010', 'å': '11100101',
'f': '01100110', 'é': '11101001', 'j': '01101010', 'í': '11101101',
'n': '01101110', 'ñ': '11110001', 'r': '01110010', 'õ': '11110101',
'v': '01110110', 'ù': '11111001', 'z': '01111010', 'ý': '11111101',
'~': '01111110', '\x01': '00000001', '\x82': '10000010', '\x05': '00000101',
'\x86': '10000110', '\t': '00001001', '\x8a': '10001010', '\r': '00001101',
'\x8e': '10001110', '\x11': '00010001', '\x92': '10010010', '\x15': '00010101',
'\x96': '10010110', '\x19': '00011001', '\x9a': '10011010', '\x1d': '00011101',
'\x9e': '10011110', '!': '00100001', '¢': '10100010', '%': '00100101',
'¦': '10100110', ')': '00101001', 'ª': '10101010', '-': '00101101',
'®': '10101110', '1': '00110001', '²': '10110010', '5': '00110101',
'¶': '10110110', '9': '00111001', 'º': '10111010', '=': '00111101',
'¾': '10111110', 'A': '01000001', 'Â': '11000010', 'E': '01000101',
'Æ': '11000110', 'I': '01001001', 'Ê': '11001010', 'M': '01001101',
'Î': '11001110', 'Q': '01010001', 'Ò': '11010010', 'U': '01010101',
'Ö': '11010110','Y': '01011001', 'Ú': '11011010', ']': '01011101',
'Þ': '11011110','a': '01100001', 'â': '11100010', 'e': '01100101',
'æ': '11100110','i': '01101001', 'ê': '11101010', 'm': '01101101',
'î': '11101110','q': '01110001', 'ò': '11110010', 'u': '01110101',
'ö': '11110110','y': '01111001', 'ú': '11111010', '}': '01111101',
'þ': '11111110'}




def group(n, iterable, fillvalue=None):
    """Return an iterator of n-length chunks of iterable."""
    args = [iter(iterable)] * n
    return itertools.zip_longest(fillvalue=fillvalue, *args)


def do_encode(text):
    """Function to convert some text to “binary” text."""
    return ''.join([DICT[i] for i in text])

def encode(text):
    """Just a wrapper around do_encode, no check currently."""
    return do_encode(text)


def do_decode(binary):
    """Function to convert “binary” text into text."""
    return ''.join([chr(int(''.join(p), 2)) for p in group(8, binary, '')])

def decode(binary):
    """Just a wrapper around do_decode, with some checks."""
    for i in binary:
        if i != '0' and i != '1':
            raise ValueError('Put 0 or 1')
        elif len(binary) % 8 != 0:
            raise ValueError('No 8 bits, add \'0\' for a length of 8 bits')
    return do_decode(binary)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description="" \
                                     "Encode/decode some text in binary form.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('encode', help="Encode data in binary.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to " \
                                  "binary.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the “binary” text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to encode in binary.")

    unhide_parser = sparsers.add_parser('decode',
                                        help="Decode binary to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert " \
                                    "from binary.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the decoded text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The binary text to decode.")

    args = parser.parse_args()


    if args.command == "encode":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = encode(data)
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
        return 0

    elif args.command == "decode":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decode(data)
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
        return 0


if __name__ == "__main__":
    main()

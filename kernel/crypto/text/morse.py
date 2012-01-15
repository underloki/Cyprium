#! /usr/bin/python3
#
########################################################################
#                                                                      #
# Cyprium is a multifunction cryptographic, steganographic and         #
# cryptanalysis tool developped by members of The Hackademy.           #
# French White Hat Hackers Community!                                  #
# www.thehackademy.fr                                                  #
# Copyright © 2012                                                     #
# Authors: SAKAROV, Madhatter, mont29, Luxerails, PauseKawa, fred,     #
# afranck64, Tyrtamos.                                                 #
# Contact: cyprium@thehackademy.fr, sakarov@thehackademy.fr,           #
# madhatter@thehackademy.fr, mont29@thehackademy.fr,                   #
# irc.thehackademy.fr #cyprium, irc.thehackademy.fr #hackademy         #
#                                                                      #
# Cyprium is free software: you can redistribute it and/or modify      #
# it under the terms of the GNU General Public License as published    #
# by the Free Software Foundation, either version 3 of the License,    #
# or any later version.                                                #
#                                                                      #
# This program is distributed in the hope that it will be useful,      #
# but without any warranty; without even the implied warranty of       #
# merchantability or fitness for a particular purpose. See the         #
# GNU General Public License for more details.                         #
#                                                                      #
# The terms of the GNU General Public License is detailed in the       #
# COPYING attached file. If not, see : http://www.gnu.org/licenses     #
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

__version__ = "0.0.1"
__date__ = "2012/02/13"
__python__ = "3.x" # Required Python version
__about__ = "" \
"===== About Morse =====\n\n" \
"Morse is a tool which can text in morse and morse to string.\n" \
"The valides structures of morse code, for imput and output, are:\n" \
"International : ===...=.=.=.=...=.=...=.=.=.......\n" \
"=.=...=.=.=.......=.===.......=.=.=...===.===.===...=.=.=\n" \
"Fast international : - .... .. ...  / .. ...  / .-  / ... --- ...\n" \
"Fast slashed international : -/..../../...//../...//.-//.../---/...\n" \
"The path of the input file can be absolute (e.g. for linux, if the input\n" \
"file is on your desktop: '/home/admin_name/Desktop/your_input_file'), or\n" \
"relative to the dir from where you started Morse.\n\n" \
"Obviously, the same goes for the output file.\n\n" \
"Cyprium.Morse version {} ({}).\n" \
"Licence GPL3\n" \
"software distributed on the site: http://thehackademy.fr\n\n" \
"Current execution context:\n" \
" Operating System: {}\n" \
" Python version: {}" \
"".format(__version__, __date__, utils.__pf__, utils.__pytver__)


stomorse = {'A': '=.===',               'a': '=.===',
            'B': '===.=.=.=',           'b': '===.=.=.=',
            'C': '===.=.===.=',         'c': '===.=.===.=',
            'D': '===.=.=',             'd': '===.=.=',
            'E': '=',                   'e': '=',
            'F': '=.=.===.=',           'f': '=.=.===.=',
            'G': '===.===.=',           'g': '===.===.=',
            'H': '=.=.=.=',             'h': '=.=.=.=',
            'I': '=.=',                 'i': '=.=',
            'J': '=.===.===.===',       'j': '=.===.===.===',
            'K': '===.=.===',           'k': '===.=.===',
            'L': '=.===.=.=',           'l': '=.===.=.=',
            'M': '===.===',             'm': '===.===',
            'N': '===.=',               'n': '===.=',
            'O': '===.===.===',         'o': '===.===.===',
            'P': '=.===.===.=',         'p': '=.===.===.=',
            'Q': '===.===.=.===',       'q': '===.===.=.===',
            'R': '=.===.=',             'r': '=.===.=',
            'S': '=.=.=',               's': '=.=.=',
            'T': '===',                 't': '===',
            'U': '=.=.===',             'u': '=.=.===',
            'V': '=.=.=.===',           'v': '=.=.=.===',
            'W': '=.===.===',           'w': '=.===.===',
            'X': '===.=.=.===',         'x': '===.=.=.===',
            'Y': '===.=.===.===',       'y': '===.=.===.===',
            'Z': '===.===.=.=',         'z': '===.===.=.=',
            'Ä': '=.===.=.===',         'ä': '=.===.=.===',
            'Æ': '=.===.=.===',         'æ': '=.===.=.===',
            'À': '=.===.===.=.===',     'å': '=.===.===.=.===',
            'Å': '=.===.===.=.===',     'à': '=.===.===.=.===',
            'Ĉ': '===.=.===.=.=',       'ĉ': '===.=.===.=.=',
            'Ç': '===.=.===.=.=',       'ç': '===.=.===.=.=',
            'Ð': '=.=.===.===.=',       'ð': '=.=.===.===.=',
            'È': '=.===.=.=.===',       'è': '=.===.=.=.===',
            'É': '=.=.===.=.=',         'é': '=.=.===.=.=',
            'Ĝ': '===.===.=.===.=',     'ĝ': '===.===.=.===.=',
            'Ĥ': '===.=.===.===.=',     'ĥ': '===.=.===.===.=',
            'Ĵ': '=.===.===.===.=',     'ĵ': '=.===.===.===.=',
            'Ñ': '===.===.=.===.===',   'ñ': '===.===.=.===.===',
            'Ö': '===.===.===.=',       'ö': '===.===.===.=',
            'Ŝ': '=.=.=.===.=',         'ŝ': '=.=.=.===.=',
            'Þ': '=.===.===.=.=',       'þ': '=.===.===.=.=',
            'Ü': '=.=.===.===',         'ü': '=.=.===.===',
            'Ŭ': '=.=.===.===',         'ŭ': '=.=.===.===',
            'Ø': '=.=.===.===',         'ø': '=.=.===.===',
            '1': '=.===.===.===',       '2': '=.=.===.===.===',
            '3': '=.=.=.===.===',       '4': '=.=.=.=.===',
            '5': '=.=.=.=.=',           '6': '===.=.=.=.=', 
            '7': '===.===.=.=.=',       '8': '===.===.===.=.=',
            '9': '===.===.===.===.=',   '0': '===.===.===.===.===',
            ',': '===.===.=.=.===.===', '_': '=.=.===.====.===',
            '=': '=.===.=.===.=.===',   '!': '===.=.===.=.===.===',
            '&': '=.===.=.=.=',         '=': '===.=.=.=.===',
            '+': '=.===.=.===.=',       '"': '=.===.=.=.===.=',
            '@': '=.===.====.===.=',    '$': '=.=.=.===.=.=.===',
            '=': '=.===.=.===.=.===',   '?': '=.=.===.===.=.=',
            ';': '===.=.===.=.===.=',   ':': '===.===.===.=.=.=',
            "'": '=.===.===.===.===.=', '-': '===.=.=.=.=.===',
            '/': '===.=.=.===.=',       '(': '===.=.===.===.=.',
            ')': '===.=.===.===.=.===', '\n': '\n',
            '.': '.===.===.===',        '’': '=.===.===.===.===.=',
            'ê': '=',                   '«': '=.===.=.=.===.=',
            '»': '=.===.=.=.===.='}
            
fastdic  = {'A': '.-',              'a': '.-',
            'B': '-...',            'b': '-...',
            'C': '-.-.',            'c': '-.-.',
            'D': '-..',             'd': '-..',
            'E': '.',               'e': '.',
            'F': '..-.',            'f': '..-.',
            'G': '--.',             'g': '--.',
            'H': '....',            'h': '....',
            'I': '..',              'i': '..',
            'J': '.---',            'j': '.---',
            'K': '-.-',             'k': '-.-',
            'L': '.-..',            'l': '.-..',
            'M': '--',              'm': '--',
            'N': '-.',              'n': '-.',
            'O': '---',             'o': '---',
            'P': '.--.',            'p': '.--.',
            'Q': '--.-',            'q': '--.-',
            'R': '.-.',             'r': '.-.',
            'S': '...',             's': '...',
            'T': '-',               't': '-',
            'U': '..-',             'u': '..-',
            'V': '...-',            'v': '...-',
            'W': '.--',             'w': '.--',
            'X': '-..-',            'x': '-..-',
            'Y': '-.--',            'y': '-.--',
            'Z': '--..',            'z': '--..',
            'Ä': '.-.-',            'ä': '.-.-',
            'Æ': '.-.-',            'æ': '.-.-',
            'À': '.--.-',           'å': '.--.-',
            'Å': '.--.-',           'à': '.--.-',
            'Ĉ': '-.-..',           'ĉ': '-.-..',
            'Ç': '-.-..',           'ç': '-.-..',
            'Ð': '..--.',           'ð': '..--.',
            'È': '.-..-',           'è': '.-..-',
            'É': '..-..',           'é': '..-..',
            'Ĝ': '--.-.',           'ĝ': '--.-.',
            'Ĥ': '-.--.',           'ĥ': '-.--.',
            'Ĵ': '.---.',           'ĵ': '.---.',
            'Ñ': '--.--',           'ñ': '--.--',
            'Ö': '---.',            'ö': '---.',
            'Ŝ': '...-.',           'ŝ': '...-.',
            'Þ': '.--..',           'þ': '.--..',
            'Ü': '..--',            'ü': '..--',
            'Ŭ': '..--',            'ŭ': '..--',
            'Ø': '..--',            'ø': '..--',
            '1': '.----',           '2': '..---',
            '3': '...--',           '4': '....-',
            '5': '.....',           '6': '-....',
            '7': '--...',           '8': '---..',
            '9': '----.',           '0': '-----',
            ' ': '....',            '\n': '\n',
            ',': '--..--',          '_': '..--.-',
            '.': '.-.-.-',          '!': '-.-.--',
            '&': '.-...',           '=': '-...-',
            '+': '.-.-.',           '"': '.-..-.',
            '@': '.--.-.',          '$': '...-..-',
            '.': '.-.-.-',          '?': '..--..',
            ';': '-.-.-.',          ':': '---...',
            "'": '.----.',          '-': '-....-',
            '/': '-..-.',           '(': '-.--.',
            ')': '-.--.-',          '   ': '....',
            '’': '.----.',          'ê': '.',
            '«': '.-..-.',          '»': '.-..-.'}

faststringdic = {'-..': 'D',    '....': 'H',    '..-': 'U',
                 '....-': '4',  '-....': '6',   '.....': '5',
                 '---..': '8',  '-..-': 'X',    '--.-': 'Q',
                 '.-.': 'R',    '.--..': 'Þ',   '.--.-': 'À',
                 '.': 'E',      '..---': '2',   '.--': 'W',
                 '.-': 'A',     '..': 'I',      '-.-.': 'C',
                 '...--': '3',  '...-.': 'Ŝ',   '-.--': 'Y',
                 '-': 'T',      '-.-..': 'Ç',   '.-.-': 'Æ',
                 '.-..': 'L',   '--.-.': 'Ĝ',   '--..': 'Z',
                 '...': 'S',    '.----': '1',   '.--.': 'P',
                 '.---.': 'Ĵ',  '..--.': 'Ð',   '..--': 'Ŭ',
                 '..-..': 'É',  '---.': 'Ö',    '-----': '0',
                 '-.-': 'K',    '----.': '9',   '.---': 'J',
                 '---': 'O',    '-.--.': 'Ĥ',   '--': 'M',
                 '-.': 'N',     '--.': 'G',     '...-': 'V',
                 '--...': '7',  '.-..-': 'È',   '--.--': 'Ñ',
                 '..-.': 'F',   '-...': 'B',    '': '',
                 '-.-.--': '!', '--..--': ',',  '/': ' ',
                 '-..-.': '/',  '.-.-.': '+',   '\n': '\n',
                 '.--.-.': '@', '..--.-': '_',  ' ': '    ',
                 '-....-': '-', '---...': ':',  ' ':' ',
                 '.----.': "'", '-.--.': '(',   '-.--.-': ')',
                 '...-..-': '$','..--..': '?',  '---.': '!',
                 '.-..-.': '"', '-...-': '=',   '.-.-.-': '.',
                 '-.-.-.': ';', '.-...': '&'}

morsedic = {'.===.===.===': '.',        '=.===.===.===.=': 'Ĵ',
            '=.=.===': 'U',             '=.===.===.=': 'P',
            '===.===.=.=': 'Z',         '\n': '\n',
            '===.=.=.=': 'B',           '===.===': 'M',
            '===.===.===.=.=.=': ':',   '=.=.=.=.===': '4',
            '=.=.=.=': 'Ĥ',             '===.=.===.=.=': 'Ĉ',
            '=.===.===.===.===.=': "'", '=.===.=.=.===': 'È',
            '=.=.=.===.=': 'Ŝ',         '=.===.===.=.=': 'Þ',
            '===.=.=.===.=': '/',       '=.===.=.===.=.===': '=',
            '=.=.===.===.=.=': '?',     '===.===.===.===.===': '0',
            '=.=.===.=.=': 'É',         '=.===.=.===.=': '+',
            '=.=': 'I',                 '===.===.=': 'G',
            '=.=.===.===': 'Ŭ',         '=.===.=.===': 'Ä',
            '===.=.===.===.=.===': ')', '===.=.===.=.===.===': '!',
            '=.===.===.===': '1',       '=.=.===.====.===': '_',
            '=.===': 'A',               '===.=.=': 'D',
            '===.===.=.===.===': 'Ñ',   '=.=.=.===.===': '3',
            '===.=.===.=': 'C',         '=.=.===.===.===': '2',
            '=.===.=.=': 'L',           '===.=.===.===': 'Y',
            '===': 'T',                 '===.=.=.=.=.===': '-',
            '===.===.===.=': 'Ö',       '===.===.=.===': 'Q',
            '===.=.=.=.=': '6',         '=.===.=.=.=': '&',
            '=.=.=.=': 'H',             '=.=.=.===': 'V',
            '===.===.===.=.=': '8',     '=.=.=': 'S',
            '===.=': 'N',               '=.=.===.=': 'F',
            '=.===.=.=.===.=': '"',     '=.===.====.===.=': '@',
            '=.===.=': 'R',             '=.=.===.===.=': 'Ð',
            '===.=.=.===': 'X',         '===.===.=.=.=': '7',
            '=.=.=.=.=': '5',           '=': 'E',
            '===.===.===.===.=': '9',   '=.===.===': 'W',
            '===.===.=.===.=': 'Ĝ',     '===.===.===': 'O',
            '===.=.===': 'K',           '===.=.===.=.===.=': ';',
            '=.===.===.=.===': 'À',     '=.=.=.===.=.=.===': '$',
            '===.===.=.=.===.===': ',', '': '',
            '===.=.===.===.=': '('}

def cypher(expression, fast='false'):
    """Return a morse code from expression.
       Optionnal modes is
       international code
       'fast' international
       fast 'slashed' international.
    """
    if fast == 'slashed':
        currentdic = fastdic
        w_sep = '/'
        c_sep = '/'
        l_sep = -1
    elif fast == 'true':
        currentdic = fastdic
        w_sep = ' / '
        c_sep = ' '
        l_sep = -1
    else:
        currentdic = stomorse
        w_sep = '....'
        c_sep = '...'
        l_sep = -3

    morse = ''
    for c in expression:
        if c == ' ':
            morse += w_sep
        elif c in currentdic:
            morse += currentdic[c] + c_sep
        else:
            # raise ValueError("Text contains unallowed chars: '{}'!".format(c))
            morse += '<Error>'
    return morse[:l_sep]

def _decode_to_text(s, w_sep, c_sep, dic):
    """Internal function.
    Return a text from a morse code."""
    expression = ''
    for words in s.split(w_sep):
        for c in words.split(c_sep):
            if c in dic:
                expression += dic[c]
            # Just for international normalyze
            elif c[1:] in dic:
                    expression += dic[c[1:]]
            else:
                expression += '<Error>'
        expression += ' '
    return expression[:-1]

def _decode_to_string(morse_s, c_sep):
    """Internal function.
    Return a morse code from a string."""
    expression = ''
    for c in morse_s.split(c_sep):
        if c in faststringdic:
            expression += faststringdic[c]
        else:
            expression += '<Error>'
    return expression


def decypher(morse_s):
    """Wrapper for internals _decode_to_text/_decode_to_string methods.
    Check the code morse style and some others checks."""
    # Any text given ?
    if not morse_s:
        raise ValueError("No text given!")
    # Fast international slashed mode
    elif '//' in morse_s:
        return _decode_to_text(morse_s, '//', '/', faststringdic)
    # Fast international mode
    elif ' / ' in morse_s:
        return _decode_to_text(morse_s, ' / ', ' ', faststringdic)
    # Or slashed mode with single word
    elif '/' in morse_s:
        return _decode_to_string(morse_s, '/')
    # Just international
    elif '=' in morse_s:
        return _decode_to_text(morse_s, '.......', '...', morsedic)
    # Single word ?
    elif '-' or '.' in morse_s:
        return _decode_to_string(morse_s, ' ')
    # Not a morse code ?
    else:
        raise ValueError("No morse code found!")


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description="Cypher/decypher some text "
                                                 "in morse form.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('cypher', help="Cypher data in morse.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "morse.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the “morse” text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to cypher in morse.")
    hide_parser.add_argument('-m', '--mode',
                             help="""The type of morse code to use.\n
                             Valids options: fast, slashed or None (International)""")

    unhide_parser = sparsers.add_parser('decypher',
                                        help="Decypher morse to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from morse.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the decypherd "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The morse text to decypher.")

    sparsers.add_parser('about', help="About Morse…")

    args = parser.parse_args()

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.mode)
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
            if args.ifile:
                data = args.ifile.read()
            else:
                data = args.data
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

if __name__ == "__main__":
    main()

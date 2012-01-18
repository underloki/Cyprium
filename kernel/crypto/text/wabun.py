#!/usr/bin/python3
#coding:utf-8
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
import itertools
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
"===== About Wabun =====\n\n" \
"Encrypt a text using the Wabun code(japan morse)\n"\
"the encryption is based on a substitution of chars\n"\
"by their Wabun-representation. Some chars will not be\n"\
"replaced\n"\
"'HELLO WORLD' ==> '. L L .-...  .--- R L D'\n"\
"Allowed chars are strict-ascii uppercase, comma, spaces\n"\
"and fullstop."\
"encoded chars are separated by one space, and words by two.\n"\
"Cyprium.Wabun version {} ({}).\n" \
"Licence GPL3\n" \
"software distributed on the site: http://thehackademy.fr \n\n" \
"Current execution context:\n" \
"    Operating System: {}\n" \
"    Python version: {}" \
"".format(__version__, __date__, utils.__pf__, utils.__pytver__)
FILTER = {
    ',': '.-.-.-',
    '.': '.-.-..',
    'A': '--.--',
    'BA': '-.....',
    'BE': '...',
    'BI': '--..-..',
    'BO': '-....',
    'BU': '--....',
    'CHI': '..-.',
    'DA': '-...',
    'DE': '.-.--..',
    'DI': '..-...',
    'DO': '..-....',
    'DU': '.--...',
    'E': '-.---',
    'FU': '--..',
    'GA': '.--....',
    'GE': '-.--..',
    'GI': '-.-....',
    'GO': '---..',
    'GU': '...-..',
    'HA': '-...',
    'HE': '.',
    'HI': '--..-',
    'HO': '-..',
    'I': '.-',
    'KA': '._..',
    'KE': '-.--',
    'KI': '-.-..',
    'KO': '----',
    'KU': '...-',
    'MA': '-..-',
    'ME': '-..-',
    'MI': '..-.-',
    'MO': '-..-.',
    'MU': '-',
    'NA': '.-.',
    'NE': '--.-',
    'NI': '-.-.',
    'NO': '..--',
    'NU': '....',
    'O': '.-...',
    'PA': '-.....--.',
    'PE': '...--.',
    'PI': '--....--.-',
    'PO': '-....--.',
    'PU': '--....--.',
    'RA': '...',
    'RE': '--',
    'RI': '--.',
    'RO': '.-.-',
    'RU': '-.--.',
    'SA': '-.-.-',
    'SE': '.---.',
    'SHI': '--.-.',
    'SO': '---.',
    'SU': '---.-',
    'TA': '-.',
    'TE': '.-.--',
    'TO': '..-..',
    'TSU': '.--.',
    'U': '..-',
    'WA': '-.-',
    'WE': '.--..',
    'WI': '.-..-',
    'WO': '.---',
    'YA': '.--',
    'YO': '--',
    'YU': '-..--',
    'ZA': '-.-.-..',
    'ZE': '.---...',
    'ZI': '--.-...',
    'ZO': '---...',
    'ZU': '---.-..'
    }

REVERSED_FILTER = {v: k for k, v in FILTER.items()}

###C-P
def encrypt_word(word):
    """Yields all possible encryptions of a word, as tuples
       (codes, factor_crypted).
    """
    ln_w = len(word)
    for grps in utils.all_groups_in_order(word, max_n=3):
        crypted = 0
        y = []
        for el in grps:
            el = "".join(el)
            if el in FILTER:
                y.append(FILTER[el])
                crypted += len(el)
            else:
                y.append(" ".join(el))
        yield (" ".join(y), crypted / ln_w)

def do_encrypt(text, exhaustive=False, min_encrypt=0.8):
    """Encrypt text in wabun code.
       Returns a list of encrypted words, or tuples of encrypted words,
       that either have a higher encrypt level than min_encrypt,
       or are the higest encrypted solutions.
    """
    words = text.split()
    enc_w = []
    if exhaustive:
        for w in words:
            solutions = {s for s in encrypt_word(w)}
            fact = min(max(solutions, key=lambda x: x[1])[1], min_encrypt)
            enc_w.append(tuple((s[0] for s in solutions if s[1] >= fact)))
    else:
        for w in words:
            els = []
            i = 0
            ln_w = len(w)
            while i < ln_w:
                if w[i:i+3] in FILTER:
                    els.append(FILTER[w[i:i+3]])
                    i += 3
                elif w[i:i+2] in FILTER:
                    els.append(FILTER[w[i:i+2]])
                    i += 2
                elif w[i] in FILTER:
                    els.append(FILTER[w[i]])
                    i += 1
                else:
                    els.append(w[i])
                    i += 1
            enc_w.append((" ".join(els),))
    return enc_w
def encrypt(text, exhaustive=False, min_encrypt=0.8):
    """Just a wrapper around do_encrypt, with some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed charsetÂ¦
    c_text = set(text)
    c_allowed = set(string.ascii_uppercase) | set(",.")
    c_allowed.add(' ')
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only strict ASCII "
                         "uppercase chars and space are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_encrypt(text, exhaustive=exhaustive, min_encrypt=min_encrypt)
def decipher_code(code):
    """Yields all possible meanings of a number."""
    ln_w = len(code)
    valid_codes = set(REVERSED_FILTER.keys())
    for grps in utils.all_groups_in_order(code, max_n=3):
        grps = tuple(("".join(grp) for grp in grps))
        if set(grps) <= valid_codes:
            yield tuple((REVERSED_FILTER[e] for e in grps))
def do_decipher(text):
    """Decipher text in wabun code.
       Returns a list of deciphered words, or tuples of deciphered words,
       in case several solutions are possible.
    """
    import string
    valid_c = set(string.ascii_uppercase)
    words = text.split('  ')
    dec_w = []
    for w in words:
        if ' ' in w:
            # Nice, just decode each element (letter).
            dec = []
            for c in w.split():
                if c in valid_c:
                    dec.append(c)
                elif c in REVERSED_FILTER:
                    dec.append(REVERSED_FILTER[c])
                else:
                    raise ValueError("{} is an invalid wabun element!"
                                     "".format(c))
            dec_w.append(("".join(dec),))
        else:
            # Not nice, each element is not well space-separated,
            # try to decipher nonetheless...
            is_code = False
            dec = []
            curr = ''
            for c in w:
                if c in valid_c:
                    if is_code:
                        dec.append(tuple("".join(e) for e in decipher_code(curr)))
                        is_code = False
                        curr = c
                    else:
                        curr += c
                else:  # Assume digit!
                    if is_code:
                        curr += c
                    else:
                        if curr:
                            dec.append((curr,))
                        curr = c
                        is_code = True
            if curr in valid_c:
                dec.append((curr,))
            else:  # Assume digit!
                dec.append(tuple("".join(e) for e in decipher_code(curr)))
            dec_w.append(tuple(("".join(d) for d in itertools.product(*dec))))
    return dec_w

def decipher(text):
    """Just a wrapper around do_decipher, with some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed charsÃ¢â‚¬Â¦
    c_text = set(text)
    c_allowed = {' '}
    c_allowed.update(set(string.ascii_uppercase) | set("-."))
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only ascii uppercase "
                         "minus, fullstop and commas): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decipher(text)

def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decipher some text in "
                                     "wabun code.")
    sparsers = parser.add_subparsers(dest="command")
    hide_parser = sparsers.add_parser('encrypt', help="Encryptcode text in "
                                                      "wabun.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "wabun.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the wabun "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to encrypt in wabun.")
    hide_parser.add_argument('--exhaustive', action="store_true",
                             help="Use a complete search of all possible "
                                  "encryptions. WARNING: with long words, it "
                                  "will take a *very* long time to compute "
                                  "(tens of seconds with 15 chars word, and "
                                  "increasing at a *very* high rate)!")
    hide_parser.add_argument('--min_encrypt', type=float, default=0.8,
                             help="Minimum level of encryption, if possible. "
                                  "Only relevant with --exhaustive!")
    unhide_parser = sparsers.add_parser('decipher',
                                        help="Decipher wabun to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from wabun.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the deciphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The text to decipher.")
    sparsers.add_parser('about', help="About Wabun:")
    args = parser.parse_args()
    if args.command == "encrypt":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = encrypt(data, exhaustive=args.exhaustive,
                          min_encrypt=args.min_encrypt)
            if args.ofile:
                args.ofile.write("\n\n".join(out))
            else:
                print("\n".join(utils.format_multiwords(out, sep="  ")))
        except Exception as e:
            print(e, "\n\n")
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return 0
    elif args.command == "decipher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decipher(data)
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

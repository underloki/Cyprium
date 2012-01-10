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
import itertools

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/01/09"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"===== About Atomic =====\n\n" \
"Atomic allows you to encrypt and decrypt ascii-chars only text in the\n" \
"atomic-code.\n\n" \
"“Hello world” → “2 L L 8  74 8 R L D”\n\n" \
"Note that the text must be uppercase, and that the non-cryptable chars\n" \
"will remain unciphered. Spaces are allowed and coded as double-spaces.\n\n" \
"It can also decipher texts like “2LL8  748RLD”, printing all possible\n" \
"solutions.\n\n" \
"Cyprium.Atomic version {} ({}).\n" \
"Licence GPL3\n" \
"software distributed on the site: http://thehackademy.fr\n\n" \
"Current execution context:\n" \
"    Operating System: {}\n" \
"    Python version: {}" \
"".format(__version__, __date__, utils.__pf__, utils.__pytver__)

FILTER = {'AC': '89',
          'AG': '47',
          'AL': '13',
          'AM': '95',
          'AR': '18',
          'AS': '33',
          'AT': '85',
          'AU': '79',
          'B': '5',
          'BA': '56',
          'BE': '4',
          'BH': '107',
          'BI': '83',
          'BK': '97',
          'BR': '35',
          'C': '6',
          'CA': '20',
          'CD': '48',
          'CE': '58',
          'CF': '98',
          'CL': '17',
          'CM': '96',
          'CN': '112',
          'CO': '27',
          'CR': '24',
          'CS': '55',
          'CU': '29',
          'DB': '105',
          'DS': '110',
          'DY': '66',
          'ER': '68',
          'ES': '99',
          'EU': '63',
          'F': '9',
          'FE': '26',
          'FM': '100',
          'FR': '87',
          'GA': '31',
          'GD': '64',
          'GE': '32',
          'H': '1',
          'HE': '2',
          'HF': '72',
          'HG': '80',
          'HO': '67',
          'HS': '108',
          'I': '53',
          'IN': '49',
          'IR': '77',
          'K': '19',
          'KR': '36',
          'LA': '57',
          'LI': '3',
          'LR': '103',
          'LU': '71',
          'MD': '101',
          'MG': '12',
          'MN': '25',
          'MO': '42',
          'MT': '109',
          'N': '7',
          'NA': '11',
          'NB': '41',
          'ND': '60',
          'NE': '10',
          'NI': '28',
          'NO': '102',
          'NP': '93',
          'O': '8',
          'OS': '76',
          'P': '15',
          'PA': '91',
          'PB': '82',
          'PD': '46',
          'PM': '61',
          'PO': '84',
          'PR': '59',
          'PT': '78',
          'PU': '94',
          'RA': '88',
          'RB': '37',
          'RE': '75',
          'RF': '104',
          'RG': '111',
          'RH': '45',
          'RN': '86',
          'RU': '44',
          'S': '16',
          'SB': '51',
          'SC': '21',
          'SE': '34',
          'SG': '106',
          'SI': '14',
          'SM': '62',
          'SN': '50',
          'SR': '38',
          'TA': '73',
          'TB': '65',
          'TC': '43',
          'TE': '52',
          'TH': '90',
          'TI': '81',
          'TM': '69',
          'U': '92',
          'UUH': '116',
          'UUO': '118',
          'UUP': '115',
          'UUQ': '114',
          'UUS': '117',
          'UUT': '113',
          'V': '23',
          'W': '74',
          'XE': '54',
          'Y': '39',
          'YB': '70',
          'ZN': '30',
          'ZR': '40',
          ' ': ''}

REVERSED_FILTER = {v: k for k, v in FILTER.items()}


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
    """Encrypt text in atomic code.
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
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(string.ascii_uppercase)
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
    """Decipher text in atomic code.
       Returns a list of deciphered words, or tuples of deciphered words,
       in case several solutions are possible.
    """
    import string
    valid_c = set(string.ascii_uppercase)

    words = text.split('  ')
    dec_w = []

    for w in words:
        if not w:
            continue
        if ' ' in w or w.isalpha() or w in REVERSED_FILTER.keys():
            # Nice, just decode each element (letter).
            dec = []
            for c in w.split():
                if c in valid_c:
                    dec.append(c)
                elif c in REVERSED_FILTER:
                    dec.append(REVERSED_FILTER[c])
                else:
                    raise ValueError("{} is an invalid atomic element!"
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
            if c in valid_c:
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
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = {' '}
    c_allowed.update(set(string.ascii_uppercase) | set(string.digits))
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only ascii uppercase "
                         "chars, digits and spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decipher(text)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decipher some text in "
                                     "atomic code.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('encrypt', help="Encryptcode text in "
                                                      "atomic.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "atomic.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the atomic "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to encrypt in atomic.")
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
                                        help="Decipher atomic to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from atomic.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the deciphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The text to decipher.")

    sparsers.add_parser('about', help="About Atomic…")

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

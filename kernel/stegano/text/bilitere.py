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

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/01/10"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"===== About Bilitere =====\n\n" \
"Bilitere is a steganographic (!) tool which can encrypt text in the.\n" \
"bilitere code, which is a binary encoding using A and B as digits.\n\n" \
"Encrypt input can be any string containing ASCII lowercase letters only\n" \
"(no spaces), decipher input must be an integer number of groups of five\n" \
"(A,B) digits.\n\n" \
"Note that [ij] and [uv] have the same bilitere codes.\n\n" \
"Cyprium.Bilitere version {} ({}).\n" \
"Licence GPL3\n" \
"software distributed on the site: http://thehackademy.fr\n\n" \
"Current execution context:\n" \
"    Operating System: {}\n" \
"    Python version: {}" \
"".format(__version__, __date__, utils.__pf__, utils.__pytver__)


def int_to_bilitere(i):
    if 0 < i > 31:
        raise ValueError("bilitere only accepts [0..31] values")
    return "{:0>5b}".format(i).replace('0', 'A').replace('1', 'B')


DICO = {k: int_to_bilitere(v) for v, k in enumerate(string.ascii_lowercase) if k not in 'jv'}
DICO['j'] = DICO['i']
DICO['v'] = DICO['u']
#for k, v in DICO.items():
#    print(k, ": ", v, sep="")

DICO_REV = {v: k for k, v in DICO.items()}
DICO_REV[DICO['i']] = '[ij]'
DICO_REV[DICO['u']] = '[uv]'


def do_encrypt(text):
    """Encrypt message d --> AAABB"""
    return "".join((DICO[c] for c in text))


def encrypt(text):
    """Just a wrapper around do_encrypt, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(string.ascii_lowercase)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only lowercase strict "
                         "ASCII chars are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_encrypt(text)


def do_decipher(text):
    """Decipher message AAABB --> d"""
    ret = []
    for c in utils.grouper(text, 5):
        c = ''.join(c)
        if c in DICO_REV:
            ret.append(DICO_REV[c])
        else:
            raise ValueError("{} is not a valid bilitere code!"
                             "".format(c))
    return "".join(ret)


def decipher(text):
    """Just a wrapper around do_decipher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = {'A', 'B'}
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only A and B "
                         "are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    # Check for length.
    if len(text) % 5:
        raise ValueError("Text must contains an integer number of groups of "
                         "five chars (current length: {})…"
                         "".format(len(text)))
    return do_decipher(text)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decipher some lowercase-"
                                     "no-space text to/from bilitere"
                                     "code.")

    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('encrypt', help="Encryptcode text in "
                                                      "atomic.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "bilitere.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the bilitere "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to encrypt in atomic.")

    unhide_parser = sparsers.add_parser('decipher',
                                        help="Decipher atomic to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from bilitere.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the deciphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The text to decipher.")

    sparsers.add_parser('about', help="About Bilitere…")

    args = parser.parse_args()

    if args.command == "encrypt":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = encrypt(data)
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

    elif args.command == "decipher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decipher(data)
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

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

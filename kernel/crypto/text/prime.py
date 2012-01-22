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
__date__ = "2012/01/16"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Prime =====
Prime allows you to cypher and decrypt textes in the
prime-code.
Allows chars are: upper-case alphabetic letters and spaces

the cypher-methode take an argument "base":
    the base-argument represent the first prime number to use
    in the representation.
    base = 1 ==> A=2, B=3, C=5, ...
    base = 2 ==> A=3, B=5, C=7, ...

with text="HELLO WORLD":
    cypher(txt, 1) = '1  19 11 37 37 47  83 47 61 37 7'
    cypher(txt, 2) = '2  23 13 41 41 53  89 53 67 41 11'

Cyprium.Prime version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)

LIST = ['2',
    '3',
    '5',
    '7',
    '11',
    '13',
    '17',
    '19',
    '23',
    '29',
    '31',
    '37',
    '41',
    '43',
    '47',
    '53',
    '59',
    '61',
    '67',
    '71',
    '73',
    '79',
    '83',
    '89',
    '97',
    '101',
    '103',
    '107',
    '109',
    '113',
    '127',
    '131',
    '137',
    '139',
    '149',
    '151',
    '157',
    '163',
    '167',
    '173',
    '179',
    '181',
    '191',
    '193',
    '197',
    '199',
    '211',
    '223',
    '227',
    '229',
    '233',
    '239',
    '241',
    '251',
    '257',
    '263',
    '269',
    '271',
    '277',
    '281',
    '283',
    '293',
    '307',
    '311',
    '313',
    '317',
    '331',
    '337',
    '347',
    '349',
    '353',
    '359',
    '367',
    '373',
    '379',
    '383',
    '389',
    '397',
    '401',
    '409',
    '419',
    '421',
    '431',
    '433',
    '439',
    '443',
    '449',
    '457',
    '461',
    '463',
    '467',
    '479',
    '487',
    '491',
    '499',
    '503',
    '509',
    '521',
    '523',
    '541',
    '547',
    '557',
    '563',
    '569',
    '571',
    '577',
    '587',
    '593',
    '599',
    '601',
    '607',
    '613',
    '617',
    '619',
    '631',
    '641',
    '643',
    '647',
    '653',
    '659',
    '661',
    '673',
    '677',
    '683',
    '691',
    '701',
    '709',
    '719',
    '727',
    '733',
    '739',
    '743',
    '751',
    '757',
    '761',
    '769',
    '773',
    '787',
    '797',
    '809',
    '811',
    '821',
    '823',
    '827',
    '829',
    '839',
    '853',
    '857',
    '859',
    '863',
    '877',
    '881',
    '883',
    '887',
    '907',
    '911',
    '919',
    '929',
    '937',
    '941',
    '947',
    '953',
    '967',
    '971',
    '977',
    '983',
    '991',
    '997']

BASE_MIN = 1
BASE_MAX = len(LIST) - 26

def do_cypher_char(c, base=1):
    """cypher a char in Prime-code, using the base <base>"""
    id_c = ord(c)
    if id_c>=65 and id_c<=97:
        return LIST[ord(c)-65+base-1]
    elif c=="":
        return ""
    else:
        return " "

def do_cypher_word(word, base=1):
    """cypher a word in Prime-code, using the base <base>"""
    lst = [do_cypher_char(c,base) for c in word]
    return " ".join(lst)

def do_cypher(text, base=1):
    """cypher a text in Prime-code, using the base <base>"""
    lst = [do_cypher_word(wrd,base) for wrd in text.split()]
    lst.insert(0, str(base))
    return lst

def cypher(text, base=1):
    """Just a wrapper around do_cypher"""
    # Check for unallowed chars
    c_text = set(text)
    c_allowed = set(" ABCDEFGHIJKLMNOPARSTUVWXYZ")
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only strict ASCII "
                         "uppercase-chars and spaces): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    if base not in range(BASE_MIN, BASE_MAX):
        raise ValueError("The base must be a digit in range({}, {})"
                            "".format(BASE_MIN, BASE_MAX))
    return "  ".join(do_cypher(text, base))

def do_decypher_char(c, base=1):
    """decypher a Prime-coded char"""
    if c in LIST:
        id_c = LIST.index(c)
        return chr(id_c + 65 -base + 1)
    elif c=="":
        return ""
    else:
        return " "

def do_decypher_word(word, base=1):
    """decypher a Prime-coded word"""
    res = [do_decypher_char(c, base) for c in word.split()]
    return "".join(res)

def do_decypher(text):
    """decypher a Prime-coded text"""
    lst = text.split("  ")
    base = int(lst[0])
    res = [do_decypher_word(wrd, base) for wrd in lst[1:]]
    return res

def decypher(text):
    """Just a wrapper around do_decypher, with some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed = set("0123456789 ")
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only digits "
                         "and spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return " ".join(do_decypher(text))


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decypher some text in "
                                     "prime code.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('cypher', help="Encrypt text in "
                                                     "prime.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "prime.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the prime "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to cypher in prime.")

    unhide_parser = sparsers.add_parser('decypher',
                                        help="Decypher prime to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from prime.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the decyphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The text to decypher.")

    sparsers.add_parser('about', help="About Prime")

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
#! /usr/bin/python3

########################################################################
# #
# Cyprium is a multifunction cryptographic, steganographic and #
# cryptanalysis tool developped by members of The Hackademy. #
# French White Hat Hackers Community! #
# www.thehackademy.fr #
# Copyright © 2012 #
# Authors: SAKAROV, Madhatter, mont29, Luxerails, PauseKawa, fred, #
# afranck64, Tyrtamos. #
# Contact: cyprium@thehackademy.fr, sakarov@thehackademy.fr, #
# madhatter@thehackademy.fr, mont29@thehackademy.fr, #
# irc.thehackademy.fr #cyprium, irc.thehackademy.fr #hackademy #
# #
# Cyprium is free software: you can redistribute it and/or modify #
# it under the terms of the GNU General Public License as published #
# by the Free Software Foundation, either version 3 of the License, #
# or any later version. #
# #
# This program is distributed in the hope that it will be useful, #
# but without any warranty; without even the implied warranty of #
# merchantability or fitness for a particular purpose. See the #
# GNU General Public License for more details. #
# #
# The terms of the GNU General Public License is detailed in the #
# COPYING attached file. If not, see : http://www.gnu.org/licenses #
# #
########################################################################


import sys
import os
import string
import itertools

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/03/5"
__python__ = "3.x" # Required Python version
__about__ = ""\
"""Cyprium.Vigenere version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
Operating System: {}
Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)

# Algorithms
ALGO_VIGENERE = 1
ALGO_AUTOCLAVE = 2
ALGO_GRONSFELD = 3
ALGO_BEAUFORT = 4

# Maps
WHITESMAP = set("0123456789.,;!? ")


def _char_shift(c, k, negativ=False, base=ord('A'), modulo=26):
    '''shift the char c, with the position in alphabet26 of char k,
    negativ : shift in negativ side or not
    base : base of char, 65==> upper, 97==>lower
    modulo : the number of letters'''
    if negativ:
        return chr(((ord(c) - base*2 - ord(k)) % modulo) + base)
    else:
        return chr(((ord(c) - base*2 + ord(k)) % modulo) + base)


def _char_shift_int(c, shift, base=ord('A'), modulo=26):
    '''shift the char c, with <shift> positions,
    base : base of char, 65==> upper, 97==>lower
    modulo : the number of letters'''
    return chr(((ord(c) - base + shift) % modulo) + base)


def _process_vigenere(text, key, decrypt=False):
    '''cypher or decypher text with key using the vigenere-cypher'''
    index = 0
    limit = len(key)
    res = []
    for c in text:
        if c in WHITESMAP:
            yield c
        else:
            yield _char_shift(c, key[index], negativ=decrypt)
            index = (index + 1) % limit


def _process_autoclave(text, key, decrypt=False):
    '''cypher or decypher text with key using the autoclave-cypher'''
    index = 0
    res = []
    limit = len(key)
    if decrypt:
        nKey = list(key)
        last = 0
        for c in text:
            if c in WHITESMAP:
                res.append(c)
            else:
                if index >= limit:
                    while res[last + index - limit] in WHITESMAP:
                        last +=1
                    nKey.append(res[last + index - limit])
                res.append(_char_shift(c, nKey[index], negativ=decrypt))
                index += 1
    else:
        if len(key) < len(text):
            nKey = key + "".join(i for i in text if i not in WHITESMAP)
        for c in text:
            if c in WHITESMAP:
                res.append(c)
            else:
                res.append(_char_shift(c, nKey[index]))
                index += 1
    return res


def _process_gronsfeld(text, key, decrypt=False):
    '''cypher or decypher text with key using the gronsfeld-cypher'''
    index = 0
    nKey = str(key)
    limit = len(nKey)
    res = []
    if (decrypt):
        for c in text:
            if c in WHITESMAP:
                yield c
            else:
                yield _char_shift_int(c, -int(nKey[index]))
                index = (index + 1) % limit
    else:
        for c in text:
            if c in WHITESMAP:
                yield c
            else:
                yield _char_shift_int(c, int(nKey[index]))
                index = (index + 1) % limit


def _process_beaufort(text, key, decrypt=False):
    '''cypher or decypher text with key using the beaufort-cypher'''
    index = 0
    limit = len(key)
    res = []
    for c in text:
        if c in WHITESMAP:
            yield c
        else:
            yield _char_shift(key[index], c, True)
            index = (index + 1) % limit


def do_cypher_vigenere(text, key):
    '''Cypher the message <text> with <key> using the vigenere square'''
    return _process_vigenere(text, key, False)

def do_cypher_autoclave(text, key):
    '''Cypher the message <text> with <key> using the autocalve-cypher'''
    return _process_autoclave(text, key, False)

def do_cypher_gronsfeld(text, key):
    '''Cypher the message <text> with <key> using the vigenere square'''
    return _process_gronsfeld(text, key, False)

def do_cypher_beaufort(text, key):
    '''Cypher the message <text> with <key> using the vigenere square'''
    return _process_beaufort(text, key, False)


def cypher(text, key, algo):
    '''Just a wrapper around do_cypher_xxx, whit some checks.'''
    if not text:
        raise ValueError("No text given!")
    c_text = set(text)
    c_allowed = set(WHITESMAP)
    utils.WE2UASCII_CHARSET
    c_allowed.update(utils.WE2UASCII_CHARSET)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only uppercase "
                        "chars, digits and poctuation): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    c_key = set(key)
    if algo in (ALGO_VIGENERE, ALGO_AUTOCLAVE, ALGO_BEAUFORT):
        c_allowed = set(string.ascii_uppercase)
    else:
        c_allowed = set(string.digits)
    if not (c_key <= c_allowed):
        raise ValueError("Key contains unallowed chars : '{}'!"
                        "".format("', '".join(sorted(c_key - c_allowed))))
    if algo == ALGO_VIGENERE:
        res_gen = do_cypher_vigenere(text, key)
    elif algo == ALGO_GRONSFELD:
        res_gen = do_cypher_gronsfeld(text, key)
    elif algo == ALGO_AUTOCLAVE:
        res_gen = do_cypher_autoclave(text, key)
    elif algo == ALGO_BEAUFORT:
        res_gen = do_cypher_beaufort(text, key)
    else:
        raise ValueError("Unknow algorithm specified ({})."
                        "".format(algo))
    return "".join(res_gen)



def do_decypher_vigenere(text, key):
    '''Decypher the message <text> with <key> using the vigenere square'''
    return _process_vigenere(text, key, True)

def do_decypher_autoclave(text, key):
    '''Decypher the message <text> with <key> using the autocalve-cypher'''
    return _process_autoclave(text, key, True)

def do_decypher_gronsfeld(text, key):
    '''Decypher the message <text> with <key> using the vigenere square'''
    return _process_gronsfeld(text, key, True)

def do_decypher_beaufort(text, key):
    '''Decypher the message <text> with <key> using the vigenere square'''
    return _process_beaufort(text, key, True)


def decypher(text, key, algo, bloc=None):
    '''Just a wrapper around do_decypher_xxx, whit some checks.'''
    if not text:
        raise ValueError("No text given!")
    c_text = set(text)
    c_allowed = set(WHITESMAP)
    c_allowed.update(string.ascii_uppercase)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only uppercase "
                        "chars, digits and poctuation): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    
    c_key = set(key)
    if algo in (ALGO_VIGENERE, ALGO_AUTOCLAVE, ALGO_BEAUFORT):
        c_allowed = set(string.ascii_uppercase)
    else:
        c_allowed = set(string.digits)
    if not (c_key <= c_allowed):
        raise ValueError("Key contains unallowed chars : '{}'!"
                        "".format("', '".join(sorted(c_key - c_allowed))))
    if algo == ALGO_VIGENERE:
        res_gen = do_decypher_vigenere(text, key)
    elif algo == ALGO_GRONSFELD:
        res_gen = do_decypher_gronsfeld(text, key)
    elif algo == ALGO_AUTOCLAVE:
        c_key = set(key)
        c_allowed = set("0123456789")
        res_gen = do_decypher_autoclave(text, key)
    elif algo == ALGO_BEAUFORT:
        res_gen = do_decypher_beaufort(text, key)
    else:
        raise ValueError("Unknow algorithm specified ({})."
                        "".format(algo))
    return "".join(res_gen)

def test():
    keys = ["ANF", "ANF", "1024", "ANF"]
    for i in range(4):
        print ("".join(decypher(cypher("HI HELLO WORLD. THIS IS MY SUPER ALGO"
        " 1024", keys[i], i+1), keys[i], i+1)), " <== algo", i+1)



#test()

def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    # Helper func.
    _algos = {'vigenere': ALGO_VIGENERE, 'v': ALGO_VIGENERE,
              'autoclave': ALGO_AUTOCLAVE, 'a': ALGO_AUTOCLAVE,
              'gronsfeld': ALGO_GRONSFELD, 'g': ALGO_GRONSFELD,
              'beaufort' : ALGO_BEAUFORT, 'b': ALGO_BEAUFORT,
              'all': None, '*': None}

    def _2ialgo(b):
        return _algos.get(b, None)

    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some lowercase-"
                                     "no-space text to/from biliteral"
                                     "code.")
    parser.add_argument('--debug', action="store_true", default=False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher', help="Cypher text in some "
                                                 "vigenere code family.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-k', '--key', type=str,
                         help="The cyphering key, has different meanings "
                              "depending on the algorithm chosen, see about "
                              "help for details.")
    cparser.add_argument('-a', '--algo', type=_2ialgo,
                         choices=_algos.values(), default=_algos['v'],
                         help="Which algorithm to use for cyphering.")

    dparser = sparsers.add_parser('decypher',
                                          help="Decypher biliteral to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to convert "
                                      "from some vigenere.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    dparser.add_argument('-d', '--data',
                                 help="The text to decypher.")
    dparser.add_argument('-k', '--key', type=str, default=None,
                         help="The decyphering key, has different meanings "
                              "depending on the algorithm chosen, see about "
                              "help for details.")
    dparser.add_argument('-a', '--algo', type=_2ialgo,
                         choices=_algos.values(), default=_algos['v'],
                         help="Which algorithm to use for decyphering.")

    sparsers.add_parser('about', help="About Vigenereâ€¦")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.key, args.algo, args.key)
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
        return 0

    elif args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decypher(data, args.key, args.algo)
            if args.key is None:
                out = sorted(out, key=lambda o: o[5], reverse=True)
                if not args.ofile:
                    out = out[:10]
                out = "\n".join(("Match: {:<4.2} Lang: {: <6} ALGO: {} "
                                 "METHOD: {:4} KEY: {: > 6} {}"
                                 "".format(avg, lng, algo, method, key, res)
                                 for algo, method, key, res, lng, avg in out))
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
        return 0

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()
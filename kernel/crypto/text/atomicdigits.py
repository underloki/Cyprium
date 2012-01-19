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
import functools

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
"""===== About AtomicDigits =====
AtomicDigits allows you to cypher and decrypt ascii-chars only text in the
atomic digits-code.

“Hello world” → “2 L L 8  74 8 R L D”

Note that the text must be uppercase, and that the non-cryptable chars will
remain unciphered. Spaces are allowed and coded as double-spaces.

You can also use another cypher algorithm, “exhaustive”, that will, for each
word, check *all* possible chipering, and output (again, for each word) all
solutions giving a cyphering threshold (i.e. nbr of cyphered chars/total nbr
of chars) higher than the given one ([0.0 .. 1.0]).

WARNING: Do not use this with words over about 20 chars length, compute time
         will become prohibitive.

E.g. for “NITROGEN”, with a threshold of 0.5 (at least half of the letters
cyphered):
     7 I T R 8 32 7
     7 I T R O 32 7
    7 53 T R 8 G E 7
    7 53 T R 8 32 7
     28 T R O 32 7
     28 T R 8 32 7
     28 T R 8 G E 7
     N I T R 8 32 7
    7 53 T R O 32 7


It can also decypher texts like “2LL8  748RLD”, printing all possible
solutions.

Cyprium.AtomicDigits version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)

MAP = {'AC': '89',
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

R_MAP = utils.revert_dict(MAP)


def cypher_word(word):
    """Yields all possible cypherings of a word, as tuples
       (codes, factor_crypted).
    """
    ln_w = len(word)
    for grps in utils.all_groups_in_order(word, (1, 2, 3)):
        cyphered = 0
        y = []
        for el in grps:
            el = "".join(el)
            if el in MAP:
                y.append(MAP[el])
                cyphered += len(el)
            else:
                y.append(" ".join(el))
        yield (" ".join(y), cyphered / ln_w)


def do_cypher(text, exhaustive=False, min_cypher=0.8):
    """Encrypt text in atomic digits code.
       Returns either a str with cyphered words (default basic algorithm),
       or, when exhaustive is True, a dict with following values:
           solutions: (a tuple of tuples of cyphered words)
                      [with either a cypher factor higer than min_cypher,
                       or the highest possible cypher factor],
           n_solutions: the total number of solutions,
           best_solutions: (a tuple of tuples of best cyphered words),
           best_n_solutions: the number of best solutions,
           best_cypher: the cypher factor of best solutions.
    """
    words = text.split()
    if exhaustive:
        all_s = []
        best_s = []
        best_c = []
        for w in words:
            solutions = {s for s in cypher_word(w)}
            fact = min(max(solutions, key=lambda x: x[1])[1], min_cypher)
            all_s.append(tuple((s[0] for s in solutions if s[1] >= fact)))
            max_cypher = max(solutions, key=lambda s: s[1])[1]
            best_s.append(tuple((s[0] for s in solutions \
                                          if s[1] >= max_cypher)))
            best_c.append(max_cypher)
        return {"solutions": tuple(all_s),
                "n_solutions": \
                    functools.reduce(lambda n, w: n * len(w), all_s, 1),
                "best_solutions": tuple(best_s),
                "best_n_solutions": \
                    functools.reduce(lambda n, w: n * len(w), best_s, 1),
                "best_cypher": \
                    functools.reduce(lambda n, c: n + c, best_c) / len(best_c)}
    else:
        enc_w = []
        for w in words:
            els = []
            i = 0
            ln_w = len(w)
            while i < ln_w:
                if w[i:i + 3] in MAP:
                    els.append(MAP[w[i:i + 3]])
                    i += 3
                elif w[i:i + 2] in MAP:
                    els.append(MAP[w[i:i + 2]])
                    i += 2
                elif w[i] in MAP:
                    els.append(MAP[w[i]])
                    i += 1
                else:
                    els.append(w[i])
                    i += 1
            enc_w.append(" ".join(els))
        return "  ".join(enc_w)


def cypher(text, exhaustive=False, min_cypher=0.8):
    """Just a wrapper around do_cypher, with some checks."""
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
    return do_cypher(text, exhaustive=exhaustive, min_cypher=min_cypher)


def decypher_code(code):
    """Yields all possible meanings of a number."""
    ln_w = len(code)
    valid_codes = set(R_MAP.keys())
    for grps in utils.all_groups_in_order(code, (1, 2, 3)):
        grps = tuple(("".join(grp) for grp in grps))
        if set(grps) <= valid_codes:
            yield tuple((R_MAP[e] for e in grps))


def do_decypher(text):
    """Decypher text in atomic digits code.
       Returns a list of decyphered words, or tuples of decyphered words,
       in case several solutions are possible.
    """
    import string
    valid_c = set(string.ascii_uppercase)

    dec_w = []

    # For each word...
    for w in text.split('  '):
        do_exhaustive = True
        if not w:
            continue
        if ' ' in w or w.isalpha() or w in R_MAP.keys():
            # Nice, just decode each element (letter).
            do_exhaustive = False
            dec = []
            for c in w.split():
                if c in valid_c:
                    dec.append(c)
                elif c in R_MAP:
                    dec.append(R_MAP[c])
                else:
                    # No more nice, switch to "exhaustive" decode.
                    do_exhaustive = True
            if not do_exhaustive:
                dec_w.append(("".join(dec),))
        if do_exhaustive:
            # Not nice, each element is not well space-separated, or there are
            # some invalid atomic codes inside it
            # try to decypher nonetheless...
            is_code = False
            dec = []
            curr = ''
            for c in w:
                if c in valid_c:
                    if is_code:
                        dec.append(tuple("".join(e) for e in
                                                        decypher_code(curr)))
                        is_code = False
                        curr = c
                    else:
                        curr += c
                elif c == ' ' and curr:  # A separator.
                    if is_code:
                        dec.append(tuple("".join(e) for e in
                                                        decypher_code(curr)))
                        is_code = False
                    else:
                        dec.append((curr,))
                    curr = ''
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
                dec.append(tuple("".join(e) for e in decypher_code(curr)))
            dec_w.append(tuple(("".join(d) for d in itertools.product(*dec))))

    return dec_w


def decypher(text):
    """Just a wrapper around do_decypher, with some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars...
    c_text = set(text)
    c_allowed = {' '}
    c_allowed.update(set(string.ascii_uppercase) | set(string.digits))
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only ascii uppercase "
                         "chars, digits and spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))
    return do_decypher(text)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Encrypt/decypher some text in "
                                     "atomic digits code.")
    sparsers = parser.add_subparsers(dest="command")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    hide_parser = sparsers.add_parser('cypher', help="Encryptcode text in "
                                                     "atomic digits.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text to convert to "
                                  "atomic digits.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the atomic digits "
                                  "text.")
    hide_parser.add_argument('-d', '--data',
                             help="The text to cypher in atomic digits.")
    hide_parser.add_argument('--exhaustive', action="store_true",
                             help="Use a complete search of all possible "
                                  "cypherings. WARNING: with long words, it "
                                  "will take a *very* long time to compute "
                                  "(seconds with 20 chars word, and "
                                  "increasing at a high rate)!")
    hide_parser.add_argument('--min_cypher', type=float, default=0.8,
                             help="Minimum level of cyphering, if possible. "
                                  "Only relevant with --exhaustive, defaults "
                                  "to 0.8!")

    unhide_parser = sparsers.add_parser('decypher',
                                        help="Decypher atomic digits to text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to convert "
                                    "from atomic digits.")
    unhide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the decyphered "
                                    "text.")
    unhide_parser.add_argument('-d', '--data',
                               help="The text to decypher.")

    sparsers.add_parser('about', help="About AtomicDigits…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, exhaustive=args.exhaustive,
                          min_cypher=args.min_cypher)
            if args.exhaustive:
                print("Exaustive found {} solutions for a minimum "
                      "cyphering of {}, among which {} solutions with the "
                      "highest possible cyphering ({}):"
                      "".format(out["n_solutions"], args.min_cypher,
                                out["best_n_solutions"],
                                out["best_cypher"]))
                text = "\n".join(utils.format_multiwords(out["solutions"],
                                                         sep="  "))
                b_text = \
                    "\n".join(utils.format_multiwords(out["best_solutions"],
                                                      sep="  "))
            else:
                text = out
                b_text = ""
            if args.ofile:
                args.ofile.write(text)
                if b_text:
                    args.ofile.write("\n\n")
                    args.ofile.write(b_text)
            else:
                if args.exhaustive:
                    print("Best solutions:")
                    print(b_text)
                    print("\nAll solutions:")
                print(text)
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
            out = decypher(data)
            text = "\n".join(utils.format_multiwords(out))
            if args.ofile:
                args.ofile.write(text)
            else:
                print(text)
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

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
import itertools

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils
import kernel.hunspell as hunspell
import kernel.matchdic as matchdic

__version__ = "0.5.0"
__date__ = "2012/02/26"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Caesar =====
Caesar is a cryptographic tool which can cypher text in three different
versions of Caesar’s code: Basic, Progressive and Caesar’s square.

All accept only strict ASCII upper chars, and sometime spaces (this will be
detailed for each algo).



The Basic algorithm simply applies a constant offset to each char, cycling
from Z to A: “Bonjours” with offset (key) 4 gives “FSRNSYVW”.

This algo just output spaces unchanged, but note that having spaces make it
even weaker than it already is…



The Progressive algorithm applies a varying offset to each char, also cycling
from Z to A. It has two different methods, and behaves differently when
cyphering a single word or a whole text (with spaces between words).

The offset can follow to different increasing schemes:
* Geometrical progression: with a given key, offset will be key, key*2,
  key*3, etc.
* Shift: This a geometrical progression of 1, but initially offset by key
  (i.e. key, key+1, key+2, etc.).

With no-spaces texts, the offset is increased for each char, while it is only
increased for each new word in texts containing spaces.
*This means spacing is crucial with this algo, loosing or changing it will make
the text undecypherable!*

E.g.:
* “GUTEN TAG” in geometrical mode, with key 12: “SGFQZ RYE”
* “GUTENTAG”  in geometrical mode, with key 12: “SSDAVNGY”
* “HOLA MUNDO” in shift method, with key 7: “OVSH UCVLW”
* “HOLAMUNDO”  in shift method, with key 7: “OWUKXGARD”

Note that with geometrical method, using key 13 is not a good idea, as one char
or word over two will remain uncyphered (13*2 = 26…)!



The Caesar’s square is more like matrix operation called “transposition”. The
idea is to cut the input text in pieces of same length (as much as possible,
the last one will likely be shorter…), to place them over the other, and then
to read the columns of that table.

E.g. “CAIVSIVLIVSCAESAR” with a width of 4 gives
    CAIV
    SIVL
    IVSC
    AESA
    R
… hence “CSIARAIVEIVSSVLCA”

That tool implements the three variants of this algo, Square itself (i.e. using
a table of n*n dimension, as small as possible for the given text)
[when key=0], constant width, and constant high (which is also known as the
Cytale cyphering).



This tool can also hack some cyphered text, and output most probable decyphered
result, using per-language lists of words.
{}


Cyprium.Caesar version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(hunspell.__about__,
           __version__, __date__, utils.__pf__, utils.__pytver__)


# Algorithms
ALGO_BASIC = 1  # Basic, classical constant-shift caesar code.
ALGO_PROGRESS = 2  # Variable-shift caesar code.
ALGO_SQUARE = 3  # Caesar's square code.

# Variants of Basic algo (for sake of consistency...).
BASIC_BASIC = 11

# Variants of Progressive algo.
PROGRESS_GEOMETRIC = 21  # Also "basic", which is a geometric suite based on 1.
PROGRESS_SHIFT = 22

# Variants of Square algo.
SQUARE_SQUARE = 31
SQUARE_CONSTWIDTH = 32
SQUARE_CONSTHIGH = 33


VALID_CHARSET = set(string.ascii_uppercase) | {' '}

# Used to adapt dics, for hacking.
DIC_CHARSET = utils.WE2UASCII_CHARSET
DIC_CHARMAP = utils.WE2UASCII_CHARMAP


# Printing helpers.
TXT_ALGOS_MAP = {ALGO_BASIC: "Basic",
                 ALGO_PROGRESS: "Progressive",
                 ALGO_SQUARE: "Square"}
TXT_ALGOS_MAP_MAXLEN = max(len(n) for n in TXT_ALGOS_MAP.values())
TXT_METHODS_MAP = {BASIC_BASIC: "Basic",
                   PROGRESS_GEOMETRIC: "Geometric",
                   PROGRESS_SHIFT: "Shifted",
                   SQUARE_SQUARE: "Squarish",
                   SQUARE_CONSTWIDTH: "Constant width",
                   SQUARE_CONSTHIGH: "Constant high"}
TXT_METHODS_MAP_MAXLEN = max(len(n) for n in TXT_METHODS_MAP.values())
TXT_HACKSOLUTIONS_PATTERN = "Match: {:<4.2}  Lang: {: <6}  ALGO: " \
                            "{: <{alg_len}}  METHOD: {: <{met_len}}  " \
                            "KEY: {: > 6}"


def square_max_key(text):
    """Compute max key for a given text, in square algo."""
    return int(len(text.replace(' ', '')) ** 0.5)


def _process_progressive(text, key, method, _reverse=False):
    """
    (De)cypher message to progressive caesar (increasing offset).
    """
    base = ord('A')
    modulo = ord('Z') - base + 1

    if method == PROGRESS_GEOMETRIC:
        # Basic is a specific case of geometric, with key = 1!
        delta = key
    elif method == PROGRESS_SHIFT:
        delta = key
        key = 1

    if _reverse:
        s = -1
    else:
        s = 1

    if ' ' in text:
        ret = []
        for w in text.split():
            ret.append("".join(utils.char_shift(c, base, modulo, delta * s)
                               for c in w))
            delta = (delta + key) % modulo
        return " ".join(ret)
    else:  # Mono-word...
        ret = []
        for c in text:
            ret.append(utils.char_shift(c, base, modulo, delta * s))
            delta = (delta + key) % modulo
        return "".join(ret)


def _process_square(text, key, _reverse=False):
    """
    (De)cypher message using caesar's square.
    key = 0 -> square.
    key > 0 -> fixed-width rectangle.
    key < 0 -> fixed-height rectangle.
    """
    base = ord('A')
    modulo = ord('Z') - base + 1

    square = []
    text = text.replace(' ', '')
    ln_txt = len(text)

    if key == 0:
        # Squarish square...
        t = ln_txt ** 0.5
        key = int(t)
        # e.g. length 577 will be 25*24, not 25*25...
        # More generally, x² - (x-1)² = 2x - 1
        # Hence we can have either x*x, or x*(x-1) grids...
        if (key < t and (not _reverse or ((key + 1) * key) < ln_txt)):
            key += 1
    elif key < 0:
        # Variable width, let's just recalculate the width we'll need
        # for this text, given the constant height!
        key = (len(text) - key - 1) // -key

    if _reverse and len(text) % key:
        # We need a "square" where empty places are on the rightest column,
        # not the lowest row!
        dlt = key - (len(text) % key)
        high = (len(text) + key - 1) // key
        f_ln = key * (high - dlt)
        square = tuple(utils.grouper(text[:f_ln], key, '')) + \
                 tuple(g + ('',)
                       for g in utils.grouper(text[f_ln:], key - 1, ''))
    else:
        square = tuple(utils.grouper(text, key, ''))
    return "".join("".join(p) for p in zip(*square))


def do_cypher_basic(text, key):
    """
    Cypher message to basic caesar (constant offset).
    """
    # Let’s use a dict here (as it’s a constant one to one mapping).
    base = ord('A')
    modulo = ord('Z') - base + 1
    _map = {c: utils.char_shift(c, base, modulo, key) for c in set(text)}
    _map[' '] = ' '
    return "".join(_map[c] for c in text)


def do_cypher_progressive(text, key, method):
    """
    Cypher message to progressive caesar (increasing offset).
    """
    return _process_progressive(text, key, method, False)


def do_cypher_square(text, key, method):
    """
    Cypher message to caesar's square.
    key = 0 -> square.
    key > 0 -> fixed-width rectangle.
    key < 0 -> fixed-high rectangle.
    """
    if method == SQUARE_SQUARE:
        key = 0
    elif method == SQUARE_CONSTHIGH:
        key = -key
    return _process_square(text, key, False)


def cypher(text, algo, key, method=PROGRESS_GEOMETRIC):
    """Just a wrapper around do_cypher_xxx, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(string.ascii_uppercase) | {' '}
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only uppercase "
                         "strict ASCII chars and spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))

    if algo == ALGO_BASIC:
        if 1 > key > 25:
            raise ValueError("Invalid key value, {} is out of [1, 25] range."
                             "".format(key))
        return do_cypher_basic(text, key)
    elif algo == ALGO_PROGRESS:
        if 1 > key > 25:
            raise ValueError("Invalid key value, {} is out of [1, 25] range."
                             "".format(key))
        if method not in {PROGRESS_GEOMETRIC, PROGRESS_SHIFT}:
            raise ValueError("Invalid mode for progressive algorithm ({})."
                             "".format(method))
        return do_cypher_progressive(text, key, method)
    elif algo == ALGO_SQUARE:
        if key and 2 > abs(key) > square_max_key(text):
            raise ValueError("Invalid key value (size), {} is out of "
                             "[-1000, 1000] range.".format(key))
        return do_cypher_square(text, key, method)
    else:
        raise ValueError("Unknown algorithm specified ({})."
                         "".format(algo))


def do_decypher_basic(text, key):
    """
    Decypher message to basic caesar (constant offset).
    """
    # It's just a matter of applying reversed cypher operation...
    return do_cypher_basic(text, -key)


def do_decypher_progressive(text, key, mode):
    """
    Decypher message to progressive caesar (increasing offset).
    """
    # It's just a matter of applying reversed cypher operation...
    return _process_progressive(text, key, mode, True)


def do_decypher_square(text, key, method):
    """
    Decypher message to caesar’s square.
    key = 0 -> square.
    key > 0 -> fixed-width rectangle.
    key < 0 -> fixed-height rectangle.
    """
    # It's just a matter of applying reversed cypher operation...
    if method == SQUARE_SQUARE:
        key = 0
    elif method == SQUARE_CONSTWIDTH:
        key = -key
    return _process_square(text, key, True)


def do_hack(text, algos=None, methods=None, keys=None):
    """
    Brute-force hacking of caesar-cyphered text...
    """
    h = hunspell.Hunspell()
    h.load_dic_zip(hunspell.ZIP_DICS)
    m = matchdic.MatchDic(h)
    m.init(charset=DIC_CHARSET, charmap=DIC_CHARMAP, minlen=3)

    def _gen(text, algos, methods, keys):
        if algos:
            algos = set(algos)
        else:
            algos = {ALGO_BASIC, ALGO_PROGRESS, ALGO_SQUARE}
        if keys:
            ks = (k for k in keys if 0 < k < 26)
        else:
            ks = range(1, 26)
        meths = {PROGRESS_GEOMETRIC, PROGRESS_SHIFT}
        if methods:
            meths = set(methods) & meths
        for k in ks:
            if ALGO_BASIC in algos:
                yield (ALGO_BASIC, BASIC_BASIC, k, do_decypher_basic(text, k))
            if ALGO_PROGRESS in algos:
                if PROGRESS_GEOMETRIC in meths:
                    yield (ALGO_PROGRESS, PROGRESS_GEOMETRIC, k,
                           do_decypher_progressive(text, k,
                                                   PROGRESS_GEOMETRIC))
                if PROGRESS_SHIFT in meths and k != 1:
                    yield (ALGO_PROGRESS, PROGRESS_SHIFT, k,
                           do_decypher_progressive(text, k, PROGRESS_SHIFT))
        if ALGO_SQUARE in algos:
            maxkey = square_max_key(text)
            if keys:
                ks = (k for k in keys if 2 < k <= maxkey)
            else:
                ks = range(2, maxkey + 1)
            meths = {SQUARE_SQUARE, SQUARE_CONSTWIDTH, SQUARE_CONSTHIGH}
            if methods:
                meths = set(methods) & meths
            # Squarish square!
            if SQUARE_SQUARE in meths:
                yield (ALGO_SQUARE, SQUARE_SQUARE, 0,
                       do_decypher_square(text, None, SQUARE_SQUARE))
            for k in ks:
                if SQUARE_CONSTWIDTH in meths:
                    yield (ALGO_SQUARE, SQUARE_CONSTWIDTH, k,
                           do_decypher_square(text, k, SQUARE_CONSTWIDTH))
                if SQUARE_CONSTHIGH in meths:
                    yield (ALGO_SQUARE, SQUARE_CONSTHIGH, k,
                           do_decypher_square(text, k, SQUARE_CONSTHIGH))
    generator = _gen(text, algos, methods, keys)

    # Make three probes in results...
    slice_len = 50
    slice_nbr = max(1, min(3, (len(text) + slice_len - 1) // slice_len))
    slice_step = max((len(text) - slice_len) // slice_nbr, 1)
    for algo, method, key, res in generator:
        # The first probe determines the language!
        maxmatch = m.find_best_dic(res[:slice_len])
        lng = max(maxmatch, key=lambda k: maxmatch[k])
        avg = maxmatch[lng]
        for i in range(slice_step, slice_nbr * slice_step, slice_step):
            avg += m.get_match_level(lng, res[i:i + slice_len])
        avg /= slice_nbr
        yield (algo, method, key, res, lng, avg)


def decypher(text, algos, methods, keys):
    """Just a wrapper around do_decypher_xxx, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for unallowed chars…
    c_text = set(text)
    c_allowed = set(string.ascii_uppercase) | {' '}
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only uppercase "
                         "strict ASCII chars and spaces are allowed): '{}'!"
                         "".format("', '".join(sorted(c_text - c_allowed))))

    if ((algos is None or getattr(algos, "__iter__", None)) and
        (methods is None or getattr(methods, "__iter__", None)) and
        (keys is None or getattr(keys, "__iter__", None))):
        return do_hack(text, algos, methods, keys)
    elif algos == ALGO_BASIC:
        if 1 > key > 25:
            raise ValueError("Invalid key value, {} is out of [1, 25] range."
                             "".format(key))
        return do_decypher_basic(text, key)
    elif algo == ALGO_PROGRESS:
        if 1 > key > 25:
            raise ValueError("Invalid key value, {} is out of [1, 25] range."
                             "".format(key))
        if methods not in {PROGRESS_GEOMETRIC, PROGRESS_SHIFT}:
            raise ValueError("Invalid variant for progressive algorithm ({})."
                             "".format(methods))
        return do_decypher_progressive(text, key, methods)
    elif algo == ALGO_SQUARE:
        maxkey = square_max_key(text)
        if key and 2 > abs(key) > maxkey:
            raise ValueError("Invalid key value (size), {} is out of valid "
                             "ranges for this text (None or [2, {}])."
                             "".format(key, maxkey))
        if methods not in {SQUARE_SQUARE, SQUARE_CONSTWIDTH, SQUARE_CONSTHIGH}:
            raise ValueError("Invalid variant for square algorithm ({})."
                             "".format(methods))
        return do_decypher_square(text, key, methods)
    else:
        raise ValueError("Unknown algorithm specified ({})."
                         "".format(algo))


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    # Helper func.
    _algos = {'basic': ALGO_BASIC, 'b': ALGO_BASIC,
              'progressive': ALGO_PROGRESS, 'p': ALGO_PROGRESS,
              'square': ALGO_SQUARE, 's': ALGO_SQUARE,
              'all': None, 'a': None}

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
                                                 "caesar’s code family.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-k', '--key', type=int,
                         help="The cyphering key, has different meanings "
                              "depending on the algorithm chosen, see about "
                              "help for details.")
    cparser.add_argument('-a', '--algo', type=_2ialgo,
                         choices=_algos.values(), default=_algos['b'],
                         help="Which algorithm to use for cyphering.")
    cparser.add_argument('--shift', action='store_true',
                         help="Progressive algo only, use shift mode instead "
                              "of usual geometric one.")
    cparser.add_argument('--constwidth', action='store_true',
                         help="Square algo only, use constant width grid "
                              "instead squarish one.")
    cparser.add_argument('--consthigh', action='store_true',
                         help="Square algo only, use constant high grid "
                              "instead squarish one.")

    dparser = sparsers.add_parser('decypher',
                                          help="Decypher biliteral to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to convert "
                                      "from biliteral.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    dparser.add_argument('-d', '--data',
                                 help="The text to decypher.")
    dparser.add_argument('-k', '--key', type=int, default=None,
                         help="The decyphering key, has different meanings "
                              "depending on the algorithm chosen, see about "
                              "help for details.")
    dparser.add_argument('-a', '--algo', type=_2ialgo,
                         choices=_algos.values(), default=_algos['a'],
                         help="Which algorithm to use for decyphering.")
    dparser.add_argument('--shift', action='store_true',
                         help="Progressive algo only, use shift mode instead "
                              "of usual geometric one.")
    dparser.add_argument('--constwidth', action='store_true',
                         help="Square algo only, use constant width grid "
                              "instead squarish one.")
    dparser.add_argument('--consthigh', action='store_true',
                         help="Square algo only, use constant high grid "
                              "instead squarish one.")

    sparsers.add_parser('about', help="About Caesar…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            if args.algo == ALGO_PROGRESS:
                method = PROGRESS_GEOMETRIC
                if args.shift:
                    method = PROGRESS_SHIFT
            else:
                method = SQUARE_SQUARE
                if args.constwidth:
                    method = SQUARE_CONSTWIDTH
                elif args.consthigh:
                    method = SQUARE_CONSTHIGH
            out = cypher(data, args.algo, args.key, method)
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
            if args.algo == ALGO_PROGRESS:
                method = PROGRESS_GEOMETRIC
                if args.shift:
                    method = PROGRESS_SHIFT
            else:
                method = SQUARE_SQUARE
                if args.constwidth:
                    method = SQUARE_CONSTWIDTH
                elif args.consthigh:
                    method = SQUARE_CONSTHIGH
            if args.key is None:
                if args.algo:
                    args.algo = (args.algo,)
                method = None
            out = decypher(data, args.algo, method, args.key)
            if args.key is None:
                out = sorted(out, key=lambda o: o[5], reverse=True)
                if not args.ofile:
                    out = out[:10]
                fmt = TXT_HACKSOLUTIONS_PATTERN + "\n    {}"
                out = "\n".join((fmt.format(avg, lng, TXT_ALGOS_MAP[algo],
                                            TXT_METHODS_MAP[method], key, res,
                                            alg_len=TXT_ALGOS_MAP_MAXLEN,
                                            met_len=TXT_METHODS_MAP_MAXLEN)
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

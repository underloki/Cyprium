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
a table of n*n dimension, as small as possible for the given text) [when key=0],
constant width [when key > 0], and constant high [when key < 0].



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

# Variants of Progressive algo.
PROGRESS_GEOMETRIC = 1  # Also "basic", which is a geometric suite based on 1.
PROGRESS_SHIFT = 2


# Used to adapt dics, for hacking.
CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZÆŒÀÉÈÙÊÂÎÔÛËÏÜÇÑß")
CHARMAP = {"Æ": "AE", "Œ": "OE", "À": "A", "É": "E", "È": "E", "Ù": "U",
           "Ê": "E", "Â": "A", "Î": "I", "Ô": "O", "Û": "U", "Ë": "E",
           "Ï": "I", "Ü": "U", "Ç": "C", "Ñ": "N", "ß": "SS"}
CHARMAP.update({k.lower(): v for k, v in CHARMAP.items()})
CHARMAP.update({k.lower(): k for k in CHARSET if k not in CHARMAP})
CHARSET |= {c.lower() for c in CHARSET}
CHARSET.add(" ")


def _char_shift(c, base, modulo, shift):
    return chr(((ord(c) - base + shift) % modulo) + base)


def _process_progressive(text, key, mode, _reverse=False):
    """
    (De)cypher message to progressive caesar (increasing offset).
    """
    base = ord('A')
    modulo = ord('Z') - base + 1

    if mode == PROGRESS_GEOMETRIC:
        # Basic is a specific case of geometric, with key = 1!
        delta = key
    elif mode == PROGRESS_SHIFT:
        delta = key
        key = 1

    if _reverse:
        s = -1
    else:
        s = 1

    if ' ' in text:
        ret = []
        for w in text.split():
            ret.append("".join(_char_shift(c, base, modulo, delta * s)
                               for c in w))
            delta = (delta + key) % modulo
        return " ".join(ret)
    else:  # Mono-word...
        ret = []
        for c in text:
            ret.append(_char_shift(c, base, modulo, delta * s))
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
        height = (len(text) + key - 1) // key
        f_ln = key * (height - dlt)
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
    _map = {c: _char_shift(c, base, modulo, key) for c in set(text)}
    _map[' '] = ' '
    return "".join(_map[c] for c in text)


def do_cypher_progressive(text, key, mode):
    """
    Cypher message to progressive caesar (increasing offset).
    """
    return _process_progressive(text, key, mode, False)


def do_cypher_square(text, key):
    """
    Cypher message to caesar's square.
    key = 0 -> square.
    key > 0 -> fixed-width rectangle.
    key < 0 -> fixed-height rectangle.
    """
    return _process_square(text, key, False)


def cypher(text, algo, key, mode=PROGRESS_GEOMETRIC):
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
        if mode not in {PROGRESS_GEOMETRIC, PROGRESS_SHIFT}:
            raise ValueError("Invalid mode for progressive algorithm ({})."
                             "".format(mode))
        return do_cypher_progressive(text, key, mode)
    elif algo == ALGO_SQUARE:
        if -1000 > key > 1000:
            raise ValueError("Invalid key value (size), {} is out of "
                             "[-1000, 1000] range.".format(key))
        return do_cypher_square(text, key)
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


def do_decypher_square(text, key):
    """
    Decypher message to caesar’s square.
    key = 0 -> square.
    key > 0 -> fixed-width rectangle.
    key < 0 -> fixed-height rectangle.
    """
    # It's just a matter of applying reversed cypher operation...
    return _process_square(text, -key, True)


def do_hack(text, algo):
    """
    """
    h = hunspell.Hunspell()
    h.load_dic_zip(hunspell.ZIP_DICS)
    m = matchdic.MatchDic(h)
    m.init(charset=CHARSET, charmap=CHARMAP, minlen=3)

    if algo == ALGO_BASIC:
        generator = ((k, ALGO_BASIC, None, do_decypher_basic(text, k))
                     for k in range(1, 26))
    elif algo == ALGO_PROGRESS:
        def _gen(text):
            for k in range(1, 26):
                yield (k, ALGO_PROGRESS, PROGRESS_GEOMETRIC,
                       do_decypher_progressive(text, k, PROGRESS_GEOMETRIC))
                yield (k, ALGO_PROGRESS, PROGRESS_SHIFT,
                       do_decypher_progressive(text, k, PROGRESS_SHIFT))
        generator = _gen(text)
    elif algo == ALGO_SQUARE:
        def _gen(text):
            maxkey = (len(text) + 1) // 2
            # Squarish square!
            yield (0, ALGO_SQUARE, None, do_decypher_square(text, 0))
            for k in range(1, maxkey + 1):
                yield (k, ALGO_SQUARE, None, do_decypher_square(text, k))
                yield (-k, ALGO_SQUARE, None, do_decypher_square(text, -k))
        generator = _gen(text)
    # test everything!
    else:
        def _gen(text):
            for k in range(1, 26):
                yield (ALGO_BASIC, None, k, do_decypher_basic(text, k))
                yield (ALGO_PROGRESS, PROGRESS_GEOMETRIC, k,
                       do_decypher_progressive(text, k, PROGRESS_GEOMETRIC))
                yield (ALGO_PROGRESS, PROGRESS_SHIFT, k,
                       do_decypher_progressive(text, k, PROGRESS_SHIFT))
            maxkey = (len(text) + 1) // 2
            # Squarish square!
            yield (ALGO_SQUARE, None, 0, do_decypher_square(text, 0))
            for k in range(1, maxkey + 1):
                yield (ALGO_SQUARE, None, k, do_decypher_square(text, k))
                yield (ALGO_SQUARE, None, -k, do_decypher_square(text, -k))
        generator = _gen(text)

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


def decypher(text, algo, key, mode=PROGRESS_GEOMETRIC):
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

    if key is None:
        return do_hack(text, algo)
    elif algo == ALGO_BASIC:
        if 1 > key > 25:
            raise ValueError("Invalid key value, {} is out of [1, 25] range."
                             "".format(key))
        return do_decypher_basic(text, key)
    elif algo == ALGO_PROGRESS:
        if 1 > key > 25:
            raise ValueError("Invalid key value, {} is out of [1, 25] range."
                             "".format(key))
        if mode not in {PROGRESS_GEOMETRIC, PROGRESS_SHIFT}:
            raise ValueError("Invalid mode for progressive algorithm ({})."
                             "".format(mode))
        return do_decypher_progressive(text, key, mode)
    elif algo == ALGO_SQUARE:
        maxkey = (len(text) + 1) // 2
        if -maxkey > key > maxkey:
            raise ValueError("Invalid key value (size), {} is out of "
                             "valid range for this text ([-{}, {}])."
                             "".format(key, -maxkey, maxkey))
        return do_decypher_square(text, key)
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

    sparsers.add_parser('about', help="About Caesar…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            mode = PROGRESS_GEOMETRIC
            if args.shift:
                mode = PROGRESS_SHIFT
            out = cypher(data, args.algo, args.key, mode)
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
            mode = PROGRESS_GEOMETRIC
            if args.shift:
                mode = PROGRESS_SHIFT
            out = decypher(data, args.algo, args.key, mode)
            if args.key is None:
                out = sorted(out, key=lambda o: o[5], reverse=True)
                if not args.ofile:
                    out = out[:10]
                out = "\n".join(("Match: {:<4.2}  Lang: {: <6}  ALGO: {}  "
                                 "METHOD: {:4}  KEY: {: > 6}     {}"
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

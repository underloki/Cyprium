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
import functools

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.2.0"
__date__ = "2012/02/18"
__python__ = "3.x" # Required Python version
__about__ = "" \
"""===== About Morse|Wabun =====
Morse|Wabun is a tool which can “(de)cypher” text to/from morse, or its
japanese version, Wabun.

The valides structures of morse code, for input and output, are:

International: “===...=.=.=.=...=.=...=.=.=.......=.=...=.=.=”,
               where a '.' separates each morse’s “digit”,
                     a '...' separates each letter,
                     a '.......' separates each word (i.e. a space),
                     a '=' represents a dot,
                     and a '===' represents a dash.
Fast international: “- .... .. ... / .. ... / .- / ... --- ...”,
               where a ' ' separates each letter,
                     a ' / ' separates each word (i.e. a space),
                     a '.' represents a dot,
                     and a '-' represents a dash.

Wabun uses the kana japanese syllable alphabet morse code. This means that
each morse code represents a syllable, and not a letter – hence all letters
of a text typically cannot be cyphered, and you get something like:

“HELLO WORLD” ==> “. L L .-... / .--- R L D”

You can have the same variants (standard and fast representations).

You can also use another cypher algorithm for Wabun, “exhaustive”, that will,
for each word, check *all* possible cyphering, and output (again, for each
word) all solutions giving a cyphering threshold (i.e. nbr of cyphered chars/
total nbr of chars) higher than the given one ([0.0 .. 1.0]) – note that
with this tool, a cyphering of 0.6/0.7 is in general already very high, higher
values are very seldom possible (except with rōmaji!).

WARNING: Avoid using that option with words with more than about 15 chars,
         the compute time will quickly become prohibitive!

E.g. for “KATAKANA”,with a threshold of 0.7:
    K --.-- T --.-- .-.. .-.
     K --.-- -. .-.. N --.--
     K --.-- -. K --.-- .-.
        .-.. -. .-.. .-.
     .-.. -. K --.-- N --.--
       .-.. -. K --.-- .-.
    .-.. T --.-- K --.-- .-.
      .-.. T --.-- .-.. .-.
      .-.. -. .-.. N --.--
       K --.-- -. .-.. .-.
    .-.. T --.-- .-.. N --.--

Note that both tools expect uppercase-text only. Morse accepts a few special
chars, in addition to ASCII letters and numbers, while Wabun only accepts
strict ASCII letters and coma, spaces and dots.

The path of the input file can be absolute (e.g. for linux, if the input
file is on your desktop: '/home/admin_name/Desktop/your_input_file'), or
relative to the dir from where you started Morse.

Obviously, the same goes for the output file.

Cyprium.Morse version {} ({}).
Licence GPL3
software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}"
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


def _fast_to_standard(code):
    """
    Convert fast to standard morse representation.
        '.--.-' --> '=.===.===.=.==='
    """
    rep = {'.': '=', '-': '==='}
    return ".".join((rep[c] for c in code))


FI_MAP = {'A': '.-',
          'B': '-...',
          'C': '-.-.',
          'D': '-..',
          'E': '.',
          'F': '..-.',
          'G': '--.',
          'H': '....',
          'I': '..',
          'J': '.---',
          'K': '-.-',
          'L': '.-..',
          'M': '--',
          'N': '-.',
          'O': '---',
          'P': '.--.',
          'Q': '--.-',
          'R': '.-.',
          'S': '...',
          'T': '-',
          'U': '..-',
          'V': '...-',
          'W': '.--',
          'X': '-..-',
          'Y': '-.--',
          'Z': '--..',
          'Ä': '.-.-',    'Æ': '.-.-',
          'Å': '.--.-',   'À': '.--.-',
          'Ĉ': '-.-..',   'Ç': '-.-..',
#          'CH': '----',
          'Ð': '..--.',
          'È': '.-..-',
          'É': '..-..',
          'Ĝ': '--.-.',
          'Ĥ': '-.--.',
          'Ĵ': '.---.',
          'Ñ': '--.--',
          'Ö': '---.',    'Ø': '---.',
          'Ŝ': '...-.',
          'Þ': '.--..',
          'Ü': '..--',    'Ŭ': '..--',
          '1': '.----', 
          '2': '..---',
          '3': '...--',
          '4': '....-',
          '5': '.....',
          '6': '-....',
          '7': '--...',
          '8': '---..',
          '9': '----.',
          '0': '-----',
#          ' ': '....',
#          '\n': '\n',
          ',': '--..--',
          '_': '..--.-',
          '.': '.-.-.-',
          '!': '-.-.--',
          '&': '.-...',
          '=': '-...-',
          '+': '.-.-.',
          '-': '-....-',
          '/': '-..-.',
          "'": '.----.',
          '"': '.-..-.',
          '@': '.--.-.',
          '$': '...-..-',
          '?': '..--..',
          ';': '-.-.-.',
          ':': '---...',
          '(': '-.--.',
          ')': '-.--.-'}
#          '   ': '....'}

# Better to auto-generate that dict from "fast" one!
SI_MAP = {k: _fast_to_standard(v) for k, v in FI_MAP.items()}

_exs = {'.-.-': '[ÄÆ]',
        '.--.-': '[ÅÀ]',
        '-.-..': '[ĈÇ]',
        '---.': '[ÖØ]',
        '..--': '[ÜŬ]'}
RFI_MAP = utils.revert_dict(FI_MAP, _exs)

_exs = {_fast_to_standard(k): v for k, v in _exs.items()}
RSI_MAP = utils.revert_dict(SI_MAP, _exs)


FW_MAP = {',': '.-.-.-',
          '.': '.-.-..',
          '-': '.--.-',
          '(': '-.--.-',
          ')': '.-..-.',
          'A': '--.--',
          'BA': '-.....',
          'BE': '...',
          'BI': '--..-..',
          'BO': '-....',
          'BU': '--....',
          'BYA': '--..-...--',
          'BYU': '--..-..-..--',
          'BYO': '--..-..--',
          'CHA': '..-..--',
          'CHI': '..-.',
          'CHO': '..-.--',
          'CHU': '..-.-..--',
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
          'GYA': '-.-.....--',
          'GYO': '-.-....--',
          'GYU': '-.-....-..--',
          'HA': '-...',
          'HE': '.',
          'HI': '--..-',
          'HO': '-..',
          'HYA': '--..-.--',
          'HYO': '--..---',
          'HYU': '--..--..--',
          'I': '.-',
          'JA': '--.-....--',
          'JO': '--.-...--',
          'JU': '--.-...-..--',
          'JI': '--.-...',
          'KA': '.-..',
          'KE': '-.--',
          'KI': '-.-..',
          'KO': '----',
          'KU': '...-',
          'KYA': '-.-...--',
          'KYO': '-.-..--',
          'KYU': '-.-..-..--',
          'MA': '-..-',
          'ME': '-..-',
          'MI': '..-.-',
          'MO': '-..-.',
          'MU': '-',
          'MYA': '..-.-.--',
          'MYO': '..-.---',
          'MYU': '..-.--..--',
          'N': '.-.-.',
          'NA': '.-.',
          'NE': '--.-',
          'NI': '-.-.',
          'NO': '..--',
          'NU': '....',
          'NYA': '-.-..--',
          'NYO': '-.-.--',
          'NYU': '-.-.-..--',
          'O': '.-...',
          'PA': '-.....--.',
          'PE': '...--.',
          'PI': '--....--.-',
          'PO': '-....--.',
          'PU': '--....--.',
          'PYA': '--..-..--..--',
          'PYO': '--..-..--.--',
          'PYU': '--..-..--.-..--',
          'RA': '...',
          'RE': '--',
          'RI': '--.',
          'RO': '.-.-',
          'RU': '-.--.',
          'RYA': '--..--',
          'RYO': '--.--',
          'RYU': '--.-..--',
          'SA': '-.-.-',
          'SE': '.---.',
          'SHA': '--.-..--',
          'SHI': '--.-.',
          'SHO': '--.-.--',
          'SHU': '--.-.-..--',
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
          'ZO': '---...',
          'ZU': '---.-..'}

# Better to auto-generate that dict from "fast" one!
SW_MAP = {k: _fast_to_standard(v) for k, v in FW_MAP.items()}

# For reverse Wabun, add ascii chars not in Wabun code (mapping to themselves).
RFW_MAP = {c: c for c in string.ascii_uppercase}
RFW_MAP.update(utils.revert_dict(FW_MAP))

RSW_MAP = {c: c for c in string.ascii_uppercase}
RSW_MAP.update(utils.revert_dict(SW_MAP))


# Methods.
INTER = 1  # International.
WABUN = 2  # Wabun (based on kana japanese syllables).
# Variants.
STANDARD = 1  # ('=.===.=...=.......===.===')
FAST = 2      # ('.-. . / --')


# Wabun-only!
def cypher_word(word, c_map, c_sep):
    """
    Yields all possible cypherings of a word, as tuples
    (codes, factor_cyphered).
    factor_cyphered = nbr cyphered letters / nbr letters.
    """
    ln_w = len(word)
    for grps in utils.all_groups_in_order(word, max_n=3):
        cyphered = 0
        y = []
        for el in grps:
            el = "".join(el)
            if el in c_map:
                y.append(c_map[el])
                cyphered += len(el)
            else:
                y.append(c_sep.join(el))
        yield (c_sep.join(y), cyphered / ln_w)


def do_cypher(text, method=INTER, variant=STANDARD, exhaustive=False,
              min_cypher=0.7):
    """
    Return morse or Wabun cyphered text.
    Optional methods are:
        INTER: International code.
        WABUN: Wabun japanese code.
    Optional variants are:
        STANDARD: Standard representation.
        FAST: Fast representation.

    Returns either a str with cyphered words (default basic algorithm,
    only option for international method),
    or, for Wabun, when exhaustive is True, a dict with following values:
        solutions: (a tuple of tuples of cyphered words)
                   [with either a cypher factor higer than min_cypher,
                    or the highest possible cypher factor],
        n_solutions: the total number of solutions,
        best_solutions: (a tuple of tuples of best cyphered words),
        best_n_solutions: the number of best solutions,
        best_cypher: the cypher factor of best solutions.
    """
    if variant == STANDARD:
        w_sep = '.......'
        c_sep = '...'
    elif variant == FAST:
        w_sep = ' / '
        c_sep = ' '

    words = text.split()

    if method == INTER:
        if variant == STANDARD:
            c_map = SI_MAP
        elif variant == FAST:
            c_map = FI_MAP
        morse = []
        for w in words:
            # do_cypher expects checked data, do not handle errors here.
            morse.append(c_sep.join((c_map[c] for c in w)))
        return w_sep.join(morse)

    elif method == WABUN:
        if variant == STANDARD:
            c_map = SW_MAP
        elif variant == FAST:
            c_map = FW_MAP

        if exhaustive:
            all_s = []
            best_s = []
            best_c = []
            for w in words:
                solutions = {s for s in cypher_word(w, c_map, c_sep)}
                fact = min(max(solutions, key=lambda x: x[1])[1], min_cypher)
                all_s.append(tuple((s[0] for s in solutions if s[1] >= fact)))
                all_s.append((w_sep,))
                max_cypher = max(solutions, key=lambda s: s[1])[1]
                best_s.append(tuple((s[0] for s in solutions \
                                              if s[1] >= max_cypher)))
                best_s.append((w_sep,))
                best_c.append(max_cypher)
            # Remove last word-separator.
            del all_s[-1]
            del best_s[-1]
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
                    if w[i:i+3] in c_map:
                        els.append(c_map[w[i:i+3]])
                        i += 3
                    elif w[i:i+2] in c_map:
                        els.append(c_map[w[i:i+2]])
                        i += 2
                    elif w[i] in c_map:
                        els.append(c_map[w[i]])
                        i += 1
                    else:
                        els.append(w[i])
                        i += 1
                enc_w.append(c_sep.join(els))
            return w_sep.join(enc_w)


def cypher(text, method=INTER, variant=STANDARD, exhaustive=False,
           min_cypher=0.7):
    """Wrapper around do_cypher, making some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check for invalid chars.
    if method == INTER:
        c_text = set(text)
        c_allowed = set(FI_MAP) | {' '}
        if not (c_text <= c_allowed):
            raise ValueError("Text contains unallowed chars (only a subset of "
                             "uppercase occidental chars are allowed): '{}'!"
                             "".format("', '".join(sorted(c_text - c_allowed)))
                            )
    elif method == WABUN:
        c_text = set(text)
        c_allowed = set(string.ascii_uppercase) | set(' ,.')
        if not (c_text <= c_allowed):
            raise ValueError("Text contains unallowed chars (only ASCII "
                             "uppercase chars (and space, coma and dots) "
                             "are allowed): '{}'!"
                             "".format("', '".join(sorted(c_text - c_allowed)))
                            )
    return do_cypher(text, method, variant, exhaustive, min_cypher)


def do_decypher(text, method=INTER, variant=STANDARD):
    """Decypher morse or Wabun text in given variant."""
    if variant == STANDARD:
        w_sep = '.......'
        c_sep = '...'
        if method == INTER:
            c_map = RSI_MAP
        elif method == WABUN:
            c_map = RSW_MAP
    elif variant == FAST:
        w_sep = ' / '
        c_sep = ' '
        if method == INTER:
            c_map = RFI_MAP
        elif method == WABUN:
            c_map = RFW_MAP

    ret = []
    for w in text.split(w_sep):
        ret.append("".join((c_map[c] for c in w.split(c_sep))))
    return " ".join(ret)


def decypher(text, method=None):
    """Wrapper around do_decypher, making some checks."""
    # Any text given ?
    if not text:
        raise ValueError("No text given!")
    # Fast variant.
    if ' ' in text:
        c_text = set(text.split(' '))
        c_allowed_i = set(RFI_MAP) | {'/'}
        c_allowed_w = set(RFW_MAP) | {'/'} | set(string.ascii_uppercase)
        invalid_i = c_text - c_allowed_i
        invalid_w = c_text - c_allowed_w
        # Fast International.
        if not invalid_i and method in {None, INTER}:
            return do_decypher(text, INTER, FAST)
        # Fast Wabun.
        elif not invalid_w and method in {None, WABUN}:
            return do_decypher(text, WABUN, FAST)
        # Else, error!
        if len(invalid_i) > len(invalid_w) or method == INTER:
            raise ValueError("Text appears to be fast international morse "
                             "containing invalid codes: '{}'!"
                             "".format("', '".join(sorted(invalid_i))))
        else:
            raise ValueError("Text appears to be fast Wabun containing "
                             "invalid chars or codes: '{}'!"
                             "".format("', '".join(sorted(invalid_w))))
    # Standard variant.
    elif '=' in text:
        c_text = {c.strip('.') for c in text.split('...')}
        c_allowed_i = set(RSI_MAP) | {''}
        c_allowed_w = set(RSW_MAP) | set(string.ascii_uppercase) | {''}
        invalid_i = c_text - c_allowed_i
        invalid_w = c_text - c_allowed_w
        # Standard International.
        if not invalid_i and method in {None, INTER}:
            return do_decypher(text, INTER, STANDARD)
        # Standard Wabun.
        elif not invalid_w and method in {None, WABUN}:
            return do_decypher(text, WABUN, STANDARD)
        # Else, error!
        print(invalid_i, invalid_w)
        if len(invalid_i) > len(invalid_w) or method == INTER:
            raise ValueError("Text appears to be standard international "
                             "morse containing invalid codes: '{}'!"
                             "".format("', '".join(sorted(invalid_i))))
        else:
            raise ValueError("Text appears to be standard Wabun "
                             "containing invalid chars or codes: '{}'!"
                             "".format("', '".join(sorted(invalid_w))))
    else:
        raise ValueError("That text seems to be no morse nor Wabun!")


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description="Cypher/decypher some text "
                                                 "in morse or Wabun code.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cypher_parser = sparsers.add_parser('cypher', help="Cypher data.",
                                        description="Cypher some text in "
                                                    "morse or Wabun code.")
    cypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text to cypher.")
    cypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                               help="A file into which write the cyphered "
                                    "text.")
    cypher_parser.add_argument('-d', '--data', help="The text to cypher.")
    cypher_parser.add_argument('-w', '--wabun', action="store_const",
                               const=WABUN, default=INTER, dest="method",
                               help="Use Wabun instead of international code.")
    cypher_parser.add_argument('-f', '--fast', action="store_const",
                               const=FAST, default=STANDARD, dest="variant",
                               help="Use fast morse/Wabun variant, instead of "
                                    " standard one.")
    cypher_parser.add_argument('--exhaustive', action="store_true",
                               help="Use a complete search of all possible "
                                    "cypherings. Only relevant with --wabun. "
                                    "WARNING: with long words, it "
                                    "will take a *very* long time to compute "
                                    "(tens of seconds with 15 chars word, and "
                                    "increasing at a *very* high rate)!")
    cypher_parser.add_argument('--min_cypher', type=float, default=0.7,
                               help="Minimum level of cyphering, if possible. "
                                    "Only relevant with --exhaustive!"
                                    "Note typical good cypher level is 0.7 "
                                    "(nbr of chars/nbr of cyphered chars, "
                                    "for each word), defaults to 0.7.")

    decypher_parser = sparsers.add_parser('decypher', help="Text to Decypher.",
                                          description="Decypher some text "
                                                      "from morse or Wabun "
                                                      "code (auto-detected "
                                                      "by default).")
    decypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to "
                                      "decypher.")
    decypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    decypher_parser.add_argument('-d', '--data', help="The text to decypher.")
    decypher_parser.add_argument('-n', '--international', action="store_const",
                                 const=INTER, default=None,
                                 help="Force international decyphering "
                                      "(default: auto detection).")
    decypher_parser.add_argument('-w', '--wabun', action="store_const",
                                 const=WABUN, default=None, dest="method",
                                 help="Force Wabun decyphering (default: "
                                      "auto detection).")

    sparsers.add_parser('about', help="About Morse|Wabun…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            exhaustive = args.exhaustive and args.method == WABUN
            out = cypher(data, args.method, args.variant, exhaustive,
                         args.min_cypher)
            if exhaustive:
                print("Exaustive found {} solutions for a minimum "
                      "cyphering of {}, among which {} solutions with the "
                      "highest possible cyphering ({}):"
                      "".format(out["n_solutions"], args.min_cypher,
                                out["best_n_solutions"],
                                out["best_cypher"]))
                text = "\n".join(utils.format_multiwords(out["solutions"],
                                                         sep=""))
                b_text = \
                    "\n".join(utils.format_multiwords(out["best_solutions"],
                                                      sep=""))
            else:
                text = out
                b_text = ""
            if args.ofile:
                args.ofile.write(text)
                if b_text:
                    args.ofile.write("\n\n")
                    args.ofile.write(b_text)
            else:
                if exhaustive:
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
        return

    elif args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decypher(data, args.method)
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
        return

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

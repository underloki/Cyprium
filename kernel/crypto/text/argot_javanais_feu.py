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

__version__ = "0.1.0"
__date__ = "2012/01/15"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About ArgotJavanais|LangueDeFeu =====
ArgotJavanais|LangueDeFeu allows you to cypher and decrypt some text using
one of those methods (or there generic version).

The principle is to insert a syllable (always the same, two letters only,
which we’ll call “obfuscating syllable”) between consonants and vowels
(with a few additional restrictions/special cases).

Javanais method allows (and searches for, at decypher time) the traditional
'ja', 'av' and 'va' syllables, and all their case variants ('Ja', 'VA', etc.).
E.g. using ja:
“Les « Blousons Noirs » vous parlent…” →
    “Ljaes « Bljaousjaons Njaoirs » vjaous parljaent…”

Feu method allows (and search for, at decypher time) all syllables made of
a 'f' and a vowel, and all their case variants ('fe', 'Af', 'fO', 'UF', etc.).
E.g. using Ef:
“Les Apaches sont sur le sentier des Halles.” →
    “LEfes EfApEfachEfes sEfont sEfur lEfe sEfentEfier dEfes HEfallEfes.”

Generic method allows (and search for, at decypher time) all syllables made of
a consonant and a vowel, or two different vowels, and all their case variants
(example of *not allowed* syllables: 'oO', 'ii', 'fp', 'Kz', etc.).
E.g. using uz:
“Casque d’or refait sa permanente.” ->
    “Cuzasquzue d’or ruzefuzait suza puzermuzanuzentuze.”

You can also use another cypher algorithm, “exhaustive”, that will, for each
word, check *all* possible chipering, and output (again, for each word) all
solutions giving a cyphering threshold (i.e. nbr of obfuscating syllables
added/total nbr of chars) higher than the given one ([0.0 .. 1.0]).

E.g. for “Bellville”, with 'av' and a threshold of 0.2:
     Bellavevavillave
      Bellevavillave
      Bellavevaville
     Bavellevavillave
      Bellavevillave
     Bavellavevaville
      Bavellevillave
     Bavellavevillave
      Bavellevaville
    Bavellavevavillave
      Bavellaveville

WARNING: If the text already contains the obfuscating syllable, it will
         likely be lost a decyphering time!

Cyprium.ArgotJavanais|LangueDeFeu version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


# XXX For now, only work on basic (ASCII) letters.
VOWELS = {'a', 'e', 'i', 'o', 'u', 'y',
          'A', 'E', 'I', 'O', 'U', 'Y'}
CONSONANTS = set(string.ascii_letters) - VOWELS


# For cases like ys -> y[sylb]is, yr -> y[sylb]ir, etc.
Y_C_ADD = 'i'


# Types...
GENERIC = 0
JAVANAIS = 1
FEU = 2


def is_valid_syllable(method, syllable):
    """Return True if syllable is a valid obsucating one for given type."""
    if len(syllable) != 2:
        return False

    l = set(syllable)
    if method == GENERIC:
        # One or two vowels, not twice the same letter.
        return (l & VOWELS) and (len(l) == 2)
    if method == JAVANAIS:
        # ja, av, va, and case variants.
        valids = set()
        for v in ('aj', 'ja', 'av', 'va'):
            valids |= set(utils.case_variants(v))
        return syllable in valids
    elif method == FEU:
        # One vowel and f/F.
        return (l & VOWELS) and (l & {'f', 'F'})
    return False


def _obfuscate_syllable(s, o_s, is_first=False):
    """Return the obfuscated syllable by given type, if possible."""
    # Length-agnostic.
    # Start of word, begin by a vowel (a, is, ef, etc.).
    if is_first and s[0] in VOWELS:
        return "".join((o_s, s))
    # Two letters.
    elif len(s) == 2:
        # No obfuscation if it generates doublons (e.g. aavv -> NO!).
        if s[0] == o_s[0] or s[1] == o_s[1]:
            return s
        # Most common case (s is ba, se, ti, etc.)
        if s[0] in CONSONANTS and s[1] in VOWELS:
            return "".join((s[0], o_s, s[1]))
        # s is ye, ya, etc.
        elif s[0] in {'y', 'Y'} and s[1] in VOWELS:
            return "".join((s[0], o_s, s[1]))
        # s is ys, yr, etc.
        elif s[0] in {'y', 'Y'} and s[1] in CONSONANTS:
            return "".join((s[0], o_s, Y_C_ADD, s[1]))
    # Else, just return the org syllable.
    return s


def cypher_word(word, syllable):
    """
    Yields all possible cypherings of a word, as tuples
    (codes, factor_cyphered).
    factor_cyphered = nbr added syllables / nbr letters.
    """
    ln_w = len(word)
    for grps in utils.all_groups_in_order(word, max_n=2):
        cyphered = 0
        y = []
        first = True
        for el in grps:
            el = "".join(el)
            cyp = _obfuscate_syllable(el, syllable, first)
            if cyp != el:
                cyphered += 1
            y.append(cyp)
            if first:
                first = False
        yield ("".join(y), cyphered / ln_w)


def do_cypher(text, syllable, exhaustive=False, min_cypher=0.8):
    """
    Cypher (obfuscate) text in "argot javanais" or "langue de feu" method.
    Returns either a str with cyphered words (default basic algorithm),
    or, when exhaustive is True, a dict with following values:
        solutions: (a tuple of tuples of cyphered words)
                   [with either a cypher factor higer than min_cypher,
                    or the highest possible cypher factor],
        n_solutions: the total number of solutions,
        best_solutions: (a tuple of tuples of best cyphered words),
        best_n_solutions: the number of best solutions,
        best_cypher: the cypher factor of best solutions.
    Warning: If the text already contains the obfuscating syllable, it will
             likely be lost a decyphering time!
    """
    words = text.split()
    if exhaustive:
        all_s = []
        best_s = []
        best_c = []
        for w in words:
            solutions = {s for s in cypher_word(w, syllable)}
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
            first = True
            i = 0
            ln_w = len(w)
            while i < ln_w:
                s = w[i:i + 2]
                cyb = _obfuscate_syllable(s, syllable, first)
                if cyb != s:
                    els.append(cyb)
                    i += 2
                else:
                    els.append(s[0])
                    i += 1
                if first:
                    first = False
            enc_w.append("".join(els))
        return " ".join(enc_w)


def cypher(text, method, syllable, exhaustive=False, min_cypher=0.8):
    """Wrapper around do_cypher, making some checks."""
    import string
    if not text:
        raise Exception("No text given!")
    # Check the given syllable is compatible with given method.
    if not is_valid_syllable(method, syllable):
        m_name = "Generic"
        if method == JAVANAIS:
            m_name = "Argot Javanais"
        elif method == FEU:
            m_name = "Langue de Feu"
        raise ValueError("Given syllable ({}) is invalid for “{}” type."
                         "".format(syllable, m_name))
    return do_cypher(text, syllable, exhaustive, min_cypher)


#############################################################################
def decypher_word(word, syllable):
    """
    We cannot use replace, as in some cases (single syllable, syllable at end
    of word...), we know we must not remove it, as it can’t have been added
    by the cyphering algorithm.
    """
    if word == syllable:
        return word

    len_w = len(word)
    if word.endswith(syllable):
        if len_w > 3:
            return "".join((word[0:-2].replace(syllable, ''), word[-2:]))
        else:
            return word
    return word.replace(syllable, '')


def do_decypher(text, method, syllable=None):
    """
    Decypher text, by removing given syllable, or most common one,
    from it.
    Return a list, as if syllable is not given, there might be more than one!
    """
    if not syllable:
        # Find the most common syllable(s).
        sybs = {}
        invalids = set()
        for s in utils.nwise(text, 2):
            s = "".join(s)
            if s in invalids:
                continue
            if s not in sybs:
                if is_valid_syllable(method, s):
                    sybs[s] = 1
                else:
                    invalids.add(s)
            else:
                sybs[s] += 1
        max_nr = max(sybs.values())
        syb = (k for k, v in sybs.items() if v == max_nr)
    else:
        syb = (syllable,)

    # XXX About the 'ys' -> 'y[syb]is': There’s no way to detect this at
    #     decypher time!
    ret = []
    for s in syb:
        # We can’t directly use replace(). :/
        ret.append((s, " ".join((decypher_word(w, s) for w in text.split()))))
    return ret


def decypher(text, method, syllable=None):
    """Wrapper around do_decypher, making some (very limited!) checks."""
    if not text:
        raise Exception("No text given!")
    # Check the given syllable (if any) is compatible with given method.
    if syllable and not is_valid_syllable(syllable, method):
        m_name = "Generic"
        if method == JAVANAIS:
            m_name = "Argot Javanais"
        elif method == FEU:
            m_name = "Langue de Feu"
        raise ValueError("Given syllable ({}) is invalid for “{}” type."
                         "".format(syllable, m_name))
    return do_decypher(text, method, syllable)


def main():
    # Treating direct script call with args
    # Args retrieval
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher a text according to "
                                     "“Argot Javanais”, “Langue de Feu”, "
                                     "or a generic version of those, i.e. by "
                                     "adding an obfuscating syllable between "
                                     "consonants and vowels.\n"
                                     "Example: 'Test' => 'Tavest'.\n")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cypher_parser = sparsers.add_parser('cypher', help="Cypher text.")
    cypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                help="A file containing the text to cypher.")
    cypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                help="A file into which write the cyphered "
                                     "text.")
    cypher_parser.add_argument('-d', '--data', help="The text to cypher.")
    cypher_parser.add_argument('-s', '--syllable', help="Obfuscating syllable "
                                                        "to insert in text.")
    cypher_parser.add_argument('-j', '--javanais', action="store_true",
                               help="Restrict allowed obfuscating syllables "
                                    "to ja, av and va (and their case "
                                    "variants).")
    cypher_parser.add_argument('-f', '--feu', action="store_true",
                               help="Restrict allowed obfuscating syllablse "
                                    "to a f and a vowel (and their case "
                                    "variants).")
    cypher_parser.add_argument('--exhaustive', action="store_true",
                               help="Use a complete search of all possible "
                                    "cypherings. WARNING: with long words, it "
                                    "will take a *very* long time to compute "
                                    "(tens of seconds with 15 chars word, and "
                                    "increasing at a *very* high rate)!")
    cypher_parser.add_argument('--min_cypher', type=float, default=0.2,
                               help="Minimum level of cyphering, if possible. "
                                    "Only relevant with --exhaustive!"
                                    "Note typical good cypher level is 0.3 "
                                    "(nbr of chars/nbr of syllables added, "
                                    "for each word), defaults to 0.2.")

    decypher_parser = sparsers.add_parser('decypher', help="Decypher text.")
    decypher_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                                 help="A file containing the text to "
                                      "decypher.")
    decypher_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                                 help="A file into which write the decyphered "
                                      "text.")
    decypher_parser.add_argument('-d', '--data', help="The text to decypher.")
    decypher_parser.add_argument('-s', '--syllable',
                                 help="Obfuscating syllable to remove from "
                                      "text (if none given, the most common "
                                      "one compatible with choosen method "
                                      "will be used).")
    decypher_parser.add_argument('-j', '--javanais', action="store_true",
                               help="Restrict allowed obfuscating syllables "
                                    "to ja, av and va (and their case "
                                    "variants).")
    decypher_parser.add_argument('-f', '--feu', action="store_true",
                               help="Restrict allowed obfuscating syllables "
                                    "to a f and a vowel (and their case "
                                    "variants).")

    sparsers.add_parser('about', help="About ArgotJavanais|LangueDeFeu…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            method = GENERIC
            syllable = args.syllable
            if args.javanais:
                method = JAVANAIS
                if not syllable:
                    print("WARNING: No obfuscating syllable given, using "
                          "'av' default one.")
                    syllable = "av"
            if args.feu:
                method = FEU
                if not syllable:
                    print("WARNING: No obfuscating syllable given, using "
                          "'fe' default one.")
                    syllable = "fe"
            if args.syllable in data:
                print("WARNING: The choosen obfuscating syllable is already "
                      "present in the text, decyphering will likely give "
                      "wrong results…")
            out = cypher(data, method, args.syllable, args.exhaustive,
                         args.min_cypher)
            if args.exhaustive:
                print("Exaustive found {} solutions for a minimum "
                      "cyphering of {}, among which {} solutions with the "
                      "highest possible cyphering ({}):"
                      "".format(out["n_solutions"], args.min_cypher,
                                out["best_n_solutions"],
                                out["best_cypher"]))
                text = "\n".join(utils.format_multiwords(out["solutions"],
                                                         sep=" "))
                b_text = \
                    "\n".join(utils.format_multiwords(out["best_solutions"],
                                                      sep=" "))
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
        return

    elif args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            method = GENERIC
            if args.javanais:
                method = JAVANAIS
            if args.feu:
                method = FEU
            out = decypher(data, method, args.syllable)
            text = "\n\n".join(["Using '{}':\n    {}"
                                "".format(o[0], o[1]) for o in out])
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
        return

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

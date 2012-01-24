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
__date__ = "2012/01/24"
__python__ = "3.x"  # Required Python version


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
LARGONJI = 10


# Loucherbem...
# To add after a vowel (sound type, see below).
LARGONJI_SYLLABLES_V = {"quème", "qué", "puche"}

# To add after a consonant.
LARGONJI_SYLLABLES_C = {"ème", "esse", "i", "ic", "oc", "ouche"}

# End "vowels" combinations.
# Higly french-centric... :/
LARGONJI_VOWELS = {
    "a", "at", "as", "ât",
    "e", "eu", "eux", "eut", "es",
    "i", "y", "is", "it", "ît", "ie", "ies", "ient", "ys",
    "o", "au", "aux", "ôt", "ôts", "os",
    "u", "ut", "ût", "us", "ue", "ues",
    "ué", "uée",
    "an", "ant", "en", "ent", "end", "ends", "emps",
    "è", "ai", "ait", "ais", "aie", "aient", "aît",
    "é", "ez", "er", "és", "ée", "ées",
    "on", "ont", "ons",
    "un", "in", "uns", "ins"}


__about__ = "" \
"""===== About Argots =====
Argots allows you to cypher and decypher some text using one of Argot Javanais,
Langue de Feu (or there generic version), or Largonji des Loucherbems methods.


== Argot Javanais, Langue de Feu and Generic ==
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
word, check *all* possible cyphering, and output (again, for each word) all
solutions giving a cyphering threshold (i.e. nbr of obfuscating syllables
added/total nbr of chars) around the given one ([0.0 .. 1.0] ± 0.05) – note
that with this tool, a cyphering of 0.3/0.4 is in general already very high,
higher values are very seldom possible.

WARNING: Avoid using that option with words with more than about 20 chars,
         the compute time will quickly become prohibitive!

E.g. for “Bellville”, with 'av' and a cyphering goal of 0.3:
    Bavelleviavllave
    Bavellavevillave
    Beavlleviavllave
    Beavllavevillave
    Bavellevavillave
    Bavellaveviavlle
    Bavellavevaville
    Bellaveviavllave
    Beavllaveviavlle
    Beavllevavillave
    Bellavevavillave
    Beavllavevaville

WARNING: If the text already contains the obfuscating syllable, it will
         likely be lost a decyphering time!


== Largonji des Loucherbems ==
WARNING: While previous methods, even though french at origin, are quite easily
         extendable to other languages, the Louchébem is tightly related to
         french phonetic, and hence might give strange/unusable results with
         other languages.
         And even with french, it’s hard to get reliable results with
         procedural algorithms… So this tool is more an help than an
         “out-of-the-box” solution.

This “cyphering” roughly consists in, for each word:
    * If the first letter is a consonant, move it to the end of the word.
    * Add an 'l' at the beginning of the word.
    * Finally, add a (more or less random) syllable at the end of the word.
So you get “boucher” (butcher) ==> “oucherb” ==> “loucherb” ==> “loucherbème”.
           “jargon” ==> “argonj” ==> “largonj” ==> “largonji”.
           “abricot” ==> “abricot” ==> “labricot” ==> “labricotqué”
           “lapin” ==> “apinl” ==> “lapinl” ==> “lapinlic”.
           etc.

By default, the following vowels can be added after a “phonetic vowel”:
    '{}'
And those, after a consonant:
    '{}'
You can specify other sets, but beware, this might make decyphering even more
complicated and unreliable…

Note that during decyphering, if Argots finds an unknown suffix, it will try
to use it too – but result may well be quite wrong in this case. And given
the fuzzyness of this argots, decyphering will systematically output the
original (cyphered) word, at the end of the lists.

Note also that current code assume “largonji suffixes” are never longer than 5
chars, and never (de)cyphers words shorter than 4 chars (sorry for
“loufoque” !).


Cyprium.Argots version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(LARGONJI_SYLLABLES_V, LARGONJI_SYLLABLES_C, __version__,
           __date__, utils.__pf__, utils.__pytver__)


def is_valid_syllable(method, syllable):
    """Return True if syllable is a valid obfsucating one for given type."""
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
    elif method == LARGONJI:
        # Very simple, not real rules...
        #     Must contain at least a vowel,
        #     and length in [1, 5], with consonant(s) if length > 2.
        return (l & VOWELS) and ((1 <= len(l) <= 2) or
                                 ((3 <= len(l) <= 5) and (l & CONSONANTS)))
    return False


def _obfuscate_syllable(s, o_s, is_first=False):
    """Return the obfuscated syllable by given type, if possible."""
    # Start of word, begin by a mono-vowel (a, i, e, etc.).
    if is_first and s in VOWELS:
        if s[0] != o_s[0]:
            return "".join((s, o_s))
    # Two letters.
    elif len(s) == 2:
        # No obfuscation if it generates doublons (e.g. aavv -> NO!).
        if s[0] == o_s[0] or s[1] == o_s[1]:
            return s
        # s is ye, ya, etc.
        elif s[0] in {'y', 'Y'} and s[1] in VOWELS:
            return "".join((s[0], o_s, s[1]))
        # s is ys, yr, etc.
        elif s[0] in {'y', 'Y'} and s[1] in CONSONANTS:
            return "".join((s[0], o_s, Y_C_ADD, s[1]))
        # Most common case (s is ba, ok, se, ti, ut, ir, etc.)
        elif (s[0] in CONSONANTS and s[1] in VOWELS) or \
             (s[0] in VOWELS and s[1] in CONSONANTS):
            return "".join((s[0], o_s, s[1]))
    # Else, just return the org syllable.
    return s


def _loucherbemize(word, sylb_v, sylb_c):
    """
    Yields all possible cypherings of a word.
    """
    def _generator(prepnd, word, fl, ends, appnd):
        for end in ends:
            yield "".join((prepnd, word, fl, end, appnd))

    prepnd = appnd = ""
    # Take apart non-alpha starting chars (like quotes, etc.).
    for idx, c in enumerate(word):
        if c.isalpha():
            prepnd = word[:idx]
            word = word[idx:]
            break
    # Take apart non-alpha ending chars (like coma, dots, etc.).
    for idx, c in enumerate(word):
        if not c.isalpha():
            appnd = word[idx:]
            word = word[:idx]
            break

    # Do not affect short words!
    if len(word) < 4:
        return ("".join((prepnd, word, appnd)),)  # pseudo-generator...

    # Get first letter if consonant.
    if word[0].isupper():
        fl = word[0].lower()
        prepnd = prepnd + 'L'
    else:
        fl = word[0]
        prepnd = prepnd + 'l'

    # Very basic plural handling...
    if word[-1] in "sS":
        appnd = word[-1] + appnd
        word = word[:-1]

    # Always add a "consonant-compliant" end.
    if fl in CONSONANTS:
        return _generator(prepnd, word[1:], fl, sylb_c, appnd)
    # If word starts with a vowel, no "fl" to insert, have to check whether
    # it ends with a "vowel" or consonant.
    fl = ''
    w = word.lower()
    for i in range(-5, 0):
        if w[i:] in LARGONJI_VOWELS:
            # We have a "vowel" end, use a "vowel-compliant" end.
            return _generator(prepnd, word, fl, sylb_v, appnd)
    # At this stage, it’s assumed to end with a consonant.
    return _generator(prepnd, word, fl, sylb_c, appnd)


def _unloucherbemize(word, sylb_v, sylb_c):
    """
    Yields all possible decypherings of a word (together with its org form).
    """
    def _generator(prepnd, words, appnd):
        for w in words:
            yield "".join((prepnd, w, appnd))

    prepnd = appnd = ""
    # Take apart non-alpha starting chars (like quotes, etc.).
    for idx, c in enumerate(word):
        if c.isalpha():
            prepnd = word[:idx]
            word = word[idx:]
            break
    # Take apart non-alpha ending chars (like coma, dots, etc.).
    for idx, c in enumerate(word):
        if not c.isalpha():
            appnd = word[idx:]
            word = word[:idx]
            break

    # Do not affect short words, or words not starting by 'l'/'L'!
    if len(word) < 6 or word[0] not in 'lL':
        return ("".join((prepnd, word, appnd)),)  # pseudo-generator...

    is_upper = word[0].isupper()

    # Very basic plural handling...
    if word[-1] in "sS":
        appnd = word[-1] + appnd
        word = word[:-1]

    # XXX Here we assume "largonji suffix" is never longer than 5 chars.
    #     And cyphered words are at least 4 (-1 for possible s,
    #     +1 for starting l) length.
    #     Again, all this is quite fuzzy... :/
    w = word.lower()
    for i in range(max(-5, 4 - len(w)), 0):
        if w[i:] in sylb_v:
            # We have a "vowel-compliant" end, which means the org word started
            # with a vowel, and ended with "phonetic-vowel".
            # This is the only case where we can decypher for sure, but return
            # the cyphered form of the word nevertheless.
            if is_upper:
                # Capitalize the word... and remove first l.
                w1 = word[1].upper() + word[2:i]
            else:
                w1 = word[1:i]
            return _generator(prepnd, (w1, word), appnd)
        elif w[i:] in sylb_c:
            # We have a "consonant-compliant" end, which means the org word
            # either started with a consonant, or started with a vowel and
            # ended with a consonant.
            # Return both possibilities (and cyphered word too).
            if is_upper:
                # Capitalize the words...
                w1 = word[i - 1].upper() + word[1:i - 1]
                w2 = word[1].upper() + word[2:i]
            else:
                w1 = word[i - 1] + word[1:i - 1]
                w2 = word[1:i]
            return _generator(prepnd, (w1, w2, word), appnd)

    # At this stage, we did not find a known suffix largonji syllable.
    # Try some blind decyphering...
    # XXX This is very hackish, boring, and unreliable code!
    # First, get the two previous syllables as (c1v1, c2v2)
    v2 = ""
    c2 = ""
    
    for i in range(max(-5, 4 - len(w)), 0):
        if w[i:] in LARGONJI_VOWELS:
            if w[i - 1] not in CONSONANTS:
                # Fuzzy/error, just return unmodified cyphered word.
                return _generator(prepnd, (word,), appnd)
            v2 = word[i:]
            c2 = word[i - 1]
            word = word[:i - 1]
            w = w[:i - 1]
            break
    if not v2 and w[-1] in CONSONANTS:
        # Ends like "-ic", "ok", etc.
        c2 = word[-1]
        word = word[:-1]
        w = w[:-1]
    v1 = ""
    c1 = ""
    if len(word) > 5:
        for i in range(max(-5, 4 - len(w)), 0):
            if w[i:] in LARGONJI_VOWELS:
                v1 = word[i:]
                word = word[:i]
                w = w[:i]
                if w[-1] in CONSONANTS:
                    c1 = word[-1]
                    word = word[:-1]
                break
    # And now, create all possible words...
    ws = [c2 + word[1:] + c1 + v1,
          word[1:] + c1 + v1,
          word[1:] + c1 + v1 + c2]
    if c1:
        ws += [c1 + word[1:],
               word[1:],
               word[1:] + c1]
    # Capitalize if needed.
    if is_upper:
        ws =  [w[0].upper() + w[1:] for w in ws]
    # Org word
    ws.append(word + c1 + v1 + c2 + v2)
    return _generator(prepnd, ws, appnd)


###############################################################################
def cypher_word(word, syllable):
    """
    Yields all possible cypherings of a word, as tuples
    (codes, factor_cyphered).
    factor_cyphered = nbr added syllables / nbr letters.
    """
    ln_w = len(word)
    for grps in utils.all_groups_in_order(word, (1,2)):
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


def do_cypher(text, method, syllable, exhaustive=False, cypher_goal=0.8):
    """
    Cypher (obfuscate) text in "argot javanais" or "langue de feu" method.
    Or, if method is LARGONJI, in largonji des loucherbems (in this case,
    syllable must be a tuple(vowel-compliant syllables,
                             consonant-compliant syllables).
    Returns either a str with cyphered words (default basic algorithm),
    or, when exhaustive is True, a dict with following values:
        solutions: (a tuple of tuples of cyphered words)
                   [with either a cypher factor near cypher_goal,
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
            fact_min = min(max(solutions, key=lambda x: x[1])[1],
                           max(cypher_goal - 0.05, 0.0))
            t_s = [s for s in solutions if s[1] >= fact_min]
            fact_max = max(min(t_s, key=lambda x: x[1])[1],
                           cypher_goal + 0.05)
            all_s.append(tuple((s[0] for s in t_s
                                     if fact_min <= s[1] <= fact_max)))
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


def cypher(text, method, syllable, exhaustive=False, cypher_goal=0.8):
    """Wrapper around do_cypher, making some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check the given syllable is compatible with given method.
    if not is_valid_syllable(method, syllable):
        m_name = "Generic"
        if method == JAVANAIS:
            m_name = "Argot Javanais"
        elif method == FEU:
            m_name = "Langue de Feu"
        raise ValueError("Given syllable ({}) is invalid for “{}” type."
                         "".format(syllable, m_name))
    return do_cypher(text, method, syllable, exhaustive, cypher_goal)


def do_cypher_largonji(text, vowel_syllables=LARGONJI_SYLLABLES_V,
                       consonant_syllables=LARGONJI_SYLLABLES_C):
    """
    Cypher (obfuscate) text in "largonji des loucherbems".
    Syllables must be a tuple(vowel-compliant syllables,
                              consonant-compliant syllables).
    Return a dict with following values:
        solutions: (a tuple of tuples of cyphered words),
        n_solutions: the total number of solutions.
    """
    # In this case, syllable must be a tuple of syllables "vowel-compliant"
    # and "consonant-compliant".
    s = tuple(tuple(_loucherbemize(w, vowel_syllables, consonant_syllables))
              for w in text.split())
    return {"solutions": s,
            "n_solutions": functools.reduce(lambda n, w: n * len(w), s, 1)}


def cypher_largonji(text, vowel_syllables=LARGONJI_SYLLABLES_V,
                          consonant_syllables=LARGONJI_SYLLABLES_C):
    """Wrapper around do_cypher, making some checks."""
    import string
    if not text:
        raise ValueError("No text given!")
    # Check there are some syllables, and vowels and consonants do not match.
    if not (vowel_syllables and consonant_syllables):
        raise ValueError("No suffix syllables given!")
    vs = set(vowel_syllables)
    cs = set(consonant_syllables)
    if vs & cs:
        raise ValueError("Some vowel and consonant syllables are the same, "
                         "this would make decyphering really unreliable, "
                         "please fix that ('{}')!"
                         "".format("', '".join(vs & cs)))
    # Be sure to not have doubles...
    vowel_syllables = tuple(vs)
    consonant_syllables = tuple(cs)
    return do_cypher_largonji(text, vowel_syllables, consonant_syllables)


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
        if len_w <= 2:
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
        raise ValueError("No text given!")
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


def do_decypher_largonji(text, vowel_syllables=LARGONJI_SYLLABLES_V,
                         consonant_syllables=LARGONJI_SYLLABLES_C):
    """
    Decypher text, by removing trailing syllables, and starting 'l'.
    syllables is a tuple (syllables_for_vowels, syllables_for_consonants).
    Return a list of tuples containing each possible decipher for each word.
    """
    ret = [tuple(_unloucherbemize(w, vowel_syllables, consonant_syllables))
           for w in text.split()]
    return ret


def decypher_largonji(text, vowel_syllables=LARGONJI_SYLLABLES_V,
                      consonant_syllables=LARGONJI_SYLLABLES_C):
    """Wrapper around do_decypher_largonji, making some checks."""
    if not text:
        raise ValueError("No text given!")
    # Check vowels and consonants do not match.
    vs = set(vowel_syllables)
    cs = set(consonant_syllables)
    if vs & cs:
        raise ValueError("Some vowel and consonant syllables are the same, "
                         "this would make decyphering really unreliable, "
                         "please fix that ('{}')!"
                         "".format("', '".join(vs & cs)))
    # Be sure to not have doubles...
    vowel_syllables = tuple(vs)
    consonant_syllables = tuple(cs)
    return do_decypher_largonji(text, vowel_syllables, consonant_syllables)


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

    cparser = sparsers.add_parser('cypher', help="Cypher text.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-s', '--syllable',
                         help="Obfuscating syllable to insert in text.")
    cparser.add_argument('-j', '--javanais', action="store_true",
                         help="Restrict allowed obfuscating syllables to ja, "
                              "av and va (and their case variants).")
    cparser.add_argument('-f', '--feu', action="store_true",
                         help="Restrict allowed obfuscating syllables to a f "
                              "and a vowel (and their case variants).")
    cparser.add_argument('--exhaustive', action="store_true",
                         help="Use a complete search of all possible "
                              "cypherings. WARNING: with long words, it will "
                              "take a *very* long time to compute (seconds "
                              "with 20 chars word, and increasing at a high "
                              "rate)!")
    cparser.add_argument('--cypher_goal', type=float, default=0.2,
                         help="Minimum level of cyphering, if possible. Only "
                              "relevant with --exhaustive! Note typical good "
                              "cypher level is 0.3 (nbr of syllables added/"
                              "nbr of chars, for each word), defaults to 0.2.")
    cparser.add_argument('-l', '--largonji', action="store_true",
                         help="Use Largonji des Loucherbems cyphering.")
    cparser.add_argument('--vowel_syllables', nargs='*',
                         default = LARGONJI_SYLLABLES_V,
                         help="Largonji: syllables to add after a vowel, at "
                              "the end of words (defaults to '{}')."
                              "".format("', '".join(LARGONJI_SYLLABLES_V)))
    cparser.add_argument('--consonant_syllables', nargs='*',
                         default = LARGONJI_SYLLABLES_C,
                         help="Largonji: syllables to add after a consonant, "
                              "at the end of words (defaults to '{}')."
                              "".format("', '".join(LARGONJI_SYLLABLES_C)))

    dparser = sparsers.add_parser('decypher', help="Decypher text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-s', '--syllable',
                         help="Obfuscating syllable to remove from text (if "
                              "none given, the most common one compatible "
                              "with choosen method will be used).")
    dparser.add_argument('-j', '--javanais', action="store_true",
                         help="Restrict allowed obfuscating syllables to ja, "
                              "av and va (and their case variants).")
    dparser.add_argument('-f', '--feu', action="store_true",
                         help="Restrict allowed obfuscating syllables to a f "
                              "and a vowel (and their case variants).")
    dparser.add_argument('-l', '--largonji', action="store_true",
                         help="Use Largonji des Loucherbems decyphering.")
    dparser.add_argument('--vowel_syllables', nargs='*',
                         default = LARGONJI_SYLLABLES_V,
                         help="Largonji: syllables to search for vowels, at "
                              "the end of words (defaults to '{}')."
                              "".format("', '".join(LARGONJI_SYLLABLES_V)))
    dparser.add_argument('--consonant_syllables', nargs='*',
                         default = LARGONJI_SYLLABLES_C,
                         help="Largonji: syllables to search for consonants, "
                              "at the end of words (defaults to '{}')."
                              "".format("', '".join(LARGONJI_SYLLABLES_C)))

    sparsers.add_parser('about', help="About Argots…")

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
            if args.largonji:
                out = cypher_largonji(data, args.vowel_syllables,
                                      args.consonant_syllables)
                print("Largonji found {} solutions."
                      "".format(out["n_solutions"]))
                print(out["solutions"])
                text = "\n".join(utils.format_multiwords(out["solutions"],
                                                         sep=" "))
                btext = ""
            else:
                if args.syllable in data:
                    print("WARNING: The chosen obfuscating syllable is "
                          "already present in the text, decyphering will "
                          "likely give wrong results…")
                out = cypher(data, method, args.syllable, args.exhaustive,
                             args.cypher_goal)
                if args.exhaustive:
                    print("Exhaustive found {} solutions for a minimum "
                          "cyphering of {}, among which {} solutions with the "
                          "highest possible cyphering ({}):"
                          "".format(out["n_solutions"], args.cypher_goal,
                                    out["best_n_solutions"],
                                    out["best_cypher"]))
                    text = "\n".join(utils.format_multiwords(out["solutions"],
                                                             sep=" "))
                    b_text = "\n".join(utils.format_multiwords(
                                             out["best_solutions"], sep=" "))
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

            if args.largonji:
                out = decypher_largonji(data, args.vowel_syllables,
                                        args.consonant_syllables)
                text = "\n".join(utils.format_multiwords(out))
            else:
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

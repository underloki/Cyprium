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
from difflib import SequenceMatcher

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/05/31"
__python__ = "3.x"  # Required Python version
__about__ = ""\
'''Cyprium.Vigenere version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Vigenere is a tool that allows you to cypher a text into another one,
using the vigenere-cypher. It also contains 3 variants:
    Autoclave: uses the plain text to make the key so much longer
as the plain text.

    Beaufort: uses classic vigenere but process the key-letter as clear
text and the clear-text letter as key.

    Gronsfeld: uses digits, where the classic vigenere uses letters.
it uses a string of digits as key.

Allowed chars are ascii-letters, digits and ascii-punctuation

Example
    text = "AN HACKADEMY"
    key = "KEY"
    cypher(text, key, ALGO_VIGENERE)
            = "KR FKGIKHCWC"

    cypher(text, key, ALGO_BEAUFORT)
            = "KR RKCOKBUYG"

    cypher(text, key, ALGO_AUTOCLAVE)
            = "KR FAPRAFOMB"

    cyphper(text, "789", ALGO_GRONSFELD)
            = "HV QHKTHLNTG"

    An option "with_spaces" determines if spaces and punctuation should
be store.
    cypher(text, key, ALGO_VIGENERE, with_spaces=False)
        = "KRFKGIKHCWC"

decypher methods haven the same parameters.
Current execution context:
Operating System: {}
Python version: {}
'''.format(__version__, __date__, utils.__pf__, utils.__pytver__)

# Algorithms
ALGO_VIGENERE = 1
ALGO_AUTOCLAVE = 2
ALGO_GRONSFELD = 3
ALGO_BEAUFORT = 4

# Maps
WHITESMAP = set(string.punctuation + string.digits)

def clean(text, map=None, spaces=False):
    '''clean a text, using the charmap <map> and return:
        the cleaned text, if spaces==False
        the cleaned text and the spaces, if spaces==True'''
    if not map:
        map = utils.WE2UASCII_CHARMAP
    max = len(text)
    index = 0
    cleaned = []
    whites = []
    new_spaces = 0
    while index < max:
        c = text[index]
        repr_c = c
        if c.isalpha():
            if c in map:
                repr_c = map[c]
                if len(repr_c)>1:
                    new_spaces += 1
            cleaned.extend(repr_c)
        else:
            whites.append((text[index], new_spaces+index))
        index +=1
    if spaces:
        return cleaned, whites
    else:
        return cleaned


def pack(text, whites):
    '''pack <text> with <whites> and return a list'''
    for i in whites:
        text.insert(i[1], i[0])
    return text


def _char_shift(c, k, negativ=False, base=ord('A'), modulo=26):
    '''shift the char c, with the position in alphabet26 of char k,
    negativ : shift in negativ side or not
    base : base of char, 65==> upper, 97==>lower
    modulo : the number of letters'''
    if negativ:
        return chr(((ord(c) - base * 2 - ord(k)) % modulo) + base)
    else:
        return chr(((ord(c) - base * 2 + ord(k)) % modulo) + base)


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
                        last += 1
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


def cypher(text, key, algo, with_spaces=True):
    '''Just a wrapper around do_cypher_xxx, whit some checks.'''
    if not text:
        raise ValueError("No text given!")
    text, spaces = clean(text, spaces=True)
    c_text = set(text)
    c_allowed = set(WHITESMAP)
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
    if with_spaces:
        return "".join(pack(list(res_gen), spaces))
    else:
        return "".join(c for c in res_gen if c != " ")


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


def decypher(text, key, algo, with_spaces=True):
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
    text, spaces = clean(text, spaces=True)
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
    if with_spaces:
        return "".join(pack(list(res_gen), spaces))
    else:
        return "".join(c for c in res_gen if c != " ")


############ Hack Section ###############
def _count(key, most, lang, limit=5, map=None):
    if not map:
        map = reverse_v_square
    lst = []
    for c in most[:limit]:
        lst.append(map[key][c])
    return get_ratio(lst, STATS[lang][:limit])


def _compare(key, most, lang, limit=5, map=None):
    if not map:
        map = reverse_v_square
    lst = []
    for c in most[:limit]:
        lst.append(map[key][c])
    return SequenceMatcher(None, lst, STATS[lang][:limit]).ratio()


def get_ratio(lst1, lst2):
    '''return the containing ratio of lst1 in lst2'''
    count = 1.0
    for i in lst1:
        if i in lst2:
            count += 1
    return count/len(lst1)


def get_IC(text):
    '''determines the IC of the given text'''
    occurences = [0]*26
    for i in range(26):
        occurences[i] += text.count(chr(65 + i))
        occurences[i] += text.count(chr(97 + i))
    total = float(sum(occurences))
    return sum((n*(n-1))/(total*(total-1)) for n in occurences if n>1)

def find_key_length(text, size=6, nb_values=None, recursiv=False):
    '''finds the key-length of a vigenere's like cyphered text'''
    MAX = 2000
    MIN = 500
    NB_ELEMENTS = 5
    if len(text)<MIN:
        size = 2
    dic = {}
    index = 0
    alpha_index = 0
    limit = len(text)
    if limit>MAX:
        limit = MAX
    while ((index + size) < limit):
        item = text[index: index+size]
        if item in dic:
            dic[item].append(index)
        else:
            dic[item] = [alpha_index]
        alpha_index += 1
        index += 1
    res = [i for i in dic.values() if len(i)>1]
    nRes = []
    for lst in res:
        cLst = []
        for i in range(len(lst) - 1):
            nRes.extend(set(_factorize(lst[i+1] - lst[i])))
    ens = set(nRes)
    dic = {}
    res = [];
    for i in ens:
        dic[i] = nRes.count(i)
        res.append((nRes.count(i), i))
    res.sort()
    res.reverse()
    if res:
        if size<4:
            return int(max(i[1] for i in res[:NB_ELEMENTS]))
        else:
            return int(res[0][1])
    else:
        if not recursiv:
            return find_key_length(text, size-1, nb_values, True)
        else:
            return 5

def _factorize(n):
    dividends = [n]
    for i in range(2, int(n**0.5) + 1):
        if (n%i == 0):
            dividends.append(i)
            dividends.append(n/i)
    return dividends

LANGUAGES = {
            "fr": "French",
            "en": "English",
            "de": "Deutsch",
            "es": "Spanish",
            "fi": "Finnish",
            "it": "Italian",
            "nl": "Dutch",
            "pe": "Spanish-Peru"
            }
ICS = {
    "fr": 0.0778,
    "es": 0.0770,
    "de": 0.0762,
    "en": 0.0667,
    "fi": 0.0737,
    "nl": 0.0798,
    "it": 0.0738,
    "pe": 0.0745}

STATS = {
        "fr": ["E", "A", "S", "T", "I", "R", "N", "U", "L", "O",
         "D", "M", "C", "P", "V", "H", "G", "F", "B", "Q", "J",
          "X", "Z", "Y", "K", "W"],
        "en": ["E", "T", "A", "O", "I", "N", "S", "H", "R", "L",
         "D", "U", "C", "M", "W", "Y", "F", "G", "P", "B", "V",
          "K", "J", "X", "Q", "Z"],
        "de": ["E", "N", "I", "S", "R", "A", "T", "D", "H", "U",
         "L", "C", "G", "M", "O", "B", "W", "F", "K", "Z", "V",
          "P", "J", "Y", "X", "A"],
        "es": ["E", "A", "O", "S", "N", "R", "I", "L", "D", "U",
         "T", "C", "M", "P", "B", "H", "Q", "Y", "V", "G", "F",
          "J", "Z", "X", "K", "W"],
        "pe": ["E", "A", "O", "S", "R", "I", "T", "M", "N", "U",
         "D", "C", "P", "L", "V", "H", "A", "G", "F", "B", "Z",
          "J", "X", "K", "W", "Y"],
        "fi": ["A", "I", "T", "N", "E", "S", "L", "O", "K", "U",
         "M", "H", "V", "R", "J", "P", "Y", "D", "G", "C", "B",
          "F", "W", "Z", "X", "A"],
        "ca": ["E", "A", "S", "R", "L", "T", "I", "N", "O", "U",
         "M", "D", "C", "P", "V", "B", "Q", "G", "F", "H", "X",
          "J", "Y", "K", "Z", "W"],
        "cs": ["E", "O", "A", "N", "T", "L", "S", "I", "V", "D",
         "K", "R", "M", "P", "U", "Y", "H", "J", "C", "B", "Z",
          "G", "F", "X", "W", "Q"],
        "af": ["E", "I", "N", "A", "S", "R", "O", "D", "T", "L",
         "G", "K", "V", "U", "M", "W", "H", "B", "P", "Y", "F",
          "J", "C", "Z", "X", "Q"],
        "da": ["E", "R", "N", "T", "D", "A", "I", "S", "L", "G",
         "O", "M", "K", "V", "H", "F", "U", "B", "P", "J", "Y",
          "C", "W", "X", "Z", "Q"],
        "pe": ["E", "A", "O", "S", "R", "I", "T", "M", "N", "U",
         "D", "C", "P", "L", "V", "H", "Q", "G", "F", "B", "Z",
          "J", "X", "K", "W", "Y"],
        "nl": ["E", "N", "A", "T", "I", "O", "R", "D", "S", "L",
         "H", "G", "K", "M", "V", "U", "J", "W", "Z", "P", "B",
          "C", "F", "Y", "X", "Q"],
        "it": ["E", "A", "I", "O", "N", "T", "R", "L", "S", "C",
         "D", "U", "P", "M", "V", "G", "H", "B", "F", "Z", "Q"]}


def _get_reverse_v_square():
    '''returns a vigenere's square, where item[c][i] represents the
    key-char that have been used to cypher c and have i'''
    lst = list(string.ascii_uppercase)
    map = {}
    for c in lst:
        tmp = {}
        for i in lst:
            tmp[_char_shift(c, i)] = i
        map[c] = tmp
    return map

reverse_v_square = _get_reverse_v_square()

def _get_reverse_g_square():
    lst = list(string.ascii_uppercase)
    map = {}
    for c in lst:
        tmp = {}
        for i in lst:
            tmp[_char_shift(c, i)] = i
        map[c] = tmp
    return map

reverse_g_square = _get_reverse_v_square()

def _get_reverse_b_square():
    '''returns a vigenere's square, where item[c][i] represents the
    key-char that have been used to cypher c and have i.
    Using the beaufort's cypher'''
    lst = list(string.ascii_uppercase)
    map = {}
    for c in lst:
        tmp = {}
        for i in lst:
           tmp[_char_shift(i, c, True)] = i
        map[c] = tmp
    return map

reverse_b_square = _get_reverse_b_square()

def order(lst, limit=5):
    '''returns in order the <limit> most appearing chars'''
    ords = []
    for i in string.ascii_uppercase:
        ords.append((lst.count(i), i))
    ords.sort()
    ords.reverse()
    return [item[1] for item in ords][:limit]

def find_language(text):
    '''determines the language of text using its IC'''
    ic = get_IC(text)
    res = []
    for i, k in ICS.items():
        res.append((abs(ic-k), i))
    res.sort()
    return res[0][1]


def _find_k(most_chars, language, limit=5, map=None,
                                probas=((3, 0), (2, 1), (2, 2))):
    if not map:
        map = reverse_v_square
    lst = []
    for item in probas:
        for i in range(item[0]):
            lst.append( map[STATS[language][item[1]]][most_chars[i]])
    res = []
    for c in lst:
        res.append((_count(c, most_chars, language, limit, map), c))
    res = _get_mosts(res)
    return res

def _get_mosts(lst):
    lst.sort()
    lst.reverse()
    res = []
    for val, item in lst:
        if val==lst[0][0]:
            res.append(item)
    return res

def _process_hack_vigenere(text, algo, key_length, language,
                                        limit=10, ratio=0.75):
    '''return a possibly key for the given text,
    the key's length == key_length'''
    groups = list(utils.grouper2(text, key_length))
    if algo==ALGO_BEAUFORT:
        map = reverse_b_square
        _process = _process_beaufort
    elif algo==ALGO_GRONSFELD:
        map = reverse_g_square
        _process = _process_vigenere
    else:
        map = reverse_v_square
        _process = _process_vigenere
    keys = []
    result = []
    tmp_limit = limit
    for i in range(key_length):
        limit = tmp_limit
        char = []
        ls =  []
        for item in groups:
            if len(item)>i:
                ls.append(item[i])
        most_chars = order(ls, limit=26)
        vars = []
        #this tuple represents the probabilities:
        #use two times the first char, 1 time the second...
        probas = ((6, 0), (1, 1))
        for item in probas:
            for i in range(item[0]):
                vars.append( map[STATS[language][item[1]]][most_chars[i]])
        lst = []
        for k in vars:
            if (("J">= k and algo==ALGO_GRONSFELD) or algo!=ALGO_GRONSFELD):
                cur = "".join(_process(STATS[language][:limit], k))
                if get_ratio(cur, most_chars[:limit]) >= ratio:
                    if k not in char:
                        char.append(k)
        if not char:
            lst_keys = []
            limit = 10
            lst = _find_k(most_chars, language, limit, map)
            lst_keys.extend(lst)

            limit = 20
            lst = []
            for c in vars:
                lst.append((_count(c, most_chars, language, limit, map), c))
            lst = _get_mosts(lst)
            lst_keys.extend(lst)
            lst = []
            for c in set(lst_keys):
                lst.append((lst_keys.count(c), c))
            lst = _get_mosts(lst)
            char.append(lst[0])
        keys.append(vars)
        result.append(char)
    return result


def _clear(text):
    '''return a upper-case text, just containing ascii letters'''
    return "".join((c.upper() for c in text if c in string.ascii_letters))


def hack(text, algo, key_length=None, language=None):
    c_text = set(text)
    c_allowed = set(WHITESMAP)
    c_allowed.update(string.ascii_uppercase)
    if not (c_text <= c_allowed):
        raise ValueError("Text contains unallowed chars (only uppercase "
                        "chars, digits and poctuation): '{}'!"
                        "".format("', '".join(sorted(c_text - c_allowed))))
    if algo==ALGO_VIGENERE:
        if not key_length:
            key_length = find_key_length(text)
        if not language:
            language = find_language(text)
        return "".join(i[0] for i in _process_hack_vigenere(_clear(text),
                        algo, key_length, language))
    elif algo==ALGO_BEAUFORT:
        if not key_length:
            key_length = find_key_length(text)
        if not language:
            language = find_language(text)
        return "".join(i[0] for i in _process_hack_vigenere(_clear(text),
                        algo, key_length, language))
    elif algo==ALGO_GRONSFELD:
        if not key_length:
            key_length = find_key_length(text)
        if not language:
            language = find_language(text)
        alpha_key = "".join(i[0] for i in _process_hack_vigenere(_clear(text),
                        algo, key_length, language))
        return "".join(str((ord(c)-65)%10) for c in alpha_key)






#################### main ###############
def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    # Helper func.
    _algos = {'vigenere': ALGO_VIGENERE, 'v': ALGO_VIGENERE,
              'autoclave': ALGO_AUTOCLAVE, 'a': ALGO_AUTOCLAVE,
              'gronsfeld': ALGO_GRONSFELD, 'g': ALGO_GRONSFELD,
              'beaufort': ALGO_BEAUFORT, 'b': ALGO_BEAUFORT,
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

    sparsers.add_parser('about', help="About Vigenere")

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

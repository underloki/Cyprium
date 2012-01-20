########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   www.thehackademy.fr                                                #
#   Copyright Â© 2012                                                   #
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
import itertools
import time


###############################################################################
# Flags.
###############################################################################
DEBUG = True


###############################################################################
# Misc platform abstraction code.
###############################################################################
__pf__ = sys.platform
if __pf__ == "win32":
    if sys.getwindowsversion().platform == 2:
        winpf = " (NT/2000/XP/Vista/7)"
    else:
        winpf = ""
    __pf__ = "Windows" + winpf
elif __pf__ == "cygwin":
    __pf__ = "Windows/Cygwin"
elif __pf__ == "linux2":
    __pf__ = "Linux"
elif __pf__ == "os2":
    __pf__ = "OS/2"
elif __pf__ == "os2emx":
    __pf__ = "OS/2 EMX"
elif __pf__ == "darwin":
    __pf__ = "Mac OS X"
else:
    __pf__ = "?"

major, minor, micro, _, _ = sys.version_info
__pytver__ = "{}.{}.{}".format(major, minor, micro)


###############################################################################
# Misc utils.
###############################################################################
def revert_dict(d, exceptions={}):
    """
    Revert a mapping (dict).
    If several keys have the same values, use the optional exceptions dict
    to give the result you want for those values-as-key.
    """
    return {v: exceptions.get(v, k) for k, v in d.items()}


# XXX this does not work nice!
def msgerr():
    """Returns a clear error message: error name + error message."""
    return " ".join((sys.exc_info()[0].__name__, str(sys.exc_info()[1])))


def num_to_base(num, base, min_digits=1):
    """
    Returns a string with the integer num encoded in base.
    base is a list or tuple containing all "digits" (the first being '0' one).
    If the encoded number is shorter than min_digits, base[0] is used as left
    fill value.
    """
    b = len(base)
    out = []
    # Standard â€œdecimal to base nâ€ algo...
    # Note that that algo generates digits in "reversed" order...
    while num != 0:
        r = num % b
        num //= b
        out.append(str(base[r]))
    if len(out) < min_digits:
        out += [str(base[0])] * (min_digits - len(out))
    return "".join(reversed(out))


###############################################################################
# Iterators/sets operations.
###############################################################################
def grouper(iterable, n, fillvalue=None):
    """
    Return an iterator of n-length chunks of iterable.

    >>> grouper('ABCDEFG', 3, 'x')
    ABC DEF Gxx
    """
    args = [iter(iterable)] * n
    return itertools.zip_longest(fillvalue=fillvalue, *args)


def grouper2(lst, n, gap=0):
    """
    Return an iterator of n-length chunks of iterable.

    >>> grouper('ABCDEFG', 3, 1)
    ABC EFG

    Compared to grouper, it has no fillvalue (thus returning a truncated
    last element), and lst must be subscriptable (i.e. not an iterator).
    But you can get groups of n elements separated (spaced) by gap elements.
    Also, it is quicker than grouper, except for small n (tipically <10).
    """
    return (lst[i:i + n] for i in range(0, len(lst), n + gap))


def nwise(iterable, n=1):
    """s, n=2 -> (s0,s1), (s1,s2), (s2, s3), ..."""
    its = itertools.tee(iterable, n)
    for i, it in enumerate(its):
        for j in range(i):
            next(it, None)
    return zip(*its)


def cut_iter(iterable, *cuts):
    """
    Returns an iterator of iterable parts of
    len1=cuts[1], len2=cuts[2], etc.
    iterable must be subscriptable.
    """
    curr = 0
    for c in cuts:
        next = curr + c
        yield iterable[curr:next]
        curr = next


def _rec_all_groups_in_order(iterable, lengths=(1,2)):
    """lengths is assumed sorted!"""
    # This will recursively cut iterable in all possible sets of chunks which
    # lengths are in the given values.
    # Might yield nothing, when no arrangements are possible!
    ln = len(iterable)
    for l in lengths:
        if l > ln:
            return
        base = [iterable[:l]]
        if l == ln:
            yield base
            return
        for els in _rec_all_groups_in_order(iterable[l:], lengths):
            # Void els, continue.
            if not els:
                continue
            # One element, and length does not match.
            if len(els) == 1 and len(els[0]) + l != ln:
                continue
            yield base + list(els)


def all_groups_in_order(iterable, lengths=(1,2)):
    """
    abc, (1,2,3) -> a,b,c   ab,c   a,bc   abc
    abcd, (2, 3) -> ab,cd
    Note that, depending on the lengths given, it might yield nothing!
    """
    # Just be sure lengths are sorted and iterable is subscriptable!
    lengths = tuple(sorted(lengths))
    iterable = tuple(iterable)
    return _rec_all_groups_in_order(iterable, lengths)


def case_variants(txt):
    """
    Yield all case variants of given text.
    "all" --> all, All, aLl, alL, ALl, AlL, aLL, ALL
    """
    TXT = txt.swapcase()
    # Nice comprehension! :p
    return ("".join(v) for v in
                       itertools.product(*(tuple(set(c)) for c in
                                                         zip(txt, TXT))))


###############################################################################
# Formating.
###############################################################################
def format_multiwords(words, sep=' '):
    """
    Format words as multi-lines text output.
    Returns a list of lines.
    (this) (is,was,will be) (a) (test) â†’
           is
    this   was   a test
         will be
    """
    # Check we have no void list of words...
    t_words = words
    for i, w in enumerate(t_words):
        if not w:
            if not isinstance(words, list):
                words = list(words)
            words[i] = ('-@$!$@-',)
    # Higher number of possibilities for a single word.
    if len(words) > 1:
        max_nr = len(max(*words, key=len))
    else:
        max_nr = len(max(words, key=len))
    if max_nr == 1:
        return [sep.join((w[0] for w in words))]
    # Get start/end line number for each word in words.
    els_nr = []
    for e in words:
        diff_e = max_nr - len(e)
        min_e = diff_e // 2
        max_e = max_nr - (diff_e - min_e) - 1
        els_nr.append((min_e, max_e))
    # Format line.
    fmt_line = sep.join(["{{: ^{}}}".format(len(max(els, key=len)))
                         for els in words])

    ret = []
    for i in range(max_nr):
        els = []
        for idx, e in enumerate(words):
            if els_nr[idx][0] <= i <= els_nr[idx][1]:
                els.append(e[i - els_nr[idx][0]])
            else:
                els.append('')
        ret.append(fmt_line.format(*els))
    return ret


###############################################################################
# Prime numbers.
###############################################################################
def all_primes(n):
    """Yield all prime numbers from 0 to n."""
    n = int(n)
    if n < 2:
        return
    # NOTE: This is Sieve of Eratosthenes, but only on odd numbers.
    #       It’s a bit more complex to grasp, but takes half of memory,
    #       and tends to be somewhat quicker when reaching high numbers
    #       (1000000 and over).

    # Create a list for all odd numbers.
    # Note: theorically, 1 is not prime, but as we never test it...
    lst = [True] * (n // 2)
    yield 2  # 2 is a prime number.
    # Use **0.5 instead of Math.sqrt().
    root = int(n ** 0.5) // 2
    root = root + [1,0][root % 2]  # Get an odd root.
    for i in range(1, root + 1):
        if lst[i]:
            y = i * 2 + 1
            # Get rid of all odd multiples of i.
            lst[i::y] = [False] * (((n // y) + 1) // 2)
            yield y
    for i in range(root, n // 2):
        if lst[i]:
            yield i * 2 + 1


_primes_under_100 = {all_primes(100)}


def is_prime(n):
    """Return True if a number is prime and False otherwise."""
    if n <= 100:
        return n in _primes_under_100
    if n % 2 == 0 or n % 3 == 0:
        return False

    for f in range(5, int(n ** 0.5), 6):
        if n % f == 0 or n % (f + 2) == 0:
            return False
    return True


def prime_range(end, start=2):
    """
    Yield prime numbers from start to end.
    Note: Only better that all_primes when start is very high, and
          end - start is relatively low.
    """
    if end < 2 or end < start:
        return
    if end == 2:
        yield 2
    if start < 3:
        for p in all_primes(end):
            yield p

    start = start + [1,0][start % 2]  # Get an odd start.
    for i in range(start, end + 1, 2):
        if is_prime(i):
            yield i

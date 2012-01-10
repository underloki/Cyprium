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
import itertools
import time

__pf__ = sys.platform
if __pf__ == 'win32':
    if sys.getwindowsversion().platform == 2:
        winpf = ' (NT/2000/XP/x64)'
    else:
        winpf = ''
    __pf__ = 'Windows' + winpf
elif __pf__ == 'cygwin':
    __pf__ = 'Windows/Cygwin'
elif __pf__ == 'linux2':
    __pf__ = 'Linux'
elif __pf__ == 'os2':
    __pf__ = 'OS/2'
elif __pf__ == 'os2emx':
    __pf__ = 'OS/2 EMX'
elif __pf__ == 'darwin':
    __pf__ = 'Mac OS X'
else:
    __pf__ = '?'

major, minor, micro, _, _ = sys.version_info
__pytver__ = '{}.{}.{}'.format(major, minor, micro)


def grouper(iterable, n, fillvalue=None):
    """Return an iterator of n-length chunks of iterable.
       grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    """
    args = [iter(iterable)] * n
    return itertools.zip_longest(fillvalue=fillvalue, *args)


def nwise(iterable, n=1):
    "s, n=2 -> (s0,s1), (s1,s2), (s2, s3), ..."
    its = itertools.tee(iterable, n)
    for i, it in enumerate(its):
        for j in range(i):
            next(it, None)
    return zip(*its)


def cut_iter(iterable, *cuts):
    """Returns an iterator of iterable parts of
       len1=cuts[1], len2=cuts[2], etc.
       iterable must be subscriptable.
    """
    curr = 0
    for c in cuts:
        next = curr + c
        yield iterable[curr:next]
        curr = next


def all_groups_in_order(iterable, min_n=1, max_n=1):
    """abc, 3 -> a,b,c   ab,c   a,bc   abc"""
    ln = len(iterable)
    min_blocks = ln // max_n
    max_blocks = ln // min_n
    for r in range(min_blocks, max_blocks + 1):
        cur_max_n = min(max_n + 1, ln - r + 2)
        for c in itertools.product(range(min_n, cur_max_n), repeat=r):
            if sum(c) != ln:
                continue
            yield cut_iter(tuple(iterable), *c)


def format_multiwords(words, sep=' '):
    """Format words as multi-lines text output.
       Returns a list of lines.
       (this) (is,was,will be) (a) (test) →
              is          
       this   was   a test
            will be       
    """
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

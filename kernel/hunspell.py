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
import string
import re


class Hunspell(object):
    """
    This class implements a subset of the hunspell format, to generate
    simple lists of words.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.flag_mode = "ASCII"
        self.af_map = {}
        self.af_classes = {}
        self.base_words = []

    def load_dic(self, dic_path, aff_path=None):
        self.reset()
        if aff_path is None:
            aff_path = dic_path[:-3] + "aff"
        with open(aff_path) as lines:
            self.parse_aff(lines)
        with open(dic_path) as lines:
            self.parse_dic(lines)

    def parse_aff(self, lines):
        """
        Parse an .aff hunspell file, handling only a subset of features.
        """

        af = 0
        curr = ""

        def _if_preprocess(regex, is_sfx):
            """
            Parse the pseudo-regex syntax of hunspell conditions, generating
            a valid regex one.
            """
            if regex == '.':
                return None  # No condition!
            ret = [regex]
            if '-' in regex and '[' in regex:
                # Just make sure '-' is first char if in [] sets...
                temp = regex.split('[')
                reg = re.compile(r"(\^?)(.*?)(-)(.*?\].*)")
                ret = [temp[0]]
                for t in temp[1:]:
                    m = reg.match(t)
                    if m:
                        grps = m.goups()
                        ret.append("".join((m[0], m[2], m[1], m[3])))
                    else:
                        ret.append(t)
            if is_sfx:
                return re.compile(".*?" + "[".join(ret))
            else:
                return re.compile("[".join(ret) + ".*")

        for l in lines:
            l = l.split()
            if not l:
                continue
            if l[0] == "FLAG":
                self.flag_mode = l[1]
            elif l[0] == "AF":
                if af:
                    self.af_map[str(af)] = l[1]
                af += 1
            elif l[0] in {"PFX", "SFX"}:
                if l[1] != curr:
                    # Add a new prefix/suffix class.
                    curr = l[1]
                    if l[0] == "SFX":
                        self.af_classes[curr] = {"sfx": True}
                    else:
                        self.af_classes[curr] = {"sfx": False}
                    if l[2] == "Y":
                        self.af_classes[curr]["crossp"] = True
                    else:
                        self.af_classes[curr]["crossp"] = False
                    self.af_classes[curr]["rules"] = []
                else:
                    # Parse/add a new rule to current class.
                    # XXX We do not handle "recursive" affixes here!
                    if l[2] == "0":
                        l[2] = ""
                    if l[3] == "0":
                        l[3] = ""
                    elif '\\' in l[3]:
                        l[3] = l[3].replace(r"\\", "##")
                        l[3] = l[3].replace('\\', '')
                        l[3] = l[3].replace("##", '\\')
                    r = {"strip": l[2], "add": (l[3], []),
                         "if": _if_preprocess(l[4],
                                              self.af_classes[curr]["sfx"])}
                    self.af_classes[curr]["rules"].append(r)

    def parse_dic(self, lines):
        """
        Parse a .dic hunspell file.
        """
        def _classes_split(fmode, clss):
            if fmode in {"ASCII", "UTF-8"}:
                return clss
            elif fmode == "long":
                ln = len(clss)
                # XXX This will cut last char in case of odd number...
                #     But this is not supposed to happen!
                return (clss[i:i+2] for i in range(0, ln, 2))
            elif fmode == "num":
                return clss.split(',')

        def _classes_preprocess(af, clss):
            """
            Generate all possible combinaisons for a given set of classes.
            """
            spfx = []
            cpfx = [None]
            ssfx = []
            csfx = [None]
            for c in clss:
                if c not in af:
                    continue
                afc = af[c]
                if afc["sfx"]:
                    if afc["crossp"]:
                        csfx.append(c)
                    else:
                        ssfx.append((c, None))
                else:
                    if afc["crossp"]:
                        cpfx.append(c)
                    else:
                        spfx.append((c, None))
            ret = list(itertools.product(cpfx, csfx))
            ret.remove((None, None))
            ret += spfx + ssfx
            return ret

        first_l = True
        for l in lines:
            l = l.rstrip("\n\r")
            if first_l:
                first_l = False
                if set(l) < set("0123456789"):
                    continue
            if not l or l.startswith('\t'):
                continue
            # XXX This is not conform to specs... But seems to work with
            #     most dics for now!
            l = l.split('/')
            l[0] = l[0].split()[0]
            classes = []
            if len(l) > 1:
                l[1] = l[1].split()[0]
                l[1] = self.af_map.get(l[1], l[1])
                l[1] = _classes_split(self.flag_mode, l[1])
                classes = _classes_preprocess(self.af_classes, l[1])
            self.base_words.append((l[0], classes))

    def gen_words(self, minlen=0, maxlen=0):
        """
        Yield words, generated from content of self.base_words and
        self.af_classes.
        if minlen or maxlen are not > 0, they limit minimal/maximal
        length of generated words.
        """
        for w, af in self.base_words:
            yield w
            # XXX Avoid to yield several times the same word...
            #     Only per-baseword guard, though.
            words = {w}
            pfx = []
            sfx = []
            comb = []
            for c1, c2 in af:
                for _w in self.apply_class(w, c1, c2):
                    if _w not in words:
                        yield _w
                        words.add(_w)

    def apply_class(self, word, c, *clss):
        if clss:
            for _w in self.apply_class(word, *clss):
                yield _w
        if c not in self.af_classes:
            return
        c = self.af_classes[c]
        for r in c["rules"]:
            if r["if"] and not r["if"].match(word):
                continue
            add = r["add"][0]
            if c["sfx"]:
                if r["strip"]:
                    _w = word[:-len(r["strip"])] + add
                else:
                    _w = word + add
                yield _w
            else:
                if r["strip"]:
                    _w = add + word[len(r["strip"]):]
                else:
                    _w = add + word
                yield _w
            # Recursive process of other classes.
            if clss:
                for _w in self.apply_class(_w, *clss):
                    yield _w


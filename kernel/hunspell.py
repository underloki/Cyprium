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
import re


ZIP_DICS = os.path.join(os.path.dirname(__file__), "dics.zip")
MAXLEN = 10000  # XXX We assume no generated word can be longer than that!


class Hunspell(object):
    """
    This class implements a subset of the hunspell format, to generate
    simple lists of words.
    """

    def __init__(self):
        self.reset()

    def reset(self, idname=None):
        if idname:
            self.dics[idname] = {"flag_mode": "ASCII",
                                 "af_map": {},
                                 "af_classes": {},
                                 "base_words": []}
        else:
            self.dics = {}

    def load_dic_file(self, dic_path, aff_path=None, idname=None):
        """
        Load the given dic file.
        If aff_path is None, it will be (dic_path[:-4].aff).
        idname is the identifier of the dic, dic_path if None.
        """
        if aff_path is None:
            aff_path = dic_path[:-3] + "aff"
        if idname == None:
            idname = dic_path
        self.reset(idname)
        with open(aff_path) as lines:
            self.parse_aff(self.dics[idname], lines)
        with open(dic_path) as lines:
            self.parse_dic(self.dics[idname], lines)

    def load_dic_zip(self, zip_path, names=[]):
        """
        Load some dics from a zip archive.
        names is an iterable of dic names (withour .dic/.aff extensions), if
        empty all dics from archive will be loaded.
        """
        def bytes2str(lines):
            for l in lines:
                # XXX For now, we assume encoding is utf-8!
                yield l.decode("utf-8")

        import zipfile
        with zipfile.ZipFile(zip_path) as zip_arch:
            files = set(zip_arch.namelist())
            if not names:
                names = (f[:-4] for f in files if f.endswith(".dic"))
            names = ((n, n + ".dic", n + ".aff") for n in names
                     if {n + ".dic", n + ".aff"} <= files)
            for idname, dic, aff in names:
                self.reset(idname)
                lines = zip_arch.open(aff)
                self.parse_aff(self.dics[idname], bytes2str(lines))
                lines = zip_arch.open(dic)
                self.parse_dic(self.dics[idname], bytes2str(lines))

    def parse_aff(self, dic, lines):
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

        af_map = dic["af_map"]
        af_classes = dic["af_classes"]
        for l in lines:
            l = l.split()
            if not l:
                continue
            if l[0] == "FLAG":
                dic["flag_mode"] = l[1]
            elif l[0] == "AF":
                if af:
                    af_map[str(af)] = l[1]
                af += 1
            elif l[0] in {"PFX", "SFX"}:
                if l[1] != curr:
                    # Add a new prefix/suffix class.
                    curr = l[1]
                    if l[0] == "SFX":
                        af_classes[curr] = {"sfx": True}
                    else:
                        af_classes[curr] = {"sfx": False}
                    if l[2] == "Y":
                        af_classes[curr]["crossp"] = True
                    else:
                        af_classes[curr]["crossp"] = False
                    af_classes[curr]["rules"] = []
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
                         "if": _if_preprocess(l[4], af_classes[curr]["sfx"])}
                    af_classes[curr]["rules"].append(r)

    def parse_dic(self, dic, lines):
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
        flag_mode = dic["flag_mode"]
        af_map = dic["af_map"]
        af_classes = dic["af_classes"]
        base_words = dic["base_words"]
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
                l[1] = af_map.get(l[1], l[1])
                l[1] = _classes_split(flag_mode, l[1])
                classes = _classes_preprocess(af_classes, l[1])
            base_words.append((l[0], classes))

    def gen_words(self, dics=None, minlen=0, maxlen=MAXLEN, unique=False):
        """
        Yield words, generated from content of self.base_words and
        self.af_classes.
        If dics is not None, it must be an iterable of dic names present in
        self.dics.
        minlen and maxlen limit minimal/maximal length of generated words.
        If unique is True, you can be sure it will not yield twice a same word.
        However, this option is heavy on memory (several hundreds of Mo with
        current four dics in dics.zip…)
        """
        words = set()
        if dics == None:
            dics = self.dics
        for k in dics:
            dic = self.dics[k]
            for w, af in dic["base_words"]:
                # XXX Avoid to yield several times the same word...
                #     Only per-baseword guard, though.
                if not unique or w not in words:
                    if minlen < len(w) < maxlen:
                        yield w
                    if unique:
                        words.add(w)
                    else:
                        words = {w}
                pfx = []
                sfx = []
                comb = []
                for c1, c2 in af:
                    for _w in self.apply_class(dic, w, c1, c2):
                        if minlen < len(_w) < maxlen and _w not in words:
                            yield _w
                            words.add(_w)

    def apply_class(self, dic, word, c, *clss):
        if clss:
            for _w in self.apply_class(dic, word, *clss):
                yield _w
        if c not in dic["af_classes"]:
            return
        c = dic["af_classes"][c]
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
                for _w in self.apply_class(dic, _w, *clss):
                    yield _w


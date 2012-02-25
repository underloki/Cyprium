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

import settings
import kernel.cache as cache


ZIP_DICS = settings.HUNSPELL_ZIP_DICS
DO_CACHE = settings.CCH_USE


class Hunspell(object):
    """
    This class implements a subset of the hunspell format, to generate
    simple lists of words.
    """

    # Used to ensure cached data was cached with same version.
    # Change that when modifying parse code!
    _hash_salt = b"1.0.0"

    def __init__(self):
        self.reset()

    def _get_ids(self):
        return self.dics.keys()
    ids = property(_get_ids, doc="ids of dics currently loaded")

    def get_hash(self, uid):
        """
        Returns a copy of aff hash, updated with dic hash value.
        """
        if uid in self.dics:
            hsh = self.dics[uid]["aff_hash"].copy()
            hsh.update(self.dics[uid]["dic_hash"].digest())
            return hsh

    def reset(self, uid=None):
        """
        Reset generating parsed data for a given uid, or for all if None.
        """
        if uid:
            self.dics[uid] = {"flag_mode": "ASCII",
                              "af_map": {},
                              "af_classes": {},
                              "base_words": [],
                              "aff_hash": None,
                              "dic_hash": None}
        else:
            self.dics = {}

    def _load_dic(self, uid, aff, dic):
        """
        Helper func.
        """
        # aff (rules) part.
        if DO_CACHE and self.dics[uid]["aff_hash"] in cache.cache:
            c = cache.cache.get(self.dics[uid]["aff_hash"])
            self.dics[uid]["flag_mode"] = c[0]
            self.dics[uid]["af_map"] = c[1]
            self.dics[uid]["af_classes"] = c[2]
        else:
            self.parse_aff(self.dics[uid], aff)
            if DO_CACHE:
                c = (self.dics[uid]["flag_mode"], self.dics[uid]["af_map"],
                     self.dics[uid]["af_classes"])
                cache.cache.cache(self.dics[uid]["aff_hash"], c)
        # dicc (base words) part.
        if DO_CACHE and self.dics[uid]["dic_hash"] in cache.cache:
            bw = cache.cache.get(self.dics[uid]["dic_hash"])
            self.dics[uid]["base_words"] = bw
        else:
            self.parse_dic(self.dics[uid], dic)
            if DO_CACHE:
                cache.cache.cache(self.dics[uid]["dic_hash"],
                                  self.dics[uid]["base_words"])

    def load_dic_file(self, dic_path, aff_path=None, uid=None):
        """
        Load the given dic file.
        If aff_path is None, it will be (dic_path[:-4].aff).
        idname is the identifier of the dic, dic_path if None.
        """
        if aff_path is None:
            aff_path = dic_path[:-3] + "aff"
        if uid == None:
            uid = dic_path
        with open(aff_path) as aff, open(dic_path) as dic:
            self.reset(uid)
            # First compute hashes.
            self.dics[uid]["aff_hash"] = cache.cache.hashfile(aff_path,
                                                              self._hash_salt)
            self.dics[uid]["dic_hash"] = cache.cache.hashfile(dic_path,
                                                              self._hash_salt)
            # And then, parse data (or load from cache).
            self._load_dic(uid, aff, dic)

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
            for uid, dic_path, aff_path in names:
                self.reset(uid)
                # First compute hashes.
                aff = zip_arch.open(aff_path)
                dic = zip_arch.open(dic_path)
                self.dics[uid]["aff_hash"] = \
                    cache.cache.hashiostream(aff, self._hash_salt)
                self.dics[uid]["dic_hash"] = \
                    cache.cache.hashiostream(dic, self._hash_salt)
                # And then, parse data (or load from cache).
                aff = zip_arch.open(aff_path)
                dic = zip_arch.open(dic_path)
                self._load_dic(uid, bytes2str(aff), bytes2str(dic))

    # -------------------------------------------------------------------------
    # Parsing!

    # First, two helper funcs.
    @staticmethod
    def _classes_split(fmode, clss):
        """
        Splits a string into a list of aff classes, from given fmode flag mode.
        """
        if fmode in {"ASCII", "UTF-8"}:
            return clss
        elif fmode == "long":
            ln = len(clss)
            # XXX This will cut last char in case of odd number...
            #     But this is not supposed to happen!
            return (clss[i:i+2] for i in range(0, ln, 2))
        elif fmode == "num":
            return clss.split(',')

    @staticmethod
    def _classes_preprocess(af, clss):
        """
        Generates all possible combinaisons for a given set of classes.
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

    # And now, real parser funcs.
    def parse_aff(self, dic, lines):
        """
        Parses an .aff hunspell file, handling only a subset of features.
        """

        af = 0
        curr = ""

        def _if_preprocess(regex, is_sfx):
            """
            Parses the pseudo-regex syntax of hunspell conditions, generating
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
        flag_mode = dic["flag_mode"]
        for l in lines:
            l = l.split()
            if not l:
                continue
            if l[0] == "FLAG":
                flag_mode = dic["flag_mode"] = l[1]
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
                    if l[2] == "0":
                        l[2] = ""
                    # XXX This does not handle escaped '/'!
                    l3 = l[3].split('/')
                    l3[0] = l3[0].split()[0]
                    # We have to delay pre-processing of classes here,
                    # as they are not yet all defined!
                    if len(l3) == 1:
                        l3.append("")
                    if l3[0] == "0":
                        l3[0] = ""
                    elif '\\' in l3[0]:
                        l3[0] = l3[0].replace(r"\\", "##")
                        l3[0] = l3[0].replace('\\', '')
                        l3[0] = l3[0].replace("##", '\\')
                    r = {"strip": l[2], "add": [l3[0], l3[1]],
                         "if": _if_preprocess(l[4], af_classes[curr]["sfx"])}
                    af_classes[curr]["rules"].append(r)

        # Now, we can pre-process "recursive" classes calls found in
        # classes' rules.
        for c in af_classes.values():
            for r in c["rules"]:
                clss = r["add"][1]
                clss = af_map.get(clss, clss)
                clss = self._classes_split(flag_mode, clss)
                r["add"][1] = self._classes_preprocess(af_classes, clss)

    def parse_dic(self, dic, lines):
        """
        Parses a .dic hunspell file.
        """
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
            # XXX This does not handle escaped '/'!
            l = l.split('/')
            l[0] = l[0].split()[0]
            classes = []
            if len(l) > 1:
                l[1] = l[1].split()[0]
                l[1] = af_map.get(l[1], l[1])
                l[1] = self._classes_split(flag_mode, l[1])
                classes = self._classes_preprocess(af_classes, l[1])
            # XXX In case we want to support "user dics", we'll have to make
            #     this a key: value (dict) stuff...
            base_words.append((l[0], classes))

    def gen_words(self, dics=None, minlen=None, maxlen=None, unique=False):
        """
        Yields words, generated from content of base_words and af_classes of
        given uid(s).
        If dics is not None, it must be an iterable of dic names (uids) present
        in self.dics.
        Is not None, minlen and maxlen limit minimal/maximal length of
        generated words.
        If unique is True, you can be sure it will not yield twice a same word.
        However, this option is heavy on memory (several hundreds of Mo with
        current four dics in dics.zip…).
        """
        words = set()
        if minlen or maxlen:
            if not minlen:
                minlen = 1
            if not maxlen:
                maxlen = 32767  # XXX Arbitrary high value.
            bypass_len = False
        else:
            bypass_len = True
        if dics == None:
            dics = self.dics
        for k in dics:
            dic = self.dics[k]
            for w, af in dic["base_words"]:
                # XXX Avoid to yield several times the same word...
                #     Only per-baseword guard, unless unique is set.
                if not unique or w not in words:
                    if bypass_len or minlen < len(w) < maxlen:
                        yield w
                    if unique:
                        words.add(w)
                    else:
                        words = {w}
                pfx = []
                sfx = []
                comb = []
                for clss in af:
                    for _w in self.apply_class(dic, w, *clss):
                        if (bypass_len or minlen <= len(_w) < maxlen) and \
                           _w not in words:
                            yield _w
                            words.add(_w)

    def apply_class(self, dic, word, c, *clss):
        """
        Applies class c to word, and then recursively calls itself
        with remaining clss classes, and/or c's own recursive classes.
        Yeah, recursive nightmare!
        """
        if clss:
            for _w in self.apply_class(dic, word, *clss):
                yield _w
        if c not in dic["af_classes"]:
            return
        c = dic["af_classes"][c]
        for r in c["rules"]:
            if r["if"] and not r["if"].match(word):
                continue
            add, rc_clss = r["add"]
            if c["sfx"]:
                if r["strip"]:
                    _w = word[:-len(r["strip"])] + add
                else:
                    _w = word + add
            else:  # Prefix...
                if r["strip"]:
                    _w = add + word[len(r["strip"]):]
                else:
                    _w = add + word
            yield _w
            # Recursive process of other classes.
            if clss:
                for _r_w in self.apply_class(dic, _w, *clss):
                    yield _r_w
            # If this rule recursively uses other rules...
            # XXX Arg...
            if rc_clss:
                for _rc_cls in rc_clss:
                    for _rc_w in self.apply_class(dic, _w, *_rc_cls):
                        yield _rc_w
                        if clss:
                            for _r_w in self.apply_class(dic, _rc_w, *clss):
                                yield _r_w

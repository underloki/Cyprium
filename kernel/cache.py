########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   cyprium.hackademics.fr                                             #                                                  #
#   Authors: SAKAROV, mont29, afranck64                                #
#   Contact: admin@hackademics.fr                                      #
#   Forum: hackademics.fr                                              #
#   Twitter: @hackademics_                                             #
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


import os
import pickle
import hashlib
import functools
import shutil

import settings
import kernel.utils as utils


CCH_DIR = settings.CCH_BASE_DIR
CCH_MAX_SIZE = settings.CCH_MAX_SIZE * 1024 * 1024  # Given in Mo…

HASH_TYPE = settings.CCH_HASH_TYPE
HASH_READ_CHUNK = 65536


class DiskCache(object):
    """
    An helper class to handle on-disk caching of heavy files.
    The key in those functions can be either:
    * a simple string
    * a hash object (from hashlib, having an hexdigest member)
    * or an iterable of such types elements.
    In the later case, DiskCache will create a directory for each item
    but the last one (handy to organize/categorize things…).
    """

    def __init__(self):
        """
        Inits the disk cache object.
        """
        self._cached = set()
        self._size = 0
        if os.path.exists(CCH_DIR):
            if os.path.isdir(CCH_DIR):
                for dpath, dirs, fnames in os.walk(CCH_DIR):
                    root = self.path2key(dpath)
                    self._cached.add(root)
                    self._cached |= {root + (fn,) for fn in fnames}
                    it = (os.path.getsize(os.path.join(dpath, fn))
                          for fn in fnames)
                    self._size += functools.reduce(lambda a, b: a + b, it, 0)
            else:
                print("ERROR: Can’t use disk cache, its dir path is already "
                      "a file ({})!".format(CCH_DIR))
        else:
            os.mkdir(CCH_DIR)
        self.check_size()

    def __iter__(self):
        """
        Iterates over all cached keys (dir [categories] included).
        """
        return iter(self._cached)

    def __contains__(self, key):
        """
        Checks whether that cache object knows a given key.
        In case of giving a partial key (i.e. only some first elements),
        returns true if dir exists.
        """
        return self.norm_key(key) in self._cached

    def __getitem__(self, key):
        """
        Gets a cached object.
        In case of giving a partial key (i.e. only some first elements),
        returns a dict of found elements (WARNING: this can be heavy!).
        """
        key = self.norm_key(key)
        if key not in self._cached:
            raise KeyError()
        path = self.key2path(key)
        if os.path.isdir(path):
            ret = {key: {}}
            for dpath, dirs, fnames in os.walk(path):
                for fn in fnames:
                    p = os.path.join(dpath, fn)
                    k = self.path2key(p, path)
                    if key + k not in self._cached:
                        continue
                    r = ret[key]
                    for _k in k[:-1]:
                        if _k not in r:
                            r[_k] = {}
                        r = r[_k]
                    with open(p, "rb") as f:
                        r[k[-1]] = pickle.load(f)
        else:
            with open(path, "rb") as f:
                return pickle.load(f)

    def __setitem__(self, key, data):
        """
        Stores an object into cache.
        In case of giving a partial key (i.e. only some first elements),
        raises an error.
        """
        key = self.norm_key(key)
        path = self.key2path(key)
        oldsize = 0
        if key in self._cached and os.path.isdir(path):
            raise KeyError()
        elif os.path.isfile(path):
            oldsize = os.path.getsize(path)
        else:
            dirp = os.path.dirname(path)
            if not os.path.exists(dirp):
                os.makedirs(dirp)
        with open(path, "wb") as f:
            pickle.dump(data, f)
        self._cached.add(key)
        key = key[:-1]
        while key not in self._cached:
            self._cached.add(key)
            key = key[:-1]
        self._size += os.path.getsize(path) - oldsize
        self.check_size()

    def __delitem__(self, key):
        """
        Stores an object into cache.
        In case of giving a partial key (i.e. only some first elements),
        deletes the whole tree under given key.
        """
        key = self.norm_key(key)
        if key not in self._cached:
            raise KeyError()
        path = self.key2path(key)
        if os.path.isdir(path):
            for k in (k for k in self._cached if self.issub(k, key)):
                p = self.key2path(k)
                if os.path.isfile(p):
                    self._cached.remove(k)
                    self._size -= os.path.getsize(p)
            shutil.rmtree(path)
        elif os.path.isfile(path):
            self._cached.remove(key)
            self._size -= os.path.getsize(path)
            os.remove(path)

    def check_size(self):
        """
        Checks actual cache size is not over allowed limit, and removes
        oldest-used cached elements if needed.
        """
        if self._size > CCH_MAX_SIZE:
            files = []
            for el in self._cached:
                fn = os.path.join(CCH_DIR, *el)
                if os.path.isfile(fn):
                    stat = os.stat(fn)
                    files.append((el, fn, stat.st_atime, stat.st_size))
            files.sort(key=lambda x: x[2])
            print("WARNING! Cache too big ({} Mo), removing some files…".format(self._size / 1024 / 1024))
            for el, fn, atime, size in files:
                if utils.DEBUG:
                    print("    Removing {} (key: {}).".format(fn, str(el)))
                os.remove(fn)
                self._cached.remove(el)
                self._size -= size
                el = el[:-1]
                while el:
                    path = self.key2path(el)
                    if os.listdir(path):  # Not empty!
                        break
                    if utils.DEBUG:
                        print("    Removing empty {} (key: {}).".format(path, str(el)))
                    os.rmdir(path)
                    self._cached.remove(el)
                    el = el[:-1]
                if self._size <= CCH_MAX_SIZE:
                    break
        if self._size < 0:
            self._size = 0

    @staticmethod
    def norm_key(key):
        """
        Converts all type of keys into a tuple of strings.
        """
        if isinstance(key, str):
            return (key,)
        elif hasattr(key, "hexdigest"):
            return (key.hexdigest(),)
        return tuple(getattr(el, "hexdigest", lambda: el)() for el in key)

    @staticmethod
    def issub(key, root=()):
        """
        Checks (normalized) key is a sub-key of (normalized) root.
        """
        if len(root) > len(key):
            return False
        return key[:len(root)] == root

    @staticmethod
    def key2path(key, root=CCH_DIR):
        """
        Converts a (normalized) key into a file path.
        """
        return os.path.join(root, *key)

    @staticmethod
    def path2key(path, root=CCH_DIR):
        """
        Converts a file path into a (normalized) key.
        """
        path = os.path.normpath(os.path.relpath(path, root))
        key = path.split(os.path.sep)
        if key[0] == '.':
            del key[0]
        return tuple(key)

    @staticmethod
    def hashbytes(b, salt):
        """
        Returns an hashlib’s hash object fed with salt and b bytes.
        """
        h = hashlib.new(HASH_TYPE, salt)
        h.update(b)
        return h

    @staticmethod
    def hashiostream(rs, salt):
        """
        Returns an hashlib’s hash object fed with salt bytes, and the whole
        content of rs binary iostream.
        """
        h = hashlib.new(HASH_TYPE, salt)
        chunk = rs.read(HASH_READ_CHUNK)
        while chunk:
            h.update(chunk)
            chunk = rs.read(HASH_READ_CHUNK)
        return h

    @staticmethod
    def hashfile(path, salt):
        """
        Returns an hashlib’s hash object fed with salt bytes, and the whole
        content of path file (binary-read).
        """
        with open(path, "rb") as f:
            return Hunspell.hashiostream(f, salt)


cache = DiskCache()

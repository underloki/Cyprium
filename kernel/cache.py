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


import os
import pickle
import hashlib

import settings


CCH_DIR = settings.CCH_BASE_DIR

HASH_TYPE = settings.CHC_HASH_TYPE
HASH_READ_CHUNK = 65536


# XXX TODO Doesn't handle at all obsolescence of cached data.
#          Should add at least a delete(uid) function,
#          probably an "invariant id" system,
#          and a "timeout" system too...
class DiskCache(object):
    """
    An helper class to handle on-disk caching of heavy files.
    """

    def __init__(self):
        """
        Inits the disk cache object.
        """
        if os.path.exists(CCH_DIR):
            if os.path.isdir(CCH_DIR):
                self._cached = {p for p in os.listdir(CCH_DIR)
                                  if os.path.isfile(os.path.join(CCH_DIR, p))}
            else:
                print("ERROR: Can’t use disk cache, its dir path is already "
                      "a file ({})!".format(CCH_DIR))
        else:
            os.mkdir(CCH_DIR)
            self._cached = set()

    def __contains__(self, uid):
        """
        Checks whether that cache object knows a given uid.
        uid can be either a string, or a hash object (from hashlib).
        """
        if hasattr(uid, "hexdigest"):
            uid = uid.hexdigest()
        return uid in self._cached

    def get(self, uid):
        """
        Gets a cached object.
        uid can be either a string, or a hash object (from hashlib).
        """
        if hasattr(uid, "hexdigest"):
            uid = uid.hexdigest()
        if uid not in self._cached:
            return None
        path = os.path.join(CCH_DIR, uid)
        with open(path, "rb") as f:
            return pickle.load(f)

    def cache(self, uid, data):
        """
        Stores an object into cache.
        uid can be either a string, or a hash object (from hashlib).
        """
        if hasattr(uid, "hexdigest"):
            uid = uid.hexdigest()
        path = os.path.join(CCH_DIR, uid)
        with open(path, "wb") as f:
            pickle.dump(data, f)
            self._cached.add(uid)

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

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


import string


class UI:
    """Base, "None" UI class (also used as "interface").
       NOTE: All those functions might return None, in addition
             to some expected data...
    """

    # "defines" of messages levels.
    INFO = 10
    WARNING = 20
    ERROR = 30
    FATAL = 40

    # Sub-types of get_data.
    # XX1 sub-types are lists.
    STRING = 0        # Default...
    STR_LIST = 1
    UPPER = 10        # Only upper chars.
    LOWER = 20        # Only lower chars.
    PATH = 30         # Check is format-valid, and autocompletion?
    INT = 100
    INT_LIST = 101
    FLOAT = 110
    FLOAT_LIST = 111

    # What to use as level marker in UI...
    INDENT = "    "

    ###########################################################################
    # Init.
    ###########################################################################
    def __init__(self):
        pass

    ###########################################################################
    # UI itself.
    ###########################################################################
    def message(self, message="", indent=0, level=INFO):
        """
        Print a message to the user, with some formatting given the level
        value.
        """
        pass

    def get_data(self, message="", indent=0, sub_type=STRING,
                 allow_void=False, list_sep=',',
                 completion=None, completion_kwargs={},
                 validate=None, validate_kwargs={}):
        """
        Get some data from the user.
        Will ensure data is valid given sub_type, and call
        If allow_void is True, return None or "" in case user types nothing,
        (else print a menu).
        If sub_type is a list one (xx1 code), use list_sep as item separator.
        completion callback if user hits <tab>.
            completion(data_already_entered=None, **completion_kwargs)
            must return a list of (complete) possible data.
        validate callback to check entry is valid:
            validate(data=None, **validate_kwargs)
            must return a tuple (valid, "valid_msg", "invalid_msg")
        """
        return None

    def get_choice(self, msg="", options=[], indent=0, start_opt="",
                   end_opt="", oneline=False, multichoices=None):
        """
        Give some choices to the user, and get its answer.
        Message is printed once. Then, choices is a list of tuples:
            (returned_key_str_or_obj, label, tip)
            where:
                returned_key_str_or_obj: unique str or hashable object.
                                         void string for separators.
                label: name of the entry, with a '*' before the key letter.
                       You can specify ONE default option by using rather
                       a '$' before the letter.
                       You can specify a multi-chars key by putting another
                       * (or $) after the last letter of that key.
                tip: short help.
            One choice a line.
        start_opt and end_opt are optional string to put before/after the
        option list.
        If the optional oneline is True, all menu choices are concatenated
        on a single line, e.g. "Go back to (M)enu or (T)ry again!".
        If multichoices is not None, user can choose several options (using
        multichoices value as separator).
        """
        # Return the default element, if present.
        for c in options:
            if '$' in c[1]:
                return c[0]
        return None

    ###########################################################################
    # Helper callbacks.
    ###########################################################################

    @staticmethod
    def validate_charset(data, charset=set(string.printable), charmap={}):
        """
        Helper callback used to validate a string input.
        charset contains all allowed chars.
        charmap, if not void, contains a one2one mapping to convert some
        validated chars to others. It is applied *after* checking against
        charset.
        Returns a boolean, the org or processed data, and an optional message.
        """
        if set(data) <= charset:
            if charmap:
                charmap = str.maketrans(charmap)
                data = data.translate(charmap)
            return True, data, ""
        return (False, data, "“{}” contains invalid chars ({})."
                             "".format(data, ", ".join(set(data) - charset)))

    @staticmethod
    def validate_codecs(data):
        """
        Helper callback used to validate a codec (or iterable of codecs) input.
        """
        import codecs
        if isinstance(data, str):
            tdata = (data,)
        else:
            tdata = data
        err = []
        try:
            for dt in tdata:
                codecs.lookup(dt)
            return True, data, ""
        except Exception as e:
            err.append(str(e))
        return (False, data, "“{}” contains invalid encoding(s) ({})."
                             "".format(tdata, ", ".join(err)))

    @staticmethod
    def validate_number_range(data, minnbr, maxnbr):
        """
        Helper callback used to validate a number (or iterable of numbers)
        input.
        minnbr and maxnbr are the lower and upper bounds of allowed values.
        """
        if hasattr(data, "__iter__"):
            invalids = {n for n in data if minnbr > n or n > maxnbr}
            if invalids:
                return (False, data,
                        "“({})” contains values out of range [{}, {}] ({})."
                        "".format(", ".join(str(i) for i in data), minnbr,
                                  maxnbr, ", ".join(str(i) for i in invalids)))
            return True, data, ""
        elif minnbr > n > maxnbr:
            return (False, data, "“{}” is out of range [{}, {}]."
                                 "".format(data, minnbr, maxnbr))
        return True, data, ""

    ###########################################################################
    # Util text/file functions.
    ###########################################################################

    # Misc.
    def text_file_get_path(self, msg, codec, indent=0):
        """Get a text path (with codec)."""
        msg = " ".join((msg, "(if not using the current encoding, “{}”, " \
                             "add the desired one after a “;”, like this: " \
                             "“my/file.txt;latin1”): ".format(codec)))
        path = self.get_data(msg, indent=indent)
        if ';' in path:
            path, codec = path.split(';', 1)
        return path, codec

    # Read/Get.
    def text_file_ropen(self, path=None, codec=None, indent=0):
        """Helper to open a text file in read mode."""
        import locale
        default_codec = locale.getpreferredencoding()
        if not codec:
            codec = default_codec
        if not path:
            path, codec = self.text_file_get_path("Choose an input text file",
                                                  codec, indent=indent)
            if path is None:  # No user interaction, return.
                return

        while 1:
            if not codec:
                codec = default_codec
            try:
                return open(path, 'r', encoding=codec)
            except Exception as e:
                self.message(e)
                options = [("retry", "$try again", ""),
                           ("menu", "or go back to *menu", "")]
                answ = self.get_choice("Could not open that file, please",
                                       options, oneline=True)
                if answ != "retry":
                    return
                path, codec = self.text_file_get_path("Choose an input text "
                                                      "file", codec)

    def text_file_read(self, path=None, codec=None, indent=0):
        """Helper to read the whole content of a text file."""
        ifile = None
        while 1:
            try:
                ifile = self.text_file_ropen(path, codec, indent=indent)
                if ifile is None:
                    return
                return ifile.read()
            except Exception as e:
                self.message(e)
                options = [("retry", "$try again", ""),
                           ("menu", "or go back to *menu", "")]
                answ = self.get_choice("Could not read that file, please",
                                       options, indent=indent, online=True)
                if answ != "retry":
                    return
            finally:
                if ifile:
                    ifile.close()

    def text_input(self, msg, indent=0, sub_type=STRING, allow_void=False,
                   completion=None, completion_kwargs={}, no_file=False,
                   validate=None, validate_kwargs={}):
        """Helper to get some text, either from console or from a file."""
        idt = self.INDENT * indent
        if sub_type == self.STR_LIST:
            prompt = "(Texts, ','-separated): "
        elif sub_type == self.UPPER:
            prompt = "(Text, uppercase): "
        elif sub_type == self.LOWER:
            prompt = "(Text, lowercase): "
        elif sub_type == self.PATH:
            prompt = "(Text, path): "
        elif sub_type == self.INT:
            prompt = "(Integer number): "
        elif sub_type == self.INT_LIST:
            prompt = "(Integer numbers, ','-separated): "
        elif sub_type == self.FLOAT:
            prompt = "(Float number): "
        elif sub_type == self.FLOAT_LIST:
            prompt = "(Float numbers, ','-separated): "
        else:
            prompt = "(Text): "
        while 1:
            if not no_file:
                options = [("console", "directly from $console", ""),
                           ("file", "or reading a *file", "")]
                answ = self.get_choice(msg, options, indent=indent, start_opt="(",
                                       end_opt=")", oneline=True)
            if no_file or answ == "console":
                return self.get_data(" ".join((msg, prompt)), indent=indent,
                                     sub_type=sub_type, allow_void=allow_void,
                                     completion=completion,
                                     completion_kwargs=completion_kwargs,
                                     validate=validate,
                                     validate_kwargs=validate_kwargs)
            elif answ == "file":
                ret = self.text_file_read(indent=indent)
                if sub_type == self.UPPER:
                    return ret.upper()
                elif sub_type == self.LOWER:
                    return ret.lower()
                elif sub_type == self.INT:
                    try:
                        return int(ret)
                    except:
                        msg = "Could not convert {} to an integer".format(ret)
                        options = [("retry", "$retry", ""),
                                   ("abort", "or *abort", "")]
                        answ = self.get_choice(msg, options, indent=indent,
                                               start_opt="(", end_opt=")",
                                               oneline=True)
                        if answ == "retry":
                            continue
                        return
                elif sub_type == self.FLOAT:
                    try:
                        return float(ret)
                    except:
                        msg = "Could not convert {} to a float".format(ret)
                        options = [("retry", "$retry", ""),
                                   ("abort", "or *abort", "")]
                        answ = self.get_choice(msg, options, indent=indent,
                                               start_opt="(", end_opt=")",
                                               oneline=True)
                        if answ == "retry":
                            continue
                        return
                return ret
            else:
                return

    # Write/print.
    def text_file_wopen(self, path=None, codec=None):
        """Helper to open a text file in write mode."""
        import os
        import locale
        default_codec = locale.getpreferredencoding()
        if not codec:
            codec = default_codec
        if not path:
            path, codec = self.text_file_get_path("Choose an output text file",
                                                  codec)
            if path is None:  # No user interaction, return.
                return

        while 1:
            if not codec:
                codec = default_codec
            action = "replace"
            if os.path.isfile(path):
                options = [("replace", "$replace its content", ""),
                           ("append", "*append to its content", ""),
                           ("retry", "or choose an*other one", "")]
                action = self.get_choice("This file already exists, "
                                         "do you want to", options,
                                         oneline=True)
            try:
                if action == "replace":
                    return open(path, 'w', encoding=codec)
                elif action == "append":
                    return open(path, 'a', encoding=codec)
            except Exception as e:
                self.message(e)
                options = [("retry", "$try again", ""),
                           ("menu", "or go back to *menu", "")]
                action = self.get_choice("Could not open that file, please",
                                         options, oneline=True)
                if action != "retry":
                    return
            path, codec = self.text_file_get_path("Choose an input text file",
                                                  codec)

    def text_file_write(self, data, indent=0, path=None, codec=None):
        """Helper to write the whole content of a text file."""
        ofile = None
        while 1:
            try:
                ofile = self.text_file_wopen(path, codec)
                if ofile is None:
                    return
                ofile.write(data)
                return True
            except Exception as e:
                self.message(e)
                options = [("retry", "$try again", ""),
                           ("menu", "or go back to *menu", "")]
                answ = self.get_choice("Could not write to that file, please",
                                       options, oneline=True)
                if answ != "retry":
                    return
            finally:
                if ofile:
                    ofile.close()

    def text_output(self, msg, data="", print_msg="", indent=0, maxlen=None,
                    multiline=False, multiblocks=10):
        """
        Helper to output some text, either into console or into a file.
        All following parameters are console-only:
            indent is a number of indentations to add to output.
            maxlen is the max length to print out data, if not None.
                   User will then be asked whether he wants to see the whole
                   output.
            If multiline is True, data must be a subscriptable, which each item
            will be printed on a new line.
            If multiline is True, multiblocks specifies the number of lines to
            display at once, user will then be asked whether he wants to see
            more lines or not.
        """
        options = [({"console"}, "print to $console", ""),
                   ({"file"}, "write into a *file", ""),
                   ({"console", "file"}, "or *both", "")]
        answ = self.get_choice(msg, options, indent=indent, start_opt="(",
                               end_opt=")", oneline=True)
        idt = self.INDENT * indent
        if "console" in answ:
            if multiline:
                self.message(print_msg + ":", indent=indent)
                nextblock = True
                bstart = 0
                nlines = len(data)
                if multiblocks:
                    bend = multiblocks
                else:
                    bend = len(data)
                tindent = indent + 1
                maxlenmap = []
                while nextblock:
                    if bstart < nlines:
                        for idx, d in enumerate(data[bstart:bend]):
                            if maxlen and len(d) > maxlen:
                                maxlenmap.append(idx + bstart)
                                maxlenidx = str(len(maxlenmap))
                                self.message("[{}] {}"
                                             "".format(maxlenidx, d[:maxlen]),
                                             indent=tindent)
                            else:
                                self.message(d, indent=tindent)
                        bstart = bend
                        bend += multiblocks
                    if maxlenmap:
                        options = [(1, "get *whole version of some lines", "")]
                        if bstart < nlines:
                            options.append((False,
                                            "show *more lines ({} to {} over "
                                            "{})".format(bstart,
                                                         min(bend, nlines),
                                                         nlines), ""))
                        options.append((-1, "or *return", ""))
                        t = True
                        while t:
                            t = self.get_choice(msg, options,
                                                indent=tindent,
                                                start_opt="(", end_opt=")",
                                                oneline=True)
                            if t == 1:
                                v = self.validate_number_range
                                vkw = {"minnbr": 1,
                                       "maxnbr": len(maxlenmap)}
                                tk = self.text_input("Line(s) to print "
                                                     "([1 … {}])"
                                                     "".format(vkw["maxnbr"]),
                                                     indent=tindent,
                                                     no_file=True,
                                                     sub_type=self.INT_LIST,
                                                     validate=v,
                                                     validate_kwargs=vkw)
                                for k in tk:
                                    k = maxlenmap[k - 1]
                                    self.message(data[k], indent=tindent)
                            elif t == -1:
                                nextblock = t = False
                    else:
                        if bstart < nlines:
                            options = [(True,
                                        "show *more lines ({} to {} over {})"
                                        "".format(bstart, min(bend, nlines),
                                                  nlines), ""),
                                       (False, "or *return", "")]
                        else:
                            options = [(False, "*return", "")]
                        nextblock = self.get_choice(msg, options,
                                                    indent=tindent,
                                                    start_opt="(",
                                                    end_opt=")",
                                                    oneline=True)
            else:
                if maxlen and len(data) > maxlen:
                    self.message(": ".join((print_msg, data[:maxlen])),
                                 indent=indent)
                    options = [(True, "get *whole data", ""),
                               (False, "or *continue", "")]
                    if (self.get_choice(msg, options, indent=indent,
                                        start_opt="(", end_opt=")",
                                        oneline=True)):
                        self.message(data, indent=indent)
                else:
                    self.message(": ".join((print_msg, data)),
                                 indent=indent)

        if "file" in answ:
            self.text_file_write(data, indent=indent)

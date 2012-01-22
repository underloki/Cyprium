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
    STRING = None  # Default...
    UPPER = 10     # Only upper chars.
    LOWER = 20     # Only lower chars.
    PATH = 30      # Check is format-valid, and autocompletion?
    INT = 100
    FLOAT = 110

    ###########################################################################
    # Init.
    ###########################################################################
    def __init__(self):
        pass

    ###########################################################################
    # UI itself.
    ###########################################################################
    def message(self, message="", level=INFO):
        """Print a message to the user, with some formatting given
           the level value.
        """
        pass

    def get_data(self, message="", sub_type=STRING, allow_void=False,
                 completion=None, completion_kwargs={},
                 validate=None, validate_kwargs={}):
        """
        Get some data from the user.
        Will ensure data is valid given sub_type, and call
        If allow_void is True, return None or "" in case user types nothing,
        (else print a menu).
        completion callback if user hits <tab>.
            completion(data_already_entered=None, **completion_kwargs)
            must return a list of (complete) possible data.
        validate callback to check entry is valid:
            validate(data=None, **validate_kwargs)
            must return a tupple (valid, "valid_msg", "invalid_msg")
        """
        return None

    def get_choice(self, message="", choices=[], start_opt="", end_opt="",
                   oneline=False, multichoices=None):
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
        opt_start and opt_end are optional string to put before/after the
        option list.
        If the optional oneline is True, all menu choices are concatenated
        on a single line, e.g. "Go back to (M)enu or (T)ry again!".
        If multichoices is not None, user can choose several options (using
        multichoices value as separator).
        """
        # Return the default element, if present.
        for c in choices:
            if '$' in c[1]:
                return c[0]
        return None

    ###########################################################################
    # Util text/file functions.
    ###########################################################################

    # Misc.
    def text_file_get_path(self, msg, codec):
        """Get a text path (with codec)."""
        msg = " ".join((msg, "(if not using the current encoding, “{}”, " \
                             "add the desired one after a “;”, like this: " \
                             "“my/file.txt;latin1”): ".format(codec)))
        path = self.get_data(msg)
        if ';' in path:
            path, codec = path.split(';', 1)
        return path, codec

    # Read/Get.
    def text_file_ropen(self, path=None, codec=None):
        """Helper to open a text file in read mode."""
        import locale
        default_codec = locale.getpreferredencoding()
        if not codec:
            codec = default_codec
        if not path:
            path, codec = self.text_file_get_path("Choose an input text file",
                                                  codec)
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

    def text_file_read(self, path=None, codec=None):
        """Helper to read the whole content of a text file."""
        ifile = None
        while 1:
            try:
                ifile = self.text_file_ropen(path, codec)
                if ifile is None:
                    return
                return ifile.read()
            except Exception as e:
                self.message(e)
                options = [("retry", "$try again", ""),
                           ("menu", "or go back to *menu", "")]
                answ = self.get_choice("Could not read that file, please",
                                       options, online=True)
                if answ != "retry":
                    return
            finally:
                if ifile:
                    ifile.close()

    def text_input(self, msg, sub_type=STRING, allow_void=False,
                   completion=None, completion_kwargs={},
                   validate=None, validate_kwargs={}):
        """Helper to get some text, either from console or from a file."""
        while 1:
            options = [("console", "directly from $console", ""),
                       ("file", "or reading a *file", "")]
            answ = self.get_choice(msg, options, start_opt="(", end_opt=")",
                                   oneline=True)
            if answ == "console":
                return self.get_data("Please type the text: ",
                                     sub_type=sub_type, allow_void=allow_void,
                                     completion=completion,
                                     completion_kwargs=completion_kwargs,
                                     validate=validate,
                                     validate_kwargs=validate_kwargs)
            elif answ == "file":
                ret = self.text_file_read()
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
                        answ = self.get_choice(msg, options, start_opt="(",
                                               end_opt=")", oneline=True)
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
                        answ = self.get_choice(msg, options, start_opt="(",
                                               end_opt=")", oneline=True)
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

    def text_file_write(self, data, path=None, codec=None):
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

    def text_output(self, msg, data, print_msg=""):
        """Helper to output some text, either into console or into a file."""
        options = [("console", "print to $console", ""),
                   ("file", "write into a *file", ""),
                   ("both", "or *both", "")]
        answ = self.get_choice(msg, options, start_opt="(", end_opt=")",
                               oneline=True)
        if answ in {"console", "both"}:
            self.message(": ".join((print_msg, data)))
        if answ in {"file", "both"}:
            self.text_file_write(data)

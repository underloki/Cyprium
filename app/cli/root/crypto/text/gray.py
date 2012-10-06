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

# In case we directly run that file, we need to add the whole cyprium to path,
# to get access to CLI stuff!
if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..", "..",
                                                 "..")))

import app.cli
import kernel.crypto.text.gray as gray
import kernel.utils as utils


class Gray(app.cli.Tool):
    """CLI wrapper for gray crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Gray! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some textual data"),
                       (self.decypher, "d*ecypher",
                                       "Decypher binary into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Gray")]
            msg = "Cyprium.Gray"
            answ = ui.get_choice(msg, options)

            if answ == 'tree':
                self._tree.print_tree(ui, self._tree.FULL)
            elif answ == 'quit':
                self._tree.current = self._tree.current.parent
                quit = True
            else:
                answ(ui)
        ui.message("Back to Cyprium menus! Bye.")

    def about(self, ui):
        ui.message(gray.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        ui.message("--- Encoding ---")
        text = "Hello World!"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Gray cyphered data (3, 4, 5 and 8 bits words, utf-8):"
                   "\n    {}".format("\n    ".join(gray.cypher(text,
                                                   lengths=(3, 4, 5, 8)))))
        ui.message("+ Note how padding bits are added to get an integer "
                   "number of words of n bits.")
        ui.message("")

        ui.message("--- Decoding ---")
        ui.message("+ You must specify the word length used at encode time "
                   "(which must be a multiple of number of binary bits given "
                   "to decypher).")
        htext = "0110010101101010010100011101101101000010010110101011000" \
                "001100100110010110100000101000001001100101100000010110111000"
        ui.message("“Numbers” utf-8 text used as input (5 bits words): {}"
                   "".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(gray.decypher(htext, codecs="utf-8", lengths=5)))
        ui.message("")

        ui.message("+ The input text to decypher may have space-separated "
                   "bytes:")
        htext = "10010011 11000000 11110101 01001100 01010001 01001010 " \
                "00110000 01010001 00110000 01100011 01010111 01011010 " \
                "01011010 00110000 01101010 01010001 01010011 01001010 " \
                "10010011 11000000 11010101 00110000 01001011 01010111 " \
                "01001010 01010111 01010001 01010010 01011100 01010111 " \
                "01001011 00111001"
        ui.message("“binary” utf-8, 8 bits words, text used as input: {}"
                   "".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(gray.decypher(htext, codecs="utf-8", lengths=8)))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to decypher must contain only valid "
                   "binary digits (and optionally spaces):")
        htext = "011001010111211101101100015000110110111101101101011a" \
                "001010010001"
        ui.message("“Numbers” text used as binary input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(gray.decypher(htext, codecs="ascii",
                                               lengths=8)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must have an integer number "
                   "of words of n length (once spaces have been striped):")
        htext = "01100101 0110111 0110110 0110011 0110111 0101101 0110011 " \
                "0000001"
        ui.message("“Numbers” text used as input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(gray.decypher(htext, codecs="ascii",
                                               lengths=8)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to cypher to numbers")
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Get codec to use.
                    options = [(gray.DEFAULT, "$utf-8", ""),
                               (gray.ASCII, "*ascii", ""),
                               (None, "or specify another *codec", "")]
                    codec = ui.get_choice("Do you want to use", options,
                                          oneline=True)
                    if codec is None:
                        codec = ui.get_data("Type the codec you want to use "
                                            "(e.g. 'latin-9'): ")

                    # Get word length(s).
                    options = [(3, "*three", ""),
                               (4, "*four", ""),
                               (5, "f$ive", ""),
                               (8, "*height (byte)", ""),
                               (None, "and/or *other word length(s)", "")]
                    lengths = ui.get_choice("Do you want to use", options,
                                            oneline=True, multichoices=",")
                    if None in lengths:
                        lengths.remove(None)
                        lengths += ui.get_data("Type the lengths you want to "
                                               "use (e.g. '7,12,6'): ",
                                               sub_type=ui.INT_LIST)

                    txt = gray.cypher(txt, codec, lengths)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    if utils.DEBUG:
                        import traceback
                        traceback.print_tb(sys.exc_info()[2])
                    ui.message(str(e), level=ui.ERROR)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "binary, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                txt = "\n    " + "\n    ".join("{} bits: {}".format(ln, t)
                                               for ln, t in zip(lengths, txt))
                ui.text_output("Data successfully converted", txt,
                               "Gray-encoded form(s) of data")

            options = [("redo", "*cypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return

    def decypher(self, ui):
        """Interactive version of decypher()."""
        txt = ""
        ui.message("===== Decypher Mode =====")

        while 1:
            txt = ui.text_input("Please choose some binary numbers text")

            is_single_result = False

            # Get codec to use.
            options = [(gray.DEFAULT, "*utf-8", ""),
                       (gray.ASCII, "*ascii", ""),
                       (..., "a$ll", ""),
                       (None, "and/or specify *others", "")]
            codecs = set(ui.get_choice("Which codecs do you want to try",
                                       options, oneline=True,
                                       multichoices=','))
            if ... in codecs:
                codecs = set(utils.ALL_CODECS)
            elif None in codecs:
                v = ui.validate_codecs
                codecs.remove(None)
                codecs |= set(ui.text_input("Type the codec you want to use "
                                            "(e.g. 'latin-9'), or nothing to "
                                            "use all: ",indent=1,
                                            no_file=True, sub_type=ui.STR_LIST,
                                            validate=v, validate_kwargs={},
                                            allow_void=True) or
                              utils.ALL_CODECS)

            # Get word length.
            options = [(3, "*three", ""),
                       (4, "*four", ""),
                       (5, "f*ive", ""),
                       (8, "*height (byte)", ""),
                       (..., "$all possible", ""),
                       (None, "and/or *others", "")]
            lengths = set(ui.get_choice("Which word lengths do you want to "
                                        "try", options, oneline=True,
                                        multichoices=','))
            if ... in lengths:
                lengths = None
            elif None in lengths:
                def v(data, ln):
                    err = []
                    for dt in data:
                        if ln % dt:
                            err.append(str(dt))
                    if err:
                        return (False, data, "“{}” contains invalid lengths "
                                             "({}).".format(data,
                                                            ", ".join(err)))
                    return True, data, ""
                kwargs = {"ln": len(txt)}
                lengths.remove(None)
                lengths |= set(ui.text_input("Type the word lengths you want "
                                             "to use, or nothing to try all "
                                             "possible: ",indent=1,
                                             no_file=True,
                                             sub_type=ui.INT_LIST,
                                             validate=v,
                                             validate_kwargs=kwargs,
                                             allow_void=True) or ())
                if not lengths:
                    lengths = None

            if codecs and len(codecs) == 1 and lengths and len(lengths) == 1:
                codecs = tuple(codecs)[0]
                lengths = tuple(lengths)[0]
                is_single_result = True

            try:
                out = gray.decypher(txt, codecs, lengths)
            except Exception as e:
                if utils.DEBUG:
                    import traceback
                    traceback.print_tb(sys.exc_info()[2])
                ui.message(str(e), level=ui.ERROR)

            if is_single_result:
                ui.text_output("Text successfully decyphered", out,
                               "The decyphered text is")
            else:
                t = sorted(out, key=lambda o: o[4], reverse=True)
                out = []
                cdc_len = gray.TXT_CODECS_MAXLEN
                len_len = gray.TXT_LENGTHS_MAXLEN
                pattern = gray.TXT_HACKSOLUTIONS_PATTERN
                for codec, length, res, lng, avg in t:
                    out += (pattern.format(avg, lng, codec, length,
                                           cdc_len=cdc_len, len_len=len_len),
                            ui.INDENT + res)
                ui.text_output("Text successfully decyphered", out,
                               "Best solutions found are", maxlen=200,
                               multiline=True, multiblocks=20)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "gray"
TIP = "Tool to convert text to/from Gray-encoded binary text."
TYPE = app.cli.Node.TOOL
CLASS = Gray

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Gray")
    Gray(tree).main(ui)

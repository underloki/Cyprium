#! /usr/bin/python3

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
import kernel.crypto.text.baudot as baudot
import kernel.utils as utils


class Baudot(app.cli.Tool):
    """CLI wrapper for baudot crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Baudot! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in Baudot"),
                       (self.decypher, "d*ecypher",
                                       "Decypher Baudot into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Baudot")]
            msg = "Cyprium.Baudot"
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
        ui.message(baudot.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Encoding ---")
        text = "bye bye 2011 :)"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Baudot cyphered data (binary, octal, decimal and "
                   "hexadecimal):\n    {}"
                   "".format("\n    ".join(baudot.cypher(text,
                                                         bases=(2,8,10,16)))))
        ui.message("")

        ui.message("--- Decoding ---")
        ui.message("+ In general, you can let Baudot find which base is used.")
        htext = "1f1401121218041b131617130d"
        ui.message("Baudot text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(baudot.decypher(htext)))
        ui.message("")

        ui.message("+ The input text to decypher may have space-separated "
                   "bytes:")
        htext = "11111 10100 00001 10010 10010 11000 00100 11011 10011 10110 10111 10011 01101"
        ui.message("Baudot text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(baudot.decypher(htext)))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to cypher must contain only valid "
                   "chars (ascii lowercase, digits, and a few others):")
        text = "Baudot was used by “paper tapes”…"
        ui.message("Text to cypher: {}".format(text))
        try:
            ui.message("The cypherd data is: {}"
                       "".format(baudot.cypher(text)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must contain only valid "
                   "digits for the given base:")
        htext = "111111010111211101101100015000110110111101101101011a" \
                "0010100100201"
        ui.message("Baudot text used as binary input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(baudot.decypher(htext, base=2)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must have an integer number "
                   "of “bytes” (once spaces have been striped):")
        htext = "11111 01101 010110 01011 00111 01011 110011 00001"
        ui.message("Baudot text used as input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(baudot.decypher(htext, base=2)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to cypher to Baudot",
                                    sub_type=ui.LOWER)
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Get base(s).
                    options = [(2, "$binary", ""),
                               (8, "*octal", ""),
                               (10, "*decimal", ""),
                               (16, "and/or he*xadecimal", "")]
                    bases = ui.get_choice("Do you want to use", options,
                                          oneline=True, multichoices=",")

                    txt = baudot.cypher(txt, set(bases))
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    if utils.DEBUG:
                        import traceback
                        traceback.print_tb(sys.exc_info()[2])
                    ui.message(str(e), ui.ERROR)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "Baudot, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                txt = "\n    " + "\n    ".join(txt)
                ui.text_output("Text successfully converted", txt,
                               "Baudot version(s) of text")

            options = [("redo", "*cypher another text", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return

    def decypher(self, ui):
        """Interactive version of decypher()."""
        txt = ""
        ui.message("===== Decypher Mode =====")

        while 1:
            txt = ui.text_input("Please choose some Baudot text")

            # Get base.
            options = [(2, "*binary", ""),
                       (8, "*octal", ""),
                       (10, "*decimal", ""),
                       (16, "he*xadecimal", ""),
                       (None, "or $auto-detect it", "")]
            base = ui.get_choice("Do you want to use", options,
                                 oneline=True)

            try:
                ui.text_output("Text successfully decyphered",
                               baudot.decypher(txt, base),
                               "The decyphered text is")
            except Exception as e:
                if utils.DEBUG:
                    import traceback
                    traceback.print_tb(sys.exc_info()[2])
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "baudot"
TIP = "Tool to convert text to/from Baudot code."
TYPE = app.cli.Node.TOOL
CLASS = Baudot

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Baudot")
    Baudot(tree).main(ui)

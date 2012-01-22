#! /usr/bin/python3

########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   www.thehackademy.fr                                                #
#   Copyright Ã‚Â© 2012                                                   #
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
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        text = "HELLO WORLD"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Baudot cyphered data: {}"
                   "".format(baudot.cypher(text)))
        ui.message("")

        ui.message("--- Decyphering ---")
        htext = '11111 00001 00101 10000 00100 00101 11000 01110 11110 11000 '\
                '10010 10000 00111 10101 00100 11011 11001 01101 11101 11001'
        ui.message("Baudot text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(baudot.decypher(htext)))
        ui.message("")

        ui.message("--- Won't work ---")
        text = "salut v-1024 ha! THA"
        ui.message("+ The input text to cypher must be have only"
                   "ABCDEFG, digits, sapces and some symbols:")
        ui.message("Data to cypher: {}\n".format(text))
        try:
            ui.message("Baudot cyphered data: {}"
                       "".format(baudot.cypher(text)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be valid Baudot "
                   "encoded text")
        htext = "010111 01 0 10100 1110 0100101 01  01011011 10101 11001"
        ui.message("Baudot text used as input: {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(baudot.decypher(htext)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to cypher to Baudot")
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Will also raise an exception if data is None.
                    txt = baudot.cypher(txt)
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
                ui.text_output("Text successfully converted", txt,
                               "Baudot version of text")

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

            try:
                ui.text_output("Text successfully decyphered",
                               baudot.decypher(txt),
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


NAME = "*baudot"
TIP = "Tool to convert text to/from Baudot-digits code."
TYPE = app.cli.Node.TOOL
CLASS = Baudot

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Baudot")
    Baudot(tree).main(ui)

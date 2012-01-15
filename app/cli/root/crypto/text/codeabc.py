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
import kernel.crypto.text.codeabc as codeabc
import kernel.utils as utils


class CodeABC(app.cli.Tool):
    """CLI wrapper for codeABC crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.CodeABC! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in codeABC"),
                       (self.decypher, "d*ecypher",
                                       "Decypher codeABC into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.CodeABC")]
            msg = "Cyprium.CodeABC"
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
        ui.message(codeabc.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        ui.message("--- Cyphering ---")
        ui.message("Data to cypher: {}\n".format("hello wolrd"))
        ui.message("CodeABC cyphered data: {}"
                   "".format(codeabc.cypher("hello world")))

        htext = "66 444 222 33 0 222 666 3 33 0 44 33 44"
        ui.message("--- Decyphering ---")
        ui.message("CodeABC text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(codeabc.decypher(htext)))

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to cypher must be space and acsii "
                   "lowercase letters only:")
        ui.message("Data to cypher: {}\n".format("Hello Wolrd!"))
        try:
            ui.message("CodeABC cyphered data: {}"
                       "".format(codeabc.cypher("Hello World!")))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.message("+ The input text to decypher must be valid abc codes "
                   "only:")
        htext = "66 444 222 3333 0 222 666 3 33 00 44 33 44"
        ui.message("CodeABC text used as input: {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(codeabc.decypher(htext)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to cypher to codeABC")
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Will also raise an exception if data is None.
                    txt = codeabc.cypher(txt)
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
                                         "codeABC, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "CodeABC version of text")

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
            txt = ui.text_input("Please choose some codeABC text")

            try:
                ui.text_output("Text successfully decyphered",
                               codeabc.decypher(txt),
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


NAME = "*codeABC"
TIP = "Tool to convert text to/from codeABC code."
TYPE = app.cli.Node.TOOL
CLASS = CodeABC

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("CodeABC")
    CodeABC(tree).main(ui)

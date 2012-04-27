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
import kernel.crypto.text.prime as prime
import kernel.utils as utils


class Prime(app.cli.Tool):
    """CLI wrapper for prime crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Prime! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in Prime"),
                       (self.decypher, "d*ecypher",
                                       "Decypher Prime into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Prime")]
            msg = "Cyprium.Prime"
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
        ui.message(prime.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        text = "prime numbers are widely used in cryptography"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Prime cyphered data, base 1: {}"
                   "".format(prime.cypher(text, 1)))
        ui.message("Prime cyphered data, base 79: {}"
                   "".format(prime.cypher(text, 79)))
        ui.message("")

        ui.message("--- Decyphering ---")
        htext = "457 383 389 449  389 449  421 431  383 347 449 383  " \
                "457 347 349 409 367"
        ui.message("Prime text used as input (base 69): {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(prime.decypher(htext, 69)))
        ui.message("")

        ui.message("--- Won’t work ---")
        text = "The next prime year is 2017!"
        ui.message("+ The input text to cypher must be strict "
                   "ascii lowercase chars and spaces:")
        ui.message("Data to cypher: {}\n".format(text))
        try:
            ui.message("Prime cyphered data: {}"
                       "".format(prime.cypher(text)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be valid Prime "
                   "encoded text:")
        htext = "13447 24 14 15  15 234 2345 6  24 234 1345 3457 2345  " \
                "24 2345 1778 1456"
        ui.message("Prime text used as input (base 1): {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(prime.decypher(htext)))
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
                txt = ui.text_input("Text to cypher to Prime",
                                    sub_type=ui.LOWER)
                if txt is None:
                    break  # Go back to main Cypher menu.

                # Get base.
                base = 1
                b = ui.text_input("Base prime to use", sub_type=ui.INT)
                if b:
                    base = b

                try:
                    txt = prime.cypher(txt, base)
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
                                         "Prime, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Prime version of text")

            options = [("redo", "*cypher another text", ""),
                       ("quit", "or go back to $menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return

    def decypher(self, ui):
        """Interactive version of decypher()."""
        txt = ""
        ui.message("===== Decypher Mode =====")

        while 1:
            txt = ui.text_input("Please choose some Prime text")

            # Get base.
            base = 1
            b = ui.text_input("Base prime to use", sub_type=ui.INT)
            if b:
                base = b

            try:
                ui.text_output("Text successfully decyphered",
                               prime.decypher(txt, base),
                               "The decyphered text is")
            except Exception as e:
                if utils.DEBUG:
                    import traceback
                    traceback.print_tb(sys.exc_info()[2])
                ui.message(str(e), level=ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to $menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "prime"
TIP = "Tool to convert text to/from Prime numbers code."
TYPE = app.cli.Node.TOOL
CLASS = Prime

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Prime")
    Prime(tree).main(ui)

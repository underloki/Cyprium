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


# In case we directly run that file, we need to add the whole cyprium to path,
# to get access to CLI stuff!
if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..", "..",
                                                 "..")))

import app.cli
import kernel.crypto.text.celldrawer as celldrawer


class Celldrawer(app.cli.Tool):
    """CLI wrapper for celldrawer crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Celldrawer! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in celldrawer"),
                       (self.decypher, "d*ecypher",
                                       "Decypher celldrawer into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Celldrawer")]
            msg = "Cyprium.Celldrawer"
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
        ui.message(celldrawer.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        ui.message("Data to cypher: {}\n".format("hello wolrd"))
        ui.message("Celldrawer cyphered data: {}"
                   "".format(celldrawer.cypher("hello world")))
        ui.message("")

        htext = "123580 147*369#8 321457*0#  147*369#8 *74269#8 32470# " \
                "147*538# *74269#8 *7412690 321457*0# *7415369# 15380"
        ui.message("--- Decyphering ---")
        ui.message("Celldrawer text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(celldrawer.decypher(htext)))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to cypher must be acsii lowercase "
                   "letters only:")
        ui.message("Data to cypher: {}\n".format("Hello Wolrd!"))
        try:
            ui.message("Celldrawer cyphered data: {}"
                       "".format(celldrawer.cypher("Hello World!")))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be phone digits only:")
        htext = "123580 147*369#8 321457*0#  1N7*369#8 *74269#8 32470# " \
                "147*538# *74269#8 *7412690 321457*0# *741k369# 15380!"
        ui.message("Celldrawer text used as input: {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(celldrawer.decypher(htext)))
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
                txt = ui.text_input("Text to cypher to celldrawer")
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Will also raise an exception if data is None.
                    txt = celldrawer.cypher(txt)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "celldrawer, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Celldrawer version of text")

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
            txt = ui.text_input("Please choose some celldrawer text")

            try:
                ui.text_output("Text successfully decyphered",
                               celldrawer.decypher(txt),
                               "The decyphered text is")
            except Exception as e:
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "ce*lldrawer"
TIP = "Tool to convert text to/from celldrawer code."
TYPE = app.cli.Node.TOOL
CLASS = Celldrawer

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Celldrawer")
    Celldrawer(tree).main(ui)

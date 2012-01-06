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
    import sys, os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..", "..",
                                                 "..")))

import app.cli
import kernel.crypto.text.cellphone as cellphone


class Cellphone(app.cli.Tool):
    """CLI wrapper for cellphone crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Cellphone! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.encrypt, "*encrypt",
                                      "Encrypt some text in cellphone"),
                       (self.decypher, "de*cypher",
                                       "Decypher cellphone into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Sema")]
            msg = "Cyprium.Cypher"
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
        text = "===== About Cellphone =====\n\n" \
               "Cellphone encrypts/decyphers “cellphone” code.\n\n "\
               "This code only accepts lowercase ASCII letters, and " \
               "represents them by phone digits (#*0123456789), so that " \
               "each code “draws” its letter on a 4×3 phone keyboard.\n\n" \
               "            2  \n" \
               "          4   6\n" \
               "          7 8 9\n" \
               "E.G.: A:  *   #"

        ui.message(text)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)


    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        ui.message("--- Encrypting ---")
        ui.message("Data to encrypt: {}\n".format("hello wolrd"))
        ui.message("Cellphone encrypted data: {}"
                   "".format(cellphone.encrypt("hello world")))

        htext = "123580 147*369#8 321457*0#  147*369#8 *74269#8 32470# " \
                "147*538# *74269#8 *7412690 321457*0# *7415369# 15380"
        ui.message("--- Decyphering ---")
        ui.message("Cellphone text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(cellphone.decypher(htext)))

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to encrypt must be acsii lowercase "
                   "letters only:")
        ui.message("Data to encrypt: {}\n".format("Hello Wolrd!"))
        try:
            ui.message("Cellphone encrypted data: {}"
                       "".format(cellphone.encrypt("Hello World!")))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.message("+ The input text to decypher must be phone digits only:")
        htext = "123580 147*369#8 321457*0#  1N7*369#8 *74269#8 32470# " \
                "147*538# *74269#8 *7412690 321457*0# *741k369# 15380!"
        ui.message("Cellphone text used as input: {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(cellphone.decypher(htext)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)


    def encrypt(self, ui):
        """Interactive version of encrypt()."""
        txt = ""
        ui.message("===== Encrypt Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to encrypt to cellphone")
                if txt is None:
                    break  # Go back to main Encrypt menu.

                try:
                    # Will also raise an exception if data is None.
                    txt = cellphone.encrypt(txt)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "cellphone, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Cellphone version of text")

            options = [("redo", "*encrypt another text", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return


    def decypher(self, ui):
        """Interactive version of decypher()."""
        txt = ""
        ui.message("===== Decypher Mode =====")

        while 1:
            txt = ui.text_input("Please choose some cellphone text")

            try:
                ui.text_output("Text successfully decyphered",
                               cellphone.decypher(txt),
                               "The decyphered text is")
            except Exception as e:
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME  = "ce*llphone"
TIP   = "Tool to convert text to/from cellphone code."
TYPE  = app.cli.Node.TOOL
CLASS = Cellphone

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Cellphone")
    Cellphone(tree).main(ui)

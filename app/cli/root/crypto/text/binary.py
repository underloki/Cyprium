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
import kernel.crypto.text.binary as binary


class Binary(app.cli.Tool):
    """CLI wrapper for binary crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Binary! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some textual data in binary"),
                       (self.decypher, "d*ecypher",
                                       "Decypher binary into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Sema")]
            msg = "Cyprium.Binary"
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
        ui.message(binary.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        ui.message("--- Encoding ---")
        ui.message("Data to cypher: {}\n".format("Hello World!"))
        ui.message("Binary cypherd data: {}"
                   "".format(binary.cypher("Hello World!")))
        ui.message("")

        htext = "01110111011001010110110001100011011011110110110101100101" \
                "00100001"
        ui.message("--- Decoding ---")
        ui.message("“Binary” text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}".format(binary.decypher(htext)))

        ui.message("+ The input text to decypher may have space-separated "
                   "octets:")
        htext = "01110111 01100101 01101100 01100011 01101111 01101101 " \
                "01100101 00100001"
        ui.message("--- Decoding ---")
        ui.message("“Binary” text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}".format(binary.decypher(htext)))

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to decypher must be (0, 1) digits only:")
        htext = "011001010111211101101100015000110110111101101101011a" \
                "001010010001"
        ui.message("“Binary” text used as input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(binary.decypher(htext)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.message("+ The input text to decypher must have a length multiple "
                   "of 8 (once spaces have been striped):")
        htext = "01100101 0110111 0110110 0110011 0110111 0101101 0110011 " \
                "0000001"
        ui.message("“Binary” text used as input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(binary.decypher(htext)))
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
                txt = ui.text_input("Text to cypher to binary")
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Will also raise an exception if data is None.
                    codec = ui.get_data("Type the codec you want to use (e.g. "
                                        "'utf-8'), or leave empty to use "
                                        "default 'ascii' one: ")
                    if not codec:
                        codec = "ascii"
                    txt = binary.cypher(txt, codec)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "binary, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Data successfully converted", txt,
                               "Binary form of data")

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
            txt = ui.text_input("Please choose some binary text")

            codec = ui.get_data("Type the codec you want to use (e.g. "
                                "'utf-8'), or leave empty to use "
                                "default 'ascii' one: ")
            if not codec:
                codec = "ascii"

            try:
                ui.text_output("Data successfully decypherd",
                               binary.decypher(txt, codec),
                               "The hidden data is")
            except Exception as e:
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "b*inary"
TIP = "Tool to convert text to/from “binary” text."
TYPE = app.cli.Node.TOOL
CLASS = Binary

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Binary")
    Binary(tree).main(ui)

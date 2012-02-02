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
import kernel.crypto.text.octopus as octopus
import kernel.utils as utils


class Octopus(app.cli.Tool):
    """CLI wrapper for octopus crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Octopus! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some textual data in numbers"),
                       (self.decypher, "d*ecypher",
                                       "Decypher numbers into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Octopus")]
            msg = "Cyprium.Octopus"
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
        ui.message(octopus.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        ui.message("--- Encoding ---")
        text = "Hello World!"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Octopus cyphered data (binary, octal, decimal and "
                   "hexadecimal utf-8):\n    {}"
                   "".format("\n    ".join(octopus.cypher(text,
                                                          bases=(2,8,10,16)))))
        ui.message("")

        ui.message("--- Decoding ---")
        ui.message("+ In general, you can let Octopus find which base is "
                   "used.")
        htext = "127145154143157155145041040040040346254242040350277216041"
        ui.message("“Numbers” utf-8 text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(octopus.decypher(htext, codec="utf-8")))
        ui.message("")

        ui.message("+ The input text to decypher may have space-separated "
                   "bytes:")
        htext = "1001111 1100011 1110100 1101111 1110000 1110101 1110011"
        ui.message("“Numbers” ascii-7 text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(octopus.decypher(htext, codec="ascii7")))
        ui.message("")

        ui.message("+ The input text to decypher may have space-separated "
                   "bytes:")
        htext = "110001011100001011000011110001001100100111000011"
        ui.message("“Numbers” ebcdic text used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(octopus.decypher(htext, codec="cp500")))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to decypher must contain only valid "
                   "digits for the given base:")
        htext = "011001010111211101101100015000110110111101101101011a" \
                "001010010001"
        ui.message("“Numbers” text used as binary input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(octopus.decypher(htext, codec="ascii",
                                                  base=2)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must have an integer number "
                   "of “bytes” (once spaces have been striped):")
        htext = "01100101 0110111 0110110 0110011 0110111 0101101 0110011 " \
                "0000001"
        ui.message("“Numbers” text used as input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(octopus.decypher(htext, codec="ascii",
                                                  base=2)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ Auto-detection of the base might fail, especially with "
                   "short messages. In the example below (decimal EBCDIC), as "
                   "there are no '8' nor '9', the tool detect it as octal.")
        htext = "131136133131146064137163064150164163"
        ui.message("“Numbers” EBCDIC text used as input: {}".format(htext))
        ui.message("The auto-detected decypherd data is: {}"
                   "".format(octopus.decypher(htext, codec="cp500")))
        ui.message("The decimal decypherd data is: {}"
                   "".format(octopus.decypher(htext, codec="cp500", base=10)))
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
                    options = [(octopus.DEFAULT, "$utf-8", ""),
                               (octopus.ASCII, "*ascii", ""),
                               (octopus.EBCDIC, "*ebcdic", ""),
                               (octopus.ASCII7, "ascii*7 (binary encode over "
                                                "7 bits only)", ""),
                               (None, "or specify another *codec", "")]
                    codec = ui.get_choice("Do you want to use", options,
                                          oneline=True)
                    if codec is None:
                        codec = ui.get_data("Type the codec you want to use "
                                            "(e.g. 'latin-9'): ")

                    # Get base(s).
                    options = [(2, "$binary", ""),
                               (8, "*octal", ""),
                               (10, "*decimal", ""),
                               (16, "and/or he*xadecimal", "")]
                    bases = ui.get_choice("Do you want to use", options,
                                          oneline=True, multichoices=",")

                    txt = octopus.cypher(txt, codec, set(bases))
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
                                         "binary, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                txt = "\n    " + "\n    ".join(txt)
                ui.text_output("Data successfully converted", txt,
                               "Octopus form(s) of data")

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
            txt = ui.text_input("Please choose some numbers text")

            # Get codec to use.
            options = [(octopus.DEFAULT, "$utf-8", ""),
                       (octopus.ASCII, "*ascii", ""),
                       (octopus.EBCDIC, "*ebcdic", ""),
                       (octopus.ASCII7, "ascii*7 (binary encode over 7 bits "
                                        "only)", ""),
                       (None, "or specify another *codec", "")]
            codec = ui.get_choice("Do you want to use", options,
                                  oneline=True)
            if codec is None:
                codec = ui.get_data("Type the codec you want to use "
                                    "(e.g. 'latin-9'): ")

            # Get base.
            options = [(2, "*binary", ""),
                       (8, "*octal", ""),
                       (10, "*decimal", ""),
                       (16, "he*xadecimal", ""),
                       (None, "or $auto-detect it", "")]
            base = ui.get_choice("Do you want to use", options,
                                 oneline=True)

            try:
                ui.text_output("Data successfully decypherd",
                               octopus.decypher(txt, codec, base),
                               "The hidden data is")
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


NAME = "octopus"
TIP = "Tool to convert text to/from “number” text."
TYPE = app.cli.Node.TOOL
CLASS = Octopus

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Octopus")
    Octopus(tree).main(ui)

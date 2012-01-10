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


# In case we directly run that file, we need to add the whole cyprium to path,
# to get access to CLI stuff!
if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..", "..",
                                                 "..")))

import app.cli
import kernel.crypto.text.atomic as atomic
import kernel.utils as utils


class Atomic(app.cli.Tool):
    """CLI wrapper for atomic crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Atomic! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.encrypt, "*encrypt",
                                      "Encrypt some text in atomic"),
                       (self.decipher, "de*cipher",
                                       "Decipher atomic into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Atomic")]
            msg = "Cyprium.Atomic"
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
        ui.message(atomic.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Encrypting ---")
        ui.message("Data to encrypt: {}".format("HOW ARE YOU NICEDAYISNTIT"))
        out = atomic.encrypt("HOW ARE YOU NICEDAYISNTIT")
        ui.message("Atomic encrypted data:\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out, sep="  "))))
        ui.message("")

        htext = "90 53 16  53 16  A  Q 92 53 52  16 53 M 15 L E  52 16 T"
        ui.message("--- Deciphering ---")
        ui.message("Atomic text used as input: {}".format(htext))
        out = atomic.decipher(htext)
        ui.message("The deciphered data is:\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out))))
        ui.message("")

        ui.message("--- Notes ---")
        ui.message("+ You can choose the optionnal Exhaustive option, to get "
                   "all possible encodings of each words higher than the "
                   "given threshold of encryption (or the highest possible):")
        ui.message("Data to encrypt: {}".format("HOW ARE YOU NICEDAYISNTIT"))
        out = atomic.encrypt("HOW ARE YOU NICEDAYISNTIT", exhaustive=True,
                             min_encrypt=0.8)
        ui.message("Atomic exhaustive encrypted data (threshold: 0.8):\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out, sep="  "))))
        ui.message("")

        htext = "1874  A75  39892  75358DA39535081T"
        ui.message("+ You can try to decipher a text with atomic numbers "
                   "merged (i.e. no more spaces between them – nasty!):")
        ui.message("Data to decipher: {}".format(htext))
        out = atomic.decipher(htext)
        ui.message("Atomic deciphered data:\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out))))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to encrypt must be ASCII uppercase "
                   "chars only:")
        ui.message("Data to encrypt: {}\n".format("Hello WORLD !"))
        try:
            out = atomic.encrypt("Hello WORLD !")
            ui.message("Atomic encrypted data:\n    {}"
                       "".format("\n    ".join(utils.format_multiwords(out))))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decipher must be valid Atomic:")
        htext = "90 53 016  53 16  A  Q 922 53 52  16 53 M 15 L E  52 16 T"
        ui.message("Atomic text used as input: {}".format(htext))
        try:
            out = atomic.decipher(htext)
            ui.message("Atomic deciphered data:\n    {}"
                       "".format("\n    ".join(utils.format_multiwords(out))))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def encrypt(self, ui):
        """Interactive version of encrypt()."""
        txt = ""
        ui.message("===== Encrypt Mode =====")

        while 1:
            done = False
            while 1:
                exhaustive = False
                threshold = 0.9
                txt = ui.text_input("Text to encrypt to Atomic",
                                    sub_type=ui.UPPER)
                if txt is None:
                    break  # Go back to main Encrypt menu.

                options = [("exhst", "*exhaustive encryption", ""),
                           ("simple", "or $simple one", "")]
                answ = ui.get_choice("Do you want to use", options,
                                     oneline=True)
                if answ == "exhst":
                    exhaustive = True
                    t = ui.get_data("Encrypt threshold: ",
                                    sub_type=ui.FLOAT)
                    if t is not None:
                        threshold = t

                try:
                    # Will also raise an exception if data is None.
                    txt = atomic.encrypt(txt, exhaustive=exhaustive,
                                         min_encrypt=threshold)
                    txt = "\n    " + "\n    ".join(utils.format_multiwords(txt))
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "Atomic, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Atomic version of text")

            options = [("redo", "*encrypt another text", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return

    def decipher(self, ui):
        """Interactive version of decipher()."""
        txt = ""
        ui.message("===== Decipher Mode =====")

        while 1:
            txt = ui.text_input("Please choose some Atomic text",
                                sub_type=ui.UPPER)

            try:
                txt = atomic.decipher(txt)
                txt = "\n    " + "\n    ".join(utils.format_multiwords(txt))
                ui.text_output("Text successfully deciphered",
                               txt,
                               "The deciphered text is")
            except Exception as e:
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decipher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "Ato*mic"
TIP = "Tool to convert text to/from atomic code."
TYPE = app.cli.Node.TOOL
CLASS = Atomic

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Atomic")
    Atomic(tree).main(ui)

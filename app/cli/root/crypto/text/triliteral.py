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
import kernel.crypto.text.triliteral as triliteral
import kernel.utils as utils


class Triliteral(app.cli.Tool):
    """CLI wrapper for triliteral crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Triliteral! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in triliteral"),
                       (self.decypher, "d*ecypher",
                                       "Decypher triliteral into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Triliteral")]
            msg = "Cyprium.Biliteral"
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
        ui.message(triliteral.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        text = "snoworrain"
        ui.message("Data to cypher: {}".format(text))
        out = triliteral.cypher(text)
        ui.message("Triliteral cyphered data: {}".format(out))
        ui.message("")

        ui.message("--- Decyphering ---")
        htext = "CBAACCCAAACCCABCABACBABBACBAAAAACBABAAAABAABBBBACCAABABBC" \
                "CABABCBCC"
        ui.message("Triliteral text used as input: {}".format(htext))
        out = triliteral.decypher(htext)
        ui.message("The decyphered data is: {}".format(out))
        ui.message("")

        ui.message("--- Note ---")
        ui.message("+ You can select another base than the default one "
                   "(1, 'a' -> AAA). E.g. with a base 13:")
        text = "trytocypherthis"
        ui.message("Data to cypher: {}".format(text))
        out = triliteral.cypher(text, 13)
        ui.message("Triliteral base 13 cyphered data: {}".format(out))
        out = triliteral.decypher(out, 13)
        ui.message("The base 13 decyphered data is: {}".format(out))
        ui.message("")


        ui.message("--- Won’t work ---")
        ui.message("+ The input text to cypher must be ASCII lowercase "
                   "chars only:")
        ui.message("Data to cypher: {}\n".format("Hello World !"))
        try:
            out = triliteral.cypher("Hello World !")
            ui.message("Triliteral cyphered data: {}"
                       "".format(out))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be valid Triliteral:")
        htext = "AABCBBBAABABCCCCBBAACABACABCBAABACBAAAACCABABCCBACB"
        ui.message("Triliteral text used as input: {}".format(htext))
        try:
            out = triliteral.decypher(htext)
            ui.message("Triliteral decyphered data: {}"
                       "".format(out))
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
                base = 1
                txt = ui.text_input("Text to cypher to Triliteral",
                                    sub_type=ui.LOWER)
                if txt is None:
                    break  # Go back to main Cypher menu.

                t = ui.get_data("Cypher base (nothing to use default "
                                "{} one): ".format(base),
                                sub_type=ui.INT, allow_void=True)
                if t is not None:
                    base = t

                try:
                    # Will also raise an exception if data is None.
                    txt = triliteral.cypher(txt, base)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "Biliteral, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Triliteral base {} version of text"
                               "".format(base))

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
            base = 1
            txt = ui.text_input("Please choose some Triliteral text",
                                sub_type=ui.UPPER)

            t = ui.get_data("Decypher base (nothing to use default "
                            "{} one): ".format(base),
                            sub_type=ui.INT, allow_void=True)
            if t is not None:
                base = t

            try:
                ui.text_output("Text successfully decyphered",
                               triliteral.decypher(txt, base),
                               "The base {} decyphered text is"
                               "".format(base))
            except Exception as e:
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "triliteral"
TIP = "Tool to convert text to/from triliteral code."
TYPE = app.cli.Node.TOOL
CLASS = Triliteral

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Triliteral")
    Triliteral(tree).main(ui)

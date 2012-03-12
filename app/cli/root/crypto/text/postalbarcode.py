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
import kernel.crypto.text.postalbarcode as postalbarcode
import kernel.utils as utils


class PostalBarcode(app.cli.Tool):
    """CLI wrapper for postalbarcode crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.PostalBarcode! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some digits in postal bar code"),
                       (self.decypher, "d*ecypher",
                                       "Decypher postal bar code"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.PostalBarcode")]
            msg = "Cyprium.PostalBarcode"
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
        ui.message(postalbarcode.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        text = "3141592654"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Postal bar code cyphered data:\n"
                   "    org straight: {}\n    org reversed: {}\n"
                   "    cls straight: {}\n    cls reversed: {}"
                   "".format(*postalbarcode.cypher(text,
                                                   m_org=True, m_cls=True,
                                                   o_stght=True, o_rev=True)))
        ui.message("")

        ui.message("--- Decyphering ---")
        htext = "⋅||⋅|| ||⋅⋅|| ⋅|⋅||| ||⋅|⋅| ⋅||⋅|| ||⋅|⋅| ⋅|⋅||| ||⋅|⋅| " \
                "⋅||⋅|| ||⋅|⋅|"
        ui.message("Postal bar code text used as input: {}".format(htext))
        ui.message("The decyphered data is:\n"
                   "    straight: {}\n    reversed: {}"
                   "".format(*postalbarcode.decypher(htext,
                                                     o_stght=True,
                                                     o_rev=True)))
        ui.message("")

        htext = " || || ||  ||  | ||| || | |  || || || | |  | ||| || | | " \
                " || || || | |"
        ui.message("Postal bar code text used as input: {}".format(htext))
        ui.message("The decyphered data is:\n"
                   "    straight: {}\n    reversed: {}"
                   "".format(*postalbarcode.decypher(htext,
                                                     o_stght=True,
                                                     o_rev=True)))
        ui.message("")

        ui.message("--- Won’t work ---")
        text = "3.141592654"
        ui.message("+ The input text to cypher must be digits only:")
        ui.message("Data to cypher: {}\n".format(text))
        try:
            ui.message("Postal bar code cyphered data: {}"
                       "".format(postalbarcode.cypher(text)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be valid postal "
                   "bar codes only:")
        htext = "⋅||⋅|| ||  || ⋅|⋅|⋅| ||⋅|⋅| ⋅||⋅|| || | | ⋅|⋅||| ||⋅|⋅| " \
                "⋅||⋅|| ||⋅|⋅|"
        ui.message("Braille text used as input: {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(postalbarcode.decypher(htext)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to cypher to Braille")
                if txt is None:
                    break  # Go back to main Cypher menu.

                options = [((True, False), "*original (pipes and dots)", ""),
                           ((False, True), "*classical (pipes and spaces)",
                                           ""),
                           ((True, True), "or *both versions", "")]
                m_org, m_cls = ui.get_choice("Do you want to get", options,
                                             oneline=True)

                options = [((True, False), "*straight", ""),
                           ((False, True), "*reversed", ""),
                           ((True, True), "or *both orders", "")]
                o_stght, o_rev = ui.get_choice("Do you want to get", options,
                                               oneline=True)

                try:
                    # Will also raise an exception if data is None.
                    txt = postalbarcode.cypher(txt, m_org=m_org, m_cls=m_cls,
                                               o_stght=o_stght, o_rev=o_rev)
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
                                         "Braille, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                if len(txt) > 1:
                    txt = "\n    " + "\n    ".join(txt)
                else:
                    txt, = txt
                ui.text_output("Text successfully converted", txt,
                               "Braille version of text")

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
            txt = ui.text_input("Please choose some Braille text")

            options = [((True, False), "*straight", ""),
                       ((False, True), "*reversed", ""),
                       ((True, True), "or *both orders", "")]
            o_stght, o_rev = ui.get_choice("Do you want to get", options,
                                           oneline=True)

            try:
                txt = postalbarcode.decypher(txt, o_stght=o_stght, o_rev=o_rev)
                if len(txt) > 1:
                    txt = "\n    " + "\n    ".join(txt)
                else:
                    txt, = txt
                ui.text_output("Text successfully decyphered", txt,
                               "The decyphered text is")
            except Exception as e:
                if utils.DEBUG:
                    import traceback
                    traceback.print_tb(sys.exc_info()[2])
                ui.message(str(e), level=ui.ERROR)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "*postal bar code"
TIP = "Tool to convert number to/from postal bar code."
TYPE = app.cli.Node.TOOL
CLASS = PostalBarcode

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("PostalBarcode")
    PostalBarcode(tree).main(ui)

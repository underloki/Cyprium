########################################################################
#                                                                      #
#   Cyprium is a multifunction cryptographic, steganographic and       #
#   cryptanalysis tool developped by members of The Hackademy.         #
#   French White Hat Hackers Community!                                #
#   cyprium.hackademics.fr                                             #                                                  #
#   Authors: SAKAROV, mont29, afranck64                                #
#   Contact: admin@hackademics.fr                                      #
#   Forum: hackademics.fr                                              #
#   Twitter: @hackademics_                                             #
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
import kernel.crypto.text.chinesecypher as chinesecypher
import kernel.utils as utils


class ChineseCypher(app.cli.Tool):
    """CLI wrapper for chinesecypher crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.ChineseCypher! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in chinesecypher"),
                       (self.decypher, "d*ecypher",
                                       "Decypher chinesecypher into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.ChineseCypher")]
            msg = "Cyprium.ChineseCypher"
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
        ui.message(chinesecypher.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!\n")

        ui.message("--- Cyphering ---")
        text = "china is a big country"
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("ChineseCypher cyphered data, (Chinese, Samurai and "
                   "digits):\n    {}"
                   "".format("\n    "
                             "".join(chinesecypher.cypher(text,
                                                          chinese=True,
                                                          samurai=True,
                                                          digits=True))))
        ui.message("")

        ui.message("--- Decyphering Chinese version ---")
        htext = "————||||| ——||| ——  " \
                "——||| — —|| ———|| — —||| —— ———|||| ——————"
        ui.message("ChineseCypher text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(chinesecypher.decypher(htext)))
        ui.message("")

        ui.message("--- Decyphering Samurai version ---")
        htext = "||||————— ||——— ||  " \
                "||——— | |—— |||—— | |——— || |||———— ||||||"
        ui.message("ChineseCypher text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(chinesecypher.decypher(htext)))
        ui.message("")

        ui.message("--- Decyphering Digits version ---")
        htext = "45 23 20  23 10 12 32 10 13 20 34 60"
        ui.message("ChineseCypher text used as input: {}".format(htext))
        ui.message("The decyphered data is: {}"
                   "".format(chinesecypher.decypher(htext)))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to cypher must be acsii lowercase "
                   "letters only:")
        ui.message("Data to cypher: {}\n".format("Hello Wolrd!"))
        try:
            ui.message("ChineseCypher cyphered data: {}"
                       "".format(chinesecypher.cypher("Hello World!",
                                                      chinese=True)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be phone digits only:")
        htext = "49 23 ||———  23 10 12 ———|| 10 13 88 34 60"
        ui.message("ChineseCypher text used as input: {}".format(htext))
        try:
            ui.message("The decyphered data is: {}"
                       "".format(chinesecypher.decypher(htext)))
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
                txt = ui.text_input("Text to cypher to chinesecypher")
                if txt is None:
                    break  # Go back to main Cypher menu.

                options = [((True, False, False), "*Chinese", ""),
                           ((False, True, False), "*Samurai", ""),
                           ((False, False, True), "*Digits", ""),
                           ((True, True, True), "or *all of them", "")]
                chinese, samurai, digits = \
                         ui.get_choice("What version(s) do you want to get, ",
                                       options, oneline=True)

                try:
                    # Will also raise an exception if data is None.
                    txt = chinesecypher.cypher(txt, chinese=chinese,
                                               samurai=samurai, digits=digits)
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
                                         "chinesecypher, please", options,
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
                               "ChineseCypher version of text")

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
            txt = ui.text_input("Please choose some chinesecypher text")

            try:
                ui.text_output("Text successfully decyphered",
                               chinesecypher.decypher(txt),
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


NAME = "chinese cypher"
TIP = "Tool to convert text to/from chinese cypher code."
TYPE = app.cli.Node.TOOL
CLASS = ChineseCypher

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("ChineseCypher")
    ChineseCypher(tree).main(ui)

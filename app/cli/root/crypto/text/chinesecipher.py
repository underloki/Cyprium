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
import kernel.crypto.text.chinesecipher as chinesecipher


class ChineseCipher(app.cli.Tool):
    """CLI wrapper for chinesecipher crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.ChineseCipher! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.encrypt, "*encrypt",
                                      "Encrypt some text in chinesecipher"),
                       (self.decipher, "de*cipher",
                                       "Decipher chinesecipher into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.ChineseCipher")]
            msg = "Cyprium.ChineseCipher"
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
        ui.message(chinesecipher.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!\n")

        ui.message("--- Encrypting ---")
        text = "china is a big country"
        ui.message("Data to encrypt: {}\n".format(text))
        ui.message("ChineseCipher encrypted data, (Chinese, Samurai and "
                   "digits):\n    {}"
                   "".format("\n    "
                             "".join(chinesecipher.encrypt(text,
                                                           chinese=True,
                                                           samurai=True,
                                                           digits=True))))
        ui.message("")

        ui.message("--- Deciphering Chinese version ---")
        htext = "————||||| ——||| ——  " \
                "——||| — —|| ———|| — —||| —— ———|||| ——————"
        ui.message("ChineseCipher text used as input: {}".format(htext))
        ui.message("The deciphered data is: {}"
                   "".format(chinesecipher.decipher(htext)))
        ui.message("")

        ui.message("--- Deciphering Samurai version ---")
        htext = "||||————— ||——— ||  " \
                "||——— | |—— |||—— | |——— || |||———— ||||||"
        ui.message("ChineseCipher text used as input: {}".format(htext))
        ui.message("The deciphered data is: {}"
                   "".format(chinesecipher.decipher(htext)))
        ui.message("")

        ui.message("--- Deciphering Digits version ---")
        htext = "45 23 20  23 10 12 32 10 13 20 34 60"
        ui.message("ChineseCipher text used as input: {}".format(htext))
        ui.message("The deciphered data is: {}"
                   "".format(chinesecipher.decipher(htext)))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to encrypt must be acsii lowercase "
                   "letters only:")
        ui.message("Data to encrypt: {}\n".format("Hello Wolrd!"))
        try:
            ui.message("ChineseCipher encrypted data: {}"
                       "".format(chinesecipher.encrypt("Hello World!",
                                                       chinese=True)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decipher must be phone digits only:")
        htext = "49 23 ||———  23 10 12 ———|| 10 13 88 34 60"
        ui.message("ChineseCipher text used as input: {}".format(htext))
        try:
            ui.message("The deciphered data is: {}"
                       "".format(chinesecipher.decipher(htext)))
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
                txt = ui.text_input("Text to encrypt to chinesecipher")
                if txt is None:
                    break  # Go back to main Encrypt menu.

                options = [((True, False, False), "*Chinese", ""),
                           ((False, True, False), "*Samurai", ""),
                           ((False, False, True), "*Digits", ""),
                           ((True, True, True), "or *all of them", "")]
                chinese, samurai, digits = \
                         ui.get_choice("What version(s) do you want to get, ",
                                       options, oneline=True)

                try:
                    # Will also raise an exception if data is None.
                    txt = chinesecipher.encrypt(txt, chinese=chinese,
                                                samurai=samurai, digits=digits)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "chinesecipher, please", options,
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
                               "ChineseCipher version of text")

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
            txt = ui.text_input("Please choose some chinesecipher text")

            try:
                ui.text_output("Text successfully deciphered",
                               chinesecipher.decipher(txt),
                               "The deciphered text is")
            except Exception as e:
                ui.message(str(e), ui.ERROR)

            options = [("redo", "*decipher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "c*hinese chipher"
TIP = "Tool to convert text to/from chinese cipher code."
TYPE = app.cli.Node.TOOL
CLASS = ChineseCipher

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("ChineseCipher")
    ChineseCipher(tree).main(ui)

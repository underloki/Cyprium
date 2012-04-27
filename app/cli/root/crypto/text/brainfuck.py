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
import kernel.crypto.text.brainfuck as brainfuck
import kernel.utils as utils


class Brainfuck(app.cli.Tool):
    """CLI wrapper for brainfuck crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Brainfuck! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some textual data"),
                       (self.decypher, "d*ecypher",
                                       "Decypher code into text"),
                       (self.convert, "c*onvert",
                                      "Convert code to another language"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Octopus")]
            msg = "Cyprium.Brainfuck"
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
        ui.message(brainfuck.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        ui.message("--- Encoding ---")
        text = "Hello World!"
        bf = brainfuck.brainfuck
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Brainfuck cyphered data (utf-8): {}"
                   "".format(brainfuck.cypher(text, lang=bf.BRAINFUCK)))
        ui.message("Ook cyphered data (utf-8): {}"
                   "".format(brainfuck.cypher(text, lang=bf.OOK)))
        ui.message("Spoon cyphered data (utf-8): {}"
                   "".format(brainfuck.cypher(text, lang=bf.SPOON)))
        ui.message("SegFaultProg cyphered data (utf-8): {}"
                   "".format(brainfuck.cypher(text, lang=bf.SIGSEV)))
        ui.message("")

        ui.message("--- Decoding ---")
        ui.message("+ Brainfuck will find out which language it is.")
        htext = "++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++.>---.++++++" \
                "+++++++++..+++++++++.<<++.>>-----------.---------.+++++++++" \
                "+++++++++.<<.>>++.--------------------.----.+++++++++++++++" \
                "++.<<.++++++++++++++++++.--.+.+."
        ui.message("Brainfuck code used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(brainfuck.decypher(htext, codec="utf-8")))
        ui.message("")
        htext = "+8[>+4*2+8*3+12>+13>+14>+15>+16*8+19*9+20>+28<10-]*2+.*1.>4" \
                "+.+4.*4+.*5-.*3+5.<2.>4-.*4.+4.>-3.<-.*3.*1.*3-.>2+5.*4+.." \
                "*6+.<5.>9+2.<3.>+4.*5-.<2+.*5-.+.>5.<3.*8+.*10.*7.>2+6."
        ui.message("Brainfuck code used as input: {}".format(htext))
        ui.message("The decypherd data is: {}"
                   "".format(brainfuck.decypher(htext, codec="utf-8")))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input code to decypher must be valid!")
        htext = "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook." \
                " Ook. Ook. Ook. Ook! Ook?" \
                "*4.+4.>-3.<-.*3.*1.*3-.>2+5.*4+..*6+.<5.>9+2.<3.>+4.*5-.<2+."
        ui.message("“Numbers” text used as binary input: {}".format(htext))
        try:
            ui.message("The decypherd data is: {}"
                       "".format(brainfuck.decypher(htext)))
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
                txt = ui.text_input("Text to cypher to code")
                if txt is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Get codec to use.
                    options = [(brainfuck.DEFAULT, "$utf-8", ""),
                               (None, "or specify another *codec", "")]
                    codec = ui.get_choice("Do you want to use", options,
                                          oneline=True)
                    if codec is None:
                        codec = ui.get_data("Type the codec you want to use "
                                            "(e.g. 'latin-9'): ")

                    # Get language.
                    bf = brainfuck.brainfuck
                    options = [(bf.BRAINFUCK, "$brainfuck", ""),
                               (bf.OOK, "*ook", ""),
                               (bf.FASTOOK, "*fast ook", ""),
                               (bf.SPOON, "*spoon", ""),
                               (bf.SIGSEV, "or se*gfaultprog", "")]
                    lang = ui.get_choice("Do you want to generate", options,
                                         oneline=True)

                    # Get obfuscation.
                    obfs = ui.get_data("Do you want to generate obfuscated "
                                       "code (0.0 or nothing for none, "
                                       "value up to 1.0): ", sub_type=ui.FLOAT,
                                       allow_void=True)
                    if not obfs:
                        obfs = 0.0

                    # Get seed for random generator.
                    options = [(None, "current $time", ""),
                               (-1, "*cyphered text", ""),
                               (1, "or specify a custom *seed", "")]
                    seed = ui.get_choice("To init the random generator, do "
                                         "you want to use", options,
                                         oneline=True)
                    if seed == 1:
                        seed = ui.get_data("Type the integer you want to "
                                           "use: ", sub_type=ui.INT)
                    elif seed == -1:
                        seed = txt

                    txt = brainfuck.cypher(txt, lang, codec, obfs, seed)
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
                                         "the chosen language, please",
                                         options, oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Data successfully converted", txt,
                               "Code form of data")

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
            txt = ui.text_input("Please choose some “code” text")

            # Get codec to use.
            options = [(brainfuck.DEFAULT, "$utf-8", ""),
                       (None, "or specify another *codec", "")]
            codec = ui.get_choice("Do you want to use", options,
                                  oneline=True)
            if codec is None:
                codec = ui.get_data("Type the codec you want to use "
                                    "(e.g. 'latin-9'): ")

            try:
                ui.text_output("Data successfully decypherd",
                               brainfuck.decypher(txt, codec),
                               "The hidden data is")
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

    def convert(self, ui):
        """Interactive version of convert()."""
        txt = ""
        ui.message("===== Convert Mode =====")

        while 1:
            done = False
            while 1:
                code = ui.text_input("Code to convert to some language")
                if code is None:
                    break  # Go back to main Cypher menu.

                try:
                    # Get language.
                    bf = brainfuck.brainfuck
                    options = [(bf.BRAINFUCK, "$brainfuck", ""),
                               (bf.OOK, "*ook", ""),
                               (bf.FASTOOK, "*fast ook", ""),
                               (bf.SPOON, "*spoon", ""),
                               (bf.SIGSEV, "or se*gfaultprog", "")]
                    lang = ui.get_choice("Do you want to convert to", options,
                                         oneline=True)

                    # Get obfuscation.
                    obfs = ui.get_data("Do you want to generate obfuscated "
                                       "code (0.0 or nothing for none, "
                                       "value up to 1.0): ", sub_type=ui.FLOAT,
                                       allow_void=True)
                    if not obfs:
                        obfs = 0.0

                    # Get seed for random generator.
                    options = [(None, "current $time", ""),
                               (-1, "*cyphered text", ""),
                               (1, "or specify a custom *seed", "")]
                    seed = ui.get_choice("To init the random generator, do "
                                         "you want to use", options,
                                         oneline=True)
                    if seed == 1:
                        seed = ui.get_data("Type the integer you want to "
                                           "use: ", sub_type=ui.INT)
                    elif seed == -1:
                        seed = code

                    code = brainfuck.convert(code, lang, obfs, seed)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    if utils.DEBUG:
                        import traceback
                        traceback.print_tb(sys.exc_info()[2])
                    ui.message(str(e), level=ui.ERROR)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that code into "
                                         "the chosen language, please",
                                         options, oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Code successfully converted", code, "Code")

            options = [("redo", "*convert another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return


NAME = "brainfuck"
TIP = "Tool to convert text to/from brainfuck & co language."
TYPE = app.cli.Node.TOOL
CLASS = Brainfuck

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Brainfuck")
    Brainfuck(tree).main(ui)

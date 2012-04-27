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
import random


# In case we directly run that file, we need to add the whole cyprium to path,
# to get access to CLI stuff!
if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..", "..",
                                                 "..")))

import app.cli
import kernel.crypto.text.atomicdigits as atomicdigits
import kernel.utils as utils


class AtomicDigits(app.cli.Tool):
    """CLI wrapper for atomicdigits crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.AtomicDigits! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in atomic digits"),
                       (self.decypher, "d*ecypher",
                                       "Decypher atomic digits into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.AtomicDigits")]
            msg = "Cyprium.AtomicDigits"
            answ = ui.get_choice(msg, options)

            if answ == 'tree':
                self._tree.print_tree(ui, self._tree.FULL)
            elif answ == 'quit':
                self._tree.current = self._tree.current.parent
                quit = True
            else:
                answ(ui)
        ui.message("Back to Cyprium menus! Bye.")

    def _get_exhaustive_txt(self, out, ui, min_cypher, act=None):
        ui.message("Exaustive found {} solutions for a minimum cyphering of "
                   "{}, among which {} solutions with the highest possible "
                   "cyphering ({})."
                   "".format(out["n_solutions"], min_cypher,
                             out["best_n_solutions"],
                             out["best_cypher"]))

        if act not in {"all", "best", "rand", "rand_best"}:
            options = [("all", "*all solutions", ""),
                       ("best", "all $best solutions", ""),
                       ("rand", "*one random solution", ""),
                       ("rand_best", "or one *random best solution", "")]
            act = ui.get_choice("Do you want to get", options,
                                 oneline=True)

        if act == "all":
            lines = utils.format_multiwords(out["solutions"], sep="  ")
            return "\n    {}".format("\n    ".join(lines))
        elif act == "best":
            lines = utils.format_multiwords(out["best_solutions"], sep="  ")
            return "\n    {}".format("\n    ".join(lines))
        elif act == "rand":
            return "  ".join((random.choice(w) for w in out["solutions"]))
        else:
            return "  ".join((random.choice(w) for w in out["best_solutions"]))

    def about(self, ui):
        ui.message(atomicdigits.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        ui.message("Data to cypher: {}".format("HOW ARE YOU NICEDAYISNTIT"))
        out = atomicdigits.cypher("HOW ARE YOU NICEDAYISNTIT")
        ui.message("Atomic digits cyphered data:\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out,
                                                                   sep="  "))))
        ui.message("")

        htext = "90 53 16  53 16  A  Q 92 53 52  16 53 M 15 L E  52 16 T"
        ui.message("--- Decyphering ---")
        ui.message("Atomic digits text used as input: {}".format(htext))
        out = atomicdigits.decypher(htext)
        ui.message("The decyphered data is:\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out))))
        ui.message("")

        ui.message("--- Notes ---")
        ui.message("+ You can choose the optionnal Exhaustive option, to get "
                   "all possible encodings of each words higher than the "
                   "given threshold of cyphering (or the highest possible):")
        ui.message("Data to cypher: {}".format("HOW ARE YOU NICEDAYISNTIT"))
        out = atomicdigits.cypher("HOW ARE YOU NICEDAYISNTIT", exhaustive=True,
                             min_cypher=0.8)
        out = self._get_exhaustive_txt(out, ui, min_cypher=0.8, act="all")
        ui.message(out)
        ui.message("")

        htext = "1874  A75  39892  75358DA39535081T"
        ui.message("+ You can try to decypher a text with atomic numbers "
                   "merged (i.e. no more spaces between them – nasty!):")
        ui.message("Data to decypher: {}".format(htext))
        out = atomicdigits.decypher(htext)
        ui.message("Atomic digits decyphered data:\n    {}"
                   "".format("\n    ".join(utils.format_multiwords(out))))
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The input text to cypher must be ASCII uppercase "
                   "chars only:")
        ui.message("Data to cypher: {}\n".format("Hello WORLD !"))
        try:
            out = atomicdigits.cypher("Hello WORLD !")
            ui.message("Atomic digits cyphered data:\n    {}"
                       "".format("\n    ".join(utils.format_multiwords(out))))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("+ The input text to decypher must be valid atomic digits:")
        htext = "90 53 016  53 16  A  Q 922 53 52  16 53 M 15 L E  52 16 T"
        ui.message("Atomic digits text used as input: {}".format(htext))
        try:
            out = atomicdigits.decypher(htext)
            ui.message("Atomic digits decyphered data:\n    {}"
                       "".format("\n    ".join(utils.format_multiwords(out))))
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
                exhaustive = False
                threshold = 0.8
                txt = ui.text_input("Text to cypher to atomic digits",
                                    sub_type=ui.UPPER)
                if txt is None:
                    break  # Go back to main Cypher menu.

                options = [("exhst", "*exhaustive cyphering", ""),
                           ("simple", "or $simple one", "")]
                answ = ui.get_choice("Do you want to use", options,
                                     oneline=True)
                if answ == "exhst":
                    exhaustive = True
                    t = ui.get_data("Cypher threshold (nothing to use default "
                                    "{} one): ".format(threshold),
                                    sub_type=ui.FLOAT, allow_void=True)
                    if t is not None:
                        threshold = t

                try:
                    # Will also raise an exception if data is None.
                    txt = atomicdigits.cypher(txt, exhaustive=exhaustive,
                                              min_cypher=threshold)
                    if exhaustive:
                        txt = self._get_exhaustive_txt(txt, ui,
                                                       min_cypher=threshold)
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
                                         "atomic digits, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Atomic digits version of text")

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
            txt = ui.text_input("Please choose some atomic digits text",
                                sub_type=ui.UPPER)

            try:
                txt = atomicdigits.decypher(txt)
                txt = "\n    " + "\n    ".join(utils.format_multiwords(txt))
                ui.text_output("Text successfully decyphered",
                               txt,
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


NAME = "atomic"
TIP = "Tool to convert text to/from atomic digits code."
TYPE = app.cli.Node.TOOL
CLASS = AtomicDigits

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("AtomicDigits")
    AtomicDigits(tree).main(ui)

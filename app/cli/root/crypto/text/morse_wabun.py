#! /usr/bin/python3

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


# In case we directly run that file, we need to add the whole cyprium to path,
# to get access to CLI stuff!
if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..", "..",
                                                 "..")))

import app.cli
import kernel.crypto.text.morse_wabun as morse_wabun
import kernel.utils as utils


class MorseWabun(app.cli.Tool):
    """CLI wrapper for morse_wabun crypto text tool."""
    @staticmethod
    def _get_exhaustive_txt(out, w_sep, ui, min_cypher, act=None):
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
            lines = utils.format_multiwords(out["solutions"], sep="")
            return "\n    {}".format("\n    ".join(lines))
        elif act == "best":
            lines = utils.format_multiwords(out["best_solutions"], sep="")
            return "\n    {}".format("\n    ".join(lines))
        elif act == "rand":
            return "".join((random.choice(w) for w in out["solutions"]))
        else:
            return "".join((random.choice(w) for w in out["best_solutions"]))

## Main stuff.
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Morse|Wabun! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some textual data in "
                                     "morse/wabun"),
                       (self.decypher, "d*ecypher",
                                       "Decypher morse/wabun to text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Morse")]
            msg = "Cyprium.Morse|Wabun"
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
        ui.message(morse_wabun.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering to Morse ---")
        text = "VANCOUVER! VANCOUVER! THIS IS IT!"
        ui.message("Data to cypher: {}".format(text))
        out = morse_wabun.cypher(text, morse_wabun.INTER, morse_wabun.STANDARD)
        ui.message("International standard morse: {}".format(out))
        out = morse_wabun.cypher(text, morse_wabun.INTER, morse_wabun.FAST)
        ui.message("International fast morse: {}".format(out))
        ui.message("")

        ui.message("--- Cyphering to Wabun ---")
        text = "LE KATAKANA DU SAMOURAI ETAIT EN FER BLANC."
        ui.message("Data to cypher: {}".format(text))
        out = morse_wabun.cypher(text, morse_wabun.WABUN, morse_wabun.STANDARD)
        ui.message("Wabun standard morse: {}".format(out))
        out = morse_wabun.cypher(text, morse_wabun.WABUN, morse_wabun.FAST)
        ui.message("Wabun fast morse: {}".format(out))
        ui.message("")

        ui.message("--- Decyphering ---")
        htext = ".. -.-. .. / ...- .- -. -.-. --- ..- ...- . .-. .-.-.- / " \
                "-.-. --- -- -- . -. - / .- .-.. .-.. . --.. -....- ...- " \
                "--- ..- ... --..-- / .--. .- .-. .. ... ..--.."
        ui.message("Note that most of the time, you can use default options "
                   "here (i.e. automatic detection)!")
        ui.message("First input: {}".format(htext))
        out = morse_wabun.decypher(htext)
        ui.message("The decyphered data is: {}".format(out))
        htext = "T...=.......===.===.=.===.=...=.=.===.===..." \
                "===.===.=.=.===.=.=.......=.===...S......." \
                "S...===.===.=.=.=.=.===.===.=.===...=.===.=.===.===.=.=..." \
                "===.===.=...N...G.......=.===.=.=.=...N.......T...=......." \
                "===.=.===...L...L"
        ui.message("Second input: {}".format(htext))
        out = morse_wabun.decypher(htext)
        ui.message("The decyphered data is: {}".format(out))
        ui.message("")

        ui.message("--- Notes ---")
        ui.message("+ For Wabun cyphering, you can choose the optionnal "
                   "Exhaustive option, to get all possible encodings of each "
                   "words higher than the given threshold of cyphering (or "
                   "the highest possible):")
        text = "THE SHOGUN IS DRINKING GREEN TEA."
        ui.message("Data to cypher: {}".format(text))
        out = morse_wabun.cypher(text, morse_wabun.WABUN, morse_wabun.FAST,
                                 exhaustive=True, min_cypher=0.6)
        out = self._get_exhaustive_txt(out, ' / ', ui,
                                       min_cypher=0.6, act="all")
        ui.message("Cyphered solutions with cypher factor higher than 0.6:")
        ui.message(out)
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ As usual, only valid letters/codes can be given "
                   "(always uppercase).")
        text = "\"HELLŌ 2012 WØRLD…\""
        ui.message("* International Morse supports numbers, and some special "
                   "chars and accentuated occidental chars")
        ui.message("Data to cypher in international morse: {}"
                   "".format(text))
        try:
            out = morse_wabun.cypher(text, morse_wabun.INTER)
            ui.message("Morse cyphered data: {}".format(out))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("* Wabun Morse supports only ASCII chars, spaces, dots, "
                   "coma and parenthesis:")
        ui.message("Data to cypher in international morse: {}"
                   "".format(text))
        try:
            out = morse_wabun.cypher(text, morse_wabun.WABUN)
            ui.message("WABUN cyphered data: {}".format(out))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)

        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                exhaustive = False
                threshold = 0.7

                txt = ui.text_input("Text to cypher to Morse/Wabun",
                                    sub_type=ui.UPPER)
                if txt is None:
                    break  # Go back to main Cypher menu.

                # Get cyphering method.
                options = [(morse_wabun.INTER,
                            "$international morse cyphering", ""),
                           (morse_wabun.WABUN, "or *wabun one", "")]
                method = ui.get_choice("Do you want to use", options,
                                       oneline=True)

                # Get cyphering variant.
                options = [(morse_wabun.STANDARD,
                            "$standard variant (=.===...=.=.......===.=)", ""),
                           (morse_wabun.FAST,
                            "or *fast one (. -.- / ..--)", "")]
                variant = ui.get_choice("Do you want to use", options,
                                        oneline=True)

                # What algo to use (wabun only).
                if method == morse_wabun.WABUN:
                    options = [("exhst", "*exhaustive cyphering", ""),
                               ("simple", "or $simple one", "")]
                    answ = ui.get_choice("Do you want to use", options,
                                         oneline=True)
                    if answ == "exhst":
                        exhaustive = True
                        t = ui.get_data("Cypher threshold (nothing to use "
                                        "default {} one): ".format(threshold),
                                        sub_type=ui.FLOAT, allow_void=True)
                        if t is not None:
                            threshold = t

                try:
                    # Will also raise an exception if data is None.
                    txt = morse_wabun.cypher(txt, method, variant,
                                             exhaustive=exhaustive,
                                             min_cypher=threshold)
                    if exhaustive:
                        w_sep = ''
                        if variant == morse_wabun.FAST:
                            w_sep = " / "
                        txt = self._get_exhaustive_txt(txt, w_sep, ui,
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
                                         "morse, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return

            if done:
                ui.text_output("Data successfully converted", txt,
                               "Morse form of data")

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
            txt = ui.text_input("Please choose some morse/wabun text",
                                sub_type=ui.UPPER)

            # Get optional decyphering method.
            options = [(morse_wabun.INTER,
                        "*international morse decyphering", ""),
                       (morse_wabun.WABUN, "*wabun one", ""),
                       (None, "or $auto detect cypher method", "")]
            method = ui.get_choice("Do you want to force", options,
                                   oneline=True)

            try:
                ui.text_output("Data successfully decypherd",
                               morse_wabun.decypher(txt, method),
                               "The cyphered data is")
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


NAME = "morse|wabun"
TIP = "Tool to convert text to/from morse/wabun code."
TYPE = app.cli.Node.TOOL
CLASS = MorseWabun

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Morse|Wabun")
    MorseWabun(tree).main(ui)

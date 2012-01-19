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
import kernel.crypto.text.argots as argots
import kernel.utils as utils


class Argots(app.cli.Tool):
    """CLI wrapper for argots crypto text tool."""

    @staticmethod
    def _validate(txt, **kwargs):
        m = kwargs['method']
        return (argots.is_valid_syllable(m, txt),
                "", "That syllable is not valid for the method you choose!")

    @staticmethod
    def _get_exhaustive_txt(out, ui, min_cypher, act=None):
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
            lines = utils.format_multiwords(out["solutions"], sep=" ")
            return "\n    {}".format("\n    ".join(lines))
        elif act == "best":
            lines = utils.format_multiwords(out["best_solutions"], sep=" ")
            return "\n    {}".format("\n    ".join(lines))
        elif act == "rand":
            return " ".join((random.choice(w) for w in out["solutions"]))
        else:
            return " ".join((random.choice(w) for w in out["best_solutions"]))

## Main stuff.
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Argots! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in argot javanais, "
                                     "langue de feu or Largonji des "
                                     "louchébems"),
                       (self.decypher, "d*ecypher",
                                       "Decypher some argot into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Argots")]
            msg = "Cyprium.Argots"
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
        ui.message(argots.__about__)
        ui.get_choice("", [("", "Go back to *menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        text = "Les « Blousons Noirs » vous parlent…"
        ui.message("Data to cypher: {}".format(text))
        out = argots.cypher(text, argots.JAVANAIS, 'av')
        ui.message("Argot Javanais with 'av': {}".format(out))
        ui.message("")

        ui.message("--- Decyphering ---")
        htext = "LEfes EfApEfachEfes sEfont sEfur lEfe sEfentEfier dEfes HEfallEfes."
        ui.message("Note that most of the time, you can use default options "
                   "here (i.e. Generic, and give no obfuscating syllable), "
                   "as that kind of “cyphering” is really easy to break!")
        ui.message("Langue de Feu text used as input: {}".format(htext))
        out = argots.decypher(htext, argots.FEU)
        ui.message("The decyphered data is:\n    With '{}': {}"
                   "".format(out[0][0], out[0][1]))
        ui.message("")

        ui.message("--- Notes ---")
        ui.message("+ You can choose the optionnal Exhaustive option, to get "
                   "all possible encodings of each words higher than the "
                   "given threshold of cyphering (or the highest possible):")
        text = "Do you know Ménilmuche and Belleville ?"
        ui.message("Data to cypher: {}".format(text))
        out = argots.cypher(text, argots.GENERIC, 'uz', exhaustive=True,
                            min_cypher=0.2)
        out = self._get_exhaustive_txt(out, ui, min_cypher=0.2, act="all")
        ui.message("Generic cyphered solutions with cypher factor higher "
                   "than 0.2:")
        ui.message(out)
        ui.message("")

        ui.message("--- Won’t work ---")
        ui.message("+ The obfuscating syllable must comply to the choosen "
                   "method!")
        text = "Hello WORLD !"
        ui.message("Data to cypher, using Javanais and 'eh': {}\n"
                   "".format(text))
        try:
            out = argots.cypher(text, argots.JAVANAIS, 'eh')
            ui.message("Javanais cyphered data: {}".format(out))
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
                exhaustive = False
                threshold = 0.2
                method = argots.JAVANAIS
                syllable = "uz"

                txt = ui.text_input("Text to cypher")
                if txt is None:
                    break  # Go back to main Cypher menu.

                # Get obfuscating method.
                options = [(argots.JAVANAIS,
                            "$javanais cyphering", ""),
                           (argots.FEU, "langue de *feu", ""),
                           (argots.GENERIC, "or *generic one", "")]
                method = ui.get_choice("Do you want to use", options,
                                       oneline=True)
                if method == argots.JAVANAIS:
                    syllable = "av"
                elif method == argots.FEU:
                    syllable = "fe"

                # Get obfuscating syllable.
                s = ui.get_data("Obfuscating syllable (or nothing to use "
                                "default '{}' one): ".format(syllable),
                                allow_void=True,
                                validate=self._validate,
                                validate_kwargs={'method': method})
                if s:
                    syllable = s

                # What algo to use.
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
                    txt = argots.cypher(txt, method, syllable,
                                        exhaustive=exhaustive,
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
                    ui.message(str(e), ui.ERROR)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into "
                                         "atomic digits, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Sema menu.
                    # Else, retry with another data to hide.

            if done:
                meth = "Generic"
                if method == argots.JAVANAIS:
                    meth = "Argot Javanais"
                elif method == argots.FEU:
                    meth = "Langue de Feu"
                ui.text_output("Text successfully converted", txt,
                               "{} version of text".format(meth))

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
            txt = ui.text_input("Please choose some atomic digits text")
            syllable = None
            method = argots.GENERIC

            # Get obfuscating method.
            options = [(argots.JAVANAIS,
                        "*javanais decyphering", ""),
                       (argots.FEU, "langue de *feu", ""),
                       (argots.GENERIC, "or $generic one", "")]
            method = ui.get_choice("Do you want to use", options,
                                   oneline=True)

            # Get obfuscating syllable.
            s = ui.get_data("Obfuscating syllable (or nothing to search "
                            "for the most common one): ", allow_void=True,
                            validate=self._validate,
                            validate_kwargs={'method': method})
            if s:
                syllable = s

            try:
                txt = argots.decypher(txt, method, syllable)
                if len(txt) > 1:
                    txt = "\n    " + \
                          "\n".join(["Using '{}':\n    {}"
                                     "".format(t[0], t[1]) for t in txt])
                elif txt:
                    txt = txt[0][1]
                else:
                    txt = ""
                ui.text_output("Text successfully decyphered",
                               txt, "The decyphered text is")
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


NAME = "argots"
TIP = "Tool to convert text to/from Argot Javanais / Langue de Feu / " \
      "Largonji des Louchébems “codes”."
TYPE = app.cli.Node.TOOL
CLASS = Argots

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Argots")
    Argots(tree).main(ui)

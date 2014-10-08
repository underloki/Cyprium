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
import kernel.stegano.text.sema as sema
import kernel.utils as utils


class Sema(app.cli.Tool):
    """CLI wrapper for sema stegano text tool."""
    marker = b"\xcc\xa3".decode("utf8")

    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Sema! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.hide, "*hide", "Hide some data into a text"),
                       (self.unhide, "*unhide",
                                     "Find the data hidden into the given "
                                     "text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Sema")]
            msg = "Cyprium.Sema"
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
        ui.message(sema.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        text = "“Mes souvenirs sont comme les pistoles dans la bourse du " \
               "diable. Quand on l’ouvrit, on n’y trouva que des feuilles " \
               "mortes. J’ai beau fouiller le passé je n’en retire plus que " \
               "des bribes d’images et je ne sais pas très bien ce qu’elles " \
               "représentent, ni si ce sont des souvenirs ou des fictions.” " \
               "– extrait de « La nausée » de Jean-Paul Sartre."
        marker = self.marker

        ui.message("--- Hiding ---")
        data = "comix"
        ui.message("Text used as source (input file): {}".format(text))
        ui.message("Data to hide: {}\n".format(data))
        ui.message("Text with hidden data (output file): {}"
                   "".format(sema.hide(text, data, marker, 0)))
        ui.message("")

        htext = "“Mes s" + marker + "ouvenirs sont comme les pistoles dans " \
                "la bourse du di" + marker + "able. Quand on l’ouvrit, on " \
                "n’y trouva que des feuilles mo" + marker + "rtes. J’ai " \
                "beau fouiller le passé je n’en retire plus que des bribes " \
                "d’im" + marker + "ages et je ne sais pas très bien ce " \
                "qu’elles représentent, ni si ce sont des sou" + marker + \
                "venirs ou des fictions.” – extrait de « La nausée » de " \
                "Jean-Paul Sar" + marker + "tre."
        ui.message("--- Unhiding ---")
        ui.message("Text used as source (input file): {}".format(htext))
        ui.message("The hidden data is: {}"
                   "".format(sema.unhide(htext, marker, 0)))

        ui.message("--- Won’t work ---")
        ui.message("+ The letters to hide must be present in the input text:")
        data = "zowix"
        ui.message("Text used as source (input file): {}".format(text))
        ui.message("Data to hide: {}".format(data))
        try:
            ui.message("Text with hidden data (output file): {}"
                       "".format(sema.hide(text, data, marker, 0)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)

        ui.message("+ The input text must be long enough for the given data "
                   "to hide (at least 40 times):")
        data = "This is quite a long boring sentence"
        ui.message("Data to hide: {}".format(data))
        try:
            ui.message("Text with hidden data (output file): {}"
                       "".format(sema.hide(text, data, marker, 0)))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)

        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def hide(self, ui):
        """Interactive version of hide()."""
        txt = ""
        ui.message("===== Hide Mode =====")

        while 1:
            done = False
            while not done:
                txt = ui.text_input("Text into which hide data")
                if txt is None:
                    break  # Go back to main Hide menu.

                while 1:
                    data = ui.text_input("Data to hide into the text")
                    try:
                        # Will also raise an exception if data is None.
                        txt = sema.hide(txt, data, self.marker, 0)
                        done = True  # Out of those loops, output result.
                        break
                    except Exception as e:
                        if utils.DEBUG:
                            import traceback
                            traceback.print_tb(sys.exc_info()[2])
                        ui.message(str(e), level=ui.ERROR)
                        options = [("retry", "*try again", ""),
                                   ("file", "choose another *input file", ""),
                                   ("menu", "or go back to *menu", "")]
                        msg = "Could not hide that data into the given " \
                              "text, please"
                        answ = ui.get_choice(msg, options, oneline=True)
                        if answ == "file":
                            break  # Go back to input file selection.
                        elif answ in {None, "menu"}:
                            return  # Go back to main Sema menu.
                        # Else, retry with another data to hide.

            if done:
                ui.text_output("Data successfully hidden", txt,
                               "Text with hidden data")

            options = [("redo", "*hide another data", ""),
                       ("quit", "or go back to $menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ in {None, "quit"}:
                return

    def unhide(self, ui):
        """Interactive version of unhide()."""
        txt = ""
        ui.message("===== Unhide Mode =====")

        while 1:
            txt = ui.text_input("Please choose some text with hidden data")

            if txt is not None:
                try:
                    ui.text_output("Data successfully unhidden",
                                   sema.unhide(txt, self.marker, 0),
                                   "The hidden data is")
                except Exception as e:
                    if utils.DEBUG:
                        import traceback
                        traceback.print_tb(sys.exc_info()[2])
                    ui.message(str(e), level=ui.ERROR)

            options = [("redo", "*unhide another data", ""),
                       ("quit", "or go back to $menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "sema"
TIP = "Tool to hide some text into a much bigger one, " \
      "by placing small dots below some letters."
TYPE = app.cli.Node.TOOL
CLASS = Sema

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Sema")
    Sema(tree).main(ui)

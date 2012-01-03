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

import app.cli
import kernel.stegano.text.sema as sema

class Sema(app.cli.Tool):
    marker = b"\xcc\xa3".decode("utf8")

    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Sema! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.hide, "*hide", "Hide some data into a text"),
                       (self.unhide, "*unhide", "Find the data hidden into the given text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Sema")]
            msg = "Cyprium.Sema"
            answ = ui.get_choice(msg, options)

            if answ == 'tree':
                self._tree.print_tree(ui)
            elif answ == 'quit':
                self._tree.current = self._tree.current.parent
                quit = True
            else:
                answ(ui)
        ui.message("Back to Cyprium menus! Bye.")

    def about(self, ui):
        text = "===== About Sema =====\n\n" \
               "Sema is a steganographic tool which can hide text datas in a " \
               "file, by putting dots (or optionally, another sign) under " \
               "letters.\n" \
               "By this way, it allows you to hide a keychain (a word or a " \
               "sentence) via semagrammas (dots) in a larger text file. This " \
               "technique allows to confuse the reader who won’t see most of " \
               "the dots and will believe that the few ones he sees are " \
               "probably a bug.\n\n" \
               "The max length of the hidden data must be 40 times less longer " \
               "than the input text.\n\n" \
               "Note that only strict ASCII alphanumeric chars are allowed in "\
               "data to hide, any other char will be striped!\n\n" \
               "Example:\n\n" \
               "input file size = 1000 char\n\n" \
               "max length of hidden data = 25 char\n\n" \
               "The path of the input file can be absolute (e.g. for linux, if " \
               "the input file is located on your desktop: " \
               "'/home/admin_name/Desktop/your_input_file'), or relative to the " \
               "dir from where you started Sema.\n\n" \
               "Obviously, the same goes for the output file.\n"

        ui.message(text)
        ui.get_choice("", [("", "Go back to *menu", "")], True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")

        text = "“Mes souvenirs sont comme les pistoles dans la bourse du " \
               "diable. Quand on l’ouvrit, on n’y trouva que des feuilles " \
               "mortes. J’ai beau fouiller le passé je n’en retire plus que des " \
               "bribes d’images et je ne sais pas très bien ce qu’elles " \
               "représentent, ni si ce sont des souvenirs ou des fictions.” " \
               "– extrait de « La nausée » de Jean-Paul Sartre."
        marker = self.marker

        ui.message("--- Hiding ---")
        ui.message("Text used as source (input file): {}".format(text))
        ui.message("Data to hide: {}\n".format("comix"))
        ui.message("Text with hidden data (output file): {}"
                   "".format(sema.hide(text, "comix", marker, 0)))
        ui.message("")

        htext = "“Mes s"+marker+"ouvenirs sont comme les pistoles dans la " \
                "bourse du di"+marker+"able. Quand on l’ouvrit, on n’y " \
                "trouva que des feuilles mo"+marker+"rtes. J’ai beau fouiller " \
                "le passé je n’en retire plus que des bribes d’im"+marker+"ages " \
                "et je ne sais pas très bien ce qu’elles représentent, ni si ce " \
                "sont des sou"+marker+"venirs ou des fictions.” – extrait de " \
                "« La nausée » de Jean-Paul Sar"+marker+"tre."
        ui.message("--- Unhiding ---")
        ui.message("Text used as source (input file): {}".format(htext))
        ui.message("The hidden data is: {}".format(sema.unhide(htext, marker, 0)))

        ui.message("--- Won’t work ---")
        ui.message("+ The letters to hide must be present in the input text:")
        ui.message("Text used as source (input file): {}".format(text))
        ui.message("Data to hide: {}".format("zowix"))
        try:
            ui.message("Text with hidden data (output file): {}"
                       "".format(sema.hide(text, "zowix", marker, 0)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.message("+ The input text must be long enough for the given data to "
                   "hide (at least 40 times):")
        ui.message("Data to hide: {}".format("This is quite a long boring sentence"))
        try:
            ui.message("Text with hidden data (output file): {}"
                       "".format(sema.hide(text, "This is quite a long boring sentence", marker, 0)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)

        ui.get_choice("", [("", "Go back to *menu", "")], True)

    def hide(self, ui):
        """Interactive version of hide()."""
        txt = ""
        done = False
        ui.message("===== Hide Mode =====")

        while not done:
            while 1:
                answ = ui.get_data("Choose an input text file: ")
                try:
                    with open(answ, 'r') as ifile:
                        txt = ifile.read()
                    break;
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again,", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not open that file, please", options, True)
                    if answ != "retry":
                        return

            while 1:
                answ = ui.get_data("Data to hide: ")
                try:
                    txt = sema.hide(txt, answ, self.marker, 0)
                    done = True # Go out of parent loop too!
                    break;
                except Exception as e:
                    print(e)
                    options = [("retry", "*try again,", ""),
                               ("file", "choose another *input file,", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not hide that data into the given text, please", options, True)
                    if answ == "file":
                        break; # Go back to input file selection.
                    elif answ != "retry":
                        return

        while 1:
            answ =  ui.get_data("Choose an output text file: ")
            try:
                with open(answ, 'w') as ofile:
                    ofile.encoding = "utf-8"
                    ofile.write(txt)
                break;
            except Exception as e:
                print(e)
                options = [("retry", "*try again,", ""),
                           ("menu", "or go back to *menu", "")]
                answ = ui.get_choice("Could not open that file, please", options, True)
                if answ != "retry":
                    return

        ui.message("Data successfully hidden in file! Back to Sema menu…")


    def unhide(self, ui):
        """Interactive version of unhide()."""
        txt = ""
        ui.message("===== Unhide Mode =====")

        while 1:
            answ = ui.get_data("Choose an input text file: ")
            try:
                with open(answ, 'r') as ifile:
                    txt = ifile.read()
                break;
            except Exception as e:
                print(e)
                options = [("retry", "*try again,", ""),
                           ("menu", "or go back to *menu", "")]
                answ = ui.get_choice("Could not open that file, please", options, True)
                if answ != "retry":
                    return

        try:
            ui.message("The hidden data is: {}".format(sema.unhide(txt, self.marker, 0)))
        except Exception as e:
            ui.message(str(e), ui.ERROR)
            return

        ui.message("Data successfully unhidden from file! Back to Sema menu…")


NAME  = "*sema"
TIP   = "Tool to hide some text into a much bigger one, by placing small dots below some letters."
TYPE  = app.cli.Node.TOOL
CLASS = Sema


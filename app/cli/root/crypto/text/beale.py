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
import kernel.crypto.text.beale as beale
import kernel.utils as utils


class Beale(app.cli.Tool):
    """CLI wrapper for Beale crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Beale! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text in Beale"),
                       (self.decypher, "d*ecypher",
                                       "Decypher Beale into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Beale")]
            msg = "Cyprium.Beale"
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
        ui.message(beale.__about__)
        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        ui.message("--- Cyphering ---")
        text = "George Washington"
        key = "We the People of the United States, in Order to form a more perfect Union, establish Justice, insure " \
              "domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the " \
              "Blessings of Liberty to ourselves and our Posterity, do ordain and establish this Constitution for " \
              "the United States of America.\n" \
              "\n" \
              "\n" \
              "Article. I.\n" \
              "\n" \
              "Section. 1.\n" \
              "\n" \
              "All legislative Powers herein granted shall be vested in a Congress of the United States, which " \
              "shall consist of a Senate and House of Representatives.\n" \
              "\n" \
              "\n" \
              "Section. 2.\n" \
              "\n" \
              "The House of Representatives shall be composed of Members chosen every second Year by the People of " \
              "the several States, and the Electors in each State shall have the Qualifications requisite for " \
              "Electors of the most numerous Branch of the State Legislature.\n" \
              "\n" \
              "No Person shall be a Representative who shall not have attained to the age of twenty five Years, and " \
              "been seven Years a Citizen of the United States, and who shall not, when elected, be an Inhabitant " \
              "of that State in which he shall be chosen.\n" \
              "\n" \
              "Representatives and direct Taxes shall be apportioned among the several States which may be included " \
              "within this Union, according to their respective Numbers, which shall be determined by adding to the " \
              "whole Number of free Persons, including those bound to Service for a Term of Years, and excluding " \
              "Indians not taxed, three fifths of all other Persons. The actual Enumeration shall be made within " \
              "three Years after the first Meeting of the Congress of the United States, and within every " \
              "subsequent Term of ten Years, in such Manner as they shall by Law direct. The Number of " \
              "Representatives shall not exceed one for every thirty Thousand, but each State shall have at Least " \
              "one Representative; and until such enumeration shall be made, the State of New Hampshire shall be " \
              "entitled to chuse three, Massachusetts eight, Rhode-Island and Providence Plantations one, " \
              "Connecticut five, New-York six, New Jersey four, Pennsylvania eight, Delaware one, Maryland six, " \
              "Virginia ten, North Carolina five, South Carolina five, and Georgia three.\n" \
              "\n" \
              "When vacancies happen in the Representation from any State, the Executive Authority thereof shall " \
              "issue Writs of Election to fill such Vacancies.\n" \
              "\n" \
              "The House of Representatives shall chuse their Speaker and other Officers; and shall have the sole " \
              "Power of Impeachment."
        ui.message("Data to cypher: {}".format(text))
        ui.message("Text used as key: {}".format(key))
        out = beale.cypher(text, key, 0)
        ui.message("Beale cyphered data with seed 0: {}".format(out))
        out = beale.cypher(text, key, 1787)
        ui.message("Beale cyphered data with seed 1787: {}".format(out))
        ui.message("")

        ui.message("--- Decyphering ---")
        # Note: cyphered with seed 350!
        htext = "55, 2, 85, 55, 78, 47, 33, 92, 52, 20, 88, 88, 8, 46, 48, 63"
        key = "Warning: hunt the cat out of your kitchen before you cook this!\n" \
              "\n" \
              "Heat the oven to 350 degrees F (175 degrees C).\n" \
              "Beat butter, white sugar, and brown sugar with an electric mixer in a large bowl until smooth. Beat " \
              "in one egg until completely incorporated; beat in last egg along with vanilla extract. Combine " \
              "flour, cocoa, baking soda, and salt in a bowl. Stir flour mixture into butter mixture until just " \
              "incorporated. Drop spoonfuls of dough 2 inches apart onto ungreased baking sheets.\n" \
              "Bake in preheated oven until edges of cookies are firm, 10 to 12 minutes. Remove to wire racks and " \
              "dust warm cookies with confectioners’ sugar."
        ui.message("Beale text used as input: {}".format(htext))
        ui.message("Text used as key: {}".format(key))
        out = beale.decypher(htext, key)
        ui.message("The decyphered data is: {}".format(out))
        ui.message("")

        ui.message("--- Won’t work ---")
        text = "Mayflower"
        key = "The Mayflower was the ship that transported English and Dutch Separatists and other adventurers " \
              "referred to by the Separatists as “the Strangers” to Plymouth, Massachusetts in 1620."
        ui.message("+ The cyphering key must contain words starting with all (ASCII) letters found in the text to "
                   "cypher (preferably several words for each letter):")
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Text used as key: {}".format(key))
        try:
            out = beale.cypher(text, key)
            ui.message("Beale cyphered data: {}".format(out))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("+ You can enter anything as text to decypher, but only the numbers in it will be taken into "
                   "account. Those numbers must be in the number of words in the key’s range:")
        htext = "At the 136th day of the year 181 of the 167 Heroes area, 129 sword men and 196 riders crossed the " \
                "11 Sand Sees to defeat the 666 warriors of the Dark Witch." # Last number should be 277!
        key = "In 17th century colonial North America, the supernatural was part of everyday life, for there was a " \
              "strong belief that Satan was present and active on Earth. This concept emerged in Europe around the " \
              "fifteenth century and spread to North America when it was colonized. Witchcraft was then used by " \
              "peasants, who invoked particular charms for farming and agriculture. Over time, the idea of white " \
              "magic transformed into dark magic and became associated with demons and evil spirits. From 1560 to " \
              "1670, witchcraft persecutions became common as superstitions became associated with the devil. In " \
              "“Against Modern Sadducism” (1668), Joseph Glanvill claimed that he could prove the existence of " \
              "witches and ghosts of the supernatural realm. Glanvill wrote about the “denial of the bodily " \
              "resurrection, and the [supernatural] spirits”. In his treatise, he claimed that ingenious men should " \
              "believe in witches and apparitions; if they doubted the reality of spirits, they not only denied " \
              "demons, but also the almighty God. Glanvill wanted to prove that the supernatural could not be " \
              "denied; those who did deny apparitions were considered heretics for it also disproved their beliefs " \
              "in angels. Works by men such as Glanvill and Cotton Mather tried to prove to humanity that “demons " \
              "were alive”, which played on the fears of individuals who believed that demons were active among " \
              "them on Earth.\n" \
              "\n" \
              "Men and women in Salem believed that all the misfortunes were attributed to the work of the devil; " \
              "when things like infant death, crop failures or friction among the congregation occurred, the " \
              "supernatural was blamed. Because of the unusual size of the outbreak of witchcraft accusations, " \
              "various aspects of the historical context of this episode have been considered as specific " \
              "contributing factors."
        ui.message("Beale cypher used as input: {}".format(htext))
        ui.message("Text used as key: {}".format(key))
        try:
            out = beale.decypher(htext, key)
            ui.message("Beale decyphered data: {}".format(out))
        except Exception as e:
            ui.message(str(e), level=ui.ERROR)
        ui.message("")

        ui.message("Don’t expect any decyphering without the key – it’s just impossible to hack!", level=ui.WARNING)
        ui.message("")

        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                txt = ui.text_input("Text to cypher to Beale")
                if txt is None:
                    break  # Go back to main Cypher menu.
                key = ui.text_input("Cyphering key")
                if key is None:
                    break  # Go back to main Cypher menu.
                seed = ui.get_data("Random seed (any integer, defaults to 0): ", sub_type=ui.INT, allow_void=True)
                if seed is None:
                    seed = 0

                try:
                    # Will also raise an exception if data is None.
                    txt = beale.cypher(txt, key, seed)
                    done = True  # Out of those loops, output result.
                    break
                except Exception as e:
                    if utils.DEBUG:
                        import traceback
                        traceback.print_tb(sys.exc_info()[2])
                    ui.message(str(e), level=ui.ERROR)
                    options = [("retry", "*try again", ""),
                               ("menu", "or go back to *menu", "")]
                    answ = ui.get_choice("Could not convert that data into Beale, please", options, oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Beale menu.
                    # Else, retry with another data to cypher.

            if done:
                ui.text_output("Text successfully converted", txt, "Beale version of text")

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
            txt = ui.text_input("Please choose some Beale cypher")
            key = ui.text_input("Cyphering key")

            try:
                ui.text_output("Text successfully decyphered", beale.decypher(txt, key), "The decyphered text is")
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


NAME = "beale"
TIP = "Tool to convert text to/from Beale cypher."
TYPE = app.cli.Node.TOOL
CLASS = Beale

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Beale")
    Beale(tree).main(ui)

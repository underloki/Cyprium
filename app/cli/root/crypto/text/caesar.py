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
import kernel.crypto.text.caesar as caesar
import kernel.utils as utils


class Caesar(app.cli.Tool):
    """CLI wrapper for caesar crypto text tool."""
    def main(self, ui):
        ui.message("********** Welcome to Cyprium.Caesar! **********")
        quit = False
        while not quit:
            options = [(self.about, "*about", "Show some help!"),
                       (self.demo, "*demo", "Show some examples"),
                       (self.cypher, "*cypher",
                                     "Cypher some text with caesar"),
                       (self.decypher, "d*ecypher",
                                       "Decypher caesar into text"),
                       ("", "-----", ""),
                       ("tree", "*tree", "Show the whole tree"),
                       ("quit", "*quit", "Quit Cyprium.Caesar")]
            msg = "Cyprium.Caesar"
            answ = ui.get_choice(msg, options=options)

            if answ == 'tree':
                self._tree.print_tree(ui, self._tree.FULL)
            elif answ == 'quit':
                self._tree.current = self._tree.current.parent
                quit = True
            else:
                answ(ui)
        ui.message("Back to Cyprium menus! Bye.")

    def about(self, ui):
        ui.message(caesar.__about__)
        ui.get_choice("", options=[("", "Go back to $menu", "")], oneline=True)

    def demo(self, ui):
        ui.message("===== Demo Mode =====")
        ui.message("Running a small demo/testing!")
        ui.message("")

        text = "JULE CAESAR WAS A FAMOUS ROMAN GENERAL"
        ui.message("--- Cyphering ---")
        ui.message("(Note: you can cypher a same text with different "
                   "algorithms/keys at once.)")
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Caesar Basic cyphered data, key 13: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_BASIC, 13)))
        ui.message("Caesar Progressive cyphered data, geometric progression, "
                   "key 7: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_PROGRESS, 7,
                             caesar.PROGRESS_GEOMETRIC)))
        ui.message("Caesar Progressive cyphered data, shifted unitary "
                   "progression, key 5: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_PROGRESS, 5,
                             caesar.PROGRESS_SHIFT)))
        ui.message("Caesar Square cyphered data, squarish square: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_SQUARE, None,
                             caesar.SQUARE_SQUARE)))
        ui.message("Caesar Square cyphered data, constant width “square”, "
                   "key 3: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_SQUARE, 3,
                             caesar.SQUARE_CONSTWIDTH)))
        ui.message("Caesar Square cyphered data, constant high “square”, "
                   "key 3: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_SQUARE, 3,
                             caesar.SQUARE_CONSTHIGH)))
        text = text.replace(' ', '')
        ui.message("Please note, however, that space-less data will be much "
                   "harder to hack. With progressive algorithm, it even "
                   "completely changes the results (and square algo always "
                   "removes them, anyway!):")
        ui.message("Data to cypher: {}\n".format(text))
        ui.message("Caesar Basic cyphered data, key 13: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_BASIC, 13)))
        ui.message("Caesar Progressive cyphered data, geometric progression, "
                   "key 7: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_PROGRESS, 7,
                             caesar.PROGRESS_GEOMETRIC)))
        ui.message("Caesar Progressive cyphered data, shifted unitary "
                   "progression, key 5: {}"
                   "".format(caesar.cypher(text, caesar.ALGO_PROGRESS, 5,
                             caesar.PROGRESS_SHIFT)))
        ui.message("")

        htext = "JSEAUAOUANERSLLRCSACIITOPNETOANATNICMSNESCABCASOOEIODUP"
        ui.message("--- Decyphering ---")
        ui.message("In addition to usual known algo/key uncyphering, Caesar "
                   "can also hack himself! It will then propose you all "
                   "possible outputs, sorted by relevance.")
        ui.message("Caesar text used as input: {}".format(htext))
        out = caesar.decypher(htext, None, None, None)
        t = sorted(out, key=lambda o: o[5], reverse=True)
        out = []
        algos = caesar.TXT_ALGOS_MAP
        alg_len = caesar.TXT_ALGO_MAP_MAXLEN
        methods = caesar.TXT_METHODS_MAP
        met_len = caesar.TXT_MATHODS_MAP_MAXLEN
        pattern = caesar.TXT_HACKSOLUTIONS_PATTERN
        for algo, method, key, res, lng, avg in t:
            out += (pattern.format(avg, lng, algos[algo],
                                   methods[method], key,
                                   alg_len=alg_len, met_len=met_len),
                    ui.INDENT + res)
        ui.message("Best solutions found are:\n\n" + "\n\n".join(out[:20]))
        ui.message("Note: In real situation, you’ll have the choice to see "
                   "more solutions if you like! ;)")
        ui.message("")

#        ui.message("--- Won’t work ---")
#        ui.message("+ The input text to cypher must be acsii lowercase "
#                   "letters only:")
#        ui.message("Data to cypher: {}\n".format("Hello Wolrd!"))
#        try:
#            ui.message("Celldrawer cyphered data: {}"
#                       "".format(celldrawer.cypher("Hello World!")))
#        except Exception as e:
#            ui.message(str(e), level=ui.ERROR)
#        ui.message("")

#        ui.message("+ The input text to decypher must be phone digits only:")
#        htext = "123580 147*369#8 321457*0#  1N7*369#8 *74269#8 32470# " \
#                "147*538# *74269#8 *7412690 321457*0# *741k369# 15380!"
#        ui.message("Celldrawer text used as input: {}".format(htext))
#        try:
#            ui.message("The decyphered data is: {}"
#                       "".format(celldrawer.decypher(htext)))
#        except Exception as e:
#            ui.message(str(e), level=ui.ERROR)
#        ui.message("")

        ui.get_choice("", [("", "Go back to $menu", "")], oneline=True)

    @staticmethod
    def _cypher(txt, algos, methods, keys, ui):
        _txt = {caesar.ALGO_BASIC: {caesar.BASIC_BASIC: []},
                caesar.ALGO_PROGRESS: {caesar.PROGRESS_GEOMETRIC: [],
                                       caesar.PROGRESS_SHIFT: []},
                caesar.ALGO_SQUARE: {caesar.SQUARE_SQUARE: [],
                                     caesar.SQUARE_CONSTWIDTH: [],
                                     caesar.SQUARE_CONSTHIGH: []},
               }
        nbr = 0
        for algo in algos:
            for method in methods[algo]:
                # XXX This is rather hackish, ugly and weak...
                #     But simplest solution I found so far. :/
                if method == caesar.SQUARE_SQUARE:
                    _txt[algo][method] = \
                        [("", caesar.cypher(txt, algo, None, method))]
                else:
                    _txt[algo][method] = \
                        [(k, caesar.cypher(txt, algo, k, method))
                         for k in keys[algo]]
                nbr += len(_txt[algo][method])

        txt = []
        for algo in algos:
            for method in methods[algo]:
                if not _txt[algo][method]:
                    continue
                elif nbr > 1:
                    txt.append(" ".join((caesar.TXT_ALGOS_MAP[algo],
                                         caesar.TXT_METHODS_MAP[method])))
                    txt += ("{}{: >4}: {}".format(ui.INDENT, k, t)
                            for k, t in _txt[algo][method])
                else:
                    txt += (t for k, t in _txt[algo][method])
        return "\n".join(txt)

    def cypher(self, ui):
        """Interactive version of cypher()."""
        txt = ""
        ui.message("===== Cypher Mode =====")

        while 1:
            done = False
            while 1:
                v, vkw = ui.validate_charset, {"charset": caesar.DIC_CHARSET,
                                               "charmap": caesar.DIC_CHARMAP}
                txt = ui.text_input("Text to cypher with caesar",
                                    sub_type=ui.UPPER,
                                    validate=v, validate_kwargs=vkw)
                if txt is None:
                    break  # Go back to main Cypher menu.

                algos = []
                methods = {}  # Only used by progressive and square!
                keys = {}

                options = ((caesar.ALGO_BASIC, "*basic", ""),
                           (caesar.ALGO_PROGRESS, "*progressive", ""),
                           (caesar.ALGO_SQUARE, "and/or *square", ""))
                t = set(ui.get_choice("Which cyphering algorithm(s) do you"
                                      "want to use,", options,
                                      oneline=True, multichoices=','))
                if caesar.ALGO_BASIC in t:
                    a = caesar.ALGO_BASIC
                    algos.append(a)
                    v = ui.validate_number_range
                    vkw = {"minnbr": 1, "maxnbr": 25}
                    tk = ui.text_input("Key(s) to use for basic caesar"
                                       "([1 … 25])", indent=1,
                                       no_file=True, sub_type=ui.INT_LIST,
                                       validate=v, validate_kwargs=vkw)
                    keys[a] = sorted(tk)
                    methods[a] = (caesar.BASIC_BASIC,)
                if caesar.ALGO_PROGRESS in t:
                    a = caesar.ALGO_PROGRESS
                    algos.append(a)
                    v = ui.validate_number_range
                    vkw = {"minnbr": 1, "maxnbr": 25}
                    options = ((caesar.PROGRESS_GEOMETRIC,
                                "*geometric progression", ""),
                               (caesar.PROGRESS_SHIFT,
                                "and/or *shifted unitary progression", ""))
                    tt = set(ui.get_choice("Which progressive method(s) do "
                                           "you want to use,", indent=1,
                                           options=options,
                                           oneline=True, multichoices=','))
                    methods[a] = []
                    if caesar.PROGRESS_GEOMETRIC in tt:
                        methods[a].append(caesar.PROGRESS_GEOMETRIC)
                    if caesar.PROGRESS_SHIFT in tt:
                        methods[a].append(caesar.PROGRESS_SHIFT)
                    tk = ui.text_input("Key(s) to use for progressive"
                                       "caesar ([1 … 25])", no_file=True,
                                       indent=1, sub_type=ui.INT_LIST,
                                       validate=v, validate_kwargs=vkw)
                    keys[a] = sorted(tk)
                if caesar.ALGO_SQUARE in t:
                    a = caesar.ALGO_SQUARE
                    algos.append(a)
                    v = ui.validate_number_range
                    vkw = {"minnbr": 2,
                           "maxnbr": caesar.square_max_key(txt)}
                    options = ((caesar.SQUARE_SQUARE, "*squarish", ""),
                               (caesar.SQUARE_CONSTWIDTH, "fixed *width", ""),
                               (caesar.SQUARE_CONSTHIGH,
                                "and/or fixed *high square", ""))
                    tt = set(ui.get_choice("Which square variant(s) do "
                                           "you want to use,", indent=1,
                                           options=options,
                                           oneline=True, multichoices=','))
                    methods[a] = []
                    keys[a] = []
                    if caesar.SQUARE_SQUARE in tt:
                        methods[a].append(caesar.SQUARE_SQUARE)
                    if ({caesar.SQUARE_CONSTWIDTH, caesar.SQUARE_CONSTHIGH} &
                        tt):
                        tk = ui.text_input("Key(s) to use for non-squarish"
                                           "square caesar ([2 … {}])"
                                           "".format(vkw["maxnbr"]),
                                           sub_type=ui.INT_LIST,
                                           no_file=True, indent=1,
                                           validate=v, validate_kwargs=vkw)
                        keys[a] = sorted(tk)
                        if caesar.SQUARE_CONSTWIDTH in tt:
                            methods[a].append(caesar.SQUARE_CONSTWIDTH)
                        if caesar.SQUARE_CONSTHIGH in tt:
                            methods[a].append(caesar.SQUARE_CONSTHIGH)

                try:
                    txt = self._cypher(txt, algos, methods, keys, ui)
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
                                         "caesar, please", options,
                                         oneline=True)
                    if answ in {None, "menu"}:
                        return  # Go back to main Caesar menu.
                    # Else, retry with another data to hide.

            if done:
                ui.text_output("Text successfully converted", txt,
                               "Caesar version(s) of text")

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
            v, vkw = ui.validate_charset, {"charset": caesar.VALID_CHARSET}
            txt = ui.text_input("Text to uncypher with caesar",
                                sub_type=ui.UPPER,
                                validate=v, validate_kwargs=vkw)

            algos = None
            methods = None  # Always tray all methods!
            keys = None  # Keys common to all algos.

            options = ((caesar.ALGO_BASIC, "*basic", ""),
                       (caesar.ALGO_PROGRESS, "*progressive", ""),
                       (caesar.ALGO_SQUARE, "*square", ""),
                       (None, "and/or *all", ""))
            t = set(ui.get_choice("Which uncyphering algorithm(s) do you "
                                  "want to try,", options,
                                  oneline=True, multichoices=','))
            if None not in t:
                algos = t

            if algos and len(algos) == 1:
                if caesar.ALGO_BASIC in algos:
                    v = ui.validate_number_range
                    vkw = {"minnbr": 1, "maxnbr": 25}
                    tk = ui.text_input("Key(s) to use for basic caesar"
                                       "([1 … 25])", indent=1, no_file=True,
                                       sub_type=ui.INT_LIST,
                                       validate=v, validate_kwargs=vkw)
                    keys = sorted(tk)
                    methods = (caesar.BASIC_BASIC,)
                elif caesar.ALGO_PROGRESS in algos:
                    v = ui.validate_number_range
                    vkw = {"minnbr": 1, "maxnbr": 25}
                    options = ((caesar.PROGRESS_GEOMETRIC,
                                "*geometric progression", ""),
                               (caesar.PROGRESS_SHIFT,
                                "and/or *shifted unitary progression", ""))
                    tt = set(ui.get_choice("Which progressive method(s) do "
                                           "you want to try,", indent=1,
                                           options=options,
                                           oneline=True, multichoices=','))
                    methods = []
                    if caesar.PROGRESS_GEOMETRIC in tt:
                        methods.append(caesar.PROGRESS_GEOMETRIC)
                    if caesar.PROGRESS_SHIFT in tt:
                        methods.append(caesar.PROGRESS_SHIFT)
                    tk = ui.text_input("Key(s) to use for progressive"
                                       "caesar ([1 … 25])", no_file=True,
                                       indent=1, sub_type=ui.INT_LIST,
                                       validate=v, validate_kwargs=vkw)
                    keys = sorted(tk)
                elif caesar.ALGO_SQUARE in algos:
                    v = ui.validate_number_range
                    vkw = {"minnbr": 2,
                           "maxnbr": caesar.square_max_key(txt)}
                    options = ((caesar.SQUARE_SQUARE, "*squarish", ""),
                               (caesar.SQUARE_CONSTWIDTH, "fixed *width", ""),
                               (caesar.SQUARE_CONSTHIGH,
                                "and/or fixed *high square", ""))
                    tt = set(ui.get_choice("Which square variant(s) do "
                                           "you want to try,", indent=1,
                                           options=options,
                                           oneline=True, multichoices=','))
                    methods = []
                    keys = []
                    if caesar.SQUARE_SQUARE in tt:
                        methods.append(caesar.SQUARE_SQUARE)
                    if ({caesar.SQUARE_CONSTWIDTH, caesar.SQUARE_CONSTHIGH} &
                        tt):
                        tk = ui.text_input("Key(s) to use for non-squarish"
                                           "square caesar ([2 … {}])"
                                           "".format(vkw["maxnbr"]),
                                           sub_type=ui.INT_LIST,
                                           no_file=True, indent=1,
                                           validate=v, validate_kwargs=vkw)
                        keys = sorted(tk)
                        if caesar.SQUARE_CONSTWIDTH in tt:
                            methods.append(caesar.SQUARE_CONSTWIDTH)
                        if caesar.SQUARE_CONSTHIGH in tt:
                            methods.append(caesar.SQUARE_CONSTHIGH)
            elif not algos or caesar.ALGO_SQUARE in algos:
                v = ui.validate_number_range
                vkw = {"minnbr": 2,
                       "maxnbr": max(25, caesar.square_max_key(txt))}
                tk = ui.text_input("Key(s) to use for caesar ([2 … {}], or "
                                   "nothing)".format(vkw["maxnbr"]),
                                   indent=1, sub_type=ui.INT_LIST,
                                   allow_void=True, no_file=True,
                                   validate=v, validate_kwargs=vkw)
                if tk:
                    keys = sorted(tk)
            else:
                v = ui.validate_number_range
                vkw = {"minnbr": 2, "maxnbr": 25}
                tk = ui.text_input("Key(s) to use for caesar ([2 … {}])"
                                   "".format(vkw["maxnbr"]), no_file=True,
                                   indent=1, sub_type=ui.INT_LIST,
                                   validate=v, validate_kwargs=vkw)
                keys = sorted(tk)

            try:
                out = caesar.decypher(txt, algos, methods, keys)
            except Exception as e:
                if utils.DEBUG:
                    import traceback
                    traceback.print_tb(sys.exc_info()[2])
                ui.message(str(e), level=ui.ERROR)

            if algos and len(algos) == 1 and keys and len(keys) == 1:
                ui.text_output("Text successfully decyphered", out,
                               "The decyphered text is")
            else:
                t = sorted(out, key=lambda o: o[5], reverse=True)
                out = []
                algos = caesar.TXT_ALGOS_MAP
                alg_len = caesar.TXT_ALGO_MAP_MAXLEN
                methods = caesar.TXT_METHODS_MAP
                met_len = caesar.TXT_MATHODS_MAP_MAXLEN
                pattern = caesar.TXT_HACKSOLUTIONS_PATTERN
                for algo, method, key, res, lng, avg in t:
                    out += (pattern.format(avg, lng, algos[algo],
                                           methods[method], key,
                                           alg_len=alg_len, met_len=met_len),
                            ui.INDENT + res)
                ui.text_output("Text successfully decyphered", out,
                               "Best solutions found are", maxlen=200,
                               multiline=True, multiblocks=20)

            options = [("redo", "*decypher another data", ""),
                       ("quit", "or go back to *menu", "")]
            answ = ui.get_choice("Do you want to", options, oneline=True)
            if answ == "quit":
                return


NAME = "caesar"
TIP = "Tool to convert text to/from caesar code variants."
TYPE = app.cli.Node.TOOL
CLASS = Caesar

# Allow tool to be used directly, without using Cyprium menu.
if __name__ == "__main__":
    import app.cli.ui
    ui = app.cli.ui.UI()
    tree = app.cli.NoTree("Caesar")
    Caesar(tree).main(ui)

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


import sys, os, os.path
import importlib


#le BADPLATFORMS pour signaler les os sur lesquels un module ne tourne.
class Node:
    """A category/tool."""

    # The node type.
    CATEGORY = 1
    TOOL     = 2

    def __init__(self, tree, parent, module):
        self.tree = tree
        self.parent = parent
        self.children = []
        self.module = module
        self.name = module.NAME
        self.tip = module.TIP
        self.type = module.TYPE
        if hasattr(module, "CLASS"):
            self.obj = module.CLASS(self.tree)
        else:
            self.obj = None

        # Now find all sub-modules/-packages.
        if hasattr(self.module, "__file__") and self.type == self.CATEGORY:
            path, fn = os.path.split(self.module.__file__)
            # If that module is indeed a package.
            if fn == "__init__.py":
                for el in os.listdir(path):
                    if el in ("__init__.py", "__pycache__"):
                        continue
                    p = os.path.join(path, el)
                    # import sub packages
                    if not (os.path.isdir(p) or (os.path.isfile(p) and el[-3:] == ".py")):
                        continue
                    if os.path.isfile(p):
                        el = el[:-3]

                    try:
                        m = importlib.import_module(".".join((self.module.__name__, el)))
                        self.children.append(Node(self.tree, self, m))
                    except Exception as e:
                        print(e)


class Tree:
    """Class representing the whole tool tree."""

    # Print tree modes.
    COMPACT = 1
    FULL = 2

    # Welcome
    MSG_WELCOME = "" \
    "########################################################################\n"\
    "#                                                                      #\n"\
    "#   Cyprium is a multifunction cryptographic, steganographic and       #\n"\
    "#   cryptanalysis tool developped by members of The Hackademy.         #\n"\
    "#   French White Hat Hackers Community!                                #\n"\
    "#   www.thehackademy.fr                                                #\n"\
    "#   Copyright © 2012                                                   #\n"\
    "#   Authors: SAKAROV, Madhatter, mont29, Luxerails, PauseKawa, fred,   #\n"\
    "#   afranck64, Tyrtamos.                                               #\n"\
    "#   Contact: cyprium@thehackademy.fr, sakarov@thehackademy.fr,         #\n"\
    "#   madhatter@thehackademy.fr, mont29@thehackademy.fr,                 #\n"\
    "#   irc.thehackademy.fr #cyprium, irc.thehackademy.fr #hackademy       #\n"\
    "#                                                                      #\n"\
    "#   This is free software under GNU GPL licence.                       #\n"\
    "#   You are welcome to redistribute it under the GNU GPL conditions.   #\n"\
    "#                                                                      #\n"\
    "########################################################################\n"\

    def __init__(self, root):
        self._root = Node(self, None, root)
        self._current = self._root


    def get_root(self):
        return self._root

    root = property(get_root, doc="Root Node.")


    def get_current(self):
        return self._current

    def set_current(self, node):
        self._current = node

    current = property(get_current, set_current,
                       doc="Current Node (tool or category) in menu.")


    def print_tree(self, ui, mode=COMPACT):
        """Print the whole tree, with current node if set."""
        pass

    def main(self, ui):
        """Print a menu (choices) with current level nodes."""
        ui.message(self.MSG_WELCOME)

        quit = False
        while not quit:
            if self._current.obj:
                self._current.obj.main(ui)
            else:
                print("In Tree.main()!")
                options = []
                for n in self._current.children:
                    options.append((n, n.name, n.tip))
                options += [("", "-----", ""),
                            ("tree", "*tree", "Show the whole tree"),
                            ("back", "*back", "Go back one level"),
                            ("quit", "*quit", "Quit Cyprium")]
                answ = ui.get_choice("temp", options)
                if answ == 'quit':
                    quit = True
                elif answ == 'tree':
                    self.print_tree(ui)
                elif answ == 'back':
                    if self._current.parent:
                        self._current = self._current.parent
                else:
                    self._current = answ
                    print(self.current)

        ui.message("Goodbye !")


class Tool:
    """CLI class wrapping a tool."""

    def __init__(self, tree):
        self._tree = tree

    def print_tree(self, ui, mode=Tree.COMPACT):
        """Print the whole tree, with current node if set."""
        pass

    def main(self, ui):
        """Entry point of the tool (main menu)."""
        pass

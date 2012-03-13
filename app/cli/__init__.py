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
import importlib

import kernel.utils as utils
import settings


class Node:
    """A category/tool."""

    # The node type.
    CATEGORY = 1
    TOOL = 2

    def __init__(self, tree, parent, module):
        self.tree = tree
        self.parent = parent
        self.children = []
        self.module = module
        if hasattr(module, "NAME"):
            self.name = module.NAME
            self.tip = module.TIP
            self.type = module.TYPE
        else:
            self.name = ""
            self.tip = ""
            self.type = None
        self.clean_name = self.name.replace('*', '').replace('$', '')
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
                    if not (os.path.isdir(p) or \
                       (os.path.isfile(p) and el[-3:] == ".py")):
                        continue
                    if os.path.isfile(p):
                        el = el[:-3]

                    try:
                        m = importlib.import_module( \
                                      ".".join((self.module.__name__, el)))
                        self.children.append(Node(self.tree, self, m))
                    except Exception as e:
                        if utils.DEBUG:
                            import traceback
                            traceback.print_tb(sys.exc_info()[2])
                        print(e)

    def is_descendant(self, node):
        """Check whether the given node is a descendant of self."""
        for n in self.children:
            if n is node or n.is_descendant(node):
                return True
        return False

    def sort_children(self):
        """Sort children nodes (first categorie, then tools ones)."""
        t_cats = []
        t_tools = []
        for c in self.children:
            c.sort_children()
            if c.type == self.CATEGORY:
                t_cats.append(c)
            else:
                t_tools.append(c)
        key = lambda c: c.clean_name
        self.children = sorted(t_cats, key=key) + sorted(t_tools, key=key)


class Tree:
    """Class representing the whole tool tree."""

    # Print tree modes.
    COMPACT = 1
    FULL = 2

    # Print tree, current node marker.
    CURR_MARKER = "  <<<"

    # XXX Find a nice way to avoid > 80 char lines...
    MSG_LOGO = "\n" \
    "     01000   011  011  110010   111000   00111001 00    11 0      1   \n"\
    "    00   10   11  10   10   10  11   01     10    10    01 00    00   \n"\
    "   00     1    1000    10    01 11    10    01    00    10 000  001   \n"\
    "   01           01     00   01  10   10     00    01    10 01 01 00   \n"\
    "   10           00     00010    010000      11    00    00 10    11   \n"\
    "   00     0     11     01       10    1     01    10    11 00    00   \n"\
    "    10   11     00     10       00    11    00     1    0  10    11   \n"\
    "     01101      01     11       10    01 00100000   0010   00    01   \n"

    MSG_WELCOME = "" \
    "######################################################################\n"\
    "#                                                                    #\n"\
    "#   Cyprium is a multifunction cryptographic, steganographic and     #\n"\
    "#   cryptanalysis tool developped by members of The Hackademy.       #\n"\
    "#   French White Hat Hackers Community!                              #\n"\
    "#   www.thehackademy.fr                                              #\n"\
    "#   Copyright © 2012                                                 #\n"\
    "#   Authors: SAKAROV, Madhatter, mont29, Luxerails, PauseKawa, fred, #\n"\
    "#   afranck64, Tyrtamos.                                             #\n"\
    "#   Contact: cyprium@thehackademy.fr, sakarov@thehackademy.fr,       #\n"\
    "#   madhatter@thehackademy.fr, mont29@thehackademy.fr,               #\n"\
    "#   irc.thehackademy.fr #cyprium, irc.thehackademy.fr #hackademy     #\n"\
    "#                                                                    #\n"\
    "#   This is free software under GNU GPL licence.                     #\n"\
    "#   You are welcome to redistribute it under the GNU GPL conditions. #\n"\
    "#                                                                    #\n"\
    "######################################################################\n"\


    WARNINGS = ""
    if sys.platform == 'darwin':  # = Mac OS X
        WARNINGS = "Mac OS X console: at most 1024 chars per entry!"

    ###########################################################################
    # Init.
    ###########################################################################
    def __init__(self, root):
        self._root = Node(self, None, root)
        self._root.sort_children()
        self._current = self._root

    ###########################################################################
    # Main entry point.
    ###########################################################################
    def main(self, ui):
        """Print a menu (choices) with current level nodes."""
        import time

        dl = settings.UI_SPLASH_DELAY / 1000
        ui.message(self.MSG_LOGO)
        time.sleep(dl)
        ui.message(self.MSG_WELCOME)
        if self.WARNINGS:
            ui.message(self.WARNINGS, ui.WARNING)
        time.sleep(dl)

        quit = False
        while not quit:
            if self._current.obj:
                try:
                    self._current.obj.main(ui)
                except Exception as e:
                    if utils.DEBUG:
                        import traceback
                        traceback.print_tb(sys.exc_info()[2])
                    ui.message(str(e), level=ui.ERROR)
            else:
                options = []
                idx = 1
                for n in self._current.children:
                    if n.type == Node.TOOL:
                        name = "*{}*{} {}".format(idx, " " if idx < 10 else "",
                                                  n.clean_name)
                        idx += 1
                    else:
                        name = n.name
                    options.append((n, name, n.tip))
                options += [("", "-----", ""),
                            ("about", "*about", "Show Cyprium info"),
                            ("tree", "*tree", "Show the whole tree"),
                            ("back", "*back", "Go back one level"),
                            ("quit", "*quit", "Quit Cyprium")]
                msg = "Cyprium -*- {}".format(self.breadcrumbs())
                answ = ui.get_choice(msg, options=options)
                if answ == 'quit':
                    quit = True
                elif answ == 'tree':
                    self.print_tree(ui, mode=self.FULL)
                elif answ == 'back':
                    if self._current.parent:
                        self._current = self._current.parent
                elif answ == 'about':
                    ui.message(self.MSG_LOGO)
                    ui.message(self.MSG_WELCOME)
                else:
                    self._current = answ

        ui.message("Goodbye !")

    ###########################################################################
    # Properties.
    ###########################################################################
    def get_root(self):
        return self._root

    root = property(get_root, doc="Root Node.")

    def get_current(self):
        return self._current

    def set_current(self, node):
        if (self._root.is_descendant(node)):
            self._current = node

    current = property(get_current, set_current,
                       doc="Current Node (tool or category) in menu.")

    ###########################################################################
    # Tree drawing.
    ###########################################################################
    def breadcrumbs(self):
        """Return a one-line string with "path" to current node."""
        chain = [self._current]
        while chain[0].parent:
            chain.insert(0, chain[0].parent)
        return "/".join([n.clean_name for n in chain])

    def print_tree(self, ui, mode=COMPACT):
        """Print the whole tree, with current node if set."""
        if mode == self.COMPACT:
            ui.message(self.breadcrumbs())
        else:
            def rec(tree, lines, lvl, node):
                if node.type == Node.CATEGORY:
                    elts = ["    " * lvl, "/", node.clean_name]
                else:
                    elts = ["    " * lvl, "* ", node.clean_name]
                if tree._current == node:
                    elts.append(self.CURR_MARKER)
                lines.append("".join(elts))
                for child in node.children:
                    rec(tree, lines, lvl + 1, child)

            lines = []
            rec(self, lines, 0, self.root)
            ui.message("\n".join(lines))


class NoTree(Tree):
    """Fake Tree class used when a Tool is called directly."""

    def __init__(self, name):
        self._root = Node(self, None, None)
        self._current = self._root
        self._name = name

    ###########################################################################
    # Main entry point.
    ###########################################################################
    def main(self, ui):
        """Dummy void func."""
        return

    ###########################################################################
    # Tree drawing.
    ###########################################################################
    def breadcrumbs(self):
        """Return a one-line string with "path" to current node."""
        return "/{}".format(self._name)

    def print_tree(self, ui, mode=Tree.COMPACT):
        """Print the whole tree, with current node if set."""
        if mode == self.COMPACT:
            ui.message(self.breadcrumbs())
        else:
            ui.message("{}{}".format(self._name, self.CURR_MARKER))


class Tool:
    """CLI class wrapping a tool."""

    def __init__(self, tree):
        self._tree = tree

    def print_tree(self, ui, mode=Tree.COMPACT):
        """Print the whole tree, with current node if set."""
        self._tree.print_tree(ui, mode)

    def main(self, ui):
        """Entry point of the tool (main menu)."""
        pass

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

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils

__version__ = "0.5.0"
__date__ = "2012/01/08"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About Sema =====

Sema is a steganographic tool which can hide text datas in a file, by
putting dots (or optionally, another sign) under letters.
By this way, it allows you to hide a keychain (a word or a sentence)
via semagrammas (dots) in a larger text file. This technique allows
to confuse the reader who won’t see most of the dots and will believe
that the few ones he sees are probably a bug.

The max length of the hidden data must be 40 times less longer than the
input text.

Note that only strict ASCII alphanumeric chars are allowed in data to
hide, any other char will be striped!

Example:
input file size = 1000 char
max length of hidden data = 25 char

The path of the input file can be absolute (e.g. for linux, if the input
file is on your desktop: '/home/admin_name/Desktop/your_input_file'), or
relative to the dir from where you started Sema.

Obviously, the same goes for the output file.

Cyprium.Sema version {} ({}).
Licence GPL3.
software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


# We assume text/data length has already been checked, that marker is a valid
# utf8 char, and that delta is low enough (I’d say len(data) * 2 at most…).
def do_hide(text, data, marker, delta):
    """Hide data into text, using marker, and optionally an obfuscating delta.
    """
    # Be sure we have all needed chars in the text!
    c_needed = set(data)
    c_available = set(text)
    if not c_needed <= c_available:
        raise Exception("Letters '{}' were not found in the text!"
                        "".format("', '".join(sorted(c_needed - c_available))))

    # Now, we have all needed letters.
    # But they might be not placed well!
    # So, make two tries, first a nicely distributed one,
    # then a "simplest" one.
    org_text = text
    len_text = len(text)
    ln_chunk = len_text // len(data)
    cur = max(0, -delta)
    failed = False
    for i, c in enumerate(data):
        cur = max(cur, (ln_chunk * i) + i)
        idx = text.find(c, cur) + 1
        # If no letter was found, error.
        if idx == 0:
            failed = True
            break
        cur = idx + 1
        idx += delta
        # If delta is to high, error.
        if idx >= len_text + i:
            failed = True
            break
        text = text[:idx] + marker + text[idx:]

    # If even distribution failed, just try "first available letter" method.
    if failed:
        text = org_text
        cur = max(0, -delta)
        for i, c in enumerate(data):
            idx = text.find(c, cur) + 1
            # If no letter was found, error.
            if idx == 0:
                raise Exception("Could not hide \"{}\" in the input "
                                "text (letter '{}' was not found in "
                                "remaining text)!".format(data, c))
            cur = idx + 1
            idx += delta
            # If delta is to high, error.
            if idx >= len_text + i:
                raise Exception("Could not hide \"{}\" in the input "
                                "text (delta ({}) is to high for letter '{}' "
                                "in remaining text)!".format(delta, data, c))
            text = text[:idx] + marker + text[idx:]

    return text


def hide(text, data, marker, delta):
    """Just a wrapper around do_hide, with some checks."""
    import string
    if not data:
        raise Exception("no data given!")
    # Check for unallowed chars…
    c_data = set(data)
    c_allowed = set(string.ascii_lowercase)
    if not (c_data <= c_allowed):
        raise Exception("Data contains unallowed chars (only lowercase strict "
                        "ASCII chars are allowed): '{}'!"
                        "".format("', '".join(sorted(c_data - c_allowed))))
    if len(data) / len(text) > 0.025:
        raise Exception("The hiding text should be at least 40 times "
                        "longer than the data to hide into it (data: {} "
                        "chars, input text: {} chars)!"
                        "".format(len(data), len(text)))
    if delta > len(data) * 2:
        raise Exception("The obfuscating delta is too high, it "
                        "should not be higher than twice the data length.")
    return do_hide(text, data, marker, delta)


def do_unhide(text, marker, delta):
    """Unhide some data from the given text, using marker and optionally
       an obfuscating delta."""
    cur = text.find(marker)
    max_idx = len(text) - 2
    ret = []
    while cur != -1:
        idx = cur - delta
        if delta >= 0:
            idx -= 1
        if max_idx < idx < 0:
            raise Exception("Got a letter idx out of range, your "
                            "delta value is probably wrong!")
            return ""
        ret.append(text[idx])
        cur = text.find(marker, cur + 1)
    return "".join(ret)


def unhide(text, marker, delta):
    """Just a wrapper around do_unhide (no checks currently)."""
    return do_unhide(text, marker, delta)


def do_test(text, data, marker, delta):
    print("Data: {}\n".format(data))

    stega = hide(text, data, marker, delta)

    print("Hidden data (with '{}' as marker, and a delta of {}): « {} »\n"
          "".format(marker, delta, stega))

    result = unhide(stega, marker, delta)

    print("Unhidden data: {}\n\n".format(result))


def test():
    text = "“Mes souvenirs sont comme les pistoles dans la bourse du " \
           "diable. Quand on l’ouvrit, on n’y trouva que des feuilles " \
           "mortes. J’ai beau fouiller le passé je n’en retire plus que des " \
           "bribes d’images et je ne sais pas très bien ce qu’elles " \
           "représentent, ni si ce sont des souvenirs ou des fictions.” " \
           "– extrait de « La nausée » de Jean-Paul Sartre."
    marker = b"\xcc\xa3".decode("utf8")
    tests = (("comix", 0, marker), ("htsdz", -1, marker),
             ("Hello World!", 3, marker), ("bonjour a tous", 6, marker))

    print("Text used as source: {}.\n".format(text))
    for data, delta, mark in tests:
        try:
            do_test(text, data, mark, delta)
        except Exception as e:
            print(e, "\n\n")


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Hide/unhide a word or short sentence "
                                     "into a long text (which should be at "
                                     "least 40 times longer).")
    parser.add_argument('-d', '--delta', type=int, default=0,
                        help="An optional delta to add to marked letters, "
                             "to further obfuscate hidden data.")
    parser.add_argument('-m', '--marker', default=b"\xcc\xa3".decode("utf8"),
                        help="The unicode char marker.")
    parser.add_argument('--debug', action="store_true", default=False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('hide', help="Hide data in text.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text into which "
                                  "hide the data.")
    hide_parser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                             help="A file into which write the stegano text.")
    hide_parser.add_argument('-d', '--data',
                             help="The data to hide into the text.")
    hide_parser.add_argument('-m', '--marker',
                             default=b"\xcc\xa3".decode("utf8"),
                             help="The unicode char marker.")

    unhide_parser = sparsers.add_parser('unhide',
                                        help="Unhide data from text.")
    unhide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                               help="A file containing the text with "
                                    "hidden data.")

    sparsers.add_parser('test', help="Small auto-tests…")
    sparsers.add_parser('about', help="About Sema…")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "hide":
        try:
            args.ofile.write(hide(args.ifile.read(), args.data,
                                  args.marker, args.delta))
        except Exception as e:
            if utils.DEBUG:
                raise e
            print(e, "\n\n")
        finally:
            args.ifile.close()
            args.ofile.close()
        return

    elif args.command == "unhide":
        try:
            print(unhide(args.ifile.read(), args.marker, args.delta))
        except Exception as e:
            if utils.DEBUG:
                raise e
            print(e, "\n\n")
        finally:
            args.ifile.close()
        return

    elif args.command == "test":
        test()
        return

    elif args.command == "about":
        print(__about__)
        return


if __name__ == "__main__":
    main()

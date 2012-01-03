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

# We assume txt/data length has already been checked, that marker is a valid utf8 char,
# and that delta is low enough (I’d say len(data) * 2 at most…).
def do_hide(txt, data, marker, delta):
    """Hide data into txt, using marker, and optionally an obfuscating delta."""
    # Be sure we have all needed chars in the text!
    needed_c = set(data)
    available_c = set(txt)
    if not needed_c <= available_c:
        raise Exception("ERROR: Letters '{}' were not found in the text!" \
                        "".format("', '".join(sorted(needed_c - available_c))))

    # Now, we have all needed letters.
    # But they might be not placed well!
    # So, make two tries, first a nicely distributed one,
    # then a "simplest" one.
    org_txt = txt
    len_txt = len(txt)
    ln_chunk = len_txt//len(data)
    cur = max(0, -delta)
    failed = False
    for i, c in enumerate(data):
        cur = max(cur, (ln_chunk * i) + i)
        idx = txt.find(c, cur) + 1
        # If no letter was found, error.
        if idx == 0:
            failed = True
            break
        cur = idx+1
        idx += delta
        # If delta is to high, error.
        if idx >= len_txt + i:
            failed = True
            break
        txt = txt[:idx] + marker + txt[idx:]

    # If even distribution failed, just try "first available letter" method.
    if failed:
        txt = org_txt
        cur = max(0, -delta)
        for i, c in enumerate(data):
            idx = txt.find(c, cur) + 1
            # If no letter was found, error.
            if idx == 0:
                raise Exception("ERROR: Could not hide \"{}\" in the input " \
                                "text (letter '{}' was not found in " \
                                "remaining text)!".format(data, c))
            cur = idx+1
            idx += delta
            # If delta is to high, error.
            if idx >= len_txt + i:
                raise Exception("ERROR: Could not hide \"{}\" in the input " \
                                "text (delta ({}) is to high for letter '{}' " \
                                "in remaining text)!".format(delta, data, c))
            txt = txt[:idx] + marker + txt[idx:]

    return txt


def hide(txt, data, marker, delta):
    """Just a wrapper around do_hide, with some checks."""
    import string
    if not data:
        raise Exception("ERROR: no data given!")
    # Remove all unallowed chars…
    if not (set(data) <= set(string.ascii_lowercase)):
        raise Exception("ERROR: data contains unallowed chars (only lowercase strict ASCII chars are allowed)!")
    if len(data) / len(txt) > 0.025:
        raise Exception("ERROR: the hiding text should be at least 40 times "
                        "longer than the data to hide into it (data: {} "
                        "chars, input text: {} chars)!"
                        "".format(len(data), len(txt)))
    if delta > len(data) * 2:
        raise Exception("ERROR: the obfuscating delta is too high, it " \
                        "should not be higher than twice the data length.")
    return do_hide(txt, data, marker, delta)


def do_unhide(txt, marker, delta):
    """Unhide some data from the given txt, using marker and optionally
       an obfuscating delta."""
    cur = txt.find(marker)
    max_idx = len(txt)-2
    ret = []
    while cur != -1:
        idx = cur - delta
        if delta >= 0:
            idx -= 1
        if max_idx < idx < 0:
            raise Exception("ERROR: got a letter idx out of range, your "
                            "delta value is probably wrong!")
            return ""
        ret.append(txt[idx])
        cur = txt.find(marker, cur+1)
    return "".join(ret)


def unhide(txt, marker, delta):
    """Just a wrapper around do_unhide (no checks currently)."""
    return do_unhide(txt, marker, delta)


def do_test(txt, data, marker, delta):
    print("Data: {}\n".format(data))

    stega = hide(txt, data, marker, delta)

    print("Hidden data (with '{}' as marker, and a delta of {}): « {} »\n" \
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
    tests = (("comix", 0, marker), ("htsdz", -1, marker), ("Hello World!", 3, marker), ("bonjour a tous", 6, marker))

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
    parser = argparse.ArgumentParser(description="" \
                                     "Hide/unhide a word or short sentence " \
                                     "into a long text (which should be at " \
                                     "least 40 times longer).\n" \
                                     "Use it without any arg to go in " \
                                     "interactive mode.")
    parser.add_argument('-d', '--delta', type=int, default=0,
                        help="An optional delta to add to marked letters, " \
                             "to further obfuscate hidden data.")
    parser.add_argument('-m', '--marker', default=b"\xcc\xa3".decode("utf8"),
                        help="The unicode char marker.")
    sparsers = parser.add_subparsers(dest="command")

    hide_parser = sparsers.add_parser('hide', help="Hide data in text.")
    hide_parser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                             help="A file containing the text into which " \
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
                               help="A file containing the text with " \
                                    "hidden data.")

    test_parser = sparsers.add_parser('test', help="Small auto-tests…")

    args = parser.parse_args()


    if args.command == "hide":
        try:
            args.ofile.write(hide(args.ifile.read(), args.data,
                                  args.marker, args.delta))
        except Exception as e:
            print(e, "\n\n")
        finally:
            args.ifile.close()
            args.ofile.close()
        return 0

    elif args.command == "unhide":
        try:
            print(unhide(args.ifile.read(), args.marker, args.delta))
        except Exception as e:
            print(e, "\n\n")
        finally:
            args.ifile.close()
        return 0

    elif args.command == "test":
        test()
        return


if __name__ == "__main__":
    main()

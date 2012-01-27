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
import string

# In case we directly run that file, we need to add the kernel to path,
# to get access to generic stuff in kernel.utils!
if __name__ == '__main__':
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..", "..")))

import kernel.utils as utils
import kernel.brainfuck as brainfuck


DEFAULT = "utf-8"


__version__ = "0.5.1"
__date__ = "2012/01/26"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About BrainFuck =====
BrainFuck, and the similar Ook, Spoon and SegFaultProg languages, are some
minimalist programming languages, highly unreadable by a human being – that’s
why they can be used to cypher some textual data.

This tool “(de)cyphers” any kind of text into one of those language, using a
given codec to convert text to/from binary (defaults to "utf-8").

While decyphering such code is quite straightforward (is just a matter of
“executing” the given code and showing the result), cyphering is more complex.

Indeed, you can virtually generate in infinite number of cyphering for a same
text (limit is in fact enforced by the size of the interpreter memory,
currently 100Ko). Hence, you have two different controls over that generation
process:

*The randomness:
    Generating such code is by design random. However, you might want to get
    some control over that randomness. So you have the option to either get a
    pure random solution, get a reproducible random solution by giving a number
    as feed for the generator, or use the whole cyphered text as feed.

*The level of obfuscation:
    Such generated code can be rather compact solution (something like 10 times
    the original text length for BrainFuck, for example), or thousands of chars
    for a simple word. This is the same principle as with obfuscation of source
    code. So you can specify an obfuscation level, from 0.0 (10 times longer at
    most) to 1.0 (10000 times longer at least).


Cyprium.Prime version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


#def do_cypher(text, base=1):
#    """Cypher a word in Prime code,from given base."""
#    # Let’s rather build a dict, will be much quicker with long texts.
#    maps = {k: str(PRIMES[v + base - 1])  # -1 because first base is 1...
#            for v, k in enumerate(string.ascii_lowercase)}
#    maps[' '] = ''
#    return " ".join((maps[c] for c in text))


#def cypher(text, base=1):
#    """Just a wrapper around do_cypher"""
#    if not text:
#        raise ValueError("No text given!")
#    # Check for unallowed chars.
#    c_text = set(text)
#    c_allowed = set(string.ascii_lowercase) | {' '}
#    if not (c_text <= c_allowed):
#        raise ValueError("Text contains unallowed chars (only strict ASCII "
#                         "lowercase-chars and spaces): '{}'!"
#                         "".format("', '".join(sorted(c_text - c_allowed))))
#    # Check for invalid base.
#    if BASE_MIN > base > BASE_MAX:
#        raise ValueError("The base must be a digit in [{}, {}]."
#                         "".format(BASE_MIN, BASE_MAX))
#    return do_cypher(text, base)


def do_decypher(text, codec="utf-8"):
    """Decypher a BrainFuck & co cyphered text."""
    ret = brainfuck.decypher(text)
    return ret.decode(codec)


def decypher(text, codec="utf-8"):
    """Just a wrapper around do_decypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Simple check...
    # XXX This func will called three times in the whole decyphering process :/
    #     Even though not very time-consuming, this is not optimal.
    try:
        brainfuck.detect_type(text)
    except Exception as e:
        raise ValueError("It seems that text is no valid/known code ({})…"
                         "".format(str(e)))
    return do_decypher(text, codec)


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)
    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some text in "
                                     "prime code.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

#    cparser = sparsers.add_parser('cypher', help="Encrypt text in prime.")
#    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
#                         help="A file containing the text to cypher.")
#    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
#                         help="A file into which write the cyphered text.")
#    cparser.add_argument('-d', '--data', help="The text to cypher.")
#    cparser.add_argument('-b', '--base', type=int, default=1,
#                         help="Which base to use to cypher the text "
#                              "(1: A = 2; 2: A = 3; 3: A = 5; etc.).")

    dparser = sparsers.add_parser('decypher', help="Decypher prime to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="The codec to use for decyphering.")

    sparsers.add_parser('about', help="About Prime.")

    sparsers.add_parser('test', help="Run basic tests.")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = cypher(data, args.base)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            if utils.DEBUG:
                raise e
            raise e
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return

    if args.command == "decypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            out = decypher(data, args.codec)
            if args.ofile:
                args.ofile.write(out)
            else:
                print(out)
        except Exception as e:
            if utils.DEBUG:
                raise e
            raise e
        finally:
            if args.ifile:
                args.ifile.close()
            if args.ofile:
                args.ofile.close()
        return

    elif args.command == "about":
        print(__about__)
        return

    elif args.command == "test":
        texts = ["++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++.>---.+++++++"
                 "++++++++..+++++++++.<<++.>>-----------.---------.+++++++++++"
                 "+++++++.<<.>>++.--------------------.----.+++++++++++++++++."
                 "<<.++++++++++++++++++.--.+.+.",
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook. Ook? "
                 "Ook. Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook? Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook! Ook! Ook? Ook! "
                 "Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook. Ook. Ook. Ook! Ook. "
                 "Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. "
                 "Ook. Ook. Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook? Ook. "
                 "Ook. Ook. Ook. Ook. Ook! Ook. Ook. Ook? Ook. Ook? Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. "
                 "Ook? Ook. Ook! Ook. Ook. Ook? Ook. Ook? Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. "
                 "Ook. Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook! Ook. Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! "
                 "Ook! Ook.",
                 "....................!?.?...?.......?...............?........"
                 "............?.?.?.?.!!?!.?.?.?.?!!!!!!!!!!!!!!!!!!!!!!!!!!!."
                 "..................................!.!!!!!!!!!!!!!!!........."
                 "..............................!.?..........................."
                 "..................!.?...................!..?.?!!!.?.?.!!!!!!"
                 "!!!!!!!!!..?.?..!.?.........................!...!..?!!!.?.?."
                 "!..........................................................."
                 "....!.",
                 "111111111100100010101011101011111110101111111111011011011011"
                 "000001101001001001000000000000000000000000000000000000000000"
                 "101011111111111111111001010111111100101000000000000000000000"
                 "000000000000000000000000000000000000000101001101111111111100"
                 "101001001011111111111111111111111001010011011000000000000000"
                 "000000001010010010100101000000000000000000000000000000000000"
                 "000101000000000000101001101100101001001011111111001010000000"
                 "000000000000000000000000000000001010111111111111111111001010"
                 "100101000000000000000000000000000000000000000000000000101011"
                 "111111111110010100110110010100101111110010100100000000000000"
                 "000000000000000000000000000010101111111111111001010000000000"
                 "001010111111111100101001100000000000000000000000000000000000"
                 "0000001010",
                 "*A+H.[-]+e.+7..+3.*B+32.*A+8.-8.+3.[-]+d."]
        for t in texts:
            print(t, "\n\n=>", decypher(t, "ascii"), "\n\n\n")
        t = texts[-1]
        print(t, "\n\n=>", brainfuck.BrainFuck().convert(t, brainfuck.BRAINFUCK), "\n\n\n")
        t = texts[0]
        print(t, "\n\n=>", brainfuck.BrainFuck().convert(t, brainfuck.OOK), "\n\n\n")
        print(t, "\n\n=>", brainfuck.BrainFuck().convert(t, brainfuck.FASTOOK), "\n\n\n")
        print(t, "\n\n=>", brainfuck.BrainFuck().convert(t, brainfuck.SPOON), "\n\n\n")
        print(t, "\n\n=>", brainfuck.BrainFuck().convert(t, brainfuck.SIGSEV), "\n\n\n")
        return


if __name__ == "__main__":
    main()

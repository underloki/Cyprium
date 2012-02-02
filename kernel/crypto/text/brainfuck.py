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


__version__ = "0.6.0"
__date__ = "2012/02/02"
__python__ = "3.x"  # Required Python version
__about__ = "" \
"""===== About BrainFuck =====
BrainFuck, and the similar Ook, Spoon and SegFaultProg languages, are some
minimalist programming languages, highly unreadable by a human being – that’s
why they can be used to cypher some textual data.

This tool “(de)cyphers” any kind of text into one of those language, using a
given codec to convert text to/from binary (defaults to "utf-8").

While decyphering such code is quite straightforward (it’s just a matter of
“executing” the given code and showing the result), cyphering is more complex.

Indeed, you can virtually generate in infinite number of cyphering for a same
text (limit is in fact enforced by the size of the interpreter memory,
currently 100Ko).

This tool uses a quite good algorithm to generate some “opcode” (an internal
representation of SegFaultProg). This process is very little affected by
randomness.

Based on this opcode, it can add some obfuscating code (i.e. code not affecting
the output data), which is this time higly affected by randomness.

*The randomness:
    You might want to get some control over that randomness. So you have the
    option to either get a pure random solution (default behavior), get a
    reproducible random solution by giving a number as seed for the generator,
    or use the whole cyphered text as seed.

*The level of obfuscation:
    Such generated code can be a rather compact solution (something like 10
    times the original text length for BrainFuck, for example), or thousands of
    chars for a simple word. This is the same principle as with obfuscation of
    source code. So you can specify an obfuscation level, from 0.0 (no
    obfuscation) to 1.0 (adding an average of 5 “nop” opcodes between each
    “useful” ones). Note that an opcode will translate as one intruction in
    SegFaultProg, but might generate several tens of instructions in the other
    languages…


In addition, this tool also can convert some code between different languages.


Cyprium.Prime version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}
""".format(__version__, __date__, utils.__pf__, utils.__pytver__)


def do_cypher(text, lang, codec=DEFAULT, obfs_fact=0.0, seed=None):
    """Cypher a word in brainfuck & co code."""
    text = text.encode(codec)
    return brainfuck.cypher(text, lang, obfs_fact, seed)


def cypher(text, lang, codec=DEFAULT, obfs_fact=0.0, seed=None):
    """Just a wrapper around do_cypher."""
    if not text:
        raise ValueError("No text given!")
    # Check lang is known.
    if lang not in {brainfuck.BRAINFUCK, brainfuck.OOK, brainfuck.FASTOOK,
                    brainfuck.SPOON, brainfuck.SIGSEV}:
        raise ValueError("Unknown language choosen…")
    return do_cypher(text, lang, codec, obfs_fact, seed)


def do_decypher(text, codec=DEFAULT):
    """Decypher a BrainFuck & co cyphered text."""
    ret = brainfuck.decypher(text)
    return ret.decode(codec)


def decypher(text, codec=DEFAULT):
    """Just a wrapper around do_decypher, with some checks."""
    if not text:
        raise ValueError("No text given!")
    # Simple check...
    # XXX This func will be called two times in the whole process :/
    #     Even though not very time-consuming, this is not optimal.
    try:
        brainfuck.detect_type(text)
    except Exception as e:
        raise ValueError("It seems that text is no valid/known code ({})…"
                         "".format(str(e)))
    return do_decypher(text, codec)


def do_convert(code, lang, obfs_fact=0.0, seed=None):
    """Convert some code to another language."""
    return brainfuck.convert(code, lang, obfs_fact, seed)


def convert(code, lang, obfs_fact=0.0, seed=None):
    """Just a wrapper around do_convert."""
    if not code:
        raise ValueError("No code given!")
    # Check lang is known.
    if lang not in {brainfuck.BRAINFUCK, brainfuck.OOK, brainfuck.FASTOOK,
                    brainfuck.SPOON, brainfuck.SIGSEV}:
        raise ValueError("Unknown target language choosen…")
    # Simple check...
    # XXX This func will be called two times in the whole process :/
    #     Even though not very time-consuming, this is not optimal.
    try:
        brainfuck.detect_type(code)
    except Exception as e:
        raise ValueError("It seems that code is no valid/known code ({})…"
                         "".format(str(e)))
    return do_convert(code, lang, obfs_fact, seed)


def test():
    """Various tests/checks..."""
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
    print(t, "\n\n=>", convert(t, brainfuck.BRAINFUCK), "\n\n\n")

    t = texts[0]
    print(t, "\n\n=>", convert(t, brainfuck.OOK), "\n\n\n")
    print(t, "\n\n=>", convert(t, brainfuck.FASTOOK), "\n\n\n")
    print(t, "\n\n=>", convert(t, brainfuck.SPOON), "\n\n\n")
    print(t, "\n\n=>", convert(t, brainfuck.SIGSEV), "\n\n\n")

    t = "A quite simple dummy “test”…"
    s = 23
    f = 2.0
    c = "utf-8"
    tt = cypher(t, brainfuck.SIGSEV, c, 0.0, seed=s)
    print(t, "\n\n=>", tt, "\n", decypher(tt, c), "\n\n\n")
    tt = cypher(t, brainfuck.SIGSEV, c, f, seed=s)
    print(t, "\n\n=>", tt, "\n", decypher(tt, c), "\n\n\n")
    for s in range(100):
        tt = cypher(t, brainfuck.SIGSEV, c, f, seed=s)
        try:
            if decypher(tt, c) != t:
                print(s)
                print(t, "\n\n=>", tt, "\n", decypher(tt, c), "\n\n\n")
        except Exception as e:
            print(s, tt)
            raise e

    t = """===== About Argots =====
Argots allows you to cypher and decypher some text using one of Argot Javanais,
Langue de Feu (or there generic version), or Largonji des Loucherbems methods.


== Argot Javanais, Langue de Feu and Generic ==
The principle is to insert a syllable (always the same, two letters only,
which we’ll call “obfuscating syllable”) between consonants and vowels
(with a few additional restrictions/special cases).

Javanais method allows (and searches for, at decypher time) the traditional
'ja', 'av' and 'va' syllables, and all their case variants ('Ja', 'VA', etc.).
E.g. using ja:
“Les « Blousons Noirs » vous parlent…” →
    “Ljaes « Bljaousjaons Njaoirs » vjaous parljaent…”

Feu method allows (and search for, at decypher time) all syllables made of
a 'f' and a vowel, and all their case variants ('fe', 'Af', 'fO', 'UF', etc.).
E.g. using Ef:
“Les Apaches sont sur le sentier des Halles.” →
    “LEfes EfApEfachEfes sEfont sEfur lEfe sEfentEfier dEfes HEfallEfes.”

Generic method allows (and search for, at decypher time) all syllables made of
a consonant and a vowel, or two different vowels, and all their case variants
(example of *not allowed* syllables: 'oO', 'ii', 'fp', 'Kz', etc.).
E.g. using uz:
“Casque d’or refait sa permanente.” ->
    “Cuzasquzue d’or ruzefuzait suza puzermuzanuzentuze.”

You can also use another cypher algorithm, “exhaustive”, that will, for each
word, check *all* possible cyphering, and output (again, for each word) all
solutions giving a cyphering threshold (i.e. nbr of obfuscating syllables
added/total nbr of chars) around the given one ([0.0 .. 1.0] ± 0.05) – note
that with this tool, a cyphering of 0.3/0.4 is in general already very high,
higher values are very seldom possible.

WARNING: Avoid using that option with words with more than about 20 chars,
         the compute time will quickly become prohibitive!

E.g. for “Bellville”, with 'av' and a cyphering goal of 0.3:
    Bavelleviavllave
    Bavellavevillave
    Beavlleviavllave
    Beavllavevillave
    Bavellevavillave
    Bavellaveviavlle
    Bavellavevaville
    Bellaveviavllave
    Beavllaveviavlle
    Beavllevavillave
    Bellavevavillave
    Beavllavevaville

WARNING: If the text already contains the obfuscating syllable, it will
         likely be lost a decyphering time!


== Largonji des Loucherbems ==
WARNING: While previous methods, even though french at origin, are quite easily
         extendable to other languages, the Louchébem is tightly related to
         french phonetic, and hence might give strange/unusable results with
         other languages.
         And even with french, it’s hard to get reliable results with
         procedural algorithms… So this tool is more an help than an
         “out-of-the-box” solution.

This “cyphering” roughly consists in, for each word:
    * If the first letter is a consonant, move it to the end of the word.
    * Add an 'l' at the beginning of the word.
    * Finally, add a (more or less random) syllable at the end of the word.
So you get “boucher” (butcher) ==> “oucherb” ==> “loucherb” ==> “loucherbème”.
           “jargon” ==> “argonj” ==> “largonj” ==> “largonji”.
           “abricot” ==> “abricot” ==> “labricot” ==> “labricotqué”
           “lapin” ==> “apinl” ==> “lapinl” ==> “lapinlic”.
           etc.

By default, the following vowels can be added after a “phonetic vowel”:
    '{}'
And those, after a consonant:
    '{}'
You can specify other sets, but beware, this might make decyphering even more
complicated and unreliable…

Note that during decyphering, if Argots finds an unknown suffix, it will try
to use it too – but result may well be quite wrong in this case. And given
the fuzzyness of this argots, decyphering will systematically output the
original (cyphered) word, at the end of the lists.

Note also that current code assume “largonji suffixes” are never longer than 5
chars, and never (de)cyphers words shorter than 4 chars (sorry for
“loufoque” !).


Cyprium.Argots version {} ({}).
Licence GPL3
Software distributed on the site: http://thehackademy.fr

Current execution context:
    Operating System: {}
    Python version: {}""".encode("utf-8")
    bf = brainfuck.BrainFuck()
    opcode = bf.bytes_to_opcode(t)
    tt = bf.opc2sigsev(opcode)
    print(tt, "\n\n=>", decypher(tt, "utf-8"), "\n", len(tt), "\n\n\n")


def main():
    # The argparse is much nicer than directly using sys.argv...
    # Try 'program.py -h' to see! ;)

    # Helper func.
    _langs = {'brainfuck': brainfuck.BRAINFUCK, 'b': brainfuck.BRAINFUCK,
              'ook': brainfuck.OOK, 'ook': brainfuck.OOK,
              'fastook': brainfuck.FASTOOK, 'f': brainfuck.FASTOOK,
              'spoon': brainfuck.SPOON, 's': brainfuck.SPOON,
              'segfaultprog': brainfuck.SIGSEV, 'g': brainfuck.SIGSEV}
    def _2ilang(b):
        return _langs.get(b, None)

    import argparse
    parser = argparse.ArgumentParser(description=""
                                     "Cypher/decypher some text in "
                                     "prime code.")
    parser.add_argument('--debug', action="store_true", default = False,
                        help="Enable debug mode.")

    sparsers = parser.add_subparsers(dest="command")

    cparser = sparsers.add_parser('cypher',
                                  help="Cypher text in brainfuck & co.")
    cparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to cypher.")
    cparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the cyphered text.")
    cparser.add_argument('-d', '--data', help="The text to cypher.")
    cparser.add_argument('-l', '--lang', nargs="?", type=_2ilang,
                         choices=_langs.values(), default=_langs['b'],
                         help="In which language ouput the cyphered text "
                              "([b]rainfuck, [o]ok, [f]astook, [s]poon, "
                              "se[g]faultprog, defaults to brainfuck if "
                              "none chosen).")
    cparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="Which codec to use to convert the text "
                              "to binary (defaults to {}).".format(DEFAULT))
    cparser.add_argument('-f', '--obfuscation_factor', type=float, default=0.0,
                         help="How many obfuscating code to add, from 0.0 "
                              "(none, default) to 1.0.")
    cparser.add_argument('-s', '--seed', type=int,
                         help="The value to use as seed for the random "
                              "generator. Either a positive integer, nothing "
                              "(default) to use current time, or a negative "
                              "value to use the data to cypher.")

    dparser = sparsers.add_parser('decypher',
                                  help="Decypher brainfuck & co to text.")
    dparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the text to decypher.")
    dparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the decyphered text.")
    dparser.add_argument('-d', '--data', help="The text to decypher.")
    dparser.add_argument('-c', '--codec', default=DEFAULT,
                         help="The codec to use for decyphering.")

    oparser = sparsers.add_parser('convert',
                                  help="Convert code to another language.")
    oparser.add_argument('-i', '--ifile', type=argparse.FileType('r'),
                         help="A file containing the code to convert.")
    oparser.add_argument('-o', '--ofile', type=argparse.FileType('w'),
                         help="A file into which write the converted code.")
    oparser.add_argument('-d', '--data', help="The code to convert.")
    oparser.add_argument('-l', '--lang', nargs="?", type=_2ilang,
                         choices=_langs.values(), default=_langs['b'],
                         help="To which language convert the code "
                              "([b]rainfuck, [o]ok, [f]astook, [s]poon, "
                              "se[g]faultprog, defaults to brainfuck if "
                              "none chosen).")
    oparser.add_argument('-f', '--obfuscation_factor', type=float, default=0.0,
                         help="How many obfuscating code to add, from 0.0 "
                              "(none, default) to 1.0.")
    oparser.add_argument('-s', '--seed', type=int,
                         help="The value to use as seed for the random "
                              "generator. Either a positive integer, nothing "
                              "(default) to use current time, or a negative "
                              "value to use the data to cypher.")

    sparsers.add_parser('about', help="About Prime.")

    sparsers.add_parser('test', help="Run basic tests.")

    args = parser.parse_args()
    utils.DEBUG = args.debug

    if args.command == "cypher":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            if args.seed < 0:
                args.seed = data
            out = cypher(data, args.lang, args.codec,
                         args.obfuscation_factor, args.seed)
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

    if args.command == "convert":
        try:
            data = args.data
            if args.ifile:
                data = args.ifile.read()
            if args.seed < 0:
                args.seed = data
            out = convert(data, args.lang, args.obfuscation_factor, args.seed)
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
        test()
        return


if __name__ == "__main__":
    main()

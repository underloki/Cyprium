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
"""
This file contains a complete valid virtual machine for brainfuck language,
as well as other similar dialects (Ook, Fast Ook and Spoon).
It also contains a virtual machine for SegFaultProg.
"""

import sys
import os
import random
import string

import kernel.utils as utils


# Languages
BRAINFUCK = 1
OOK = 10
FASTOOK = 11
SPOON = 20
SIGSEV = 30


class BrainFuck():
    """
    """

    # Opcodes
    # XXX Eventhough this is probably not compliant with the SegFaultProg
    #     standard, <v> values maybe be any positive integer, not only
    #     8 bits ones.
#    NOP = 0     # No operation, does nothing.
    PTRINC = 1   # Increment cell pointer by <v>, up to MAXCELLS.
    PTRDEC = 2   # Decrement cell pointer by <v>, up to first cell.
    PTRSET = 3   # Set cell pointer to <v>, between [0..MAXCELLS].
    INC = 20     # Increment cell value by <v> (8bits, cyclic).
    DEC = 21     # Decrement cell value by <v> (8bits, cyclic).
    # Opening brace, skip to matching closing brace is current cell is NULL.
    BOPEN = 30
    # Closing brace, back to matching opening brace is current cell is not NULL.
    BCLOSE = 31
    OUTPUT = 40  # Output cell value.
    INPUT = 41   # Set cell value with input.

    # Misc
    MAXCELLS = 100000  # Max number of cells.

    # Conversion mappings.
    CONVERT_FUNCS = {}

    TO_BRAINFUCK = {PTRINC: '>',
                    PTRDEC: '<',
                    INC: '+',
                    DEC: '-',
                    BOPEN: '[',
                    BCLOSE: ']',
                    OUTPUT: '.',
                    INPUT: ','}
    FROM_BRAINFUCK = utils.revert_dict(TO_BRAINFUCK)

    # Fast ook, in fact...
    TO_OOK = {PTRINC: '.?',
              PTRDEC: '?.',
              INC: '..',
              DEC: '!!',
              BOPEN: '!?',
              BCLOSE: '?!',
              OUTPUT: '!.',
              INPUT: '.!'}
    FROM_OOK = utils.revert_dict(TO_OOK)

    TO_SPOON = {PTRINC: '010',
                PTRDEC: '011',
                INC: '1',
                DEC: '000',
                BOPEN: '00100',
                BCLOSE: '0011',
                OUTPUT: '001010',
                INPUT: '0010110'}
    FROM_SPOON = utils.revert_dict(TO_SPOON)

    TO_SIGSEV = {PTRINC: '>',
                 PTRDEC: '<',
                 PTRSET: '*',
                 INC: '+',
                 DEC: '-',
                 BOPEN: '[',
                 BCLOSE: ']',
                 OUTPUT: '.',
                 INPUT: ','}
    FROM_SIGSEV = utils.revert_dict(TO_SIGSEV)

    ###########################################################################
    def __init__(self, inpt=input, outpt=print, seed=None):
        self.input = inpt
        self.output = outpt
        self.seed = seed
        self.reset_state()
        pass

    def reset_state(self):
        """Reset the internal code and state of the virtual machine."""
        self._code = []
        self._bracemap = {}
        self._cells = [0]
        self._cellptr = 0
        self._codeptr = 0
        self._max_codeptr = 0

    def reset_random(self):
        """Reset random generator."""
        if self.seed:
            random.seed(self.seed)
        else:
            random.seed()

    ###########################################################################
    # Core code.
    ###########################################################################
    def prepare(self, code):
        """Convert code to machine, and validate the final code."""
        tp = detect_type(code)
        self._code = self.optimize(self.CONVERT_FUNCS[tp][0](self, code))
        self.buildbracemap()
        return self._code

    def buildbracemap(self):
        """Build the matching braces map of given machine code."""
        open_braces = []
        self._bracemap = {}
        for self._codeptr, opc in enumerate(self._code):
            opc = opc[0]  # Get opcode!
            if opc == self.BOPEN:
                open_braces.append(self._codeptr)
            elif opc == self.BCLOSE:
                self._bracemap[self._codeptr] = open_braces[-1]
                self._bracemap[open_braces[-1]] = self._codeptr
                del open_braces[-1]
        return self._bracemap

    def evaluate(self, code):
        """
        Brainfuck & co virtual machine...
        """
        ret = []

        self.reset_state()

        # Convert code to machine, and validate.
        self.prepare(code)

        self._max_codeptr = len(self._code) - 1
        self._cellptr = 0
        self._codeptr = 0

        while self._codeptr <= self._max_codeptr:
            cmd, val = self._code[self._codeptr]

            if cmd == self.PTRINC:
                if val is None:
                    val = 1
                self._cellptr = min(self._cellptr + val, self.MAXCELLS - 1)
                if self._cellptr >= len(self._cells):
                    self._cells += [0] * (self._cellptr - len(self._cells) + 1)

            elif cmd == self.PTRDEC:
                if val is None:
                    val = 1
                self._cellptr = max(0, self._cellptr - val)

            elif cmd == self.PTRSET:
                # XXX Do nothing if no value given!
                if val is not None:
                    self._cellptr = max(0, min(val, self.MAXCELLS - 1))
                    if self._cellptr >= len(self._cells):
                        self._cells += [0] * \
                                       (self._cellptr - len(self._cells) + 1)

            elif cmd == self.INC:
                if val is None:
                    val = 1
                self._cells[self._cellptr] = \
                          (self._cells[self._cellptr] + val) % 255

            elif cmd == self.DEC:
                if val is None:
                    val = 1
                self._cells[self._cellptr] = \
                          (self._cells[self._cellptr] - val) % 255

            elif cmd == self.BOPEN and self._cells[self._cellptr] == 0:
                self._codeptr = self._bracemap[self._codeptr]

            elif cmd == self.BCLOSE and self._cells[self._cellptr] != 0:
                self._codeptr = self._bracemap[self._codeptr]

            elif cmd == self.OUTPUT:
                self.output(self._cells[self._cellptr])

            elif cmd == self.INPUT:
                inpt = self.input()
                if inpt:
                    # XXX If user can input non-ascii chars, this can raise
                    #     an exception... Might need better way to do this.
                    self._cells[self._cellptr] = ord(inpt[0].encode('ascii'))

            self._codeptr += 1

    ###########################################################################
    def optimize(self, code):
        """
        Optimize opcode (using SegFaultProg features).
        In other words, produce an opcode with values as often as possible,
        gathering together similar (compatible) opcodes.
        """
        # Compatible opcodes...
        _compat_ptr = {self.PTRINC, self.PTRDEC, self.PTRSET}
        _compat_val = {self.INC, self.DEC}
        _compat = _compat_ptr | _compat_val
        _op_inc = {self.PTRINC, self.INC}
        _op_dec = {self.PTRDEC, self.DEC}
        _op_set = {self.PTRSET}

        ret = []
        org_ptr = new_ptr = 0
        dlt = 0
        curr_cat = set()
        for opc, val in code:
            # If we have to finish the current set of opcodes.
            if curr_cat and opc not in curr_cat:
                # Else, if we have to first finalize the previous set of
                # pointer opcodes.
                if curr_cat == _compat_ptr:
                    new_ptr += dlt
                    if new_ptr != org_ptr:
                        new_ptr = org_ptr = min(max(0, new_ptr),
                                                self.MAXCELLS-1)
                        ret.append((self.PTRSET, org_ptr))
                    curr_cat = set()
                # Else, if we have to first finalize the previous set of
                # value opcodes.
                elif curr_cat == _compat_val:
                    dlt = int((abs(dlt) % 255) * (dlt / abs(dlt)))
                    if dlt > 0:
                        ret.append((self.INC, dlt))
                    elif dlt < 0:
                        ret.append((self.DEC, -dlt))
                    curr_cat = set()

            # If we remain in a same category of opcodes, or have to start
            # a new one...
            if opc in curr_cat or opc in _compat:
                if not curr_cat:
                    if opc in _compat_ptr:
                        curr_cat = _compat_ptr
                    elif opc in _compat_val:
                        curr_cat = _compat_val
                    dlt = 0
                if opc in _op_set and val is not None:
                    new_ptr = val
                    dlt = 0
                elif opc in _op_inc:
                    if val == None:
                        val = 1
                    dlt += val
                elif opc in _op_dec:
                    if val == None:
                        val = 1
                    dlt -= val

            # Else, single op...
            else:
                ret.append((opc, val))  # XXX val should always be None here...

        return ret

    def unoptimize(self, code):
        """
        Move back opcode to be directly usable by Brainfuck & co.
        In other words, produce an opcode without any values (all are None).
        """
        ret = []
        ptr = 0
        for opc, val in code:
            if opc == self.PTRSET:
                if val is None:
                    continue  # "Error", ignore.
                delta = val - ptr
                if delta > 0:
                    ret += [(self.PTRINC, None)] * delta
                elif delta < 0:
                    ret += [(self.PTRDEC, None)] * -delta
                ptr = val
                continue
            if val is None:
                val = 1
            if opc == self.PTRINC:
                ptr += val
            elif opc == self.PTRDEC:
                ptr -= val
            ret += [(opc, None)] * val
        return ret

    def obfuscate(self, code, factor):
        """
        Randomly obfuscate the given opcode by given factor.
        code is assumed optimized.
        factor is a multiplicating factor for the number of opcodes to produce.
        E.g. if you have an input code of 10 opcodes, and a factor of 3, you’ll
        get 30 opcodes as ouput.
        Note: It’s the caller responsability to handle random generator reset,
              if needed.
        """
        return code

    def convert(self, code, target, factor = 1.0):
        """
        Convert some (textual form of) language to another one.
        Note that the ouput form is by default optimized, use the factor option
        if you want some obfuscation (see obfuscate() doc).
        """
        tp = detect_type(code)
        code = self.optimize(self.CONVERT_FUNCS[tp][0](self, code))
        return self.CONVERT_FUNCS[target][1](self, self.obfuscate(code, factor))

    ###########################################################################
    # Convert functions.
    ###########################################################################
    # BrainFuck code.
    def bf2opc(self, code):
        """Convert brainfuck to opcode."""
        code = code.replace(' ', '')
        return [(self.FROM_BRAINFUCK[opc], None) for opc in code]

    def opc2bf(self, code):
        """Convert opcode to brainfuck."""
        # Get Brainfuck & co compatible opcode.
        code = self.unoptimize(code)
        return "".join((self.TO_BRAINFUCK[opc] for opc, v in code))

    CONVERT_FUNCS[BRAINFUCK] = (bf2opc, opc2bf)

    # Ook code.
    def ook2opc(self, code):
        """Convert ook to opcode."""
        # Convert full ook to fast one.
        code = code.lower().replace("ook", '')
        code = code.replace(' ', '')
        return [(self.FROM_OOK[opc], None) for opc in utils.grouper2(code, 2)]

    def opc2ook(self, code):
        """Convert opcode to ook (without "Ook" if full is False."""
        # Get Brainfuck & co compatible opcode.
        code = self.unoptimize(code)
        ret = []
        for opc, v in code:
            ret += self.TO_OOK[opc]
        return "".join(ret)

    def opc2fastook(self, code):
        """Convert opcode to ook (without "Ook" if full is False."""
        # Get Brainfuck & co compatible opcode.
        code = self.unoptimize(code)
        ret = []
        for opc, v in code:
            ret += self.TO_OOK[opc]
        return " Ook".join(ret).lstrip()  # Remove first space...

    CONVERT_FUNCS[OOK] = (ook2opc, opc2ook)
    CONVERT_FUNCS[FASTOOK] = (ook2opc, opc2fastook)

    # Spoon code.
    def spoon2opc(self, code):
        """Convert spoon to opcode."""
        # XXX Seems this code is desinged to be interpreted without any
        #     separator... Makes it slightly more complex to decode.
        #     Decypher by checking from longest to shortest opcode!

        # First, create an ordered list (from longest to shortest) of tuples
        # (opcodes_length, {opcodes}).
        _tops = {}
        for opcode in self.FROM_SPOON.keys():
            if len(opcode) in _tops:
                _tops[len(opcode)].add(opcode)
            else:
                _tops[len(opcode)] = set((opcode,))
        _ops = tuple((k, _tops[k]) for k in sorted(_tops.keys(), reverse=True))

        # And now, loop over the whole code, trying each time to get the
        # longest matching opcode code...
        ret = []
        code = code.replace(' ', '')
        idx = 0
        code_ln = len(code)
        while idx < code_ln:
            for ln, ops in _ops:
                ln = min(ln + idx, code_ln)
                if code[idx:ln] in ops:
                    ret.append((self.FROM_SPOON[code[idx:ln]], None))
                    idx = ln
                    break
        return ret

    def opc2spoon(self, code):
        """Convert opcode to spoon."""
        # Get Brainfuck & co compatible opcode.
        code = self.unoptimize(code)
        return "".join((self.TO_SPOON[opc] for opc, v in code))

    CONVERT_FUNCS[SPOON] = (spoon2opc, opc2spoon)

    # Sigsev code.
    # XXX As SegFaultProg is a bit different, conversion is a bit more complex.
    # XXX The description of '[' is a bit fuzzy, here we assume it's the same
    #     as with brainfuck (i.e. skip if current cell is NULL).
    def sigsev2opc(self, code):
        """Convert sigsev to opcode."""
        code.replace(' ', '')
        opcs = self.FROM_SIGSEV  # All valid opcodes.
        ret = []  # A list of (opcode, value).
        val = None  # Default value.
        for c in code:
            if c in opcs:
                if val:
                    if len(val) == 1 and val in string.ascii_letters:
                        val = ord(val)
                    else:
                        val = int(val)
                # Note val is one opcode late, compared to c!
                if ret:
                    ret[-1] = (ret[-1], val)
                val = None
                ret.append(opcs[c])
            else:
                val = val + c if val else c
        # Append the last value!
        if val:
            if len(val) == 1 and val in string.ascii_letters:
                val = ord(val)
            else:
                val = int(val)
        ret[-1] = (ret[-1], val)
        return ret

    def opc2sigsev(self, code):
        """Convert opcode to sigsev. This conversion uses random and seed."""
        ret = []
        self.reset_random()

        ptr = 0
        for opc, val in code:
            # As optimized opcode is supposed to have only PTRSET pointer
            # opcodes, we have to randomly convert thoose to PTRINC/PTRDEC
            # ones...
            # XXX In case we get already obfuscated code, this will decrease
            #     the usage of PTRSET... Will see whther this is a problem.
            # This implies we also have to keep track of current cell pointer.
            if opc == self.PTRSET:
                if val is None:
                    continue  # "Error", ignore.
                if random.randint(0, 1):
                    dlt = val - ptr
                    ptr = val
                    val = abs(dlt)
                    if dlt > 0:
                        opc = self.PTRINC
                    elif dlt < 0:
                        opc = self.PTRDEC
                else:
                    ptr = val
            ret.append(self.TO_SIGSEV[opc])
            # If valid value, add it.
            if val is not None:
                # Do not print val when 1 and opcode is inc/dec...
                if opc != self.PTRSET and val == 1:
                    continue
                # If alpha-compatible value, randomly choose between alpha
                # and integer representation.
                if chr(val) in string.ascii_letters:
                    if random.randint(0, 1):
                        ret[-1] = ret[-1] + chr(val)
                    else:
                        ret[-1] = ret[-1] + str(val)
                else:
                    ret[-1] = ret[-1] + str(val)
        return "".join(ret)

    CONVERT_FUNCS[SIGSEV] = (sigsev2opc, opc2sigsev)


def detect_type(code):
    """Detect what type of "brainfuck" code we have."""
    if set(code) <= (set(BrainFuck.FROM_BRAINFUCK.keys()) | {' '}):
        return BRAINFUCK
    elif set(code) <= {'.', '!', '?', 'o', 'O', 'k', 'K', ' '}:
        return OOK
    elif set(code) <= {'0', '1', ' '}:
        return SPOON
    elif set(code) <= (set(string.ascii_letters) | set(string.digits) |
                       set(BrainFuck.FROM_SIGSEV.keys()) | {' '}):
        return SIGSEV
    raise ValueError("Unknown language!")


def decypher(code):
    """Simple wrapper to return code interpreted output as bytes."""
    out = BytesOutput()
    BrainFuck(outpt=out).evaluate(code)
    return bytes(out)


class BytesOutput():
    """
    A simple class that can be used as output for BrainFuck, storing values in
    a bytes string.
    """

    def __init__(self):
        self._list = []

    def __call__(self, value):
        if 0 <= value <= 255:
            self._list.append(value)

    def __bytes__(self):
        return utils.int8_to_bytes(self._list)

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
        pass

    def reset_random(self):
        """Reset random generator."""
        if self.seed:
            random.seed(self.seed)
        else:
            random.seed()

    ###########################################################################
    # Core code.
    # XXX Using instance vars here, as it might help debugging?
    ###########################################################################
    def prepare(self, code):
        """Convert code to machine, and validate the final code."""
        tp = detect_type(code)
        code = self.optimize(self.CONVERT_FUNCS[tp][0](self, code))
        return code

    def buildbracemap(self, code):
        """Build the matching braces map of given machine code."""
        open_braces = []
        bracemap = {}
        codeptr = 0
        for codeptr, opc in enumerate(code):
            opc = opc[0]  # Get opcode!
            if opc == self.BOPEN:
                open_braces.append(codeptr)
            elif opc == self.BCLOSE:
                bracemap[codeptr] = open_braces[-1]
                bracemap[open_braces[-1]] = codeptr
                del open_braces[-1]
        if open_braces:
            raise ValueError("Not enough closing braces (missing {} ones)"
                             "".format(len(open_braces)))
        return bracemap

    def evaluate(self, code):
        """
        Brainfuck & co virtual machine...
        """
        ret = []

        # Convert code to machine, and validate.
        code = self.prepare(code)
        bracemap = self.buildbracemap(code)

        max_codeptr = len(code) - 1
        cells = []
        cellptr = 0
        codeptr = 0

        while codeptr <= max_codeptr:
            cmd, val = code[codeptr]

            if cmd == self.PTRINC:
                if val is None:
                    val = 1
                cellptr = min(cellptr + val, self.MAXCELLS - 1)
                if cellptr >= len(cells):
                    cells += [0] * (cellptr - len(cells) + 1)

            elif cmd == self.PTRDEC:
                if val is None:
                    val = 1
                cellptr = max(0, cellptr - val)

            elif cmd == self.PTRSET:
                # XXX Do nothing if no value given!
                if val is not None:
                    cellptr = max(0, min(val, self.MAXCELLS - 1))
                    if cellptr >= len(cells):
                        cells += [0] * (cellptr - len(cells) + 1)

            elif cmd == self.INC:
                if val is None:
                    val = 1
                cells[cellptr] = (cells[cellptr] + val) % 255

            elif cmd == self.DEC:
                if val is None:
                    val = 1
                cells[cellptr] = (cells[cellptr] - val) % 255

            elif cmd == self.BOPEN and cells[cellptr] == 0:
                codeptr = bracemap[codeptr]

            elif cmd == self.BCLOSE and cells[cellptr] != 0:
                codeptr = bracemap[codeptr]

            elif cmd == self.OUTPUT:
                self.output(cells[cellptr])

            elif cmd == self.INPUT:
                inpt = self.input()
                if inpt:
                    # XXX If user can input non-ascii chars, this can raise
                    #     an exception... Might need better way to do this.
                    cells[cellptr] = ord(inpt[0].encode('ascii'))

            codeptr += 1

    ###########################################################################
    def optimize(self, code, compress=True):
        """
        Optimize opcode (using SegFaultProg features).
        In other words, produce an opcode with values as often as possible,
        gathering together similar (compatible) opcodes.
        If compress is True, will call compress_cells on optimized code.
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
                    if dlt:
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

        if compress:
            ret = self.compress_cells(ret)
        return ret

    def compress_cells(self, code):
        """
        Moves all used cells as near as possible to first (0) one.
        Can reduce quite higly Brainfuck & co code length!
        """
        ret = []
        cells = {}
        curr_ptr = 0
        new_ptr = 0
        _opptr = {self.PTRINC, self.PTRDEC, self.PTRSET}
        in_ptr_op = True  # We are at cell 0 at the begining, so...
        for opc, val in code:
            if opc not in _opptr:
                if in_ptr_op:
                    if curr_ptr not in cells:
                        cells[curr_ptr] = new_ptr
                        new_ptr += 1
                    ret.append((self.PTRSET, cells[curr_ptr]))
                    in_ptr_op = False
                ret.append((opc, val))
            else:
                if opc == self.PTRSET:
                    curr_ptr = val
                elif opc == self.PTRINC:
                    curr_ptr = min(curr_ptr + val, self.MAXCELLS)
                elif opc == self.PTRDEC:
                    curr_ptr = max(curr_ptr - val, 0)
                in_ptr_op = True

        return ret

    def no_values(self, code):
        """
        Move back opcode to be directly usable by Brainfuck & co.
        In other words, produce an opcode without any values (all are None).
        And obviously, no PTRSET either!
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
        Note: Number of opcodes applies directly to SegFaultProg, but not to
              Brainfuck and co (will be much more longer).
        """
        # We work in two passes: one to "parse" the code and detect points
        # where we have to "nullify" obfuscation effects on some cells, and
        # The other where we really generate the obfs code.
        cell_ptr = 0

        # First pass.
        # key: opcode ptr, value: cell(s) to reset, with for each cell, wether
        #                         to really reset value, or just mark it as
        #                         reset.
        null_points = {}
        in_loop = 0
        # We need to reset all cells involved in a loop, before it starts, and
        # after each run, else things are un-manageable!
        # Level 0 is main program, no need to fill it currently.
        lstack = [(0, {})]

        def _null_point(null_points, idx, ptr, do):
            if idx in null_points:
                null_points[idx].append((ptr, do))
            else:
                null_points[idx] = [(ptr, do)]

        for idx, opc_val in enumerate(code):
            opc, val = opc_val
            if opc == self.OUTPUT:
                _null_point(null_points, idx, cell_ptr, True)
            elif opc == self.INPUT:
                # No need to effectively reset the cell value here!
                _null_point(null_points, idx, cell_ptr, False)
            elif opc == self.BOPEN:
                in_loop += 1
                lstack.append((idx, {cell_ptr}))
            elif opc == self.BCLOSE:
                init_idx, cells = lstack[in_loop]
                for c in cells:
                    _null_point(null_points, init_idx, c, True)
                    _null_point(null_points, idx, c, True)
                del lstack[in_loop]
                in_loop -= 1
            elif opc == self.PTRSET:
                cell_ptr = val
            elif opc == self.PTRINC:
                cell_ptr = min(self.MAXCELLS - 1, cell_ptr + val)
            elif opc == self.PTRDEC:
                cell_ptr = max(0, cell_ptr - val)
            elif opc in {self.INC, self.DEC} and in_loop:
                # In loops, we have to systematically reset values before
                # modifying them, as we don’t know how much times the
                # obfuscating code affecting it is run...
                lstack[in_loop][1].add(cell_ptr)

        # Second pass.
        # This is a map of used cells, to control their modifications in
        # obfuscation process.
        cells = {}
        cell_ptr = 0
        factor -= 1
        if not factor:
            return code

        if code[0][0] not in {self.PTRSET, self.PTRINC, self.PTRDEC}:
            cells[0] = 0

        curr_nbr = factor
        ret = []
        for idx, opc_val in enumerate(code):
            opc, val = opc_val
            obfs, nbr_done = self.rand_null_opcode(cells, cell_ptr, curr_nbr)
            ret += obfs

            # If needed, reset the needed cell(s).
            tmp_ptr = cell_ptr
            for ptr, do in null_points.get(idx, []):
                if do and ptr in cells and cells[ptr]:
                    if ptr != tmp_ptr:
                        ret.append((self.PTRSET, ptr))
                        tmp_ptr = ptr
                        nbr_done += 1
                    if cells[ptr] > 127:
                        ret.append((self.INC, 255 - cells[ptr]))
                    else:
                        ret.append((self.DEC, cells[ptr]))
                    nbr_done += 1
                cells[ptr] = 0

            # update current cell pointer, if needed!
            if opc == self.PTRSET:
                cell_ptr = val
            elif opc == self.PTRINC:
                cell_ptr = min(self.MAXCELLS - 1, cell_ptr + val)
            elif opc == self.PTRDEC:
                cell_ptr = max(0, cell_ptr - val)
            elif tmp_ptr != cell_ptr:
                ret.append((self.PTRSET, cell_ptr))
                nbr_done += 1

            ret.append((opc, val))
            curr_nbr += factor - nbr_done

        return ret

    def rand_null_opcode(self, cells, org_ptr, nbr):
        """
        Generate some amount of opcode that does nothing!
        """
        # Avoid too big changes, would be over-verbose in Brainfuck & co.
        MAX_PTRSHIFT = 10
        MAX_VALSHIFT = 10
        # Randomize length of nop code.
        nbr = int(random.uniform(nbr * 0.5, nbr * 1.5))
        curr_ptr = org_ptr
        # We need at least two opcodes for obfuscation.
        if nbr < 2:
            return ([], 0)

        ret = []
        n = 0
        # We keep the last two opcodes to reset (cell pointer and/or value).
        while n < nbr - 1:
            # 3/10 to change current value, 1/10 to make a dummy loop (if
            # possible), 6/10 to change current pointer (cell).
            r = random.randint(1, 10)
            if r < 3:
                # Random value change.
                dlt = random.randint(0, MAX_VALSHIFT)
                if random.randint(0, 1):
                    ret.append((self.INC, dlt))
                    cells[curr_ptr] = (cells.get(curr_ptr, 0) + dlt) % 255
                else:
                    ret.append((self.DEC, dlt))
                    cells[curr_ptr] = (cells.get(curr_ptr, 0) - dlt) % 255
                n += 1
            elif r > 4:
                curr_ptr = random.randint(max(0, curr_ptr - MAX_PTRSHIFT),
                                          min(self.MAXCELLS - 1,
                                              curr_ptr + MAX_PTRSHIFT))
                ret.append((self.PTRSET, curr_ptr))
                n += 1
            elif n > 4 and curr_ptr not in cells:  # Only affect unsed cells!
                # Simple dummy loop reseting cell to zero, for now...
                if random.randint(0, 1):
                    ret += [(self.BOPEN, None), (self.INC, None),
                            (self.BCLOSE, None)]
                else:
                    ret += [(self.BOPEN, None), (self.DEC, None),
                            (self.BCLOSE, None)]
                n += 3
        # Finalize NOP code by returning to org_ptr cell (if needed).
        if curr_ptr != org_ptr:
            ret.append((self.PTRSET, org_ptr))
            n += 1
        return (ret, n)

    def convert(self, code, target, factor=1.0):
        """
        Convert some (textual form of) language to another one.
        Note that the ouput form is by default optimized, use the factor option
        if you want some obfuscation (see obfuscate() doc).
        """
        tp = detect_type(code)
        code = self.optimize(self.CONVERT_FUNCS[tp][0](self, code))
        self.reset_random()
        return self.CONVERT_FUNCS[target][1](self, self.obfuscate(code, factor))

    def bytes_to_opcode(self, bytes):
        """
        Convert a sequence of bytes into some (relatively optimized) opcode.

        Rough algo is that:
        * Find out all bytes (values) that are higly used. They will get
          “constant” cells.
        * Find out all other “blocks” of power-of-2 continuous values
          which contain some used bytes (values).
        E.g. if we have values 33, 64, 196, 178, 179, 222, and 33 and 196 are
        highly used, we’ll have:
        * cell 0 used as counter for loop which will init var cells.
        * a loop to init cell 1 (64), cell 2 (176), and cell 3 (208),
          provided we use at most 16 blocks (cells) for vars.
        * A static init of cell 4 to 33, and cell 5 to 196.

        Then it’s just a matter off going forth and back between defined
        cells, adjusting variable ones as needed, and ouputting values!
        """
        # Threshold under which a byte is common enough to get its own
        # "constant" cell.
        # XXX Seems that option is not really usefull, as it tend to
        #     produce longer code when not zero...
        CONST_T = 0
        # Number of variable cells, for other bytes values.
        # Must be a power of two, up to 256.
        BLOCKS = 32
        STEP = 256 // BLOCKS

        nbr = [0]*256
        ln_bytes = 0
        for b in bytes:
            nbr[b] += 1
            ln_bytes += 1
        # Find out bytes common enough to get a "const" cell for them own.
        consts = {}
        # Temp cell pointer, need to later offset all constant ones by the
        # room taken by variable ones.
        cell_ptr = 0
        for c, n in enumerate(nbr):
            if n and ln_bytes / n < CONST_T:
                consts[c] = cell_ptr
                cell_ptr += 1
                nbr[c] = 0  # We do not need this value anymore.
        # Now, find out the blocks we can avoid to init (i.e. those for wich
        # all values in nbr are 0).
        cell_ptr = 1  # We need the first cell as loop controller!
        var = {}
        var_val = {}
        STEP = 256 // BLOCKS
        idx = 0
        while idx < 256:
            if set(nbr[idx:idx + STEP]) != {0}:
                var[idx // STEP] = cell_ptr
                cell_ptr += 1
                var_val[idx // STEP] = idx
            idx += STEP
        # Now wa can offset constant pointers!
        off = len(var) + 1
        for c in consts:
            consts[c] += off

        ret = []
        # Let's init our cells (both variable and constant ones).
        ret.append((self.INC, STEP))
        # Loop to init var cells.
        if var:
            ret.append((self.BOPEN, None))
            idx = 1  # First var cell starts at zero (if needed).
            while idx < (256 // STEP):
                if idx in var:
                    ret.append((self.PTRSET, var[idx]))
                    ret.append((self.INC, idx))
                idx += 1
            ret.append((self.PTRSET, 0))
            ret.append((self.DEC, 1))
            ret.append((self.BCLOSE, None))
        # End of loop.
        # And now, constants (XXX Unordered init, not optimal...).
        for c, idx in consts.items():
            ret.append((self.PTRSET, idx))
            ret.append((self.INC, c))

        # And now, we can finally encode our bytes. Note idx is our current
        # cell pointer...
        cell_ptr = idx
        for b in bytes:
            if b in consts:
                if cell_ptr != consts[b]:
                    cell_ptr = consts[b]
                    ret.append((self.PTRSET, cell_ptr))
            else:
                idx = b // STEP
                if cell_ptr != var[idx]:
                    cell_ptr = var[idx]
                    ret.append((self.PTRSET, cell_ptr))
                if b != var_val[idx]:
                    dlt = b - var_val[idx]
                    if dlt > 0:
                        ret.append((self.INC, dlt))
                    elif dlt < 0:
                        ret.append((self.DEC, -dlt))
                    var_val[idx] = b
            ret.append((self.OUTPUT, None))

        # And we are done!
        return ret

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
        code = self.no_values(code)
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
        code = self.no_values(code)
        ret = []
        for opc, v in code:
            ret += self.TO_OOK[opc]
        return " Ook".join(ret).lstrip()  # Remove first space...

    def opc2fastook(self, code):
        """Convert opcode to ook (without "Ook" if full is False."""
        # Get Brainfuck & co compatible opcode.
        code = self.no_values(code)
        ret = []
        for opc, v in code:
            ret += self.TO_OOK[opc]
        return "".join(ret)

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
        code = self.no_values(code)
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
                    if dlt >= 0:
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


def cypher(bytes, lang=BRAINFUCK, obfs_fact=0.0, seed=None):
    """Simple wrapper to return bytes as code."""
    fact = obfs_fact * 5 + 1
    bf = BrainFuck(seed=seed)
    code = bf.bytes_to_opcode(bytes)
    bf.reset_random()
    code = bf.obfuscate(code, fact)
    bf.reset_random()
    txt = bf.CONVERT_FUNCS[lang][1](bf, code)
    return txt


def decypher(code):
    """Simple wrapper to return code interpreted output as bytes."""
    out = BytesOutput()
    BrainFuck(outpt=out).evaluate(code)
    return bytes(out)


def convert(code, lang=BRAINFUCK, obfs_fact=0.0, seed=None):
    """Simple wrapper to convert code to code."""
    fact = obfs_fact * 5 + 1
    bf = BrainFuck(seed=seed)
    return bf.convert(code, lang, fact)


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

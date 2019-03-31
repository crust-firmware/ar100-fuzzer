#!/usr/bin/python3
#
# Copyright © 2017-2019 The Crust Firmware Authors.
# SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
#

import itertools
import math
import os
import random
import sys
import textwrap

def limit(value):
    return value % 2**32


def random_value(signed=False, bits=32):
    if signed:
        return random.randrange(-2**(bits-1), 2**(bits-1))
    else:
        return random.randrange(0, 2**bits)


def rotate_right(value, bits):
    low_part = value >> bits
    high_part = limit(value << (32 - bits))
    return high_part | low_part


def sign_extend(value, from_bits):
    low_part = value & ((1 << from_bits) - 1)
    high_part = -(2**from_bits) if value & (1 << (from_bits - 1)) else 0
    return high_part | low_part


class Instruction(object):
    def __init__(self, name):
        self.name = name

    def _asm(self, out_names, in_names):
        # Generate the operand pattern
        operands = ', '.join('%' + str(n) for n in range(len(out_names + in_names)))
        return self.name + ' ' + operands

    def _post(self):
        return []

    def _pre(self):
        return []

    def assembly(self, inputs):
        """
        Return the GNU `asm` syntax for this instruction (and any pre/post
        instructions, if necessary).
        """
        # Grab the operand information from the subclass implementation
        out_constraints, in_constraints = self.constraints()
        out_names, in_names = self.names()
        # Sanity check
        if len(in_constraints) != len(in_names):
            raise ValueError
        if len(out_constraints) != len(out_names):
            raise ValueError
        # Get the actual assembly string
        asm = self._asm(out_names, in_names)
        # Map the inputs and outputs to the inline assembly syntax
        pattern = '"{0}" ({1})'
        # Register names for register operands; numbers for immediates
        in_values = []
        for op in zip(in_names, in_constraints, inputs):
            in_values.append(op[0] if 'r' in op[1] else op[2])
        in_params = ', '.join(pattern.format(c, n) for c, n in
                zip(in_constraints, in_values))
        out_params = ', '.join(pattern.format(c, n) for c, n in zip(out_constraints, out_names))
        return 'asm volatile ("{}" : {} : {});'.format(asm, out_params, in_params)

    def constraints(self):
        """
        Return a two-tuple of n-tuples: first the output constraints, followed
        by the input constraints.
        """
        return (), ()

    def format(self, inputs):
        """
        Return the assembly for this instruction, with all operands replaced by
        their literal values.
        """
        if not inputs:
            return self.name
        return self.name + ' [' + ', '.join(map(lambda i: hex(i % 2**32), inputs)) + ']'

    def names(self):
        """
        Return a two-tuple of n-tuples: first the output operand names,
        followed by the input operand names.
        """
        return (), ()

    def inputs(self):
        """
        Return an n-tuple containing arbitrarily chosen values for each input,
        in the same order as returned by names().
        """
        return ()

    def outputs(self, inputs):
        """
        Return an n-tuple containing the expected value for each output
        operand, in the same order as returned by names().
        """
        return ()

    def supported(self):
        """
        Return True if this instruction can be tested, otherwise False.
        """
        return False

    def test_impl(self):
        """
        Return the source code for a C function that can be called to test this
        instruction.
        """
        if self.supported():
            # Grab the operand information from the subclass implementation
            out_constraints, in_constraints = self.constraints()
            out_names, in_names = self.names()
            # Grab an arbitrary set of inputs and their respective outputs
            inputs = self.inputs()
            outputs = self.outputs(inputs)
            # Sanity check
            if len(inputs) != len(in_names):
                raise ValueError
            if len(outputs) != len(out_names):
                raise ValueError
            # Generate variable initialization code for register operands
            setup = [
                'exception = expected_exception = 0;',
                'label = &&trampoline;',
            ]
            for op in zip(in_names, in_constraints, inputs):
                if 'r' in op[1]:
                    setup.append(f'register uint32_t {op[0]} = {hex(op[2])};')
            for op in zip(out_names, out_constraints, outputs):
                if 'r' in op[1]:
                    setup.append(f'register uint32_t {op[0]}; // = {hex(op[2])}')
            # Grab the assembly statement
            asm = self.assembly(inputs)
            # Generate assertions for output variables
            checks = []
            for op in zip(out_names, outputs):
                if op[1] is not None:
                    checks.append(f'expect("{self.format(inputs)}", "{op[0]}", {op[0]}, {hex(op[1])});')
            # Generate the exception recovery trampoline
            tramp = [
                'trampoline: if (exception == expected_exception)',
                '\tstatus = PASS;',
                'else if (expected_exception == 0)',
                '\tstatus = NSUP;',
                'else',
                '\tstatus = FAIL;',
            ]
            # Concatenate all of the lines of code
            fail_stat = 'status = FAIL;'
            body = setup + self._pre() + [asm] + self._post() + [fail_stat] + checks + tramp
        else:
            body = [f'printf("Don\'t know how to test %s\\n", "{self.name}");']

        body_text = '\n'.join('\t' + line for line in body)
        return f'noinline void\n{self.test_name()}(void)\n{{\n{body_text}\n}}\n'

    def test_name(self):
        """
        Return the name of a C function that can be called to test this
        instruction.
        """
        return 'test_' + self.name.replace('.', '_')


class BFForm(Instruction):
    """
    Instructions that examine the flag and optionally branch.
    """
    def __init__(self, name, expr=None):
        super().__init__(name)
        self._expr = expr

    def _asm(self, out_names, in_names):
        return textwrap.dedent(f"""
            l.sfnei r0, %1\\n\\t
            {self.name} 1f\\n\\t
            l.or %0, r0, r0\\n\\t
            l.ori %0, r0, 1\\n\\t
            1: l.nop
        """).replace('\n', '')

    def constraints(self):
        return ('=r',), ('I')

    def names(self):
        return ('rD',), ('I')

    def inputs(self):
        return (random.choice((0, 1)),)

    def outputs(self, inputs):
        return (inputs[0] ^ int(self._expr),)

    def supported(self):
        return self._expr is not None


class CMOV(Instruction):
    """
    l.cmov takes two register inputs, and produces one register output based on
    the value of the flag.
    """
    def _asm(self, out_names, in_names):
        return 'l.sfnei r0, %3\\n\\tl.cmov %0, %1, %2'

    def constraints(self):
        return ('=r',), ('r', 'r', 'I')

    def names(self):
        return ('rD',), ('rA', 'rB', 'I')

    def inputs(self):
        return (random_value(), random_value(), random.choice((0, 1)))

    def outputs(self, inputs):
        return (inputs[0] if inputs[2] else inputs[1],)

    def supported(self):
        return True


class EForm(Instruction):
    """
    Simple instructions that trigger an exception.
    """
    def __init__(self, name, exc):
        super().__init__(name)
        self._exc = exc

    def _pre(self):
        return [f'expected_exception = {self._exc};']

    def constraints(self):
        return (), ('K',)

    def names(self):
        return (), ('K',)

    def inputs(self):
        return (random_value(bits=16),)

    def outputs(self, inputs):
        return ()

    def supported(self):
        return False


class LForm(Instruction):
    """
    Instructions that take one memory (register/offset) input, and produce one .
    register output.
    """
    def supported(self):
        return False


class MACForm(Instruction):
    """
    Instructions that read or update the multiply-accumulate registers.
    """
    def supported(self):
        return False


class MOVHI(Instruction):
    """
    l.movhi takes one unsigned immediate input, and produces one register
    output.
    """
    def constraints(self):
        return ('=r',), ('K',)

    def names(self):
        return ('rD',), ('K',)

    def inputs(self):
        return (random_value(bits=16),)

    def outputs(self, inputs):
        return (inputs[0] << 16,)

    def supported(self):
        return True


class RForm(Instruction):
    """
    Instructions that take one register input, and produce one register
    output.

    expr:   Expression relating the inputs to the output
    signed: Whether or not the operands are signed
    """
    def __init__(self, name, expr=None, signed=False):
        super().__init__(name)
        self._expr = expr
        self._signed = signed

    def constraints(self):
        return ('=r',), ('r',)

    def names(self):
        return ('rD',), ('rA',)

    def inputs(self):
        return (random_value(self._signed),)

    def outputs(self, inputs):
        return (self._expr(*inputs),)

    def supported(self):
        return self._expr is not None


class RIForm(Instruction):
    """
    Instructions that take one register input and one immediate input, and
    produce one register output.

    expr:   Expression relating the inputs to the output
    bits:   The number of bits used to represent the immediate operand
    signed: Whether or not the operands are signed
    """
    def __init__(self, name, expr=None, bits=16, signed=False):
        super().__init__(name)
        self._expr = expr
        self._bits = bits
        self._signed = signed

    def constraints(self):
        return ('=r',), ('r', 'I' if self._signed else 'K')

    def names(self):
        return ('rD',), ('rA', 'I' if self._signed else 'K')

    def inputs(self):
        return (random_value(self._signed),
                random_value(self._signed and self._bits != 5, self._bits))

    def outputs(self, inputs):
        return (self._expr(*inputs),)

    def supported(self):
        return self._expr is not None


class RRForm(Instruction):
    """
    Instructions that take two register inputs, and produce one register
    output.

    expr:   Expression relating the inputs to the output
    signed: Whether or not the operands are signed
    """
    def __init__(self, name, expr=None, bits=32, signed=False):
        super().__init__(name)
        self._expr = expr
        self._bits = bits
        self._signed = signed

    def constraints(self):
        return ('=r',), ('r', 'r')

    def names(self):
        return ('rD',), ('rA', 'rB')

    def inputs(self):
        return (random_value(self._signed),
                random_value(self._signed and self._bits != 5, self._bits))

    def outputs(self, inputs):
        return (self._expr(*inputs),)

    def supported(self):
        return self._expr is not None


class SForm(Instruction):
    """
    Instructions that take one register input, and produce one memory
    (register/offset) output.
    """
    def supported(self):
        return False


class SFForm(Instruction):
    """
    Instructions that take two register inputs, and set the value of the flag.
    """
    def __init__(self, name, expr=None, signed=False):
        super().__init__(name)
        self._expr = expr
        self._signed = signed

    def _asm(self, out_names, in_names):
        return textwrap.dedent(f"""
            {self.name} %1, %2\\n\\t
            l.bnf 1f\\n\\t
            l.or %0, r0, r0\\n\\t
            l.ori %0, r0, 1\\n\\t
            1: l.nop
        """).replace('\n', '')

    def constraints(self):
        return ('=r',), ('r', 'r')

    def names(self):
        return ('rD',), ('rA', 'rB')

    def inputs(self):
        return (random_value(self._signed), random_value(self._signed))

    def outputs(self, inputs):
        return (int(self._expr(*inputs)),)

    def supported(self):
        return self._expr is not None


class SFIForm(Instruction):
    """
    Instructions that one register input and one immediate input, and set the
    value of the flag.
    """
    def __init__(self, name, expr=None, signed=False):
        super().__init__(name)
        self._expr = expr
        self._signed = signed

    def _asm(self, out_names, in_names):
        return textwrap.dedent(f"""
            {self.name} %1, %2\\n\\t
            l.bnf 1f\\n\\t
            l.or %0, r0, r0\\n\\t
            l.ori %0, r0, 1\\n\\t
            1: l.nop
        """).replace('\n', '')

    def constraints(self):
        return ('=r',), ('r', 'i')

    def names(self):
        return ('rD',), ('rA', 'I')

    def inputs(self):
        # The immediate operand is always sign extended. Coerce it to a
        # positive number for unsigned comparisons to work on the Python side.
        immediate = random_value(True, bits=16)
        if not self._signed:
            immediate = immediate % 2**32
        return (random_value(self._signed), immediate)

    def outputs(self, inputs):
        return (int(self._expr(*inputs)),)

    def supported(self):
        return self._expr is not None


class XForm(Instruction):
    """
    Simple instructions with no operands.
    """
    def supported(self):
        return True


orbis32 = [
    RRForm('l.add', lambda a, b: limit(a + b)),
    Instruction('l.addc'),
    RIForm('l.addi', lambda a, b: limit(a + b), signed=True),
    Instruction('l.addic'),
    RRForm('l.and', lambda a, b: a & b),
    RIForm('l.andi', lambda a, b: a & b),
    BFForm('l.bf', True),
    BFForm('l.bnf', False),
    CMOV('l.cmov'),
    XForm('l.csync'),
    XForm('l.cust1'),
    XForm('l.cust2'),
    XForm('l.cust3'),
    XForm('l.cust4'),
    XForm('l.cust5'),
    XForm('l.cust6'),
    XForm('l.cust7'),
    XForm('l.cust8'),
    RRForm('l.div', lambda a, b: a // b, signed=True),
    RRForm('l.divu', lambda a, b: a // b),
    RForm('l.extbs', lambda a: sign_extend(a, 8), signed=True),
    RForm('l.extbz', lambda a: a % 2**8),
    RForm('l.exths', lambda a: sign_extend(a, 16), signed=True),
    RForm('l.exthz', lambda a: a % 2**16),
    RForm('l.extws', lambda a: a, signed=True),
    RForm('l.extwz', lambda a: a),
    RForm('l.ff1', lambda a: int(math.log(a, 2)) + 1 if a else 0),
    RForm('l.fl1', lambda a: int(math.log(a & -a, 2)) + 1 if a else 0),
    Instruction('l.j'),
    Instruction('l.jal'),
    Instruction('l.jalr'),
    Instruction('l.jr'),
    LForm('l.lbs'),
    LForm('l.lbz'),
    LForm('l.ld'),
    LForm('l.lhs'),
    LForm('l.lhz'),
    LForm('l.lwa'),
    LForm('l.lws'),
    LForm('l.lwz'),
    MACForm('l.mac'),
    MACForm('l.maci'),
    MACForm('l.macrc'),
    MACForm('l.macu'),
    Instruction('l.mfspr'),
    MOVHI('l.movhi'),
    MACForm('l.msb'),
    MACForm('l.msbu'),
    XForm('l.msync'),
    Instruction('l.mtspr'),
    RRForm('l.mul', lambda a, b: limit(a * b), signed=True),
    MACForm('l.muld'),
    MACForm('l.muldu'),
    RIForm('l.muli', lambda a, b: limit(a * b), signed=True),
    RRForm('l.mulu', lambda a, b: limit(a * b)),
    XForm('l.nop'),
    RRForm('l.or', lambda a, b: a | b),
    RIForm('l.ori', lambda a, b: a | b),
    XForm('l.psync'),
    Instruction('l.rfe'),
    RRForm('l.ror', lambda a, b: rotate_right(a, b % 32)),
    RIForm('l.rori', lambda a, b: rotate_right(a, b), bits=5),
    SForm('l.sb'),
    SForm('l.sd'),
    SFForm('l.sfeq', lambda a, b: a == b),
    SFIForm('l.sfeqi', lambda a, b: a == b),
    SFForm('l.sfges', lambda a, b: a >= b, signed=True),
    SFIForm('l.sfgesi', lambda a, b: a >= b, signed=True),
    SFForm('l.sfgeu', lambda a, b: a >= b),
    SFIForm('l.sfgeui', lambda a, b: a >= b),
    SFForm('l.sfgts', lambda a, b: a > b, signed=True),
    SFIForm('l.sfgtsi', lambda a, b: a > b, signed=True),
    SFForm('l.sfgtu', lambda a, b: a > b),
    SFIForm('l.sfgtui', lambda a, b: a > b),
    SFForm('l.sfles', lambda a, b: a <= b, signed=True),
    SFIForm('l.sflesi', lambda a, b: a <= b, signed=True),
    SFForm('l.sfleu', lambda a, b: a <= b),
    SFIForm('l.sfleui', lambda a, b: a <= b),
    SFForm('l.sflts', lambda a, b: a < b, signed=True),
    SFIForm('l.sfltsi', lambda a, b: a < b, signed=True),
    SFForm('l.sfltu', lambda a, b: a < b),
    SFIForm('l.sfltui', lambda a, b: a < b),
    SFForm('l.sfne', lambda a, b: a != b),
    SFIForm('l.sfnei', lambda a, b: a != b),
    SForm('l.sh'),
    RRForm('l.sll', lambda a, b: limit(a << (b % 32))),
    RIForm('l.slli', lambda a, b: limit(a << b), bits=5),
    RRForm('l.sra', lambda a, b: a >> (b % 32), signed=True),
    RIForm('l.srai', lambda a, b: a >> b, bits=5, signed=True),
    RRForm('l.srl', lambda a, b: a >> (b % 32)),
    RIForm('l.srli', lambda a, b: a >> b, bits=5),
    RRForm('l.sub', lambda a, b: limit(a - b), signed=True),
    SForm('l.sw'),
    SForm('l.swa'),
    EForm('l.sys', 'SYSTEM_CALL_EXCEPTION'),
    EForm('l.trap', 'TRAP_EXCEPTION'),
    RRForm('l.xor', lambda a, b: a ^ b),
]

def main():
    print(textwrap.dedent("""\
        /*
         * Copyright © 2017-2019 The Crust Firmware Authors.
         * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
         */

        #include <console.h>
        #include <exception.h>
        #include <stddef.h>
        #include <stdint.h>
        #include <util.h>

        #define noinline __attribute__((__noinline__))
        #define asm __asm__

        #define expect(expr, str, var, val) if (var != (uint32_t) val) { \\
        	printf("Incorrect value for %s in %s! Expected 0x%x, got 0x%x\\n", \\
        	       str, expr, val, var); \\
        	return; \\
        }

        enum status {
        	SKIP,
        	FAIL,
        	PASS,
                NSUP,
        };

        struct test {
        	const char *const name;
        	void (*const fn)(void);
        };

        /* The status of the current test. */
        volatile uint32_t status;
        /* The number of tests with each status. */
        uint32_t skip;
        uint32_t fail;
        uint32_t pass;
        uint32_t nsup;

        /* The address to return to after and exception. */
        void *volatile label;
        /* The number of the expected exception. */
        volatile uint32_t expected_exception;
        /* The number of the last exception. */
        volatile uint32_t exception;
    """))

    for inst in orbis32:
        print(inst.test_impl())

    print('const struct test tests[] = {')
    for inst in orbis32:
        print(f'\t{{ .name = "{inst.name}", .fn = {inst.test_name()} }},')
    print('};')

    print(textwrap.dedent("""
        #include <devices.h>
        #include <mmio.h>

        #define R_TWD_RESTART_KEY 0x0d140000

        enum {
                R_TWD_STAT_REG     = 0x0000,
                R_TWD_CTRL_REG     = 0x0010,
                R_TWD_RESTART_REG  = 0x0014,
                R_TWD_LOW_CNT_REG  = 0x0020,
                R_TWD_HIGH_CNT_REG = 0x0024,
                R_TWD_INTERVAL_REG = 0x0030,
        };

        void
        main(void) {
        	const char *message;

                /* Disable the watchdog. */
        	mmio_set_32(DEV_R_TWD + R_TWD_CTRL_REG, BIT(1) | BIT(9));

        	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
        		status = SKIP;
        		tests[i].fn();
        		switch(status) {
        		case SKIP:
        			skip++;
        			message = "SKIP: %s\\n";
        			break;
        		case FAIL:
        			fail++;
        			message = "FAIL: %s\\n";
        			break;
        		case PASS:
        			pass++;
        			message = "PASS: %s\\n";
        			break;
        		case NSUP:
        			nsup++;
        			message = "NSUP: %s\\n";
        			break;
        		default:
        			message = "UNKNOWN: %s\\n";
        			break;
        		}
        		printf(message, tests[i].name);
        	}
        	printf("%u tests: %u passed, %u failed, %u skipped, %u not supported\\n",
        	       ARRAY_SIZE(tests), pass, fail, skip, nsup);
        }\
    """))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Output file name required')
    #try:
    else:
        with open(sys.argv[1], 'w') as f:
            sys.stdout = f
            main()
    #except Exception as e:
    #    os.remove(sys.argv[1])
    #    sys.exit(str(e))

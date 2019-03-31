/*
 * Copyright © 2017-2019 The Crust Firmware Authors.
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
 */

#include <asm/exception.h>
#include <asm/macros.S>
#include <asm/spr.h>

func start
	l.mfspr	r2, r0, SPR_SYS_PPC_ADDR
	l.srli	r2, r2, 8
	l.sfleui r2, TRAP_EXCEPTION	# Check for a valid exception
	l.bnf	1f			# Resume startup if no exception
	l.nop
	l.sw	-132(r1), r3		# Save r3 on the stack
	l.movhi	r3, hi(exception)	# Get the exception number pointer
	l.ori	r3, r3, lo(exception)
	l.sw	0(r3), r2		# Save the exception number
	l.movhi	r2, hi(label)		# Get the return label pointer
	l.ori	r2, r2, lo(label)
	l.lwz	r2, 0(r2)		# Load the return label address
	l.jr	r2			# Jump back to the test procedure
	l.lwz	r3, -132(r1)		# Restore r3 from the stack
1:	l.addi	r3, r0, 0		# Invalidate instruction cache
	l.addi	r4, r0, 4096		# Cache lines (256) * block size (16)
1:	l.mtspr	r0, r3, SPR_ICACHE_ICBIR_ADDR
	l.sfltu	r3, r4
	l.bf	1b
	l.addi	r3, r3, 16		# Cache block size
	l.psync				# Flush CPU pipeline
	l.mfspr	r3, r0, SPR_SYS_SR_ADDR	# Enable instruction cache
	l.ori	r3, r3, SPR_SYS_SR_ICE_MASK
	l.mtspr	r0, r3, SPR_SYS_SR_ADDR
	l.nop				# One cache block of nops
	l.nop
	l.nop
	l.nop
	l.movhi	r5, hi(__bss_start)	# Clear .bss
	l.ori	r3, r5, lo(__bss_start)
	l.movhi	r5, hi(__bss_end)
	l.ori	r4, r5, lo(__bss_end)
1:	l.sw    0(r3), r0
	l.sfltu r3, r4
	l.bf	1b
	l.addi	r3, r3, 4
	l.movhi	r5, hi(__stack_end)
	l.j	main			# Jump to C entry point
	l.ori	r1, r5, lo(__stack_end)	# Initialize stack pointer
endfunc start

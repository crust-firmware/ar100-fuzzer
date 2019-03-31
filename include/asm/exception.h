/*
 * Copyright © 2017-2019 The Crust Firmware Authors.
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
 */

#ifndef ASM_EXCEPTION_H
#define ASM_EXCEPTION_H

#define RESET_EXCEPTION                  0x01
#define BUS_ERROR_EXCEPTION              0x02
#define DATA_PAGE_FAULT_EXCEPTION        0x03
#define INSTRUCTION_PAGE_FAULT_EXCEPTION 0x04
#define TICK_TIMER_EXCEPTION             0x05
#define ALIGNMENT_EXCEPTION              0x06
#define ILLEGAL_INSTRUCTION_EXCEPTION    0x07
#define INTERRUPT_EXCEPTION              0x08
#define DATA_TLB_MISS_EXCEPTION          0x09
#define INSTRUCTION_TLB_MISS_EXCEPTION   0x0a
#define RANGE_EXCEPTION                  0x0b
#define SYSTEM_CALL_EXCEPTION            0x0c
#define FLOATING_POINT_EXCEPTION         0x0d
#define TRAP_EXCEPTION                   0x0e

#define EXCEPTION_VECTOR_ADDRESS(n)      (0x100 * (n))

#endif /* ASM_EXCEPTION_H */

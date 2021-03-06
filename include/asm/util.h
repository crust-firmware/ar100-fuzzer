/*
 * Copyright © 2017-2019 The Crust Firmware Authors.
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
 */

#ifndef ASM_UTIL_H
#define ASM_UTIL_H

#ifdef __ASSEMBLER__
#define U(n)          (n)
#else
#define U(n)          (n ## U)
#endif

#define BIT(n)        (U(1) << (n))
#define GENMASK(h, l) ((U(0xffffffff) << (l)) & (U(0xffffffff) >> (31 - (h))))

#endif /* ASM_UTIL_H */

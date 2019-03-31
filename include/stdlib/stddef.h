/*
 * Copyright © 2005-2014 Rich Felker, et al.
 * Copyright © 2017-2019 The Crust Firmware Authors.
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
 */

#ifndef STDDEF_H
#define STDDEF_H

#define NULL                   ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)

typedef int      ptrdiff_t;
typedef unsigned size_t;

#endif /* STDDEF_H */

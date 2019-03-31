/*
 * Copyright © 2017-2019 The Crust Firmware Authors.
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
 */

#include <console.h>
#include <ctype.h>
#include <devices.h>
#include <mmio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <util.h>

#define BYTES_PER_ROW  16
#define BYTES_PER_WORD sizeof(uint32_t)

enum {
	UART_THR = 0x0000,
	UART_LSR = 0x0014,
};

enum {
	UART_LSR_THRE = BIT(5),
};

void
hexdump(uintptr_t addr, uint32_t bytes)
{
	uintptr_t start;

	/* Always start at a multiple of BYTES_PER_ROW. */
	addr &= ~(BYTES_PER_ROW - 1);
	for (start = addr; addr - start < bytes; addr += BYTES_PER_ROW) {
		uint32_t *words = (uint32_t *)addr;

		/* This assumes BYTES_PER_ROW is 16, which it will always be.
		 * It's more of an informational constant, not a variable. */
		printf("%08x: %08x %08x %08x %08x  ",
		       addr, words[0], words[1], words[2], words[3]);

		/* The ARISC processor's data lines are swapped in hardware for
		 * compatibility with the little-endian ARM CPUs. To examine
		 * individual bytes, we must reverse each group of 4 bytes. */
		for (int i = BYTES_PER_WORD - 1; i < BYTES_PER_ROW; --i) {
			char c = ((char *)addr)[i];
			putc(isprint(c) ? c : '.');
			if (i % BYTES_PER_WORD == 0)
				i += 2 * BYTES_PER_WORD;
		}
		putc('\n');
	}
}

static void
print_padding(int width, bool zero)
{
	for (int i = 0; i < width; ++i)
		putc(zero ? '0' : ' ');
}

static void
print_decimal(char sign, int width, bool zero, uint32_t num)
{
	unsigned digits  = 1;
	unsigned divisor = 1;

	while (divisor <= num / 10) {
		++digits;
		divisor *= 10;
	}
	if (sign) {
		putc(sign);
		--width;
	}
	print_padding(width - digits, zero);
	while (digits--) {
		uint32_t digit = 0;
		while (num >= divisor) {
			num -= divisor;
			++digit;
		}
		putc(digit + '0');
		divisor /= 10;
	}
}

static void
print_hex(int width, bool zero, uint32_t num)
{
	unsigned bits   = 8 * sizeof(num);
	unsigned digits = 2 * sizeof(num);

	while (digits > 1) {
		if ((num >> (bits - 4)) & 0xf)
			break;
		--digits;
		num <<= 4;
	}
	print_padding(width - digits, zero);
	while (digits--) {
		uint32_t digit = (num >> (bits - 4)) & 0xf;
		putc(digit < 10 ? digit + '0' : digit - 10 + 'a');
		num <<= 4;
	}
}

static void
print_signed(char sign, int width, bool zero, int32_t num)
{
	if (num < 0)
		print_decimal('-', width, zero, -num);
	else
		print_decimal(sign, width, zero, num);
}

static void
print_string(const char *s)
{
	while (*s)
		putc(*s++);
}

void
printf(const char *fmt, ...)
{
	bool zero;
	char c, sign;
	int  width;
	uintptr_t arg;
	va_list args;

	va_start(args, fmt);
	while ((c = *fmt++)) {
		if (c != '%') {
			putc(c);
			continue;
		}
		if (*fmt == '%') {
			++fmt;
			putc(c);
			continue;
		}
		arg   = va_arg(args, uintptr_t);
		sign  = '\0';
		width = 0;
		zero  = false;
conversion:
		switch ((c = *fmt++)) {
		case ' ':
			if (!sign)
				sign = ' ';
			goto conversion;
		case '+':
			sign = '+';
			goto conversion;
		case 'c':
			print_padding(width - 1, zero);
			putc(arg);
			break;
		case 'd':
		case 'i':
			print_signed(sign, width, zero, arg);
			break;
		case 'p':
			/* "%p" behaves like "0x%08x". */
			print_string("0x");
			width = 2 * sizeof(arg);
			zero  = true;
		/* falls through */
		case 'x':
			print_hex(width, zero, arg);
			break;
		case 's':
			print_padding(width - strlen((const char *)arg), zero);
			print_string((const char *)arg);
			break;
		case 'u':
			print_decimal(sign, width, zero, arg);
			break;
		default:
			if (c == '0' && width == 0)
				zero = true;
			else if (isdigit(c))
				width = 10 * width + (c - '0');
			goto conversion;
		}
	}
	va_end(args);
}

void
putc(char c)
{
	if (c == '\n')
		putc('\r');
	mmio_poll_32(DEV_UART0 + UART_LSR, UART_LSR_THRE);
	mmio_write_32(DEV_UART0 + UART_THR, c);
}

void
puts(const char *s)
{
	print_string(s);
	putc('\n');
}

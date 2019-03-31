#
# Copyright © 2017-2019 The Crust Firmware Authors.
# SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
#

SRC		 = .
OBJ		 = build

HOST		 = 

CROSS_COMPILE	?= or1k-linux-musl-
AR		 = $(CROSS_COMPILE)gcc-ar
CC		 = $(CROSS_COMPILE)gcc
CPP		 = $(CROSS_COMPILE)cpp
OBJCOPY		 = $(CROSS_COMPILE)objcopy

HOSTAR		 = ar
HOSTCC		 = cc

PYTHON		 = python3

COMMON_CFLAGS	 = -g -O1 -pipe -std=c11 \
		   -fdata-sections \
		   -ffunction-sections \
		   -fno-builtin \
		   -fno-common \
		   -fvar-tracking-assignments \
		   -Wall -Wextra -Wformat=2 -Wno-pedantic -Wshadow \
		   -Werror=implicit-function-declaration \
		   -Werror=implicit-int \
		   -Werror=pointer-arith \
		   -Werror=pointer-sign \
		   -Werror=strict-prototypes \
		   -Werror=vla \
		   -Wno-missing-field-initializers
COMMON_CPPFLAGS	 = -I$(SRC)/include \
		   -I$(SRC)/include/soc/a64

AFLAGS		 = -Wa,--fatal-warnings
CFLAGS		 = $(COMMON_CFLAGS) \
		   -ffixed-r2 \
		   -ffreestanding \
		   -flto \
		   -fno-asynchronous-unwind-tables \
		   -fno-pie \
		   -fomit-frame-pointer \
		   -funsigned-char \
		   -msoft-div -msoft-mul \
		   -static
CPPFLAGS	 = $(COMMON_CPPFLAGS) \
		   -I$(SRC)/include/stdlib \
		   -nostdinc \
		   -Werror=missing-include-dirs
LDFLAGS		 = -nostdlib \
		   -Wl,-O1 \
		   -Wl,--build-id=none \
		   -Wl,--fatal-warnings \
		   -Wl,--gc-sections \
		   -Wl,--no-dynamic-linker \
		   -Wl,--no-undefined

HOSTCFLAGS	 = $(COMMON_CFLAGS)
HOSTCPPFLAGS	 = $(COMMON_CPPFLAGS) \
		   -D_XOPEN_SOURCE=700
HOSTLDFLAGS	 =
HOSTLDLIBS	 =

###############################################################################

fuzzer	 = $(OBJ)/fuzzer.bin
loader	 = $(OBJ)/loader
objects	 = $(OBJ)/console.o \
	   $(OBJ)/start.o \
	   $(OBJ)/main.o \
	   $(OBJ)/runtime.o \
	   $(OBJ)/string.o

###############################################################################

M := @$(if $(filter-out 0,$(V)),:,exec printf '  %-7s %s\n')
Q :=  $(if $(filter-out 0,$(V)),,@)exec

all: fuzzer tools

check: run

clean:
	$(Q) rm -fr $(OBJ)

fuzzer: $(fuzzer)

run: $(fuzzer) $(loader)
	@scp $(fuzzer) root@$(HOST):/tmp/$(notdir $(fuzzer))
	@scp $(loader) root@$(HOST):/tmp/$(notdir $(loader))
	@ssh root@$(HOST) /tmp/$(notdir $(loader)) /tmp/$(notdir $(fuzzer))

tools: $(loader)

$(OBJ)/%.bin: $(OBJ)/%.elf
	$(M) OBJCOPY $@
	$(Q) $(OBJCOPY) -O binary -S --reverse-bytes 4 $< $@

$(OBJ)/%.elf $(OBJ)/%.map: $(OBJ)/%.ld $(objects)
	$(M) LD $@
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) -Wl,-Map,$(OBJ)/$*.map -o $@ -T $^

$(OBJ)/%.ld: $(SRC)/src/%.ld.S | $(OBJ)/.
	$(M) CPP $@
	$(Q) $(CPP) $(CPPFLAGS) -MMD -MF $@.d -MT $@ -P -o $@ $<

$(OBJ)/%.o: $(SRC)/src/%.S | $(OBJ)/.
	$(M) AS $@
	$(Q) $(CC) $(CPPFLAGS) $(AFLAGS) -MMD -c -o $@ $<

$(OBJ)/%.o: $(SRC)/src/%.c | $(OBJ)/.
	$(M) CC $@
	$(Q) $(CC) $(CPPFLAGS) $(CFLAGS) $(AFLAGS) -MMD -c -o $@ $<

$(OBJ)/%: $(OBJ)/%.o
	$(M) HOSTLD $@
	$(Q) $(HOSTCC) $(HOSTCFLAGS) $(HOSTLDFLAGS) -o $@ $^ $(HOSTLDLIBS)

$(OBJ)/%.o: $(SRC)/tools/%.c | $(OBJ)/.
	$(M) HOSTCC $@
	$(Q) $(HOSTCC) $(HOSTCPPFLAGS) $(HOSTCFLAGS) -MMD -c -o $@ $<

$(SRC)/%.c: $(SRC)/%.py
	$(M) GEN $@
	$(Q) $(PYTHON) $< $@

%/.:
	$(Q) mkdir -p $*

%.d:;
$(SRC)/Makefile:;

-include $(fuzzer:.bin=.ld.d) $(objects:.o=.d)

.PHONY: all check clean fuzzer run tools
.SECONDARY:
.SUFFIXES:

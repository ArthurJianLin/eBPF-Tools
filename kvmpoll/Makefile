# SPDX-License-Identifier: GPL-2.0
.SUFFIXES:
CC     = $(CROSS_COMPILE)gcc
CLANG  = $(CROSS_COMPILE)clang

BPF_MCPU ?= v1

CFLAGS += -iquote ./
CFLAGS += -iquote ../libbpf/src/
CLANGFLAGS += -iquote ../vmlinux/4.19/
CLANGFLAGS += -DENABLE_ATOMICS_TESTS -D__KERNEL__ \
	      -D__BPF_TRACING__ -D__TARGET_ARCH_x86 \
	      -DBPF_NO_PRESERVE_ACCESS_INDEX \
	      -g -fno-stack-protector -Werror \
	      -Wno-compare-distinct-pointer-types \
	      -fno-asynchronous-unwind-tables \
	      -fno-stack-protector -O2 -mlittle-endian \
	      -target bpf -mcpu=$(BPF_MCPU)

LIBBPF   = ../tools/libbpf.a.0.5.0
LDLIBS  += $(LIBBPF) -lelf -lz -lrt -lzstd

BPFTOOL = ../tools/bpftool
KVMPOLL_BIN = ../bin/kvmpoll

.PHONY: all clean kvmpoll
.DEFAULT_GOAL := all

define v0.5.0
@(cd ../libbpf && git reset --hard v0.5.0 && cd -)
endef

all: $(KVMPOLL_BIN)

clean:
	rm -f ./*.o kvmpoll.skel.h kvmpoll.bpf.o kvmpoll_user.o

kvmpoll.bpf.o: kvmpoll.bpf.c kvmpoll.h
	$(v0.5.0)
	$(CLANG) $(CFLAGS) $(CLANGFLAGS) -c -o $@ kvmpoll.bpf.c

kvmpoll.skel.h: kvmpoll.bpf.o
	$(BPFTOOL) gen skeleton kvmpoll.bpf.o > $@
	@(sed -i 's@#include <bpf/libbpf.h>@#include "libbpf.h"@g' $@)

kvmpoll_user.o: kvmpoll.c kvmpoll.skel.h kvmpoll.h
	$(v0.5.0)
	$(CC) $(CFLAGS) -g -c -o $@ kvmpoll.c

../libbpf/src/libbpf.a:
	cd ../libbpf && git reset --hard v0.5.0 && make -C src && cd -

../tools/libbpf.a.0.5.0: ../libbpf/src/libbpf.a
	cp ../libbpf/src/libbpf.a ../tools/libbpf.a.0.5.0

$(KVMPOLL_BIN): ../tools/libbpf.a.0.5.0 kvmpoll.skel.h kvmpoll_user.o
	$(v0.5.0)
	$(CC) -static -g -o $@ kvmpoll_user.o $(LDLIBS)

kvmpoll: $(KVMPOLL_BIN)

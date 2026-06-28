# SPDX-License-Identifier: GPL-2.0
.SUFFIXES:
CC     = $(CROSS_COMPILE)gcc
CLANG  = $(CROSS_COMPILE)clang

# Newer clang + -mcpu=v3/probe emits BPF_J32 (opcode 16) that 4.19 rejects.
# Override on newer-only hosts: make BPF_MCPU=probe
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
NUMAWAKE_BIN = ../bin/numawake
TOPO_BIN = ../bin/numawake_topo

.PHONY: all clean bpf topo numawake
.DEFAULT_GOAL := all

define v0.5.0
@(cd ../libbpf && git reset --hard v0.5.0 && cd -)
endef

all: bpf topo numawake

clean:
	rm -f ./*.o numawake.skel.h numawake.bpf.o

numawake_topology.o: numawake_topology.c numawake_topology.h numawake.h
	$(v0.5.0)
	$(CC) $(CFLAGS) -g -c -o $@ numawake_topology.c

numawake_topo.o: numawake_topo.c numawake_topology.h
	$(CC) $(CFLAGS) -g -c -o $@ numawake_topo.c

$(TOPO_BIN): ../tools/libbpf.a.0.5.0 numawake_topology.o numawake_topo.o
	$(v0.5.0)
	$(CC) -static -g -o $@ numawake_topo.o numawake_topology.o $(LDLIBS)

numawake.bpf.o: numawake.bpf.c numawake.h numawake_bpf.h
	$(v0.5.0)
	$(CLANG) $(CFLAGS) $(CLANGFLAGS) -c -o $@ numawake.bpf.c

bpf: numawake.bpf.o

numawake.skel.h: numawake.bpf.o
	$(BPFTOOL) gen skeleton numawake.bpf.o > $@
	@(sed -i 's@#include <bpf/libbpf.h>@#include "libbpf.h"@g' $@)

numawake_user.o: numawake.c numawake.skel.h numawake_topology.h
	$(v0.5.0)
	$(CC) $(CFLAGS) -g -c -o $@ numawake.c

numawake_print.o: numawake_print.c numawake_print.h
	$(CC) $(CFLAGS) -g -c -o $@ numawake_print.c

numawake_attach.o: numawake_attach.c numawake_attach.h
	$(v0.5.0)
	$(CC) $(CFLAGS) -g -c -o $@ numawake_attach.c

$(NUMAWAKE_BIN): ../tools/libbpf.a.0.5.0 numawake.skel.h numawake_user.o numawake_topology.o numawake_print.o numawake_attach.o
	$(v0.5.0)
	$(CC) -static -g -o $@ numawake_user.o numawake_topology.o numawake_print.o numawake_attach.o $(LDLIBS)

numawake: $(NUMAWAKE_BIN)

topo: $(TOPO_BIN)

../libbpf/src/libbpf.a:
	cd ../libbpf && git reset --hard v0.5.0 && make -C src && cd -

../tools/libbpf.a.0.5.0: ../libbpf/src/libbpf.a
	cp ../libbpf/src/libbpf.a ../tools/libbpf.a.0.5.0

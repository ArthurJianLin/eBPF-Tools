/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NUMAWAKE_BPF_H
#define __NUMAWAKE_BPF_H

/*
 * BPF-side helpers for enqueue_cpu / enqueue_ts updates.
 * Included only from numawake.bpf.c (and tests). User ABI: numawake.h.
 */

#include "numawake.h"

#ifndef BPF_ANY
#define BPF_ANY		0
#define BPF_NOEXIST	1
#define BPF_EXIST	2
#endif

/* Stashed kprobe entry args, keyed by smp_processor_id (valid only until kretprobe). */
struct numawake_choose_ctx {
	__u32 pid;
	__s32 prev_cpu;
};

#endif /* __NUMAWAKE_BPF_H */

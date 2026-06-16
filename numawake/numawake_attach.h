/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NUMAWAKE_ATTACH_H
#define __NUMAWAKE_ATTACH_H

struct bpf_program;

/*
 * Attach BPF to a tracepoint via perf_event_open + PERF_EVENT_IOC_SET_BPF.
 * Avoids bpf_link_create(), which fails with EACCES in some containers and
 * is unavailable on 4.19 anyway.
 * Returns perf_event fd (>= 0) or negative errno.
 */
int numawake_attach_tracepoint(struct bpf_program *prog,
			       const char *tp_category,
			       const char *tp_name);

#endif /* __NUMAWAKE_ATTACH_H */

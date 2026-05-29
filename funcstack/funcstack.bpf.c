// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 
 *
 * Yongkai Wu   Created this.
 *
 * TODO:
 * - support ustack
 * - support stack tracing in tracepoint
 */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "funcstack.h"

#define BPF_F_CURRENT_CPU 0xffffffffULL

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 127 * sizeof(u64));
	__uint(max_entries, 10000);
} stackmap SEC(".maps");

SEC("dummy")
int BPF_PROG(dummy_probe)
{
	struct event_t event = {}, *e;

	e = &event;

	e->pid = bpf_get_current_pid_tgid();
	e->start_ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

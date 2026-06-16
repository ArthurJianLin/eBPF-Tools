// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "verify_symbol.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static void bump_counter(__u32 key)
{
	__u64 *val, init = 1;

	val = bpf_map_lookup_elem(&counters, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
	else
		bpf_map_update_elem(&counters, &key, &init, BPF_ANY);
}

SEC("kretprobe/select_task_rq_fair")
int BPF_KRETPROBE(handle_select_task_rq_fair)
{
	bump_counter(CNT_SELECT_TASK_RQ_FAIR);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	bump_counter(CNT_SCHED_WAKEUP);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	bump_counter(CNT_SCHED_WAKEUP_NEW);
	return 0;
}

SEC("tracepoint/sched/sched_migrate_task")
int handle_sched_migrate_task(struct trace_event_raw_sched_migrate_task *ctx)
{
	bump_counter(CNT_SCHED_MIGRATE_TASK);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

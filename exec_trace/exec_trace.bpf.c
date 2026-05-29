// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* 
 *
 * 2025-06-11   Yongkai Wu   Created this.
 *
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "exec_trace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task, *parent_task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &task->real_parent);
	bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent_task->pid);
	bpf_probe_read_kernel_str(e->parent_comm, sizeof(e->parent_comm), parent_task->comm);

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

	return 0;
}

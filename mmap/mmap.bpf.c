/***************************************************************************************
*   DESCRIPTION : Source code of kernel mode for mmap ebpf tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2025-12-18 -- Guanbing Huang written
*****************************************************************************************/

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "mmap.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_enable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[TASK_COMM_LEN]);
} comm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u32);
} pid_map SEC(".maps");

#define MAX_ENTRIES     10240
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct mmap_event);
} enter_mmap_map SEC(".maps");

static int is_contained(char *str, char *sub)
{
	char *p1 = str;
	char *p2 = sub;
	int i = 0;
	while (i < TASK_COMM_LEN && *p2 != '\0') {
		if (*p1 != *p2) {
			return 0;
		}
		p1++;
		p2++;
		i++;
	}

	return 1;
}

static int skip(int pid)
{
	__u32 key = 0;
	__u32 *pvalue;
	__u32 *enable;
	char comm[TASK_COMM_LEN] = { 0 };

	enable = bpf_map_lookup_elem(&filter_enable_map, &key);
	if (enable == NULL || *enable == 0) {
		/* if fiflter disabled, not skip */
		return 0;
	}

	if (*enable == MMAP_ENV_COMM_EN) {
		key = 0;
		pvalue = bpf_map_lookup_elem(&comm_map, &key);
		if (pvalue) {
			bpf_get_current_comm(comm, sizeof(comm));
			int ret =is_contained(comm, (char*)pvalue);
			if (ret == 0) {
				/* user set process name, current process not match, skip */
				return 1;
			}
		}
		return 0;
	}

	if (*enable == MMAP_ENV_PID_EN) {
		pvalue = bpf_map_lookup_elem(&pid_map, &pid);
		if (pvalue == NULL) {
			/* user set pid, current pid not match, skip */
			return 1;
		}
	}
	return 0; /* match process name or pid, not skip */
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int mmap_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct mmap_event e = { 0 };
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();

	e.pid = pid_tgid >> 32;

	if (skip(e.pid)) {
		return 0;
	}

	bpf_get_current_comm(e.comm, sizeof(e.comm));
	e.type = EVENT_TYPE_MMAP;
	e.time_ns = bpf_ktime_get_ns();
	e.tgid = (__u32)pid_tgid;
	e.addr = ctx->args[0];
	e.len = ctx->args[1];
	e.prot = ctx->args[2];
	e.flags = ctx->args[3];
	e.fd = ctx->args[4];
	e.offset = ctx->args[5];

	bpf_map_update_elem(&enter_mmap_map, &e.pid, &e, BPF_ANY);

//	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int mmap_exit(struct trace_event_raw_sys_enter *ctx)
{
	struct mmap_event *e;
	__u64 pid_tgid;
	__u32 pid;

	pid_tgid = bpf_get_current_pid_tgid();

	pid = pid_tgid >> 32;

	if (skip(pid)) {
		return 0;
	}

	e = bpf_map_lookup_elem(&enter_mmap_map, &pid);
	if (e == NULL) {
		return 0;
	}

	e->addr = ctx->args[0];

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, e, sizeof(*e));

	bpf_map_delete_elem(&enter_mmap_map, &pid);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int munmap_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct munmap_event e = { 0 };
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();

	e.pid = pid_tgid >> 32;

	if (skip(e.pid)) {
		return 0;
	}

	bpf_get_current_comm(e.comm, sizeof(e.comm));
	e.type = EVENT_TYPE_MUNMAP;
	e.time_ns = bpf_ktime_get_ns();
	e.tgid = (__u32)pid_tgid;
	e.addr = ctx->args[0];
	e.len = ctx->args[1];

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

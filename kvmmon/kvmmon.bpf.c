// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * kvm_exit→kvm_entry latency histogram (first bucket 0–64 µs merged; HLT filtered).
 *
 * Userspace maintains monitored_tgids hash (QEMU thread-group IDs).
 * Per-tgid histogram in hists hash. Unmonitored tgids skip in tracepoints.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "kvmmon.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, KVMMON_MAX_MONITORED);
	__type(key, __u32);
	__type(value, __u8);
} monitored_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} stack_thresh_map SEC(".maps");

struct trace_event_raw_kvm_exit {
	struct trace_entry ent;
	__u32 exit_reason;
	__u8 __pad1[4];
	__u64 guest_rip;
	__u32 isa;
	__u8 __pad2[4];
	__u64 info1;
	__u64 info2;
};

struct trace_event_raw_kvm_userspace_exit {
	struct trace_entry ent;
	__u32 reason;
	__s32 kvm_errno;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct kvm_pending);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, KVMMON_MAX_MONITORED);
	__type(key, __u32);
	__type(value, struct kvm_hist);
} hists SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 127 * sizeof(__u64));
	__uint(max_entries, 4096);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} perf_buf SEC(".maps");

static __always_inline __u64 cfg_stack_thresh(void)
{
	__u32 k = 0;
	__u64 *p = bpf_map_lookup_elem(&stack_thresh_map, &k);

	return p ? *p : 0;
}

static __always_inline int targ_match(__u32 tgid)
{
	__u8 *v = bpf_map_lookup_elem(&monitored_tgids, &tgid);

	return v && *v;
}

static __always_inline int is_hlt(__u32 reason, __u32 isa)
{
	if (isa == KVM_ISA_VMX)
		return (reason & 0xffffu) == VMX_EXIT_HLT;
	if (isa == KVM_ISA_SVM)
		return reason == SVM_EXIT_HLT;
	return 0;
}

static __always_inline void hist_account(__u32 tgid, __u64 delta_ns)
{
	struct kvm_hist *hp;
	struct kvm_hist z = {};
	__u64 us = delta_ns / 1000;

	hp = bpf_map_lookup_elem(&hists, &tgid);
	if (!hp) {
		bpf_map_update_elem(&hists, &tgid, &z, BPF_ANY);
		hp = bpf_map_lookup_elem(&hists, &tgid);
		if (!hp)
			return;
	}

	__sync_fetch_and_add(&hp->sum_us, us);

	/* Slot 0: merged 0–64 µs (exclusive upper bound 64). */
	if (us < 64) {
		__sync_fetch_and_add(&hp->slots[0], 1);
	} else if (us < 128) {
		__sync_fetch_and_add(&hp->slots[1], 1);
	} else if (us < 256) {
		__sync_fetch_and_add(&hp->slots[2], 1);
	} else if (us < 512) {
		__sync_fetch_and_add(&hp->slots[3], 1);
	} else if (us < 1024) {
		__sync_fetch_and_add(&hp->slots[4], 1);
	} else {
		__sync_fetch_and_add(&hp->slots[5], 1);
	}
}

SEC("tracepoint/kvm/kvm_exit")
int tp_kvm_exit(struct trace_event_raw_kvm_exit *ctx)
{
	struct kvm_pending p = {};
	__u64 pt;
	__u32 tid, tgid;

	pt = bpf_get_current_pid_tgid();
	tgid = pt >> 32;
	if (!targ_match(tgid))
		return 0;

	tid = (__u32)pt;

	p.ts_ns = bpf_ktime_get_ns();
	p.exit_reason = ctx->exit_reason;
	p.isa = ctx->isa;
	bpf_map_update_elem(&pending, &tid, &p, BPF_ANY);
	return 0;
}

SEC("tracepoint/kvm/kvm_userspace_exit")
int tp_kvm_userspace_exit(struct trace_event_raw_kvm_userspace_exit *ctx)
{
	__u64 pt;
	__u32 tid, tgid;

	(void)ctx;
	pt = bpf_get_current_pid_tgid();
	tgid = pt >> 32;
	if (!targ_match(tgid))
		return 0;

	tid = (__u32)pt;
	bpf_map_delete_elem(&pending, &tid);
	return 0;
}

SEC("tracepoint/kvm/kvm_entry")
int tp_kvm_entry(void *ctx)
{
	struct kvm_pending *pp;
	__u64 pt, now, lat;
	__u32 tid, tgid;
	__u64 sth;

	pt = bpf_get_current_pid_tgid();
	tgid = pt >> 32;
	if (!targ_match(tgid))
		return 0;

	tid = (__u32)pt;

	pp = bpf_map_lookup_elem(&pending, &tid);
	if (!pp || !pp->ts_ns)
		return 0;

	now = bpf_ktime_get_ns();
	lat = now - pp->ts_ns;
	if ((s64)lat < 0) {
		bpf_map_delete_elem(&pending, &tid);
		return 0;
	}

	if (!is_hlt(pp->exit_reason, pp->isa))
		hist_account(tgid, lat);

	sth = cfg_stack_thresh();
	if (sth && lat >= sth && !is_hlt(pp->exit_reason, pp->isa)) {
		struct kvm_long_event ev;
		volatile __u64 *p = (volatile __u64 *)&ev;

		p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 0; p[4] = 0;
		ev.ts_ns = now;
		ev.latency_ns = lat;
		ev.tgid = tgid;
		ev.tid = tid;
		ev.exit_reason = pp->exit_reason;
		ev.isa = pp->isa;
		ev.stack_id = (__s32)bpf_get_stackid(ctx, &stack_traces, 0);
		bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &ev,
				      sizeof(ev));
	}

	bpf_map_delete_elem(&pending, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

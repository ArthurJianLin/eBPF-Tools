// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "kvmpoll.h"

#define TASK_RUNNING	0

/*
 * 4.19 kvm_vcpu_wakeup — confirm field layout via tracefs format on target host.
 */
struct trace_event_raw_kvm_vcpu_wakeup {
	struct trace_entry ent;
	__u64 ns;
	__u8 waited;
	__u8 valid;
	__u8 __pad[6];
};

/*
 * 4.19 kvm_halt_poll_ns — grow/shrink updates per-vcpu budget (new field).
 * Fires on grow_halt_poll_ns / shrink_halt_poll_ns, not every poll start.
 */
struct trace_event_raw_kvm_halt_poll_ns {
	struct trace_entry ent;
	__u8 grow;
	__u8 __pad[3];
	__u32 vcpu_id;
	__s32 new_ns;
	__s32 old_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, KVMPOLL_MAX_MONITORED);
	__type(key, __u32);
	__type(value, __u8);
} monitored_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} vcpu_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct kvmpoll_fail_pending);
} fail_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NS_NS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} ns_sum SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kvmpoll_hist);
} hist_success SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kvmpoll_hist);
} hist_fail SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kvmpoll_hist);
} hist_event_wait SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kvmpoll_hist);
} hist_runqueue SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kvmpoll_hist);
} hist_mechanism_tax SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kvmpoll_hist);
} hist_poll_actual SEC(".maps");

/* Per vCPU thread: kvm_vcpu_block() entry time (T_block_entry). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} block_start SEC(".maps");

/* Per vCPU thread: current halt poll budget (ns). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} poll_budget SEC(".maps");

/* [0] = default budget when thread has no map entry (module halt_poll_ns). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} default_poll_ns SEC(".maps");

static __always_inline int targ_match(__u32 tgid)
{
	__u8 *v = bpf_map_lookup_elem(&monitored_tgids, &tgid);

	return v && *v;
}

static __always_inline int vcpu_tracked(__u32 pid)
{
	__u8 *v;

	if (!pid)
		return 0;
	v = bpf_map_lookup_elem(&vcpu_pids, &pid);
	return v && *v;
}

static __always_inline void track_vcpu(__u32 pid)
{
	__u8 one = 1;

	if (pid)
		bpf_map_update_elem(&vcpu_pids, &pid, &one, BPF_ANY);
}

static __always_inline void bump(__u32 key)
{
	__u64 *val, init = 1;

	val = bpf_map_lookup_elem(&counters, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
	else
		bpf_map_update_elem(&counters, &key, &init, BPF_ANY);
}

static __always_inline void add_ns(__u32 key, __u64 ns)
{
	__u64 *val;

	if (!ns)
		return;

	val = bpf_map_lookup_elem(&ns_sum, &key);
	if (!val)
		return;
	__sync_fetch_and_add(val, ns);
}

static __always_inline __u64 default_budget(void)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&default_poll_ns, &key);

	if (!v || !*v)
		return KVMPOLL_DEFAULT_HALT_POLL_NS;
	return *v;
}

static __always_inline __u64 thread_budget(__u32 pid)
{
	__u64 *v = bpf_map_lookup_elem(&poll_budget, &pid);
	__u64 b;

	if (v && *v)
		b = *v;
	else
		b = default_budget();
	if (!b)
		b = KVMPOLL_DEFAULT_HALT_POLL_NS;
	return b;
}

static __always_inline __u32 hist_slot(__u64 ns)
{
	__u64 us = ns / 1000;

	if (us < KVMPOLL_HIST_US_0_30)
		return 0;
	if (us < KVMPOLL_HIST_US_30_64)
		return 1;
	if (us < KVMPOLL_HIST_US_64_128)
		return 2;
	if (us < KVMPOLL_HIST_US_128_256)
		return 3;
	if (us < KVMPOLL_HIST_US_256_512)
		return 4;
	if (us < KVMPOLL_HIST_US_512_1024)
		return 5;
	if (us < KVMPOLL_HIST_US_1024_2048)
		return 6;
	return 7;
}

static __always_inline void hist_account(void *hist_map, __u64 ns)
{
	__u32 key = 0;
	struct kvmpoll_hist *hp;
	struct kvmpoll_hist z = {};
	__u32 slot;

	if (!ns)
		return;

	hp = bpf_map_lookup_elem(hist_map, &key);
	if (!hp) {
		bpf_map_update_elem(hist_map, &key, &z, BPF_ANY);
		hp = bpf_map_lookup_elem(hist_map, &key);
		if (!hp)
			return;
	}

	slot = hist_slot(ns);
	if (slot >= KVMPOLL_HIST_SLOTS)
		slot = KVMPOLL_HIST_SLOTS - 1;

	__sync_fetch_and_add(&hp->slots[slot], 1);
	__sync_fetch_and_add(&hp->total, 1);
}

static __always_inline void block_start_delete(__u32 pid)
{
	if (pid)
		bpf_map_delete_elem(&block_start, &pid);
}

static __always_inline void fail_pending_delete(__u32 pid)
{
	if (pid) {
		bpf_map_delete_elem(&fail_pending, &pid);
		block_start_delete(pid);
	}
}

static __always_inline void fail_pending_expire(__u32 pid, __u64 now)
{
	struct kvmpoll_fail_pending *fp;

	if (!pid)
		return;

	fp = bpf_map_lookup_elem(&fail_pending, &pid);
	if (!fp || !fp->t_sleep)
		return;

	if (now - fp->t_sleep > KVMPOLL_ATTRIB_EXPIRE_NS)
		fail_pending_delete(pid);
}

static __always_inline void fail_pending_on_sleep(__u32 pid, __u64 now)
{
	struct kvmpoll_fail_pending fp = {};
	__u64 *t0;

	if (!pid)
		return;

	fail_pending_expire(pid, now);

	t0 = bpf_map_lookup_elem(&block_start, &pid);
	if (t0 && now > *t0)
		fp.poll_actual = now - *t0;

	fp.t_sleep = now;
	fp.flags = KVMPOLL_FA_SLEEP;
	bpf_map_update_elem(&fail_pending, &pid, &fp, BPF_ANY);
	block_start_delete(pid);
}

static __always_inline void fail_pending_on_wakeup(__u32 pid, __u64 now)
{
	struct kvmpoll_fail_pending *fp, val;

	if (!pid)
		return;

	fail_pending_expire(pid, now);

	fp = bpf_map_lookup_elem(&fail_pending, &pid);
	if (!fp || !(fp->flags & KVMPOLL_FA_SLEEP))
		return;

	val = *fp;
	val.t_wakeup = now;
	val.flags |= KVMPOLL_FA_WOKEN;
	bpf_map_update_elem(&fail_pending, &pid, &val, BPF_ANY);
}

static __always_inline void fail_pending_on_run(__u32 pid, __u64 now)
{
	struct kvmpoll_fail_pending *fp, val;
	__u64 rq;

	if (!pid)
		return;

	fp = bpf_map_lookup_elem(&fail_pending, &pid);
	if (!fp || !(fp->flags & KVMPOLL_FA_WOKEN) || !fp->t_wakeup)
		return;
	if (fp->flags & KVMPOLL_FA_RUN)
		return;

	rq = now - fp->t_wakeup;
	if ((s64)rq < 0)
		return;

	val = *fp;
	val.runqueue_ns = rq;
	val.flags |= KVMPOLL_FA_RUN;
	bpf_map_update_elem(&fail_pending, &pid, &val, BPF_ANY);
}

static __always_inline void fail_close_attrib(__u32 pid, __u64 ns, __u64 poll_budget)
{
	struct kvmpoll_fail_pending *fp;
	__u64 event_wait, runqueue, post_poll, mechanism_tax, poll_used;
	__u8 paired;

	fp = bpf_map_lookup_elem(&fail_pending, &pid);
	paired = fp && (fp->flags & KVMPOLL_FA_SLEEP) &&
		 (fp->flags & KVMPOLL_FA_WOKEN) &&
		 (fp->flags & KVMPOLL_FA_RUN);

	poll_used = poll_budget;
	if (fp && fp->poll_actual)
		poll_used = fp->poll_actual;

	if (paired) {
		event_wait = fp->t_wakeup > fp->t_sleep ?
			     fp->t_wakeup - fp->t_sleep : 0;
		runqueue = fp->runqueue_ns;
		if (event_wait) {
			add_ns(NS_FAIL_EVENT_WAIT, event_wait);
			hist_account(&hist_event_wait, event_wait);
		}
		if (runqueue) {
			add_ns(NS_FAIL_RUNQUEUE, runqueue);
			hist_account(&hist_runqueue, runqueue);
		}
		if (fp->poll_actual) {
			add_ns(NS_FAIL_POLL_ACTUAL, fp->poll_actual);
			hist_account(&hist_poll_actual, fp->poll_actual);
		}
		post_poll = ns > poll_used ? ns - poll_used : 0;
		mechanism_tax = post_poll > event_wait ? post_poll - event_wait : 0;
		if (mechanism_tax) {
			add_ns(NS_FAIL_MECHANISM_TAX, mechanism_tax);
			hist_account(&hist_mechanism_tax, mechanism_tax);
		}
		bump(CNT_ATTRIB_PAIRED);
	} else {
		bump(CNT_ATTRIB_UNPAIRED);
	}

	fail_pending_delete(pid);
}

SEC("tracepoint/kvm/kvm_halt_poll_ns")
int handle_kvm_halt_poll_ns(struct trace_event_raw_kvm_halt_poll_ns *ctx)
{
	__u64 pt, budget;
	__u32 tgid, pid;

	pt = bpf_get_current_pid_tgid();
	tgid = pt >> 32;
	pid = (__u32)pt;
	if (!targ_match(tgid))
		return 0;

	track_vcpu(pid);
	budget = ctx->new_ns > 0 ? (__u64)ctx->new_ns : 0;
	bpf_map_update_elem(&poll_budget, &pid, &budget, BPF_ANY);
	return 0;
}

SEC("tracepoint/kvm/kvm_vcpu_wakeup")
int handle_kvm_vcpu_wakeup(struct trace_event_raw_kvm_vcpu_wakeup *ctx)
{
	__u64 pt, ns = ctx->ns, poll_spin;
	__u32 tgid, pid;
	__u8 waited = ctx->waited;
	__u8 valid = ctx->valid;

	pt = bpf_get_current_pid_tgid();
	tgid = pt >> 32;
	pid = (__u32)pt;
	if (!targ_match(tgid))
		return 0;

	track_vcpu(pid);
	bump(CNT_WAKEUP_TOTAL);

	if (waited) {
		poll_spin = thread_budget(pid);
		bump(CNT_FAIL);
		add_ns(NS_FAIL_BLOCK, ns);
		add_ns(NS_FAIL_POLL_SPIN, poll_spin);
		hist_account(&hist_fail, ns);
		fail_close_attrib(pid, ns, poll_spin);
	} else if (valid) {
		bump(CNT_SUCCESS);
		add_ns(NS_SUCCESS, ns);
		hist_account(&hist_success, ns);
		fail_pending_delete(pid);
	} else {
		bump(CNT_INVALID);
		fail_pending_delete(pid);
	}

	return 0;
}

static __always_inline int record_sched_wakeup(
	struct trace_event_raw_sched_wakeup_template *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 pid = ctx->pid;

	if (!vcpu_tracked(pid))
		return 0;

	fail_pending_on_wakeup(pid, now);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	return record_sched_wakeup(ctx);
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	return record_sched_wakeup(ctx);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	pid_t prev_pid = ctx->prev_pid;
	long prev_state = ctx->prev_state;
	pid_t next_pid = ctx->next_pid;

	if (prev_pid && prev_pid != next_pid && vcpu_tracked(prev_pid) &&
	    prev_state != TASK_RUNNING)
		fail_pending_on_sleep((__u32)prev_pid, now);

	if (next_pid && vcpu_tracked(next_pid))
		fail_pending_on_run((__u32)next_pid, now);

	return 0;
}

SEC("kprobe/kvm_vcpu_block")
int kprobe_kvm_vcpu_block(struct pt_regs *ctx)
{
	__u64 pt, now = bpf_ktime_get_ns();
	__u32 tgid, pid;

	(void)ctx;

	pt = bpf_get_current_pid_tgid();
	tgid = pt >> 32;
	pid = (__u32)pt;
	if (!targ_match(tgid))
		return 0;

	bpf_map_update_elem(&block_start, &pid, &now, BPF_ANY);
	bump(CNT_BLOCK_ENTRY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

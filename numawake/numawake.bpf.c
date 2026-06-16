// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "numawake_bpf.h"

#define BPF_F_CURRENT_CPU 0xffffffffULL

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct numawake_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} filter_enable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u32);
	__type(value, u32);
} pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUMAWAKE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct numawake_choose_ctx);
} choose_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct pending_wake);
} pending_wake SEC(".maps");

/*
 * cpu_id -> NUMA node id, filled by user space from sysfs node cpulist
 * (see numawake_topology.c).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUMAWAKE_MAX_CPUS);
	__type(key, u32);
	__type(value, u8);
} cpu_to_node_map SEC(".maps");

static __always_inline u8 numawake_cpu_node(u32 cpu)
{
	u8 *node;

	if (cpu >= NUMAWAKE_MAX_CPUS)
		return NUMAWAKE_NODE_UNKNOWN;

	node = bpf_map_lookup_elem(&cpu_to_node_map, &cpu);
	if (!node)
		return NUMAWAKE_NODE_UNKNOWN;
	return *node;
}

static __always_inline int goskip(pid_t pid)
{
	u32 key = 0;
	u32 *en;

	if (!pid)
		return 1;

	en = bpf_map_lookup_elem(&filter_enable_map, &key);
	if (!en || *en == 0)
		return 0;

	if (bpf_map_lookup_elem(&pid_map, &pid))
		return 0;
	return 1;
}

static __always_inline void pending_delete(u32 pid)
{
	if (pid)
		bpf_map_delete_elem(&pending_wake, &pid);
}

/*
 * choose 之后长时间无闭环（无 wakeup / switch）则删除，防止 Map 泄漏。
 */
static __always_inline void pending_try_expire(u32 pid)
{
	struct pending_wake *pw;
	u64 now;

	if (!pid)
		return;

	pw = bpf_map_lookup_elem(&pending_wake, &pid);
	if (!pw)
		return;

	now = bpf_ktime_get_ns();
	if (pw->choose_ts && now - pw->choose_ts > NUMAWAKE_PENDING_STALE_NS)
		pending_delete(pid);
}

static __always_inline int pending_update_enqueue(pid_t pid, int cpu, u32 or_flags,
						  bool refresh_ts)
{
	struct pending_wake *pw, val;
	u64 ts = bpf_ktime_get_ns();

	pw = bpf_map_lookup_elem(&pending_wake, &pid);
	if (!pw)
		return 0;

	val = *pw;
	val.enqueue_cpu = cpu;
	if (refresh_ts)
		val.enqueue_ts = ts;
	val.flags |= or_flags;
	return bpf_map_update_elem(&pending_wake, &pid, &val, BPF_ANY);
}

/*
 * psrun-style log2 latency buckets (ms). 4.19 verifier rejects log2l on map slots.
 */
static __always_inline void numawake_hist_record(struct numawake_hist *hp, u64 delta_ms)
{
	if (!hp)
		return;

	if (delta_ms < 2) {
		__sync_fetch_and_add(&hp->slots[0], 1);
	} else if (delta_ms < 4) {
		__sync_fetch_and_add(&hp->slots[1], 1);
	} else if (delta_ms < 8) {
		__sync_fetch_and_add(&hp->slots[2], 1);
	} else if (delta_ms < 16) {
		__sync_fetch_and_add(&hp->slots[3], 1);
	} else if (delta_ms < 32) {
		__sync_fetch_and_add(&hp->slots[4], 1);
	} else if (delta_ms < 64) {
		__sync_fetch_and_add(&hp->slots[5], 1);
	} else if (delta_ms < 128) {
		__sync_fetch_and_add(&hp->slots[6], 1);
	} else if (delta_ms < 256) {
		__sync_fetch_and_add(&hp->slots[7], 1);
	} else if (delta_ms < 512) {
		__sync_fetch_and_add(&hp->slots[8], 1);
	} else if (delta_ms < 1024) {
		__sync_fetch_and_add(&hp->slots[9], 1);
	} else if (delta_ms < 2048) {
		__sync_fetch_and_add(&hp->slots[10], 1);
	} else if (delta_ms < 4096) {
		__sync_fetch_and_add(&hp->slots[11], 1);
	} else {
		__sync_fetch_and_add(&hp->slots[13], 1);
	}
}

static __always_inline struct numawake_stats *stats_get(void)
{
	u32 key = 0;
	struct numawake_stats *st;
	struct numawake_stats zero = {};

	st = bpf_map_lookup_elem(&stats, &key);
	if (st)
		return st;

	bpf_map_update_elem(&stats, &key, &zero, BPF_ANY);
	return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline void stats_record_event(struct numawake_stats *st,
					       struct numawake_event *ev)
{
	struct numawake_hist *hp;
	u64 delta_ms;
	int cross;

	if (!st || !ev)
		return;

	cross = numawake_is_cross_numa_wake(ev->flags);

	if (cross)
		__sync_fetch_and_add(&st->cross_numa_wake, 1);
	else
		__sync_fetch_and_add(&st->same_numa_wake, 1);

	if (numawake_is_landing_deviation(ev->flags))
		__sync_fetch_and_add(&st->landing_deviation, 1);

	if (ev->flags & NUMAWAKE_F_SANITY_MISMATCH)
		__sync_fetch_and_add(&st->sanity_mismatch, 1);

	if (ev->latency_ns == 0)
		return;

	delta_ms = ev->latency_ns / 1000000U;
	hp = cross ? &st->cross_numa_lat : &st->same_numa_lat;
	numawake_hist_record(hp, delta_ms);
}

SEC("kprobe/select_task_rq_fair")
int BPF_KPROBE(entry_select_task_rq_fair, struct task_struct *p, int prev_cpu,
	       int sd_flags, int wake_flags)
{
	struct numawake_choose_ctx cctx = {};
	u32 cpu = bpf_get_smp_processor_id();

	/* Key = 被唤醒任务 p->pid，禁止用 bpf_get_current_pid_tgid() */
	bpf_probe_read(&cctx.pid, sizeof(cctx.pid), &p->pid);
	cctx.prev_cpu = prev_cpu;
	bpf_map_update_elem(&choose_args, &cpu, &cctx, BPF_ANY);
	return 0;
}

SEC("kretprobe/select_task_rq_fair")
int BPF_KRETPROBE(ret_select_task_rq_fair)
{
	struct numawake_choose_ctx *cctx;
	struct pending_wake pw = {};
	u32 cpu = bpf_get_smp_processor_id();
	int ideal_cpu;
	u32 pid;

	/*
	 * 禁止在 kretprobe 使用 PT_REGS_PARM1 取 p：返回时寄存器已失效。
	 * 与 entry 通过当前 CPU 配对 choose_args（同一次调用仍在同一 CPU 上）。
	 */
	cctx = bpf_map_lookup_elem(&choose_args, &cpu);
	if (!cctx)
		return 0;

	ideal_cpu = PT_REGS_RC(ctx);
	pid = cctx->pid;

	if (goskip(pid))
		return 0;

	pending_try_expire(pid);

	pw.pid = pid;
	pw.flags = NUMAWAKE_PF_SEEN_CHOOSE;
	pw.prev_cpu = cctx->prev_cpu;
	pw.chosen_cpu = ideal_cpu;
	pw.enqueue_cpu = ideal_cpu;
	pw.choose_ts = bpf_ktime_get_ns();
	/* enqueue_ts: sched_migrate_task (pre-wakeup) or sched_wakeup */
	pw.enqueue_ts = 0;

	bpf_map_update_elem(&pending_wake, &pid, &pw, BPF_ANY);
	return 0;
}

/*
 * 仅处理入队前的 migrate：更新 enqueue_cpu，并以最后一次 migrate 锚定 enqueue_ts。
 * 已 sched_wakeup 之后的 migrate 忽略（属落地层偏离，不改变延迟起点）。
 */
SEC("tracepoint/sched/sched_migrate_task")
int handle_sched_migrate_task(struct trace_event_raw_sched_migrate_task *ctx)
{
	pid_t pid = ctx->pid;
	struct pending_wake *pw;

	if (goskip(pid))
		return 0;

	pending_try_expire(pid);

	pw = bpf_map_lookup_elem(&pending_wake, &pid);
	if (!pw)
		return 0;

	if (!(pw->flags & NUMAWAKE_PF_SEEN_CHOOSE))
		return 0;

	if (pw->flags & NUMAWAKE_PF_SEEN_WAKEUP)
		return 0;

	return pending_update_enqueue(pid, ctx->dest_cpu, NUMAWAKE_PF_SEEN_MIGRATE,
				      true);
}

static __always_inline int record_sched_wakeup(
	struct trace_event_raw_sched_wakeup_template *ctx)
{
	pid_t pid = ctx->pid;
	struct pending_wake *pw, val;

	if (goskip(pid))
		return 0;

	pending_try_expire(pid);

	pw = bpf_map_lookup_elem(&pending_wake, &pid);
	if (!pw)
		return 0;

	val = *pw;
	val.enqueue_cpu = ctx->target_cpu;
	val.flags |= NUMAWAKE_PF_SEEN_WAKEUP;
	if (!(val.flags & NUMAWAKE_PF_SEEN_MIGRATE))
		val.enqueue_ts = bpf_ktime_get_ns();

	return bpf_map_update_elem(&pending_wake, &pid, &val, BPF_ANY);
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

/*
 * 首次运行闭环：next_pid 命中 pending_wake 时分类、更新直方图、输出 perf 事件。
 */
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	pid_t prev_pid = ctx->prev_pid;
	pid_t next_pid = ctx->next_pid;
	struct pending_wake *pw;
	struct numawake_event ev = {};
	struct numawake_stats *st;
	u8 prev_node, chosen_node;
	int first_run_cpu;

	pending_try_expire(prev_pid);

	if (!next_pid)
		return 0;

	pw = bpf_map_lookup_elem(&pending_wake, &next_pid);
	if (!pw)
		return 0;

	if (!(pw->flags & NUMAWAKE_PF_SEEN_CHOOSE))
		goto cleanup;

	if (goskip(next_pid))
		goto cleanup;

	first_run_cpu = bpf_get_smp_processor_id();

	prev_node = numawake_cpu_node(pw->prev_cpu);
	chosen_node = numawake_cpu_node(pw->chosen_cpu);

	ev.pid = next_pid;
	ev.prev_cpu = pw->prev_cpu;
	ev.chosen_cpu = pw->chosen_cpu;
	ev.enqueue_cpu = pw->enqueue_cpu;
	ev.first_run_cpu = first_run_cpu;
	ev.prev_node = prev_node;
	ev.chosen_node = chosen_node;
	ev.enqueue_node = numawake_cpu_node(pw->enqueue_cpu);
	ev.first_run_node = numawake_cpu_node(first_run_cpu);
	__builtin_memcpy(ev.comm, ctx->next_comm, sizeof(ev.comm));
	ev.comm[NUMAWAKE_COMM_LEN - 1] = '\0';

	if (prev_node != NUMAWAKE_NODE_UNKNOWN &&
	    chosen_node != NUMAWAKE_NODE_UNKNOWN &&
	    prev_node != chosen_node)
		ev.flags |= NUMAWAKE_F_CROSS_NUMA_WAKE;

	if (pw->enqueue_cpu != first_run_cpu)
		ev.flags |= NUMAWAKE_F_LANDING_DEVIATION;

	if (pw->chosen_cpu != pw->enqueue_cpu)
		ev.flags |= NUMAWAKE_F_SANITY_MISMATCH;

	if (pw->enqueue_ts)
		ev.latency_ns = bpf_ktime_get_ns() - pw->enqueue_ts;

	st = stats_get();
	stats_record_event(st, &ev);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

cleanup:
	pending_delete(next_pid);
	return 0;
}

/* SIGKILL / 正常退出：防止 select 之后永远无 wakeup 导致泄漏 */
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	pending_delete(ctx->pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NUMAWAKE_H
#define __NUMAWAKE_H

/*
 * Product semantics for NUMA wake observability.
 * See SEMANTICS.md for full definitions.
 *
 * Primary:   CROSS_NUMA_WAKE   — node(prev_cpu) != node(chosen_cpu)
 * Secondary: LANDING_DEVIATION — enqueue_cpu != first_run_cpu
 * Excluded:  chosen_cpu vs sched_wakeup.target_cpu (sanity check only)
 */

#define NUMAWAKE_COMM_LEN	16
#define NUMAWAKE_MAX_CPUS	1024
#define NUMAWAKE_MAX_NODES	64
#define NUMAWAKE_HIST_SLOTS	26

/* cpu_to_node[]: unmapped or out-of-range CPU */
#define NUMAWAKE_NODE_UNKNOWN	255

/* pending_wake 超时：choose 后过久仍未 wakeup/switch 则回收（纳秒） */
#define NUMAWAKE_PENDING_STALE_NS	1000000000ULL /* 1s */

/* Per-event classification flags (may be combined on one wake) */
enum numawake_event_flag {
	NUMAWAKE_F_CROSS_NUMA_WAKE	= 1 << 0, /* decision-layer cross NUMA */
	NUMAWAKE_F_LANDING_DEVIATION	= 1 << 1, /* enqueue != first run CPU */
	NUMAWAKE_F_SANITY_MISMATCH	= 1 << 2, /* chosen != enqueue (debug) */
};

/* Default MVP baseline: expect task to stay on node(prev_cpu) */
enum numawake_baseline {
	NUMAWAKE_BASELINE_PREV_NUMA = 0,
	/* Future: NUMAWAKE_BASELINE_CPUSET, NUMAWAKE_BASELINE_MEM_NODE, ... */
};

/*
 * pending_wake.flags — BPF-internal wake sequence state (not numawake_event_flag).
 * NUMAWAKE_PF_SEEN_CHOOSE:  kretprobe select_task_rq_fair recorded decision
 * NUMAWAKE_PF_SEEN_MIGRATE: sched_migrate_task set enqueue_cpu + enqueue_ts
 * NUMAWAKE_PF_SEEN_WAKEUP:  sched_wakeup confirmed enqueue_cpu
 *
 * enqueue_ts anchor: last pre-wakeup sched_migrate_task, else sched_wakeup.
 * Post-wakeup migrate is ignored (see README.md §重点逻辑).
 */
#define NUMAWAKE_PF_SEEN_CHOOSE	(1U << 0)
#define NUMAWAKE_PF_SEEN_MIGRATE	(1U << 1)
#define NUMAWAKE_PF_SEEN_WAKEUP	(1U << 2)

/* BPF pending state for one in-flight wake (key: pid) */
struct pending_wake {
	__u32 pid;
	__u32 flags;		/* NUMAWAKE_PF_* */
	__s32 prev_cpu;
	__s32 chosen_cpu;	/* select_task_rq_fair return / ideal_cpu */
	__s32 enqueue_cpu;	/* last enqueue decision (migrate dest or wakeup target) */
	__u64 choose_ts;	/* kretprobe timestamp */
	__u64 enqueue_ts;	/* last_enqueue_decision (migrate or wakeup) */
};

/* Perf event / ring buffer payload for one completed wake observation */
struct numawake_event {
	__u32 pid;
	__u32 flags;		/* numawake_event_flag bitmask */
	__s32 prev_cpu;
	__s32 chosen_cpu;
	__s32 enqueue_cpu;
	__s32 first_run_cpu;
	__u8  prev_node;
	__u8  chosen_node;
	__u8  enqueue_node;
	__u8  first_run_node;
	__u64 latency_ns;	/* enqueue_ts .. first sched_switch */
	char  comm[NUMAWAKE_COMM_LEN];
};

struct numawake_hist {
	__u32 slots[NUMAWAKE_HIST_SLOTS];
};

/* User-space aggregate counters (printed each interval) */
struct numawake_stats {
	__u64 cross_numa_wake;
	__u64 landing_deviation;
	__u64 same_numa_wake;
	__u64 sanity_mismatch;
	struct numawake_hist cross_numa_lat;
	struct numawake_hist same_numa_lat;
};

static inline int numawake_is_cross_numa_wake(__u32 flags)
{
	return (flags & NUMAWAKE_F_CROSS_NUMA_WAKE) != 0;
}

static inline int numawake_is_landing_deviation(__u32 flags)
{
	return (flags & NUMAWAKE_F_LANDING_DEVIATION) != 0;
}

#endif /* __NUMAWAKE_H */

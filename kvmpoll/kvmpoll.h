/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMPOLL_H
#define __KVMPOLL_H

#ifndef BPF_ANY
#define BPF_ANY		0
#define BPF_NOEXIST	1
#define BPF_EXIST	2
#endif

/* Max QEMU TGIDs in -a mode (BPF hash size). */
#define KVMPOLL_MAX_MONITORED	256

enum kvmpoll_ns_key {
	NS_SUCCESS = 0,
	NS_FAIL_BLOCK = 1,	/* Σ block ns | waited=1 (guest latency) */
	NS_FAIL_POLL_SPIN = 2,	/* C: Σ poll budget on fail (eBPF exact) */
	NS_FAIL_EVENT_WAIT = 3,	/* B1: sleep → sched_wakeup (paired) */
	NS_FAIL_RUNQUEUE = 4,	/* B2: sched_wakeup → sched_switch next */
	NS_FAIL_MECHANISM_TAX = 5, /* post_poll − event_wait (paired fail) */
	NS_FAIL_POLL_ACTUAL = 6,   /* kprobe block entry → sched sleep (paired) */
	NS_NS_MAX = 7,
};

#define NS_FAIL	NS_FAIL_BLOCK	/* legacy alias; do not add before NS_NS_MAX */

enum kvmpoll_counter_key {
	CNT_WAKEUP_TOTAL = 0,
	CNT_SUCCESS,		/* waited==0 && valid==1 */
	CNT_FAIL,		/* waited==1  (aligns with debugfs fail_count) */
	CNT_INVALID,		/* valid==0   */
	CNT_ATTRIB_PAIRED,	/* fail with sched B1+B2 paired */
	CNT_ATTRIB_UNPAIRED,	/* fail without full sched pairing */
	CNT_BLOCK_ENTRY,	/* kprobe kvm_vcpu_block (monitored tgid) */
	CNT_MAX,
};

/* fail_pending.flags in BPF */
#define KVMPOLL_FA_SLEEP	1
#define KVMPOLL_FA_WOKEN	2
#define KVMPOLL_FA_RUN		4

#define KVMPOLL_ATTRIB_EXPIRE_NS	10000000ULL	/* 10 ms */

/*
 * Wakeup latency histogram buckets (microseconds, upper bound exclusive).
 * Slot 0 merges [0, 30 µs); slots 2+ refine the old 64+ tail.
 * Last slot is 2048 µs and above (upper sentinel 0 → open-ended in userspace).
 */
#define KVMPOLL_HIST_SLOTS	8

#define KVMPOLL_HIST_US_0_30	30
#define KVMPOLL_HIST_US_30_64	64
#define KVMPOLL_HIST_US_64_128	128
#define KVMPOLL_HIST_US_128_256	256
#define KVMPOLL_HIST_US_256_512	512
#define KVMPOLL_HIST_US_512_1024	1024
#define KVMPOLL_HIST_US_1024_2048	2048
#define KVMPOLL_HIST_US_OPEN	4096	/* reporting midpoint cap for 2+ ms */

/* Default halt_poll_ns if module param unreadable (200 µs). BPF + userspace. */
#define KVMPOLL_DEFAULT_HALT_POLL_NS	200000ULL

/* Bump when BPF/userspace ABI or attribution logic changes (verify after deploy). */
#define KVMPOLL_VERSION			"20250625-attrib7"

/*
 * OWN (KVM halt poll net host CPU benefit), ns:
 *
 *   OWN_exact  = (A × B) − C
 *   OWN_approx = (A × B) − (D × E)   [only if halt_poll_ns_grow == 0]
 *
 *   A = halt_successful_poll (debugfs, window delta)
 *   B = save_time / context-switch cost (fixed constant, e.g. 3200 ns)
 *   C = Σ poll budget on fail wakeup (eBPF, kvm_halt_poll_ns + waited=1)
 *   D = fail wakeup count (debugfs halt_wakeup or attempted−success−invalid)
 *   E = halt_poll_ns module parameter
 *
 * See README.md.
 */

/* Default B: VM-Exit + VM-Entry on Intel 8566C (override with -B). */
#define KVMPOLL_DEFAULT_SAVE_TIME_NS	3200ULL

struct kvmpoll_hist {
	__u64 slots[KVMPOLL_HIST_SLOTS];
	__u64 total;
};

struct kvmpoll_fail_pending {
	__u64 t_sleep;
	__u64 t_wakeup;
	__u64 runqueue_ns;
	__u64 poll_actual;	/* T_sleep − T_block_entry (kprobe), 0 if missing */
	__u8 flags;
	__u8 __pad[7];
};

struct kvmpoll_snapshot {
	__u64 success_count;
	__u64 fail_count;
	__u64 invalid_count;
	__u64 attrib_paired;
	__u64 attrib_unpaired;
	__u64 success_ns;
	__u64 fail_ns;			/* guest block time, not CPU */
	__u64 fail_poll_spin_ns;	/* C: Σ poll budget on fail */
	__u64 fail_poll_actual_ns;	/* Σ kprobe poll_actual on paired fail */
	__u64 fail_event_wait_ns;
	__u64 fail_runqueue_ns;
	__u64 fail_mechanism_tax_ns;
	struct kvmpoll_hist hist_success;
	struct kvmpoll_hist hist_fail;
	struct kvmpoll_hist hist_poll_actual;
	struct kvmpoll_hist hist_event_wait;
	struct kvmpoll_hist hist_runqueue;
	struct kvmpoll_hist hist_mechanism_tax;
};

struct kvmpoll_debugfs_halt {
	__u64 successful;	/* A source */
	__u64 fail_wakeup;	/* D source (0 if stat missing) */
	__u64 attempted;
	__u64 invalid;
	bool have_successful;
	bool have_fail_wakeup;
};

#ifndef __BPF__
#ifndef __VMLINUX_H__

static inline __u32 kvmpoll_hist_us_upper(unsigned slot)
{
	static const __u32 upper[KVMPOLL_HIST_SLOTS] = {
		KVMPOLL_HIST_US_0_30,
		KVMPOLL_HIST_US_30_64,
		KVMPOLL_HIST_US_64_128,
		KVMPOLL_HIST_US_128_256,
		KVMPOLL_HIST_US_256_512,
		KVMPOLL_HIST_US_512_1024,
		KVMPOLL_HIST_US_1024_2048,
		0,
	};

	if (slot >= KVMPOLL_HIST_SLOTS)
		return 0;
	return upper[slot];
}

static inline __u64 kvmpoll_hist_bucket_mid_ns(unsigned slot)
{
	__u32 hi = kvmpoll_hist_us_upper(slot);
	__u32 lo = slot ? kvmpoll_hist_us_upper(slot - 1) : 0;

	if (!hi)
		hi = KVMPOLL_HIST_US_OPEN;
	return (__u64)(lo + hi) / 2 * 1000ULL;
}

static inline __u64 kvmpoll_hist_percentile_ns(const struct kvmpoll_hist *h,
						 unsigned pct)
{
	__u64 target, cum = 0, prev_cum = 0;
	unsigned i;
	__u32 lo_us, hi_us;
	__u64 lo_ns, hi_ns, bucket_n, rank;

	if (!h || !h->total || pct == 0 || pct > 100)
		return 0;

	target = (h->total * pct + 50) / 100;
	for (i = 0; i < KVMPOLL_HIST_SLOTS; i++) {
		prev_cum = cum;
		cum += h->slots[i];
		if (cum < target)
			continue;

		bucket_n = h->slots[i];
		if (!bucket_n)
			return kvmpoll_hist_bucket_mid_ns(i);

		lo_us = i ? kvmpoll_hist_us_upper(i - 1) : 0;
		hi_us = kvmpoll_hist_us_upper(i);
		if (!hi_us)
			hi_us = KVMPOLL_HIST_US_OPEN;
		lo_ns = (__u64)lo_us * 1000ULL;
		hi_ns = (__u64)hi_us * 1000ULL;

		/* Linear rank within bucket (finer than fixed midpoint). */
		rank = target - prev_cum;
		if (rank > bucket_n)
			rank = bucket_n;
		return lo_ns + (hi_ns - lo_ns) * rank / bucket_n;
	}
	return kvmpoll_hist_bucket_mid_ns(KVMPOLL_HIST_SLOTS - 1);
}

static inline __u64 kvmpoll_hist_p50_ns(const struct kvmpoll_hist *h)
{
	return kvmpoll_hist_percentile_ns(h, 50);
}

static inline __u64 kvmpoll_hist_p99_ns(const struct kvmpoll_hist *h)
{
	return kvmpoll_hist_percentile_ns(h, 99);
}

static inline __u64 kvmpoll_fail_count_debugfs(const struct kvmpoll_debugfs_halt *d)
{
	if (!d)
		return 0;

	if (d->have_fail_wakeup)
		return d->fail_wakeup;
	if (!d->have_successful)
		return 0;

	return d->attempted - d->successful - d->invalid;
}

/* OWN_exact = (A × B) − C.  A/C/D for same measurement window. */
static inline __s64 kvmpoll_own_exact(__u64 success_count, __u64 save_time_ns,
					__u64 fail_poll_spin_ns)
{
	return (__s64)success_count * (__s64)save_time_ns -
	       (__s64)fail_poll_spin_ns;
}

/* OWN_approx = (A × B) − (D × E).  Valid when per-vcpu cap is fixed (grow=0). */
static inline __s64 kvmpoll_own_approx(__u64 success_count, __u64 save_time_ns,
				       __u64 fail_count, __u64 halt_poll_ns)
{
	return (__s64)success_count * (__s64)save_time_ns -
	       (__s64)fail_count * (__s64)halt_poll_ns;
}

static inline __s64 kvmpoll_own_exact_delta(__u64 a0, __u64 c0,
					      __u64 a1, __u64 c1,
					      __u64 save_time_ns)
{
	return kvmpoll_own_exact(a1, save_time_ns, c1) -
	       kvmpoll_own_exact(a0, save_time_ns, c0);
}

static inline __u64 kvmpoll_hist_poll_spin_est_ns(unsigned slot, __u64 cap_ns)
{
	__u32 lo_us = slot ? kvmpoll_hist_us_upper(slot - 1) : 0;
	__u32 hi_us = kvmpoll_hist_us_upper(slot);
	__u64 lo_ns, hi_ns, a, b;

	if (!cap_ns)
		return kvmpoll_hist_bucket_mid_ns(slot);

	lo_ns = (__u64)lo_us * 1000ULL;

	/* Open tail or bucket entirely above cap → poll capped at halt_poll_ns. */
	if (!hi_us || lo_ns >= cap_ns)
		return cap_ns;

	hi_ns = (__u64)hi_us * 1000ULL;
	a = lo_ns;
	b = hi_ns < cap_ns ? hi_ns : cap_ns;
	return (a + b) / 2;
}

static inline __u64 kvmpoll_hist_poll_spin_sum_ns(const struct kvmpoll_hist *h,
						    __u64 cap_ns)
{
	__u64 sum = 0;
	unsigned i;

	if (!h)
		return 0;

	for (i = 0; i < KVMPOLL_HIST_SLOTS; i++)
		sum += h->slots[i] * kvmpoll_hist_poll_spin_est_ns(i, cap_ns);
	return sum;
}

/* Histogram fallback when eBPF C unavailable. Prefer s->fail_poll_spin_ns. */
static inline __u64 kvmpoll_fail_poll_spin_hist_ns(const struct kvmpoll_snapshot *s,
						     __u64 halt_poll_ns)
{
	if (!s)
		return 0;

	return kvmpoll_hist_poll_spin_sum_ns(&s->hist_fail, halt_poll_ns);
}

/*
 * Host CPU time spent in halt poll spin (success + capped fail poll).
 * Lower is better. Use Δ for A/B tuning.
 */
static inline __u64 kvmpoll_host_spin_ns(const struct kvmpoll_snapshot *s,
					   __u64 halt_poll_ns)
{
	if (!s)
		return 0;

	return s->success_ns + kvmpoll_fail_poll_spin_hist_ns(s, halt_poll_ns);
}

/*
 * Optional: subtract fixed schedule-CPU credit per success (not from P50 diff).
 * sched_save_ns typically 5–15 µs from bench, not derived from fail block P50.
 */
static inline __s64 kvmpoll_own_host(const struct kvmpoll_snapshot *s,
				       __u64 halt_poll_ns,
				       __u64 sched_save_ns)
{
	__u64 spin = kvmpoll_host_spin_ns(s, halt_poll_ns);

	if (!sched_save_ns)
		return (__s64)spin;

	return (__s64)spin -
	       (__s64)s->success_count * (__s64)sched_save_ns;
}

static inline __s64 kvmpoll_own_host_delta(const struct kvmpoll_snapshot *before,
					     const struct kvmpoll_snapshot *after,
					     __u64 halt_poll_ns,
					     __u64 sched_save_ns)
{
	if (!before || !after)
		return 0;

	return kvmpoll_own_host(after, halt_poll_ns, sched_save_ns) -
	       kvmpoll_own_host(before, halt_poll_ns, sched_save_ns);
}

/* Deprecated: P50(fail)−P50(success) mixes guest sleep with spin — do not use. */
static inline __u64 kvmpoll_save_time_ns(const struct kvmpoll_snapshot *s)
{
	__u64 p50_success, p50_fail;

	if (!s)
		return 0;

	p50_success = kvmpoll_hist_p50_ns(&s->hist_success);
	p50_fail = kvmpoll_hist_p50_ns(&s->hist_fail);
	if (p50_fail <= p50_success)
		return 0;
	return p50_fail - p50_success;
}

/* Deprecated: success×save_time − fail_ns over-counts fail sleep as CPU. */
static inline __s64 kvmpoll_own(const struct kvmpoll_snapshot *s)
{
	__u64 save_ns;

	if (!s)
		return 0;

	save_ns = kvmpoll_save_time_ns(s);
	return (__s64)s->success_count * (__s64)save_ns - (__s64)s->fail_ns;
}

static inline __s64 kvmpoll_own_delta(const struct kvmpoll_snapshot *before,
				      const struct kvmpoll_snapshot *after)
{
	if (!before || !after)
		return 0;

	return kvmpoll_own(after) - kvmpoll_own(before);
}

#endif /* __VMLINUX_H__ */
#endif /* __BPF__ */

#endif /* __KVMPOLL_H */

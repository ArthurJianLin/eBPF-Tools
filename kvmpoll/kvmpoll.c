// SPDX-License-Identifier: GPL-2.0
/*
 * kvmpoll — kvm_vcpu_wakeup latency histogram (4.19, non-CO-RE).
 *
 * Filters by QEMU thread-group ID (-p or -a). Splits success / fail / invalid
 * by waited and valid; reports host poll spin (OWN) and guest block latency.
 */

#define _GNU_SOURCE
#include <argp.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include "libbpf.h"
#include "bpf.h"
#include "kvmpoll.h"
#include "kvmpoll.skel.h"

#define BAR_WIDTH		24
#define ARGP_KEY_SCAN_INTERVAL	30001

static volatile sig_atomic_t exiting;

static struct prog_env {
	bool have_pid;
	pid_t qemu_tgid;
	bool all_qemu;
	int interval_sec;
	int scan_interval_sec;
	int duration_sec;
	bool quiet;
	__u64 halt_poll_ns;
	__u64 save_time_ns;
} env = {
	.have_pid = false,
	.all_qemu = false,
	.interval_sec = 10,
	.scan_interval_sec = 300,
	.duration_sec = 0,
	.quiet = false,
	.halt_poll_ns = 0,
	.save_time_ns = KVMPOLL_DEFAULT_SAVE_TIME_NS,
};

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "QEMU process (thread group) PID" },
	{ "all-qemu", 'a', 0, 0,
	  "Monitor all QEMU processes (rescan /proc on --scan-interval)" },
	{ "interval", 'i', "SEC", 0,
	  "Print interval in seconds (default 10)" },
	{ "scan-interval", ARGP_KEY_SCAN_INTERVAL, "SEC", 0,
	  "With -a: seconds between /proc QEMU rescan passes (default 300)" },
	{ "duration", 'd', "SEC", 0,
	  "Run for SEC seconds then exit (for A/B scripts; final snapshot only with -q)" },
	{ "quiet", 'q', NULL, 0,
	  "Machine-readable key=value output" },
	{ "halt-poll-ns", 'H', "NS", 0,
	  "halt_poll_ns cap E (default: read module param)" },
	{ "save-time", 'B', "NS", 0,
	  "Context switch save time B in ns (default 3200, Intel 8566C)" },
	{},
};

static const char doc[] =
	"KVM halt poll wakeup latency (kvm_vcpu_wakeup tracepoint).\n"
	"\n"
	"Examples:\n"
	"  kvmpoll -p $(pidof qemu-system-x86_64)\n"
	"  kvmpoll -p 12345 -i 30\n"
	"  kvmpoll -a --scan-interval 60\n";

static void sig_done(int signo)
{
	(void)signo;
	exiting = 1;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit\n");
		exit(1);
	}
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	(void)state;

	switch (key) {
	case 'p': {
		long v;

		errno = 0;
		v = strtol(arg, NULL, 10);
		if (errno || v <= 0 || v > INT_MAX) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			return EINVAL;
		}
		env.qemu_tgid = (pid_t)v;
		env.have_pid = true;
		break;
	}
	case 'a':
		env.all_qemu = true;
		break;
	case 'i': {
		long v;

		errno = 0;
		v = strtol(arg, NULL, 10);
		if (errno || v <= 0 || v > 86400) {
			fprintf(stderr, "invalid interval: %s\n", arg);
			return EINVAL;
		}
		env.interval_sec = (int)v;
		break;
	}
	case ARGP_KEY_SCAN_INTERVAL: {
		long v;

		errno = 0;
		v = strtol(arg, NULL, 10);
		if (errno || v <= 0 || v > 86400) {
			fprintf(stderr, "invalid scan interval: %s\n", arg);
			return EINVAL;
		}
		env.scan_interval_sec = (int)v;
		break;
	}
	case 'd': {
		long v;

		errno = 0;
		v = strtol(arg, NULL, 10);
		if (errno || v <= 0 || v > 86400) {
			fprintf(stderr, "invalid duration: %s\n", arg);
			return EINVAL;
		}
		env.duration_sec = (int)v;
		break;
	}
	case 'q':
		env.quiet = true;
		break;
	case 'H': {
		unsigned long long v;

		errno = 0;
		v = strtoull(arg, NULL, 10);
		if (errno || v == 0) {
			fprintf(stderr, "invalid halt-poll-ns: %s\n", arg);
			return EINVAL;
		}
		env.halt_poll_ns = v;
		break;
	}
	case 'B': {
		unsigned long long v;

		errno = 0;
		v = strtoull(arg, NULL, 10);
		if (errno || v == 0) {
			fprintf(stderr, "invalid save-time: %s\n", arg);
			return EINVAL;
		}
		env.save_time_ns = v;
		break;
	}
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int attach_probes(struct kvmpoll_bpf *obj)
{
	struct bpf_link *link;
	long err;
	bool sched_ok = true;

	link = bpf_program__attach_tracepoint(obj->progs.handle_kvm_vcpu_wakeup,
					      "kvm", "kvm_vcpu_wakeup");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "kvm_vcpu_wakeup attach failed: %ld (%s)\n",
			err, strerror(-err));
		return -1;
	}
	obj->links.handle_kvm_vcpu_wakeup = link;

	link = bpf_program__attach_tracepoint(obj->progs.handle_kvm_halt_poll_ns,
					      "kvm", "kvm_halt_poll_ns");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "warning: kvm_halt_poll_ns attach failed: %ld (%s)\n",
			err, strerror(-err));
		fprintf(stderr, "         C uses module halt_poll_ns as budget fallback\n");
	} else {
		obj->links.handle_kvm_halt_poll_ns = link;
	}

	link = bpf_program__attach_tracepoint(obj->progs.handle_sched_wakeup,
					      "sched", "sched_wakeup");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "warning: sched_wakeup attach failed: %ld (%s)\n",
			err, strerror(-err));
		sched_ok = false;
	} else {
		obj->links.handle_sched_wakeup = link;
	}

	link = bpf_program__attach_tracepoint(obj->progs.handle_sched_wakeup_new,
					      "sched", "sched_wakeup_new");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "warning: sched_wakeup_new attach failed: %ld (%s)\n",
			err, strerror(-err));
		sched_ok = false;
	} else {
		obj->links.handle_sched_wakeup_new = link;
	}

	link = bpf_program__attach_tracepoint(obj->progs.handle_sched_switch,
					      "sched", "sched_switch");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "warning: sched_switch attach failed: %ld (%s)\n",
			err, strerror(-err));
		sched_ok = false;
	} else {
		obj->links.handle_sched_switch = link;
	}

	if (!sched_ok)
		fprintf(stderr,
			"warning: fail block B1/B2 attribution disabled (sched attach)\n");

	link = bpf_program__attach_kprobe(obj->progs.kprobe_kvm_vcpu_block,
					  false, "kvm_vcpu_block");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr,
			"warning: kprobe kvm_vcpu_block attach failed: %ld (%s)\n",
			err, strerror(-err));
		fprintf(stderr,
			"         poll_actual disabled (mechanism_tax uses poll budget)\n");
	} else {
		obj->links.kprobe_kvm_vcpu_block = link;
	}

	return 0;
}

static int setup_default_poll_ns(struct kvmpoll_bpf *obj, __u64 cap_ns)
{
	__u32 key = 0;
	int fd = bpf_map__fd(obj->maps.default_poll_ns);

	if (!cap_ns)
		cap_ns = KVMPOLL_DEFAULT_HALT_POLL_NS;
	return bpf_map_update_elem(fd, &key, &cap_ns, BPF_ANY);
}

static __u64 read_default_poll_ns_map(struct kvmpoll_bpf *obj)
{
	__u32 key = 0;
	__u64 val = 0;
	int fd = bpf_map__fd(obj->maps.default_poll_ns);

	if (fd < 0 || bpf_map_lookup_elem(fd, &key, &val))
		return 0;
	return val;
}

static int read_ns_sum_map_max(struct kvmpoll_bpf *obj)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	int fd = bpf_map__fd(obj->maps.ns_sum);

	if (fd < 0 || bpf_obj_get_info_by_fd(fd, &info, &len))
		return -1;
	return (int)info.max_entries;
}

static int monitored_add(struct kvmpoll_bpf *obj, __u32 tgid)
{
	__u8 one = 1;
	int fd = bpf_map__fd(obj->maps.monitored_tgids);

	return bpf_map_update_elem(fd, &tgid, &one, BPF_ANY);
}

static int monitored_del(struct kvmpoll_bpf *obj, __u32 tgid)
{
	int fd = bpf_map__fd(obj->maps.monitored_tgids);

	return bpf_map_delete_elem(fd, &tgid);
}

static int seed_vcpu_pids(struct kvmpoll_bpf *obj, pid_t tgid)
{
	char path[64];
	DIR *d;
	struct dirent *de;
	int fd = bpf_map__fd(obj->maps.vcpu_pids);
	__u8 one = 1;

	if (fd < 0)
		return -1;

	snprintf(path, sizeof(path), "/proc/%d/task", (int)tgid);
	d = opendir(path);
	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		char *endp;
		long v;
		__u32 tid;

		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		errno = 0;
		v = strtol(de->d_name, &endp, 10);
		if (errno || *endp != '\0' || v <= 0 || v > INT_MAX)
			continue;
		tid = (__u32)v;
		bpf_map_update_elem(fd, &tid, &one, BPF_ANY);
	}
	closedir(d);
	return 0;
}

static __u64 read_counter(struct kvmpoll_bpf *obj, __u32 key)
{
	int fd = bpf_map__fd(obj->maps.counters);
	__u64 val = 0;

	if (bpf_map_lookup_elem(fd, &key, &val))
		return 0;
	return val;
}

static __u64 read_ns_sum(struct kvmpoll_bpf *obj, __u32 key)
{
	int fd = bpf_map__fd(obj->maps.ns_sum);
	__u64 val = 0;

	if (bpf_map_lookup_elem(fd, &key, &val))
		return 0;
	return val;
}

static int read_hist(struct kvmpoll_bpf *obj, struct bpf_map *map,
		     struct kvmpoll_hist *out)
{
	__u32 key = 0;
	int fd = bpf_map__fd(map);

	if (!out)
		return -1;
	memset(out, 0, sizeof(*out));
	if (bpf_map_lookup_elem(fd, &key, out))
		return -1;
	return 0;
}

static void fill_snapshot(struct kvmpoll_bpf *obj, struct kvmpoll_snapshot *s)
{
	memset(s, 0, sizeof(*s));
	s->success_count = read_counter(obj, CNT_SUCCESS);
	s->fail_count = read_counter(obj, CNT_FAIL);
	s->invalid_count = read_counter(obj, CNT_INVALID);
	s->attrib_paired = read_counter(obj, CNT_ATTRIB_PAIRED);
	s->attrib_unpaired = read_counter(obj, CNT_ATTRIB_UNPAIRED);
	s->success_ns = read_ns_sum(obj, NS_SUCCESS);
	s->fail_ns = read_ns_sum(obj, NS_FAIL_BLOCK);
	s->fail_poll_spin_ns = read_ns_sum(obj, NS_FAIL_POLL_SPIN);
	s->fail_poll_actual_ns = read_ns_sum(obj, NS_FAIL_POLL_ACTUAL);
	s->fail_event_wait_ns = read_ns_sum(obj, NS_FAIL_EVENT_WAIT);
	s->fail_runqueue_ns = read_ns_sum(obj, NS_FAIL_RUNQUEUE);
	s->fail_mechanism_tax_ns = read_ns_sum(obj, NS_FAIL_MECHANISM_TAX);
	read_hist(obj, obj->maps.hist_success, &s->hist_success);
	read_hist(obj, obj->maps.hist_fail, &s->hist_fail);
	read_hist(obj, obj->maps.hist_poll_actual, &s->hist_poll_actual);
	read_hist(obj, obj->maps.hist_event_wait, &s->hist_event_wait);
	read_hist(obj, obj->maps.hist_runqueue, &s->hist_runqueue);
	read_hist(obj, obj->maps.hist_mechanism_tax, &s->hist_mechanism_tax);
}

static const char *hist_label(unsigned slot)
{
	static const char *labels[KVMPOLL_HIST_SLOTS] = {
		"0-30 us",
		"30-64 us",
		"64-128 us",
		"128-256 us",
		"256-512 us",
		"512-1024 us",
		"1-2 ms",
		"2+ ms",
	};

	if (slot >= KVMPOLL_HIST_SLOTS)
		return "?";
	return labels[slot];
}

static void print_bar(char *out, size_t olen, __u64 val, __u64 vmax)
{
	unsigned n, i;

	if (!vmax || !val) {
		if (olen)
			out[0] = '\0';
		return;
	}
	n = (unsigned)((double)val / (double)vmax * (double)BAR_WIDTH);
	if (n > BAR_WIDTH)
		n = BAR_WIDTH;
	for (i = 0; i < n && i + 1 < olen; i++)
		out[i] = '#';
	out[i] = '\0';
}

static void print_hist(FILE *out, const char *title, const struct kvmpoll_hist *h)
{
	__u64 mx = 0;
	char bar[BAR_WIDTH + 4];
	unsigned i;

	fprintf(out, "--- %s (n=%llu) ---\n", title,
		(unsigned long long)h->total);
	if (!h->total) {
		fprintf(out, "  (empty)\n");
		return;
	}

	for (i = 0; i < KVMPOLL_HIST_SLOTS; i++) {
		if (h->slots[i] > mx)
			mx = h->slots[i];
	}

	for (i = 0; i < KVMPOLL_HIST_SLOTS; i++) {
		print_bar(bar, sizeof(bar), h->slots[i], mx);
		fprintf(out, "  %-12s : %s %llu\n", hist_label(i), bar,
			(unsigned long long)h->slots[i]);
	}
}

static unsigned success_under_30_pct(const struct kvmpoll_hist *h)
{
	if (!h || !h->total)
		return 0;

	/* slot 0 is [0, 30 µs) */
	return (unsigned)((h->slots[0] * 100ULL + h->total / 2) / h->total);
}

static __u64 read_halt_poll_ns_param(void)
{
	const char *path = "/sys/module/kvm/parameters/halt_poll_ns";
	FILE *f;
	unsigned long long v;

	if (env.halt_poll_ns)
		return env.halt_poll_ns;

	f = fopen(path, "r");
	if (!f)
		return KVMPOLL_DEFAULT_HALT_POLL_NS;
	if (fscanf(f, "%llu", &v) != 1 || v == 0)
		v = KVMPOLL_DEFAULT_HALT_POLL_NS;
	fclose(f);
	return v;
}

static __u64 sum_debugfs_stat(const char *name)
{
	char cmd[256];
	__u64 sum = 0;
	FILE *p;

	snprintf(cmd, sizeof(cmd),
		 "find /sys/kernel/debug/kvm -name %s 2>/dev/null", name);
	p = popen(cmd, "r");
	if (!p)
		return 0;

	{
		char path[512];
		while (fgets(path, sizeof(path), p)) {
			FILE *f;
			unsigned long long v;

			path[strcspn(path, "\n")] = '\0';
			if (!path[0])
				continue;
			f = fopen(path, "r");
			if (!f)
				continue;
			if (fscanf(f, "%llu", &v) == 1)
				sum += v;
			fclose(f);
		}
	}
	pclose(p);
	return sum;
}

static void read_kvm_debugfs_halt(struct kvmpoll_debugfs_halt *d)
{
	memset(d, 0, sizeof(*d));

	d->successful = sum_debugfs_stat("halt_successful_poll");
	d->attempted = sum_debugfs_stat("halt_attempted_poll");
	d->invalid = sum_debugfs_stat("halt_poll_invalid");
	d->fail_wakeup = sum_debugfs_stat("halt_wakeup");

	d->have_successful = d->attempted > 0 || d->successful > 0;
	d->have_fail_wakeup = d->fail_wakeup > 0;
}

static int read_halt_poll_ns_grow(void)
{
	const char *path = "/sys/module/kvm/parameters/halt_poll_ns_grow";
	FILE *f;
	int v = -1;

	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d", &v) != 1)
		v = -1;
	fclose(f);
	return v;
}

struct own_window {
	__u64 success_count;
	__u64 fail_count;
	__u64 fail_poll_spin_ns;
	bool have_prev;
};

static void own_window_reset(struct own_window *w)
{
	memset(w, 0, sizeof(*w));
}

static void own_window_snap(struct own_window *w, const struct kvmpoll_snapshot *s)
{
	w->success_count = s->success_count;
	w->fail_count = s->fail_count;
	w->fail_poll_spin_ns = s->fail_poll_spin_ns;
	w->have_prev = true;
}

static void print_own_lines(FILE *out, const struct own_window *prev,
			    const struct kvmpoll_snapshot *s,
			    __u64 save_ns)
{
	__u64 a_win, d_win, c_win;
	__s64 own_exact;

	if (prev->have_prev) {
		a_win = s->success_count - prev->success_count;
		d_win = s->fail_count - prev->fail_count;
		c_win = s->fail_poll_spin_ns - prev->fail_poll_spin_ns;
	} else {
		a_win = s->success_count;
		d_win = s->fail_count;
		c_win = s->fail_poll_spin_ns;
	}

	own_exact = kvmpoll_own_exact(a_win, save_ns, c_win);

	fprintf(out, "OWN_exact (eBPF, last interval): B=%llu ns\n",
		(unsigned long long)save_ns);
	fprintf(out, "  Δsuccess=%llu  Δfail=%llu  ΔC=%.3f ms\n",
		(unsigned long long)a_win, (unsigned long long)d_win,
		c_win / 1e6);
	fprintf(out, "  A×B−C = %+.3f ms", own_exact / 1e6);
	if (own_exact > 0)
		fprintf(out, "  (net host CPU save)\n");
	else if (own_exact < 0)
		fprintf(out, "  (poll waste > saves)\n");
	else
		fprintf(out, "\n");
}

static void print_attrib_sanity(FILE *out, const struct kvmpoll_snapshot *s,
				__u64 cap_ns)
{
	__u64 attrib_total = s->attrib_paired + s->attrib_unpaired;
	__u64 unpaired_pct;

	if (s->fail_poll_spin_ns == 0 && s->fail_count > 0 && cap_ns > 0) {
		fprintf(out, "  [WARN] fail poll spin C=0 but halt_poll_ns=%llu — "
			"need %s (ns_sum>=%d)\n",
			(unsigned long long)cap_ns, KVMPOLL_VERSION, (int)NS_NS_MAX);
	}
	if (s->fail_count > 0 && s->hist_poll_actual.total == 0) {
		fprintf(out, "  [WARN] poll_actual histogram empty — "
			"kprobe kvm_vcpu_block not attached or no paired sleep\n");
	}
	if (attrib_total > 0 && s->attrib_unpaired > 0) {
		unpaired_pct = s->attrib_unpaired * 100 / attrib_total;
		if (unpaired_pct > 1)
			fprintf(out, "  [WARN] fail attrib unpaired=%llu (%llu%%)\n",
				(unsigned long long)s->attrib_unpaired,
				(unsigned long long)unpaired_pct);
	}
}

static void print_snapshot(FILE *out, const struct kvmpoll_snapshot *s,
			   const struct own_window *own_prev,
			   __u64 cap_ns, __u64 save_ns)
{
	__u64 p50_success = kvmpoll_hist_p50_ns(&s->hist_success);
	__u64 p50_fail = kvmpoll_hist_p50_ns(&s->hist_fail);
	__u64 p50_event = kvmpoll_hist_p50_ns(&s->hist_event_wait);
	__u64 p50_rq = kvmpoll_hist_p50_ns(&s->hist_runqueue);
	__u64 p50_poll = kvmpoll_hist_p50_ns(&s->hist_poll_actual);
	__u64 p50_mech = kvmpoll_hist_p50_ns(&s->hist_mechanism_tax);
	__u64 p99_success = kvmpoll_hist_p99_ns(&s->hist_success);
	__u64 p99_fail = kvmpoll_hist_p99_ns(&s->hist_fail);
	__u64 p99_mech = kvmpoll_hist_p99_ns(&s->hist_mechanism_tax);
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[32];

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

	fprintf(out, "\n[%s]\n", ts);
	fprintf(out, "P50/P99 (us): success %.2f/%.2f  fail_block %.2f/%.2f\n",
		p50_success / 1000.0, p99_success / 1000.0,
		p50_fail / 1000.0, p99_fail / 1000.0);
	fprintf(out, "P50/P99 (us): mechanism_tax %.2f/%.2f\n",
		p50_mech / 1000.0, p99_mech / 1000.0);
	fprintf(out, "P50 (us): event_wait %.2f  runqueue %.2f  poll_actual %.2f\n",
		p50_event / 1000.0, p50_rq / 1000.0, p50_poll / 1000.0);
	fprintf(out, "success in [0,30) us: %u%%\n",
		success_under_30_pct(&s->hist_success));
	print_attrib_sanity(out, s, cap_ns);

	print_own_lines(out, own_prev, s, save_ns);

	print_hist(out, "success spin (waited=0, valid=1)", &s->hist_success);
	print_hist(out, "fail block time (waited=1, incl sleep)", &s->hist_fail);
	print_hist(out, "fail poll_actual (block entry->sleep, kprobe, paired)",
		   &s->hist_poll_actual);
	print_hist(out, "fail event_wait B1 (sleep->wakeup, paired)", &s->hist_event_wait);
	print_hist(out, "fail runqueue B2 (wakeup->run, paired)", &s->hist_runqueue);
	print_hist(out, "fail mechanism_tax (post_poll-event_wait, paired)",
		   &s->hist_mechanism_tax);
}

static void print_snapshot_quiet(FILE *out, const struct kvmpoll_snapshot *s,
				 __u64 cap_ns, __u64 save_ns)
{
	__u64 a = s->success_count;
	__u64 d = s->fail_count;
	__u64 c = s->fail_poll_spin_ns;
	__u64 p50_success = kvmpoll_hist_p50_ns(&s->hist_success);
	__u64 p50_fail = kvmpoll_hist_p50_ns(&s->hist_fail);
	__u64 p50_event = kvmpoll_hist_p50_ns(&s->hist_event_wait);
	__u64 p50_rq = kvmpoll_hist_p50_ns(&s->hist_runqueue);
	__u64 p50_poll = kvmpoll_hist_p50_ns(&s->hist_poll_actual);
	__u64 p50_mech = kvmpoll_hist_p50_ns(&s->hist_mechanism_tax);
	__u64 p99_success = kvmpoll_hist_p99_ns(&s->hist_success);
	__u64 p99_fail = kvmpoll_hist_p99_ns(&s->hist_fail);
	__u64 p99_mech = kvmpoll_hist_p99_ns(&s->hist_mechanism_tax);
	unsigned i;

	fprintf(out, "kvmpoll_save_time_ns=%llu\n", (unsigned long long)save_ns);
	fprintf(out, "kvmpoll_halt_poll_ns=%llu\n", (unsigned long long)cap_ns);
	fprintf(out, "kvmpoll_success=%llu\n", (unsigned long long)a);
	fprintf(out, "kvmpoll_fail=%llu\n", (unsigned long long)d);
	fprintf(out, "kvmpoll_fail_poll_spin_ns=%llu\n", (unsigned long long)c);
	fprintf(out, "kvmpoll_fail_poll_actual_ns=%llu\n",
		(unsigned long long)s->fail_poll_actual_ns);
	fprintf(out, "kvmpoll_fail_event_wait_ns=%llu\n",
		(unsigned long long)s->fail_event_wait_ns);
	fprintf(out, "kvmpoll_fail_runqueue_ns=%llu\n",
		(unsigned long long)s->fail_runqueue_ns);
	fprintf(out, "kvmpoll_fail_mechanism_tax_ns=%llu\n",
		(unsigned long long)s->fail_mechanism_tax_ns);
	fprintf(out, "kvmpoll_attrib_paired=%llu\n",
		(unsigned long long)s->attrib_paired);
	fprintf(out, "kvmpoll_attrib_unpaired=%llu\n",
		(unsigned long long)s->attrib_unpaired);
	fprintf(out, "kvmpoll_own_exact_ns=%lld\n",
		(long long)kvmpoll_own_exact(a, save_ns, c));
	fprintf(out, "kvmpoll_own_approx_ns=%lld\n",
		(long long)kvmpoll_own_approx(a, save_ns, d, cap_ns));
	fprintf(out, "kvmpoll_invalid=%llu\n",
		(unsigned long long)s->invalid_count);
	fprintf(out, "kvmpoll_success_ns=%llu\n",
		(unsigned long long)s->success_ns);
	fprintf(out, "kvmpoll_fail_block_ns=%llu\n",
		(unsigned long long)s->fail_ns);
	fprintf(out, "kvmpoll_p50_success_us=%.3f\n", p50_success / 1000.0);
	fprintf(out, "kvmpoll_p99_success_us=%.3f\n", p99_success / 1000.0);
	fprintf(out, "kvmpoll_p50_fail_block_us=%.3f\n", p50_fail / 1000.0);
	fprintf(out, "kvmpoll_p99_fail_block_us=%.3f\n", p99_fail / 1000.0);
	fprintf(out, "kvmpoll_p50_event_wait_us=%.3f\n", p50_event / 1000.0);
	fprintf(out, "kvmpoll_p50_runqueue_us=%.3f\n", p50_rq / 1000.0);
	fprintf(out, "kvmpoll_p50_poll_actual_us=%.3f\n", p50_poll / 1000.0);
	fprintf(out, "kvmpoll_p50_mechanism_tax_us=%.3f\n", p50_mech / 1000.0);
	fprintf(out, "kvmpoll_p99_mechanism_tax_us=%.3f\n", p99_mech / 1000.0);
	fprintf(out, "kvmpoll_success_under_30_pct=%u\n",
		success_under_30_pct(&s->hist_success));
	for (i = 0; i < KVMPOLL_HIST_SLOTS; i++)
		fprintf(out, "kvmpoll_hist_success_%u=%llu\n", i,
			(unsigned long long)s->hist_success.slots[i]);
	for (i = 0; i < KVMPOLL_HIST_SLOTS; i++)
		fprintf(out, "kvmpoll_hist_fail_%u=%llu\n", i,
			(unsigned long long)s->hist_fail.slots[i]);
}

static int read_debugfs_u64(const char *path, __u64 *out)
{
	FILE *f;
	unsigned long long v;

	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%llu", &v) != 1) {
		fclose(f);
		return -1;
	}
	fclose(f);
	*out = v;
	return 0;
}

static int find_debugfs_halt_stat(const char *name, char *path_out, size_t path_len)
{
	const char *roots[] = {
		"/sys/kernel/debug/kvm",
		"/sys/kernel/debug/tracing",
		NULL,
	};
	char cmd[512];

	for (int i = 0; roots[i]; i++) {
		snprintf(cmd, sizeof(cmd),
			 "find %s -maxdepth 6 -name %s 2>/dev/null | head -1",
			 roots[i], name);
		FILE *p = popen(cmd, "r");
		if (!p)
			continue;
		if (fgets(path_out, path_len, p)) {
			path_out[strcspn(path_out, "\n")] = '\0';
			pclose(p);
			if (path_out[0])
				return 0;
		} else {
			pclose(p);
		}
	}
	return -1;
}

struct debugfs_halt {
	__u64 attempted;
	__u64 successful;
	__u64 invalid;
	bool have_attempted;
};

static int read_debugfs_halt(struct debugfs_halt *d)
{
	char path[512];
	__u64 val;

	memset(d, 0, sizeof(*d));

	if (!find_debugfs_halt_stat("halt_attempted_poll", path, sizeof(path)))
		if (!read_debugfs_u64(path, &val)) {
			d->attempted = val;
			d->have_attempted = true;
		}

	if (!find_debugfs_halt_stat("halt_successful_poll", path, sizeof(path)))
		if (!read_debugfs_u64(path, &val))
			d->successful = val;

	if (!find_debugfs_halt_stat("halt_poll_invalid", path, sizeof(path)))
		if (!read_debugfs_u64(path, &val))
			d->invalid = val;

	return d->have_attempted ? 0 : -1;
}

static void print_debugfs_note(const struct debugfs_halt *before,
			       const struct debugfs_halt *after)
{
	__u64 fail_before, fail_after;

	if (!before->have_attempted || !after->have_attempted)
		return;

	fail_before = before->attempted - before->successful - before->invalid;
	fail_after = after->attempted - after->successful - after->invalid;

	printf("debugfs delta: fail_count %llu -> %llu (Δ %lld)\n",
	       (unsigned long long)fail_before,
	       (unsigned long long)fail_after,
	       (long long)(fail_after - fail_before));
}

static int comm_has_qemu(const char *comm)
{
	char buf[32];
	size_t i, j;

	for (i = 0, j = 0; comm[i] && j + 1 < sizeof(buf); i++) {
		if (comm[i] == '\n')
			break;
		buf[j++] = (char)tolower((unsigned char)comm[i]);
	}
	buf[j] = '\0';
	return strstr(buf, "qemu") != NULL;
}

static int read_proc_comm(pid_t pid, char *comm, size_t comm_len)
{
	char path[64];
	FILE *f;

	if (!comm || comm_len == 0)
		return -1;

	snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(comm, comm_len, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static void warn_qemu_tgid(pid_t tgid)
{
	char comm[32];

	if (read_proc_comm(tgid, comm, sizeof(comm)) != 0) {
		fprintf(stderr,
			"warning: -p %d: no such process (or /proc unreadable)\n",
			(int)tgid);
		fprintf(stderr,
			"         use: kvmpoll -p $(pidof qemu-system-x86_64)\n");
		return;
	}
	if (!comm_has_qemu(comm)) {
		fprintf(stderr,
			"warning: -p %d comm=%s (not qemu*) — eBPF will likely stay 0\n",
			(int)tgid, comm);
		fprintf(stderr,
			"         use: kvmpoll -p $(pidof qemu-system-x86_64)\n");
	}
}

static void warn_no_ebpf_events(const struct kvmpoll_snapshot *s)
{
	if (!s)
		return;
	if (s->success_count + s->fail_count + s->invalid_count > 0)
		return;

	fprintf(stderr,
		"warning: no kvm_vcpu_wakeup events yet for this -p tgid\n");
	fprintf(stderr,
		"         check: ps -p <PID> -o comm=  (expect qemu-system-x86_64)\n");
	fprintf(stderr,
		"         or:    kvmpoll -a   (monitor all QEMU on host)\n");
}

static int pid_in_list(const pid_t *arr, size_t n, pid_t p)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (arr[i] == p)
			return 1;
	}
	return 0;
}

static int read_proc_tgid(pid_t pid, pid_t *tgid_out)
{
	char path[64];
	FILE *f;
	char line[256];

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Tgid:", 5) == 0) {
			if (sscanf(line + 5, " %d", tgid_out) != 1) {
				fclose(f);
				return -1;
			}
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static int collect_qemu_tgids(pid_t *out, size_t out_max, size_t *n_out)
{
	DIR *d;
	struct dirent *de;
	size_t n = 0;

	*n_out = 0;
	d = opendir("/proc");
	if (!d) {
		perror("opendir /proc");
		return -1;
	}
	while ((de = readdir(d)) != NULL) {
		pid_t pid, tgid;
		char path[64];
		FILE *f;
		char comm[32];
		char *endp;
		long v;

		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		errno = 0;
		v = strtol(de->d_name, &endp, 10);
		if (errno || *endp != '\0' || v <= 0 || v > INT_MAX)
			continue;
		pid = (pid_t)v;
		if (read_proc_tgid(pid, &tgid) != 0)
			continue;
		if (pid != tgid)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (!fgets(comm, sizeof(comm), f)) {
			fclose(f);
			continue;
		}
		fclose(f);
		if (!comm_has_qemu(comm))
			continue;
		if (pid_in_list(out, n, pid))
			continue;
		if (n >= out_max)
			break;
		out[n++] = pid;
	}
	closedir(d);
	*n_out = n;
	return 0;
}

static int sync_monitored_qemu(struct kvmpoll_bpf *obj, pid_t *cur, size_t *ncur)
{
	pid_t next[KVMPOLL_MAX_MONITORED];
	size_t nnext, i, j;

	if (collect_qemu_tgids(next, KVMPOLL_MAX_MONITORED, &nnext) != 0)
		return -1;

	for (i = 0; i < *ncur; i++) {
		if (!pid_in_list(next, nnext, cur[i]))
			monitored_del(obj, (__u32)cur[i]);
	}
	for (j = 0; j < nnext; j++) {
		if (!pid_in_list(cur, *ncur, next[j])) {
			if (monitored_add(obj, (__u32)next[j]) != 0)
				fprintf(stderr, "warning: monitored_add tgid %d failed\n",
					(int)next[j]);
			else {
				printf("monitor QEMU tgid %d\n", (int)next[j]);
				seed_vcpu_pids(obj, next[j]);
			}
		}
	}

	memcpy(cur, next, nnext * sizeof(pid_t));
	*ncur = nnext;
	return 0;
}

static int run_single_pid(struct kvmpoll_bpf *obj)
{
	struct kvmpoll_snapshot snap;
	struct own_window own_prev;
	time_t next_print, now, deadline = 0;
	__u64 cap_ns = read_halt_poll_ns_param();
	__u64 save_ns = env.save_time_ns;
	bool warned_no_events = false;

	own_window_reset(&own_prev);

	if (!env.quiet)
		warn_qemu_tgid(env.qemu_tgid);

	if (monitored_add(obj, (__u32)env.qemu_tgid) != 0) {
		perror("monitored_tgids");
		return -1;
	}
	if (seed_vcpu_pids(obj, env.qemu_tgid) != 0 && !env.quiet)
		fprintf(stderr, "warning: seed vcpu threads for tgid %d failed\n",
			(int)env.qemu_tgid);

	if (env.duration_sec > 0) {
		deadline = time(NULL) + env.duration_sec;
		if (!env.quiet)
			fprintf(stderr,
				"kvmpoll: QEMU tgid %d, duration %ds, interval %ds, B=%llu ns\n",
				(int)env.qemu_tgid, env.duration_sec, env.interval_sec,
				(unsigned long long)save_ns);
	} else if (!env.quiet) {
		printf("kvmpoll: QEMU tgid %d, interval %ds, B=%llu ns (Ctrl-C to exit)\n",
		       (int)env.qemu_tgid, env.interval_sec,
		       (unsigned long long)save_ns);
	}

	next_print = time(NULL) + env.interval_sec;

	while (!exiting) {
		sleep(1);
		now = time(NULL);
		if (env.duration_sec > 0 && now >= deadline)
			break;
		if (env.quiet)
			continue;
		if (now < next_print)
			continue;

		fill_snapshot(obj, &snap);
		if (!warned_no_events &&
		    snap.success_count + snap.fail_count + snap.invalid_count == 0) {
			warn_no_ebpf_events(&snap);
			warned_no_events = true;
		}
		print_snapshot(stdout, &snap, &own_prev, cap_ns, save_ns);
		fflush(stdout);
		own_window_snap(&own_prev, &snap);
		next_print = now + env.interval_sec;
	}

	fill_snapshot(obj, &snap);
	if (env.quiet) {
		print_snapshot_quiet(stdout, &snap, cap_ns, save_ns);
	} else if (env.duration_sec > 0) {
		printf("\n=== final (%ds) ===\n", env.duration_sec);
		print_snapshot(stdout, &snap, &own_prev, cap_ns, save_ns);
	} else {
		printf("\n=== final ===\n");
		print_snapshot(stdout, &snap, &own_prev, cap_ns, save_ns);
	}
	return 0;
}

static int run_all_qemu(struct kvmpoll_bpf *obj)
{
	pid_t cur[KVMPOLL_MAX_MONITORED];
	size_t ncur = 0;
	struct kvmpoll_snapshot snap;
	struct own_window own_prev;
	time_t next_print, next_scan, now;
	__u64 cap_ns = read_halt_poll_ns_param();
	__u64 save_ns = env.save_time_ns;

	own_window_reset(&own_prev);

	printf("kvmpoll: all QEMU, print every %ds, rescan every %ds, B=%llu ns\n",
	       env.interval_sec, env.scan_interval_sec,
	       (unsigned long long)save_ns);

	if (sync_monitored_qemu(obj, cur, &ncur) != 0)
		return -1;
	if (ncur == 0)
		fprintf(stderr, "warning: no QEMU processes found yet\n");
	else
		fprintf(stderr, "kvmpoll: monitoring %zu QEMU TGID(s)\n", ncur);

	next_print = time(NULL) + env.interval_sec;
	next_scan = time(NULL) + env.scan_interval_sec;

	while (!exiting) {
		sleep(1);
		now = time(NULL);

		if (now >= next_scan) {
			if (sync_monitored_qemu(obj, cur, &ncur) != 0)
				fprintf(stderr, "warning: QEMU rescan failed\n");
			next_scan = now + env.scan_interval_sec;
		}
		if (now < next_print)
			continue;

		fill_snapshot(obj, &snap);
		print_snapshot(stdout, &snap, &own_prev, cap_ns, save_ns);
		fflush(stdout);
		own_window_snap(&own_prev, &snap);
		next_print = now + env.interval_sec;
	}

	fill_snapshot(obj, &snap);
	printf("\n=== final ===\n");
	print_snapshot(stdout, &snap, &own_prev, cap_ns, save_ns);
	return 0;
}

int main(int argc, char **argv)
{
	struct kvmpoll_bpf *obj = NULL;
	int err;

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.all_qemu && env.have_pid) {
		fprintf(stderr, "-a cannot be combined with -p\n");
		return 1;
	}
	if (!env.all_qemu && !env.have_pid) {
		fprintf(stderr, "required: -p <QEMU_PID> (or -a for all QEMU)\n");
		return 1;
	}
	if (env.duration_sec > 0 && env.all_qemu) {
		fprintf(stderr, "-d requires -p (single QEMU PID)\n");
		return 1;
	}

	bump_memlock_rlimit();

	obj = kvmpoll_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = kvmpoll_bpf__load(obj);
	if (err) {
		fprintf(stderr, "BPF load failed: %d\n", err);
		goto cleanup;
	}

	{
		__u64 cap_ns = read_halt_poll_ns_param();
		__u64 map_poll;
		int ns_max;

		if (setup_default_poll_ns(obj, cap_ns) != 0)
			fprintf(stderr, "warning: default_poll_ns map init failed\n");

		map_poll = read_default_poll_ns_map(obj);
		ns_max = read_ns_sum_map_max(obj);
		if (!env.quiet) {
			fprintf(stderr, "kvmpoll %s  ns_sum_max=%d  BPF poll_budget=%llu ns\n",
				KVMPOLL_VERSION, ns_max,
				(unsigned long long)map_poll);
			if (ns_max >= 0 && ns_max < (int)NS_NS_MAX)
				fprintf(stderr,
					"warning: stale BPF (ns_sum_max=%d, need %d)\n",
					ns_max, (int)NS_NS_MAX);
			if (!map_poll)
				fprintf(stderr,
					"warning: BPF poll_budget map is 0 (C will be wrong)\n");
		}
	}

	err = attach_probes(obj);
	if (err)
		goto cleanup;

	if (env.duration_sec == 0) {
		if (signal(SIGINT, sig_done) == SIG_ERR ||
		    signal(SIGTERM, sig_done) == SIG_ERR) {
			fprintf(stderr, "signal handler: %s\n", strerror(errno));
			err = 1;
			goto cleanup;
		}
	}

	setlinebuf(stdout);

	if (env.all_qemu)
		err = run_all_qemu(obj);
	else
		err = run_single_pid(obj);

cleanup:
	kvmpoll_bpf__destroy(obj);
	return err ? 1 : 0;
}

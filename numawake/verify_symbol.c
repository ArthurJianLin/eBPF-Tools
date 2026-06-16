// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Verify select_task_rq_fair attachability and wake vs non-wake call ratio.
 *
 * Target: Linux 4.19 (no fexit/BTF; kretprobe via kallsyms).
 */

#include <argp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include "libbpf.h"
#include "bpf.h"
#include "verify_symbol.h"
#include "verify_symbol.skel.h"

#define TARGET_FUNC "select_task_rq_fair"

static struct prog_env {
	int duration_sec;
	bool skip_count;
} env = {
	.duration_sec = 5,
	.skip_count = false,
};

static const struct argp_option opts[] = {
	{ "duration", 'd', "SEC", 0, "Counting duration in seconds (default 5)" },
	{ "skip-count", 's', NULL, 0, "Only run static/attach checks, skip live counting" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		env.duration_sec = atoi(arg);
		if (env.duration_sec < 1)
			env.duration_sec = 1;
		break;
	case 's':
		env.skip_count = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static bool kallsyms_has_symbol(const char *name, char *type_out)
{
	char sym[256], type;
	unsigned long addr;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return false;

	while (fscanf(f, "%lx %c %s%*[^\n]\n", &addr, &type, sym) == 3) {
		if (!strcmp(sym, name)) {
			if (type_out)
				*type_out = type;
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;
}

static bool kernel_btf_available(void)
{
	return access("/sys/kernel/btf/vmlinux", R_OK) == 0;
}

static void print_static_checks(void)
{
	struct utsname uts;
	char ksym_type = '?';
	bool in_kallsyms, btf_sysfs;

	uname(&uts);
	in_kallsyms = kallsyms_has_symbol(TARGET_FUNC, &ksym_type);
	btf_sysfs = kernel_btf_available();

	printf("=== Static symbol checks ===\n");
	printf("Kernel: %s %s\n", uts.release, uts.version);
	printf("BTF vmlinux: %s\n", btf_sysfs ? "available" : "not available");
	printf("kallsyms '%s': %s (type '%c', t=local/static)\n",
	       TARGET_FUNC, in_kallsyms ? "found" : "NOT FOUND", ksym_type);
	printf("BTF func '%s': %s\n", TARGET_FUNC,
	       btf_sysfs ? "sysfs present (fexit not checked on libbpf 0.5.0)"
			 : "not found (expected on 4.19)");
	printf("fexit attach: %s\n",
	       btf_sysfs ? "not probed (use kretprobe on 4.19)"
			 : "NOT supported (expected on 4.19)");
	printf("\n");
	printf("4.19 note: use kretprobe (kallsyms), not fexit/BTF.\n");
	printf("Static 't' symbols in kallsyms are attachable when CONFIG_KALLSYMS_ALL=y.\n");
	printf("\n");
}

static int attach_probes(struct verify_symbol_bpf *obj)
{
	struct bpf_link *link;
	long err;

	link = bpf_program__attach_kprobe(obj->progs.handle_select_task_rq_fair,
					  true, TARGET_FUNC);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "kretprobe '%s' attach failed: %ld (%s)\n",
			TARGET_FUNC, err, strerror(-err));
		return -1;
	}
	obj->links.handle_select_task_rq_fair = link;
	printf("kretprobe '%s': attach OK\n", TARGET_FUNC);

	link = bpf_program__attach_tracepoint(obj->progs.handle_sched_wakeup,
						"sched", "sched_wakeup");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "sched_wakeup attach failed: %ld\n", err);
		return -1;
	}
	obj->links.handle_sched_wakeup = link;

	link = bpf_program__attach_tracepoint(obj->progs.handle_sched_wakeup_new,
						"sched", "sched_wakeup_new");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "sched_wakeup_new attach failed: %ld\n", err);
		return -1;
	}
	obj->links.handle_sched_wakeup_new = link;

	link = bpf_program__attach_tracepoint(obj->progs.handle_sched_migrate_task,
						"sched", "sched_migrate_task");
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "sched_migrate_task attach failed: %ld\n", err);
		return -1;
	}
	obj->links.handle_sched_migrate_task = link;

	return 0;
}

static __u64 read_counter(struct verify_symbol_bpf *obj, __u32 key)
{
	int fd = bpf_map__fd(obj->maps.counters);
	__u64 val = 0;

	if (bpf_map_lookup_elem(fd, &key, &val))
		return 0;
	return val;
}

static void run_counting(struct verify_symbol_bpf *obj)
{
	__u64 fair_before, fair_after, wake_before, wake_after, wake_new_before, wake_new_after;
	__u64 migrate_before, migrate_after;
	__u64 fair_delta, wake_delta, migrate_delta, non_wake;
	double non_wake_pct;

	fair_before = read_counter(obj, CNT_SELECT_TASK_RQ_FAIR);
	wake_before = read_counter(obj, CNT_SCHED_WAKEUP);
	wake_new_before = read_counter(obj, CNT_SCHED_WAKEUP_NEW);
	migrate_before = read_counter(obj, CNT_SCHED_MIGRATE_TASK);

	printf("Counting for %d seconds (generate workload if idle)...\n",
	       env.duration_sec);
	sleep(env.duration_sec);

	fair_after = read_counter(obj, CNT_SELECT_TASK_RQ_FAIR);
	wake_after = read_counter(obj, CNT_SCHED_WAKEUP);
	wake_new_after = read_counter(obj, CNT_SCHED_WAKEUP_NEW);
	migrate_after = read_counter(obj, CNT_SCHED_MIGRATE_TASK);

	fair_delta = fair_after - fair_before;
	wake_delta = (wake_after - wake_before) + (wake_new_after - wake_new_before);
	migrate_delta = migrate_after - migrate_before;
	non_wake = fair_delta > wake_delta ? fair_delta - wake_delta : 0;
	non_wake_pct = fair_delta ? (100.0 * non_wake / fair_delta) : 0.0;

	printf("\n=== Live counting results ===\n");
	printf("select_task_rq_fair (kretprobe): %llu\n", fair_delta);
	printf("sched_wakeup + sched_wakeup_new: %llu\n", wake_delta);
	printf("sched_migrate_task:              %llu\n", migrate_delta);
	printf("estimated non-wake calls:        %llu (%.1f%%)\n",
	       non_wake, non_wake_pct);
	printf("\n");
	printf("Interpretation:\n");
	printf("- fair_delta ~= wake_delta  => mostly wake-path calls (good for numawake)\n");
	printf("- migrate_delta > 0         => enqueue_cpu may differ from chosen_cpu;\n");
	printf("                               numawake uses migrate for enqueue_ts anchor\n");
	printf("- non-wake %% high           => load balance / migration noise; filter in BPF\n");
	printf("- fair_delta == 0             => kretprobe not firing or no scheduler activity\n");
}

int main(int argc, char **argv)
{
	struct verify_symbol_bpf *obj = NULL;
	int err;

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = "verify_symbol - check select_task_rq_fair hook feasibility",
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	bump_memlock_rlimit();
	libbpf_set_print(NULL);

	print_static_checks();

	obj = verify_symbol_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = verify_symbol_bpf__load(obj);
	if (err) {
		fprintf(stderr, "BPF load failed: %d\n", err);
		goto cleanup;
	}

	err = attach_probes(obj);
	if (err)
		goto cleanup;

	if (!env.skip_count)
		run_counting(obj);

cleanup:
	verify_symbol_bpf__destroy(obj);
	return err ? 1 : 0;
}

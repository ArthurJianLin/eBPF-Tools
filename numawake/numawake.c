// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * numawake — observe cross-NUMA wake decisions and runqueue latency.
 */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include "libbpf.h"
#include "bpf.h"
#include "numawake.h"
#include "numawake_topology.h"
#include "numawake.skel.h"
#include "numawake_print.h"
#include "numawake_attach.h"

#define MAX_PIDS 256
#define MAX_TP_FDS 8
#define TARGET_FUNC "select_task_rq_fair"

static volatile sig_atomic_t exiting;
static int tp_fds[MAX_TP_FDS];
static int tp_fd_cnt;

static struct prog_env {
	int interval_sec;
	bool filter_enable;
	int pid_count;
	pid_t pids[MAX_PIDS];
} env = {
	.interval_sec = 3,
	.filter_enable = false,
	.pid_count = 0,
};

static const struct argp_option opts[] = {
	{ "interval", 'i', "SEC", 0, "Print interval in seconds (default 3)" },
	{ "process", 'p', "PID", 0, "Trace PID or range (e.g. 123,200-205)" },
	{},
};

static void sig_int(int signo)
{
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

static void parse_pid_range(const char *range_str)
{
	char *dash_pos = strchr(range_str, '-');

	if (dash_pos) {
		*dash_pos = '\0';
		int start_pid = strtol(range_str, NULL, 10);
		int end_pid = strtol(dash_pos + 1, NULL, 10);

		if (errno || start_pid <= 0 || end_pid <= 0 || start_pid > end_pid) {
			fprintf(stderr, "invalid PID range: %s\n", range_str);
			return;
		}
		for (int pid = start_pid; pid <= end_pid; pid++) {
			if (env.pid_count >= MAX_PIDS) {
				fprintf(stderr, "Too many PIDs (max %d)\n", MAX_PIDS);
				return;
			}
			env.pids[env.pid_count++] = pid;
		}
	} else {
		int pid = strtol(range_str, NULL, 10);

		if (errno || pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", range_str);
			return;
		}
		if (env.pid_count >= MAX_PIDS) {
			fprintf(stderr, "Too many PIDs (max %d)\n", MAX_PIDS);
			return;
		}
		env.pids[env.pid_count++] = pid;
	}
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *token;

	switch (key) {
	case 'i':
		errno = 0;
		env.interval_sec = strtol(arg, NULL, 10);
		if (errno || env.interval_sec <= 0) {
			fprintf(stderr, "invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		env.pid_count = 0;
		token = strtok(arg, ",");
		while (token) {
			parse_pid_range(token);
			token = strtok(NULL, ",");
		}
		env.filter_enable = env.pid_count > 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int setup_pid_filter(struct numawake_bpf *obj)
{
	__u32 key = 0;
	int fd, i;

	fd = bpf_map__fd(obj->maps.filter_enable_map);
	if (bpf_map_update_elem(fd, &key, &env.filter_enable, BPF_ANY))
		return -1;

	if (!env.filter_enable)
		return 0;

	fd = bpf_map__fd(obj->maps.pid_map);
	for (i = 0; i < env.pid_count; i++) {
		key = env.pids[i];
		if (bpf_map_update_elem(fd, &key, &key, BPF_ANY))
			return -1;
		printf("trace pid %u\n", key);
	}
	return 0;
}

static int attach_tracepoint_fd(struct bpf_program *prog,
				const char *cat, const char *name,
				const char *label)
{
	int fd;

	if (tp_fd_cnt >= MAX_TP_FDS)
		return -ENOMEM;

	fd = numawake_attach_tracepoint(prog, cat, name);
	if (fd < 0) {
		fprintf(stderr, "%s attach failed: %s\n", label, strerror(-fd));
		return fd;
	}

	tp_fds[tp_fd_cnt++] = fd;
	return 0;
}

static void detach_tracepoints(void)
{
	int i;

	for (i = 0; i < tp_fd_cnt; i++)
		close(tp_fds[i]);
	tp_fd_cnt = 0;
}

static int attach_probes(struct numawake_bpf *obj)
{
	struct bpf_link *link;
	long err;

	link = bpf_program__attach_kprobe(obj->progs.entry_select_task_rq_fair,
					  false, TARGET_FUNC);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "kprobe '%s' attach failed: %ld\n", TARGET_FUNC, err);
		return -1;
	}
	obj->links.entry_select_task_rq_fair = link;

	link = bpf_program__attach_kprobe(obj->progs.ret_select_task_rq_fair,
					  true, TARGET_FUNC);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "kretprobe '%s' attach failed: %ld\n", TARGET_FUNC, err);
		return -1;
	}
	obj->links.ret_select_task_rq_fair = link;

	if (attach_tracepoint_fd(obj->progs.handle_sched_wakeup,
				 "sched", "sched_wakeup", "sched_wakeup") < 0)
		return -1;

	if (attach_tracepoint_fd(obj->progs.handle_sched_wakeup_new,
				 "sched", "sched_wakeup_new",
				 "sched_wakeup_new") < 0)
		return -1;

	if (attach_tracepoint_fd(obj->progs.handle_sched_migrate_task,
				 "sched", "sched_migrate_task",
				 "sched_migrate_task") < 0)
		return -1;

	if (attach_tracepoint_fd(obj->progs.handle_sched_switch,
				 "sched", "sched_switch", "sched_switch") < 0)
		return -1;

	if (attach_tracepoint_fd(obj->progs.handle_sched_process_exit,
				 "sched", "sched_process_exit",
				 "sched_process_exit") < 0)
		return -1;

	return 0;
}

static void print_stats(struct numawake_bpf *obj)
{
	struct numawake_stats st = {};
	__u32 key = 0;
	int fd = bpf_map__fd(obj->maps.stats);
	time_t t;
	struct tm *tm;
	char ts[32];

	if (bpf_map_lookup_elem(fd, &key, &st)) {
		fprintf(stderr, "stats map lookup failed\n");
		return;
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

	printf("\n[%s]\n", ts);
	printf("  cross_numa_wake:   %llu\n", st.cross_numa_wake);
	printf("  same_numa_wake:    %llu\n", st.same_numa_wake);
	printf("  landing_deviation: %llu\n", st.landing_deviation);
	printf("  sanity_mismatch:   %llu\n", st.sanity_mismatch);

	printf("  cross NUMA runqueue latency (msecs):\n");
	print_log2_hist(st.cross_numa_lat.slots, NUMAWAKE_HIST_SLOTS, "msecs");
	printf("  same NUMA runqueue latency (msecs):\n");
	print_log2_hist(st.same_numa_lat.slots, NUMAWAKE_HIST_SLOTS, "msecs");
}

int main(int argc, char **argv)
{
	struct numawake_bpf *obj = NULL;
	struct numawake_topo topo;
	int err;

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = "numawake - cross-NUMA wake observability",
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	bump_memlock_rlimit();

	obj = numawake_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = numawake_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = numawake_topo_from_sysfs(&topo);
	if (err) {
		fprintf(stderr, "topology: %s\n", strerror(-err));
		goto cleanup;
	}

	err = numawake_topo_load_map(obj->maps.cpu_to_node_map, &topo);
	if (err) {
		fprintf(stderr, "failed to load cpu_to_node map: %d\n", err);
		goto cleanup;
	}

	err = setup_pid_filter(obj);
	if (err) {
		fprintf(stderr, "failed to configure PID filter\n");
		goto cleanup;
	}

	err = attach_probes(obj);
	if (err)
		goto cleanup;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("numawake running (interval %ds). Ctrl-C to exit.\n",
	       env.interval_sec);
	while (!exiting) {
		sleep(env.interval_sec);
		print_stats(obj);
	}

cleanup:
	detach_tracepoints();
	numawake_bpf__destroy(obj);
	return err ? 1 : 0;
}

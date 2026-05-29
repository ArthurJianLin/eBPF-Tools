// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 
 *
 * 2025-06-11   Yongkai Wu   Created this.
 *
 */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/time.h>
#include "exec_trace.h"
#include "exec_trace.skel.h"

static struct env {
	bool verbose;
	char command[MAX_COMMAND_LEN];
} env;

static int command_filter;

const char *argp_program_version = "exec_trace 0.1";
const char argp_program_doc[] = "Trace the pid which execute specific command.\n"
				"\n"
				"Usage: ./exec_trace [-v] [-c <command>]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "command", 'c', "Exec-command", 0, "trace the specific command" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		strncpy(env.command, arg, MAX_COMMAND_LEN);
		command_filter=1;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct timeval tv;
    struct tm *tm;
    char buffer[80];

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);
	strftime(buffer, 80, "%Y-%m-%d-%H:%M:%S", tm);
    sprintf(buffer + strlen(buffer), ".%03ld", tv.tv_usec / 1000);

	if (!command_filter) {
		printf("%-24s %-5s %-16s %-7d %-7d %-16s %s\n", buffer, "exec", e->comm, e->pid, e->ppid,
		       e->parent_comm, e->filename);
	} else if (strncmp(e->comm, env.command, MAX_COMMAND_LEN) == 0) {
		printf("%-24s %-5s %-16s %-7d %-7d %-16s %s\n", buffer, "exec", e->comm, e->pid, e->ppid,
		       e->parent_comm, e->filename);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;
	struct exec_trace_bpf *skel;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = exec_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = exec_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = exec_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-24s %-5s %-16s %-7s %-7s %-16s %s\n", "TIME", "EVENT", "COMMAND", "PID", "PPID",
	       "PAREANT_COMM", "EXEC-FILENAME");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);

		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	exec_trace_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 
 *
 * Yongkai Wu   Created this.
 *
 * TODO:
 * - support ustack
 * - support stack tracing in tracepoint
 */

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include "funcstack.skel.h"
#include "libbpf.h"
#include "bpf.h"
#include "trace_helpers.h"
#include "funcstack.h"

enum func_type {
	FUNC_TYPE_KPROBE,
	FUNC_TYPE_KRETPROBE,
	FUNC_TYPE_TRACEPOINT,
	FUNC_TYPE_RAW_TRACEPOINT,
};

static struct prog_env {
	int functype;
	char *tp_category;
        char *funcname;
} env = {
};

static volatile bool exiting = false;
struct funcstack_bpf *obj;
struct syms_cache *syms_cache = NULL;
struct ksyms *ksyms = NULL;

const char *argp_program_version = "funcstack 0.1";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
"Trace functions and print the call stack.\n"
"\n"
"Usage: funcstack [-h] [-k|-r|-t|-o] FUNCTION\n"
"       Choices for FUNCTION: FUNCTION         (kprobe)\n"
"\v"
"Examples:\n"
"  ./funcstack -k vfs_read	# add a kprobe trace point in vfs_read()\n"
"  ./funcstack -r vfs_read	# add a kretprobe trace point in vfs_read()\n"
"  ./funcstack -t syscalls:sys_enter_execve	# add a tracepoint in \
                                               			sys_enter_execve\n"
"  ./funcstack -o sys_enter	# add a raw tracepoint in sys_enter\n"
;

static const struct argp_option opts[] = {
        { "kprobe", 'k', "kprobe", 0, "Add a kprobe"},
        { "kretprobe", 'r', "kretprobe", 0, "Add a kretprobe"},
        { "tracepoint", 't', "tracepoint", 0, "Add a tracepoint"},
	{ "raw_tracepoint", 'o', "raw_tracepoint", 0, "Add a raw tracepoint"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;

        switch (key) {
        case 'k':
		//printf("kkkkk -- state->arg_num=%d, arg=%s\n",state->arg_num, arg);
		env->functype = FUNC_TYPE_KPROBE;
		env->funcname = arg;
                break;
        case 'r':
		env->functype = FUNC_TYPE_KRETPROBE;
		env->funcname = arg;
                break;
        case 't':
		//printf("ttttt -- state->arg_num=%d, arg=%s\n",state->arg_num, arg);
		env->functype = FUNC_TYPE_TRACEPOINT;
		char tp_category[64], funcname[64];
		sscanf(arg, "%[^':']:%s", tp_category, funcname);
		printf("ttttt -- tp_category=%s, funcname=%s\n", tp_category, funcname);
		env->tp_category = strdup((const char *)tp_category);
		env->funcname = strdup((const char *)funcname);
		if ((env->tp_category == NULL) || (env->funcname == NULL)) {
			fprintf(stderr, "Argument error for tracepoint!\n");
			return ARGP_ERR_UNKNOWN;
		}
                break;
	case 'o':
		//printf("ooooo -- state->arg_num=%d, arg=%s\n",state->arg_num, arg);
		env->functype = FUNC_TYPE_RAW_TRACEPOINT;
		env->funcname = arg;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;

	case ARGP_KEY_ARG:
		//printf("ARGP_KEY_ARG -- state->arg_num=%d, arg=%s\n",state->arg_num, arg);
		break;
	case ARGP_KEY_END:
		//printf("ARGP_KEY_END -- state->arg_num=%d, arg=%s\n",state->arg_num, arg);
                if (!env->funcname) {
			fprintf(stderr, "Need a function to trace\n");
			exit(-1);
                }
                break;
        default:
		//printf("default -- state->arg_num=%d, arg=%s\n",state->arg_num, arg);
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event_t *e = data;
	int i, stack_fd;
	unsigned long *stack;
	long offset;
	const struct ksym *ksym;

	printf("time_ns:%llu  pid:%d  comm:%s exec %s():\n", e->start_ts, e->pid, e->comm, env.funcname);
	stack = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stack));

	stack_fd = bpf_map__fd(obj->maps.stackmap);
		if (bpf_map_lookup_elem(stack_fd, &e->kern_stack_id, stack) != 0) {
			fprintf(stderr, "    [Missed Kernel Stack]\n\n");
			goto cleanup;
		}
		for (i = 0; i < PERF_MAX_STACK_DEPTH && stack[i]; i++) {
			ksym = ksyms__map_addr(ksyms, stack[i]);
			offset = stack[i] - ksym->addr;
			printf("    %s+%ld\n", ksym ? ksym->name : "Unknown", offset);
		}
		printf("\n\n");

	//if (bpf_map_delete_elem(stack_fd, &e->kern_stack_id) != 0) {
	//	fprintf(stderr, "failed to delete elem!\n");
	//}

cleanup:
	free(stack);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int set_probes(struct funcstack_bpf *obj, int type)
{
	switch (type) {
		case FUNC_TYPE_KPROBE:
			bpf_program__set_kprobe(obj->progs.dummy_probe);
			break;
		case FUNC_TYPE_KRETPROBE:
			bpf_program__set_kprobe(obj->progs.dummy_probe);
			break;
		case FUNC_TYPE_TRACEPOINT:
			bpf_program__set_tracepoint(obj->progs.dummy_probe);
			break;
		case FUNC_TYPE_RAW_TRACEPOINT:
			bpf_program__set_raw_tracepoint(obj->progs.dummy_probe);
			break;

		default:
			fprintf(stderr, "type error! failed to set probes!\n");

			return -1;
	}
	return 0;
}

static int attach_probes(struct funcstack_bpf *obj, int type)
{
	long err;

	switch (type) {
		case FUNC_TYPE_KPROBE:
			obj->links.dummy_probe =
				bpf_program__attach_kprobe(obj->progs.dummy_probe, false,
							   env.funcname);
        		err = libbpf_get_error(obj->links.dummy_probe);
        		if (err) {
				fprintf(stderr, "failed to attach kprobe: %ld\n",err);
                		return -1;
        		}
			break;
		case FUNC_TYPE_KRETPROBE:
			obj->links.dummy_probe =
				bpf_program__attach_kprobe(obj->progs.dummy_probe, true,
							   env.funcname);
			err = libbpf_get_error(obj->links.dummy_probe);
			if (err) {
				fprintf(stderr, "failed to attach kretprobe: %ld\n",err);
				return -1;
			}
			break;
		case FUNC_TYPE_TRACEPOINT:
			if (env.tp_category == NULL) {
				fprintf(stderr, "tp_category is NULL!\n");
				return -1;
			}
			obj->links.dummy_probe =
				bpf_program__attach_tracepoint(obj->progs.dummy_probe, env.tp_category,
						env.funcname);
			err = libbpf_get_error(obj->links.dummy_probe);
			if (err) {
				fprintf(stderr, "failed to attach tracepoint: %ld\n",err);
				return -1;
			}
			break;
		case FUNC_TYPE_RAW_TRACEPOINT:
			obj->links.dummy_probe =
				bpf_program__attach_raw_tracepoint(obj->progs.dummy_probe, env.funcname);
			err = libbpf_get_error(obj->links.dummy_probe);
			if (err) {
				fprintf(stderr, "failed to attach raw kretprobe: %ld\n",err);
				return -1;
			}
			break;

		default:
			fprintf(stderr, "type error! failed to attach probes!\n");
			return -1;
	}

	return 0;
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int err;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
        if (err)
                return err;

	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();

	obj = funcstack_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = set_probes(obj, env.functype);
	if (err) {
		return err;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	err = funcstack_bpf__load(obj);
	if (err) {
		goto cleanup;
	}
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_buf), 64, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	err = attach_probes(obj, env.functype);
        if (err)
                goto cleanup;

	printf("Tracing %s.  Hit Ctrl-C to exit\n", env.funcname);

	while (!exiting && ((err = perf_buffer__poll(pb, 100)) >= 0)) {
		;
	}
	if (err < 0)
		printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	funcstack_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);

	return err < 0 ? -err : 0;
}


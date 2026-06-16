// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "libbpf.h"
#include "numawake_attach.h"

#ifndef __NR_perf_event_open
#if defined(__x86_64__)
#define __NR_perf_event_open 298
#elif defined(__aarch64__)
#define __NR_perf_event_open 241
#else
#error "define __NR_perf_event_open for this arch"
#endif
#endif

static int read_tracepoint_id(const char *category, const char *name)
{
	char path[256];
	FILE *f;
	int id;

	snprintf(path, sizeof(path),
		 "/sys/kernel/tracing/events/%s/%s/id", category, name);
	f = fopen(path, "r");
	if (!f) {
		snprintf(path, sizeof(path),
			 "/sys/kernel/debug/tracing/events/%s/%s/id",
			 category, name);
		f = fopen(path, "r");
	}
	if (!f)
		return -errno;

	if (fscanf(f, "%d", &id) != 1) {
		fclose(f);
		return -EINVAL;
	}
	fclose(f);
	return id;
}

int numawake_attach_tracepoint(struct bpf_program *prog,
			       const char *tp_category,
			       const char *tp_name)
{
	struct perf_event_attr attr = {};
	const char *stage;
	int prog_fd, tp_id, pfd;

	tp_id = read_tracepoint_id(tp_category, tp_name);
	if (tp_id < 0)
		return tp_id;

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		return -EINVAL;

	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.config = tp_id;

	pfd = (int)syscall(__NR_perf_event_open, &attr, -1, 0, -1,
			   PERF_FLAG_FD_CLOEXEC);
	if (pfd < 0)
		return -errno;

	stage = "PERF_EVENT_IOC_SET_BPF";
	if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
		int err = -errno;

		close(pfd);
		fprintf(stderr, "tracepoint %s/%s: %s: %s\n",
			tp_category, tp_name, stage, strerror(-err));
		return err;
	}

	stage = "PERF_EVENT_IOC_ENABLE";
	if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		int err = -errno;

		close(pfd);
		fprintf(stderr, "tracepoint %s/%s: %s: %s\n",
			tp_category, tp_name, stage, strerror(-err));
		return err;
	}

	return pfd;
}

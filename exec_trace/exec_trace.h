/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __EXEC_TRACE_H
#define __EXEC_TRACE_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127
#define MAX_COMMAND_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char parent_comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
};

#endif /* __EXEC_TRACE_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NUMAWAKE_VERIFY_SYMBOL_H
#define __NUMAWAKE_VERIFY_SYMBOL_H

#ifndef BPF_ANY
#define BPF_ANY		0
#define BPF_NOEXIST	1
#define BPF_EXIST	2
#endif

enum counter_key {
	CNT_SELECT_TASK_RQ_FAIR = 0,
	CNT_SCHED_WAKEUP = 1,
	CNT_SCHED_WAKEUP_NEW = 2,
	CNT_SCHED_MIGRATE_TASK = 3,
	CNT_MAX = 4,
};

#endif /* __NUMAWAKE_VERIFY_SYMBOL_H */

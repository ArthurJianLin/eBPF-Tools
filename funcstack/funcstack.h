#ifndef __FUNCSTACK_H
#define __FUNCSTACK_H

#define TASK_COMM_LEN   16
#define PERF_MAX_STACK_DEPTH 127

struct event_t {
        __u64 start_ts;
        __u32 pid;
        __u32 kern_stack_id;
        __u8 comm[TASK_COMM_LEN];
};

#endif

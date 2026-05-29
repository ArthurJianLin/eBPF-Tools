/***************************************************************************************
*   DESCRIPTION : Source code of kernel mode for io ebpf tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2026-04-17 -- Guanbing Huang written
*****************************************************************************************/

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "iofsstat.h"

#define S_IFMT  00170000
#define S_IFBLK  0060000
#define S_ISBLK(m)      (((m) & S_IFMT) == S_IFBLK)

#define BPF_F_CURRENT_CPU 0xffffffffULL
#define MAX_ENTRIES     10240

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} filter_enable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} device_enable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[TASK_COMM_LEN]);
} comm_enable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} pid_enable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, struct block_dev);
} block_device_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct file_event);
} file_map SEC(".maps");

static int is_contained(char *str, char *sub)
{
        char *p1 = str;
        char *p2 = sub;
        int i = 0;
        while (i < TASK_COMM_LEN && *p2 != '\0') {
                if (*p1 != *p2) {
                        return 0;
                }
                p1++;
                p2++;
                i++;
        }
        return 1;
}

SEC("kretprobe/vfs_read")
int bpf_probe_vfs_read(struct pt_regs *ctx)
{
	struct file_event e = { 0 };
	struct file_event *pe;
	struct block_dev *pb;
	struct file *file;
	__u64 pid_tgid;
	struct inode *inode;
	struct super_block *i_sb;
	umode_t i_mode;
	__u32 key = 0;
	__u32 *enable;
	__u32 *pd;
	__u32 *pid;
	char *p;

	enable = bpf_map_lookup_elem(&filter_enable_map, &key);
	if (enable == NULL || *enable == 0) {
		/* if disabled, do nothing */
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	e.pid = pid_tgid >> 32;

	key = 0;
	pid = bpf_map_lookup_elem(&pid_enable_map, &key);
	if (pid != NULL && *pid != 0 && *pid != e.pid) {
		/* not target pid, do nothing */
		return 0;
	}

	bpf_get_current_comm(e.comm, sizeof(e.comm));
	key = 0;
	p = bpf_map_lookup_elem(&comm_enable_map, &key);
	if (p != NULL && *p != '\0') {
		int ret;
		ret = is_contained(e.comm, p);
		if (ret == 0) {
			/* not target process, do nothing */
			return 0;
		}
	}

	//file = (struct file*)ctx->di;
	file = (struct file*)PT_REGS_PARM1(ctx);
	if (file == NULL) {
		return 0;
	}

	e.bw_r = PT_REGS_PARM3(ctx);

	/* 安全读取 file->f_inode（内核指针）*/
        inode = BPF_CORE_READ(file, f_inode);
	if (inode == NULL) {
		return 0;
	}

	e.inode = BPF_CORE_READ(inode, i_ino);

	i_mode = BPF_CORE_READ(inode, i_mode);
	if (S_ISBLK(i_mode)) {
		e.dev_id = BPF_CORE_READ(inode, i_rdev);
	} else {
		i_sb = BPF_CORE_READ(inode, i_sb);
		if (i_sb != NULL) {
			e.dev_id = BPF_CORE_READ(i_sb, s_dev);
		}
	}

	pb = bpf_map_lookup_elem(&block_device_map, &e.dev_id);
	if (pb == NULL) {
		return 0; /* not block device, do nothing */
	}

	key = 0;
	pd = bpf_map_lookup_elem(&device_enable_map, &key);
	if (pd != NULL && *pd != 0xFFFFFFFF && *pd != e.dev_id) {
		/* not target device, do nothing */
		return 0;
	}

	pe = bpf_map_lookup_elem(&file_map, &e.pid);
	if (pe != NULL) {
		__sync_fetch_and_add(&pe->cnt_r, 1);
		__sync_fetch_and_add(&pe->bw_r, e.bw_r);
		e.cnt_r = pe->cnt_r;
		e.bw_r = pe->bw_r;
	} else {
		e.cnt_r = 1;
		bpf_map_update_elem(&file_map, &e.pid, &e, 0);
	}

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));

        return 0;
}

SEC("kretprobe/vfs_write")
int bpf_probe_vfs_write(struct pt_regs *ctx)
{
	struct file_event e = { 0 };
	struct file_event *pe;
	struct block_dev *pb;
	struct file *file;
	__u64 pid_tgid;
	struct inode *inode;
	struct super_block *i_sb;
	umode_t i_mode;
	__u32 key = 0;
	__u32 *enable;
	__u32 *pd;
	__u32 *pid;
	char *p;

	enable = bpf_map_lookup_elem(&filter_enable_map, &key);
	if (enable == NULL || *enable == 0) {
		/* if disabled, do nothing */
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	e.pid = pid_tgid >> 32;

	key = 0;
	pid = bpf_map_lookup_elem(&pid_enable_map, &key);
	if (pid != NULL && *pid != 0 && *pid != e.pid) {
		/* not target pid, do nothing */
		return 0;
	}

	bpf_get_current_comm(e.comm, sizeof(e.comm));
	key = 0;
	p = bpf_map_lookup_elem(&comm_enable_map, &key);
	if (p != NULL && *p != '\0') {
		int ret;
		ret = is_contained(e.comm, p);
		if (ret == 0) {
			/* not target process, do nothing */
			return 0;
		}
	}

	//file = (struct file*)ctx->di;
	file = (struct file*)PT_REGS_PARM1(ctx);
	if (file == NULL) {
		return 0;
	}

	e.bw_w = PT_REGS_PARM3(ctx);

	/* 安全读取 file->f_inode（内核指针）*/
        inode = BPF_CORE_READ(file, f_inode);
	if (inode == NULL) {
		return 0;
	}

	e.inode = BPF_CORE_READ(inode, i_ino);
	i_mode = BPF_CORE_READ(inode, i_mode);
	if (S_ISBLK(i_mode)) {
		e.dev_id = BPF_CORE_READ(inode, i_rdev);
	} else {
		i_sb = BPF_CORE_READ(inode, i_sb);
		if (i_sb != NULL) {
			e.dev_id = BPF_CORE_READ(i_sb, s_dev);
		}
	}

	pb = bpf_map_lookup_elem(&block_device_map, &e.dev_id);
	if (pb == NULL) {
		return 0; /* not block device, do nothing, return */
	}

	key = 0;
	pd = bpf_map_lookup_elem(&device_enable_map, &key);
	if (pd != NULL && *pd != 0xFFFFFFFF && *pd != e.dev_id) {
		/* not target device, do nothing, return */
		return 0;
	}

	pe = bpf_map_lookup_elem(&file_map, &e.pid);
	if (pe != NULL) {
		__sync_fetch_and_add(&pe->cnt_w, 1);
		__sync_fetch_and_add(&pe->bw_w, e.bw_w);
		e.cnt_w = pe->cnt_w;
		e.bw_w = pe->bw_w;
	} else {
		e.cnt_w = e.cnt_w + 1;
		bpf_map_update_elem(&file_map, &e.pid, &e, 0);
	}

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));

        return 0;
}

char LICENSE[] SEC("license") = "GPL";

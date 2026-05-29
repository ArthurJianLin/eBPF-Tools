/***************************************************************************************
*   DESCRIPTION : Source code of user mode for io ebpf tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2026-04-17 -- Guanbing Huang written
*****************************************************************************************/

#include <stdio.h>
#include "libbpf.h"
#include "iofsstat.h"
#include "iofsstat.skel.h"
#include <sys/resource.h>
#include <argp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "bpf.h"
#include <sys/resource.h>
#include <sys/mman.h>
#include <math.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <fcntl.h>
#include <sys/syscall.h>
#include "diskstat.h"

struct linux_dirent64 {
        unsigned long long d_ino;
        long long       d_off;
        unsigned short  d_reclen;
        unsigned char   d_type;
        char            d_name[];
};

static int filter_map_fd;

#define MAX_ENTRIES 10240
#define MAX_PATH 4096
#define NSEC_PER_SEC 1000000000UL  /* 1s = 10^9ns */
#define PERF_BUFFER_PAGES	4096
#define PERF_POLL_TIMEOUT_MS	100
#define BINARY_BASE 1024
#define BUF_SIZE 4096

struct list_head {
        struct list_head *next, *prev;
};

#define POISON_POINTER_DELTA 0
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x200 + POISON_POINTER_DELTA)


#define container_of(ptr, type, member) \
    (type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member))

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) \
        struct list_head name = LIST_HEAD_INIT(name)

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
        next->prev = prev;
        prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
        __list_del(entry->prev, entry->next);
        entry->next = LIST_POISON1;
        entry->prev = LIST_POISON2;
}

#define list_entry(ptr, type, member) \
        container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
        list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry(pos, head, member) \
	for (pos = list_first_entry(head, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member) \
    for (pos = list_first_entry(head, typeof(*pos), member), \
         n = list_next_entry(pos, member); \
         &pos->member != (head); \
         pos = n, n = list_next_entry(n, member))


struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

typedef struct {
	struct hlist_node node; /* hlist node */
	unsigned int key;
	char path[MAX_PATH];  /* value */
} HashNode;

typedef struct {
	struct hlist_head *heads; /* hlist head array */
	int size;                 /* capacity */
} HashTable;

static HashTable *hash_table;

static void INIT_HLIST_HEAD(struct hlist_head *h)
{
	h->first = NULL;
}

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos; pos = pos->next)

#define hlist_entry(ptr, type, member) \
	((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

static void hlist_del(struct hlist_node *n)
{
	*n->pprev = n->next;
	if (n->next) {
		n->next->pprev = n->pprev;
	}
}

/* 头部插入节点 */
static void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	n->next = h->first;

	if (h->first) {
		h->first->pprev = &n->next;
	}

	h->first = n;
	n->pprev = &h->first;
}

static unsigned int hash(unsigned int key, int size)
{
	return key % size;
}

/* 创建哈希表 */
static HashTable *create_table(int size)
{
	HashTable *t = malloc(sizeof(HashTable));

	t->size = size;
	t->heads = malloc(size * sizeof(struct hlist_head));

	for (int i = 0; i < size; i++) {
		INIT_HLIST_HEAD(&t->heads[i]);
	}

	return t;
}

/* 插入键值对 */
static void insert(HashTable *t, unsigned int key, char *path)
{
	int idx = hash(key, t->size);
	struct hlist_head *head = &t->heads[idx];
	struct hlist_node *p;
	int len = strlen(path);

	/* 遍历查找是否已存在 */
	hlist_for_each(p, head) {
		HashNode *node = hlist_entry(p, HashNode, node);
		if (node->key == key) {
		    strcpy(node->path, path);
		    node->path[len] = '\0';
		    return;
		}
	}

	/* 创建新节点 */
	HashNode *new = malloc(sizeof(HashNode));
	new->key = key;
	strcpy(new->path, path);
	new->path[len] = '\0';
	hlist_add_head(&new->node, head);
}

/* 查找 */
static char* search(HashTable *t, unsigned int key)
{
	int idx = hash(key, t->size);
	struct hlist_node *p;

	hlist_for_each(p, &t->heads[idx]) {
		HashNode *node = hlist_entry(p, HashNode, node);
		if (node->key == key) {
			return node->path;
		}
	}

    return NULL;
}

/* 删除指定 key 的节点 */
static int delete(HashTable *t, unsigned int key)
{
	int idx = hash(key, t->size);
	struct hlist_node *p;

	hlist_for_each(p, &t->heads[idx]) {
		HashNode *node = hlist_entry(p, HashNode, node);
		if (node->key == key) {
			hlist_del(p);   /* 从 hlist 移除 */
			free(node);     /* 释放节点内存 */
			return 0;       /* 删除成功 */
		}
	}

    return -1; /* 未找到 */
}

/* 销毁哈希表 */
static void destroy_table(HashTable *t)
{
	if (t == NULL) {
		return;
	}

	/* 遍历所有桶 */
	for (int i = 0; i < t->size; i++) {
		struct hlist_node *p = t->heads[i].first;

		while (p) {
			struct hlist_node *tmp = p;
			p = p->next;
			HashNode *node = hlist_entry(tmp, HashNode, node);
			free(node); /* 释放每个节点 */
		}
	}

	free(t->heads); /* 释放哈希桶数组 */
	free(t);        /* 释放哈希表结构体 */
}

struct prog_env {
	int interval;
	int count;
	int pid;
	char dev_name[DEV_NAME_LEN];
	char comm[TASK_COMM_LEN];
};

static struct prog_env env = { 0 };

static volatile sig_atomic_t exiting = 0;

/* 二进制单位（1024进制）*/
static const char *const binary_units[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"};

static void sig_int(int signo)
{
	exiting = 1;
}

/**
 * @brief 字节转换为二进制单位（1024进制）的字符串
 * @param bytes 原始字节数（支持超大值，如10GB）
 * @param buf   输出缓冲区（存储格式化后的结果）
 * @param buf_len 缓冲区长度（建议至少32字节）
 * @return 格式化后的字符串（如 "1.23 GB"）
 */
static char *bytes_to_binary_size(uint64_t bytes, char *buf, size_t buf_len)
{
    if (bytes == 0) {
        snprintf(buf, buf_len, "0 %s", binary_units[0]);
        return buf;
    }

    /* 计算单位层级（避免浮点误差，用位运算/对数）*/
    int level = (int)(log2(bytes) / log2(BINARY_BASE));

    /* 限制最大单位为 PB */
    level = level > (sizeof(binary_units)/sizeof(char*) - 1) ? (sizeof(binary_units)/sizeof(char*) - 1) : level;

    /* 转换为对应单位的数值（保留2位小数）*/
    double size = (double)bytes / pow(BINARY_BASE, level);
    snprintf(buf, buf_len, "%.2f %s", size, binary_units[level]);
    return buf;
}

unsigned long long get_ktime_ns(void)
{
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

LIST_HEAD(file_head);

struct file_node {
	struct list_head list;
	struct file_event fevent;
};

void insert_file_node_sorted(struct file_node *new_node)
{
	struct file_node *pos;

	list_for_each_entry(pos, &file_head, list) {
		if ((new_node->fevent.bw_r + new_node->fevent.bw_w) > (pos->fevent.bw_r + pos->fevent.bw_w)) {
			__list_add(&new_node->list, pos->list.prev, &pos->list);
			return;
		}
	}

	__list_add(&new_node->list, pos->list.prev, &pos->list);
}

void delete_file_node_all()
{
	struct file_node *pos,*tmp;

	list_for_each_entry_safe(pos, tmp, &file_head, list) {
		list_del(&pos->list);
		free(pos);
	}
}

int devt_to_disk(unsigned int dev, char *disk_path, int len)
{
	char sys_path[256] = { 0 };
	int major = dev >> 20;
	int minor = dev & 0xfffff;

	snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%d:%d", major, minor);

	char real_path[512] = {0};
	ssize_t n = readlink(sys_path, real_path, sizeof(real_path)-1);
	if (n < 0) {
		return -1;
	}

	char *name = strrchr(real_path, '/');
	if (name) {
		name++;
	} else {
		name = real_path;
	}

	snprintf(disk_path, len, "%s", name);
	return 0;
}

static int check_if_block_path(char *filepath, char *disk_path)
{
	if (filepath == NULL) {
		disk_path[0] = '\0';
		return -1;
	}

	if (strstr(filepath, "/dev") != NULL) {  /* /dev/sda5 */
		struct stat st;
		if (stat(filepath, &st) == 0) {
			char sys_path[64] = {0};
		//	printf("filepath = %s, major = %d, minor = %d\n", filepath, major(st.st_rdev), minor(st.st_rdev));  // for test
			snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%d:%d", major(st.st_rdev), minor(st.st_rdev));

			char real_path[512] = {0};
			ssize_t n = readlink(sys_path, real_path, sizeof(real_path)-1);
			if (n > 0) {
				 char *p = strrchr(filepath, '/');
				 p++;
				 int len = strlen(p);
				 strcpy(disk_path, p);
				 disk_path[len] = '\0';
				return 0;   /* block device */
			}
		}
	}

	return -1;
}

void print_message()
{
	struct file_node *pos;
	char *filepath;
	char disk_path[128];
	char size_str_r[16];
	char size_str_w[16];
	int ret;

	printf("%-20s %-12s %-16s %-16s %-16s %-16s %-16s %-10s %-s\n",
		"comm", "pid", "cnt_r", "bw_r", "cnt_w", "bw_w", "inode", "device", "filepath");
	list_for_each_entry(pos, &file_head, list) {
		filepath = search(hash_table, pos->fevent.pid);
		disk_path[0] = '\0';
		ret = devt_to_disk(pos->fevent.dev_id, disk_path, sizeof(disk_path));
		if (ret < 0) {
			continue;
		}
		bytes_to_binary_size(pos->fevent.bw_r, size_str_r, 16);
		bytes_to_binary_size(pos->fevent.bw_w, size_str_w, 16);

		if (filepath != NULL) {
			printf("%-20s %-12d %-16ld %-16s %-16ld %-16s %-16ld %-10s %s\n",
				pos->fevent.comm, pos->fevent.pid, pos->fevent.cnt_r, size_str_r,
				pos->fevent.cnt_w, size_str_w, pos->fevent.inode, disk_path, filepath);
		} else {
			printf("%-20s %-12d %-16ld %-16s %-16ld %-16s %-16ld %-10s %s\n",
				pos->fevent.comm, pos->fevent.pid, pos->fevent.cnt_r, size_str_r,
				pos->fevent.cnt_w, size_str_w, pos->fevent.inode, disk_path, "");
		}
		delete(hash_table, pos->fevent.pid);
	}
	printf("\n");
}

static void handle_message(int map_fd)
{
	__u32 cur_key, next_key;

	cur_key = 0;
	while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0) {
		/* 读取 next_key 对应的 value */
		struct file_node *fnode = (struct file_node*)malloc(sizeof(struct file_node));
		if (fnode == NULL) {
			printf("file_node malloc failed!\n");
			delete_file_node_all();
			return;
		}

		if (bpf_map_lookup_elem(map_fd, &next_key, &fnode->fevent) == 0) {
			insert_file_node_sorted(fnode);
		}
		bpf_map_delete_elem(map_fd, &next_key);
		cur_key = next_key;
	}
	print_message();
	delete_file_node_all();

	return;
}

static int find_filepath_by_inode_safe(pid_t pid, ino_t target_ino, char *out_path, size_t path_len)
{
	char proc_path[256];
	char fd_path[MAX_PATH];
	char real_path[MAX_PATH];
	int dir_fd;
	char buf[BUF_SIZE] __attribute__((aligned(8))); /* 必须对齐 */
	struct linux_dirent64 *d;
	int n;

	/* 构造 /proc/pid/fd 路径 */
	snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd", pid);

	// 以 O_DIRECTORY | O_NONBLOCK 打开目录（非阻塞）*/
	dir_fd = open(proc_path, O_RDONLY | O_DIRECTORY | O_NONBLOCK);
	if (dir_fd < 0) {
		return -1;
	}

	/* 循环调用 getdents64 读取目录（替代 readdir）*/
	while (1) {
		/* 直接调用系统调用，不经过 C 库缓存 */
		n = syscall(SYS_getdents64, dir_fd, (struct linux_dirent64 *)buf, BUF_SIZE);

		/* 读取完毕 or 错误 -> 直接退出, 防止block住 */
		if (n <= 0) {
			break;
		}

		/* 遍历目录项 */
		for (int i = 0; i < n; ) {
			d = (struct linux_dirent64 *)(buf + i);

			/* 跳过 . 与 .. */
			if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0) {
				i += d->d_reclen;
				continue;
			}

			/* /proc/pid/fd/xxx */
			snprintf(fd_path, sizeof(fd_path), "%s/%s", proc_path, d->d_name);

			/* 读取软链接 -> 真实路径 */
			ssize_t len = readlink(fd_path, real_path, sizeof(real_path)-1);
			if (len <= 0) {
				i += d->d_reclen;
				continue;
			}
			real_path[len] = '\0';

			/* 获取 inode */
			struct stat st;
			if (stat(real_path, &st) == -1) {
				i += d->d_reclen;
				continue;
			}

			/* 匹配 inode */
			if (st.st_ino == target_ino) {
				strncpy(out_path, real_path, path_len - 1);
				close(dir_fd);
				return 0;
			}

			i += d->d_reclen;
		}
	}

	close(dir_fd);
	return -1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct file_event *fe = (struct file_event*)data;
	char filepath[MAX_PATH];
	char disk_path[128];

	if (size < sizeof(*fe)) {
		printf("Error: packet too small\n");
		return;
	}
#if 0
	char *f = search(hash_table, fe->pid);
	if (f != NULL) {
		int ret = check_if_block_path(f, disk_path);
		if (ret == 0) {
			return;    /* filepath found, is block path, return */
		}
	}
#endif
	if (find_filepath_by_inode_safe(fe->pid, fe->inode, filepath, MAX_PATH) == 0) {
		insert(hash_table, fe->pid, filepath);
		//printf("%s: filepath = %s, %d\n", fe->comm, filepath, fe->dev_id); //for test
	} else {
		//printf("%s: filepath = %s\n", fe->comm, "-"); //for test
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 cnt)
{
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlimit_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlimit_new) != 0) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
	return;
}

static const struct argp_option opts[] = {
	{"iofsstat", 'i', "interval",  0,        "Time interval",    0},
	{"iofsstat", 'n', "count", 0,            "Print count",   0},
	{"iofsstat", 'd', "device", 0,           "Print device",   0},
	{"iofsstat", 'c', "comm", 0,             "Print process name",   0},
	{"iofsstat", 'p', "pid", 0,              "Print process id",   0},
	{NULL,       'h', NULL,   OPTION_HIDDEN, "Show full help",  0},
	{},
};

const char program_doc[] =
"Trace the iofsstat.\n"
"\n"
"USAGE: ./iofsstat [-h] [-i interval] [-n count] [-d device] [-c comm] [-p pid]\n"
"\n";

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	int len;

	switch (key) {
	case 'i':
		env->interval = strtol(arg, NULL, 10);
		if (env->interval <= 0) {
			fprintf(stderr, "Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'n':
		env->count = strtol(arg, NULL, 10);
		if (env->count <= 0) {
			fprintf(stderr, "Invalid count: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		len = strlen(arg);
		len = len < DEV_NAME_LEN ? len : (DEV_NAME_LEN - 1);
		strncpy(env->dev_name, arg, len);
		env->dev_name[len] = '\0';
		break;
	case 'c':
		len = strlen(arg);
		len = len < TASK_COMM_LEN ? len : (TASK_COMM_LEN - 1);
		strncpy(env->comm, arg, len);
		env->comm[len] = '\0';
		break;
	case 'p':
		env->pid = strtol(arg, NULL, 10);
		if (env->pid <= 0) {
			fprintf(stderr, "Invalid pid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		default:
			return ARGP_ERR_UNKNOWN;

	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
//	args_doc = args_doc,
	.doc = program_doc,
};

#define BLOCK_SYS_PATH "/sys/class/block"

/* read major:minor from /sys/class/block/<dev>/dev */
static int get_dev_major_minor(const char *dev_name, int *major, int *minor)
{
	char path[BUF_SIZE];
	char buf[32];
	int fd, n;

	snprintf(path, sizeof(path), "%s/%s/dev", BLOCK_SYS_PATH, dev_name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (n <= 0) {
		return -1;
	}
	buf[n] = '\0';

	if (sscanf(buf, "%d:%d", major, minor) != 2) {
		return -1;
	}
	return 0;
}

static int enum_all_block_devices(struct block_dev *dev_list, int max_dev)
{
	DIR *dir;
	struct dirent *ent;
	int count = 0;

	dir = opendir(BLOCK_SYS_PATH);
	if (dir == NULL) {
		perror("opendir /sys/class/block failed");
		return -1;
	}

	while ((ent = readdir(dir)) != NULL && count < max_dev) {
		struct block_dev *dev = &dev_list[count];
		unsigned int maj, min;

		// 跳过 . 和 ..
		if (ent->d_name[0] == '.')
		    continue;

		if (get_dev_major_minor(ent->d_name, &maj, &min) < 0)
		    continue;

		strncpy(dev->dev_name, ent->d_name, sizeof(dev->dev_name) - 1);
		dev->major = maj;
		dev->minor = min;
		dev->dev_t = maj << 20 | min;  /* 内核标准 dev_t */

		count++;
	}

	closedir(dir);
	return count;
}

static struct block_dev dev_list[128] = { 0 };
static int set_block_devices(int block_device_map_fd)
{
	int n, i;
	int ret;
	struct block_dev *d;

	n = enum_all_block_devices(dev_list, 128);
	if (n < 0) {
		fprintf(stderr, "enum block devices failed!\n");
		return 1;
	}

	for (i = 0; i < n; i++) {
		d = &dev_list[i];
		ret = bpf_map_update_elem(block_device_map_fd, &d->dev_t, d, BPF_ANY);
		if (ret != 0) {
			fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct iofsstat_bpf *bpf_obj = NULL;  /* struct iofsstat_bpf is auto-generated */
	int block_device_map_fd;
	int comm_enable_map_fd;
	int pid_enable_map_fd;
	int file_map_fd;
	int ret;
	__u32 key;
	__u32 enable;
	__u64 time_start, time_end;
	int count;
	struct disk_stat prev[MAX_DEVICES], curr[MAX_DEVICES];
	int prev_cnt = 0, curr_cnt = 0;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (ret != 0) {
		return ret;
	}

	if (env.interval == 0) {
		env.interval = 1; /* 1s default */
	}

	bump_memlock_rlimit();

	bpf_obj = iofsstat_bpf__open();
	if (bpf_obj == NULL) {
		fprintf(stderr, "Failed to open BPF object!\n");
		return 1;
	}

	ret = iofsstat_bpf__load(bpf_obj);
	if (ret != 0) {
		fprintf(stderr, "Failed to load BPF object: %d\n", ret);
		goto clean_up;
	}

	block_device_map_fd = bpf_map__fd(bpf_obj->maps.block_device_map);
	set_block_devices(block_device_map_fd);
	close(block_device_map_fd);

	int device_enable_map_fd = bpf_map__fd(bpf_obj->maps.device_enable_map);
	if (strlen(env.dev_name) > 0) {
		int i = 0;
		while (dev_list[i].dev_name[0] != '\0') {
			struct block_dev *d = &dev_list[i];
			if (strcmp(env.dev_name, d->dev_name) == 0) {
				key = 0;
				ret = bpf_map_update_elem(device_enable_map_fd, &key, &d->dev_t, BPF_ANY);
				if (ret != 0) {
					fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
					close(device_enable_map_fd);
					return -1;
				}
				break;
			}
			i++;
		}

		if (dev_list[i].dev_name[0] == '\0') {
			fprintf(stderr, "Not support device: %s\n", env.dev_name);
			close(device_enable_map_fd);
			return -1;
		}
	} else {
		int dev_id = 0xFFFFFFFF;
		ret = bpf_map_update_elem(device_enable_map_fd, &key, &dev_id, BPF_ANY);
		if (ret != 0) {
			fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
			close(device_enable_map_fd);
			return -1;
		}
	}
	close(device_enable_map_fd);

	if (strlen(env.comm) > 0) {
		comm_enable_map_fd = bpf_map__fd(bpf_obj->maps.comm_enable_map);
		key = 0;
		ret = bpf_map_update_elem(comm_enable_map_fd, &key, &env.comm, BPF_ANY);
		if (ret != 0) {
			fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
			close(comm_enable_map_fd);
			return -1;
		}
		close(comm_enable_map_fd);
	}

	if (env.pid > 0) {
		pid_enable_map_fd = bpf_map__fd(bpf_obj->maps.pid_enable_map);
		key = 0;
		ret = bpf_map_update_elem(pid_enable_map_fd, &key, &env.pid, BPF_ANY);
		if (ret != 0) {
			fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
			close(pid_enable_map_fd);
			return -1;
		}
		close(pid_enable_map_fd);
	}

	filter_map_fd = bpf_map__fd(bpf_obj->maps.filter_enable_map);
	key = 0;
	enable = 1;
	ret = bpf_map_update_elem(filter_map_fd, &key, &enable, BPF_ANY);
	if (ret != 0) {
		fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
		goto clean_up;
	}

	hash_table = create_table(MAX_ENTRIES);
	if (hash_table == NULL) {
		fprintf(stderr, "failed to create hash table!\n");
                goto clean_up;
	}

	bpf_obj->links.bpf_probe_vfs_read = bpf_program__attach_kprobe(bpf_obj->progs.bpf_probe_vfs_read, false, "vfs_read");
	bpf_obj->links.bpf_probe_vfs_write = bpf_program__attach_kprobe(bpf_obj->progs.bpf_probe_vfs_write, false, "vfs_write");

	printf("Tracing IO ... Hit Ctrl-C to end.\n");

	pb = perf_buffer__new(bpf_map__fd(bpf_obj->maps.perf_buf), PERF_BUFFER_PAGES, handle_event, handle_lost_events, NULL, NULL);
	if (pb == NULL) {
		ret = -1;
		fprintf(stderr, "Failed to open perf buffer: %d\n", ret);
		goto clean_up;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		ret = -1;
		fprintf(stderr, "Can't set signal handler\n");
		goto clean_up;
	}

	file_map_fd = bpf_map__fd(bpf_obj->maps.file_map);
        time_start = get_ktime_ns();
        time_end = time_start + env.interval * NSEC_PER_SEC;
	prev_cnt = read_diskstats(prev, MAX_DEVICES);
	count = 1;
	while (!exiting) {
		ret = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-ret));
			goto clean_up;
		}
		/* reset ret to return 0 if exiting */
		ret = 0;

		if (get_ktime_ns() > time_end) {
			key = 0;
			enable = 0;
			ret = bpf_map_update_elem(filter_map_fd, &key, &enable, BPF_ANY);
			if (ret != 0) {
				fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
				goto clean_up;
			}
			curr_cnt = read_diskstats(curr, MAX_DEVICES);

			int interval_ms = (get_ktime_ns() - time_start) / 1000000;
			handle_diskstats(prev, curr, prev_cnt, curr_cnt, interval_ms);

			handle_message(file_map_fd);

			key = 0;
			enable = 1;
			ret = bpf_map_update_elem(filter_map_fd, &key, &enable, BPF_ANY);
			if (ret != 0) {
				fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
				goto clean_up;
			}

			time_start = get_ktime_ns();
			time_end = time_start + env.interval * NSEC_PER_SEC;
			prev_cnt = read_diskstats(prev, MAX_DEVICES);

			if (env.count != 0 && count >= env.count) { /* env.count default is 0 */
				break;
			} else {
				count++;
			}
		}
	}

clean_up:
	delete_file_node_all();
	destroy_table(hash_table);
	close(filter_map_fd);
	perf_buffer__free(pb); /* It will test if pb is null */
	iofsstat_bpf__destroy(bpf_obj);
	return ret != 0;
}

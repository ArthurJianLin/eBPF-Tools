/***************************************************************************************
*   DESCRIPTION : Source code of user mode for mmap ebpf tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2025-12-18 -- Guanbing Huang written
*****************************************************************************************/

#include <stdio.h>
#include "libbpf.h"
#include "mmap.h"
#include "mmap.skel.h"
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

#define RECORD_MMAP_FILE "./rd_mmap_data"
#define RECORD_MUNMAP_FILE "./rd_munmap_data"
FILE *fp_mmap = NULL;
FILE *fp_munmap = NULL;

struct prog_env {
	int enable;
	int pid;
	char comm[TASK_COMM_LEN];
};

static struct prog_env env = { 0 };


#define PERF_BUFFER_PAGES	128
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

// 二进制单位（1024进制）
static const char *const binary_units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
#define BINARY_BASE 1024


#define PROT_STR_SIZE   8
#define PROT_STR_LEN    5
#define MAP_STR_SIZE    8
#define MAP_STR_LEN     5

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

void prot_to_str(unsigned long prot, char *str)
{
	char *p;

	strncpy(str, "-----", PROT_STR_LEN);
	str[PROT_STR_LEN] = '\0';

	p = str;
	if (prot & PROT_READ) { /* page can be read */
		*p = 'R';
	}
	p++;

	if (prot & PROT_WRITE) { /* page can be written */
		*p = 'W';
	}
	p++;

	if (prot & PROT_EXEC) { /* page can be executed */
		*p = 'X';
	}
	p++;
}

static void map_to_str(unsigned long map, char *str)
{
	char *p;

	strncpy(str, "-----", MAP_STR_LEN);
	str[MAP_STR_LEN] = '\0';

	p = str;
	if (map & MAP_SHARED) {  /* Share changes */
		*p = 'S';
	}
	p++;

	if (map & MAP_PRIVATE) { /* Changes are private */
		*p = 'P';
	}
	p++;

	if (map & MAP_FIXED) {  /* Interpret addr exactly */
		*p = 'F';
	}
	p++;

	if (map & MAP_ANONYMOUS) { /* don't use a file */
		*p = 'A';
	}
	p++;
}

static int get_mmap_fd_path(pid_t pid, unsigned long fd, char *path, size_t path_sz)
{
        ssize_t ret;
        char proc_pid_fd[32] = { 0 };

        if (snprintf(proc_pid_fd, sizeof(proc_pid_fd), "/proc/%d/fd/%ld", pid, fd)
            >= sizeof(proc_pid_fd)) {
                return -1;
        }
        ret = readlink(proc_pid_fd, path, path_sz);
        if (ret < 0) {
                return -1;
        }
        if (ret >= path_sz) {
                return -1;
        }
        path[ret] = '\0';

        return 0;
}

static int64_t g_offset_ns = 0;
static int64_t calc_monotonic_offset_ns(void)
{
    struct timespec ts_real, ts_mono;
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);

    uint64_t real_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
    uint64_t mono_now_ns = (uint64_t)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec;

    return (int64_t)(real_now_ns - mono_now_ns);
}

static void format_time_ns(uint64_t ns, char *buf, size_t size)
{
    time_t sec = ns / 1000000000ULL;
    uint32_t remainder_ns = ns % 1000000000ULL;

    struct tm *tm_info = gmtime(&sec);
    if (!tm_info) {
        snprintf(buf, size, "gmtime_error");
        return;
    }

    snprintf(buf, size,
             "%04d%02d%02d %02d:%02d:%02d.%01u",
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1,
             tm_info->tm_mday,
             tm_info->tm_hour + 8,
             tm_info->tm_min,
             tm_info->tm_sec,
             remainder_ns / 1000);
}

static void handle_mmap_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct mmap_event *pe = data;
	char size_str[16] = { 0 };
	char prot_str[PROT_STR_SIZE] = { 0 };
	char map_str[MAP_STR_SIZE] = { 0 };
	char fd_path[256] = { 0 };
	char utc[128] = { 0 };

	uint64_t real_ts_ns = pe->time_ns + g_offset_ns;
	format_time_ns(real_ts_ns, utc, sizeof(utc));

	bytes_to_binary_size(pe->len, size_str, 16);

	prot_to_str(pe->prot, prot_str);

	map_to_str(pe->flags, map_str);

	get_mmap_fd_path(pe->pid, pe->fd, fd_path, 256);

	if ((env.enable & MMAP_ENV_RD_EN) == MMAP_ENV_RD_EN) {
		fprintf(fp_mmap, "%-30s %-8s %-8d %-16s 0x%-18lx %-16ld %-8s %-8s %-16ld %s\n",
			utc, "M", pe->pid, pe->comm, pe->addr, pe->len, prot_str, map_str, pe->offset, fd_path);
	} else {
		printf("%-30s %-8s %-8d %-16s 0x%-18lx %-16s %-8s %-8s %-16ld %s\n",
			utc, "M", pe->pid, pe->comm, pe->addr, size_str, prot_str, map_str, pe->offset, fd_path);
	}
}

static void handle_munmap_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct munmap_event *pe = data;
	char size_str[16] = { 0 };
	char prot_str[PROT_STR_SIZE] = { 0 };
	char map_str[MAP_STR_SIZE] = { 0 };
	char fd_path[256] = { 0 };
	char utc[128] = { 0 };

	uint64_t real_ts_ns = pe->time_ns + g_offset_ns;
	format_time_ns(real_ts_ns, utc, sizeof(utc));

	bytes_to_binary_size(pe->len, size_str, 16);

	if ((env.enable & MMAP_ENV_RD_EN) == MMAP_ENV_RD_EN) {
		fprintf(fp_munmap, "%-30s %-8s %-8d %-16s 0x%-18lx %-16ld\n", utc, "U", pe->pid, pe->comm, pe->addr, pe->len);
	} else {
		printf("%-30s %-8s %-8d %-16s 0x%-18lx %-16s\n", utc, "U", pe->pid, pe->comm, pe->addr, size_str);
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	unsigned int *pt = (unsigned int*)data;

	if (*pt == EVENT_TYPE_MMAP) {
		handle_mmap_event(ctx, cpu, data, size);
	} else if (*pt == EVENT_TYPE_MUNMAP) {
		handle_munmap_event(ctx, cpu, data, size);
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
	{"process", 'p', "PID",  0,             "Only aim pid",    0},
	{"process", 'c', "COMM", 0,             "Only aim comm",   0},
	{"record",  'r', NULL,   OPTION_HIDDEN, "Only aim record", 0},
	{NULL,      'h', NULL,   OPTION_HIDDEN, "Show full help",  0},
	{},
};

const char program_doc[] =
"Trace the mmap of process.\n"
"\n"
"USAGE: ./mmap [-h] [-p PID] [ -c COMM] [-r]\n"
"\n";

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;

	switch (key) {
	case 'p':
		env->pid = strtol(arg, NULL, 10);
		if (env->pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env->enable = env->enable | MMAP_ENV_PID_EN;
		break;
	case 'c':
		int len = strlen(arg);
		len = len < TASK_COMM_LEN ? len : (TASK_COMM_LEN - 1);
		strncpy(env->comm, arg, len);
		env->comm[len] = '\0';
		env->enable = env->enable | MMAP_ENV_COMM_EN;
		break;
	case 'r':
		env->enable = env->enable | MMAP_ENV_RD_EN;
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

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct mmap_bpf *bpf_obj = NULL;  /* struct mmap_bpf is auto-generated */
	int map_fd;
	int ret;
	__u32 key;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (ret != 0) {
		return ret;
	}

	bump_memlock_rlimit();

	bpf_obj = mmap_bpf__open();
	if (bpf_obj == NULL) {
		fprintf(stderr, "Failed to open BPF object!\n");
		return 1;
	}

	ret = mmap_bpf__load(bpf_obj);
	if (ret != 0) {
		fprintf(stderr, "Failed to load BPF object: %d\n", ret);
		goto clean_up;
	}

	map_fd = bpf_map__fd(bpf_obj->maps.filter_enable_map);
	key = 0;
	ret = bpf_map_update_elem(map_fd, &key, &env.enable, BPF_ANY);
	if (ret != 0) {
		fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
		goto clean_up;
	}

	if ((env.enable & MMAP_ENV_RD_EN) == MMAP_ENV_RD_EN) {
		fp_mmap =fopen(RECORD_MMAP_FILE, "w");
		if (fp_mmap == NULL) {
			fprintf(stderr, "Failed to open file: %s\n", RECORD_MMAP_FILE);
			goto clean_up;
		}

		fp_munmap =fopen(RECORD_MUNMAP_FILE, "w");
		if (fp_munmap == NULL) {
			fprintf(stderr, "Failed to open file: %s\n", RECORD_MUNMAP_FILE);
			goto clean_up;
		}
	}

	if ((env.enable & MMAP_ENV_COMM_EN) == MMAP_ENV_COMM_EN) {
		map_fd = bpf_map__fd(bpf_obj->maps.comm_map);
		key = 0;
		printf("comm = %s\n", env.comm);
		ret = bpf_map_update_elem(map_fd, &key, env.comm, BPF_ANY);
		if (ret != 0) {
			fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
			goto clean_up;
		}
	}

	if ((env.enable & MMAP_ENV_PID_EN) == MMAP_ENV_PID_EN) {
		map_fd = bpf_map__fd(bpf_obj->maps.pid_map);
		key = env.pid;
		printf("pid = %d\n", env.pid);
		ret = bpf_map_update_elem(map_fd, &key, &env.pid, BPF_ANY);
		if (ret != 0) {
			fprintf(stderr, "Failed to update BPF elem: %d\n", ret);
			goto clean_up;
		}
	}
	bpf_obj->links.mmap_entry = bpf_program__attach_tracepoint(bpf_obj->progs.mmap_entry, "syscalls", "sys_enter_mmap");
	bpf_obj->links.mmap_exit = bpf_program__attach_tracepoint(bpf_obj->progs.mmap_exit, "syscalls", "sys_exit_mmap");
	bpf_obj->links.munmap_entry = bpf_program__attach_tracepoint(bpf_obj->progs.munmap_entry, "syscalls", "sys_enter_munmap");
	g_offset_ns = calc_monotonic_offset_ns();

	printf("Tracing process ... Hit Ctrl-C to end.\n");

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

	printf("%-30s %-8s %-8s %-16s %-18s   %-16s %-8s %-8s %-16s %s\n", "TIME", "TYPE", "PID", "COMM", "ADDR", "SIZE", "PROT", "MAP", "OFFSET", "FILE");
	while (!exiting) {
		ret = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-ret));
			goto clean_up;
		}
		/* reset ret to return 0 if exiting */
		ret = 0;
	}

clean_up:
	perf_buffer__free(pb); /* It will test if pb is null */
	mmap_bpf__destroy(bpf_obj);
	if (fp_mmap != NULL) {
		fclose(fp_mmap);
		fp_mmap = NULL;
	}

	if (fp_munmap != NULL) {
		fclose(fp_munmap);
		fp_munmap = NULL;
	}

	return ret != 0;
}

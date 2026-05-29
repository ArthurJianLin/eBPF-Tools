// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * kvmmon: KVM exit→entry latency histogram (+ optional long-tail stacks).
 */
#define _GNU_SOURCE
#include <argp.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>

#include "bpf.h"
#include "kvmmon.h"
#include "kvmmon.skel.h"
#include "libbpf.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_POLL_MS		100
#define PERF_MAX_STACK_DEPTH	127
#define BAR_WIDTH		20

static volatile sig_atomic_t exiting;

struct a_mon_entry {
	pid_t tgid;
	char uuid[72];
};

struct a_log_ctx {
	struct a_mon_entry ent[KVMMON_MAX_MONITORED];
	size_t n;
};

struct mon_ctx {
	FILE *out; /* -p single-target log */
	struct a_log_ctx *a; /* reserved; NULL for -p */
	struct kvmmon_bpf *obj;
	struct ksyms *ksyms;
};

static FILE *mon_out_for_tgid(struct mon_ctx *m, __u32 tgid)
{
	if (!m->a)
		return m->out;
	(void)tgid;
	return stderr;
}

/* argp keys for long-only options */
#define ARGP_KEY_SCAN_INTERVAL	30001
#define ARGP_KEY_PROM_PATH	30002

static struct globals {
	bool have_pid;
	pid_t qemu_tgid;
	int interval_s; /* histogram print period */
	int scan_interval_s; /* -a only: /proc rescan period */
	/* 0 = histogram only; >0 = emit kernel stack when latency >= this (ns) */
	unsigned long long stack_thresh_ns;
	bool all_qemu;
	char *out_path; /* strdup; -p only: append stdout to this file */
	char *prom_path; /* strdup; -a: node_exporter textfile path (default below) */
} gl;

static void sig_int(int signo)
{
	(void)signo;
	exiting = 1;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
		fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK\n");
}

/*
 * Redirected FILE* (file or pipe) is fully buffered by default, so tail -f and
 * readers see nothing until the buffer fills or the process exits.
 */
static void log_stream_linebuf(FILE *fp)
{
	if (!fp)
		return;
	if (setvbuf(fp, NULL, _IOLBF, 0) != 0)
		perror("setvbuf");
}

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "QEMU process (thread group) PID", 0 },
	{ "all-qemu", 'a', 0, 0,
	  "One BPF program: whitelist QEMU TGIDs in a map (see --scan-interval). "
	  "Exports a Prometheus histogram textfile (see --prom) on each -i interval. "
	  "Cannot be used with -p, -o, or -s.",
	  0 },
	{ "output", 'o', "PATH", 0,
	  "With -p only: append stdout to this file.",
	  0 },
	{ "interval", 'i', "SEC", 0,
	  "Histogram print period in seconds (default 120).",
	  0 },
	{ "scan-interval", ARGP_KEY_SCAN_INTERVAL, "SEC", 0,
	  "With -a: seconds between /proc QEMU rescan passes (default 300).",
	  0 },
	{ "prom", ARGP_KEY_PROM_PATH, "PATH", 0,
	  "With -a: final path for node_exporter textfile metrics "
	  "(written to PATH.tmp then renamed; default "
	  "/app/monitor/prom/vm_latency.prom).",
	  0 },
	{ "stack", 's', "NS", 0,
	  "With -p only: long-tail threshold in nanoseconds; 0 = histogram only (default 0). "
	  "Example: 5000 = 5µs → emit kernel stack when latency >= threshold",
	  0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, NULL, 0 },
	{},
};

static const char doc[] =
	"KVM vmexit→vmentry latency monitor (histogram + optional stacks).\n"
	"\n"
	"Histogram counts only exits handled entirely in the host kernel: if KVM\n"
	"returns to QEMU userspace, kvm_userspace_exit clears the pending exit so the\n"
	"next kvm_entry is not paired with a stale timestamp (avoids false multi-ms\n"
	"tails). Compare with perf using timestamps in the same unit (perf script\n"
	"'time' is often seconds — multiply delta by 1e9 before comparing to ns).\n"
	"\n"
	"Example:\n"
	"  kvmmon -p $(pidof qemu-system-x86_64)\n"
	"  kvmmon -p 12345 -i 60 -s 5000\n"
	"  kvmmon -p 12345 -o /var/log/kvm-one.log\n"
	"  kvmmon -a --scan-interval 60 --prom /app/monitor/prom/vm_latency.prom\n";

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	(void)state;

	switch (key) {
	case 'a':
		gl.all_qemu = true;
		break;
	case 'o':
		if (gl.out_path) {
			free(gl.out_path);
			gl.out_path = NULL;
		}
		if (!arg || !*arg) {
			fprintf(stderr, "-o requires a non-empty path\n");
			return EINVAL;
		}
		gl.out_path = strdup(arg);
		if (!gl.out_path) {
			perror("strdup -o");
			return ENOMEM;
		}
		break;
	case 'p': {
		errno = 0;
		long v = strtol(arg, NULL, 10);

		if (errno || v <= 0 || v > INT_MAX) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			return EINVAL;
		}
		gl.qemu_tgid = (pid_t)v;
		gl.have_pid = true;
		break;
	}
	case 'i': {
		errno = 0;
		long v = strtol(arg, NULL, 10);

		if (errno || v <= 0 || v > 86400) {
			fprintf(stderr, "invalid interval: %s (use 1..86400)\n", arg);
			return EINVAL;
		}
		gl.interval_s = (int)v;
		break;
	}
	case ARGP_KEY_SCAN_INTERVAL: {
		errno = 0;
		long v = strtol(arg, NULL, 10);

		if (errno || v <= 0 || v > 86400) {
			fprintf(stderr, "invalid --scan-interval: %s (use 1..86400)\n", arg);
			return EINVAL;
		}
		gl.scan_interval_s = (int)v;
		break;
	}
	case ARGP_KEY_PROM_PATH: {
		if (gl.prom_path) {
			free(gl.prom_path);
			gl.prom_path = NULL;
		}
		if (!arg || !*arg) {
			fprintf(stderr, "--prom requires a non-empty path\n");
			return EINVAL;
		}
		gl.prom_path = strdup(arg);
		if (!gl.prom_path) {
			perror("strdup --prom");
			return ENOMEM;
		}
		break;
	}
	case 's': {
		errno = 0;
		unsigned long long v = strtoull(arg, NULL, 10);

		if (errno) {
			fprintf(stderr, "invalid -s value: %s\n", arg);
			return EINVAL;
		}
		gl.stack_thresh_ns = v;
		break;
	}
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* VMX basic exit reason = trace exit_reason & 0xffff (arch/x86/include/uapi/asm/vmx.h). */
static const char *vmx_basic_name(unsigned b)
{
	switch (b) {
	case 0:
		return "EXCEPTION_NMI";
	case 1:
		return "EXTERNAL_INTERRUPT";
	case 2:
		return "TRIPLE_FAULT";
	case 3:
		return "INIT_SIGNAL";
	case 4:
		return "SIPI_SIGNAL";
	case 6:
		return "OTHER_SMI";
	case 7:
		return "INTERRUPT_WINDOW";
	case 8:
		return "NMI_WINDOW";
	case 9:
		return "TASK_SWITCH";
	case 10:
		return "CPUID";
	case 12:
		return "HLT";
	case 13:
		return "INVD";
	case 14:
		return "INVLPG";
	case 15:
		return "RDPMC";
	case 16:
		return "RDTSC";
	case 18:
		return "VMCALL";
	case 19:
		return "VMCLEAR";
	case 20:
		return "VMLAUNCH";
	case 21:
		return "VMPTRLD";
	case 22:
		return "VMPTRST";
	case 23:
		return "VMREAD";
	case 24:
		return "VMRESUME";
	case 25:
		return "VMWRITE";
	case 26:
		return "VMOFF";
	case 27:
		return "VMON";
	case 28:
		return "CR_ACCESS";
	case 29:
		return "DR_ACCESS";
	case 30:
		return "IO_INSTRUCTION";
	case 31:
		return "MSR_READ";
	case 32:
		return "MSR_WRITE";
	case 33:
		return "INVALID_STATE";
	case 34:
		return "MSR_LOAD_FAIL";
	case 36:
		return "MWAIT_INSTRUCTION";
	case 37:
		return "MONITOR_TRAP_FLAG";
	case 39:
		return "MONITOR_INSTRUCTION";
	case 40:
		return "PAUSE_INSTRUCTION";
	case 41:
		return "MCE_DURING_VMENTRY";
	case 43:
		return "TPR_BELOW_THRESHOLD";
	case 44:
		return "APIC_ACCESS";
	case 45:
		return "EOI_INDUCED";
	case 46:
		return "GDTR_IDTR";
	case 47:
		return "LDTR_TR";
	case 48:
		return "EPT_VIOLATION";
	case 49:
		return "EPT_MISCONFIG";
	case 50:
		return "INVEPT";
	case 51:
		return "RDTSCP";
	case 52:
		return "PREEMPTION_TIMER";
	case 53:
		return "INVVPID";
	case 54:
		return "WBINVD";
	case 55:
		return "XSETBV";
	case 56:
		return "APIC_WRITE";
	case 57:
		return "RDRAND";
	case 58:
		return "INVPCID";
	case 59:
		return "VMFUNC";
	case 60:
		return "ENCLS";
	case 61:
		return "RDSEED";
	case 62:
		return "PML_FULL";
	case 63:
		return "XSAVES";
	case 64:
		return "XRSTORS";
	case 67:
		return "UMWAIT";
	case 68:
		return "TPAUSE";
	case 74:
		return "BUS_LOCK";
	case 75:
		return "NOTIFY";
	case 76:
		return "SEAMCALL";
	case 77:
		return "TDCALL";
	case 84:
		return "MSR_READ_IMM";
	case 85:
		return "MSR_WRITE_IMM";
	default:
		return NULL;
	}
}

static void format_kvm_exit_reason(char *buf, size_t len, __u32 reason, __u32 isa)
{
	unsigned base;
	unsigned high;

	if (isa == KVM_ISA_VMX) {
		base = reason & 0xffffu;
		high = reason >> 16;
		{
			const char *n = vmx_basic_name(base);

			if (n && high == 0)
				snprintf(buf, len, "%s", n);
			else if (n && high != 0)
				snprintf(buf, len, "%s|hi=0x%x", n, high);
			else if (!n && high == 0)
				snprintf(buf, len, "VMX_%u", base);
			else
				snprintf(buf, len, "VMX_%u|hi=0x%x", base, high);
		}
		return;
	}
	if (isa == KVM_ISA_SVM) {
		snprintf(buf, len, "SVM_0x%x", reason);
		return;
	}
	snprintf(buf, len, "ISA%u_raw=0x%x", isa, reason);
}

static unsigned long long hist_total(const struct kvm_hist *h)
{
	unsigned long long t = 0;
	int i;

	for (i = 0; i < KVM_HIST_SLOTS; i++)
		t += h->slots[i];
	return t;
}

static const char *hist_labels[KVM_HIST_SLOTS] = {
	"[0 - 64 us]     ",
	"[64 - 128 us]   ",
	"[128 - 256 us]  ",
	"[256 - 512 us]  ",
	"[512 - 1024 us] ",
	">= 1024 us      ",
};

static const char *p99_bucket_label(const struct kvm_hist *h,
				    unsigned long long total)
{
	unsigned long long need, cum;
	int i;

	if (!total)
		return "N/A";
	need = (total * 99ULL + 99ULL) / 100ULL;
	if (need == 0)
		need = 1;
	cum = 0;
	for (i = 0; i < KVM_HIST_SLOTS; i++) {
		cum += h->slots[i];
		if (cum >= need)
			return hist_labels[i];
	}
	return hist_labels[KVM_HIST_SLOTS - 1];
}

static void print_bar(char *out, size_t olen, unsigned long long val,
		      unsigned long long vmax)
{
	unsigned n, i;

	if (!vmax || !val) {
		if (olen)
			out[0] = '\0';
		return;
	}
	n = (unsigned)((double)val / (double)vmax * (double)BAR_WIDTH);
	if (n > BAR_WIDTH)
		n = BAR_WIDTH;
	for (i = 0; i < n && i + 1 < olen; i++)
		out[i] = '#';
	out[i] = '\0';
}

static void print_histogram(FILE *out, int hfd, __u32 tgid)
{
	struct kvm_hist h, z = {};
	unsigned long long total, mx = 0;
	int i, err;
	char bar[BAR_WIDTH + 4];

	err = bpf_map_lookup_elem(hfd, &tgid, &h);
	if (err) {
		fprintf(out,
			"--- Latency Distribution (KVM overhead, HLT excluded) ---\n"
			"(no samples)\n");
		return;
	}

	total = hist_total(&h);
	for (i = 0; i < KVM_HIST_SLOTS; i++)
		if (h.slots[i] > mx)
			mx = h.slots[i];

	fprintf(out, "--- Latency Distribution (KVM overhead, HLT excluded) ---\n");
	for (i = 0; i < KVM_HIST_SLOTS; i++) {
		print_bar(bar, sizeof(bar), h.slots[i], mx);
		fprintf(out, "  %s : %s %" PRIu32 "\n", hist_labels[i], bar,
			h.slots[i]);
	}
	fprintf(out, "  total: %llu   ~p99 bucket: %s\n", total,
		p99_bucket_label(&h, total));

	bpf_map_update_elem(hfd, &tgid, &z, BPF_ANY);
}

static void print_wall_ms(FILE *out)
{
	struct timeval tv;
	struct tm tm_buf;

	gettimeofday(&tv, NULL);
	if (!localtime_r(&tv.tv_sec, &tm_buf)) {
		fprintf(out, "?.?.?");
		return;
	}
	fprintf(out, "%02d:%02d:%02d.%03ld", tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
		(long)tv.tv_usec / 1000L);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct mon_ctx *m = ctx;
	const struct kvm_long_event *e = data;
	unsigned long *stack;
	int i, stack_fd;
	long offset;
	const struct ksym *ksym;
	char reason[128];

	(void)cpu;
	if (!m || data_sz < sizeof(*e))
		return;

	{
	FILE *of = mon_out_for_tgid(m, e->tgid);

	format_kvm_exit_reason(reason, sizeof(reason), e->exit_reason, e->isa);

	print_wall_ms(of);
	fprintf(of, " | tid=%u | lat=%" PRIu64 " ns | reason=%s | stack:\n",
		(unsigned)e->tid, (uint64_t)e->latency_ns, reason);

	if ((int)e->stack_id < 0) {
		fprintf(of, "    (stack unavailable, id=%d)\n", e->stack_id);
		return;
	}

	stack = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stack));
	if (!stack)
		return;
	stack_fd = bpf_map__fd(m->obj->maps.stack_traces);
	if (bpf_map_lookup_elem(stack_fd, &e->stack_id, stack) != 0) {
		fprintf(of, "    (missed kernel stack)\n");
		free(stack);
		return;
	}
	for (i = 0; i < PERF_MAX_STACK_DEPTH && stack[i]; i++) {
		ksym = ksyms__map_addr(m->ksyms, stack[i]);
		if (ksym) {
			offset = (long)(stack[i] - ksym->addr);
			fprintf(of, "    %s+%ld\n", ksym->name, offset);
		} else {
			fprintf(of, "    0x%lx\n", stack[i]);
		}
	}
	free(stack);
	}
}

static void handle_lost(void *ctx, int cpu, __u64 lost)
{
	struct mon_ctx *m = ctx;

	if (m && m->a) {
		fprintf(stderr, "lost %llu events on cpu %d\n",
			(unsigned long long)lost, cpu);
	} else if (m && m->out) {
		fprintf(m->out, "lost %llu events on cpu %d\n",
			(unsigned long long)lost, cpu);
	} else {
		fprintf(stderr, "lost %llu events on cpu %d\n",
			(unsigned long long)lost, cpu);
	}
}

static int run_one_qemu_session(pid_t qemu_tgid, int interval_s,
				unsigned long long stack_thresh_ns, FILE *out,
				volatile sig_atomic_t *stop_req)
{
#define KVMMON_SHOULD_STOP() \
	(exiting || (stop_req && *stop_req))
	struct kvmmon_bpf *obj = NULL;
	struct ksyms *ksyms = NULL;
	struct perf_buffer *pb = NULL;
	struct mon_ctx mctx = { .out = out, .a = NULL, .obj = NULL, .ksyms = NULL };
	int err = 0;
	__u32 k0 = 0;
	__u32 tgid_u;
	__u8 mon_one = 1;
	__u64 sth;
	int hfd, mfd;
	struct timespec sleep_chunk = { 0, 100000000L };
	int ticks, i;
	const int chunks_per_sec =
		(int)(1000000000LL / (long long)sleep_chunk.tv_nsec);

	log_stream_linebuf(out);

	obj = kvmmon_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open/load BPF skeleton (tgid %d)\n",
			(int)qemu_tgid);
		return 1;
	}
	mctx.obj = obj;

	tgid_u = (__u32)qemu_tgid;
	mfd = bpf_map__fd(obj->maps.monitored_tgids);
	if (bpf_map_update_elem(mfd, &tgid_u, &mon_one, BPF_ANY)) {
		perror("monitored_tgids");
		err = 1;
		goto cleanup;
	}
	sth = (__u64)stack_thresh_ns;
	mfd = bpf_map__fd(obj->maps.stack_thresh_map);
	if (bpf_map_update_elem(mfd, &k0, &sth, BPF_ANY)) {
		perror("stack_thresh_map");
		err = 1;
		goto cleanup;
	}

	obj->links.tp_kvm_exit = bpf_program__attach_tracepoint(
		obj->progs.tp_kvm_exit, "kvm", "kvm_exit");
	if (!obj->links.tp_kvm_exit) {
		fprintf(stderr, "attach kvm:kvm_exit failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	obj->links.tp_kvm_userspace_exit = bpf_program__attach_tracepoint(
		obj->progs.tp_kvm_userspace_exit, "kvm", "kvm_userspace_exit");
	if (!obj->links.tp_kvm_userspace_exit) {
		fprintf(stderr, "attach kvm:kvm_userspace_exit failed: %s\n",
			strerror(errno));
		err = 1;
		goto cleanup;
	}
	obj->links.tp_kvm_entry = bpf_program__attach_tracepoint(
		obj->progs.tp_kvm_entry, "kvm", "kvm_entry");
	if (!obj->links.tp_kvm_entry) {
		fprintf(stderr, "attach kvm:kvm_entry failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (stack_thresh_ns > 0) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "failed to load /proc/kallsyms\n");
			err = 1;
			goto cleanup;
		}
		mctx.ksyms = ksyms;
		pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_buf),
				      PERF_BUFFER_PAGES, handle_event, handle_lost,
				      &mctx, NULL);
		if (!pb) {
			fprintf(stderr, "perf_buffer__new failed\n");
			err = 1;
			goto cleanup;
		}
	}

	hfd = bpf_map__fd(obj->maps.hists);

	while (!KVMMON_SHOULD_STOP()) {
		time_t t = time(NULL);
		struct tm tm_buf;
		char hdr[64];

		if (localtime_r(&t, &tm_buf))
			strftime(hdr, sizeof(hdr), "[%Y-%m-%d %H:%M:%S]", &tm_buf);
		else
			snprintf(hdr, sizeof(hdr), "[?]");
		fprintf(out, "%s QEMU PID: %d | Interval: %ds\n", hdr, (int)qemu_tgid,
			interval_s);

		print_histogram(out, hfd, tgid_u);

		if (stack_thresh_ns > 0) {
			fprintf(out, "\n--- Long-tail events (>=%llu ns) ---\n",
				(unsigned long long)stack_thresh_ns);
		} else {
			fprintf(out, "\n");
		}

		ticks = interval_s * chunks_per_sec;
		if (ticks < 1)
			ticks = 1;
		for (i = 0; i < ticks && !KVMMON_SHOULD_STOP(); i++) {
			if (pb)
				perf_buffer__poll(pb, PERF_POLL_MS);
			else
				nanosleep(&sleep_chunk, NULL);
		}
		fflush(out);
	}
#undef KVMMON_SHOULD_STOP

cleanup:
	if (obj) {
		mfd = bpf_map__fd(obj->maps.monitored_tgids);
		hfd = bpf_map__fd(obj->maps.hists);
		bpf_map_delete_elem(mfd, &tgid_u);
		bpf_map_delete_elem(hfd, &tgid_u);
	}
	perf_buffer__free(pb);
	kvmmon_bpf__destroy(obj);
	ksyms__free(ksyms);
	return err;
}

static int a_log_find_idx(struct a_log_ctx *a, pid_t t)
{
	size_t i;

	for (i = 0; i < a->n; i++) {
		if (a->ent[i].tgid == t)
			return (int)i;
	}
	return -1;
}

static size_t prom_escape_label_value(const char *in, char *out, size_t olen)
{
	const char *p;
	char *q = out;
	char *qend = out + (olen > 0 ? olen - 1 : 0);

	if (!olen) {
		return 0;
	}
	for (p = in; *p && q < qend; p++) {
		if (*p == '\\') {
			if (q + 2 > qend)
				break;
			*q++ = '\\';
			*q++ = '\\';
		} else if (*p == '"') {
			if (q + 2 > qend)
				break;
			*q++ = '\\';
			*q++ = '"';
		} else if (*p == '\n') {
			if (q + 2 > qend)
				break;
			*q++ = '\\';
			*q++ = 'n';
		} else {
			*q++ = *p;
		}
	}
	*q = '\0';
	return (size_t)(q - out);
}

static int read_proc_cmdline_flat(pid_t pid, char *buf, size_t buflen)
{
	char path[64];
	int fd;
	ssize_t n;
	size_t i;

	if (buflen < 2)
		return -1;
	snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, buflen - 1);
	close(fd);
	if (n <= 0)
		return -1;
	for (i = 0; i < (size_t)n; i++) {
		if (buf[i] == '\0')
			buf[i] = ' ';
	}
	buf[n] = '\0';
	return 0;
}

static void extract_uuid_from_cmdline(const char *cmdline, char *uuid_out,
				      size_t ulo)
{
	const char *p = strstr(cmdline, "uuid=");
	size_t j;

	uuid_out[0] = '\0';
	if (!p)
		return;
	p += 5;
	j = 0;
	while (*p && j + 1 < ulo) {
		if (*p == ',' || *p == ' ' || *p == '\t')
			break;
		uuid_out[j++] = *p++;
	}
	uuid_out[j] = '\0';
}

static void fill_mon_entry_from_proc(struct a_mon_entry *e, pid_t tgid)
{
	char cmdline[4096];

	e->tgid = tgid;
	e->uuid[0] = '\0';
	if (read_proc_cmdline_flat(tgid, cmdline, sizeof(cmdline)) == 0)
		extract_uuid_from_cmdline(cmdline, e->uuid, sizeof(e->uuid));
}

static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	size_t len;
	char *p;

	len = strnlen(path, sizeof(tmp) - 1);
	if (len == 0)
		return -1;
	memcpy(tmp, path, len);
	tmp[len] = '\0';
	if (len > 1 && tmp[len - 1] == '/')
		tmp[len - 1] = '\0';
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (tmp[0] && mkdir(tmp, mode) != 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}
	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

static int write_kvm_latency_prom_textfile(const char *final_path, int hfd,
					   struct a_log_ctx *a)
{
	char tmp_path[PATH_MAX];
	char path_parent[PATH_MAX];
	FILE *fp;
	size_t i, flen;
	int ret = 0;

	flen = strlen(final_path);
	if (flen + 5 >= sizeof(tmp_path)) {
		fprintf(stderr, "kvmmon: --prom path too long\n");
		return -1;
	}
	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

	if (strlen(final_path) + 1 > sizeof(path_parent)) {
		fprintf(stderr, "kvmmon: --prom path too long for dirname\n");
		return -1;
	}
	memcpy(path_parent, final_path, strlen(final_path) + 1);
	{
		char *dp = dirname(path_parent);

		if (dp && dp[0] && strcmp(dp, ".") != 0 && mkdir_p(dp, 0755) != 0)
			fprintf(stderr,
				"kvmmon: warning: could not mkdir %s: %s\n",
				dp, strerror(errno));
	}

	fp = fopen(tmp_path, "w");
	if (!fp) {
		perror(tmp_path);
		return -1;
	}

	fprintf(fp,
		"# HELP kvm_exit_latency_us KVM exit→entry latency histogram; "
		"bucket le= upper bounds in microseconds; counts cumulative. "
		"_sum is total latency in microseconds (same truncation as buckets). "
		"_count is omitted.\n");
	fprintf(fp, "# TYPE kvm_exit_latency_us histogram\n\n");

	for (i = 0; i < a->n; i++) {
		struct kvm_hist h;
		__u32 tg = (__u32)a->ent[i].tgid;
		unsigned long long s0, s1, s2, s3, s4, s5;
		unsigned long long b64, b128, b256, b512, b1024, binf;
		char uuid_esc[160];
		const char *uuid_raw =
		    a->ent[i].uuid[0] ? a->ent[i].uuid : "unknown";

		if (bpf_map_lookup_elem(hfd, &tg, &h) != 0)
			memset(&h, 0, sizeof(h));

		s0 = h.slots[0];
		s1 = h.slots[1];
		s2 = h.slots[2];
		s3 = h.slots[3];
		s4 = h.slots[4];
		s5 = h.slots[5];
		b64 = s0;
		b128 = b64 + s1;
		b256 = b128 + s2;
		b512 = b256 + s3;
		b1024 = b512 + s4;
		binf = b1024 + s5;

		prom_escape_label_value(uuid_raw, uuid_esc, sizeof(uuid_esc));

		fprintf(fp,
			"kvm_exit_latency_us_bucket{vm_uuid=\"%s\",le=\"64\"} %llu\n",
			uuid_esc, b64);
		fprintf(fp,
			"kvm_exit_latency_us_bucket{vm_uuid=\"%s\",le=\"128\"} %llu\n",
			uuid_esc, b128);
		fprintf(fp,
			"kvm_exit_latency_us_bucket{vm_uuid=\"%s\",le=\"256\"} %llu\n",
			uuid_esc, b256);
		fprintf(fp,
			"kvm_exit_latency_us_bucket{vm_uuid=\"%s\",le=\"512\"} %llu\n",
			uuid_esc, b512);
		fprintf(fp,
			"kvm_exit_latency_us_bucket{vm_uuid=\"%s\",le=\"1024\"} %llu\n",
			uuid_esc, b1024);
		fprintf(fp,
			"kvm_exit_latency_us_bucket{vm_uuid=\"%s\",le=\"+Inf\"} %llu\n",
			uuid_esc, binf);
		fprintf(fp,
			"kvm_exit_latency_us_sum{vm_uuid=\"%s\"} %" PRIu64 "\n",
			uuid_esc, (uint64_t)h.sum_us);
		fprintf(fp, "\n");
	}

	if (fflush(fp) != 0) {
		perror("fflush prom tmp");
		ret = -1;
	}
	if (fclose(fp) != 0) {
		perror("fclose prom tmp");
		ret = -1;
	}
	if (ret == 0 && rename(tmp_path, final_path) != 0) {
		perror("rename prom tmp to final");
		ret = -1;
	}
	if (ret != 0)
		(void)unlink(tmp_path);
	return ret;
}

static int read_proc_tgid(pid_t pid, pid_t *tgid_out)
{
	char path[64];
	FILE *f;
	char line[256];

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Tgid:", 5) == 0) {
			if (sscanf(line + 5, " %d", tgid_out) != 1) {
				fclose(f);
				return -1;
			}
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static int comm_has_qemu(const char *comm)
{
	char buf[32];
	size_t i, j;

	for (i = 0, j = 0; comm[i] && j + 1 < sizeof(buf); i++) {
		if (comm[i] == '\n')
			break;
		buf[j++] = (char)tolower((unsigned char)comm[i]);
	}
	buf[j] = '\0';
	return strstr(buf, "qemu") != NULL;
}

static int pid_in_list(const pid_t *arr, size_t n, pid_t p)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (arr[i] == p)
			return 1;
	}
	return 0;
}

static int collect_qemu_tgids(pid_t *out, size_t out_max, size_t *n_out)
{
	DIR *d;
	struct dirent *de;
	size_t n = 0;

	*n_out = 0;
	d = opendir("/proc");
	if (!d) {
		perror("opendir /proc");
		return -1;
	}
	while ((de = readdir(d)) != NULL) {
		pid_t pid, tgid;
		char path[64];
		FILE *f;
		char comm[32];
		char *endp;
		long v;

		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		errno = 0;
		v = strtol(de->d_name, &endp, 10);
		if (errno || *endp != '\0' || v <= 0 || v > INT_MAX)
			continue;
		pid = (pid_t)v;
		if (read_proc_tgid(pid, &tgid) != 0)
			continue;
		if (pid != tgid)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (!fgets(comm, sizeof(comm), f)) {
			fclose(f);
			continue;
		}
		fclose(f);
		if (!comm_has_qemu(comm))
			continue;
		if (pid_in_list(out, n, pid))
			continue;
		if (n >= out_max)
			break;
		out[n++] = pid;
	}
	closedir(d);
	*n_out = n;
	return 0;
}

/*
 * -a: one BPF object, monitored_tgids map = whitelist; per-tgid hists map.
 * Scan /proc on --scan-interval; diff adds/deletes map keys.
 * On each -i interval, write Prometheus textfile to gl.prom_path (.tmp + rename).
 */
static int run_all_qemu_map_mode(void)
{
	struct kvmmon_bpf *obj = NULL;
	struct a_log_ctx alog = {};
	int err = 0;
	__u32 k0 = 0;
	__u64 sth = 0;
	int hfd, mfd, monfd;
	struct timespec sleep_chunk = { 0, 100000000L };
	int i;
	time_t next_scan, next_print, now;
	pid_t cur[KVMMON_MAX_MONITORED];
	size_t ncur;
	size_t j;

	if (!gl.prom_path) {
		fprintf(stderr, "internal error: -a without prom path\n");
		return 1;
	}

	bump_memlock_rlimit();

	exiting = 0;
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		perror("signal SIGINT");
		return 1;
	}
	if (signal(SIGTERM, sig_int) == SIG_ERR) {
		perror("signal SIGTERM");
		return 1;
	}

	fprintf(stderr,
		"kvmmon: -a single-BPF mode: prom export every %ds to %s, /proc scan every %ds; "
		"Ctrl+C stops.\n",
		gl.interval_s, gl.prom_path, gl.scan_interval_s);

	obj = kvmmon_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open/load BPF skeleton\n");
		return 1;
	}
	mfd = bpf_map__fd(obj->maps.stack_thresh_map);
	if (bpf_map_update_elem(mfd, &k0, &sth, BPF_ANY)) {
		perror("stack_thresh_map");
		err = 1;
		goto cleanup_a;
	}

	obj->links.tp_kvm_exit = bpf_program__attach_tracepoint(
		obj->progs.tp_kvm_exit, "kvm", "kvm_exit");
	if (!obj->links.tp_kvm_exit) {
		fprintf(stderr, "attach kvm:kvm_exit failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup_a;
	}
	obj->links.tp_kvm_userspace_exit = bpf_program__attach_tracepoint(
		obj->progs.tp_kvm_userspace_exit, "kvm", "kvm_userspace_exit");
	if (!obj->links.tp_kvm_userspace_exit) {
		fprintf(stderr, "attach kvm:kvm_userspace_exit failed: %s\n",
			strerror(errno));
		err = 1;
		goto cleanup_a;
	}
	obj->links.tp_kvm_entry = bpf_program__attach_tracepoint(
		obj->progs.tp_kvm_entry, "kvm", "kvm_entry");
	if (!obj->links.tp_kvm_entry) {
		fprintf(stderr, "attach kvm:kvm_entry failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup_a;
	}

	hfd = bpf_map__fd(obj->maps.hists);
	monfd = bpf_map__fd(obj->maps.monitored_tgids);

	next_scan = time(NULL);
	next_print = time(NULL);

	while (!exiting) {
		now = time(NULL);

		if (now >= next_scan) {
			if (collect_qemu_tgids(cur, KVMMON_MAX_MONITORED, &ncur) != 0) {
				err = 1;
				break;
			}

			for (i = 0; i < (int)alog.n;) {
				if (pid_in_list(cur, ncur, alog.ent[i].tgid)) {
					i++;
					continue;
				}
				{
					__u32 tg = (__u32)alog.ent[i].tgid;

					bpf_map_delete_elem(hfd, &tg);
					bpf_map_delete_elem(monfd, &tg);
					memmove(&alog.ent[i], &alog.ent[i + 1],
						(alog.n - (size_t)i - 1) *
						    sizeof(alog.ent[0]));
					alog.n--;
				}
			}

			for (j = 0; j < ncur; j++) {
				pid_t p = cur[j];
				__u32 tgu = (__u32)p;
				__u8 one = 1;

				if (a_log_find_idx(&alog, p) >= 0)
					continue;
				if (alog.n >= KVMMON_MAX_MONITORED) {
					fprintf(stderr,
						"kvmmon: max %d QEMU TGIDs in whitelist\n",
						KVMMON_MAX_MONITORED);
					break;
				}
				if (bpf_map_update_elem(monfd, &tgu, &one, BPF_ANY)) {
					perror("monitored_tgids add");
					continue;
				}
				fill_mon_entry_from_proc(&alog.ent[alog.n], p);
				alog.n++;
			}
			next_scan = now + (time_t)gl.scan_interval_s;
		}

		if (now >= next_print) {
			if (write_kvm_latency_prom_textfile(gl.prom_path, hfd, &alog) != 0)
				fprintf(stderr,
					"kvmmon: prom export failed (will retry next interval)\n");
			next_print = now + (time_t)gl.interval_s;
		}

		nanosleep(&sleep_chunk, NULL);
	}

cleanup_a:
	if (obj) {
		hfd = bpf_map__fd(obj->maps.hists);
		monfd = bpf_map__fd(obj->maps.monitored_tgids);
		for (i = 0; i < (int)alog.n; i++) {
			__u32 tg = (__u32)alog.ent[i].tgid;

			bpf_map_delete_elem(hfd, &tg);
			bpf_map_delete_elem(monfd, &tg);
		}
	}
	alog.n = 0;
	kvmmon_bpf__destroy(obj);
	return err;
}

int main(int argc, char **argv)
{
	static const struct argp argp = { opts, parse_opt, NULL, doc };
	int err = 0;

	gl.interval_s = 120;
	gl.scan_interval_s = 300;
	gl.stack_thresh_ns = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (gl.all_qemu) {
		if (gl.have_pid) {
			fprintf(stderr, "-a cannot be combined with -p\n");
			free(gl.prom_path);
			gl.prom_path = NULL;
			return 1;
		}
		if (gl.out_path) {
			fprintf(stderr, "-a cannot be combined with -o\n");
			free(gl.prom_path);
			gl.prom_path = NULL;
			return 1;
		}
		if (gl.stack_thresh_ns > 0) {
			fprintf(stderr, "-a cannot be combined with -s\n");
			free(gl.prom_path);
			gl.prom_path = NULL;
			return 1;
		}
		if (!gl.prom_path) {
			gl.prom_path =
			    strdup("/app/monitor/prom/vm_latency.prom");
			if (!gl.prom_path) {
				perror("strdup default --prom");
				return 1;
			}
		}
		err = run_all_qemu_map_mode();
		free(gl.out_path);
		gl.out_path = NULL;
		free(gl.prom_path);
		gl.prom_path = NULL;
		return err ? 1 : 0;
	}

	if (!gl.have_pid) {
		fprintf(stderr,
			"required: -p <QEMU_PID> (or -a for all QEMU)\n");
		free(gl.prom_path);
		gl.prom_path = NULL;
		return 1;
	}

	if (gl.out_path) {
		struct stat st;

		if (stat(gl.out_path, &st) == 0 && S_ISDIR(st.st_mode)) {
			fprintf(stderr,
				"-o is a directory; use -a for all QEMU\n");
			free(gl.prom_path);
			gl.prom_path = NULL;
			return 1;
		}
		if (!freopen(gl.out_path, "a", stdout)) {
			perror("freopen stdout");
			free(gl.prom_path);
			gl.prom_path = NULL;
			return 1;
		}
	}

	bump_memlock_rlimit();

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		perror("signal");
		free(gl.prom_path);
		gl.prom_path = NULL;
		return 1;
	}

	err = run_one_qemu_session(gl.qemu_tgid, gl.interval_s, gl.stack_thresh_ns,
				   stdout, NULL);
	free(gl.out_path);
	gl.out_path = NULL;
	free(gl.prom_path);
	gl.prom_path = NULL;
	return err ? 1 : 0;
}

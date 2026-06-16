// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "numawake_topology.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libbpf.h"
#include "bpf.h"

static int topo_set_cpu(struct numawake_topo *topo, int cpu, __u8 node)
{
	if (cpu < 0 || cpu >= NUMAWAKE_MAX_CPUS)
		return -ERANGE;

	if (topo->cpu_to_node[cpu] != NUMAWAKE_NODE_UNKNOWN &&
	    topo->cpu_to_node[cpu] != node)
		return -EEXIST;

	if (topo->cpu_to_node[cpu] == NUMAWAKE_NODE_UNKNOWN) {
		topo->cpu_to_node[cpu] = node;
		topo->nr_mapped_cpus++;
	}
	return 0;
}

static int parse_cpulist_segment(const char *seg, int node, struct numawake_topo *topo)
{
	char *end;
	long start, stop;
	int err;

	errno = 0;
	start = strtol(seg, &end, 10);
	if (errno || end == seg || start < 0 || start >= NUMAWAKE_MAX_CPUS)
		return -EINVAL;

	if (*end == '-') {
		stop = strtol(end + 1, &end, 10);
		if (errno || stop < start || stop >= NUMAWAKE_MAX_CPUS)
			return -EINVAL;
	} else {
		stop = start;
	}

	if (*end != '\0' && *end != ',')
		return -EINVAL;

	for (long cpu = start; cpu <= stop; cpu++) {
		err = topo_set_cpu(topo, (int)cpu, (__u8)node);
		if (err)
			return err;
	}
	return 0;
}

static int parse_cpulist(const char *list, int node, struct numawake_topo *topo)
{
	char buf[256];
	char *seg;
	int err;

	if (!list || !*list)
		return -EINVAL;

	if (snprintf(buf, sizeof(buf), "%s", list) >= (int)sizeof(buf))
		return -EINVAL;

	/* sysfs cpulist lines end with '\n' */
	buf[strcspn(buf, "\n\r")] = '\0';

	seg = buf;
	while (*seg) {
		char *comma = strchr(seg, ',');

		if (comma)
			*comma = '\0';

		err = parse_cpulist_segment(seg, node, topo);
		if (err)
			return err;

		if (!comma)
			break;
		seg = comma + 1;
	}
	return 0;
}

static int read_node_cpulist(int node, struct numawake_topo *topo)
{
	char path[PATH_MAX];
	char cpulist[256];
	FILE *f;
	int err;

	if (snprintf(path, sizeof(path), "%s/node%d/cpulist",
		     NUMAWAKE_SYSFS_NODE_DIR, node) >= (int)sizeof(path))
		return -ENAMETOOLONG;

	f = fopen(path, "r");
	if (!f)
		return -errno;

	if (!fgets(cpulist, sizeof(cpulist), f)) {
		err = ferror(f) ? -errno : -EIO;
		fclose(f);
		return err;
	}
	fclose(f);

	return parse_cpulist(cpulist, node, topo);
}

static int cmp_int(const void *a, const void *b)
{
	return *(const int *)a - *(const int *)b;
}

static void warn_unmapped_online_cpus(const struct numawake_topo *topo, FILE *out)
{
	char online[256];
	FILE *f;
	int cpus[NUMAWAKE_MAX_CPUS];
	int nr_cpus = 0;
	const char *seg;
	char buf[256];

	f = fopen("/sys/devices/system/cpu/online", "r");
	if (!f)
		return;

	if (!fgets(online, sizeof(online), f)) {
		fclose(f);
		return;
	}
	fclose(f);

	if (snprintf(buf, sizeof(buf), "%s", online) >= (int)sizeof(buf))
		return;

	buf[strcspn(buf, "\n\r")] = '\0';

	seg = buf;
	while (*seg) {
		char *comma = strchr(seg, ',');
		long start, stop;
		char *end;

		if (comma)
			*comma = '\0';

		errno = 0;
		start = strtol(seg, &end, 10);
		if (!errno && end != seg && start >= 0 && start < NUMAWAKE_MAX_CPUS) {
			if (*end == '-') {
				stop = strtol(end + 1, &end, 10);
				if (errno || stop < start || stop >= NUMAWAKE_MAX_CPUS)
					stop = start;
			} else {
				stop = start;
			}

			for (long cpu = start; cpu <= stop; cpu++) {
				if (topo->cpu_to_node[cpu] == NUMAWAKE_NODE_UNKNOWN &&
				    nr_cpus < NUMAWAKE_MAX_CPUS)
					cpus[nr_cpus++] = (int)cpu;
			}
		}

		if (!comma)
			break;
		seg = comma + 1;
	}

	if (!nr_cpus)
		return;

	qsort(cpus, nr_cpus, sizeof(cpus[0]), cmp_int);
	fprintf(out, "warning: online CPU(s) without NUMA node mapping:");
	for (int i = 0; i < nr_cpus; i++)
		fprintf(out, " %d", cpus[i]);
	fprintf(out, "\n");
}

int numawake_topo_from_sysfs(struct numawake_topo *topo)
{
	DIR *dir;
	struct dirent *ent;
	int max_node = -1;
	int err;

	if (!topo)
		return -EINVAL;

	memset(topo, 0, sizeof(*topo));
	for (int i = 0; i < NUMAWAKE_MAX_CPUS; i++)
		topo->cpu_to_node[i] = NUMAWAKE_NODE_UNKNOWN;

	dir = opendir(NUMAWAKE_SYSFS_NODE_DIR);
	if (!dir)
		return -errno;

	while ((ent = readdir(dir)) != NULL) {
		int node;

		if (strncmp(ent->d_name, "node", 4) != 0)
			continue;
		if (sscanf(ent->d_name, "node%d", &node) != 1)
			continue;
		if (node < 0 || node >= NUMAWAKE_MAX_NODES)
			continue;

		err = read_node_cpulist(node, topo);
		if (err) {
			closedir(dir);
			return err;
		}

		if (node > max_node)
			max_node = node;
	}
	closedir(dir);

	if (max_node < 0)
		return -ENOENT;

	topo->nr_nodes = max_node + 1;
	warn_unmapped_online_cpus(topo, stderr);
	return 0;
}

int numawake_topo_map_fd(int map_fd, const struct numawake_topo *topo)
{
	if (!topo || map_fd < 0)
		return -EINVAL;

	for (__u32 cpu = 0; cpu < NUMAWAKE_MAX_CPUS; cpu++) {
		__u8 node = topo->cpu_to_node[cpu];

		if (bpf_map_update_elem(map_fd, &cpu, &node, BPF_ANY))
			return -errno;
	}
	return 0;
}

int numawake_topo_load_map(struct bpf_map *map, const struct numawake_topo *topo)
{
	if (!map)
		return -EINVAL;

	return numawake_topo_map_fd(bpf_map__fd(map), topo);
}

void numawake_topo_dump(const struct numawake_topo *topo, FILE *out)
{
	int cpu;

	if (!topo || !out)
		return;

	fprintf(out, "NUMA topology: %d node(s), %d mapped CPU(s)\n",
		topo->nr_nodes, topo->nr_mapped_cpus);

	for (cpu = 0; cpu < NUMAWAKE_MAX_CPUS; cpu++) {
		if (topo->cpu_to_node[cpu] == NUMAWAKE_NODE_UNKNOWN)
			continue;
		fprintf(out, "  cpu %d -> node %u\n", cpu,
			topo->cpu_to_node[cpu]);
	}
}

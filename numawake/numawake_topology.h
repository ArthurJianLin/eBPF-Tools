/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NUMAWAKE_TOPOLOGY_H
#define __NUMAWAKE_TOPOLOGY_H

#include <stdio.h>

#include <linux/types.h>
#include "numawake.h"

#define NUMAWAKE_SYSFS_NODE_DIR "/sys/devices/system/node"

struct numawake_topo {
	__u8 cpu_to_node[NUMAWAKE_MAX_CPUS];
	int nr_nodes;
	int nr_mapped_cpus;
};

/*
 * Build cpu_to_node[] from sysfs node cpulist files under
 * /sys/devices/system/node/.
 * Returns 0 on success, negative errno on failure.
 */
int numawake_topo_from_sysfs(struct numawake_topo *topo);

/* Write topo into a BPF ARRAY map (key = cpu id, value = node id). */
int numawake_topo_map_fd(int map_fd, const struct numawake_topo *topo);

struct bpf_map;
int numawake_topo_load_map(struct bpf_map *map, const struct numawake_topo *topo);

/* Human-readable dump for debugging / numawake_topo CLI. */
void numawake_topo_dump(const struct numawake_topo *topo, FILE *out);

#endif /* __NUMAWAKE_TOPOLOGY_H */

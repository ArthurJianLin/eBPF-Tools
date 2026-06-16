// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Print cpu -> NUMA node mapping built from sysfs.
 * Used to validate numawake_topology before loading numawake BPF.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "numawake_topology.h"

int main(void)
{
	struct numawake_topo topo;
	int err;

	err = numawake_topo_from_sysfs(&topo);
	if (err) {
		fprintf(stderr, "numawake_topo_from_sysfs: %s\n", strerror(-err));
		return 1;
	}

	numawake_topo_dump(&topo, stdout);
	return 0;
}

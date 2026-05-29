/***************************************************************************************
*   DESCRIPTION : Source code of diskstat tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2026-04-24 -- Guanbing Huang written
*****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include "diskstat.h"

int read_diskstats(struct disk_stat *out, int max_dev)
{
	 FILE *fp = fopen(DISKSTAT_FILE, "r");
	 if (!fp) return -1;

	 char line[256];
	 int idx = 0;

	 while (fgets(line, sizeof(line), fp) && idx < max_dev) {
		  char dev[32];
		  unsigned int major, minor;
		  unsigned long long rd_ios, rd_merges, rd_sec, rd_tick;
		  unsigned long long wr_ios, wr_merges, wr_sec, wr_tick;
		  unsigned long long in_flight, io_tick, time_in_queue;
		  unsigned long long discard_ios, discard_merges, discard_sec, discard_tick;
		  unsigned long long flush_ios, flush_tick;

		  // 严格按内核 20 字段解析
		  sscanf(line,
				"%u %u %s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
				&major, &minor, dev,
				&rd_ios, &rd_merges, &rd_sec, &rd_tick,
				&wr_ios, &wr_merges, &wr_sec, &wr_tick,
				&in_flight, &io_tick, &time_in_queue,
				&discard_ios, &discard_merges, &discard_sec, &discard_tick,
				&flush_ios, &flush_tick);

		  // 只保存真实磁盘（vda、sda、nvme、loop 等）
		  if (sscanf(dev, "loop%s", dev) == 0) {
				strcpy(out[idx].dev, dev);
				out[idx].rd_ios = rd_ios;
				out[idx].rd_sectors = rd_sec;
				out[idx].rd_ticks = rd_tick;
				out[idx].wr_ios = wr_ios;
				out[idx].wr_sectors = wr_sec;
				out[idx].wr_ticks = wr_tick;
				out[idx].io_ticks = io_tick;
				out[idx].time_in_queue = time_in_queue;
				idx++;
		  }
	 }

	 fclose(fp);
	 return idx;
}

#define BINARY_BASE 1024
static const char *const binary_units[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"};
static char *bytes_to_binary_size(unsigned long long bytes, char *buf, size_t buf_len)
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

int handle_diskstats(struct disk_stat *prev, struct disk_stat *curr, int prev_cnt, int curr_cnt, int interval_ms)
{
	printf("%-16s %-16s %-16s %-16s %-16s %-16s %-16s %-16s	%-16s\n",
		"device-stat:", "r_iops", "w_iops", "r_bps", "w_bps", "wait", "r_wait", "w_wait", "util%");

	for (int i = 0; i < curr_cnt; i++) {
		char *dev = curr[i].dev;
		for (int j = 0; j < prev_cnt; j++) {
			if (strcmp(prev[j].dev, dev) == 0) {
				// 计算差值
				unsigned long long d_rd_ios = curr[i].rd_ios - prev[j].rd_ios;
				unsigned long long d_wr_ios = curr[i].wr_ios - prev[j].wr_ios;
				unsigned long long d_rd_sec = curr[i].rd_sectors - prev[j].rd_sectors;
				unsigned long long d_wr_sec = curr[i].wr_sectors - prev[j].wr_sectors;
				unsigned long long d_rd_tick = curr[i].rd_ticks - prev[j].rd_ticks;
				unsigned long long d_wr_tick = curr[i].wr_ticks - prev[j].wr_ticks;
				unsigned long long d_io_tick = curr[i].io_ticks - prev[j].io_ticks;
				unsigned long long d_total_io = d_rd_ios + d_wr_ios;

				// 计算指标
				double r_iops = d_rd_ios;
				double w_iops = d_wr_ios;
				unsigned long long r_bps = d_rd_sec * 512;
				unsigned long long  w_bps = d_wr_sec * 512;
				char size_str_r[16] = { 0 };
				bytes_to_binary_size(r_bps, size_str_r, 16);
				char size_str_w[16] = { 0 };
				bytes_to_binary_size(w_bps, size_str_w, 16);
				double util = (d_io_tick * 100.0) / interval_ms;
				double wait = 0.0, r_wait = 0.0, w_wait = 0.0;

				if (d_total_io > 0) {
					wait = (d_rd_tick + d_wr_tick) * 1.0 / d_total_io;
				}
				if (d_rd_ios > 0) {
					r_wait = d_rd_tick * 1.0 / d_rd_ios;
				}
				if (d_wr_ios > 0) {
						w_wait = d_wr_tick * 1.0 / d_wr_ios;
				}

				printf("%-16s %-16.1f %-16.1f %-16s %-16s %-16.1f %-16.1f %-16.1f %-16.1f\n",
					dev, r_iops, w_iops, size_str_r, size_str_w, wait, r_wait, w_wait, util > 100.0 ? 100.0 : util);
				break;
			}
		}
	}
	printf("\n");
	return 0;
}

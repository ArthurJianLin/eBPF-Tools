/***************************************************************************************
*   DESCRIPTION : Source code of diskstat tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2026-04-24 -- Guanbing Huang written
*****************************************************************************************/
#ifndef __DISKSTAT_H__
#define __DISKSTAT_H__

#define DISKSTAT_FILE "/proc/diskstats"
#define MAX_DEVICES 20
#define INTERVAL_MS 1000  // 1s

struct disk_stat {
	char dev[32];
	unsigned long long rd_ios;		// 读 IO 次数
	unsigned long long rd_sectors;  // 读扇区
	unsigned long long rd_ticks;	 // 读耗时 ms
	unsigned long long wr_ios;	 // 写 IO 次数
	unsigned long long wr_sectors;  // 写扇区
	unsigned long long wr_ticks;	 // 写耗时 ms
	unsigned long long io_ticks;	 // 设备总繁忙时间 ms (util%)
	unsigned long long time_in_queue; // 总排队+处理时间
};

// 两次采样差值，用于计算速率
struct disk_stat_prev {
	struct disk_stat stats[MAX_DEVICES];
	int count;
};

int read_diskstats(struct disk_stat *out, int max_dev);
int handle_diskstats(struct disk_stat *prev, struct disk_stat *curr, int prev_cnt, int curr_cnt, int interval_ms);

#endif /* end of __DISKSTAT_H__ */

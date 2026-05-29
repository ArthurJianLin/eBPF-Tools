/***************************************************************************************
*   DESCRIPTION : Header file for io ebpf tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2026-04-17 -- Guanbing Huang written
*****************************************************************************************/

#ifndef __IOFSSTAT_H__
#define __IOFSSTAT_H__

#define TASK_COMM_LEN		32
#define DEV_NAME_LEN 64

struct file_event {
	unsigned int pid;
	unsigned long inode;
	unsigned int dev_id;
	unsigned long cnt_r; /* count of read */
	unsigned long cnt_w; /* count of write */
	unsigned long bw_r;  /* bandwidth of read, Byte/s */
	unsigned long bw_w;  /* bandwidth of write, Byte/s */
	char comm[TASK_COMM_LEN];
};

struct block_dev {
	char dev_name[DEV_NAME_LEN];  /* 设备名：sda, sda1, nvme0n1 */
	unsigned int major;
	unsigned int minor;
	unsigned int dev_t;        /* 完整设备号 (major << 20 | minor) */
};

#endif /* end of __IOFSSTAT_H__ */

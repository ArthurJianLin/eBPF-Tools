/***************************************************************************************
*   DESCRIPTION : Header file for mmap ebpf tool
*   AUTHOR      : Guanbing Huang
*
*   HISTORY     :
*       2025-12-18 -- Guanbing Huang written
*****************************************************************************************/

#ifndef __MMAP_H__
#define __MMAP_H__

#define TASK_COMM_LEN		32
#define NAME_LEN  64
#define MMAP_ENV_PID_EN 0x1
#define MMAP_ENV_COMM_EN 0x2
#define MMAP_ENV_RD_EN 0x4

#define EVENT_TYPE_MMAP 0x1
#define EVENT_TYPE_MUNMAP 0x2

struct mmap_event {
	unsigned int type;
	unsigned long time_ns;
	unsigned int pid;
	unsigned int tgid;
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long offset;
	unsigned long fd;
	char comm[TASK_COMM_LEN];
};

struct munmap_event {
	unsigned int type;
	unsigned long time_ns;
	unsigned int pid;
	unsigned int tgid;
	unsigned long addr;
	unsigned long len;
	char comm[TASK_COMM_LEN];
};


#endif /* end of __MMAP_H__ */

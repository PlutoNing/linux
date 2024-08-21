/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_SYSINFO_H
#define _LINUX_SYSINFO_H

#include <linux/types.h>

#define SI_LOAD_SHIFT	16
/*  */
struct sysinfo {
	__kernel_long_t uptime;		/* Seconds since boot */
	__kernel_ulong_t loads[3];	/* 1, 5, and 15 minute load averages */
	__kernel_ulong_t totalram;	/* 
	全部zone的managed pages之和
	Total usable main memory size */
	__kernel_ulong_t freeram;	/* 
	每个zone的NR_FREE_PAGES之和
	Available memory size */
	__kernel_ulong_t sharedram;	/* 
	node的NR_SHMEM
	Amount of shared memory */
	__kernel_ulong_t bufferram;	/* 
	全部dev的inode的mapping的page数量之和
	Memory used by buffers */
	__kernel_ulong_t totalswap;	/* Total swap space size */
	__kernel_ulong_t freeswap;	/* swap space still available */
	__u16 procs;		   	/* Number of current processes */
	__u16 pad;		   	/* Explicit padding for m68k */
	__kernel_ulong_t totalhigh;	/* Total high memory size */
	__kernel_ulong_t freehigh;	/* Available high memory size */
	__u32 mem_unit;			/* Memory unit size in bytes */
	char _f[20-2*sizeof(__kernel_ulong_t)-sizeof(__u32)];	/* Padding: libc5 uses this.. */
};

#endif /* _LINUX_SYSINFO_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SYSCTL_H
#define _LINUX_SCHED_SYSCTL_H

#include <linux/types.h>

#ifdef CONFIG_DETECT_HUNG_TASK
/* used for hung_task and block/ */
extern unsigned long sysctl_hung_task_timeout_secs;
#else
/* Avoid need for ifdefs elsewhere in the code */
enum { sysctl_hung_task_timeout_secs = 0 };
#endif

enum sched_tunable_scaling {
	SCHED_TUNABLESCALING_NONE,
	SCHED_TUNABLESCALING_LOG,
	SCHED_TUNABLESCALING_LINEAR,
	SCHED_TUNABLESCALING_END,
};
/* 完全关闭 NUMA balancing。内核不会自动采样任务访问的页表，也不会把页迁移到本地节点。 */
#define NUMA_BALANCING_DISABLED		0x0
/* 标准模式。周期性扫描各进程的页表，统计每页在各 NUMA 节点上的访问热度，然后把“热页”迁移到任务运行所在的节点，
同时把任务迁移到页所在节点，实现双向亲和。 */
#define NUMA_BALANCING_NORMAL		0x1
/* 分层内存模式。在支持异构内存（如 DRAM + 持久内存/高带宽内存）的系统上，除了做 NUMA 亲和外，
还会根据访问频率把冷页降级到慢速节点，把热页提升到快速节点，实现“内存分层”自动管理。 */
#define NUMA_BALANCING_MEMORY_TIERING	0x2

#ifdef CONFIG_NUMA_BALANCING
extern int sysctl_numa_balancing_mode;
#else
#define sysctl_numa_balancing_mode	0
#endif

#endif /* _LINUX_SCHED_SYSCTL_H */

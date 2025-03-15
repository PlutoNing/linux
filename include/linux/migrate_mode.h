/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED
/*
 * MIGRATE_ASYNC means never block
   ASYNC 意味着永远不会阻塞
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 SYNC_LIGHT 在当前实现中意味着允许大多数操作阻塞，但不包括 ->writepage，因为潜在的停顿时间太长
 * MIGRATE_SYNC will block when migrating pages
   SYNC会在迁移页面时阻塞
 * MIGRATE_SYNC_NO_COPY will block when migrating pages but will not copy pages
 *	with the CPU. Instead, page copy happens outside the migratepage()
 *	callback and is likely using a DMA engine. See migrate_vma() and HMM
 *	(mm/hmm.c) for users of this mode.
   MIgrate_sync_no_copy 会阻塞，但是不会复制页面，而是在 migratepage() 回调
   之外进行页面复制，可能使用 DMA 引擎。
 */
enum migrate_mode {
	MIGRATE_ASYNC,
	MIGRATE_SYNC_LIGHT,
	MIGRATE_SYNC,
	MIGRATE_SYNC_NO_COPY,
};

enum migrate_reason {
	MR_COMPACTION,
	MR_MEMORY_FAILURE,
	MR_MEMORY_HOTPLUG,
	MR_SYSCALL,		/* also applies to cpusets */
	MR_MEMPOLICY_MBIND,
	MR_NUMA_MISPLACED,
	MR_CONTIG_RANGE,
	MR_LONGTERM_PIN,
	MR_DEMOTION,
	MR_TYPES
};

#endif		/* MIGRATE_MODE_H_INCLUDED */

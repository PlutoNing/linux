/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED
/*
 * MIGRATE_ASYNC means never block
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 * MIGRATE_SYNC will block when migrating pages
 * MIGRATE_SYNC_NO_COPY will block when migrating pages but will not copy pages
 *	with the CPU. Instead, page copy happens outside the migratepage()
 *	callback and is likely using a DMA engine. See migrate_vma() and HMM
 *	(mm/hmm.c) for users of this mode.
 2024年06月26日14:25:29
 只有三种类型的页框支持内存碎片整理：MIGRATE_MOVABLE、MIGRATE_CMA和MIRGATE_RECLAIMABLE。内存碎片整理有如下四种模式：
 */
enum migrate_mode {
	/* 异步模式（MIGRATE_ASYNC）：在该模式不允许进行任何阻塞操作，当需要阻塞或者调度的时候，则停止内存碎片整理。
	在该模式下只会处理MIGRATE_MOVABLE、MIGRATE_CMA类型的页框，而不会处理MIRGATE_RECLAIMABLE类型的页框，
	因为该类型的页框大多数是文件页，对文件页进行内存碎片整理，有可能涉及脏页回写，这会引起阻塞。 */
	
	MIGRATE_ASYNC,
	/* 轻同步模式（MIGRATE_SYNC_LIGHT）：该模式允许绝大部分的阻塞操作，但是不阻塞等待脏文件页的回写操作，
	因为回写时间可能很长。 */
	MIGRATE_SYNC_LIGHT,
	/*  同步模式（MIGRATE_SYNC）：该模式允许在迁移页框时允许阻塞，也就是允许页回写完成才返回结果，这是最耗时的模式。
该模式会整zone扫描，并且不会跳过标记为PG_migrate_skip标志的pageblock。*/
	MIGRATE_SYNC,
	/* 非拷贝同步模式（MIGRATE_SYNC_NO_COPY）：与同步模式类似，在迁移页框时允许阻塞，但不会进行页框拷贝。 */
	MIGRATE_SYNC_NO_COPY,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */

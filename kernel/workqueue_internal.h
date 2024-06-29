/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/workqueue_internal.h
 *
 * Workqueue internal header file.  Only to be included by workqueue and
 * core kernel subsystems.
 */
#ifndef _KERNEL_WORKQUEUE_INTERNAL_H
#define _KERNEL_WORKQUEUE_INTERNAL_H

#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

struct worker_pool;

/*
2024年6月28日23:13:03
 worker 
 运行work_struct的内核线程被称为worker，即工作线程。
 * The poor guys doing the actual heavy lifting.  All on-duty workers are
 * either serving the manager role, on idle list or on busy hash.  For
 * details on the locking annotation (L, I, X...), refer to workqueue.c.
 *
 * Only to be used in workqueue and async.
 */
struct worker {
	/* on idle list while idle, on busy hash table while busy */
	union {
		struct list_head	entry;	/* L: while idle */
		struct hlist_node	hentry;	/* L: while busy */
	};

	struct work_struct	*current_work;	/* L: work being processed 当前正在处理的work*/
	work_func_t		current_func;	/* L: current_work's fn 当前正在执行的work回调函数*/
	struct pool_workqueue	*current_pwq; /* L: current_work's pwq ，当前work所属的pool_workqueue*/
	struct list_head	scheduled;	/* L: scheduled works 所有被调度并正准备执行的work_struct都挂入该链表中*/

	/* 64 bytes boundary on 64bit, 32 on 32bit */

	struct task_struct	*task;		/* I: worker task 该工作线程的task_struct数据结构*/
	struct worker_pool	*pool;		/* A: the associated pool该工作线程所属的worker_pool */
						/* L: for rescuers */
	struct list_head	node;		/* A: anchored at pool->workers 可以把该worker挂入到worker_pool->workers链表中 */
						/* A: runs through worker->node */

	unsigned long		last_active;	/* L: last active timestamp */
	unsigned int		flags;		/* X: flags */
	int			id;		/* I: worker id */
	int			sleeping;	/* None */

	/*
	 * Opaque string set with work_set_desc().  Printed out with task
	 * dump for debugging - WARN, BUG, panic or sysrq.
	 */
	char			desc[WORKER_DESC_LEN];

	/* used only by rescuers to point to the target workqueue */
	struct workqueue_struct	*rescue_wq;	/* I: the workqueue to rescue */

	/* used by the scheduler to determine a worker's last known identity */
	work_func_t		last_func;
};

/**
 * current_wq_worker - return struct worker if %current is a workqueue worker
 */
static inline struct worker *current_wq_worker(void)
{
	if (in_task() && (current->flags & PF_WQ_WORKER))
		return kthread_data(current);
	return NULL;
}

/*
 * Scheduler hooks for concurrency managed workqueue.  Only to be used from
 * sched/ and workqueue.c.
 */
void wq_worker_running(struct task_struct *task);
void wq_worker_sleeping(struct task_struct *task);
work_func_t wq_worker_last_func(struct task_struct *task);

#endif /* _KERNEL_WORKQUEUE_INTERNAL_H */

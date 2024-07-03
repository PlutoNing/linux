/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_VMPRESSURE_H
#define __LINUX_VMPRESSURE_H

#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/cgroup.h>
#include <linux/eventfd.h>
/* 2024年06月27日11:17:14
是什么
Vmpressure 的计算在每次系统尝试做do_try_to_free_pages 回收内存时进行。其计算方法非常简单：

(1 - reclaimed/scanned)*100，也就是说回收失败的内存页越多，内存压力越大。
同时 vmpressure 提供了通知机制，用户态或内核态程序都可以注册事件通知，应对不同等级的压力。
默认定义了三级压力：low/medium/critical。low 代表正常回收；medium 代表中等压力，可能存在页交换或回写，默认值是 65%；critical 代表内存压力很大，即将 OOM，建议应用即可采取行动，默认值是 90%。
vmpressure 也有一些缺陷：
结果仅体现内存回收压力，不能反映系统在申请内存上的资源等待时间；
计算周期比较粗；
粗略的几个等级通知，无法精细化管理。
2024年07月03日10:27:44
vmpressure()函数通过计算
scanned/reclaimed比例来判断内存压力。

 */
struct vmpressure {
	/* 扫描的数量 */
	unsigned long scanned;
	/* 回收成功的数量 */
	unsigned long reclaimed;

	unsigned long tree_scanned;
	unsigned long tree_reclaimed;
	/* The lock is used to keep the scanned/reclaimed above in sync. */
	spinlock_t sr_lock;

	/* The list of vmpressure_event structs. */
	struct list_head events;
	/* Have to grab the lock on events traversal or modifications. */
	struct mutex events_lock;

	struct work_struct work;
};

struct mem_cgroup;

#ifdef CONFIG_MEMCG
extern void vmpressure(gfp_t gfp, struct mem_cgroup *memcg, bool tree,
		       unsigned long scanned, unsigned long reclaimed);
extern void vmpressure_prio(gfp_t gfp, struct mem_cgroup *memcg, int prio);

extern void vmpressure_init(struct vmpressure *vmpr);
extern void vmpressure_cleanup(struct vmpressure *vmpr);
extern struct vmpressure *memcg_to_vmpressure(struct mem_cgroup *memcg);
extern struct cgroup_subsys_state *vmpressure_to_css(struct vmpressure *vmpr);
extern int vmpressure_register_event(struct mem_cgroup *memcg,
				     struct eventfd_ctx *eventfd,
				     const char *args);
extern void vmpressure_unregister_event(struct mem_cgroup *memcg,
					struct eventfd_ctx *eventfd);
#else
static inline void vmpressure(gfp_t gfp, struct mem_cgroup *memcg, bool tree,
			      unsigned long scanned, unsigned long reclaimed) {}
static inline void vmpressure_prio(gfp_t gfp, struct mem_cgroup *memcg,
				   int prio) {}
#endif /* CONFIG_MEMCG */
#endif /* __LINUX_VMPRESSURE_H */

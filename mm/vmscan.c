// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/migrate.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/memory-tiers.h>
#include <linux/oom.h>
#include <linux/pagevec.h>
#include <linux/prefetch.h>
#include <linux/printk.h>
#include <linux/dax.h>
#include <linux/psi.h>
#include <linux/pagewalk.h>
#include <linux/shmem_fs.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/khugepaged.h>
#include <linux/rculist_nulls.h>
#include <linux/random.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>
#include <linux/balloon_compaction.h>
#include <linux/sched/sysctl.h>

#include "internal.h"
#include "swap.h"

#define CREATE_TRACE_POINTS
#include <trace/events/vmscan.h>

struct scan_control {
	/* How many pages shrink_list() should reclaim
	需要回收的页面的数量 */
	unsigned long nr_to_reclaim;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	nodemask_t	*nodemask;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	struct mem_cgroup *target_mem_cgroup;

	/*
	 * Scan pressure balancing between anon and file LRUs
	 */
	unsigned long	anon_cost;
	unsigned long	file_cost;

	/* Can active folios be deactivated as part of reclaim? */
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
	unsigned int may_deactivate:2;
	/* 这两个bit位记录是否可以强制inactive对应bit代表的文件页或者匿名页 */

	unsigned int force_deactivate:1;  /* 是否强制deactivate */
	unsigned int skipped_deactivate:1; /*  */

	/* Writepage batching in laptop mode; RECLAIM_WRITE */
	unsigned int may_writepage:1;

	/* Can mapped folios be reclaimed?
	 */
	unsigned int may_unmap:1;

	/* Can folios be swapped as part of reclaim? */
	unsigned int may_swap:1;
	/* 
	1. 老化的时候, 会根据sc判断能否交换, 可以的话会认为有偏多可回收的lruvec, 不会老化.
	所以会减少老化?

	2, 具体回收的时候, 不会回收lru
	 */


	/* Proactive reclaim invoked by userspace through memory.reclaim
	 */
	unsigned int proactive:1;

	/*
	 * Cgroup memory below memory.low is protected as long as we
	 * don't threaten to OOM. If any cgroup is reclaimed at
	 * reduced force or passed over entirely due to its memory.low
	 * setting (memcg_low_skipped), and nothing is reclaimed as a
	 * result, then go back for one more cycle that reclaims the protected
	 * memory (memcg_low_reclaim) to avert OOM.
	 */
	unsigned int memcg_low_reclaim:1;
	unsigned int memcg_low_skipped:1;

	unsigned int hibernation_mode:1;

	/* One of the zones is ready for compaction */
	unsigned int compaction_ready:1;

	/* There is easily reclaimable cold cache in the current node
	有很多非活跃文件页, 并且sc不进行deactivate */
	unsigned int cache_trim_mode:1;

	/* The file folios on the current node are dangerously low
	当前node的文件页是不是太少了 ? */
	unsigned int file_is_tiny:1;

	/* Always discard instead of demoting to lower tier memory */
	unsigned int no_demotion:1;

	/* Allocation order */
	s8 order;

	/* Scan (total_size >> priority) pages at once */
	s8 priority;

	/* The highest zone to isolate folios for reclaim from */
	s8 reclaim_idx;

	/* This context's GFP mask */
	gfp_t gfp_mask;

	/* Incremented by the number of inactive pages that were scanned
	已经scan的页面数量
	========
	shrink_node和shrink_zones之前都可以归零 */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	unsigned long nr_reclaimed;

	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;

	/* for recording the reclaimed slab by now */
	struct reclaim_state reclaim_state;
};

#ifdef ARCH_HAS_PREFETCHW
/* _folio是从_base(lru)获得的 */
/* _folio是从_base(lru)获得的 */
#define prefetchw_prev_lru_folio(_folio, _base, _field)			\
	do {								\
		if ((_folio)->lru.prev != _base) {			\
			struct folio *prev;				\
									\
			prev = lru_to_folio(&(_folio->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_folio(_folio, _base, _field) do { } while (0)
#endif

/*
 * From 0 .. 200.  Higher means more swappy.
 */
int vm_swappiness = 60;

/* 系统全部的shrinker挂接在这里 */
LIST_HEAD(shrinker_list);
DECLARE_RWSEM(shrinker_rwsem);

#ifdef CONFIG_MEMCG
static int shrinker_nr_max;

/* The shrinker_info is expanded in a batch of BITS_PER_LONG */
static inline int shrinker_map_size(int nr_items)
{
	return (DIV_ROUND_UP(nr_items, BITS_PER_LONG) * sizeof(unsigned long));
}

static inline int shrinker_defer_size(int nr_items)
{
	return (round_up(nr_items, BITS_PER_LONG) * sizeof(atomic_long_t));
}

static struct shrinker_info *shrinker_info_protected(struct mem_cgroup *memcg,
						     int nid)
{
	return rcu_dereference_protected(memcg->nodeinfo[nid]->shrinker_info,
					 lockdep_is_held(&shrinker_rwsem));
}

static int expand_one_shrinker_info(struct mem_cgroup *memcg,
				    int map_size, int defer_size,
				    int old_map_size, int old_defer_size,
				    int new_nr_max)
{
	struct shrinker_info *new, *old;
	struct mem_cgroup_per_node *pn;
	int nid;
	int size = map_size + defer_size;

	for_each_node(nid) {
		pn = memcg->nodeinfo[nid];
		old = shrinker_info_protected(memcg, nid);
		/* Not yet online memcg */
		if (!old)
			return 0;

		/* Already expanded this shrinker_info */
		if (new_nr_max <= old->map_nr_max)
			continue;

		new = kvmalloc_node(sizeof(*new) + size, GFP_KERNEL, nid);
		if (!new)
			return -ENOMEM;

		new->nr_deferred = (atomic_long_t *)(new + 1);
		new->map = (void *)new->nr_deferred + defer_size;
		new->map_nr_max = new_nr_max;

		/* map: set all old bits, clear all new bits */
		memset(new->map, (int)0xff, old_map_size);
		memset((void *)new->map + old_map_size, 0, map_size - old_map_size);
		/* nr_deferred: copy old values, clear all new values */
		memcpy(new->nr_deferred, old->nr_deferred, old_defer_size);
		memset((void *)new->nr_deferred + old_defer_size, 0,
		       defer_size - old_defer_size);

		rcu_assign_pointer(pn->shrinker_info, new);
		kvfree_rcu(old, rcu);
	}

	return 0;
}

void free_shrinker_info(struct mem_cgroup *memcg)
{
	struct mem_cgroup_per_node *pn;
	struct shrinker_info *info;
	int nid;

	for_each_node(nid) {
		pn = memcg->nodeinfo[nid];
		info = rcu_dereference_protected(pn->shrinker_info, true);
		kvfree(info);
		rcu_assign_pointer(pn->shrinker_info, NULL);
	}
}

int alloc_shrinker_info(struct mem_cgroup *memcg)
{
	struct shrinker_info *info;
	int nid, size, ret = 0;
	int map_size, defer_size = 0;

	down_write(&shrinker_rwsem);
	map_size = shrinker_map_size(shrinker_nr_max);
	defer_size = shrinker_defer_size(shrinker_nr_max);
	size = map_size + defer_size;
	for_each_node(nid) {
		info = kvzalloc_node(sizeof(*info) + size, GFP_KERNEL, nid);
		if (!info) {
			free_shrinker_info(memcg);
			ret = -ENOMEM;
			break;
		}
		info->nr_deferred = (atomic_long_t *)(info + 1);
		info->map = (void *)info->nr_deferred + defer_size;
		info->map_nr_max = shrinker_nr_max;
		rcu_assign_pointer(memcg->nodeinfo[nid]->shrinker_info, info);
	}
	up_write(&shrinker_rwsem);

	return ret;
}

static int expand_shrinker_info(int new_id)
{
	int ret = 0;
	int new_nr_max = round_up(new_id + 1, BITS_PER_LONG);
	int map_size, defer_size = 0;
	int old_map_size, old_defer_size = 0;
	struct mem_cgroup *memcg;

	if (!root_mem_cgroup)
		goto out;

	lockdep_assert_held(&shrinker_rwsem);

	map_size = shrinker_map_size(new_nr_max);
	defer_size = shrinker_defer_size(new_nr_max);
	old_map_size = shrinker_map_size(shrinker_nr_max);
	old_defer_size = shrinker_defer_size(shrinker_nr_max);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		ret = expand_one_shrinker_info(memcg, map_size, defer_size,
					       old_map_size, old_defer_size,
					       new_nr_max);
		if (ret) {
			mem_cgroup_iter_break(NULL, memcg);
			goto out;
		}
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);
out:
	if (!ret)
		shrinker_nr_max = new_nr_max;

	return ret;
}

void set_shrinker_bit(struct mem_cgroup *memcg, int nid, int shrinker_id)
{
	if (shrinker_id >= 0 && memcg && !mem_cgroup_is_root(memcg)) {
		struct shrinker_info *info;

		rcu_read_lock();
		info = rcu_dereference(memcg->nodeinfo[nid]->shrinker_info);
		if (!WARN_ON_ONCE(shrinker_id >= info->map_nr_max)) {
			/* Pairs with smp mb in shrink_slab() */
			smp_mb__before_atomic();
			set_bit(shrinker_id, info->map);
		}
		rcu_read_unlock();
	}
}

static DEFINE_IDR(shrinker_idr);
/* 好像就是分配shrinker的id ... */
static int prealloc_memcg_shrinker(struct shrinker *shrinker)
{
	int id, ret = -ENOMEM;

	if (mem_cgroup_disabled())
		return -ENOSYS;

	down_write(&shrinker_rwsem);
	/* This may call shrinker, so it must use down_read_trylock() */
	id = idr_alloc(&shrinker_idr, shrinker, 0, 0, GFP_KERNEL);
	if (id < 0)
		goto unlock;

	if (id >= shrinker_nr_max) {
		if (expand_shrinker_info(id)) {
			idr_remove(&shrinker_idr, id);
			goto unlock;
		}
	}
	shrinker->id = id;
	ret = 0;

unlock:
	up_write(&shrinker_rwsem);
	return ret;
}

static void unregister_memcg_shrinker(struct shrinker *shrinker)
{
	int id = shrinker->id;

	BUG_ON(id < 0);

	lockdep_assert_held(&shrinker_rwsem);

	idr_remove(&shrinker_idr, id);
}

static long xchg_nr_deferred_memcg(int nid, struct shrinker *shrinker,
				   struct mem_cgroup *memcg)
{
	struct shrinker_info *info;

	info = shrinker_info_protected(memcg, nid);
	return atomic_long_xchg(&info->nr_deferred[shrinker->id], 0);
}

static long add_nr_deferred_memcg(long nr, int nid, struct shrinker *shrinker,
				  struct mem_cgroup *memcg)
{
	struct shrinker_info *info;

	info = shrinker_info_protected(memcg, nid);
	return atomic_long_add_return(nr, &info->nr_deferred[shrinker->id]);
}

void reparent_shrinker_deferred(struct mem_cgroup *memcg)
{
	int i, nid;
	long nr;
	struct mem_cgroup *parent;
	struct shrinker_info *child_info, *parent_info;

	parent = parent_mem_cgroup(memcg);
	if (!parent)
		parent = root_mem_cgroup;

	/* Prevent from concurrent shrinker_info expand */
	down_read(&shrinker_rwsem);
	for_each_node(nid) {
		child_info = shrinker_info_protected(memcg, nid);
		parent_info = shrinker_info_protected(parent, nid);
		for (i = 0; i < child_info->map_nr_max; i++) {
			nr = atomic_long_read(&child_info->nr_deferred[i]);
			atomic_long_add(nr, &parent_info->nr_deferred[i]);
		}
	}
	up_read(&shrinker_rwsem);
}

/* 
是否是cgroup范围的scan
Returns true for reclaim through cgroup limits or cgroup interfaces. */
/* 
是否是cgroup范围的scan
Returns true for reclaim through cgroup limits or cgroup interfaces. */
static bool cgroup_reclaim(struct scan_control *sc)
{
	return sc->target_mem_cgroup;
}

/*
看看是不是全局回收或者根memcg回收
但是这两者有区别吗?
 * Returns true for reclaim on the root cgroup. This is true for direct
 * allocator reclaim and reclaim through cgroup interfaces on the root cgroup.
 */
static bool root_reclaim(struct scan_control *sc)
{
	return !sc->target_mem_cgroup || mem_cgroup_is_root(sc->target_mem_cgroup);
}

/**
 * writeback_throttling_sane - is the usual dirty throttling mechanism available?
    判断是否可以限流?
 * @sc: scan_control in question
 *
 * The normal page dirty throttling mechanism in balance_dirty_pages() is
 * completely broken with the legacy memcg and direct stalling in
 * shrink_folio_list() is used for throttling instead, which lacks all the
 * niceties such as fairness, adaptive pausing, bandwidth proportional
 * allocation and configurability.
 * balance_dirty_pages的正常的限流机制在这里不可用, 
    因此使用直接阻塞
 * This function tests whether the vmscan currently in progress can assume
 * that the normal dirty throttling mechanism is operational.
 */
static bool writeback_throttling_sane(struct scan_control *sc)
{
	if (!cgroup_reclaim(sc))
		return true;
#ifdef CONFIG_CGROUP_WRITEBACK
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return true;
#endif
	return false;
}
#else
static int prealloc_memcg_shrinker(struct shrinker *shrinker)
{
	return -ENOSYS;
}

static void unregister_memcg_shrinker(struct shrinker *shrinker)
{
}

static long xchg_nr_deferred_memcg(int nid, struct shrinker *shrinker,
				   struct mem_cgroup *memcg)
{
	return 0;
}

static long add_nr_deferred_memcg(long nr, int nid, struct shrinker *shrinker,
				  struct mem_cgroup *memcg)
{
	return 0;
}

static bool cgroup_reclaim(struct scan_control *sc)
{
	return false;
}

static bool root_reclaim(struct scan_control *sc)
{
	return true;
}

static bool writeback_throttling_sane(struct scan_control *sc)
{
	return true;
}
#endif

/* 把rs挂到进程 */
static void set_task_reclaim_state(struct task_struct *task,
				   struct reclaim_state *rs)
{
	/* Check for an overwrite */
	WARN_ON_ONCE(rs && task->reclaim_state);

	/* Check for the nulling of an already-nulled member */
	WARN_ON_ONCE(!rs && !task->reclaim_state);

	task->reclaim_state = rs;
}

/*
 * flush_reclaim_state(): add pages reclaimed outside of LRU-based reclaim to
 * scan_control->nr_reclaimed.
 */
static void flush_reclaim_state(struct scan_control *sc)
{
	/*
	 * Currently, reclaim_state->reclaimed includes three types of pages
	 * freed outside of vmscan:
	 * (1) Slab pages.
	 * (2) Clean file pages from pruned inodes (on highmem systems).
	 * (3) XFS freed buffer pages.
	 *
	 * For all of these cases, we cannot universally link the pages to a
	 * single memcg. For example, a memcg-aware shrinker can free one object
	 * charged to the target memcg, causing an entire page to be freed.
	 * If we count the entire page as reclaimed from the memcg, we end up
	 * overestimating the reclaimed amount (potentially under-reclaiming).
	 *
	 * Only count such pages for global reclaim to prevent under-reclaiming
	 * from the target memcg; preventing unnecessary retries during memcg
	 * charging and false positives from proactive reclaim.
	 *
	 * For uncommon cases where the freed pages were actually mostly
	 * charged to the target memcg, we end up underestimating the reclaimed
	 * amount. This should be fine. The freed pages will be uncharged
	 * anyway, even if they are not counted here properly, and we will be
	 * able to make forward progress in charging (which is usually in a
	 * retry loop).
	 *
	 * We can go one step further, and report the uncharged objcg pages in
	 * memcg reclaim, to make reporting more accurate and reduce
	 * underestimation, but it's probably not worth the complexity for now.
	 */
	if (current->reclaim_state && root_reclaim(sc)) {
		sc->nr_reclaimed += current->reclaim_state->reclaimed;
		current->reclaim_state->reclaimed = 0;
	}
}

static long xchg_nr_deferred(struct shrinker *shrinker,
			     struct shrink_control *sc)
{
	int nid = sc->nid;

	if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
		nid = 0;

	if (sc->memcg &&
	    (shrinker->flags & SHRINKER_MEMCG_AWARE))
		return xchg_nr_deferred_memcg(nid, shrinker,
					      sc->memcg);

	return atomic_long_xchg(&shrinker->nr_deferred[nid], 0);
}


static long add_nr_deferred(long nr, struct shrinker *shrinker,
			    struct shrink_control *sc)
{
	int nid = sc->nid;

	if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
		nid = 0;

	if (sc->memcg &&
	    (shrinker->flags & SHRINKER_MEMCG_AWARE))
		return add_nr_deferred_memcg(nr, nid, shrinker,
					     sc->memcg);

	return atomic_long_add_return(nr, &shrinker->nr_deferred[nid]);
}
/* sc下node是否可以demote,要看系统设置和sc设置.
然后是看demote数组里面有没有可以demote的 */
static bool can_demote(int nid, struct scan_control *sc)
{
	if (!numa_demotion_enabled)
		return false;
	if (sc && sc->no_demotion)
		return false;
	if (next_demotion_node(nid) == NUMA_NO_NODE)
		return false;

	return true;
}
/* 根据sc回收此memcg在此node上面的lruvec.
计算还能否回收匿名页  */
static inline bool can_reclaim_anon_pages(struct mem_cgroup *memcg,
					  int nid,
					  struct scan_control *sc)
{
	if (memcg == NULL) {
		/*
		 * For non-memcg reclaim, is there
		 * space in any swap device?
		 */
		if (get_nr_swap_pages() > 0)
			return true;
	} else {
		/* Is the memcg below its swap limit? */
		if (mem_cgroup_get_nr_swap_pages(memcg) > 0)
			return true;
	}

	/*
	 * The page can not be swapped.
	 *
	 * Can it be reclaimed from this node via demotion?
	 */
	return can_demote(nid, sc);
}

/*
获取zone上面还可以回收的页面数量

 * This misses isolated folios which are not accounted for to save counters.
 * As the data only determines if reclaim or compaction continues, it is
 * not expected that isolated folios will be a dominating factor.
 */
unsigned long zone_reclaimable_pages(struct zone *zone)
{
	unsigned long nr;

	nr = zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_FILE) +
		zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_FILE);

	if (can_reclaim_anon_pages(NULL, zone_to_nid(zone), NULL))
		nr += zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_ANON) +
			zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_ANON);

	return nr;
}

/**
 * lruvec_lru_size -  Returns the number of pages on the given LRU list.
 * @lruvec: lru vector
 * @lru: lru to use
 * @zone_idx: zones to consider (use MAX_NR_ZONES - 1 for the whole LRU list)
 */
static unsigned long lruvec_lru_size(struct lruvec *lruvec, enum lru_list lru,
				     int zone_idx)
{
	unsigned long size = 0;
	int zid;

	for (zid = 0; zid <= zone_idx; zid++) {
		struct zone *zone = &lruvec_pgdat(lruvec)->node_zones[zid];

		if (!managed_zone(zone))
			continue;

		if (!mem_cgroup_disabled())
			size += mem_cgroup_get_zone_lru_size(lruvec, lru, zid);
		else
			size += zone_page_state(zone, NR_ZONE_LRU_BASE + lru);
	}
	return size;
}

/*
分配shrinker的空间什么的
 * Add a shrinker callback to be called from the vm.
 */
static int __prealloc_shrinker(struct shrinker *shrinker)
{
	unsigned int size;
	int err;

	if (shrinker->flags & SHRINKER_MEMCG_AWARE) {
		err = prealloc_memcg_shrinker(shrinker);
		if (err != -ENOSYS)
			return err;

		shrinker->flags &= ~SHRINKER_MEMCG_AWARE;
	}

	size = sizeof(*shrinker->nr_deferred);
	if (shrinker->flags & SHRINKER_NUMA_AWARE)
		size *= nr_node_ids;

	shrinker->nr_deferred = kzalloc(size, GFP_KERNEL);
	if (!shrinker->nr_deferred)
		return -ENOMEM;

	return 0;
}

#ifdef CONFIG_SHRINKER_DEBUG
/* 设置shrinker的属性, 分配成员的内存空间 */
int prealloc_shrinker(struct shrinker *shrinker, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	shrinker->name = kvasprintf_const(GFP_KERNEL, fmt, ap);
	va_end(ap);
	if (!shrinker->name)
		return -ENOMEM;

	err = __prealloc_shrinker(shrinker);
	if (err) {
		kfree_const(shrinker->name);
		shrinker->name = NULL;
	}

	return err;
}
#else
int prealloc_shrinker(struct shrinker *shrinker, const char *fmt, ...)
{
	return __prealloc_shrinker(shrinker);
}
#endif

void free_prealloced_shrinker(struct shrinker *shrinker)
{
#ifdef CONFIG_SHRINKER_DEBUG
	kfree_const(shrinker->name);
	shrinker->name = NULL;
#endif
	if (shrinker->flags & SHRINKER_MEMCG_AWARE) {
		down_write(&shrinker_rwsem);
		unregister_memcg_shrinker(shrinker);
		up_write(&shrinker_rwsem);
		return;
	}

	kfree(shrinker->nr_deferred);
	shrinker->nr_deferred = NULL;
}

/* 注册shrinker
添加到全局链表
添加到debugfs */
void register_shrinker_prepared(struct shrinker *shrinker)
{
	down_write(&shrinker_rwsem);
	list_add_tail(&shrinker->list, &shrinker_list);
	shrinker->flags |= SHRINKER_REGISTERED;
	shrinker_debugfs_add(shrinker);
	up_write(&shrinker_rwsem);
}

static int __register_shrinker(struct shrinker *shrinker)
{
	int err = __prealloc_shrinker(shrinker);

	if (err)
		return err;
	register_shrinker_prepared(shrinker);
	return 0;
}

#ifdef CONFIG_SHRINKER_DEBUG
int register_shrinker(struct shrinker *shrinker, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	shrinker->name = kvasprintf_const(GFP_KERNEL, fmt, ap);
	va_end(ap);
	if (!shrinker->name)
		return -ENOMEM;

	err = __register_shrinker(shrinker);
	if (err) {
		kfree_const(shrinker->name);
		shrinker->name = NULL;
	}
	return err;
}
#else
int register_shrinker(struct shrinker *shrinker, const char *fmt, ...)
{
	return __register_shrinker(shrinker);
}
#endif
EXPORT_SYMBOL(register_shrinker);

/*
 * Remove one
 */
void unregister_shrinker(struct shrinker *shrinker)
{
	struct dentry *debugfs_entry;
	int debugfs_id;

	if (!(shrinker->flags & SHRINKER_REGISTERED))
		return;

	down_write(&shrinker_rwsem);
	list_del(&shrinker->list);
	shrinker->flags &= ~SHRINKER_REGISTERED;
	if (shrinker->flags & SHRINKER_MEMCG_AWARE)
		unregister_memcg_shrinker(shrinker);
	debugfs_entry = shrinker_debugfs_detach(shrinker, &debugfs_id);
	up_write(&shrinker_rwsem);

	shrinker_debugfs_remove(debugfs_entry, debugfs_id);

	kfree(shrinker->nr_deferred);
	shrinker->nr_deferred = NULL;
}
EXPORT_SYMBOL(unregister_shrinker);

/**
 * synchronize_shrinkers - Wait for all running shrinkers to complete.
 *
 * This is equivalent to calling unregister_shrink() and register_shrinker(),
 * but atomically and with less overhead. This is useful to guarantee that all
 * shrinker invocations have seen an update, before freeing memory, similar to
 * rcu.
 */
void synchronize_shrinkers(void)
{
	down_write(&shrinker_rwsem);
	up_write(&shrinker_rwsem);
}
EXPORT_SYMBOL(synchronize_shrinkers);

#define SHRINK_BATCH 128

static unsigned long do_shrink_slab(struct shrink_control *shrinkctl,
				    struct shrinker *shrinker, int priority)
{
	unsigned long freed = 0;
	unsigned long long delta;
	long total_scan;
	long freeable;
	long nr;
	long new_nr;
	long batch_size = shrinker->batch ? shrinker->batch
					  : SHRINK_BATCH;
	long scanned = 0, next_deferred;

	freeable = shrinker->count_objects(shrinker, shrinkctl);
	if (freeable == 0 || freeable == SHRINK_EMPTY)
		return freeable;

	/*
	 * copy the current shrinker scan count into a local variable
	 * and zero it so that other concurrent shrinker invocations
	 * don't also do this scanning work.
	 */
	nr = xchg_nr_deferred(shrinker, shrinkctl);

	if (shrinker->seeks) {
		delta = freeable >> priority;
		delta *= 4;
		do_div(delta, shrinker->seeks);
	} else {
		/*
		 * These objects don't require any IO to create. Trim
		 * them aggressively under memory pressure to keep
		 * them from causing refetches in the IO caches.
		 */
		delta = freeable / 2;
	}

	total_scan = nr >> priority;
	total_scan += delta;
	total_scan = min(total_scan, (2 * freeable));

	trace_mm_shrink_slab_start(shrinker, shrinkctl, nr,
				   freeable, delta, total_scan, priority);

	/*
	 * Normally, we should not scan less than batch_size objects in one
	 * pass to avoid too frequent shrinker calls, but if the slab has less
	 * than batch_size objects in total and we are really tight on memory,
	 * we will try to reclaim all available objects, otherwise we can end
	 * up failing allocations although there are plenty of reclaimable
	 * objects spread over several slabs with usage less than the
	 * batch_size.
	 *
	 * We detect the "tight on memory" situations by looking at the total
	 * number of objects we want to scan (total_scan). If it is greater
	 * than the total number of objects on slab (freeable), we must be
	 * scanning at high prio and therefore should try to reclaim as much as
	 * possible.
	 */
	while (total_scan >= batch_size ||
	       total_scan >= freeable) {
		unsigned long ret;
		unsigned long nr_to_scan = min(batch_size, total_scan);

		shrinkctl->nr_to_scan = nr_to_scan;
		shrinkctl->nr_scanned = nr_to_scan;
		ret = shrinker->scan_objects(shrinker, shrinkctl);
		if (ret == SHRINK_STOP)
			break;
		freed += ret;

		count_vm_events(SLABS_SCANNED, shrinkctl->nr_scanned);
		total_scan -= shrinkctl->nr_scanned;
		scanned += shrinkctl->nr_scanned;

		cond_resched();
	}

	/*
	 * The deferred work is increased by any new work (delta) that wasn't
	 * done, decreased by old deferred work that was done now.
	 *
	 * And it is capped to two times of the freeable items.
	 */
	next_deferred = max_t(long, (nr + delta - scanned), 0);
	next_deferred = min(next_deferred, (2 * freeable));

	/*
	 * move the unused scan count back into the shrinker in a
	 * manner that handles concurrent updates.
	 */
	new_nr = add_nr_deferred(next_deferred, shrinker, shrinkctl);

	trace_mm_shrink_slab_end(shrinker, shrinkctl->nid, freed, nr, new_nr, total_scan);
	return freed;
}

#ifdef CONFIG_MEMCG
static unsigned long shrink_slab_memcg(gfp_t gfp_mask, int nid,
			struct mem_cgroup *memcg, int priority)
{
	struct shrinker_info *info;
	unsigned long ret, freed = 0;
	int i;

	if (!mem_cgroup_online(memcg))
		return 0;

	if (!down_read_trylock(&shrinker_rwsem))
		return 0;

	info = shrinker_info_protected(memcg, nid);
	if (unlikely(!info))
		goto unlock;

	for_each_set_bit(i, info->map, info->map_nr_max) {
		struct shrink_control sc = {
			.gfp_mask = gfp_mask,
			.nid = nid,
			.memcg = memcg,
		};
		struct shrinker *shrinker;

		shrinker = idr_find(&shrinker_idr, i);
		if (unlikely(!shrinker || !(shrinker->flags & SHRINKER_REGISTERED))) {
			if (!shrinker)
				clear_bit(i, info->map);
			continue;
		}

		/* Call non-slab shrinkers even though kmem is disabled */
		if (!memcg_kmem_online() &&
		    !(shrinker->flags & SHRINKER_NONSLAB))
			continue;

		ret = do_shrink_slab(&sc, shrinker, priority);
		if (ret == SHRINK_EMPTY) {
			clear_bit(i, info->map);
			/*
			 * After the shrinker reported that it had no objects to
			 * free, but before we cleared the corresponding bit in
			 * the memcg shrinker map, a new object might have been
			 * added. To make sure, we have the bit set in this
			 * case, we invoke the shrinker one more time and reset
			 * the bit if it reports that it is not empty anymore.
			 * The memory barrier here pairs with the barrier in
			 * set_shrinker_bit():
			 *
			 * list_lru_add()     shrink_slab_memcg()
			 *   list_add_tail()    clear_bit()
			 *   <MB>               <MB>
			 *   set_bit()          do_shrink_slab()
			 */
			smp_mb__after_atomic();
			ret = do_shrink_slab(&sc, shrinker, priority);
			if (ret == SHRINK_EMPTY)
				ret = 0;
			else
				set_shrinker_bit(memcg, nid, i);
		}
		freed += ret;

		if (rwsem_is_contended(&shrinker_rwsem)) {
			freed = freed ? : 1;
			break;
		}
	}
unlock:
	up_read(&shrinker_rwsem);
	return freed;
}
#else /* CONFIG_MEMCG */
static unsigned long shrink_slab_memcg(gfp_t gfp_mask, int nid,
			struct mem_cgroup *memcg, int priority)
{
	return 0;
}
#endif /* CONFIG_MEMCG */

/**
 * shrink_slab - shrink slab caches
 * @gfp_mask: allocation context
 * @nid: node whose slab caches to target
 * @memcg: memory cgroup whose slab caches to target
 * @priority: the reclaim priority
 *
 * Call the shrink functions to age shrinkable caches.
 *
 * @nid is passed along to shrinkers with SHRINKER_NUMA_AWARE set,
 * unaware shrinkers will receive a node id of 0 instead.
 *
 * @memcg specifies the memory cgroup to target. Unaware shrinkers
 * are called only if it is the root cgroup.
 *
 * @priority is sc->priority, we take the number of objects and >> by priority
 * in order to get the scan target.
 *
 * Returns the number of reclaimed slab objects.
 */
static unsigned long shrink_slab(gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg,
				 int priority)
{
	unsigned long ret, freed = 0;
	struct shrinker *shrinker;

	/*
	 * The root memcg might be allocated even though memcg is disabled
	 * via "cgroup_disable=memory" boot parameter.  This could make
	 * mem_cgroup_is_root() return false, then just run memcg slab
	 * shrink, but skip global shrink.  This may result in premature
	 * oom.
	 */
	if (!mem_cgroup_disabled() && !mem_cgroup_is_root(memcg))
		return shrink_slab_memcg(gfp_mask, nid, memcg, priority);

	if (!down_read_trylock(&shrinker_rwsem))
		goto out;

	list_for_each_entry(shrinker, &shrinker_list, list) {
		struct shrink_control sc = {
			.gfp_mask = gfp_mask,
			.nid = nid,
			.memcg = memcg,
		};

		ret = do_shrink_slab(&sc, shrinker, priority);
		if (ret == SHRINK_EMPTY)
			ret = 0;
		freed += ret;
		/*
		 * Bail out if someone want to register a new shrinker to
		 * prevent the registration from being stalled for long periods
		 * by parallel ongoing shrinking.
		 */
		if (rwsem_is_contended(&shrinker_rwsem)) {
			freed = freed ? : 1;
			break;
		}
	}

	up_read(&shrinker_rwsem);
out:
	cond_resched();
	return freed;
}

static unsigned long drop_slab_node(int nid)
{
	unsigned long freed = 0;
	struct mem_cgroup *memcg = NULL;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		freed += shrink_slab(GFP_KERNEL, nid, memcg, 0);
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);

	return freed;
}

void drop_slab(void)
{
	int nid;
	int shift = 0;
	unsigned long freed;

	do {
		freed = 0;
		for_each_online_node(nid) {
			if (fatal_signal_pending(current))
				return;

			freed += drop_slab_node(nid);
		}
	} while ((freed >> shift++) > 1);
}
/* 判断reclaimer的类型
就是不同的reclaimer有不同的offset

 */
static int reclaimer_offset(void)
{
	BUILD_BUG_ON(PGSTEAL_DIRECT - PGSTEAL_KSWAPD !=
			PGDEMOTE_DIRECT - PGDEMOTE_KSWAPD);
	BUILD_BUG_ON(PGSTEAL_DIRECT - PGSTEAL_KSWAPD !=
			PGSCAN_DIRECT - PGSCAN_KSWAPD);
	BUILD_BUG_ON(PGSTEAL_KHUGEPAGED - PGSTEAL_KSWAPD !=
			PGDEMOTE_KHUGEPAGED - PGDEMOTE_KSWAPD);
	BUILD_BUG_ON(PGSTEAL_KHUGEPAGED - PGSTEAL_KSWAPD !=
			PGSCAN_KHUGEPAGED - PGSCAN_KSWAPD);

	if (current_is_kswapd())
		return 0;
	if (current_is_khugepaged())
		return PGSTEAL_KHUGEPAGED - PGSTEAL_KSWAPD;
	return PGSTEAL_DIRECT - PGSTEAL_KSWAPD;
}

static inline int is_page_cache_freeable(struct folio *folio)
{
	/*
	 * A freeable page cache folio is referenced only by the caller
	 * that isolated the folio, the page cache and optional filesystem
	 * private data at folio->private.
	 */
	return folio_ref_count(folio) - folio_test_private(folio) ==
		1 + folio_nr_pages(folio);
}

/*
 * We detected a synchronous write error writing a folio out.  Probably
 * -ENOSPC.  We need to propagate that into the address_space for a subsequent
 * fsync(), msync() or close().
 *
 * The tricky part is that after writepage we cannot touch the mapping: nothing
 * prevents it from being freed up.  But we have a ref on the folio and once
 * that folio is locked, the mapping is pinned.
 *
 * We're allowed to run sleeping folio_lock() here because we know the caller has
 * __GFP_FS.
 */
static void handle_write_error(struct address_space *mapping,
				struct folio *folio, int error)
{
	folio_lock(folio);
	if (folio_mapping(folio) == mapping)
		mapping_set_error(mapping, error);
	folio_unlock(folio);
}
/*

返回真:
1. kswapd不起作用了
2. write_pending的页面还不多, 可回收页面比较多
  */
/* todddo */
static bool skip_throttle_noprogress(pg_data_t *pgdat)
{
	int reclaimable = 0, write_pending = 0;
	int i;

	/*
	 * If kswapd is disabled, reschedule if necessary but do not
	 * throttle as the system is likely near OOM.
	 kswapd无法发挥作用了,返回true
	 */
	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
		return true;

	/*
	 * If there are a lot of dirty/writeback folios then do not
	 * throttle as throttling will occur when the folios cycle
	 * towards the end of the LRU if still under writeback.
	 如果有很多脏或者回写的页面,就不throttle.
	 因为这些页面如何到lru的end的时候还在回写中,就会自动throttle.
	 */
	for (i = 0; i < MAX_NR_ZONES; i++) {
		struct zone *zone = pgdat->node_zones + i;

		if (!managed_zone(zone))
			continue;

		reclaimable += zone_reclaimable_pages(zone);
		write_pending += zone_page_state_snapshot(zone,
						  NR_ZONE_WRITE_PENDING);
	}
	if (2 * write_pending <= reclaimable)
		return true;

	return false;
}
/* 回收过程中调用此函数来限流自己, 会根据状态来决定是否实质限流.
挂到队列上阻塞, 
--------------------
写回脏页也会调用此进行必要的限流
  */
/* todddo */
void reclaim_throttle(pg_data_t *pgdat, enum vmscan_throttle_state reason)
{
	wait_queue_head_t *wqh = &pgdat->reclaim_wait[reason];
	long timeout, ret;
	DEFINE_WAIT(wait);

	/*
	 * Do not throttle user workers, kthreads other than kswapd or
	 * workqueues. They may be required for reclaim to make
	 * forward progress (e.g. journalling workqueues or kthreads).
	不限流除kswapd之外的内核线程
	 不throttle这些进程
	 */
	if (!current_is_kswapd() &&
	    current->flags & (PF_USER_WORKER|PF_KTHREAD)) {
		
		cond_resched();

		return;
	}

	/*
	 * These figures are pulled out of thin air.
		这些数字是凭空想象出来的
	 * VMSCAN_THROTTLE_ISOLATED is a transient condition based on too many
	 * parallel reclaimers which is a short-lived event so the timeout is
	 * short. Failing to make progress or waiting on writeback are
	 * potentially long-lived events so use a longer timeout. This is shaky
	 * logic as a failure to make progress could be due to anything from
	 * writeback to a slow device to excessive referenced folios at the tail
	 * of the inactive LRU. 
	 VMSCAN_THROTTLE_ISOLATED是一个短暂的条件,基于太多的很快结束的并行回收者,所以超时时间很短.
	 失败或者等待回写是潜在的长期事件,所以使用更长的超时时间.
	 这是一个摇摆的逻辑,因为进展的失败可能是由于任何事情引起的,从回写到慢设备到在
	 不活跃LRU的尾部的过多引用的folio.

	 */
	switch(reason) {
	case VMSCAN_THROTTLE_WRITEBACK:
	//这个是因为回写过多,所以限流回收进程?
		timeout = HZ/10;

		if (atomic_inc_return(&pgdat->nr_writeback_throttled) == 1) {
			/* 如果刚才还没有被限流的, 自己是第一个 */
			WRITE_ONCE(pgdat->nr_reclaim_start,
				node_page_state(pgdat, NR_THROTTLED_WRITTEN));
		}

		break;
	case VMSCAN_THROTTLE_CONGESTED:
		fallthrough;
	case VMSCAN_THROTTLE_NOPROGRESS:
		if (skip_throttle_noprogress(pgdat)) {/* 
		1. kswapd不起作用了
		2. write_pending的页面还不多, 可回收页面比较多
		*/
			cond_resched();
			return;
		}
		/* kswap还ok
		write pending比较多 */
		timeout = 1;

		break;
	case VMSCAN_THROTTLE_ISOLATED:
		timeout = HZ/50;
		break;
	default:
		WARN_ON_ONCE(1);
		timeout = HZ;
		break;
	}
	/* 浅浅调度一下,等一会儿 */
	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);

	ret = schedule_timeout(timeout);
	finish_wait(wqh, &wait);

	//这里是睡醒了
	if (reason == VMSCAN_THROTTLE_WRITEBACK)
		atomic_dec(&pgdat->nr_writeback_throttled);

	trace_mm_vmscan_throttled(pgdat->node_id, jiffies_to_usecs(timeout),
				jiffies_to_usecs(timeout - ret),
				reason);
}

/*
 * Account for folios written if tasks are throttled waiting on dirty
 * folios to clean. If enough folios have been cleaned since throttling
 * started then wakeup the throttled tasks.
   记录写回的folio,如果有足够多的folio被写回了,就唤醒等待的进程

 */
void __acct_reclaim_writeback(pg_data_t *pgdat, struct folio *folio,
							int nr_throttled)
{
	unsigned long nr_written;

	node_stat_add_folio(folio, NR_THROTTLED_WRITTEN);

	/*
	 * This is an inaccurate read as the per-cpu deltas may not
	 * be synchronised. However, given that the system is
	 * writeback throttled, it is not worth taking the penalty
	 * of getting an accurate count. At worst, the throttle
	 * timeout guarantees forward progress.
	   这是一个不准确的读取,因为per-cpu的增量可能不同步.
	   但是,鉴于系统被写回限流,不值得付出获取准确计数的代价.
	   最坏的情况下,限流超时保证了向前的进展.

	 */
	nr_written = node_page_state(pgdat, NR_THROTTLED_WRITTEN) -
		READ_ONCE(pgdat->nr_reclaim_start);

	if (nr_written > SWAP_CLUSTER_MAX * nr_throttled)
		wake_up(&pgdat->reclaim_wait[VMSCAN_THROTTLE_WRITEBACK]);
}

/* possible outcome of pageout() */
typedef enum {
	/* failed to write folio out, folio is locked */
	PAGE_KEEP,
	/* move folio to the active list, folio is locked */
	PAGE_ACTIVATE,
	/* folio has been sent to the disk successfully, folio is unlocked */
	PAGE_SUCCESS,
	/* folio is clean and locked */
	PAGE_CLEAN,
} pageout_t;

/*
 * pageout is called by shrink_folio_list() for each dirty folio.
 * Calls ->writepage().
 */
static pageout_t pageout(struct folio *folio, struct address_space *mapping,
			 struct swap_iocb **plug)
{
	/*
	 * If the folio is dirty, only perform writeback if that write
	 * will be non-blocking.  To prevent this allocation from being
	 * stalled by pagecache activity.  But note that there may be
	 * stalls if we need to run get_block().  We could test
	 * PagePrivate for that.
	 * 如果是脏folio, 仅仅在不阻塞的情况下回写, 
	   为了防止内存分配被pagecache干扰

	 * If this process is currently in __generic_file_write_iter() against
	 * this folio's queue, we can perform writeback even if that
	 * will block.
	 * 如果当前进程就是执行vfs的写入回调, 即使阻塞也会回写
	 * If the folio is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	   如果是交换页, 即使阻塞也会回写.
	 */
	if (!is_page_cache_freeable(folio))
		return PAGE_KEEP;
	if (!mapping) {
		/*
		 * Some data journaling orphaned folios can have
		 * folio->mapping == NULL while being dirty with clean buffers.
		 */
		if (folio_test_private(folio)) {
			if (try_to_free_buffers(folio)) {
				folio_clear_dirty(folio);
				pr_info("%s: orphaned folio\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	if (mapping->a_ops->writepage == NULL)
		return PAGE_ACTIVATE;

	if (folio_clear_dirty_for_io(folio)) {
		int res;
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.for_reclaim = 1,
			.swap_plug = plug,
		};

		folio_set_reclaim(folio);
		res = mapping->a_ops->writepage(&folio->page, &wbc);
		if (res < 0)
			handle_write_error(mapping, folio, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			folio_clear_reclaim(folio);
			return PAGE_ACTIVATE;
		}

		if (!folio_test_writeback(folio)) {
			/* synchronous write or broken a_ops? */
			folio_clear_reclaim(folio);
		}
		trace_mm_vmscan_write_folio(folio);
		node_stat_add_folio(folio, NR_VMSCAN_WRITE);
		return PAGE_SUCCESS;
	}

	return PAGE_CLEAN;
}

/*
 从mapping移除folio
 * Same as remove_mapping, but if the folio is removed from the mapping, it
 * gets returned with a refcount of 0.
 */
static int __remove_mapping(struct address_space *mapping, struct folio *folio,
			    bool reclaimed, struct mem_cgroup *target_memcg)
{
	int refcount;
	void *shadow = NULL;

	BUG_ON(!folio_test_locked(folio));
	BUG_ON(mapping != folio_mapping(folio));

	if (!folio_test_swapcache(folio))
		spin_lock(&mapping->host->i_lock);

	xa_lock_irq(&mapping->i_pages);
	/*
	 * The non racy check for a busy folio.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the folio, it may be possible that they dirty it then
	 * drop the reference. So if the dirty flag is tested before the
	 * refcount here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!folio_test_dirty(folio)    [good]
	 * folio_set_dirty(folio);
	 * folio_put(folio);
	 *				!refcount(folio)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the folio->flags
	 * load is not satisfied before that of folio->_refcount.
	 *
	 * Note that if the dirty flag is always set via folio_mark_dirty,
	 * and thus under the i_pages lock, then this ordering is not required.
	 */
	refcount = 1 + folio_nr_pages(folio);
	if (!folio_ref_freeze(folio, refcount))
		goto cannot_free;
	/* note: atomic_cmpxchg in folio_ref_freeze provides the smp_rmb */
	if (unlikely(folio_test_dirty(folio))) {
		folio_ref_unfreeze(folio, refcount);
		goto cannot_free;
	}

	if (folio_test_swapcache(folio)) {
		swp_entry_t swap = folio->swap;

		if (reclaimed && !mapping_exiting(mapping))
			shadow = workingset_eviction(folio, target_memcg);
		__delete_from_swap_cache(folio, swap, shadow);
		mem_cgroup_swapout(folio, swap);
		xa_unlock_irq(&mapping->i_pages);
		put_swap_folio(folio, swap);
	} else {
		void (*free_folio)(struct folio *);

		free_folio = mapping->a_ops->free_folio;
		/*
		 * Remember a shadow entry for reclaimed file cache in
		 * order to detect refaults, thus thrashing, later on.
		 *
		 * But don't store shadows in an address space that is
		 * already exiting.  This is not just an optimization,
		 * inode reclaim needs to empty out the radix tree or
		 * the nodes are lost.  Don't plant shadows behind its
		 * back.
		 *
		 * We also don't store shadows for DAX mappings because the
		 * only page cache folios found in these are zero pages
		 * covering holes, and because we don't want to mix DAX
		 * exceptional entries and shadow exceptional entries in the
		 * same address_space.
		 */
		if (reclaimed && folio_is_file_lru(folio) &&
		    !mapping_exiting(mapping) && !dax_mapping(mapping))
			shadow = workingset_eviction(folio, target_memcg);
		__filemap_remove_folio(folio, shadow);
		xa_unlock_irq(&mapping->i_pages);
		if (mapping_shrinkable(mapping))
			inode_add_lru(mapping->host);
		spin_unlock(&mapping->host->i_lock);

		if (free_folio)
			free_folio(folio);
	}

	return 1;

cannot_free:
	xa_unlock_irq(&mapping->i_pages);
	if (!folio_test_swapcache(folio))
		spin_unlock(&mapping->host->i_lock);
	return 0;
}

/**
 从mapping移除folio
 * remove_mapping() - Attempt to remove a folio from its mapping.
 * @mapping: The address space.
 * @folio: The folio to remove.
 *
 * If the folio is dirty, under writeback or if someone else has a ref
 * on it, removal will fail.
 * Return: The number of pages removed from the mapping.  0 if the folio
 * could not be removed.
 * Context: The caller should have a single refcount on the folio and
 * hold its lock.
 */
long remove_mapping(struct address_space *mapping, struct folio *folio)
{
	if (__remove_mapping(mapping, folio, false, NULL)) {
		/*
		 * Unfreezing the refcount with 1 effectively
		 * drops the pagecache ref for us without requiring another
		 * atomic operation.
		 */
		folio_ref_unfreeze(folio, 1);
		return folio_nr_pages(folio);
	}
	return 0;
}

/**
把isolate的folio返回合适的lru
 * folio_putback_lru - Put previously isolated folio onto appropriate LRU list.
 * @folio: Folio to be returned to an LRU list.
 *
 * Add previously isolated @folio to appropriate LRU list.
 * The folio may still be unevictable for other reasons.
 *
 * Context: lru_lock must not be held, interrupts must be enabled.
 */
void folio_putback_lru(struct folio *folio)
{
	folio_add_lru(folio);
	folio_put(folio);		/* drop ref from isolate */
}
/*  */
enum folio_references {
	FOLIOREF_RECLAIM,
	FOLIOREF_RECLAIM_CLEAN,
	FOLIOREF_KEEP,
	FOLIOREF_ACTIVATE,
};
/* 获取folio的映射情况? */
static enum folio_references folio_check_references(struct folio *folio,
						  struct scan_control *sc)
{
	int referenced_ptes, referenced_folio;
	unsigned long vm_flags;

	referenced_ptes = folio_referenced(folio, 1, sc->target_mem_cgroup,
					   &vm_flags);
	/* 刚才是不是被referenced */				   
	referenced_folio = folio_test_clear_referenced(folio);

	/*
	 * The supposedly reclaimable folio was found to be in a VM_LOCKED vma.
	 * Let the folio, now marked Mlocked, be moved to the unevictable list.
	 */
	if (vm_flags & VM_LOCKED)
		return FOLIOREF_ACTIVATE;

	/* rmap lock contention: rotate */
	if (referenced_ptes == -1)
		return FOLIOREF_KEEP;

	if (referenced_ptes) {
		/*
		 * All mapped folios start out with page table
		 * references from the instantiating fault, so we need
		 * to look twice if a mapped file/anon folio is used more
		 * than once.
		 *
		 * Mark it and spare it for another trip around the
		 * inactive list.  Another page table reference will
		 * lead to its activation.
		 *
		 * Note: the mark is set for activated folios as well
		 * so that recently deactivated but used folios are
		 * quickly recovered.
		 */
		folio_set_referenced(folio);

		if (referenced_folio || referenced_ptes > 1)
			return FOLIOREF_ACTIVATE;

		/*
		 * Activate file-backed executable folios after first usage.
		 */
		if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio))
			return FOLIOREF_ACTIVATE;

		return FOLIOREF_KEEP;
	}

	/* Reclaim if clean, defer dirty folios to writeback */
	if (referenced_folio && folio_is_file_lru(folio))
		return FOLIOREF_RECLAIM_CLEAN;

	return FOLIOREF_RECLAIM;
}

/* 
检查一个folio是否dirty或者在写回
Check if a folio is dirty or under writeback */
static void folio_check_dirty_writeback(struct folio *folio,
				       bool *dirty, bool *writeback)
{
	struct address_space *mapping;

	/*
	 * Anonymous folios are not handled by flushers and must be written
	 * from reclaim context. Do not stall reclaim based on them.
	 * MADV_FREE anonymous folios are put into inactive file list too.
	 * They could be mistakenly treated as file lru. So further anon
	 * test is needed.
	 flusher不处理匿名页, 所以匿名页在
	 */
	if (!folio_is_file_lru(folio) ||
	    (folio_test_anon(folio) && !folio_test_swapbacked(folio))) {/* 如果
		如果是swap_backed,
		或者不是swapbacked, 但是匿名页 */
		*dirty = false;
		*writeback = false;
		return;
	}

	/* 到这里不是swapbacked 并且  */

	/* By default assume that the folio flags are accurate */
	*dirty = folio_test_dirty(folio);
	*writeback = folio_test_writeback(folio);

	/* Verify dirty/writeback state if the filesystem supports it */
	if (!folio_test_private(folio))
		return;

	mapping = folio_mapping(folio);

	if (mapping && mapping->a_ops->is_dirty_writeback)
		mapping->a_ops->is_dirty_writeback(folio, dirty, writeback);
}

static struct folio *alloc_demote_folio(struct folio *src,
		unsigned long private)
{
	struct folio *dst;
	nodemask_t *allowed_mask;
	struct migration_target_control *mtc;

	mtc = (struct migration_target_control *)private;

	allowed_mask = mtc->nmask;
	/*
	 * make sure we allocate from the target node first also trying to
	 * demote or reclaim pages from the target node via kswapd if we are
	 * low on free memory on target node. If we don't do this and if
	 * we have free memory on the slower(lower) memtier, we would start
	 * allocating pages from slower(lower) memory tiers without even forcing
	 * a demotion of cold pages from the target memtier. This can result
	 * in the kernel placing hot pages in slower(lower) memory tiers.
	 */
	mtc->nmask = NULL;
	mtc->gfp_mask |= __GFP_THISNODE;
	dst = alloc_migration_target(src, (unsigned long)mtc);
	if (dst)
		return dst;

	mtc->gfp_mask &= ~__GFP_THISNODE;
	mtc->nmask = allowed_mask;

	return alloc_migration_target(src, (unsigned long)mtc);
}

/*
 * Take folios on @demote_folios and attempt to demote them to another node.
 * Folios which are not demoted are left on @demote_folios.
 */
static unsigned int demote_folio_list(struct list_head *demote_folios,
				     struct pglist_data *pgdat)
{
	int target_nid = next_demotion_node(pgdat->node_id);
	unsigned int nr_succeeded;
	nodemask_t allowed_mask;

	struct migration_target_control mtc = {
		/*
		 * Allocate from 'node', or fail quickly and quietly.
		 * When this happens, 'page' will likely just be discarded
		 * instead of migrated.
		 */
		.gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) | __GFP_NOWARN |
			__GFP_NOMEMALLOC | GFP_NOWAIT,
		.nid = target_nid,
		.nmask = &allowed_mask
	};

	if (list_empty(demote_folios))
		return 0;

	if (target_nid == NUMA_NO_NODE)
		return 0;

	node_get_allowed_targets(pgdat, &allowed_mask);

	/* Demotion ignores all cpuset and mempolicy settings */
	migrate_pages(demote_folios, alloc_demote_folio, NULL,
		      (unsigned long)&mtc, MIGRATE_ASYNC, MR_DEMOTION,
		      &nr_succeeded);

	__count_vm_events(PGDEMOTE_KSWAPD + reclaimer_offset(), nr_succeeded);

	return nr_succeeded;
}

/* 判断设置了此@gfp的(回收, 分配?)操作来操作folio是否需要与fs交互? */
static bool may_enter_fs(struct folio *folio, gfp_t gfp_mask)
{
	if (gfp_mask & __GFP_FS)
		return true;

	if (!folio_test_swapcache(folio) || !(gfp_mask & __GFP_IO))
		return false;
	/* folio_test_swapcache && __GFP_IO , return true */
	/*
	 * We can "enter_fs" for swap-cache with only __GFP_IO
	 * providing this isn't SWP_FS_OPS.
	 * ->flags can be updated non-atomicially (scan_swap_map_slots),
	 * but that will never affect SWP_FS_OPS, so the data_race
	 * is safe.
	 */
	return !data_race(folio_swap_flags(folio) & SWP_FS_OPS);
}

/*
回收@folio_list的页面
 * shrink_folio_list() returns the number of reclaimed pages
 */
static unsigned int shrink_folio_list(struct list_head *folio_list,
		struct pglist_data *pgdat, struct scan_control *sc,
		struct reclaim_stat *stat, bool ignore_references)
{
	LIST_HEAD(ret_folios);
	LIST_HEAD(free_folios);
	LIST_HEAD(demote_folios);
	unsigned int nr_reclaimed = 0;
	unsigned int pgactivate = 0;
	bool do_demote_pass;
	struct swap_iocb *plug = NULL;

	memset(stat, 0, sizeof(*stat));
	cond_resched();
	do_demote_pass = can_demote(pgdat->node_id, sc);

retry:
	while (!list_empty(folio_list)) {
		struct address_space *mapping;
		struct folio *folio;
		enum folio_references references = FOLIOREF_RECLAIM;
		bool dirty, writeback;
		unsigned int nr_pages;

		cond_resched();
		/* 取出一个folio */
		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);

		if (!folio_trylock(folio)) //锁住页面本身的flag
			goto keep;

		VM_BUG_ON_FOLIO(folio_test_active(folio), folio);

		nr_pages = folio_nr_pages(folio);

		/* Account the number of base pages */
		sc->nr_scanned += nr_pages;

		if (unlikely(!folio_evictable(folio)))
			goto activate_locked;
		
		/* 如果不回收mapped的页面 */
		if (!sc->may_unmap && folio_mapped(folio))
			goto keep_locked;

		/* 不是mapped, 或者可以unmap */
		/* folio_update_gen() tried to promote this page? */
		/* todddo 看来mglru开启情况下, 大多数情况都不回收mapped, 即使开启了may_unmap*/

		if (lru_gen_enabled() && !ignore_references &&
		    folio_mapped(folio) && folio_test_referenced(folio))
			goto keep_locked;



		/*
		 * The number of dirty pages determines if a node is marked
		 * reclaim_congested. kswapd will stall and start writing
		 * folios if the tail of the LRU is all dirty unqueued folios.
		脏页的数量决定node是否被标记为reclaim_congested,

		 */
		folio_check_dirty_writeback(folio, &dirty, &writeback);

		if (dirty || writeback) //发现脏页
			stat->nr_dirty += nr_pages;

		if (dirty && !writeback)  //发现未被回写的脏页
			stat->nr_unqueued_dirty += nr_pages;

		/*
		 * Treat this folio as congested if folios are cycling
		 * through the LRU so quickly that the folios marked
		 * for immediate reclaim are making it to the end of
		 * the LRU a second time.
			folio_test_reclaim说明见过一次, 并且现在还在回写
			所以认为是congested了
		 */
		if (writeback && folio_test_reclaim(folio))
			stat->nr_congested += nr_pages;

		/*
		 * If a folio at the tail of the LRU is under writeback, there
		 * are three cases to consider.
		 * 如果lru尾部的page正在回写, 有三种情况需要考虑
		 * 1) If reclaim is encountering an excessive number
		 *    of folios under writeback and this folio has both
		 *    the writeback and reclaim flags set, then it
		 *    indicates that folios are being queued for I/O but
		 *    are being recycled through the LRU before the I/O
		 *    can complete. Waiting on the folio itself risks an
		 *    indefinite stall if it is impossible to writeback
		 *    the folio due to I/O error or disconnected storage
		 *    so instead note that the LRU is being scanned too
		 *    quickly and the caller can stall after the folio
		 *    list has been processed.
		 * 如果回收遇到了过多的正在回写的folio,并且这个folio有回写和回收标记,
		 * 那么这表明folio正在排队进行I/O,但是在I/O完成之前又被回收到LRU中.
		 * 如果此时等待folio本身会导致无限期的停顿,如果由于I/O错误或断开的存储而无法回写
		 * folio,
		 	因此请注意LRU正在被扫描得太快,调用者可以在folio列表处理完后停顿.

		 * 2) Global or new memcg reclaim encounters a folio that is
		 *    not marked for immediate reclaim, or the caller does not
		 *    have __GFP_FS (or __GFP_IO if it's simply going to swap,
		 *    not to fs). In this case mark the folio for immediate
		 *    reclaim and continue scanning.
		 *	  遇到了page(没有直接回收标记, 调用者没有设置gfp_fs,gfp_io),这种情况
		 		把page标记为直接回收,然后继续扫描.
				因为可能需要fs,所以需要may_enter_fs() 	
		 *    Require may_enter_fs() because we would wait on fs, which
		 *    may not have submitted I/O yet. And the loop driver might
		 *    enter reclaim, and deadlock if it waits on a folio for
		 *    which it is needed to do the write (loop masks off
		 *    __GFP_IO|__GFP_FS for this reason); but more thought
		 *    would probably show more reasons.
		 * 全局或者新的memcg回收遇到了一个没有标记为immediate reclaim的folio,
		 或者调用者没有__GFP_FS(或者__GFP_IO 如果调用者只是想swap,并不是写回)
		 在这种情况下,标记folio为immediate reclaim,然后继续扫描.
		 需要may_enter_fs()因为我们会等待fs,而且可能还没有提交I/O.
		 并且loop driver可能进入回收,并且在等待一个folio上死锁,而这个folio是需要写入的
		 (loop为了这个原因屏蔽了__GFP_IO|__GFP_FS);
		 *
		 * 3) Legacy memcg encounters a folio that already has the
		 *    reclaim flag set. memcg does not have any dirty folio
		 *    throttling so we could easily OOM just because too many
		 *    folios are in writeback and there is nothing else to
		 *    reclaim. Wait for the writeback to complete.
		 *
		 * In cases 1) and 2) we activate the folios to get them out of
		 * the way while we continue scanning for clean folios on the
		 * inactive list and refilling from the active list. The
		 * observation here is that waiting for disk writes is more
		 * expensive than potentially causing reloads down the line.
		 * Since they're marked for immediate reclaim, they won't put
		 * memory pressure on the cache working set any longer than it
		 * takes to write them to disk.
		 情况1和2里面我们先不考虑这个folio,去处理后续的干净folio.
		 */
		if (folio_test_writeback(folio)) {/* 正在写回的情况? */
			/* Case 1 above */
			if (current_is_kswapd() && 
			    folio_test_reclaim(folio) &&
			    test_bit(PGDAT_WRITEBACK, &pgdat->flags)) {
					/* 对于kswap来说, 现在node很多回写,并且这个页面已经是第二次遇见了, 去处理下一个 */
				stat->nr_immediate += nr_pages;
				goto activate_locked;

			/* Case 2 above */
			} else if (writeback_throttling_sane(sc) ||
			    !folio_test_reclaim(folio) ||
			    !may_enter_fs(folio, sc->gfp_mask)) {/* 正在回写的页面没有reclaim 标记? */
					/* 遇到了page(没有回收标记, 或者调用者没有设置gfp_fs,gfp_io),
					这种情况把page标记为直接回收,然后继续扫描.因为可能需要fs,所以
					需要may_enter_fs() */
				/*
				   可能是因为发生了竞争,此时刚刚会写完,end_wb正在工作一半可能.
				 * This is slightly racy -
				 * folio_end_writeback() might have
				 * just cleared the reclaim flag, then
				 * setting the reclaim flag here ends up
				 * interpreted as the readahead flag - but
				 * that does not matter enough to care.
				 * What we do want is for this folio to
				 * have the reclaim flag set next time
				 * memcg reclaim reaches the tests above,
				 * so it will then wait for writeback to
				 * avoid OOM; and it's also appropriate
				 * in global reclaim.
				 */
				folio_set_reclaim(folio);
				stat->nr_writeback += nr_pages;
				goto activate_locked;

			/* Case 3 above */
			} else {/* 等待回写完成, 过会儿再试 */
				folio_unlock(folio);
				folio_wait_writeback(folio);
				/* then go back and try same folio again */
				/*  */
				list_add_tail(&folio->lru, folio_list);
				continue;
			}
		}


		if (!ignore_references)
			references = folio_check_references(folio, sc);

		switch (references) {
		case FOLIOREF_ACTIVATE:
			goto activate_locked;
		case FOLIOREF_KEEP:
			stat->nr_ref_keep += nr_pages;
			goto keep_locked;

		case FOLIOREF_RECLAIM:
		case FOLIOREF_RECLAIM_CLEAN:
			; /* try to reclaim the folio below */
		}

		/*
		 * Before reclaiming the folio, try to relocate
		 * its contents to another node.
		 */
		if (do_demote_pass &&
		    (thp_migration_supported() || !folio_test_large(folio))) {
			list_add(&folio->lru, &demote_folios);
			folio_unlock(folio);
			continue;
		}

		/*
		 * Anonymous process memory has backing store?
		 * Try to allocate it some swap space here.
		 * Lazyfree folio could be freed directly
		   匿名页有交换空间? 尝试在这里分配一些交换空间.
		   lazyfree folio可以直接释放.
		 */
		if (folio_test_anon(folio) && folio_test_swapbacked(folio)) {/* 如果是交换匿名页 */
			if (!folio_test_swapcache(folio)) { /* 如果仅仅只在swap file? */
				if (!(sc->gfp_mask & __GFP_IO))
					goto keep_locked;

				if (folio_maybe_dma_pinned(folio))
					goto keep_locked;

				if (folio_test_large(folio)) {
					/* cannot split folio, skip it */
					if (!can_split_folio(folio, NULL))
						goto activate_locked;
					/*
					 * Split folios without a PMD map right
					 * away. Chances are some or all of the
					 * tail pages can be freed without IO.
					 */
					if (!folio_entire_mapcount(folio) &&
					    split_folio_to_list(folio,
								folio_list))
						goto activate_locked;
				}
				/* 给folio分配swp cache 空间?*/
				if (!add_to_swap(folio)) {/*  */
					if (!folio_test_large(folio))
						goto activate_locked_split;
					/* Fallback to swap normal pages */
					if (split_folio_to_list(folio,
								folio_list))
						goto activate_locked;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
					count_vm_event(THP_SWPOUT_FALLBACK);
#endif
					if (!add_to_swap(folio))
						goto activate_locked_split;
				}
			}

		} else 
		/* 如果是被交换的其他大页?比如shmem的大页 */
		if (folio_test_swapbacked(folio) &&
			   folio_test_large(folio)) {/* 如果是多页面的交换页 */
			/* Split shmem folio */
			if (split_folio_to_list(folio, folio_list))
				goto keep_locked;
		}

		/*
		 * If the folio was split above, the tail pages will make
		 * their own pass through this function and be accounted
		 * then.
		 */
		if ((nr_pages > 1) && !folio_test_large(folio)) {
			sc->nr_scanned -= (nr_pages - 1);
			nr_pages = 1;
		}

		/*
		 * The folio is mapped into the page tables of one or more
		 * processes. Try to unmap it here.
		 */
		if (folio_mapped(folio)) {/* 如果是被mapped */
			enum ttu_flags flags = TTU_BATCH_FLUSH;
			bool was_swapbacked = folio_test_swapbacked(folio);

			if (folio_test_pmd_mappable(folio))
				flags |= TTU_SPLIT_HUGE_PMD;

			try_to_unmap(folio, flags);

			if (folio_mapped(folio)) {/* 还是mapped? 失败情况.  */
				stat->nr_unmap_fail += nr_pages;
				if (!was_swapbacked &&
				    folio_test_swapbacked(folio))
					stat->nr_lazyfree_fail += nr_pages;
				goto activate_locked;
			}
		}

		/*
		 * Folio is unmapped now so it cannot be newly pinned anymore.
		 * No point in trying to reclaim folio if it is pinned.
		 * Furthermore we don't want to reclaim underlying fs metadata
		 * if the folio is pinned and thus potentially modified by the
		 * pinning process as that may upset the filesystem.
		 */
		if (folio_maybe_dma_pinned(folio))
			goto activate_locked;
		mapping = folio_mapping(folio);
		if (folio_test_dirty(folio)) {/* 如果是dirty页面.  */
			/* Only kswapd can writeback filesystem folios
			 * to avoid risk of stack overflow. 
			 只有kswapd回写dirty
			 But avoid injecting inefficient single-folio I/O into
			 * flusher writeback as much as possible: only
			 * write folios when we've encountered many
			 * dirty folios, and when we've already scanned
			 * the rest of the LRU for clean folios and see
			 * the same dirty folios again (with the reclaim
			 * flag set).
			 尽可能的避免回收单个dirty,可能会影响IO.
			 所以只在看到很多dirty, 并且在把其他的clean page扫描完成之后,再次看到这个dirty之后,才回收这个dirty.
			具体是说,第一次看到dirty的时候,不直接回收,而是设置此page的reclaim 
			flag后,去处理下一个页面.等把其他的clean扫描完之后, 再次扫描到这个dirty(已经设置了reclaim
			flag), 才回收这个dirty.
			 */
			if (folio_is_file_lru(folio) &&
			    (!current_is_kswapd() ||
			     !folio_test_reclaim(folio) ||
			     !test_bit(PGDAT_DIRTY, &pgdat->flags))) {/* 
				 如果是文件页, 
				 然后只要自己不是kswapd, 或者这个dirty没有reclaim flag, 或者node还没有很脏, 
				 就先放弃这个dirty.*/
				/* Immediately reclaim when written back.
				 * Similar in principle to folio_deactivate()
				 * except we already have the folio isolated
				 * and know it's dirty
				 */
				node_stat_mod_folio(folio, NR_VMSCAN_IMMEDIATE,
						nr_pages);
				folio_set_reclaim(folio);
				goto activate_locked;
			}
			/* 下面是准备写回.  */
			/* 走到这里就说明, kswap要在node很脏的情况下回收这个已经被扫描过一次的dirty了 */
			if (references == FOLIOREF_RECLAIM_CLEAN)
				goto keep_locked;
			if (!may_enter_fs(folio, sc->gfp_mask))
				goto keep_locked;
			if (!sc->may_writepage)
				goto keep_locked;
			/*Folio is dirty. Flush the TLB if a writable entry
			 * potentially exists to avoid CPU writes after I/O
			 * starts and then write it out here.
			 */
			try_to_unmap_flush_dirty();
			switch (pageout(folio, mapping, &plug)) {
			case PAGE_KEEP:
				goto keep_locked;
			case PAGE_ACTIVATE:
				goto activate_locked;
			case PAGE_SUCCESS:
				stat->nr_pageout += nr_pages;

				if (folio_test_writeback(folio))
					goto keep;
				if (folio_test_dirty(folio))
					goto keep;

				/*
				 * A synchronous write - probably a ramdisk.  Go
				 * ahead and try to reclaim the folio.
				 */
				if (!folio_trylock(folio))
					goto keep;
				if (folio_test_dirty(folio) ||
				    folio_test_writeback(folio))
					goto keep_locked;
				mapping = folio_mapping(folio);
				fallthrough;
			case PAGE_CLEAN:
				; /* try to free the folio below */
			}
		}

		/*
		 * If the folio has buffers, try to free the buffer
		 * mappings associated with this folio. If we succeed
		 * we try to free the folio as well.
		 *
		 * We do this even if the folio is dirty.
		 * filemap_release_folio() does not perform I/O, but it
		 * is possible for a folio to have the dirty flag set,
		 * but it is actually clean (all its buffers are clean).
		 * This happens if the buffers were written out directly,
		 * with submit_bh(). ext3 will do this, as well as
		 * the blockdev mapping.  filemap_release_folio() will
		 * discover that cleanness and will drop the buffers
		 * and mark the folio clean - it can be freed.
		 *
		 * Rarely, folios can have buffers and no ->mapping.
		 * These are the folios which were not successfully
		 * invalidated in truncate_cleanup_folio().  We try to
		 * drop those buffers here and if that worked, and the
		 * folio is no longer mapped into process address space
		 * (refcount == 1) it can be freed.  Otherwise, leave
		 * the folio on the LRU so it is swappable.
		 */
		if (folio_needs_release(folio)) {
			if (!filemap_release_folio(folio, sc->gfp_mask))
				goto activate_locked;
			if (!mapping && folio_ref_count(folio) == 1) {
				folio_unlock(folio);
				if (folio_put_testzero(folio))
					goto free_it;
				else {
					/*
					 * rare race with speculative reference.
					 * the speculative reference will free
					 * this folio shortly, so we may
					 * increment nr_reclaimed here (and
					 * leave it off the LRU).
					 */
					nr_reclaimed += nr_pages;
					continue;
				}
			}
		}

		if (folio_test_anon(folio) && !folio_test_swapbacked(folio)) {
			/* follow __remove_mapping for reference */
			if (!folio_ref_freeze(folio, 1))
				goto keep_locked;
			/*
			 * The folio has only one reference left, which is
			 * from the isolation. After the caller puts the
			 * folio back on the lru and drops the reference, the
			 * folio will be freed anyway. It doesn't matter
			 * which lru it goes on. So we don't bother checking
			 * the dirty flag here.
			 */
			count_vm_events(PGLAZYFREED, nr_pages);
			count_memcg_folio_events(folio, PGLAZYFREED, nr_pages);
		} else if (!mapping || !__remove_mapping(mapping, folio, true,
							 sc->target_mem_cgroup))
			goto keep_locked;

		folio_unlock(folio);
free_it:
		/*
		 * Folio may get swapped out as a whole, need to account
		 * all pages in it.
		 */
		nr_reclaimed += nr_pages;

		/*
		 * Is there need to periodically free_folio_list? It would
		 * appear not as the counts should be low
		 */
		if (unlikely(folio_test_large(folio)))
			destroy_large_folio(folio);
		else
			list_add(&folio->lru, &free_folios);
		continue;

activate_locked_split:
		/*
		 * The tail pages that are failed to add into swap cache
		 * reach here.  Fixup nr_scanned and nr_pages.
		 */
		if (nr_pages > 1) {
			sc->nr_scanned -= (nr_pages - 1);
			nr_pages = 1;
		}
activate_locked:
/* 需要保留的情况? 这里是lock之后遇到了,比如
不打算写回的脏页, 保留
无法unmap
unevictable的页面 */
		/* Not a candidate for swapping, so reclaim swap space. */
		if (folio_test_swapcache(folio) &&
		    (mem_cgroup_swap_full(folio) || folio_test_mlocked(folio)))
			folio_free_swap(folio);
		VM_BUG_ON_FOLIO(folio_test_active(folio), folio);
		if (!folio_test_mlocked(folio)) {
			int type = folio_is_file_lru(folio);
			folio_set_active(folio);
			stat->nr_activate[type] += nr_pages;
			count_memcg_folio_events(folio, PGACTIVATE, nr_pages);
		}
keep_locked:
/* 加锁之后需要keep的情况,
比如不能unmap页面 */
		folio_unlock(folio);

keep:
/* 这里是保留不回收, 可能因为
1, 无法lock */
		list_add(&folio->lru, &ret_folios);
		VM_BUG_ON_FOLIO(folio_test_lru(folio) ||
				folio_test_unevictable(folio), folio);
	}
	/* 'folio_list' is always empty here */

	/* Migrate folios selected for demotion */
	nr_reclaimed += demote_folio_list(&demote_folios, pgdat);
	/* Folios that could not be demoted are still in @demote_folios */
	if (!list_empty(&demote_folios)) {
		/* Folios which weren't demoted go back on @folio_list */
		list_splice_init(&demote_folios, folio_list);

		/*
		 * goto retry to reclaim the undemoted folios in folio_list if
		 * desired.
		 *
		 * Reclaiming directly from top tier nodes is not often desired
		 * due to it breaking the LRU ordering: in general memory
		 * should be reclaimed from lower tier nodes and demoted from
		 * top tier nodes.
		 *
		 * However, disabling reclaim from top tier nodes entirely
		 * would cause ooms in edge scenarios where lower tier memory
		 * is unreclaimable for whatever reason, eg memory being
		 * mlocked or too hot to reclaim. We can disable reclaim
		 * from top tier nodes in proactive reclaim though as that is
		 * not real memory pressure.
		 */
		if (!sc->proactive) {
			do_demote_pass = false;
			goto retry;
		}
	}

	pgactivate = stat->nr_activate[0] + stat->nr_activate[1];

	mem_cgroup_uncharge_list(&free_folios);
	try_to_unmap_flush();
	free_unref_page_list(&free_folios);

	list_splice(&ret_folios, folio_list);
	count_vm_events(PGACTIVATE, pgactivate);

	if (plug)
		swap_write_unplug(plug);

	return nr_reclaimed;
}

unsigned int reclaim_clean_pages_from_list(struct zone *zone,
					   struct list_head *folio_list)
{
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.may_unmap = 1,
	};
	struct reclaim_stat stat;
	unsigned int nr_reclaimed;
	struct folio *folio, *next;
	LIST_HEAD(clean_folios);
	unsigned int noreclaim_flag;

	list_for_each_entry_safe(folio, next, folio_list, lru) {
		if (!folio_test_hugetlb(folio) && folio_is_file_lru(folio) &&
		    !folio_test_dirty(folio) && !__folio_test_movable(folio) &&
		    !folio_test_unevictable(folio)) {
			folio_clear_active(folio);
			list_move(&folio->lru, &clean_folios);
		}
	}

	/*
	 * We should be safe here since we are only dealing with file pages and
	 * we are not kswapd and therefore cannot write dirty file pages. But
	 * call memalloc_noreclaim_save() anyway, just in case these conditions
	 * change in the future.
	 */
	noreclaim_flag = memalloc_noreclaim_save();
	nr_reclaimed = shrink_folio_list(&clean_folios, zone->zone_pgdat, &sc,
					&stat, true);
	memalloc_noreclaim_restore(noreclaim_flag);

	list_splice(&clean_folios, folio_list);
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE,
			    -(long)nr_reclaimed);
	/*
	 * Since lazyfree pages are isolated from file LRU from the beginning,
	 * they will rotate back to anonymous LRU in the end if it failed to
	 * discard so isolated count will be mismatched.
	 * Compensate the isolated count for both LRU lists.
	 */
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_ANON,
			    stat.nr_lazyfree_fail);
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE,
			    -(long)stat.nr_lazyfree_fail);
	return nr_reclaimed;
}

/*
 * Update LRU sizes after isolating pages. The LRU size updates must
 * be complete before mem_cgroup_update_lru_size due to a sanity check.
 */
static __always_inline void update_lru_sizes(struct lruvec *lruvec,
			enum lru_list lru, unsigned long *nr_zone_taken)
{
	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
	}

}

#ifdef CONFIG_CMA
/*
 * It is waste of effort to scan and reclaim CMA pages if it is not available
 * for current allocation context. Kswapd can not be enrolled as it can not
 * distinguish this scenario by using sc->gfp_mask = GFP_KERNEL
 */
static bool skip_cma(struct folio *folio, struct scan_control *sc)
{
	return !current_is_kswapd() &&
			gfp_migratetype(sc->gfp_mask) != MIGRATE_MOVABLE &&
			get_pageblock_migratetype(&folio->page) == MIGRATE_CMA;
}
#else
static bool skip_cma(struct folio *folio, struct scan_control *sc)
{
	return false;
}
#endif

/*
从lruvec进行isolate页面到dst.
try_get, 清除lru之后, 加入dst
 * Isolating page from the lruvec to fill in @dst list by nr_to_scan times.
 *
 * lruvec->lru_lock is heavily contended.  Some of the functions that
 * shrink the lists perform better by taking out a batch of pages
 * and working on them outside the LRU lock.
 *
 * For pagecache intensive workloads, this function is the hottest
 * spot in the kernel (apart from copy_*_user functions).
 *
 * Lru_lock must be held before calling this function.
 *
 * @nr_to_scan:	The number of eligible pages to look through on the list.
 * @lruvec:	The LRU vector to pull pages from.
 * @dst:	The temp list to put pages on to.
 * @nr_scanned:	The number of pages that were scanned.
 * @sc:		The scan_control struct for this reclaim session
 * @lru:	LRU list id for isolating
 *
 * returns how many pages were moved onto *@dst.
 */
static unsigned long isolate_lru_folios(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct list_head *dst,
		unsigned long *nr_scanned, struct scan_control *sc,
		enum lru_list lru)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_taken = 0;
	unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
	/* 记录zone的跳过页面的数量 */
	unsigned long nr_skipped[MAX_NR_ZONES] = { 0, };
	unsigned long skipped = 0;
	unsigned long scan, total_scan, nr_pages;
	LIST_HEAD(folios_skipped);

	total_scan = 0;
	scan = 0;

	while (scan < nr_to_scan && !list_empty(src)) {/* 遍历nr_to_scan次数, */
		struct list_head *move_to = src;
		struct folio *folio;

		folio = lru_to_folio(src);

		prefetchw_prev_lru_folio(folio, src, flags);
		/* 获取folio的页面数量 */
		nr_pages = folio_nr_pages(folio);
		total_scan += nr_pages;

		if (folio_zonenum(folio) > sc->reclaim_idx ||
				skip_cma(folio, sc)) {/* 这里是跳过的逻辑 */

			nr_skipped[folio_zonenum(folio)] += nr_pages;
			move_to = &folios_skipped;/* 这个路径的move是到folios_skipped */
			goto move;
		}

		/*
		 * Do not count skipped folios because that makes the function
		 * return with no isolated folios if the LRU mostly contains
		 * ineligible folios.  This causes the VM to not reclaim any
		 * folios, triggering a premature OOM.
		 * Account all pages in a folio.
		 */
		scan += nr_pages;

		if (!folio_test_lru(folio))
			goto move;

		if (!sc->may_unmap && folio_mapped(folio))
			goto move;

		/*
		 * Be careful not to clear the lru flag until after we're
		 * sure the folio is not being freed elsewhere -- the
		 * folio release code relies on it.
		 */

		 /* 先tryget : 
		 然后clear lru : 需要防止race */
		if (unlikely(!folio_try_get(folio)))
			goto move;

		if (!folio_test_clear_lru(folio)) {
			/* Another thread is already isolating this folio */
			folio_put(folio);
			goto move;
		}

		nr_taken += nr_pages;
		nr_zone_taken[folio_zonenum(folio)] += nr_pages;
		move_to = dst;/* 这里是move到dst */

move:/* 默认的move是move到src */
		list_move(&folio->lru, move_to);
	}

	/*
	 * Splice any skipped folios to the start of the LRU list. Note that
	 * this disrupts the LRU order when reclaiming for lower zones but
	 * we cannot splice to the tail. If we did then the SWAP_CLUSTER_MAX
	 * scanning would soon rescan the same folios to skip and waste lots
	 * of cpu cycles.
	 */
	if (!list_empty(&folios_skipped)) {/* 如果skipped链表,也被move了页面,
	这里处理.
	是说明这里面有跳过的页面. */
		int zid;

		list_splice(&folios_skipped, src);
		/* 处理每一个有跳过页面的zone */
		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
			if (!nr_skipped[zid])
				continue;

			__count_zid_vm_events(PGSCAN_SKIP, zid, nr_skipped[zid]);
			skipped += nr_skipped[zid];
		}
	}

	/* 返回本次扫描了多少页面 */
	*nr_scanned = total_scan;
	trace_mm_vmscan_lru_isolate(sc->reclaim_idx, sc->order, nr_to_scan,
				    total_scan, skipped, nr_taken,
				    sc->may_unmap ? 0 : ISOLATE_UNMAPPED, lru);
	update_lru_sizes(lruvec, lru, nr_zone_taken);
	return nr_taken;
}

/**
 * folio_isolate_lru() - Try to isolate a folio from its LRU list.
 * @folio: Folio to isolate from its LRU list.
 *
 * Isolate a @folio from an LRU list and adjust the vmstat statistic
 * corresponding to whatever LRU list the folio was on.
 *
 * The folio will have its LRU flag cleared.  If it was found on the
 * active list, it will have the Active flag set.  If it was found on the
 * unevictable list, it will have the Unevictable flag set.  These flags
 * may need to be cleared by the caller before letting the page go.
 *
 * Context:
 *
 * (1) Must be called with an elevated refcount on the folio. This is a
 *     fundamental difference from isolate_lru_folios() (which is called
 *     without a stable reference).
 * (2) The lru_lock must not be held.
 * (3) Interrupts must be enabled.
 *
 * Return: true if the folio was removed from an LRU list.
 * false if the folio was not on an LRU list.
 */
bool folio_isolate_lru(struct folio *folio)
{
	bool ret = false;

	VM_BUG_ON_FOLIO(!folio_ref_count(folio), folio);

	if (folio_test_clear_lru(folio)) {
		struct lruvec *lruvec;

		folio_get(folio);
		lruvec = folio_lruvec_lock_irq(folio);
		lruvec_del_folio(lruvec, folio);
		unlock_page_lruvec_irq(lruvec);
		ret = true;
	}

	return ret;
}

/*
 * A direct reclaimer may isolate SWAP_CLUSTER_MAX pages from the LRU list and
 * then get rescheduled. When there are massive number of tasks doing page
 * allocation, such sleeping direct reclaimers may keep piling up on each CPU,
 * the LRU list will go small and be scanned faster than necessary, leading to
 * unnecessary swapping, thrashing and OOM.
 直接回收可能会隔离出一些页面,但是之后被调度睡眠
 如果有很多这种直接回收过程,可能会堆积大量页面
 */
static int too_many_isolated(struct pglist_data *pgdat, int file,
		struct scan_control *sc)
{
	unsigned long inactive, isolated;
	bool too_many;

	if (current_is_kswapd())
		return 0;

	if (!writeback_throttling_sane(sc))
		return 0;

	if (file) {
		inactive = node_page_state(pgdat, NR_INACTIVE_FILE);
		isolated = node_page_state(pgdat, NR_ISOLATED_FILE);
	} else {
		inactive = node_page_state(pgdat, NR_INACTIVE_ANON);
		isolated = node_page_state(pgdat, NR_ISOLATED_ANON);
	}

	/*
	 * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
	 * won't get blocked by normal direct-reclaimers, forming a circular
	 * deadlock.
	 */
	if (gfp_has_io_fs(sc->gfp_mask))
		inactive >>= 3;

	too_many = isolated > inactive;

	/* Wake up tasks throttled due to too_many_isolated. */
	if (!too_many)
		wake_throttle_isolated(pgdat);

	return too_many;
}

/*
把list里面的folio重新加入lruvec.
如果是unevictable, 就putback
如果put之后无人引用了, free
然后执行add folio
============
返回的时候, list里面是需要free的page
 * move_folios_to_lru() moves folios from private @list to appropriate LRU list.
 * On return, @list is reused as a list of folios to be freed by the caller.
 *
 * Returns the number of pages moved to the given lruvec.
 */
static unsigned int move_folios_to_lru(struct lruvec *lruvec,
		struct list_head *list)
{
	int nr_pages, nr_moved = 0;
	LIST_HEAD(folios_to_free);/* 这里存储加入lru之前发现没人引用了的folio */

	while (!list_empty(list)) {
		/* 取一个folio */
		struct folio *folio = lru_to_folio(list);

		VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
		/* 移出此folio */
		list_del(&folio->lru);

		if (unlikely(!folio_evictable(folio))) {/* 如果folio是unevictable */
			spin_unlock_irq(&lruvec->lru_lock);
			/* 放回lru */
			folio_putback_lru(folio);
			spin_lock_irq(&lruvec->lru_lock);
			continue;
		}

		/*
		 * The folio_set_lru needs to be kept here for list integrity.
		 * Otherwise:
		 *   #0 move_folios_to_lru             #1 release_pages
		 *   if (!folio_put_testzero())
		 *				      if (folio_put_testzero())
		 *				        !lru //skip lru_lock
		 *     folio_set_lru()
		 *     list_add(&folio->lru,)
		 *                                        list_add(&folio->lru,)
		 */
		folio_set_lru(folio);

		if (unlikely(folio_put_testzero(folio))) {/* 如果put之后
		就没人引用了 */
			__folio_clear_lru_flags(folio);

			if (unlikely(folio_test_large(folio))) {
				spin_unlock_irq(&lruvec->lru_lock);
				destroy_large_folio(folio);
				spin_lock_irq(&lruvec->lru_lock);
			} else
				list_add(&folio->lru, &folios_to_free);

			continue;
		}

		/*
		 * All pages were isolated from the same lruvec (and isolation
		 * inhibits memcg migration).
		 */
		VM_BUG_ON_FOLIO(!folio_matches_lruvec(folio, lruvec), folio);

		lruvec_add_folio(lruvec, folio);
		nr_pages = folio_nr_pages(folio);
		nr_moved += nr_pages;
		if (folio_test_active(folio))
			workingset_age_nonresident(lruvec, nr_pages);
	}

	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&folios_to_free, list);

	return nr_moved;
}

/*
 * If a kernel thread (such as nfsd for loop-back mounts) services a backing
 * device by writing to the page cache it sets PF_LOCAL_THROTTLE. In this case
 * we should not throttle.  Otherwise it is safe to do so.
 */
static int current_may_throttle(void)
{
	return !(current->flags & PF_LOCAL_THROTTLE);
}

/*
回收页面
 * shrink_inactive_list() is a helper for shrink_node().  It returns the number
 * of reclaimed pages
 */
static unsigned long shrink_inactive_list(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct scan_control *sc,
		enum lru_list lru)
{
	LIST_HEAD(folio_list);
	unsigned long nr_scanned;
	unsigned int nr_reclaimed = 0;
	unsigned long nr_taken;
	struct reclaim_stat stat;
	bool file = is_file_lru(lru);
	enum vm_event_item item;
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	bool stalled = false;

	while (unlikely(too_many_isolated(pgdat, file, sc))) {
		if (stalled)
			return 0;

		/* wait a bit for the reclaimer. */
		stalled = true;
		reclaim_throttle(pgdat, VMSCAN_THROTTLE_ISOLATED);

		/* We are about to die and free our memory. Return now. */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);
	
	/* isolate页面到folio_list */
	nr_taken = isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	
	item = PGSCAN_KSWAPD + reclaimer_offset();
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, nr_scanned);

	__count_memcg_events(lruvec_memcg(lruvec), item, nr_scanned);
	__count_vm_events(PGSCAN_ANON + file, nr_scanned);

	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0)
		return 0;

	/* 这里开始回收isolate的folio */
	nr_reclaimed = shrink_folio_list(&folio_list, pgdat, sc, &stat, false);

	spin_lock_irq(&lruvec->lru_lock);
	move_folios_to_lru(lruvec, &folio_list);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	item = PGSTEAL_KSWAPD + reclaimer_offset();
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, nr_reclaimed);
	__count_memcg_events(lruvec_memcg(lruvec), item, nr_reclaimed);
	__count_vm_events(PGSTEAL_ANON + file, nr_reclaimed);
	spin_unlock_irq(&lruvec->lru_lock);

	lru_note_cost(lruvec, file, stat.nr_pageout, nr_scanned - nr_reclaimed);
	mem_cgroup_uncharge_list(&folio_list);
	free_unref_page_list(&folio_list);

	/*
	 * If dirty folios are scanned that are not queued for IO, it
	 * implies that flushers are not doing their job. This can
	 * happen when memory pressure pushes dirty folios to the end of
	 * the LRU before the dirty limits are breached and the dirty
	 * data has expired. It can also happen when the proportion of
	 * dirty folios grows not through writes but through memory
	 * pressure reclaiming all the clean cache. And in some cases,
	 * the flushers simply cannot keep up with the allocation
	 * rate. Nudge the flusher threads in case they are asleep.
	   有未被IO的脏页多说明flusher可能没有工作好
	   发生这个,可能是因为内存压力, 也可能是因为由于回收干净页太多, 导致脏页比例
	   相对变高, 
	   所以这里唤醒一次

	 */
	if (stat.nr_unqueued_dirty == nr_taken) {
		wakeup_flusher_threads(WB_REASON_VMSCAN);
		/*
		 * For cgroupv1 dirty throttling is achieved by waking up
		 * the kernel flusher here and later waiting on folios
		 * which are in writeback to finish (see shrink_folio_list()).
		 *
		 * Flusher may not be able to issue writeback quickly
		 * enough for cgroupv1 writeback throttling to work
		 * on a large system .
		 */
		if (!writeback_throttling_sane(sc))
			reclaim_throttle(pgdat, VMSCAN_THROTTLE_WRITEBACK);
	}

	sc->nr.dirty += stat.nr_dirty;
	sc->nr.congested += stat.nr_congested;
	sc->nr.unqueued_dirty += stat.nr_unqueued_dirty;
	sc->nr.writeback += stat.nr_writeback;
	sc->nr.immediate += stat.nr_immediate;
	sc->nr.taken += nr_taken;
	if (file)
		sc->nr.file_taken += nr_taken;

	trace_mm_vmscan_lru_shrink_inactive(pgdat->node_id,
			nr_scanned, nr_reclaimed, &stat, sc->priority, file);

	return nr_reclaimed;
}

/*
2024年09月09日17:08:15
 * shrink_active_list() moves folios from the active LRU to the inactive LRU.
 *
 * We move them the other way if the folio is referenced by one or more
 * processes.
 *
 * If the folios are mostly unmapped, the processing is fast and it is
 * appropriate to hold lru_lock across the whole operation.  But if
 * the folios are mapped, the processing is slow (folio_referenced()), so
 * we should drop lru_lock around each folio.  It's impossible to balance
 * this, so instead we remove the folios from the LRU while processing them.
 * It is safe to rely on the active flag against the non-LRU folios in here
 * because nobody will play with that bit on a non-LRU folio.
 *
 * The downside is that we have to touch folio->_refcount against each folio.
 * But we had to alter folio->flags anyway.
 */
static void shrink_active_list(unsigned long nr_to_scan,
			       struct lruvec *lruvec,
			       struct scan_control *sc,
			       enum lru_list lru)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	LIST_HEAD(l_hold);	/* The folios which were snipped off */
	LIST_HEAD(l_active); /* 存储从l_hold里面"拯救"的folio? */
	LIST_HEAD(l_inactive);
	unsigned nr_deactivate, nr_activate;
	unsigned nr_rotated = 0;
	int file = is_file_lru(lru);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);

	/* isolate页面(清除lru标记)到l_hold */
	nr_taken = isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	if (!cgroup_reclaim(sc))
		__count_vm_events(PGREFILL, nr_scanned);

	__count_memcg_events(lruvec_memcg(lruvec), PGREFILL, nr_scanned);

	spin_unlock_irq(&lruvec->lru_lock);

	while (!list_empty(&l_hold)) {/* 逐个处理isolate取下的页面 */
		struct folio *folio;

		cond_resched();
		folio = lru_to_folio(&l_hold);
		list_del(&folio->lru);

		if (unlikely(!folio_evictable(folio))) {
			folio_putback_lru(folio);
			continue;
		}

		if (unlikely(buffer_heads_over_limit)) {
			if (folio_needs_release(folio) &&
			    folio_trylock(folio)) { /* 如果有priv ,并且需要释放 */
				filemap_release_folio(folio, 0);
				folio_unlock(folio);
			}
		}

		/* Referenced or rmap lock contention: rotate */
		if (folio_referenced(folio, 0, sc->target_mem_cgroup,
				     &vm_flags) != 0) {/* 如果有pte映射folio */
			/*
			 * Identify referenced, file-backed active folios and
			 * give them one more trip around the active list. So
			 * that executable code get better chances to stay in
			 * memory under moderate memory pressure.  Anon folios
			 * are not likely to be evicted by use-once streaming
			 * IO, plus JVM can create lots of anon VM_EXEC folios,
			 * so we ignore them here.
			 */
			if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {

				nr_rotated += folio_nr_pages(folio);
				/* 不移到inactive, 反而移到active.  */
				list_add(&folio->lru, &l_active);
				continue;
			}
		}

		folio_clear_active(folio);	/* we are de-activating */
		folio_set_workingset(folio);

		/* 加入到inactive */
		list_add(&folio->lru, &l_inactive);
	}

	/*
	 * Move folios back to the lru list.
	 */
	spin_lock_irq(&lruvec->lru_lock);
	/* 把这些要active或者inactive的folio, 放回去 */
	nr_activate = move_folios_to_lru(lruvec, &l_active);
	nr_deactivate = move_folios_to_lru(lruvec, &l_inactive);
	/* list里面余下的都是放回过程中发现是free的 */
	/* Keep all free folios in l_active list */
	/* 把free的集中到一起 */
	list_splice(&l_inactive, &l_active);

	__count_vm_events(PGDEACTIVATE, nr_deactivate);
	__count_memcg_events(lruvec_memcg(lruvec), PGDEACTIVATE, nr_deactivate);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);


	if (nr_rotated)
		lru_note_cost(lruvec, file, 0, nr_rotated);
	
	/* 现在l_active里面都是free的, 无人引用的, 准备free */
	mem_cgroup_uncharge_list(&l_active);

	free_unref_page_list(&l_active);
	trace_mm_vmscan_lru_shrink_active(pgdat->node_id, nr_taken, nr_activate,
			nr_deactivate, nr_rotated, sc->priority, file);
}

static unsigned int reclaim_folio_list(struct list_head *folio_list,
				      struct pglist_data *pgdat)
{
	struct reclaim_stat dummy_stat;
	unsigned int nr_reclaimed;
	struct folio *folio;
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.no_demotion = 1,
	};

	nr_reclaimed = shrink_folio_list(folio_list, pgdat, &sc, &dummy_stat, false);
	while (!list_empty(folio_list)) {
		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}

	return nr_reclaimed;
}

unsigned long reclaim_pages(struct list_head *folio_list)
{
	int nid;
	unsigned int nr_reclaimed = 0;
	LIST_HEAD(node_folio_list);
	unsigned int noreclaim_flag;

	if (list_empty(folio_list))
		return nr_reclaimed;

	noreclaim_flag = memalloc_noreclaim_save();

	nid = folio_nid(lru_to_folio(folio_list));
	do {
		struct folio *folio = lru_to_folio(folio_list);

		if (nid == folio_nid(folio)) {
			folio_clear_active(folio);
			list_move(&folio->lru, &node_folio_list);
			continue;
		}

		nr_reclaimed += reclaim_folio_list(&node_folio_list, NODE_DATA(nid));
		nid = folio_nid(lru_to_folio(folio_list));
	} while (!list_empty(folio_list));

	nr_reclaimed += reclaim_folio_list(&node_folio_list, NODE_DATA(nid));

	memalloc_noreclaim_restore(noreclaim_flag);

	return nr_reclaimed;
}
/* 回收lru页面 */
static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
				 struct lruvec *lruvec, struct scan_control *sc)
{
	if (is_active_lru(lru)) {
		if (sc->may_deactivate & (1 << is_file_lru(lru)))
			shrink_active_list(nr_to_scan, lruvec, sc, lru);
		else
			sc->skipped_deactivate = 1;
		return 0;
	}

	return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
}

/*
看看lruvec这个lru类型的inactive的数量是不是过少了.
 * The inactive anon list should be small enough that the VM never has
 * to do too much work.
 *
 * The inactive file list should be small enough to leave most memory
 * to the established workingset on the scan-resistant active list,
 * but large enough to avoid thrashing the aggregate readahead window.
 *
 * Both inactive lists should also be large enough that each inactive
 * folio has a chance to be referenced again before it is reclaimed.
 *
 * If that fails and refaulting is observed, the inactive list grows.
 *
 * The inactive_ratio is the target ratio of ACTIVE to INACTIVE folios
 * on this LRU, maintained by the pageout code. An inactive_ratio
 * of 3 means 3:1 or 25% of the folios are kept on the inactive list.
 *
 * total     target    max
 * memory    ratio     inactive
 * -------------------------------------
 *   10MB       1         5MB
 *  100MB       1        50MB
 *    1GB       3       250MB
 *   10GB      10       0.9GB
 *  100GB      31         3GB
 *    1TB     101        10GB
 *   10TB     320        32GB
 */
static bool inactive_is_low(struct lruvec *lruvec, enum lru_list inactive_lru)
{
	enum lru_list active_lru = inactive_lru + LRU_ACTIVE;
	unsigned long inactive, active;
	unsigned long inactive_ratio;
	unsigned long gb;

	inactive = lruvec_page_state(lruvec, NR_LRU_BASE + inactive_lru);
	active = lruvec_page_state(lruvec, NR_LRU_BASE + active_lru);

	gb = (inactive + active) >> (30 - PAGE_SHIFT);
	if (gb)
		inactive_ratio = int_sqrt(10 * gb);
	else
		inactive_ratio = 1;

	return inactive * inactive_ratio < active;
}

/*  */
enum scan_balance {
	SCAN_EQUAL, /* 匿名和文件页都回收 */
	SCAN_FRACT,
	SCAN_ANON, /* 回收过程扫描匿名页 */ 
	SCAN_FILE, /* 回收过程不让swap , 扫描文件页 */
};
/* 2024年09月11日11:28:06
与sc的may_deactivate有关.
根据node的情况设置了一些sc的属性.
 */
static void prepare_scan_count(pg_data_t *pgdat, struct scan_control *sc)
{
	unsigned long file;
	struct lruvec *target_lruvec;

	if (lru_gen_enabled())
		return;

	target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);

	/*
	 * Flush the memory cgroup stats, so that we read accurate per-memcg
	 * lruvec stats for heuristics.
	 */
	mem_cgroup_flush_stats();

	/*
	 * Determine the scan balance between anon and file LRUs.
	 取得对匿名页和文件页的偏好?
	 */
	spin_lock_irq(&target_lruvec->lru_lock);
	sc->anon_cost = target_lruvec->anon_cost;
	sc->file_cost = target_lruvec->file_cost;
	spin_unlock_irq(&target_lruvec->lru_lock);

	/*
	下面是计算是否可以deactivate,以及针对的类型
	 * Target desirable inactive:active list ratios for the anon
	 * and file LRU lists.
	 */
	if (!sc->force_deactivate) {
		/* 如果不是强制deactivate, 下面分别计算然后决定要不要deactivate匿名页
		或者文件页 */
		unsigned long refaults;

		/*
		 * When refaults are being observed, it means a new
		 * workingset is being established. Deactivate to get
		 * rid of any stale active pages quickly.
		 */

		/* 先计算是否强制deactivate匿名页 
		2024年10月17日17:27:27*/
		refaults = lruvec_page_state(target_lruvec,
				WORKINGSET_ACTIVATE_ANON);
		if (refaults != target_lruvec->refaults[WORKINGSET_ANON] ||
			inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
			sc->may_deactivate |= DEACTIVATE_ANON; /* 可以deactivate匿名页 */
		else
			sc->may_deactivate &= ~DEACTIVATE_ANON;


		refaults = lruvec_page_state(target_lruvec,
				WORKINGSET_ACTIVATE_FILE);
		if (refaults != target_lruvec->refaults[WORKINGSET_FILE] ||
		    inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
			sc->may_deactivate |= DEACTIVATE_FILE;
		else
			sc->may_deactivate &= ~DEACTIVATE_FILE;

	} else /* 如果是强制deactivate, 就置位两者,表示都可以强制inactive.   */
		sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;



	/*
	 * If we have plenty of inactive file pages that aren't
	 * thrashing, try to reclaim those first before touching
	 * anonymous pages.

	 */
	file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
	if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE))
		sc->cache_trim_mode = 1; /* 有很多非活跃文件页, 并且sc不进行deactivate */
	else
		sc->cache_trim_mode = 0;

	/*
	 * Prevent the reclaimer from falling into the cache trap:
	 防止回收落入陷阱
	  as cache pages start out inactive, every cache fault will tip
	 * the scan balance towards the file LRU.  And as the file LRU
	 * shrinks, so does the window for rotation from references.
	 ?????
	 * This means we have a runaway feedback loop where a tiny
	 * thrashing file LRU becomes infinitely more attractive than
	 * anon pages.  
	 ???
	 Try to detect this based on file LRU size.

	 */
	if (!cgroup_reclaim(sc)) {/* 如果是全局回收的话 */
		unsigned long total_high_wmark = 0;
		unsigned long free, anon;
		int z;

		free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
		file = node_page_state(pgdat, NR_ACTIVE_FILE) +
			   node_page_state(pgdat, NR_INACTIVE_FILE);

		/* 统计每个区的高水位之和? */
		for (z = 0; z < MAX_NR_ZONES; z++) {
			struct zone *zone = &pgdat->node_zones[z];

			if (!managed_zone(zone))
				continue;

			total_high_wmark += high_wmark_pages(zone);
		}


		/*
		 * Consider anon: if that's low too, this isn't a
		 * runaway file reclaim problem, but rather just
		 * extreme pressure. Reclaim as per usual then.
		 */
		anon = node_page_state(pgdat, NR_INACTIVE_ANON);

		sc->file_is_tiny =
			file + free <= total_high_wmark &&  /* 文件页空闲页低于高水位, 是否可以说明匿名页偏多? */
			!(sc->may_deactivate & DEACTIVATE_ANON) && /* 并且不能deactivate匿名页 */
			anon >> sc->priority; /* 匿名页确实挺多 */
	}
}

/*
非mglru情况下, 根据sc回收此lruvec时获取扫描和回收的数量.
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.
 *2024年10月14日17:27:04
 * nr[0] = anon inactive folios to scan;
   nr[1] = anon active folios to scan
 * nr[2] = file inactive folios to scan;
   nr[3] = file active folios to scan
 */
static void get_scan_count(struct lruvec *lruvec, struct scan_control *sc,
			   unsigned long *nr)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	unsigned long anon_cost, file_cost, total_cost;
	int swappiness = mem_cgroup_swappiness(memcg);
	u64 fraction[ANON_AND_FILE];
	u64 denominator = 0;	/* gcc */
	enum scan_balance scan_balance;
	unsigned long ap, fp;
	enum lru_list lru;

	/* If we have no swap space, do not bother scanning anon folios. */
	if (!sc->may_swap || !can_reclaim_anon_pages(memcg, pgdat->node_id, sc)) {/* 如果不能交换,
	或者没有交换空间了.  */
		scan_balance = SCAN_FILE;
		goto out;
	}

	/* 到这里说明 可以swap并且可以can_reclaim_anon_pages */

	/*
	 * Global reclaim will swap to prevent OOM even with no
	 * swappiness, but memcg users want to use this knob to
	 * disable swapping for individual groups completely when
	 * using the memory controller's swap limit feature would be
	 * too expensive.
	 全局回收将会进行交换以防止OOM，即使没有swappiness，
	 但memcg希望使用swappiness来完全禁用单个组的交换，
	 当使用内存控制器的交换限制功能成本过高时。
	 */
	if (cgroup_reclaim(sc) && !swappiness) {/* cgroup不让swap */
		scan_balance = SCAN_FILE;
		goto out;
	}


	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 回收压力很大了, 不做平衡了, 匿名和文件都扫描
	 */
	if (!sc->priority && swappiness) {
		scan_balance = SCAN_EQUAL;
		goto out;
	}

	/*
	 * If the system is almost out of file pages, force-scan anon.
	 系统文件页不多了, 扫描匿名页
	 */
	if (sc->file_is_tiny) {
		scan_balance = SCAN_ANON;
		goto out;
	}

	/*
	 * If there is enough inactive page cache, we do not reclaim
	 * anything from the anonymous working right now.
	 系统还有很多不活跃的文件页
	 */
	if (sc->cache_trim_mode) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	scan_balance = SCAN_FRACT;
	/*
	 * Calculate the pressure balance between anon and file pages.
	 *
	 * The amount of pressure we put on each LRU is inversely
	 * proportional to the cost of reclaiming each list, as
	 * determined by the share of pages that are refaulting, times
	 * the relative IO cost of bringing back a swapped out
	 * anonymous page vs reloading a filesystem page (swappiness).
	 *
	 * Although we limit that influence to ensure no list gets
	 * left behind completely: at least a third of the pressure is
	 * applied, before swappiness.
	 *
	 * With swappiness at 100, anon and file have equal IO cost.
	 */
	total_cost = sc->anon_cost + sc->file_cost;
	anon_cost = total_cost + sc->anon_cost;
	file_cost = total_cost + sc->file_cost;
	total_cost = anon_cost + file_cost;

	ap = swappiness * (total_cost + 1);
	ap /= anon_cost + 1;

	fp = (200 - swappiness) * (total_cost + 1);
	fp /= file_cost + 1;

	fraction[0] = ap;
	fraction[1] = fp;
	denominator = ap + fp;


out:
	for_each_evictable_lru(lru) {
		int file = is_file_lru(lru);
		unsigned long lruvec_size;
		unsigned long low, min;
		unsigned long scan;

		lruvec_size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);

		mem_cgroup_protection(sc->target_mem_cgroup, memcg,
				      &min, &low);

		if (min || low) {
			/*
			 * Scale a cgroup's reclaim pressure by proportioning
			 * its current usage to its memory.low or memory.min
			 * setting.
			 *
			 * This is important, as otherwise scanning aggression
			 * becomes extremely binary -- from nothing as we
			 * approach the memory protection threshold, to totally
			 * nominal as we exceed it.  This results in requiring
			 * setting extremely liberal protection thresholds. It
			 * also means we simply get no protection at all if we
			 * set it too low, which is not ideal.
			 *
			 * If there is any protection in place, we reduce scan
			 * pressure by how much of the total memory used is
			 * within protection thresholds.
			 *
			 * There is one special case: in the first reclaim pass,
			 * we skip over all groups that are within their low
			 * protection. If that fails to reclaim enough pages to
			 * satisfy the reclaim goal, we come back and override
			 * the best-effort low protection. However, we still
			 * ideally want to honor how well-behaved groups are in
			 * that case instead of simply punishing them all
			 * equally. As such, we reclaim them based on how much
			 * memory they are using, reducing the scan pressure
			 * again by how much of the total memory used is under
			 * hard protection.
			 */
			unsigned long cgroup_size = mem_cgroup_size(memcg);
			unsigned long protection;

			/* memory.low scaling, make sure we retry before OOM */
			if (!sc->memcg_low_reclaim && low > min) {
				protection = low;
				sc->memcg_low_skipped = 1;
			} else {
				protection = min;
			}

			/* Avoid TOCTOU with earlier protection check */
			cgroup_size = max(cgroup_size, protection);

			scan = lruvec_size - lruvec_size * protection /
				(cgroup_size + 1);

			/*
			 * Minimally target SWAP_CLUSTER_MAX pages to keep
			 * reclaim moving forwards, avoiding decrementing
			 * sc->priority further than desirable.
			 */
			scan = max(scan, SWAP_CLUSTER_MAX);
		} else {/* 这是说明没有min或者low的限制的话,
		就医总的数量为基准,
		来计算真正scan的数量 */
			scan = lruvec_size;
		}
		/* prior越大,说明回收刚开始,scan的数量越少. */
		scan >>= sc->priority;

		/*
		 * If the cgroup's already been deleted, make sure to
		 * scrape out the remaining cache.

		 */
		if (!scan && !mem_cgroup_online(memcg))
			scan = min(lruvec_size, SWAP_CLUSTER_MAX);

		switch (scan_balance) {
		case SCAN_EQUAL:
			/* Scan lists relative to size */
			break;
		case SCAN_FRACT:
			/*
			 * Scan types proportional to swappiness and
			 * their relative recent reclaim efficiency.
			 * Make sure we don't miss the last page on
			 * the offlined memory cgroups because of a
			 * round-off error.
			 */
			scan = mem_cgroup_online(memcg) ?
			       div64_u64(scan * fraction[file], denominator) :
			       DIV64_U64_ROUND_UP(scan * fraction[file],
						  denominator);
			break;
		case SCAN_FILE:
		case SCAN_ANON:
			/* Scan one type exclusively */
			if ((scan_balance == SCAN_FILE) != file)
				scan = 0;
			/*  */
			break;

		default:
			/* Look ma, no brain */
			BUG();
		}

		nr[lru] = scan;
	}
}

/*
 * Anonymous LRU management is a waste if there is
 * ultimately no way to reclaim the memory.
 */
static bool can_age_anon_pages(struct pglist_data *pgdat,
			       struct scan_control *sc)
{
	/* Aging the anon LRU is valuable if swap is present: */
	if (total_swap_pages > 0)
		return true;

	/* Also valuable if anon pages can be demoted: */
	return can_demote(pgdat->node_id, sc);
}

#ifdef CONFIG_LRU_GEN

#ifdef CONFIG_LRU_GEN_ENABLED
/*  */
DEFINE_STATIC_KEY_ARRAY_TRUE(lru_gen_caps, NR_LRU_GEN_CAPS);
#define get_cap(cap)	static_branch_likely(&lru_gen_caps[cap])
#else
DEFINE_STATIC_KEY_ARRAY_FALSE(lru_gen_caps, NR_LRU_GEN_CAPS);
#define get_cap(cap)	static_branch_unlikely(&lru_gen_caps[cap])
#endif

/*  */
static bool should_walk_mmu(void)
{
	return arch_has_hw_pte_young() && get_cap(LRU_GEN_MM_WALK);
}

static bool should_clear_pmd_young(void)
{
	return arch_has_hw_nonleaf_pmd_young() && get_cap(LRU_GEN_NONLEAF_YOUNG);
}

/******************************************************************************
 *                          shorthand helpers
 ******************************************************************************/

#define LRU_REFS_FLAGS	(BIT(PG_referenced) | BIT(PG_workingset))

#define DEFINE_MAX_SEQ(lruvec)						\
	unsigned long max_seq = READ_ONCE((lruvec)->lrugen.max_seq)
/* 

获取file和anon的最新gen,存储在min_seq[2]
 */
#define DEFINE_MIN_SEQ(lruvec)						\
	unsigned long min_seq[ANON_AND_FILE] = {			\
		READ_ONCE((lruvec)->lrugen.min_seq[LRU_GEN_ANON]),	\
		READ_ONCE((lruvec)->lrugen.min_seq[LRU_GEN_FILE]),	\
	}

#define for_each_gen_type_zone(gen, type, zone)				\
	for ((gen) = 0; (gen) < MAX_NR_GENS; (gen)++)			\
		for ((type) = 0; (type) < ANON_AND_FILE; (type)++)	\
			for ((zone) = 0; (zone) < MAX_NR_ZONES; (zone)++)

#define get_memcg_gen(seq)	((seq) % MEMCG_NR_GENS)
/*  */
#define get_memcg_bin(bin)	((bin) % MEMCG_NR_BINS)

static struct lruvec *get_lruvec(struct mem_cgroup *memcg, int nid)
{
	struct pglist_data *pgdat = NODE_DATA(nid);

#ifdef CONFIG_MEMCG
	if (memcg) {
		struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;

		/* see the comment in mem_cgroup_lruvec() */
		if (!lruvec->pgdat)
			lruvec->pgdat = pgdat;

		return lruvec;
	}
#endif
	VM_WARN_ON_ONCE(!mem_cgroup_disabled());

	return &pgdat->__lruvec;
}
/* 如何获取sc下的lruvec的swappiness?
sc不允许swap, 为0.
不允许demote并且没有足够swap页面
最后就是去看memcg的swappiness
=====================
返回值为真表示可以回收不活跃匿名页
 */
static int get_swappiness(struct lruvec *lruvec, struct scan_control *sc)
{
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	if (!sc->may_swap)/* sc不允许swap */
		return 0;

	if (!can_demote(pgdat->node_id, sc) &&
	    mem_cgroup_get_nr_swap_pages(memcg) < MIN_LRU_BATCH)
		return 0;

	return mem_cgroup_swappiness(memcg);
}
/* 
获取这个type最老的gen有多老?
 */
static int get_nr_gens(struct lruvec *lruvec, int type)
{
	return lruvec->lrugen.max_seq - lruvec->lrugen.min_seq[type] + 1;
}

static bool __maybe_unused seq_is_valid(struct lruvec *lruvec)
{
	/* see the comment on lru_gen_folio */
	return get_nr_gens(lruvec, LRU_GEN_FILE) >= MIN_NR_GENS &&
	       get_nr_gens(lruvec, LRU_GEN_FILE) <= get_nr_gens(lruvec, LRU_GEN_ANON) &&
	       get_nr_gens(lruvec, LRU_GEN_ANON) <= MAX_NR_GENS;
}

/******************************************************************************
 *                          Bloom filters
 ******************************************************************************/

/*
 * Bloom filters with m=1<<15, k=2 and the false positive rates of ~1/5 when
 * n=10,000 and ~1/2 when n=20,000, where, conventionally, m is the number of
 * bits in a bitmap, k is the number of hash functions and n is the number of
 * inserted items.
 *
 * Page table walkers use one of the two filters to reduce their search space.
 * To get rid of non-leaf entries that no longer have enough leaf entries, the
 * aging uses the double-buffering technique to flip to the other filter each
 * time it produces a new generation. For non-leaf entries that have enough
 * leaf entries, the aging carries them over to the next generation in
 * walk_pmd_range(); the eviction also report them when walking the rmap
 * in lru_gen_look_around().
 *
 * For future optimizations:
 * 1. It's not necessary to keep both filters all the time. The spare one can be
 *    freed after the RCU grace period and reallocated if needed again.
 * 2. And when reallocating, it's worth scaling its size according to the number
 *    of inserted entries in the other filter, to reduce the memory overhead on
 *    small systems and false positives on large systems.
 * 3. Jenkins' hash function is an alternative to Knuth's.
 */
#define BLOOM_FILTER_SHIFT	15

/* 两个布隆过滤器? */
static inline int filter_gen_from_seq(unsigned long seq)
{
	return seq % NR_BLOOM_FILTERS;
}

static void get_item_key(void *item, int *key)
{
	u32 hash = hash_ptr(item, BLOOM_FILTER_SHIFT * 2);

	BUILD_BUG_ON(BLOOM_FILTER_SHIFT * 2 > BITS_PER_TYPE(u32));

	key[0] = hash & (BIT(BLOOM_FILTER_SHIFT) - 1);
	key[1] = hash >> BLOOM_FILTER_SHIFT;
}

static bool test_bloom_filter(struct lruvec *lruvec, unsigned long seq, void *item)
{
	int key[2];
	unsigned long *filter;
	int gen = filter_gen_from_seq(seq);

	filter = READ_ONCE(lruvec->mm_state.filters[gen]);
	if (!filter)
		return true;

	get_item_key(item, key);

	return test_bit(key[0], filter) && test_bit(key[1], filter);
}

static void update_bloom_filter(struct lruvec *lruvec, unsigned long seq, void *item)
{
	int key[2];
	unsigned long *filter;
	int gen = filter_gen_from_seq(seq);

	filter = READ_ONCE(lruvec->mm_state.filters[gen]);
	if (!filter)
		return;

	get_item_key(item, key);

	if (!test_bit(key[0], filter))
		set_bit(key[0], filter);
	if (!test_bit(key[1], filter))
		set_bit(key[1], filter);
}

/*  */
static void reset_bloom_filter(struct lruvec *lruvec, unsigned long seq)
{
	unsigned long *filter;
	int gen = filter_gen_from_seq(seq);

	/* 找到对应的过滤器 */
	filter = lruvec->mm_state.filters[gen];
	if (filter) {
		bitmap_clear(filter, 0, BIT(BLOOM_FILTER_SHIFT));
		return;
	}

	filter = bitmap_zalloc(BIT(BLOOM_FILTER_SHIFT),
			       __GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN);
	WRITE_ONCE(lruvec->mm_state.filters[gen], filter);
}

/******************************************************************************
 *                          mm_struct list
 ******************************************************************************/
/*  */
/*  */
static struct lru_gen_mm_list *get_mm_list(struct mem_cgroup *memcg)
{
	static struct lru_gen_mm_list mm_list = {
		.fifo = LIST_HEAD_INIT(mm_list.fifo),
		.lock = __SPIN_LOCK_UNLOCKED(mm_list.lock),
	};

#ifdef CONFIG_MEMCG
	if (memcg)
		return &memcg->mm_list;
#endif
	VM_WARN_ON_ONCE(!mem_cgroup_disabled());

	return &mm_list;
}

void lru_gen_add_mm(struct mm_struct *mm)
{
	int nid;
	struct mem_cgroup *memcg = get_mem_cgroup_from_mm(mm);
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);

	VM_WARN_ON_ONCE(!list_empty(&mm->lru_gen.list));
#ifdef CONFIG_MEMCG
	VM_WARN_ON_ONCE(mm->lru_gen.memcg);
	mm->lru_gen.memcg = memcg;
#endif
	spin_lock(&mm_list->lock);

	for_each_node_state(nid, N_MEMORY) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		/* the first addition since the last iteration */
		if (lruvec->mm_state.tail == &mm_list->fifo)
			lruvec->mm_state.tail = &mm->lru_gen.list;
	}

	list_add_tail(&mm->lru_gen.list, &mm_list->fifo);

	spin_unlock(&mm_list->lock);
}

void lru_gen_del_mm(struct mm_struct *mm)
{
	int nid;
	struct lru_gen_mm_list *mm_list;
	struct mem_cgroup *memcg = NULL;

	if (list_empty(&mm->lru_gen.list))
		return;

#ifdef CONFIG_MEMCG
	memcg = mm->lru_gen.memcg;
#endif
	mm_list = get_mm_list(memcg);

	spin_lock(&mm_list->lock);

	for_each_node(nid) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		/* where the current iteration continues after */
		if (lruvec->mm_state.head == &mm->lru_gen.list)
			lruvec->mm_state.head = lruvec->mm_state.head->prev;

		/* where the last iteration ended before */
		if (lruvec->mm_state.tail == &mm->lru_gen.list)
			lruvec->mm_state.tail = lruvec->mm_state.tail->next;
	}

	list_del_init(&mm->lru_gen.list);

	spin_unlock(&mm_list->lock);

#ifdef CONFIG_MEMCG
	mem_cgroup_put(mm->lru_gen.memcg);
	mm->lru_gen.memcg = NULL;
#endif
}

#ifdef CONFIG_MEMCG
void lru_gen_migrate_mm(struct mm_struct *mm)
{
	struct mem_cgroup *memcg;
	struct task_struct *task = rcu_dereference_protected(mm->owner, true);

	VM_WARN_ON_ONCE(task->mm != mm);
	lockdep_assert_held(&task->alloc_lock);

	/* for mm_update_next_owner() */
	if (mem_cgroup_disabled())
		return;

	/* migration can happen before addition */
	if (!mm->lru_gen.memcg)
		return;

	rcu_read_lock();
	memcg = mem_cgroup_from_task(task);
	rcu_read_unlock();
	if (memcg == mm->lru_gen.memcg)
		return;

	VM_WARN_ON_ONCE(list_empty(&mm->lru_gen.list));

	lru_gen_del_mm(mm);
	lru_gen_add_mm(mm);
}
#endif

/* 
no mmu walk的老化调用的函数
reset哪些? 清空lruvec->mm_state.stats,这是什么 */
static void reset_mm_stats(struct lruvec *lruvec, struct lru_gen_mm_walk *walk, bool last)
{
	int i;
	int hist;

	lockdep_assert_held(&get_mm_list(lruvec_memcg(lruvec))->lock);

	if (walk) {/*  */
		hist = lru_hist_from_seq(walk->max_seq);

		for (i = 0; i < NR_MM_STATS; i++) {
			WRITE_ONCE(lruvec->mm_state.stats[hist][i],
				   lruvec->mm_state.stats[hist][i] + walk->mm_stats[i]);
			walk->mm_stats[i] = 0;
		}
	}

	if (NR_HIST_GENS > 1 && last) {/* iterate_mm_list_nowalk走这个路径 */
		hist = lru_hist_from_seq(lruvec->mm_state.seq + 1);

		for (i = 0; i < NR_MM_STATS; i++)
			WRITE_ONCE(lruvec->mm_state.stats[hist][i], 0);
	}
}
/*  */
/*  */
static bool should_skip_mm(struct mm_struct *mm, struct lru_gen_mm_walk *walk)
{
	int type;
	unsigned long size = 0;
	struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
	/*  */
	int key = pgdat->node_id % BITS_PER_TYPE(mm->lru_gen.bitmap);

	if (!walk->force_scan && !test_bit(key, &mm->lru_gen.bitmap))
		return true;
	/* 不准备跳过了, 这里清除标记, 表示刚刚访问过 */
	clear_bit(key, &mm->lru_gen.bitmap);

	for (type = !walk->can_swap; type < ANON_AND_FILE; type++) {
		size += type ? get_mm_counter(mm, MM_FILEPAGES) :
			       get_mm_counter(mm, MM_ANONPAGES) +
			       get_mm_counter(mm, MM_SHMEMPAGES);
	}
	/* 还是得跳过? */
	if (size < MIN_LRU_BATCH)
		return true;

	return !mmget_not_zero(mm);
}

/*  */
/* 遍历什么mm?
@walk是调用者的walk状态
@lruvec是要处理的lruvec
iter是个迭代器指针. */
static bool iterate_mm_list(struct lruvec *lruvec, struct lru_gen_mm_walk *walk,
			    struct mm_struct **iter)
{
	bool first = false;
	bool last = false;
	struct mm_struct *mm = NULL;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);
	struct lru_gen_mm_state *mm_state = &lruvec->mm_state;

	/*
	 * mm_state->seq is incremented after each iteration of mm_list. There
	 * are three interesting cases for this page table walker:
	 * 1. It tries to start a new iteration with a stale max_seq: there is
	 *    nothing left to do.
	 * 2. It started the next iteration: it needs to reset the Bloom filter
	 *    so that a fresh set of PTE tables can be recorded.
	 * 3. It ended the current iteration: it needs to reset the mm stats
	 *    counters and tell its caller to increment max_seq.
	 */
	spin_lock(&mm_list->lock);

	VM_WARN_ON_ONCE(mm_state->seq + 1 < walk->max_seq);

	if (walk->max_seq <= mm_state->seq)
		goto done;

	if (!mm_state->head)
		mm_state->head = &mm_list->fifo;
	/* 表示第一次遍历? */
	if (mm_state->head == &mm_list->fifo)
		first = true;

	do {/* 进行一次迭代 */
		mm_state->head = mm_state->head->next;
		if (mm_state->head == &mm_list->fifo) {/* 遍历到最后一个了 */
			WRITE_ONCE(mm_state->seq, mm_state->seq + 1);
			last = true;
			break;
		}
		/* 进行迭代,处理当前元素 */
		/* force scan for those added after the last iteration */
		if (!mm_state->tail || mm_state->tail == mm_state->head) {
			mm_state->tail = mm_state->head->next;
			walk->force_scan = true;
		}
		/* 找到mm */
		/* 找到mm */
		mm = list_entry(mm_state->head, struct mm_struct, lru_gen.list);
		if (should_skip_mm(mm, walk))
			mm = NULL;
	} while (!mm);
	/* 获取到一个可用的mm */

done:
	if (*iter || last)
		reset_mm_stats(lruvec, walk, last);

	spin_unlock(&mm_list->lock);

	if (mm && first) /* mm, last && first */
		reset_bloom_filter(lruvec, walk->max_seq + 1);

	if (*iter)
		mmput_async(*iter);

	*iter = mm;

	return last;
}

/* 老化时会调用 */
static bool iterate_mm_list_nowalk(struct lruvec *lruvec, unsigned long max_seq)
{
	bool success = false;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);
	struct lru_gen_mm_state *mm_state = &lruvec->mm_state;

	spin_lock(&mm_list->lock);

	VM_WARN_ON_ONCE(mm_state->seq + 1 < max_seq);

	if (max_seq > mm_state->seq) {/* mm_state跟不上现在的max_seq了? */
		mm_state->head = NULL;
		mm_state->tail = NULL;
		WRITE_ONCE(mm_state->seq, mm_state->seq + 1);
		reset_mm_stats(lruvec, NULL, true);
		success = true;
	}

	spin_unlock(&mm_list->lock);

	return success;
}

/******************************************************************************
 *                          PID controller
 ******************************************************************************/

/*
 * A feedback loop based on Proportional-Integral-Derivative (PID) controller.
 *
 * The P term is refaulted/(evicted+protected) from a tier in the generation
 * currently being evicted; the I term is the exponential moving average of the
 * P term over the generations previously evicted, using the smoothing factor
 * 1/2; the D term isn't supported.
 *
 * The setpoint (SP) is always the first tier of one type; the process variable
 * (PV) is either any tier of the other type or any other tier of the same
 * type.
 *
 * The error is the difference between the SP and the PV; the correction is to
 * turn off protection when SP>PV or turn on protection when SP<PV.
 *
 * For future optimizations:
 * 1. The D term may discount the other two terms over time so that long-lived
 *    generations can resist stale information.
 */
struct ctrl_pos {
	unsigned long refaulted;
	unsigned long total;
	int gain;
};

static void read_ctrl_pos(struct lruvec *lruvec, int type, int tier, int gain,
			  struct ctrl_pos *pos)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int hist = lru_hist_from_seq(lrugen->min_seq[type]);

	pos->refaulted = lrugen->avg_refaulted[type][tier] +
			 atomic_long_read(&lrugen->refaulted[hist][type][tier]);
	pos->total = lrugen->avg_total[type][tier] +
		     atomic_long_read(&lrugen->evicted[hist][type][tier]);
	if (tier)
		pos->total += lrugen->protected[hist][type][tier - 1];
	pos->gain = gain;
}

static void reset_ctrl_pos(struct lruvec *lruvec, int type, bool carryover)
{
	int hist, tier;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	bool clear = carryover ? NR_HIST_GENS == 1 : NR_HIST_GENS > 1;
	unsigned long seq = carryover ? lrugen->min_seq[type] : lrugen->max_seq + 1;

	lockdep_assert_held(&lruvec->lru_lock);

	if (!carryover && !clear)
		return;

	hist = lru_hist_from_seq(seq);

	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		if (carryover) {
			unsigned long sum;

			sum = lrugen->avg_refaulted[type][tier] +
			      atomic_long_read(&lrugen->refaulted[hist][type][tier]);
			WRITE_ONCE(lrugen->avg_refaulted[type][tier], sum / 2);

			sum = lrugen->avg_total[type][tier] +
			      atomic_long_read(&lrugen->evicted[hist][type][tier]);
			if (tier)
				sum += lrugen->protected[hist][type][tier - 1];
			WRITE_ONCE(lrugen->avg_total[type][tier], sum / 2);
		}

		if (clear) {
			atomic_long_set(&lrugen->refaulted[hist][type][tier], 0);
			atomic_long_set(&lrugen->evicted[hist][type][tier], 0);
			if (tier)
				WRITE_ONCE(lrugen->protected[hist][type][tier - 1], 0);
		}
	}
}

static bool positive_ctrl_err(struct ctrl_pos *sp, struct ctrl_pos *pv)
{
	/*
	 * Return true if the PV has a limited number of refaults or a lower
	 * refaulted/total than the SP.
	 */
	return pv->refaulted < MIN_LRU_BATCH ||
	       pv->refaulted * (sp->total + MIN_LRU_BATCH) * sp->gain <=
	       (sp->refaulted + 1) * pv->total * pv->gain;
}

/******************************************************************************
 *                          the aging
 ******************************************************************************/

/* promote pages accessed through page tables
增加folio的flag里面存储的gen
 */
static int folio_update_gen(struct folio *folio, int gen)
{
	unsigned long new_flags, old_flags = READ_ONCE(folio->flags);

	VM_WARN_ON_ONCE(gen >= MAX_NR_GENS);
	VM_WARN_ON_ONCE(!rcu_read_lock_held());

	do {
		/* lru_gen_del_folio() has isolated this page? */
		if (!(old_flags & LRU_GEN_MASK)) {
			/* for shrink_folio_list() */
			new_flags = old_flags | BIT(PG_referenced);
			continue;
		}

		new_flags = old_flags & ~(LRU_GEN_MASK | LRU_REFS_MASK | LRU_REFS_FLAGS);
		new_flags |= (gen + 1UL) << LRU_GEN_PGOFF;
	} while (!try_cmpxchg(&folio->flags, &old_flags, new_flags));

	return ((old_flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;
}

/* protect pages accessed multiple times through file descriptors
提升gen
 */
static int folio_inc_gen(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	int type = folio_is_file_lru(folio);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int new_gen, old_gen = lru_gen_from_seq(lrugen->min_seq[type]);
	unsigned long new_flags, old_flags = READ_ONCE(folio->flags);

	VM_WARN_ON_ONCE_FOLIO(!(old_flags & LRU_GEN_MASK), folio);

	do {
		/* 实际的gen是编码在flags里面.  */
		new_gen = ((old_flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;
		/* folio_update_gen() has promoted this page? */
		if (new_gen >= 0 && new_gen != old_gen)
			return new_gen; /* 如果gen已经变了, 这里就是直接返回新的gen?  */
		
		/* 提升一代 */
		new_gen = (old_gen + 1) % MAX_NR_GENS;
		/* 把新gen编码到新flags里面 */
		new_flags = old_flags & ~(LRU_GEN_MASK | LRU_REFS_MASK | LRU_REFS_FLAGS);
		new_flags |= (new_gen + 1UL) << LRU_GEN_PGOFF;
		/* for folio_end_writeback() */
		if (reclaiming)
			new_flags |= BIT(PG_reclaim);
	} while (!try_cmpxchg(&folio->flags, &old_flags, new_flags));

	lru_gen_update_size(lruvec, folio, old_gen, new_gen);

	return new_gen;
}

static void update_batch_size(struct lru_gen_mm_walk *walk, struct folio *folio,
			      int old_gen, int new_gen)
{
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	int delta = folio_nr_pages(folio);

	VM_WARN_ON_ONCE(old_gen >= MAX_NR_GENS);
	VM_WARN_ON_ONCE(new_gen >= MAX_NR_GENS);

	walk->batched++;

	walk->nr_pages[old_gen][type][zone] -= delta;
	walk->nr_pages[new_gen][type][zone] += delta;
}

static void reset_batch_size(struct lruvec *lruvec, struct lru_gen_mm_walk *walk)
{
	int gen, type, zone;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	walk->batched = 0;

	for_each_gen_type_zone(gen, type, zone) {
		enum lru_list lru = type * LRU_INACTIVE_FILE;
		int delta = walk->nr_pages[gen][type][zone];

		if (!delta)
			continue;

		walk->nr_pages[gen][type][zone] = 0;


		WRITE_ONCE(lrugen->nr_pages[gen][type][zone],
			   lrugen->nr_pages[gen][type][zone] + delta);

		if (lru_gen_is_active(lruvec, gen))
			lru += LRU_ACTIVE;
		__update_lru_size(lruvec, lru, zone, delta);
	}
}

/*  */
static int should_skip_vma(unsigned long start, unsigned long end, struct mm_walk *args)
{
	struct address_space *mapping;
	struct vm_area_struct *vma = args->vma;
	struct lru_gen_mm_walk *walk = args->private;

	if (!vma_is_accessible(vma))
		return true;

	if (is_vm_hugetlb_page(vma))
		return true;

	if (!vma_has_recency(vma))
		return true;

	if (vma->vm_flags & (VM_LOCKED | VM_SPECIAL))
		return true;

	if (vma == get_gate_vma(vma->vm_mm))
		return true;

	if (vma_is_anonymous(vma))
		return !walk->can_swap;

	if (WARN_ON_ONCE(!vma->vm_file || !vma->vm_file->f_mapping))
		return true;

	mapping = vma->vm_file->f_mapping;
	if (mapping_unevictable(mapping))
		return true;

	if (shmem_mapping(mapping))
		return !walk->can_swap;

	/* to exclude special mappings like dax, etc. */
	return !mapping->a_ops->read_folio;
}

/*
 * Some userspace memory allocators map many single-page VMAs. Instead of
 * returning back to the PGD table for each of such VMAs, finish an entire PMD
 * table to reduce zigzags and improve cache performance.
 */
static bool get_next_vma(unsigned long mask, unsigned long size, struct mm_walk *args,
			 unsigned long *vm_start, unsigned long *vm_end)
{
	unsigned long start = round_up(*vm_end, size);
	unsigned long end = (start | ~mask) + 1;
	VMA_ITERATOR(vmi, args->mm, start);

	VM_WARN_ON_ONCE(mask & size);
	VM_WARN_ON_ONCE((start & mask) != (*vm_start & mask));

	for_each_vma(vmi, args->vma) {
		if (end && end <= args->vma->vm_start)
			return false;

		if (should_skip_vma(args->vma->vm_start, args->vma->vm_end, args))
			continue;

		*vm_start = max(start, args->vma->vm_start);
		*vm_end = min(end - 1, args->vma->vm_end - 1) + 1;

		return true;
	}

	return false;
}

static unsigned long get_pte_pfn(pte_t pte, struct vm_area_struct *vma, unsigned long addr)
{
	unsigned long pfn = pte_pfn(pte);

	VM_WARN_ON_ONCE(addr < vma->vm_start || addr >= vma->vm_end);

	if (!pte_present(pte) || is_zero_pfn(pfn))
		return -1;

	if (WARN_ON_ONCE(pte_devmap(pte) || pte_special(pte)))
		return -1;

	if (WARN_ON_ONCE(!pfn_valid(pfn)))
		return -1;

	return pfn;
}

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG)
/* 获取pmd项的pfn */
static unsigned long get_pmd_pfn(pmd_t pmd, struct vm_area_struct *vma, unsigned long addr)
{
	/* 获取pmd项指向的pfn */
	unsigned long pfn = pmd_pfn(pmd);

	VM_WARN_ON_ONCE(addr < vma->vm_start || addr >= vma->vm_end);

	if (!pmd_present(pmd) || is_huge_zero_pmd(pmd))
		return -1;

	if (WARN_ON_ONCE(pmd_devmap(pmd)))
		return -1;

	if (WARN_ON_ONCE(!pfn_valid(pfn)))
		return -1;

	return pfn;
}
#endif

/* 通过pfn获取folio? */
static struct folio *get_pfn_folio(unsigned long pfn, struct mem_cgroup *memcg,
				   struct pglist_data *pgdat, bool can_swap)
{
	struct folio *folio;

	/* try to avoid unnecessary memory loads */
	if (pfn < pgdat->node_start_pfn || pfn >= pgdat_end_pfn(pgdat))
		return NULL;
	/* 从pfn转为folio */
	folio = pfn_folio(pfn);
	if (folio_nid(folio) != pgdat->node_id)
		return NULL;

	if (folio_memcg_rcu(folio) != memcg)
		return NULL;

	/* file VMAs can contain anon pages from COW */
	if (!folio_is_file_lru(folio) && !can_swap)
		return NULL;

	return folio;
}

static bool suitable_to_scan(int total, int young)
{
	int n = clamp_t(int, cache_line_size() / sizeof(pte_t), 2, 8);

	/* suitable if the average number of young PTEs per cacheline is >=1 */
	return young * n >= total;
}

/* 6.x的walk pte */
static bool walk_pte_range(pmd_t *pmd, unsigned long start, unsigned long end,
			   struct mm_walk *args)
{
	int i;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned long addr;
	int total = 0;
	int young = 0;
	struct lru_gen_mm_walk *walk = args->private;
	struct mem_cgroup *memcg = lruvec_memcg(walk->lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
	int old_gen, new_gen = lru_gen_from_seq(walk->max_seq);

	pte = pte_offset_map_nolock(args->mm, pmd, start & PMD_MASK, &ptl);
	if (!pte)
		return false;
	if (!spin_trylock(ptl)) {
		pte_unmap(pte);
		return false;
	}

	arch_enter_lazy_mmu_mode();
restart:
	for (i = pte_index(start), addr = start; addr != end; i++, addr += PAGE_SIZE) {
		unsigned long pfn;
		struct folio *folio;
		pte_t ptent = ptep_get(pte + i);

		total++;
		walk->mm_stats[MM_LEAF_TOTAL]++;

		pfn = get_pte_pfn(ptent, args->vma, addr);
		if (pfn == -1)
			continue;

		if (!pte_young(ptent)) {
			walk->mm_stats[MM_LEAF_OLD]++;
			continue;
		}

		folio = get_pfn_folio(pfn, memcg, pgdat, walk->can_swap);
		if (!folio)
			continue;

		if (!ptep_test_and_clear_young(args->vma, addr, pte + i))
			VM_WARN_ON_ONCE(true);

		young++;
		walk->mm_stats[MM_LEAF_YOUNG]++;

		if (pte_dirty(ptent) && !folio_test_dirty(folio) &&
		    !(folio_test_anon(folio) && folio_test_swapbacked(folio) &&
		      !folio_test_swapcache(folio)))
			folio_mark_dirty(folio);

		old_gen = folio_update_gen(folio, new_gen);
		if (old_gen >= 0 && old_gen != new_gen)
			update_batch_size(walk, folio, old_gen, new_gen);
	}

	if (i < PTRS_PER_PTE && get_next_vma(PMD_MASK, PAGE_SIZE, args, &start, &end))
		goto restart;

	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte, ptl);

	return suitable_to_scan(total, young);
}

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG)
/*  */
static void walk_pmd_range_locked(pud_t *pud, unsigned long addr, struct vm_area_struct *vma,
				  struct mm_walk *args, unsigned long *bitmap, unsigned long *first)
{
	int i;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct lru_gen_mm_walk *walk = args->private;
	struct mem_cgroup *memcg = lruvec_memcg(walk->lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
	int old_gen, new_gen = lru_gen_from_seq(walk->max_seq);

	VM_WARN_ON_ONCE(pud_leaf(*pud));

	/* try to batch at most 1+MIN_LRU_BATCH+1 entries */
	if (*first == -1) {
		*first = addr;
		bitmap_zero(bitmap, MIN_LRU_BATCH);
		return;
	}
	/* 如果 addr 等于 -1，则 i 的值为 0；否则，执行 : 后面的表达式。 */
	i = addr == -1 ? 0 : pmd_index(addr) - pmd_index(*first);
	if (i && i <= MIN_LRU_BATCH) {
		__set_bit(i - 1, bitmap);
		return;
	}

	pmd = pmd_offset(pud, *first);

	ptl = pmd_lockptr(args->mm, pmd);
	if (!spin_trylock(ptl))
		goto done;

	arch_enter_lazy_mmu_mode();

	do {
		unsigned long pfn;
		struct folio *folio;

		/* don't round down the first address */
		addr = i ? (*first & PMD_MASK) + i * PMD_SIZE : *first;

		pfn = get_pmd_pfn(pmd[i], vma, addr);
		if (pfn == -1)
			goto next;

		if (!pmd_trans_huge(pmd[i])) {
			/* 非巨页的情况? */
			if (should_clear_pmd_young())
				pmdp_test_and_clear_young(vma, addr, pmd + i);
			goto next;
		}
		/* 后面都是巨页的处理情况? */
		folio = get_pfn_folio(pfn, memcg, pgdat, walk->can_swap);
		if (!folio)
			goto next;

		if (!pmdp_test_and_clear_young(vma, addr, pmd + i))
			goto next;
		/* 如果本来是young, 就走下面 */
		walk->mm_stats[MM_LEAF_YOUNG]++;

		if (pmd_dirty(pmd[i]) && !folio_test_dirty(folio) &&
		    !(folio_test_anon(folio) && folio_test_swapbacked(folio) &&
		      !folio_test_swapcache(folio)))
			folio_mark_dirty(folio);
		/* 增加folio的gen */
		old_gen = folio_update_gen(folio, new_gen);
		if (old_gen >= 0 && old_gen != new_gen)
			update_batch_size(walk, folio, old_gen, new_gen);
next:
		i = i > MIN_LRU_BATCH ? 0 : find_next_bit(bitmap, MIN_LRU_BATCH, i) + 1;
	} while (i <= MIN_LRU_BATCH);

	arch_leave_lazy_mmu_mode();
	spin_unlock(ptl);
done:
	*first = -1;
}
#else
static void walk_pmd_range_locked(pud_t *pud, unsigned long addr, struct vm_area_struct *vma,
				  struct mm_walk *args, unsigned long *bitmap, unsigned long *first)
{
}
#endif

static void walk_pmd_range(pud_t *pud, unsigned long start, unsigned long end,
			   struct mm_walk *args)
{
	int i;
	pmd_t *pmd;
	unsigned long next;
	unsigned long addr;
	struct vm_area_struct *vma;
	DECLARE_BITMAP(bitmap, MIN_LRU_BATCH);
	unsigned long first = -1;
	struct lru_gen_mm_walk *walk = args->private;

	VM_WARN_ON_ONCE(pud_leaf(*pud));

	/*
	 * Finish an entire PMD in two passes: the first only reaches to PTE
	 * tables to avoid taking the PMD lock; the second, if necessary, takes
	 * the PMD lock to clear the accessed bit in PMD entries.
	 找到start对应的pmd
	 */
	pmd = pmd_offset(pud, start & PUD_MASK);
restart:
	/* walk_pte_range() may call get_next_vma() */
	vma = args->vma;
	/* i是pmd上面的一个个ent */
	for (i = pmd_index(start), addr = start; addr != end; i++, addr = next) {
		/* 获取i这个位置上的指针值 */
		pmd_t val = pmdp_get_lockless(pmd + i);

		/* 获取addr同pmd的最大地址 */
		next = pmd_addr_end(addr, end);

		if (!pmd_present(val) || is_huge_zero_pmd(val)) {
			walk->mm_stats[MM_LEAF_TOTAL]++;
			continue;
		}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE/* 巨页的路径 */
		if (pmd_trans_huge(val)) {
			unsigned long pfn = pmd_pfn(val);
			struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);

			walk->mm_stats[MM_LEAF_TOTAL]++;

			if (!pmd_young(val)) {
				walk->mm_stats[MM_LEAF_OLD]++;
				continue;
			}

			/* try to avoid unnecessary memory loads */
			if (pfn < pgdat->node_start_pfn || pfn >= pgdat_end_pfn(pgdat))
				continue;

			walk_pmd_range_locked(pud, addr, vma, args, bitmap, &first);
			continue;
		}
#endif
		walk->mm_stats[MM_NONLEAF_TOTAL]++;

		if (should_clear_pmd_young()) {
			if (!pmd_young(val))
				continue;

			walk_pmd_range_locked(pud, addr, vma, args, bitmap, &first);
		}

		if (!walk->force_scan && !test_bloom_filter(walk->lruvec, walk->max_seq, pmd + i))
			continue;

		walk->mm_stats[MM_NONLEAF_FOUND]++;

		if (!walk_pte_range(&val, addr, next, args))
			continue;

		walk->mm_stats[MM_NONLEAF_ADDED]++;

		/* carry over to the next generation */
		update_bloom_filter(walk->lruvec, walk->max_seq + 1, pmd + i);
	}

	walk_pmd_range_locked(pud, -1, vma, args, bitmap, &first);

	if (i < PTRS_PER_PMD && get_next_vma(PUD_MASK, PMD_SIZE, args, &start, &end))
		goto restart;
}

/* mm walk的时候处理p4d,pud的逻辑? */
static int walk_pud_range(p4d_t *p4d, unsigned long start, unsigned long end,
			  struct mm_walk *args)
{
	int i;
	pud_t *pud;
	unsigned long addr;
	unsigned long next;
	struct lru_gen_mm_walk *walk = args->private;

	VM_WARN_ON_ONCE(p4d_leaf(*p4d));

	pud = pud_offset(p4d, start & P4D_MASK);

restart:
	for (i = pud_index(start), addr = start; addr != end; i++, addr = next) {
		pud_t val = READ_ONCE(pud[i]);

		next = pud_addr_end(addr, end);

		if (!pud_present(val) || WARN_ON_ONCE(pud_leaf(val)))
			continue;

		walk_pmd_range(&val, addr, next, args);

		if (need_resched() || walk->batched >= MAX_LRU_BATCH) {
			end = (addr | ~PUD_MASK) + 1;
			goto done;
		}
	}

	if (i < PTRS_PER_PUD && get_next_vma(P4D_MASK, PUD_SIZE, args, &start, &end))
		goto restart;

	end = round_up(end, P4D_SIZE);
done:
	if (!end || !args->vma)
		return 1;

	walk->next_addr = max(end, args->vma->vm_start);

	return -EAGAIN;
}

/*  */
static void walk_mm(struct lruvec *lruvec, struct mm_struct *mm, struct lru_gen_mm_walk *walk)
{
	static const struct mm_walk_ops mm_walk_ops = {
		.test_walk = should_skip_vma,
		.p4d_entry = walk_pud_range,
		.walk_lock = PGWALK_RDLOCK,
	};

	int err;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);

	walk->next_addr = FIRST_USER_ADDRESS;

	do {
		DEFINE_MAX_SEQ(lruvec);

		err = -EBUSY;

		/* another thread might have called inc_max_seq() */
		if (walk->max_seq != max_seq)
			break;

		/* folio_update_gen() requires stable folio_memcg() */
		if (!mem_cgroup_trylock_pages(memcg))
			break;

		/* the caller might be holding the lock for write */
		if (mmap_read_trylock(mm)) {
			err = walk_page_range(mm, walk->next_addr, ULONG_MAX, &mm_walk_ops, walk);

			mmap_read_unlock(mm);
		}

		mem_cgroup_unlock_pages();

		if (walk->batched) {
			spin_lock_irq(&lruvec->lru_lock);
			reset_batch_size(lruvec, walk);
			spin_unlock_irq(&lruvec->lru_lock);
		}

		cond_resched();
	} while (err == -EAGAIN);
}

/* mm的walk是什么
可能会分配并创建新的mm_walk, 赋值到reclaim_state */
static struct lru_gen_mm_walk *set_mm_walk(struct pglist_data *pgdat, bool force_alloc)
{
	struct lru_gen_mm_walk *walk = current->reclaim_state->mm_walk;

	if (pgdat && current_is_kswapd()) {
		VM_WARN_ON_ONCE(walk);

		walk = &pgdat->mm_walk;
	} else if (!walk && force_alloc) {
		VM_WARN_ON_ONCE(current_is_kswapd());

		walk = kzalloc(sizeof(*walk), __GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN);
	}

	current->reclaim_state->mm_walk = walk;

	return walk;
}

static void clear_mm_walk(void)
{
	struct lru_gen_mm_walk *walk = current->reclaim_state->mm_walk;

	VM_WARN_ON_ONCE(walk && memchr_inv(walk->nr_pages, 0, sizeof(walk->nr_pages)));
	VM_WARN_ON_ONCE(walk && memchr_inv(walk->mm_stats, 0, sizeof(walk->mm_stats)));

	current->reclaim_state->mm_walk = NULL;

	if (!current_is_kswapd())
		kfree(walk);
}

/* 老化这个type的页面 */
static bool inc_min_seq(struct lruvec *lruvec, int type, bool can_swap)
{
	int zone;
	int remaining = MAX_LRU_BATCH;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int new_gen,
	old_gen = lru_gen_from_seq(lrugen->min_seq[type]);

	if (type == LRU_GEN_ANON && !can_swap)
		goto done;

	/* prevent cold/hot inversion if force_scan is true 
	逐个zone处理*/
	for (zone = 0; zone < MAX_NR_ZONES; zone++) {
		struct list_head *head = &lrugen->folios[old_gen][type][zone];

		while (!list_empty(head)) {/* 处理逐个页面 */
			struct folio *folio = lru_to_folio(head);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_zonenum(folio) != zone, folio);
			/* 移动到new gen里面 */
			new_gen = folio_inc_gen(lruvec, folio, false);
			list_move_tail(&folio->lru, &lrugen->folios[new_gen][type][zone]);

			if (!--remaining)
				return false;
		}
	}
done:
	reset_ctrl_pos(lruvec, type, true);
	WRITE_ONCE(lrugen->min_seq[type], lrugen->min_seq[type] + 1);

	return true;
}

/* 提升min seq的值 */
static bool try_to_inc_min_seq(struct lruvec *lruvec, bool can_swap)
{
	int gen, type, zone;
	bool success = false;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	DEFINE_MIN_SEQ(lruvec);

	VM_WARN_ON_ONCE(!seq_is_valid(lruvec));

	/* find the oldest populated generation */
	for (type = !can_swap; type < ANON_AND_FILE; type++) {
		while (min_seq[type] + MIN_NR_GENS <= lrugen->max_seq) {
			gen = lru_gen_from_seq(min_seq[type]);

			for (zone = 0; zone < MAX_NR_ZONES; zone++) {
				if (!list_empty(&lrugen->folios[gen][type][zone]))
					goto next;/* 这个min_seq值还有东西, 寻找下一个seq值 */
			}

			min_seq[type]++;
		}


next:
/* 当前type找到了最大的不空的min_seq值 */
		;
	}

	/* 现在min seq是最大的没有page的值了 */
	/* see the comment on lru_gen_folio */
	if (can_swap) {
		min_seq[LRU_GEN_ANON] = min(min_seq[LRU_GEN_ANON], min_seq[LRU_GEN_FILE]);
		min_seq[LRU_GEN_FILE] = max(min_seq[LRU_GEN_ANON], lrugen->min_seq[LRU_GEN_FILE]);
	}

	for (type = !can_swap; type < ANON_AND_FILE; type++) {
		if (min_seq[type] == lrugen->min_seq[type])
			continue;

		reset_ctrl_pos(lruvec, type, true);
		WRITE_ONCE(lrugen->min_seq[type], min_seq[type]);
		success = true;
	}

	return success;
}

/* 老化函数 */
static void inc_max_seq(struct lruvec *lruvec, bool can_swap, bool force_scan)
{
	int prev, next;
	int type, zone;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
restart:
	spin_lock_irq(&lruvec->lru_lock);

	VM_WARN_ON_ONCE(!seq_is_valid(lruvec));

	for (type = ANON_AND_FILE - 1; type >= 0; type--) {
		if (get_nr_gens(lruvec, type) != MAX_NR_GENS)
			continue;

		VM_WARN_ON_ONCE(!force_scan && (type == LRU_GEN_FILE || can_swap));
		/* 老化&移动 */
		if (inc_min_seq(lruvec, type, can_swap))
			continue;

		spin_unlock_irq(&lruvec->lru_lock);
		cond_resched();
		goto restart;
	}

	/* 后面更新lru size */
	/*
	 * Update the active/inactive LRU sizes for compatibility. Both sides of
	 * the current max_seq need to be covered, since max_seq+1 can overlap
	 * with min_seq[LRU_GEN_ANON] if swapping is constrained. And if they do
	 * overlap, cold/hot inversion happens.
	 */
	prev = lru_gen_from_seq(lrugen->max_seq - 1);
	next = lru_gen_from_seq(lrugen->max_seq + 1);

	for (type = 0; type < ANON_AND_FILE; type++) {
		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			enum lru_list lru = type * LRU_INACTIVE_FILE;
			long delta = lrugen->nr_pages[prev][type][zone] -
				     lrugen->nr_pages[next][type][zone];

			if (!delta)
				continue;

			__update_lru_size(lruvec, lru, zone, delta);
			__update_lru_size(lruvec, lru + LRU_ACTIVE, zone, -delta);
		}
	}

	for (type = 0; type < ANON_AND_FILE; type++)
		reset_ctrl_pos(lruvec, type, false);

	WRITE_ONCE(lrugen->timestamps[next], jiffies);
	/* make sure preceding modifications appear */
	smp_store_release(&lrugen->max_seq, lrugen->max_seq + 1);

	spin_unlock_irq(&lruvec->lru_lock);
}

/* 这个是老化的核心函数?
返回true表示老化成功.
返回false表示失败的情况? */
static bool try_to_inc_max_seq(struct lruvec *lruvec, unsigned long max_seq,
			       struct scan_control *sc, bool can_swap, bool force_scan)
{
	bool success;
	struct lru_gen_mm_walk *walk;
	struct mm_struct *mm = NULL;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	VM_WARN_ON_ONCE(max_seq > READ_ONCE(lrugen->max_seq));

	/* see the comment in iterate_mm_list() */
	if (max_seq <= READ_ONCE(lruvec->mm_state.seq)) {
		success = false;
		goto done;
	}

	/*
	 * If the hardware doesn't automatically set the accessed bit, fallback
	 * to lru_gen_look_around(), which only clears the accessed bit in a
	 * handful of PTEs. Spreading the work out over a period of time usually
	 * is less efficient, but it avoids bursty page faults.

	 */
	if (!should_walk_mmu()) {/* 不支持自动设置young位 */
		success = iterate_mm_list_nowalk(lruvec, max_seq);
		goto done;
	}
	/*  */
	/* 说明支持硬件支持自动设置young位. 可以walk mmu */
	/*  */
	walk = set_mm_walk(NULL, true);
	if (!walk) {/* 创建walk没有成功. 还是得老办法 */
		success = iterate_mm_list_nowalk(lruvec, max_seq);
		goto done;
	}

	walk->lruvec = lruvec;
	walk->max_seq = max_seq;
	walk->can_swap = can_swap;
	walk->force_scan = force_scan;

	do {/* 这里找mm */
		success = iterate_mm_list(lruvec, walk, &mm);
		if (mm)/* 这里开始处理mm? */
			walk_mm(lruvec, mm, walk);
	} while (mm);

done:
	if (success)
		inc_max_seq(lruvec, can_swap, force_scan);

	return success;
}

/******************************************************************************
 *                          working set protection
 ******************************************************************************/
/* 2024年9月15日10:25:06
获取sc可以回收的页面数量
 */
static bool lruvec_is_sizable(struct lruvec *lruvec, struct scan_control *sc)
{
	int gen, type, zone;
	unsigned long total = 0;
	/* 获取sc下lruvec的swappiness */
	bool can_swap = get_swappiness(lruvec, sc);

	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);

	DEFINE_MAX_SEQ(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	/*  */
	for (type = !can_swap; type < ANON_AND_FILE; type++) {
		unsigned long seq;
		/* 从此type的最新gen遍历到最大gen */
		for (seq = min_seq[type]; seq <= max_seq; seq++) {
			gen = lru_gen_from_seq(seq);

			for (zone = 0; zone < MAX_NR_ZONES; zone++)
				total += max(READ_ONCE(lrugen->nr_pages[gen][type][zone]), 0L);
		}
	}

	/* whether the size is big enough to be helpful */
	return mem_cgroup_online(memcg) ? (total >> sc->priority) : total;
}
/* 2024年09月09日15:58:26

 */
static bool lruvec_is_reclaimable(struct lruvec *lruvec, struct scan_control *sc,
				  unsigned long min_ttl)
{
	int gen;
	unsigned long birth;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	/* 获取file和anon的最新gen,存储在min_seq[2] */
	DEFINE_MIN_SEQ(lruvec);

	/* see the comment on lru_gen_folio
	获取file的最新gen */
	gen = lru_gen_from_seq(min_seq[LRU_GEN_FILE]);
	/* 获取file的最新gen的birth */
	birth = READ_ONCE(lruvec->lrugen.timestamps[gen]);

	if (time_is_after_jiffies(birth + min_ttl))
		return false;/* 还没超时 */

	if (!lruvec_is_sizable(lruvec, sc))
		return false;

	mem_cgroup_calculate_protection(NULL, memcg);

	return !mem_cgroup_below_min(NULL, memcg);
}

/* to protect the working set of the last N jiffies */
static unsigned long lru_gen_min_ttl __read_mostly;
/* todddo
mglru老化node的函数
 */
static void lru_gen_age_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *memcg;
	unsigned long min_ttl = READ_ONCE(lru_gen_min_ttl);

	VM_WARN_ON_ONCE(!current_is_kswapd());

	/* check the order to exclude compaction-induced reclaim */
	if (!min_ttl || 
		sc->order || 
		sc->priority == DEF_PRIORITY /* 说明刚开始? 还没必要aging? */
		)
		return;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);/* 遍历全部的memcg */
	do {
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);

		if (lruvec_is_reclaimable(lruvec, sc, min_ttl)) {/* 有可回收的lruvec也不age? */
			mem_cgroup_iter_break(NULL, memcg);
			return;
		}

		cond_resched();
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));

	/* 到这里是找到一个最底层的memcg? */

	/*
	 * The main goal is to OOM kill if every generation from all memcgs is
	 * younger than min_ttl. However, another possibility is all memcgs are
	 * either too small or below min.
	 */
	if (mutex_trylock(&oom_lock)) {
		struct oom_control oc = {
			.gfp_mask = sc->gfp_mask,
		};

		out_of_memory(&oc);

		mutex_unlock(&oom_lock);
	}
}

/******************************************************************************
 *                          rmap/PT walk feedback
 ******************************************************************************/

/*
 * This function exploits spatial locality when shrink_folio_list() walks the
 * rmap. It scans the adjacent PTEs of a young PTE and promotes hot pages. If
 * the scan was done cacheline efficiently, it adds the PMD entry pointing to
 * the PTE table to the Bloom filter. This forms a feedback loop between the
 * eviction and the aging.
 */
void lru_gen_look_around(struct page_vma_mapped_walk *pvmw)
{
	int i;
	unsigned long start;
	unsigned long end;
	struct lru_gen_mm_walk *walk;
	int young = 0;
	pte_t *pte = pvmw->pte;
	unsigned long addr = pvmw->address;
	struct folio *folio = pfn_folio(pvmw->pfn);
	bool can_swap = !folio_is_file_lru(folio);
	struct mem_cgroup *memcg = folio_memcg(folio);
	struct pglist_data *pgdat = folio_pgdat(folio);
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	DEFINE_MAX_SEQ(lruvec);
	int old_gen, new_gen = lru_gen_from_seq(max_seq);

	lockdep_assert_held(pvmw->ptl);
	VM_WARN_ON_ONCE_FOLIO(folio_test_lru(folio), folio);

	if (spin_is_contended(pvmw->ptl))
		return;

	/* avoid taking the LRU lock under the PTL when possible */
	walk = current->reclaim_state ? current->reclaim_state->mm_walk : NULL;

	start = max(addr & PMD_MASK, pvmw->vma->vm_start);
	end = min(addr | ~PMD_MASK, pvmw->vma->vm_end - 1) + 1;

	if (end - start > MIN_LRU_BATCH * PAGE_SIZE) {
		if (addr - start < MIN_LRU_BATCH * PAGE_SIZE / 2)
			end = start + MIN_LRU_BATCH * PAGE_SIZE;
		else if (end - addr < MIN_LRU_BATCH * PAGE_SIZE / 2)
			start = end - MIN_LRU_BATCH * PAGE_SIZE;
		else {
			start = addr - MIN_LRU_BATCH * PAGE_SIZE / 2;
			end = addr + MIN_LRU_BATCH * PAGE_SIZE / 2;
		}
	}

	/* folio_update_gen() requires stable folio_memcg() */
	if (!mem_cgroup_trylock_pages(memcg))
		return;

	arch_enter_lazy_mmu_mode();

	pte -= (addr - start) / PAGE_SIZE;

	for (i = 0, addr = start; addr != end; i++, addr += PAGE_SIZE) {
		unsigned long pfn;
		pte_t ptent = ptep_get(pte + i);

		pfn = get_pte_pfn(ptent, pvmw->vma, addr);
		if (pfn == -1)
			continue;

		if (!pte_young(ptent))
			continue;

		folio = get_pfn_folio(pfn, memcg, pgdat, can_swap);
		if (!folio)
			continue;

		if (!ptep_test_and_clear_young(pvmw->vma, addr, pte + i))
			VM_WARN_ON_ONCE(true);

		young++;

		if (pte_dirty(ptent) && !folio_test_dirty(folio) &&
		    !(folio_test_anon(folio) && folio_test_swapbacked(folio) &&
		      !folio_test_swapcache(folio)))
			folio_mark_dirty(folio);

		if (walk) {
			old_gen = folio_update_gen(folio, new_gen);
			if (old_gen >= 0 && old_gen != new_gen)
				update_batch_size(walk, folio, old_gen, new_gen);

			continue;
		}

		old_gen = folio_lru_gen(folio);
		if (old_gen < 0)
			folio_set_referenced(folio);
		else if (old_gen != new_gen)
			folio_activate(folio);
	}

	arch_leave_lazy_mmu_mode();
	mem_cgroup_unlock_pages();

	/* feedback from rmap walkers to page table walkers */
	if (suitable_to_scan(i, young))
		update_bloom_filter(lruvec, max_seq, pvmw->pmd);
}

/******************************************************************************
 *                          memcg LRU
 ******************************************************************************/

/* see the comment on MEMCG_NR_GENS
2024年9月16日10:19:10
todo */
enum {
	MEMCG_LRU_NOP,
	MEMCG_LRU_HEAD,
	MEMCG_LRU_TAIL,
	MEMCG_LRU_OLD,
	MEMCG_LRU_YOUNG,
};

#ifdef CONFIG_MEMCG
/*  */
static int lru_gen_memcg_seg(struct lruvec *lruvec)
{
	return READ_ONCE(lruvec->lrugen.seg);
}
/* 根据op改变此lruvec在node的位置 */
static void lru_gen_rotate_memcg(struct lruvec *lruvec, int op)
{
	int seg;
	int old, new;
	unsigned long flags;
	/* 要放入的bin */
	int bin = get_random_u32_below(MEMCG_NR_BINS);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	spin_lock_irqsave(&pgdat->memcg_lru.lock, flags);

	VM_WARN_ON_ONCE(hlist_nulls_unhashed(&lruvec->lrugen.list));

	seg = 0;
	new = old = lruvec->lrugen.gen;

	/* see the comment on MEMCG_NR_GENS */
	if (op == MEMCG_LRU_HEAD)
		seg = MEMCG_LRU_HEAD;
	else if (op == MEMCG_LRU_TAIL)
		seg = MEMCG_LRU_TAIL;
	else if (op == MEMCG_LRU_OLD) /* 获得新的代数 */
		new = get_memcg_gen(pgdat->memcg_lru.seq);
	else if (op == MEMCG_LRU_YOUNG) /* 获得新代数 */
		new = get_memcg_gen(pgdat->memcg_lru.seq + 1);
	else
		VM_WARN_ON_ONCE(true);
	/* 先移除 */
	hlist_nulls_del_rcu(&lruvec->lrugen.list);
	/* 重新插入新位置 */
	if (op == MEMCG_LRU_HEAD || op == MEMCG_LRU_OLD) /* 加入头部 */
		hlist_nulls_add_head_rcu(&lruvec->lrugen.list, &pgdat->memcg_lru.fifo[new][bin]);
	else /* 如果是young, tail, 就是加入尾部 */
		hlist_nulls_add_tail_rcu(&lruvec->lrugen.list, &pgdat->memcg_lru.fifo[new][bin]);

	pgdat->memcg_lru.nr_memcgs[old]--;
	pgdat->memcg_lru.nr_memcgs[new]++;

	lruvec->lrugen.gen = new;
	WRITE_ONCE(lruvec->lrugen.seg, seg);

	if (!pgdat->memcg_lru.nr_memcgs[old] && old == get_memcg_gen(pgdat->memcg_lru.seq))
		WRITE_ONCE(pgdat->memcg_lru.seq, pgdat->memcg_lru.seq + 1);

	spin_unlock_irqrestore(&pgdat->memcg_lru.lock, flags);
}

void lru_gen_online_memcg(struct mem_cgroup *memcg)
{
	int gen;
	int nid;
	int bin = get_random_u32_below(MEMCG_NR_BINS);

	for_each_node(nid) {
		struct pglist_data *pgdat = NODE_DATA(nid);
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		spin_lock_irq(&pgdat->memcg_lru.lock);

		VM_WARN_ON_ONCE(!hlist_nulls_unhashed(&lruvec->lrugen.list));

		gen = get_memcg_gen(pgdat->memcg_lru.seq);

		hlist_nulls_add_tail_rcu(&lruvec->lrugen.list, &pgdat->memcg_lru.fifo[gen][bin]);
		pgdat->memcg_lru.nr_memcgs[gen]++;

		lruvec->lrugen.gen = gen;

		spin_unlock_irq(&pgdat->memcg_lru.lock);
	}
}

void lru_gen_offline_memcg(struct mem_cgroup *memcg)
{
	int nid;

	for_each_node(nid) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		lru_gen_rotate_memcg(lruvec, MEMCG_LRU_OLD);
	}
}
/* mglru下的释放memcg, 可能是还需要处理node的fifo */
void lru_gen_release_memcg(struct mem_cgroup *memcg)
{
	int gen;
	int nid;

	for_each_node(nid) {
		struct pglist_data *pgdat = NODE_DATA(nid);
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		spin_lock_irq(&pgdat->memcg_lru.lock);

		if (hlist_nulls_unhashed(&lruvec->lrugen.list))
			goto unlock;

		gen = lruvec->lrugen.gen;

		hlist_nulls_del_init_rcu(&lruvec->lrugen.list);
		pgdat->memcg_lru.nr_memcgs[gen]--;

		if (!pgdat->memcg_lru.nr_memcgs[gen] && gen == get_memcg_gen(pgdat->memcg_lru.seq))
			WRITE_ONCE(pgdat->memcg_lru.seq, pgdat->memcg_lru.seq + 1);
unlock:
		spin_unlock_irq(&pgdat->memcg_lru.lock);
	}
}

void lru_gen_soft_reclaim(struct mem_cgroup *memcg, int nid)
{
	struct lruvec *lruvec = get_lruvec(memcg, nid);

	/* see the comment on MEMCG_NR_GENS */
	if (lru_gen_memcg_seg(lruvec) != MEMCG_LRU_HEAD)
		lru_gen_rotate_memcg(lruvec, MEMCG_LRU_HEAD);
}

#else /* !CONFIG_MEMCG */

static int lru_gen_memcg_seg(struct lruvec *lruvec)
{
	return 0;
}

#endif

/******************************************************************************
 *                          the eviction
 ******************************************************************************/
/* 真正isolate页面之前, 先尝试调整位置.
就是说根据页面的不同性质, 直接重新放到不同的lru上面  */
static bool sort_folio(struct lruvec *lruvec, struct folio *folio, struct scan_control *sc,
		       int tier_idx)
{
	bool success;
	int gen = folio_lru_gen(folio);
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	int delta = folio_nr_pages(folio);
	/*  */
	int refs = folio_lru_refs(folio);
	int tier = lru_tier_from_refs(refs);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	VM_WARN_ON_ONCE_FOLIO(gen >= MAX_NR_GENS, folio);

	/* unevictable
	如果性质是unevictable, 这里设置unevictable标记, 然后重新加入lru(会自动跑到unevictable lru上面) */
	if (!folio_evictable(folio)) {
		success = lru_gen_del_folio(lruvec, folio, true);
		VM_WARN_ON_ONCE_FOLIO(!success, folio);
		folio_set_unevictable(folio);
		lruvec_add_folio(lruvec, folio);
		__count_vm_events(UNEVICTABLE_PGCULLED, delta);
		return true;
	}

	/* dirty lazyfree
	脏匿名页? */
	if (type == LRU_GEN_FILE && folio_test_anon(folio) && folio_test_dirty(folio)) {
		success = lru_gen_del_folio(lruvec, folio, true);
		VM_WARN_ON_ONCE_FOLIO(!success, folio);
		folio_set_swapbacked(folio);
		lruvec_add_folio_tail(lruvec, folio);
		return true;
	}

	/* promoted */
	if (gen != lru_gen_from_seq(lrugen->min_seq[type])) {
		list_move(&folio->lru, &lrugen->folios[gen][type][zone]);
		return true;
	}

	/* protected */
	if (tier > tier_idx) {
		int hist = lru_hist_from_seq(lrugen->min_seq[type]);

		gen = folio_inc_gen(lruvec, folio, false);
		list_move_tail(&folio->lru, &lrugen->folios[gen][type][zone]);

		WRITE_ONCE(lrugen->protected[hist][type][tier - 1],
			   lrugen->protected[hist][type][tier - 1] + delta);
		return true;
	}

	/* ineligible */
	if (zone > sc->reclaim_idx || skip_cma(folio, sc)) {
		gen = folio_inc_gen(lruvec, folio, false);
		list_move_tail(&folio->lru, &lrugen->folios[gen][type][zone]);
		return true;
	}

	/* waiting for writeback */
	if (folio_test_locked(folio) || folio_test_writeback(folio) ||
	    (type == LRU_GEN_FILE && folio_test_dirty(folio))) {
		gen = folio_inc_gen(lruvec, folio, true);
		list_move(&folio->lru, &lrugen->folios[gen][type][zone]);
		return true;
	}

	return false;
}

/* mglru回收页面前isolate此folio */
static bool isolate_folio(struct lruvec *lruvec, struct folio *folio, struct scan_control *sc)
{
	bool success;

	/* swapping inhibited */
	if (!(sc->gfp_mask & __GFP_IO) &&
	    (folio_test_dirty(folio) ||
	     (folio_test_anon(folio) && !folio_test_swapcache(folio))))
		return false;

	/* raced with release_pages() */
	if (!folio_try_get(folio))
		return false;

	/* raced with another isolation */
	if (!folio_test_clear_lru(folio)) {/*  */
		folio_put(folio); /* clear lru但是之前已经没有lru标记了, 可能是race */
		return false;
	}

	/* see the comment on MAX_NR_TIERS */
	if (!folio_test_referenced(folio))
		set_mask_bits(&folio->flags, LRU_REFS_MASK | LRU_REFS_FLAGS, 0);

	/* for shrink_folio_list() */
	folio_clear_reclaim(folio);
	folio_clear_referenced(folio);

	success = lru_gen_del_folio(lruvec, folio, true);
	VM_WARN_ON_ONCE_FOLIO(!success, folio);

	return true;
}
/* isolate页面时,这里扫描指定的type的最老的lru
==============
最多isolate出min_lru_batch(64)个页面 */
static int scan_folios(struct lruvec *lruvec, struct scan_control *sc,
		       int type, int tier, struct list_head *list)
{
	int i;
	int gen;
	enum vm_event_item item;
	int sorted = 0;
	/* 表示在这个type的最老的gen的各个zone上面扫描了多少页面 */
	int scanned = 0;
	int isolated = 0;
	int remaining = MAX_LRU_BATCH;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);

	VM_WARN_ON_ONCE(!list_empty(list));

	if (get_nr_gens(lruvec, type) == MIN_NR_GENS)
		return 0;/* 说明这个type不老,全都是活跃的? */

	/* 获取gen */
	gen = lru_gen_from_seq(lrugen->min_seq[type]);

	for (i = MAX_NR_ZONES; i > 0; i--) {/* 遍历每个zone类型 */
		LIST_HEAD(moved);
		int skipped = 0;
		int zone = (sc->reclaim_idx + i) % MAX_NR_ZONES;
		/* 遍历此lruvec的在这个区类型上面的这个type的gen代的链表
		(回收指定type的最老gen的, 所以遍历的是zone) */
		struct list_head *head = &lrugen->folios[gen][type][zone];

		while (!list_empty(head)) {/* 处理这个lru, 最多处理MAX_LRU_BATCH次.
		看来也是尽量一直取完此zone的这个最老的lru上面的页面 */
			struct folio *folio = lru_to_folio(head);
			int delta = folio_nr_pages(folio);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_zonenum(folio) != zone, folio);

			scanned += delta;

			if (sort_folio(lruvec, folio, sc, tier))
				sorted += delta;

			else if (isolate_folio(lruvec, folio, sc)) {
				/* 已经从lrugen的list移出了,下面加到要回收的list里面 */
				list_add(&folio->lru, list);
				isolated += delta;
			} else {
				list_move(&folio->lru, &moved);
				skipped += delta;
			}

			if (!--remaining || max(isolated, skipped) >= MIN_LRU_BATCH)/* 如果处理的batch数量够了 */
				break;
		}/*  */

		/* 这个zone扫描完了batch数量的page */

		if (skipped) {
			list_splice(&moved, head);
			__count_zid_vm_events(PGSCAN_SKIP, zone, skipped);
		}

		if (!remaining || isolated >= MIN_LRU_BATCH)
		/* 是因为扫描批次用完了, 或者isolate到了足够页面退出的上个zone的扫描,
			那么也不用扫描其他的zone了,退出for循环 */
			break;
	}

	item = PGSCAN_KSWAPD + reclaimer_offset();
	if (!cgroup_reclaim(sc)) {
		__count_vm_events(item, isolated);
		__count_vm_events(PGREFILL, sorted);
	}

	__count_memcg_events(memcg, item, isolated);
	__count_memcg_events(memcg, PGREFILL, sorted);
	__count_vm_events(PGSCAN_ANON + type, isolated);

	/*
	 * There might not be eligible folios due to reclaim_idx. Check the
	 * remaining to prevent livelock if it's not making progress.
	 返回isolate的数量,
	 如果没有isolate到任何页面, 就看是否remaining返回扫描的数量或者0
	 */
	return isolated || !remaining ? scanned : 0;
}

static int get_tier_idx(struct lruvec *lruvec, int type)
{
	int tier;
	struct ctrl_pos sp, pv;

	/*
	 * To leave a margin for fluctuations, use a larger gain factor (1:2).
	 * This value is chosen because any other tier would have at least twice
	 * as many refaults as the first tier.
	 */
	read_ctrl_pos(lruvec, type, 0, 1, &sp);
	for (tier = 1; tier < MAX_NR_TIERS; tier++) {
		read_ctrl_pos(lruvec, type, tier, 2, &pv);
		if (!positive_ctrl_err(&sp, &pv))
			break;
	}

	return tier - 1;
}

static int get_type_to_scan(struct lruvec *lruvec, int swappiness, int *tier_idx)
{
	int type, tier;
	struct ctrl_pos sp, pv;
	int gain[ANON_AND_FILE] = { swappiness, 200 - swappiness };

	/*
	 * Compare the first tier of anon with that of file to determine which
	 * type to scan. Also need to compare other tiers of the selected type
	 * with the first tier of the other type to determine the last tier (of
	 * the selected type) to evict.
	 */
	read_ctrl_pos(lruvec, LRU_GEN_ANON, 0, gain[LRU_GEN_ANON], &sp);
	read_ctrl_pos(lruvec, LRU_GEN_FILE, 0, gain[LRU_GEN_FILE], &pv);
	type = positive_ctrl_err(&sp, &pv);

	read_ctrl_pos(lruvec, !type, 0, gain[!type], &sp);
	for (tier = 1; tier < MAX_NR_TIERS; tier++) {
		read_ctrl_pos(lruvec, type, tier, gain[type], &pv);
		if (!positive_ctrl_err(&sp, &pv))
			break;
	}

	*tier_idx = tier - 1;

	return type;
}
/* 回收前这个函数isolate页面
===========================
最多isolate 64个页面
 */
static int isolate_folios(struct lruvec *lruvec, struct scan_control *sc, int swappiness,
			  int *type_scanned, struct list_head *list)
{
	int i;
	int type;
	int scanned;
	int tier = -1;
	DEFINE_MIN_SEQ(lruvec);

	/*
	 * Try to make the obvious choice first. When anon and file are both
	 * available from the same generation, interpret swappiness 1 as file
	 * first and 200 as anon first.
	 */
	if (!swappiness)
		type = LRU_GEN_FILE;
	else if (min_seq[LRU_GEN_ANON] < min_seq[LRU_GEN_FILE])
		type = LRU_GEN_ANON;
	else if (swappiness == 1)
		type = LRU_GEN_FILE;
	else if (swappiness == 200)
		type = LRU_GEN_ANON;
	else
		type = get_type_to_scan(lruvec, swappiness, &tier);


	for (i = !swappiness; i < ANON_AND_FILE; i++) {
		if (tier < 0)
			tier = get_tier_idx(lruvec, type);
		
		/* 返回isolate或者scan的数量, isolate的页面在list. 最多isolate 64个页面 */
		scanned = scan_folios(lruvec, sc, type, tier, list);
		if (scanned)
			break;

		type = !type;
		tier = -1;
	}

	*type_scanned = type;

	return scanned;
}
/* mglru回收lru的函数
返回扫描的数量.
返回0也可能是因为lru都太新了.
 */
static int evict_folios(struct lruvec *lruvec, struct scan_control *sc, int swappiness)
{
	int type;
	int scanned;
	int reclaimed;
	LIST_HEAD(list);
	LIST_HEAD(clean);
	struct folio *folio;
	struct folio *next;
	enum vm_event_item item;
	struct reclaim_stat stat;
	struct lru_gen_mm_walk *walk;
	bool skip_retry = false;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	spin_lock_irq(&lruvec->lru_lock);
	/* isolate页面到list链表好进行回收. 最多取64个页面到list进行回收.
	这里算是回收的偏好, 回收什么页面, 比如文件还是匿名, 全看这里isolate什么
	页面到list链表进行下一步的回收 */

	scanned = isolate_folios(lruvec, sc, swappiness, &type, &list);
	/* 更新min_seq的值 */
	scanned += try_to_inc_min_seq(lruvec, swappiness);

	if (get_nr_gens(lruvec, !swappiness) == MIN_NR_GENS)/* 这是说明都很新? */
		scanned = 0;

	spin_unlock_irq(&lruvec->lru_lock);

	if (list_empty(&list))
		return scanned;
retry:
/* 开始回收isolate的页面 */
	reclaimed = shrink_folio_list(&list, pgdat, sc, &stat, false);
	sc->nr_reclaimed += reclaimed;

	/* 处理list里面剩余的page(shrink_folio_list函数因为各种原因放回的page) */
	list_for_each_entry_safe_reverse(folio, next, &list, lru) {
		if (!folio_evictable(folio)) {/* unevictable的page */
			list_del(&folio->lru);
			folio_putback_lru(folio);
			continue;
		}

		if (folio_test_reclaim(folio) &&
		    (folio_test_dirty(folio) || folio_test_writeback(folio))) {
			/* restore LRU_REFS_FLAGS cleared by isolate_folio() */
			if (folio_test_workingset(folio))
				folio_set_referenced(folio);
			continue;
		}

		if (skip_retry || folio_test_active(folio) || folio_test_referenced(folio) ||
		    folio_mapped(folio) || folio_test_locked(folio) ||
		    folio_test_dirty(folio) || folio_test_writeback(folio)) {
			/* don't add rejected folios to the oldest generation */
			set_mask_bits(&folio->flags, LRU_REFS_MASK | LRU_REFS_FLAGS,
				      BIT(PG_active));
			continue;
		}

		/* retry folios that may have missed folio_rotate_reclaimable() */
		/* clean链表里面的page似乎后续会继续重试回收? */
		list_move(&folio->lru, &clean);
		/* 这个folio算是回收失败了,好像可能会重试,这里避免重复记录scan数量 */
		sc->nr_scanned -= folio_nr_pages(folio);
	}

	spin_lock_irq(&lruvec->lru_lock);

	/* 把list放回 */
	move_folios_to_lru(lruvec, &list);
	/* 上面这个函数返回之后, list里面是需要free的page */

	walk = current->reclaim_state->mm_walk;
	if (walk && walk->batched)
		reset_batch_size(lruvec, walk);

	item = PGSTEAL_KSWAPD + reclaimer_offset();
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, reclaimed);
	__count_memcg_events(memcg, item, reclaimed);
	__count_vm_events(PGSTEAL_ANON + type, reclaimed);

	spin_unlock_irq(&lruvec->lru_lock);

	/* 处理这些需要free的page */
	mem_cgroup_uncharge_list(&list);
	free_unref_page_list(&list);

	/* 现在继续重新利用这个list链表 */
	INIT_LIST_HEAD(&list);
	/* 把clean的装入list, 继续进行回收 */
	list_splice_init(&clean, &list);

	if (!list_empty(&list)) {/* 说明有clean链表的元素被接过来了 */
		skip_retry = true;
		goto retry;
	}

	return scanned;
}
/* 
2024年10月28日10:33:19
主要还是获取可以scan的数量
也会根据获取的中间状态顺便判断是否可以age了.
 */
static bool should_run_aging(struct lruvec *lruvec, unsigned long max_seq,
			     struct scan_control *sc, bool can_swap, unsigned long *nr_to_scan)
{
	int gen, type, zone;
	unsigned long old = 0;
	unsigned long young = 0;
	unsigned long total = 0;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	/* whether this lruvec is completely out of cold folios
	如果不能swap,这里看file.
	可以swap,看anon
	 */
	if (min_seq[!can_swap] + MIN_NR_GENS > max_seq) {
		*nr_to_scan = 0;
		return true;
	}

	/* 可能从anon或者file开始遍历 */
	for (type = !can_swap; type < ANON_AND_FILE; type++) {/* 遍历type */
		unsigned long seq;

		for (seq = min_seq[type]; seq <= max_seq; seq++) {/* 遍历每一个gen */
			unsigned long size = 0;

			gen = lru_gen_from_seq(seq);

			for (zone = 0; zone < MAX_NR_ZONES; zone++)/* 遍历每一个zone */
			/* 获取指定gen指定type指定zone的数量 */
				size += max(READ_ONCE(lrugen->nr_pages[gen][type][zone]), 0L);

			total += size;

			/* 分别统计young和old的size */
			if (seq == max_seq)
				young += size;
			else if (seq + MIN_NR_GENS == max_seq)
				old += size;
		}
	}

	/* try to scrape all its memory if this memcg was deleted
	如果cgroup已经下线了, 就直接回收全部的total
	如果还没下线，可能是避免颠簸,这里进行处理,prio越大(说明刚开始回收),total
	就越小(开始的时候回收少一点).
	 */
	*nr_to_scan = mem_cgroup_online(memcg) ? (total >> sc->priority) : total;

	/*
	 * The aging tries to be lazy to reduce the overhead, while the eviction
	 * stalls when the number of generations reaches MIN_NR_GENS. Hence, the
	 * ideal number of generations is MIN_NR_GENS+1.

	 */
	if (min_seq[!can_swap] + MIN_NR_GENS < max_seq)
		return false;

	/*
	 * It's also ideal to spread pages out evenly, i.e., 1/(MIN_NR_GENS+1)
	 * of the total number of pages for each generation. A reasonable range
	 * for this average portion is [1/MIN_NR_GENS, 1/(MIN_NR_GENS+2)]. The
	 * aging cares about the upper bound of hot pages, while the eviction
	 * cares about the lower bound of cold pages.

	 */
	if (young * MIN_NR_GENS > total) /* 说明年轻的够多 */
		return true;

	if (old * (MIN_NR_GENS + 2) < total) /* 说明old的比较少了 */
		return true;

	return false;
}

/*

 * For future optimizations:
 * 1. Defer try_to_inc_max_seq() to workqueues to reduce latency for memcg
 *    reclaim.
 返回0表示没有可以scan的了
 返回-1似乎表示内部老化失败了
 */
static long get_nr_to_scan(struct lruvec *lruvec, struct scan_control *sc, bool can_swap)
{
	unsigned long nr_to_scan;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MAX_SEQ(lruvec);

	if (mem_cgroup_below_min(sc->target_mem_cgroup, memcg))
		return 0;

	if (!should_run_aging(lruvec, max_seq, sc, can_swap, &nr_to_scan))
		return nr_to_scan;

	/* 到这里说明需要age */


	/* skip the aging path at the default priority
	刚开始回收, 没必要aging? */
	if (sc->priority == DEF_PRIORITY)
		return nr_to_scan;

	/* skip this lruvec as it's low on cold folios */
	return try_to_inc_max_seq(lruvec, max_seq, sc, can_swap, false) ? -1 : 0;
}

/* 对于全局回收才有结束回收的作用 */
static unsigned long get_nr_to_reclaim(struct scan_control *sc)
{
	/* don't abort memcg reclaim to ensure fairness */
	if (!root_reclaim(sc))
		return -1;

	return max(sc->nr_to_reclaim, compact_gap(sc->order));
}
/* mglru的shrink方式
扫描和回收的数量?
对于cgroup回收: 一次操作最多回收64个页面
 */
static bool try_to_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	long nr_to_scan;
	unsigned long scanned = 0;
	/* 获取全局回收的回收目标 */
	unsigned long nr_to_reclaim = get_nr_to_reclaim(sc);
	int swappiness = get_swappiness(lruvec, sc);

	/* clean file folios are more likely to exist */
	if (swappiness && !(sc->gfp_mask & __GFP_IO))
		swappiness = 1;

	while (true) {/* 终止条件? */
		int delta;

		/* 获取lruvec上面可以scan的数量, 可能会进行老化 */
		nr_to_scan = get_nr_to_scan(lruvec, sc, swappiness);
		if (nr_to_scan <= 0)
			break;
		/* 这里进行实质回收,每次差不多回收64个
		返回scan的数量 */
		delta = evict_folios(lruvec, sc, swappiness);
		if (!delta)/* 这里退出的条件可能是什么, */
			break;

		scanned += delta;
		if (scanned >= nr_to_scan)
			break;
		
		/* 对于全局回收, 可能会break, 
		对于cgroup回收,nr_to_reclaim一直是-1,一直break.  */
		if (sc->nr_reclaimed >= nr_to_reclaim)
			break;

		cond_resched();
	}

	/* whether try_to_inc_max_seq() was successful */
	return nr_to_scan < 0;
}
/* 不管是shrink_many,还是one, 最终都是调用这个函数.
1. mglru的全局回收调用

回收lruvec的内存. */
static int shrink_one(struct lruvec *lruvec, struct scan_control *sc)
{
	bool success;
	unsigned long scanned = sc->nr_scanned;
	unsigned long reclaimed = sc->nr_reclaimed;
	int seg = lru_gen_memcg_seg(lruvec);
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	/* see the comment on MEMCG_NR_GENS */
	if (!lruvec_is_sizable(lruvec, sc))
		return seg != MEMCG_LRU_TAIL ? MEMCG_LRU_TAIL : MEMCG_LRU_YOUNG;

	mem_cgroup_calculate_protection(NULL, memcg);

	if (mem_cgroup_below_min(NULL, memcg))
		return MEMCG_LRU_YOUNG;

	if (mem_cgroup_below_low(NULL, memcg)) {
		/* see the comment on MEMCG_NR_GENS */
		if (seg != MEMCG_LRU_TAIL)
			return MEMCG_LRU_TAIL;

		memcg_memory_event(memcg, MEMCG_LOW);
	}
	/* 回收lruvec */
	success = try_to_shrink_lruvec(lruvec, sc);
	/* 回收slab , ignore_slab */
	shrink_slab(sc->gfp_mask, pgdat->node_id, memcg, sc->priority);

	if (!sc->proactive)
		vmpressure(sc->gfp_mask, memcg, false, sc->nr_scanned - scanned,
			   sc->nr_reclaimed - reclaimed);

	flush_reclaim_state(sc);

	return success ? MEMCG_LRU_YOUNG : 0;
}

#ifdef CONFIG_MEMCG
/* 开启lrugen的全局回收 */
static void shrink_many(struct pglist_data *pgdat, struct scan_control *sc)
{
	int op;
	int gen;
	int bin;
	int first_bin;
	struct lruvec *lruvec;
	struct lru_gen_folio *lrugen;
	struct mem_cgroup *memcg;
	const struct hlist_nulls_node *pos;
	/* 这里获取要回收的数量 */
	unsigned long nr_to_reclaim = get_nr_to_reclaim(sc);
	pr_debug("%s, reclaim mglru node pagecache start iter every memcg ...  \n",__func__);
	bin = first_bin = get_random_u32_below(MEMCG_NR_BINS);
restart:
	op = 0;
	memcg = NULL;
	gen = get_memcg_gen(READ_ONCE(pgdat->memcg_lru.seq));
	
	rcu_read_lock();
	/* 这里同样是遍历node上面的全部的lruvec

	不过相比于传统lru的iter按照树的结构遍历lruvec, 这里是更快的方式, 还是按照预定义的方式排序的
	可以更快取到合适的lruvec, 更快达到回收目标.
	 */
	hlist_nulls_for_each_entry_rcu(lrugen, pos, &pgdat->memcg_lru.fifo[gen][bin], list) {
		if (op) {
			lru_gen_rotate_memcg(lruvec, op);
			op = 0;
		}

		mem_cgroup_put(memcg);
		/* 根据node的fifo排序，获得lruvec */
		lruvec = container_of(lrugen, struct lruvec, lrugen);
		memcg = lruvec_memcg(lruvec);

		if (!mem_cgroup_tryget(memcg)) {
			lru_gen_release_memcg(memcg);
			memcg = NULL;
			continue;
		}

		rcu_read_unlock();
		/* 获取到了一个memcg, 这里进行操作. */
		op = shrink_one(lruvec, sc);


		rcu_read_lock();/* 这个是为了下一个循环lock的 */

		/* 对于全局回收,这里才有意义 */
		if (sc->nr_reclaimed >= nr_to_reclaim)
			break;
	}

	rcu_read_unlock();

	if (op)/* 继续调整位置 */
		lru_gen_rotate_memcg(lruvec, op);

	mem_cgroup_put(memcg);

	/* 对于全局回收,这里才有意义 */
	if (sc->nr_reclaimed >= nr_to_reclaim)
		return;

	/* restart if raced with lru_gen_rotate_memcg() */
	if (gen != get_nulls_value(pos))
		goto restart;

	/* try the rest of the bins of the current generation
	处理同代的下一个bin */
	bin = get_memcg_bin(bin + 1);
	if (bin != first_bin)
		goto restart;
}
/* mglru的memcg回收lruvec路径
回收和扫描的数量?
cgroup回收最多64个页面
 */
static void lru_gen_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	struct blk_plug plug;

	VM_WARN_ON_ONCE(root_reclaim(sc));
	VM_WARN_ON_ONCE(!sc->may_writepage || !sc->may_unmap);

	/* may_writepage && may_unmap */
	lru_add_drain();

	blk_start_plug(&plug);

	set_mm_walk(NULL, sc->proactive);

	if (try_to_shrink_lruvec(lruvec, sc))
		lru_gen_rotate_memcg(lruvec, MEMCG_LRU_YOUNG);

	clear_mm_walk();

	blk_finish_plug(&plug);
}

#else /* !CONFIG_MEMCG */

static void shrink_many(struct pglist_data *pgdat, struct scan_control *sc)
{
	BUILD_BUG();
}

static void lru_gen_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	BUILD_BUG();
}

#endif

/* 改变sc的prio
只在mglru的全局回收调用 */
static void set_initial_priority(struct pglist_data *pgdat, struct scan_control *sc)
{
	int priority;
	unsigned long reclaimable;
	/* 因为全局回收, 所有是获得root memcg在此node的lruvec */
	struct lruvec *lruvec = mem_cgroup_lruvec(NULL, pgdat);

	if (sc->priority != DEF_PRIORITY  /* 如果不是刚开始回收 */
	|| sc->nr_to_reclaim < MIN_LRU_BATCH  /* 或者? */
	)
		return;

	/* 刚开始回收,或者回收量比较大 */

	
	/*
	 * Determine the initial priority based on (
	 (total / MEMCG_NR_GENS) >> priority) * reclaimed_to_scanned_ratio = nr_to_reclaim, 
	 where the estimated reclaimed_to_scanned_ratio = inactive / total.

	 */
	 /* node上面的可回收不活跃页 */
	reclaimable = node_page_state(pgdat, NR_INACTIVE_FILE);
	if (get_swappiness(lruvec, sc))
		reclaimable += node_page_state(pgdat, NR_INACTIVE_ANON);
	
	/* 可回收的数量 */
	reclaimable /= MEMCG_NR_GENS;
	/*  */
	/* round down reclaimable and round up sc->nr_to_reclaim */
	priority = fls_long(reclaimable) - 1 - fls_long(sc->nr_to_reclaim - 1);

	sc->priority = clamp(priority, 0, DEF_PRIORITY);
}
/* mglru的全局回收 */
static void lru_gen_shrink_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	struct blk_plug plug;
	unsigned long reclaimed = sc->nr_reclaimed;

	VM_WARN_ON_ONCE(!root_reclaim(sc));

	/*
	 * Unmapped clean folios are already prioritized. Scanning for more of
	 * them is likely futile and can cause high reclaim latency when there
	 * is a large number of memcgs.
	 */
	if (!sc->may_writepage || !sc->may_unmap)
		goto done;
	
	/* may_writepage && may_unmap */

	lru_add_drain();

	blk_start_plug(&plug);

	set_mm_walk(pgdat, sc->proactive);

	set_initial_priority(pgdat, sc);/* 重新计算prio */

	if (current_is_kswapd()) /* 针对kswap的特殊处理, 因为每次回收node,
	kswap的nr_to_reclaim会置零 */
		sc->nr_reclaimed = 0;

	if (mem_cgroup_disabled())/* 没有memcg, 那么只需要处理node的lruvec */
		shrink_one(&pgdat->__lruvec, sc);
	else /* 有的话, 就需要处理target_mmecg的每一个子memcg在此node上面的lruvec */
		shrink_many(pgdat, sc);

	if (current_is_kswapd())
		sc->nr_reclaimed += reclaimed;

	clear_mm_walk();

	blk_finish_plug(&plug);

done:
	/* kswapd should never fail */
	pgdat->kswapd_failures = 0;
}


/******************************************************************************
 *                          state change
 ******************************************************************************/
/* 2024年11月05日10:19:43
用于判断mglru和传统lru是否切换成功.
 */
static bool __maybe_unused state_is_valid(struct lruvec *lruvec)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	if (lrugen->enabled) {/* mglru */
		enum lru_list lru;

		for_each_evictable_lru(lru) {
			if (!list_empty(&lruvec->lists[lru]))
				return false;
		}
	} else {/* 传统lru的话，folios不能有页面 */
		int gen, type, zone;

		for_each_gen_type_zone(gen, type, zone) {
			if (!list_empty(&lrugen->folios[gen][type][zone]))
				return false;
		}
	}

	return true;
}
/* 把lruvec从普通机制转为lrugen机制 */
static bool fill_evictable(struct lruvec *lruvec)
{
	enum lru_list lru;
	int remaining = MAX_LRU_BATCH;

	for_each_evictable_lru(lru) {
		int type = is_file_lru(lru);
		bool active = is_active_lru(lru);
		struct list_head *head = &lruvec->lists[lru];

		while (!list_empty(head)) {
			bool success;
			struct folio *folio = lru_to_folio(head);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio) != active, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_lru_gen(folio) != -1, folio);

			lruvec_del_folio(lruvec, folio);
			success = lru_gen_add_folio(lruvec, folio, false);
			VM_WARN_ON_ONCE(!success);

			if (!--remaining)
				return false;
		}
	}

	return true;
}

static bool drain_evictable(struct lruvec *lruvec)
{
	int gen, type, zone;
	int remaining = MAX_LRU_BATCH;

	for_each_gen_type_zone(gen, type, zone) {
		struct list_head *head = &lruvec->lrugen.folios[gen][type][zone];

		while (!list_empty(head)) {
			bool success;
			struct folio *folio = lru_to_folio(head);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_zonenum(folio) != zone, folio);

			success = lru_gen_del_folio(lruvec, folio, false);
			VM_WARN_ON_ONCE(!success);
			lruvec_add_folio(lruvec, folio);

			if (!--remaining)
				return false;
		}
	}

	return true;
}
/* 开启lru_gen的回调 */
/* 在传统lru与mglru切换 */
static void lru_gen_change_state(bool enabled)
{
	static DEFINE_MUTEX(state_mutex);

	struct mem_cgroup *memcg;

	cgroup_lock();
	cpus_read_lock();
	get_online_mems();
	mutex_lock(&state_mutex);

	if (enabled == lru_gen_enabled())/* 已经好了 */
		goto unlock;

	if (enabled)
		static_branch_enable_cpuslocked(&lru_gen_caps[LRU_GEN_CORE]);
	else
		static_branch_disable_cpuslocked(&lru_gen_caps[LRU_GEN_CORE]);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		int nid;

		for_each_node(nid) {/* 处理每个memcg的每一个lruvec */
			struct lruvec *lruvec = get_lruvec(memcg, nid);

			spin_lock_irq(&lruvec->lru_lock);

			VM_WARN_ON_ONCE(!seq_is_valid(lruvec));
			VM_WARN_ON_ONCE(!state_is_valid(lruvec));

			lruvec->lrugen.enabled = enabled;

			while (!(enabled ? fill_evictable(lruvec) : drain_evictable(lruvec))) {
				spin_unlock_irq(&lruvec->lru_lock);
				cond_resched();
				spin_lock_irq(&lruvec->lru_lock);
			}

			spin_unlock_irq(&lruvec->lru_lock);
		}

		cond_resched();
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));
unlock:
	mutex_unlock(&state_mutex);
	put_online_mems();
	cpus_read_unlock();
	cgroup_unlock();
}

/******************************************************************************
 *                          sysfs interface
 ******************************************************************************/

static ssize_t min_ttl_ms_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", jiffies_to_msecs(READ_ONCE(lru_gen_min_ttl)));
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details */
static ssize_t min_ttl_ms_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t len)
{
	unsigned int msecs;

	if (kstrtouint(buf, 0, &msecs))
		return -EINVAL;

	WRITE_ONCE(lru_gen_min_ttl, msecs_to_jiffies(msecs));

	return len;
}

static struct kobj_attribute lru_gen_min_ttl_attr = __ATTR_RW(min_ttl_ms);

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	unsigned int caps = 0;

	if (get_cap(LRU_GEN_CORE))
		caps |= BIT(LRU_GEN_CORE);

	if (should_walk_mmu())
		caps |= BIT(LRU_GEN_MM_WALK);

	if (should_clear_pmd_young())
		caps |= BIT(LRU_GEN_NONLEAF_YOUNG);

	return sysfs_emit(buf, "0x%04x\n", caps);
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details */
static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t len)
{
	int i;
	unsigned int caps;

	if (tolower(*buf) == 'n')
		caps = 0;
	else if (tolower(*buf) == 'y')
		caps = -1;
	else if (kstrtouint(buf, 0, &caps))
		return -EINVAL;

	for (i = 0; i < NR_LRU_GEN_CAPS; i++) {
		bool enabled = caps & BIT(i);

		if (i == LRU_GEN_CORE)
			lru_gen_change_state(enabled);
		else if (enabled)
			static_branch_enable(&lru_gen_caps[i]);
		else
			static_branch_disable(&lru_gen_caps[i]);
	}

	return len;
}

static struct kobj_attribute lru_gen_enabled_attr = __ATTR_RW(enabled);

static struct attribute *lru_gen_attrs[] = {
	&lru_gen_min_ttl_attr.attr,
	&lru_gen_enabled_attr.attr,
	NULL
};

static const struct attribute_group lru_gen_attr_group = {
	.name = "lru_gen",
	.attrs = lru_gen_attrs,
};

/******************************************************************************
 *                          debugfs interface
 ******************************************************************************/

/* debugfs的接口 */
static void *lru_gen_seq_start(struct seq_file *m, loff_t *pos)
{
	struct mem_cgroup *memcg;
	loff_t nr_to_skip = *pos;

	m->private = kvmalloc(PATH_MAX, GFP_KERNEL);
	if (!m->private)
		return ERR_PTR(-ENOMEM);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		int nid;

		for_each_node_state(nid, N_MEMORY) {
			if (!nr_to_skip--)
				return get_lruvec(memcg, nid);
		}
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));

	return NULL;
}

static void lru_gen_seq_stop(struct seq_file *m, void *v)
{
	if (!IS_ERR_OR_NULL(v))
		mem_cgroup_iter_break(NULL, lruvec_memcg(v));

	kvfree(m->private);
	m->private = NULL;
}

static void *lru_gen_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	int nid = lruvec_pgdat(v)->node_id;
	struct mem_cgroup *memcg = lruvec_memcg(v);

	++*pos;

	nid = next_memory_node(nid);
	if (nid == MAX_NUMNODES) {
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
		if (!memcg)
			return NULL;

		nid = first_memory_node;
	}

	return get_lruvec(memcg, nid);
}

static void lru_gen_seq_show_full(struct seq_file *m, struct lruvec *lruvec,
				  unsigned long max_seq, unsigned long *min_seq,
				  unsigned long seq)
{
	int i;
	int type, tier;
	int hist = lru_hist_from_seq(seq);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		seq_printf(m, "            %10d", tier);
		for (type = 0; type < ANON_AND_FILE; type++) {
			const char *s = "   ";
			unsigned long n[3] = {};

			if (seq == max_seq) {
				s = "RT ";
				n[0] = READ_ONCE(lrugen->avg_refaulted[type][tier]);
				n[1] = READ_ONCE(lrugen->avg_total[type][tier]);
			} else if (seq == min_seq[type] || NR_HIST_GENS > 1) {
				s = "rep";
				n[0] = atomic_long_read(&lrugen->refaulted[hist][type][tier]);
				n[1] = atomic_long_read(&lrugen->evicted[hist][type][tier]);
				if (tier)
					n[2] = READ_ONCE(lrugen->protected[hist][type][tier - 1]);
			}

			for (i = 0; i < 3; i++)
				seq_printf(m, " %10lu%c", n[i], s[i]);
		}
		seq_putc(m, '\n');
	}

	seq_puts(m, "                      ");
	for (i = 0; i < NR_MM_STATS; i++) {
		const char *s = "      ";
		unsigned long n = 0;

		if (seq == max_seq && NR_HIST_GENS == 1) {
			s = "LOYNFA";
			n = READ_ONCE(lruvec->mm_state.stats[hist][i]);
		} else if (seq != max_seq && NR_HIST_GENS > 1) {
			s = "loynfa";
			n = READ_ONCE(lruvec->mm_state.stats[hist][i]);
		}

		seq_printf(m, " %10lu%c", n, s[i]);
	}
	seq_putc(m, '\n');
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details 
显示统计信息?
*/
static int lru_gen_seq_show(struct seq_file *m, void *v)
{
	unsigned long seq;
	bool full = !debugfs_real_fops(m->file)->write;
	struct lruvec *lruvec = v;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int nid = lruvec_pgdat(lruvec)->node_id;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MAX_SEQ(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	if (nid == first_memory_node) {
		const char *path = memcg ? m->private : "";

#ifdef CONFIG_MEMCG
		if (memcg)
			cgroup_path(memcg->css.cgroup, m->private, PATH_MAX);
#endif
		seq_printf(m, "memcg %5hu %s\n", mem_cgroup_id(memcg), path);
	}

	seq_printf(m, " node %5d\n", nid);

	if (!full)
		seq = min_seq[LRU_GEN_ANON];
	else if (max_seq >= MAX_NR_GENS)
		seq = max_seq - MAX_NR_GENS + 1;
	else
		seq = 0;

	for (; seq <= max_seq; seq++) {
		int type, zone;
		int gen = lru_gen_from_seq(seq);
		unsigned long birth = READ_ONCE(lruvec->lrugen.timestamps[gen]);

		seq_printf(m, " %10lu %10u", seq, jiffies_to_msecs(jiffies - birth));

		for (type = 0; type < ANON_AND_FILE; type++) {
			unsigned long size = 0;
			char mark = full && seq < min_seq[type] ? 'x' : ' ';

			for (zone = 0; zone < MAX_NR_ZONES; zone++)
				size += max(READ_ONCE(lrugen->nr_pages[gen][type][zone]), 0L);

			seq_printf(m, " %10lu%c", size, mark);
		}

		seq_putc(m, '\n');

		if (full)
			lru_gen_seq_show_full(m, lruvec, max_seq, min_seq, seq);
	}

	return 0;
}
/* mglru的fs的相关回调. */
static const struct seq_operations lru_gen_seq_ops = {
	.start = lru_gen_seq_start,
	.stop = lru_gen_seq_stop,
	.next = lru_gen_seq_next,
	.show = lru_gen_seq_show,
};
/* mglru的老化 */
/* fs接口的回调函数 */
static int run_aging(struct lruvec *lruvec, unsigned long seq, struct scan_control *sc,
		     bool can_swap, bool force_scan)
{

	DEFINE_MAX_SEQ(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	if (seq < max_seq)
		return 0;

	if (seq > max_seq)
		return -EINVAL;

	if (!force_scan && min_seq[!can_swap] + MAX_NR_GENS - 1 <= max_seq)
		return -ERANGE;

	try_to_inc_max_seq(lruvec, max_seq, sc, can_swap, force_scan);

	return 0;
}

/* 这里才开始回收内存. 其实也算是回收指定lruvec */
static int run_eviction(struct lruvec *lruvec, unsigned long seq, struct scan_control *sc,
			int swappiness, unsigned long nr_to_reclaim)
{
	DEFINE_MAX_SEQ(lruvec);

	if (seq + MIN_NR_GENS > max_seq)
		return -EINVAL;

	sc->nr_reclaimed = 0;

	while (!signal_pending(current)) {
		DEFINE_MIN_SEQ(lruvec);

		if (seq < min_seq[!swappiness])
			return 0;

		if (sc->nr_reclaimed >= nr_to_reclaim)
			return 0;

		if (!evict_folios(lruvec, sc, swappiness))
			return 0;

		cond_resched();
	}

	return -EINTR;
}

/* 通过mglru的fs接口的命令来回收指定内存 */
static int run_cmd(char cmd, int memcg_id, int nid, unsigned long seq,
		   struct scan_control *sc, int swappiness, unsigned long opt)
{
	struct lruvec *lruvec;
	int err = -EINVAL;
	struct mem_cgroup *memcg = NULL;

	if (nid < 0 || nid >= MAX_NUMNODES || !node_state(nid, N_MEMORY))
		return -EINVAL;

	if (!mem_cgroup_disabled()) {
		rcu_read_lock();

		memcg = mem_cgroup_from_id(memcg_id);
		if (!mem_cgroup_tryget(memcg))
			memcg = NULL;

		rcu_read_unlock();

		if (!memcg)
			return -EINVAL;
	}

	if (memcg_id != mem_cgroup_id(memcg))
		goto done;

	/* 获取要回收的lruvec */
	lruvec = get_lruvec(memcg, nid);

	if (swappiness < 0)
		swappiness = get_swappiness(lruvec, sc);
	else if (swappiness > 200)
		goto done;

	switch (cmd) {
	case '+':
		err = run_aging(lruvec, seq, sc, swappiness, opt);
		break;
	case '-':
		err = run_eviction(lruvec, seq, sc, swappiness, opt);
		break;
	}
done:
	mem_cgroup_put(memcg);

	return err;
}

/* 
mglru的fs接口那个触发回收的命令
see Documentation/admin-guide/mm/multigen_lru.rst for details */
static ssize_t lru_gen_seq_write(struct file *file, const char __user *src,
				 size_t len, loff_t *pos)
{
	void *buf;
	char *cur, *next;
	unsigned int flags;
	struct blk_plug plug;
	int err = -EINVAL;
	struct scan_control sc = {
		.may_writepage = true,
		.may_unmap = true,
		.may_swap = true,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.gfp_mask = GFP_KERNEL,
	};

	buf = kvmalloc(len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, src, len)) {
		kvfree(buf);
		return -EFAULT;
	}

	set_task_reclaim_state(current, &sc.reclaim_state);
	flags = memalloc_noreclaim_save();
	blk_start_plug(&plug);
	if (!set_mm_walk(NULL, true)) {
		err = -ENOMEM;
		goto done;
	}

	next = buf;
	next[len] = '\0';

	while ((cur = strsep(&next, ",;\n"))) {
		int n;
		int end;
		char cmd;
		unsigned int memcg_id;
		unsigned int nid;
		unsigned long seq;
		unsigned int swappiness = -1;
		unsigned long opt = -1;

		cur = skip_spaces(cur);
		if (!*cur)
			continue;

		n = sscanf(cur, "%c %u %u %lu %n %u %n %lu %n", &cmd, &memcg_id, &nid,
			   &seq, &end, &swappiness, &end, &opt, &end);
		if (n < 4 || cur[end]) {
			err = -EINVAL;
			break;
		}

		/* 运行回收命令 */
		err = run_cmd(cmd, memcg_id, nid, seq, &sc, swappiness, opt);
		if (err)
			break;
	}
done:
	clear_mm_walk();
	blk_finish_plug(&plug);
	memalloc_noreclaim_restore(flags);
	set_task_reclaim_state(current, NULL);

	kvfree(buf);

	return err ? : len;
}
/*  */
static int lru_gen_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &lru_gen_seq_ops);
}

static const struct file_operations lru_gen_rw_fops = {
	.open = lru_gen_seq_open,
	.read = seq_read,
	.write = lru_gen_seq_write,
	.llseek = seq_lseek,
	.release = seq_release,
};
/* mglru的fs回调 */
static const struct file_operations lru_gen_ro_fops = {
	.open = lru_gen_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/******************************************************************************
 *                          initialization
 ******************************************************************************/

void lru_gen_init_lruvec(struct lruvec *lruvec)
{
	int i;
	int gen, type, zone;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	lrugen->max_seq = MIN_NR_GENS + 1;
	lrugen->enabled = lru_gen_enabled();

	for (i = 0; i <= MIN_NR_GENS + 1; i++)
		lrugen->timestamps[i] = jiffies;

	for_each_gen_type_zone(gen, type, zone)
		INIT_LIST_HEAD(&lrugen->folios[gen][type][zone]);

	lruvec->mm_state.seq = MIN_NR_GENS;
}

#ifdef CONFIG_MEMCG

/* 对node上面的memcg的快速查找 */
void lru_gen_init_pgdat(struct pglist_data *pgdat)
{
	int i, j;

	spin_lock_init(&pgdat->memcg_lru.lock);

	for (i = 0; i < MEMCG_NR_GENS; i++) {
		for (j = 0; j < MEMCG_NR_BINS; j++)
			INIT_HLIST_NULLS_HEAD(&pgdat->memcg_lru.fifo[i][j], i);
	}
}

void lru_gen_init_memcg(struct mem_cgroup *memcg)
{
	INIT_LIST_HEAD(&memcg->mm_list.fifo);
	spin_lock_init(&memcg->mm_list.lock);
}

/* 从node上面移除对memcg的记录 */
void lru_gen_exit_memcg(struct mem_cgroup *memcg)
{
	int i;
	int nid;

	VM_WARN_ON_ONCE(!list_empty(&memcg->mm_list.fifo));

	for_each_node(nid) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		VM_WARN_ON_ONCE(memchr_inv(lruvec->lrugen.nr_pages, 0,
					   sizeof(lruvec->lrugen.nr_pages)));

		lruvec->lrugen.list.next = LIST_POISON1;

		for (i = 0; i < NR_BLOOM_FILTERS; i++) {
			bitmap_free(lruvec->mm_state.filters[i]);
			lruvec->mm_state.filters[i] = NULL;
		}
	}
}

#endif /* CONFIG_MEMCG */

static int __init init_lru_gen(void)
{
	BUILD_BUG_ON(MIN_NR_GENS + 1 >= MAX_NR_GENS);
	BUILD_BUG_ON(BIT(LRU_GEN_WIDTH) <= MAX_NR_GENS);

	if (sysfs_create_group(mm_kobj, &lru_gen_attr_group))
		pr_err("lru_gen: failed to create sysfs group\n");

	debugfs_create_file("lru_gen", 0644, NULL, NULL, &lru_gen_rw_fops);
	debugfs_create_file("lru_gen_full", 0444, NULL, NULL, &lru_gen_ro_fops);

	return 0;
};
late_initcall(init_lru_gen);

#else /* !CONFIG_LRU_GEN */

static void lru_gen_age_node(struct pglist_data *pgdat, struct scan_control *sc)
{
}

static void lru_gen_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
}

static void lru_gen_shrink_node(struct pglist_data *pgdat, struct scan_control *sc)
{
}

#endif /* CONFIG_LRU_GEN */
/* mmecg回收下回收lruvec的内存
-------------

mglru的cgroup回收最多扫描和回收64个页面
 */
/* 回收lruvec的内存, 回收某node内存, 这个是某个子memcg的lruvec */
static void shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long targets[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
	bool proportional_reclaim;
	struct blk_plug plug;

	if (lru_gen_enabled() && !root_reclaim(sc)) {/* mglru的memcg路径.
	mglru的全局路径,是在上层调用者的函数处理的 */
		lru_gen_shrink_lruvec(lruvec, sc);
		return;
	}

	/* 后面是非mglru的全局和memcg回收 */

	get_scan_count(lruvec, sc, nr);

	/* Record the original scan target for proportional adjustments later */
	memcpy(targets, nr, sizeof(nr));

	/*
	 * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
	 * event that can occur when there is little memory pressure e.g.
	 * multiple streaming readers/writers. 
	 Hence, we do not abort scanning
	 * when the requested number of pages are reclaimed when scanning at
	 * DEF_PRIORITY on the assumption that the fact we are direct
	 * reclaiming implies that kswapd is not keeping up and it is best to
	 * do a batch of work at once. 
	 For memcg reclaim one check is made to
	 * abort proportional reclaim if either the file or anon lru has already
	 * dropped to zero at the first pass.
	 在直接回收过程中，以DEF_PRIORITY进行全局回收是一个正常事件，这种情况可能
	 发生在内存压力较小的情况下，例如多个流式读写操作。
	 因此，当在DEF_PRIORITY下扫描时，即使回收了请求数量的页面，也不会中止扫描，因为
	 直接回收意味着 kswapd（内核的内存回收线程）未能跟上内存回收的速度，因此最好一次性完成一批工作。
	 对于内存控制组（memcg）回收，在第一次扫描时
	 会进行一次检查，如果文件或匿名 LRU（最近最少使用）链表已经降到零，则会中止按比例回收。
	 */

	 /* 判断是不是刚刚开始的全局直接回收 */
	proportional_reclaim = (!cgroup_reclaim(sc) && !current_is_kswapd() &&
				sc->priority == DEF_PRIORITY);

	blk_start_plug(&plug);
	/* 只要还有文件页和不活跃匿名页 */
	/* 只要get_scan_count获取的还有文件页和不活跃匿名页 */
	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		unsigned long nr_anon, nr_file, percentage;
		unsigned long nr_scanned;

		for_each_evictable_lru(lru) {
			if (nr[lru]) {/* 这个lru还有可回收的 */
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;

				nr_reclaimed += shrink_list(lru, nr_to_scan,
							    lruvec, sc);
			}
		}

		cond_resched();

		if (nr_reclaimed < nr_to_reclaim /* 没完成,继续 */
		|| proportional_reclaim /* 虽然完成了,但是是刚刚开始的全局直接回收,也继续 */
		)
			continue;

		/*
		 * For kswapd and memcg, reclaim at least the number of pages
		 * requested. Ensure that the anon and file LRUs are scanned
		 * proportionally what was requested by get_scan_count(). We
		 * stop reclaiming one LRU and reduce the amount scanning
		 * proportional to the original scan target.
		 */
		nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
		nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

		/*
		 * It's just vindictive to attack the larger once the smaller
		 * has gone to zero.  And given the way we stop scanning the
		 * smaller below, this makes sure that we only make one nudge
		 * towards proportionality once we've got nr_to_reclaim.
		 */
		if (!nr_file || !nr_anon)
			break;

		if (nr_file > nr_anon) {
			unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
						targets[LRU_ACTIVE_ANON] + 1;
			lru = LRU_BASE;
			percentage = nr_anon * 100 / scan_target;
		} else {
			unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
						targets[LRU_ACTIVE_FILE] + 1;
			lru = LRU_FILE;
			percentage = nr_file * 100 / scan_target;
		}

		/* Stop scanning the smaller of the LRU */
		nr[lru] = 0;
		nr[lru + LRU_ACTIVE] = 0;

		/*
		 * Recalculate the other LRU scan count based on its original
		 * scan target and the percentage scanning already complete
		 */
		lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);

		lru += LRU_ACTIVE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);
	}
	blk_finish_plug(&plug);
	/* 更新回收的页面数量 */
	sc->nr_reclaimed += nr_reclaimed;

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 */
	if (can_age_anon_pages(lruvec_pgdat(lruvec), sc) && inactive_is_low(lruvec, LRU_INACTIVE_ANON))
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);
}

/* Use reclaim/compaction for costly allocs or under memory pressure */
static bool in_reclaim_compaction(struct scan_control *sc)
{
	if (IS_ENABLED(CONFIG_COMPACTION) && sc->order &&
			(sc->order > PAGE_ALLOC_COSTLY_ORDER ||
			 sc->priority < DEF_PRIORITY - 2)) /* 说明页面需求比较大, 已经回收至少两遍了,开启了规整机制 */
		return true;

	return false;
}

/*
 * Reclaim/compaction is used for high-order allocation requests. It reclaims
 * order-0 pages before compacting the zone. should_continue_reclaim() returns
 * true if more pages should be reclaimed such that when the page allocator
 * calls try_to_compact_pages() that it will have enough free pages to succeed.
 * It will give up earlier than that if there is difficulty reclaiming pages.

 */
static inline bool should_continue_reclaim(struct pglist_data *pgdat,
					unsigned long nr_reclaimed,
					struct scan_control *sc)
{
	unsigned long pages_for_compaction;
	unsigned long inactive_lru_pages;
	int z;

	/* If not in reclaim/compaction mode, stop
	说明不是: (页面需求比较大, 已经回收至少两遍了,开启了规整机制)??? todo */
	if (!in_reclaim_compaction(sc))
		return false;

	/*
	 * Stop if we failed to reclaim any pages from the last SWAP_CLUSTER_MAX
	 * number of pages that were scanned. This will return to the caller
	 * with the risk reclaim/compaction and the resulting allocation attempt
	 * fails. In the past we have tried harder for __GFP_RETRY_MAYFAIL
	 * allocations through requiring that the full LRU list has been scanned
	 * first, by assuming that zero delta of sc->nr_scanned means full LRU
	 * scan, but that approximation was wrong, and there were corner cases
	 * where always a non-zero amount of pages were scanned.
	 */
	if (!nr_reclaimed)
		return false;

	/* If compaction would go ahead or the allocation would succeed, stop */
	for (z = 0; z <= sc->reclaim_idx; z++) {
		struct zone *zone = &pgdat->node_zones[z];
		if (!managed_zone(zone))
			continue;

		/* Allocation can already succeed, nothing to do */
		if (zone_watermark_ok(zone, sc->order, min_wmark_pages(zone),
				      sc->reclaim_idx, 0))
			return false;

		if (compaction_suitable(zone, sc->order, sc->reclaim_idx))
			return false;
	}

	/*
	 * If we have not reclaimed enough pages for compaction and the
	 * inactive lists are large enough, continue reclaiming
	 */
	pages_for_compaction = compact_gap(sc->order);
	inactive_lru_pages = node_page_state(pgdat, NR_INACTIVE_FILE);
	if (can_reclaim_anon_pages(NULL, pgdat->node_id, sc))
		inactive_lru_pages += node_page_state(pgdat, NR_INACTIVE_ANON);

	return inactive_lru_pages > pages_for_compaction;
}
/* 回收此node的内存
遍历memcg,逐个回收 */
static void shrink_node_memcgs(pg_data_t *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *target_memcg = sc->target_mem_cgroup;
	struct mem_cgroup *memcg;

	memcg = mem_cgroup_iter(target_memcg, NULL, NULL);
	do {
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
		unsigned long reclaimed;
		unsigned long scanned;

		/*
		 * This loop can become CPU-bound when target memcgs
		 * aren't eligible for reclaim - either because they
		 * don't have any reclaimable pages, or because their
		 * memory is explicitly protected. Avoid soft lockups.
		 */
		cond_resched();

		mem_cgroup_calculate_protection(target_memcg, memcg);

		/* 决定是否跳过当前遍历到的memcg */
		if (mem_cgroup_below_min(target_memcg, memcg)) {
			/*
			 * Hard protection.
			 * If there is no reclaimable memory, OOM.
			 */
			continue;
		} else if (mem_cgroup_below_low(target_memcg, memcg)) {
			/*
			 * Soft protection.
			 * Respect the protection only as long as
			 * there is an unprotected supply
			 * of reclaimable memory from other cgroups.
			 */
			if (!sc->memcg_low_reclaim) {/* 如果不回收low的话,就跳过 */
				sc->memcg_low_skipped = 1;
				continue;
			}
			memcg_memory_event(memcg, MEMCG_LOW);
		}

		/* 决定回收此memcg */
		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;
		/* mglru的cgroup回收最多回收64个页面 */
		shrink_lruvec(lruvec, sc);

		shrink_slab(sc->gfp_mask, pgdat->node_id, memcg,
			    sc->priority);

		/* Record the group's reclaim efficiency */
		if (!sc->proactive)
			vmpressure(sc->gfp_mask, memcg, false,
				   sc->nr_scanned - scanned,
				   sc->nr_reclaimed - reclaimed);

	} while ((memcg = mem_cgroup_iter(target_memcg, memcg, NULL)));
}


/* 回收node的内存
=======================
使用之前可以归零nr_scanned,也可以临时设置nr_to_reclaim(kswap). */
static void shrink_node(pg_data_t *pgdat, struct scan_control *sc)
{
	unsigned long nr_reclaimed, nr_scanned, nr_node_reclaimed;
	struct lruvec *target_lruvec;
	bool reclaimable = false;


	/* 全局 mglru 走这里 */
	if (lru_gen_enabled() && root_reclaim(sc)) {
		lru_gen_shrink_node(pgdat, sc);
		return;
	}

	/*  全局 传统lru
		cgroup 传统lru
		cgroup mglru
		这三种情况走这个路径  */
	target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);

again:
	memset(&sc->nr, 0, sizeof(sc->nr));

	nr_reclaimed = sc->nr_reclaimed;
	nr_scanned = sc->nr_scanned;
	/* 对于非mglru,  根据sc计算此node上面需要or可以扫描等等数量,写入sc */
	prepare_scan_count(pgdat, sc);
	/* 这里进行实质的回收 */
	shrink_node_memcgs(pgdat, sc);

	flush_reclaim_state(sc);

	nr_node_reclaimed = sc->nr_reclaimed - nr_reclaimed;

	/* Record the subtree's reclaim efficiency */
	if (!sc->proactive)
		vmpressure(sc->gfp_mask, sc->target_mem_cgroup, true,
			   sc->nr_scanned - nr_scanned, nr_node_reclaimed);

	if (nr_node_reclaimed)
		reclaimable = true;

	if (current_is_kswapd()) {
		/*
		 * If reclaim is isolating dirty pages under writeback,
		 * it implies that the long-lived page allocation rate
		 * is exceeding the page laundering rate. Either the
		 * global limits are not being effective at throttling
		 * processes due to the page distribution throughout
		 * zones or there is heavy usage of a slow backing
		 * device. The only option is to throttle from reclaim
		 * context which is not ideal as there is no guarantee
		 * the dirtying process is throttled in the same way
		 * balance_dirty_pages() manages.
		 * 如果回收过程中隔离了正在回写的脏页，这意味着长期的页面分配速率超过了页面清洗速率。
		 可能是由于页面在各个区域的分布导致全局限制未能有效地限制进程，或者是因为大量使用了速度较慢的后备设备。
		 唯一的选择是在回收上下文中进行限制，这并不理想，因为无法保证对脏页进程的限制方式与 
		 `balance_dirty_pages()` 管理的方式相同。
		 * Once a node is flagged PGDAT_WRITEBACK, kswapd will
		 * count the number of pages under pages flagged for
		 * immediate reclaim and stall if any are encountered
		 * in the nr_immediate check below
		 * 一旦节点被标记为 PGDAT_WRITEBACK，kswapd 将统计标记为需要立即回收的页面数量，并在下面的
 `nr_immediate` 检查中遇到任何此类页面时暂停。
		 */
		if (sc->nr.writeback && sc->nr.writeback == sc->nr.taken)
			set_bit(PGDAT_WRITEBACK, &pgdat->flags);

		/* Allow kswapd to start writing pages during reclaim.
		允许kswap在回收过程中回写*/
		if (sc->nr.unqueued_dirty == sc->nr.file_taken)
			set_bit(PGDAT_DIRTY, &pgdat->flags);

		/*
		 * If kswapd scans pages marked for immediate
		 * reclaim and under writeback (nr_immediate), it
		 * implies that pages are cycling through the LRU
		 * faster than they are written so forcibly stall
		 * until some pages complete writeback.
		 如果kswap扫描了被标记为直接回收并且正在回写的页面
		 说明页面回写的比较慢
		 所以stall一会儿直到一些页面回写完成
		 */
		if (sc->nr.immediate)
			reclaim_throttle(pgdat, VMSCAN_THROTTLE_WRITEBACK);
	}

	/*
	 * Tag a node/memcg as congested if all the dirty pages were marked
	 * for writeback and immediate reclaim (counted in nr.congested).
	 *把memcg和node标记为congested, 如果全部的脏页正在回写
	 * Legacy memcg will stall in page writeback so avoid forcibly
	 * stalling in reclaim_throttle().

	 根据操作lru时, 设置的各种信息来设置.
	 */
	if (sc->nr.dirty && sc->nr.dirty == sc->nr.congested) {
		if (cgroup_reclaim(sc) && writeback_throttling_sane(sc))
			set_bit(LRUVEC_CGROUP_CONGESTED, &target_lruvec->flags);

		if (current_is_kswapd())
			set_bit(LRUVEC_NODE_CONGESTED, &target_lruvec->flags);
	}

	/*
	 * Stall direct reclaim for IO completions if the lruvec is
	 * node is congested. Allow kswapd to continue until it
	 * starts encountering unqueued dirty pages or cycling through
	 * the LRU too quickly.
	 尝试阻塞一下自己

	 */
	if (!current_is_kswapd() && current_may_throttle() &&
	    !sc->hibernation_mode &&
	    (test_bit(LRUVEC_CGROUP_CONGESTED, &target_lruvec->flags) ||
	     test_bit(LRUVEC_NODE_CONGESTED, &target_lruvec->flags)))

		reclaim_throttle(pgdat, VMSCAN_THROTTLE_CONGESTED);

	if (should_continue_reclaim(pgdat, nr_node_reclaimed, sc))
		goto again;

	/*
	 * Kswapd gives up on balancing particular nodes after too
	 * many failures to reclaim anything from them and goes to
	 * sleep. On reclaim progress, reset the failure counter. A
	 * successful direct reclaim run will revive a dormant kswapd.
	 */
	if (reclaimable)
		pgdat->kswapd_failures = 0;
}

/*
似乎就是检查zone等是否满足, 不检查sc的设置.
 * Returns true if compaction should go ahead for a costly-order request, or
 * the allocation would already succeed without compaction. Return false if we
 * should reclaim first.
 */
static inline bool compaction_ready(struct zone *zone, struct scan_control *sc)
{
	unsigned long watermark;

	/* Allocation can already succeed, nothing to do */
	if (zone_watermark_ok(zone, sc->order, min_wmark_pages(zone),
			      sc->reclaim_idx, 0))
		return true;

	/* Compaction cannot yet proceed. Do reclaim. */
	if (!compaction_suitable(zone, sc->order, sc->reclaim_idx))
		return false;

	/*
	 * Compaction is already possible, but it takes time to run and there
	 * are potentially other callers using the pages just freed. So proceed
	 * with reclaim to make a buffer of free pages available to give
	 * compaction a reasonable chance of completing and allocating the page.
	 * Note that we won't actually reclaim the whole buffer in one attempt
	 * as the target watermark in should_continue_reclaim() is lower. But if
	 * we are already above the high+gap watermark, don't reclaim at all.
	 */
	watermark = high_wmark_pages(zone) + compact_gap(sc->order);

	return zone_watermark_ok_safe(zone, 0, watermark, sc->reclaim_idx);
}
/*  */
static void consider_reclaim_throttle(pg_data_t *pgdat, struct scan_control *sc)
{
	/*
	 * If reclaim is making progress greater than 12% efficiency then
	 * wake all the NOPROGRESS throttled tasks.
	
	 */
	if (sc->nr_reclaimed > (sc->nr_scanned >> 3)) {/* 如果回收的成功率在1/8之上 */
		wait_queue_head_t *wqh;

		/* 取得因为VMSCAN_THROTTLE_NOPROGRESS而阻塞的reclaimer进行唤醒? */
		wqh = &pgdat->reclaim_wait[VMSCAN_THROTTLE_NOPROGRESS];
		if (waitqueue_active(wqh))
			wake_up(wqh);

		return;
	}
	/* 虽然回收成功率低 */
	/*
	 * Do not throttle kswapd or cgroup reclaim on NOPROGRESS as it will
	 * throttle on VMSCAN_THROTTLE_WRITEBACK if there are too many pages
	 * under writeback and marked for immediate reclaim at the tail of the
	 * LRU.

	 */
	if (current_is_kswapd() || cgroup_reclaim(sc)) /* 但是kswap和cgroup回收也不阻塞 */
		return;

	/* Throttle if making no progress at high prioities. */
	if (sc->priority == 1 && !sc->nr_reclaimed)
		reclaim_throttle(pgdat, VMSCAN_THROTTLE_NOPROGRESS);
}

/*
包装遍历回收node的过程.
===========================
这个函数级别可以指定回收数量吗?
 * This is the direct reclaim path, for page-allocating processes.  
 We only try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 */
static void shrink_zones(struct zonelist *zonelist, struct scan_control *sc)
{
	struct zoneref *z;
	struct zone *zone;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	gfp_t orig_mask;
	pg_data_t *last_pgdat = NULL;
	pg_data_t *first_pgdat = NULL;

	/*
	 * If the number of buffer_heads in the machine exceeds the maximum
	 * allowed level, force direct reclaim to scan the highmem zone as
	 * highmem pages could be pinning lowmem pages storing buffer_heads
	 */
	orig_mask = sc->gfp_mask;
	if (buffer_heads_over_limit) {/* 如果当前disk的buffer过多.  */
		sc->gfp_mask |= __GFP_HIGHMEM;
		sc->reclaim_idx = gfp_zone(sc->gfp_mask);
	}
	/* nodemask指定了允许的node .  */
	/* 遍历zone指定的node进行回滚 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					sc->reclaim_idx, sc->nodemask) {
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.

		 尝试全局回收下的soft reclaim回收
		 */
		if (!cgroup_reclaim(sc)) {/* 如果是全局回收 
		尝试对涉及的全部node进行soft回收*/
			if (!cpuset_zone_allowed(zone,
						 GFP_KERNEL | __GFP_HARDWALL))
				continue;

			/*
			 * If we already have plenty of memory free for
			 * compaction in this zone, don't free any more.
			 * Even though compaction is invoked for any
			 * non-zero order, only frequent costly order
			 * reclamation is disruptive enough to become a
			 * noticeable problem, like transparent huge
			 * page allocations.
			 */
			if (IS_ENABLED(CONFIG_COMPACTION) &&
			    sc->order > PAGE_ALLOC_COSTLY_ORDER &&
			    compaction_ready(zone, sc)) { /* sc设置了order会检查 */

				sc->compaction_ready = true;
				continue;
			}

			/*
			 * Shrink each node in the zonelist once. If the
			 * zonelist is ordered by zone (not the default) then a
			 * node may be shrunk multiple times but in that case
			 * the user prefers lower zones being preserved.
			 zones列表有可能是按序排列的. 因此可能会连续遍历到同一个node,
			 对每个node仅尝试一次.
			 */
			if (zone->zone_pgdat == last_pgdat)
				continue;

			/*
			 * This steals pages from memory cgroups over softlimit
			 * and returns the number of reclaimed pages and
			 * scanned pages. This works for global memory pressure
			 * and balancing, not for a memcg's limit.
			 */
			nr_soft_scanned = 0;
			nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(zone->zone_pgdat,
						sc->order, sc->gfp_mask,
						&nr_soft_scanned);

			sc->nr_reclaimed += nr_soft_reclaimed;
			/* 记录shrink_zones函数扫描了多少页面 */
			sc->nr_scanned += nr_soft_scanned;
			/* need some check for avoid more shrink_zone() */
		}

		/* 全局回收的soft reclaim完毕, 开始回收node */
		if (!first_pgdat)
			first_pgdat = zone->zone_pgdat;

		/* See comment about same check for global reclaim above */
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;

		shrink_node(zone->zone_pgdat, sc);
	}

	if (first_pgdat)/* 条件性的阻塞一下. ... */ /* 说明回收了node */ /* 说明回收了node */
		consider_reclaim_throttle(first_pgdat, sc);

	/*
	 * Restore to original mask to avoid the impact on the caller if we
	 * promoted it to __GFP_HIGHMEM.
	 刚才可能提升了gfp, 这里回滚
	 */
	sc->gfp_mask = orig_mask;
}
/* 统计refault */
/* oh, mglru可以不考虑 */
static void snapshot_refaults(struct mem_cgroup *target_memcg, pg_data_t *pgdat)
{
	struct lruvec *target_lruvec;
	unsigned long refaults;

	if (lru_gen_enabled())
		return;

	target_lruvec = mem_cgroup_lruvec(target_memcg, pgdat);

	refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_ANON);
	target_lruvec->refaults[WORKINGSET_ANON] = refaults;

	refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_FILE);
	target_lruvec->refaults[WORKINGSET_FILE] = refaults;
}

/*
回收页面的接口函数.
=============================
返回回收的数量.
回收prio次数.
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick the writeback threads and take explicit
 * naps in the hope that some of these pages can be written.  But if the
 * allocating task holds filesystem locks which prevent writeout this might not
 * work, and the allocation attempt will fail.
 *
 * returns:	0, if no pages reclaimed
 * 		else, the number of pages reclaimed
 2024年09月25日10:45:18
 try_to_free_pages和try_to_free_memcg_pages来到这里。
 根据sc对这些zone的node进行回收sc->nr_to_reclaim页面. 这里体现priority次数.
 */
static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
					  struct scan_control *sc)
{
	int initial_priority = sc->priority;

	pg_data_t *last_pgdat;
	struct zoneref *z;
	struct zone *zone;
retry:
	delayacct_freepages_start();

	if (!cgroup_reclaim(sc))
		__count_zid_vm_events(ALLOCSTALL, sc->reclaim_idx, 1);

	do {
		if (!sc->proactive)
			vmpressure_prio(sc->gfp_mask, sc->target_mem_cgroup,
					sc->priority);

		sc->nr_scanned = 0; /* 这里为什么归零?这里可以拿来限制每次回收过程扫描的
		数量吗? */
		shrink_zones(zonelist, sc);

		if (sc->nr_reclaimed >= sc->nr_to_reclaim)
			break;

		if (sc->compaction_ready) /* 什么需求触发的回收, 会打开这个flag呢.
		sc设置order的话(快速回收,慢速回收，kswap回收), 可能会走这条路径.
		free_memcg, 自己实现的逻辑, 没设置order, 就不会走这里 */
			break;

		/*
		 * If we're getting trouble reclaiming, start doing
		 * writepage even in laptop mode.
		 回收有点压力, 开启写回.
		 */
		if (sc->priority < DEF_PRIORITY - 2)
			sc->may_writepage = 1;

	} while (--sc->priority >= 0);



	/* 具体的回收过程结束 */
	/* 可能是回收目标完成了, 或者是可以规整了. */

	last_pgdat = NULL;
	for_each_zone_zonelist_nodemask(zone, z, zonelist, sc->reclaim_idx,
					sc->nodemask) {
		if (zone->zone_pgdat == last_pgdat)
			continue;

		last_pgdat = zone->zone_pgdat;
		/* 遍历zones的node, 每个node只处理一次 */

		/* 1,计算refaults */
		snapshot_refaults(sc->target_mem_cgroup, zone->zone_pgdat);

		/* 2. 清除相关标记 */
		/* cgroup回收情况下, 清除目标cgroup的LRUVEC_CGROUP_CONGESTED */
		if (cgroup_reclaim(sc)) {
			struct lruvec *lruvec;

			lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup,
						   zone->zone_pgdat);
			
			clear_bit(LRUVEC_CGROUP_CONGESTED, &lruvec->flags);
		}
	}

	delayacct_freepages_end();
	/* 回收结束, 准备返回 */

	if (sc->nr_reclaimed)  /* 回收到内存了, 返回回收数量 */
		return sc->nr_reclaimed;

	/* 一丝也没回收到 */

	/* Aborted reclaim to try compaction? don't OOM, then */
	if (sc->compaction_ready) /* 没回收到, 但是可以规整了 */
		return 1;

	/* 走到这里说明, 没回收到, 也无法规整. 调整sc设置去重试 */


	/*
	 * We make inactive:active ratio decisions based on the node's
	 * composition of memory, but a restrictive reclaim_idx or a
	 * memory.low cgroup setting can exempt large amounts of
	 * memory from reclaim. Neither of which are very common, so
	 * instead of doing costly eligibility calculations of the
	 * entire cgroup subtree up front, we assume the estimates are
	 * good, and retry with forcible deactivation if that fails.
	 根据节点的内存组成来决定非活动页面与活动页面的比例，但sc的reclaim_idx 
	 或 memory.low设置可能会使大量内存免于回收。
	 不过这两种情况并不常见，所以不在一开始就进行整个控制组的计算，而是假设这些
	 估算是合理的，如果失败则尝试强制去激活
	 */
	if (sc->skipped_deactivate) {
		sc->priority = initial_priority;
		sc->force_deactivate = 1;
		sc->skipped_deactivate = 0;
		goto retry;
	}

	/* Untapped cgroup reserves?  Don't OOM, retry. */
	if (sc->memcg_low_skipped) {
		sc->priority = initial_priority;
		sc->force_deactivate = 0;
		sc->memcg_low_reclaim = 1;
		sc->memcg_low_skipped = 0;
		goto retry;
	}

	return 0;
}
/* 
检查水位是否ok
不ok的话,会唤醒kswap
 */
static bool allow_direct_reclaim(pg_data_t *pgdat)
{
	struct zone *zone;
	/* 统计reclaimable 的 zone的min之和 */
	unsigned long pfmemalloc_reserve = 0;
	/* 统计reclaimable的zone之间的free之和 */
	unsigned long free_pages = 0;
	int i;
	bool wmark_ok;

	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
		return true; /* kswapd已经很难回收到页面了 */

	for (i = 0; i <= ZONE_NORMAL; i++) {
		zone = &pgdat->node_zones[i];
		if (!managed_zone(zone))
			continue;

		if (!zone_reclaimable_pages(zone))
			continue;

		pfmemalloc_reserve += min_wmark_pages(zone);
		free_pages += zone_page_state_snapshot(zone, NR_FREE_PAGES);
	}

	/* If there are no reserves (unexpected config) then do not throttle */
	if (!pfmemalloc_reserve)
		return true;

	/* 水位是否还ok */
	wmark_ok = free_pages > pfmemalloc_reserve / 2;

	/* kswapd must be awake if processes are being throttled */
	if (!wmark_ok && waitqueue_active(&pgdat->kswapd_wait)) {
		if (READ_ONCE(pgdat->kswapd_highest_zoneidx) > ZONE_NORMAL)
			WRITE_ONCE(pgdat->kswapd_highest_zoneidx, ZONE_NORMAL);
		/* 触发kswapd回收 */
		wake_up_interruptible(&pgdat->kswapd_wait);
	}

	return wmark_ok;
}

/* 
如果后备存储比较慢, 就限流一下.
一直阻塞, 一直唤醒kswap, 直到allow_direct_reclaim为真(意味着水位ok).
 * Throttle direct reclaimers if backing storage is backed by the network
 * and the PFMEMALLOC reserve for the preferred node is getting dangerously
 * depleted. 
 kswapd会继续工作,如果达到了低水位.
 kswapd will continue to make progress and wake the processes
 * when the low watermark is reached.
 * 返回真表示限流过程中有kill信号啥啥的
 返回false说明情况还好, 不用阻塞
 * Returns true if a fatal signal was delivered during throttling. If this
 * happens, the page allocator should not consider triggering the OOM killer.
 
 */
static bool throttle_direct_reclaim(gfp_t gfp_mask, struct zonelist *zonelist,
					nodemask_t *nodemask)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *pgdat = NULL;

	/*
	 * Kernel threads should not be throttled as they may be indirectly
	 * responsible for cleaning pages necessary for reclaim to make forward
	 * progress. 
	 内核线程不应该被throttled, 因为他们有可能就是疏通其他throttle的
	 kjournald for example may enter direct reclaim while
	 * committing a transaction where throttling it could forcing other
	 * processes to block on log_wait_commit().
	 内核线程不应该被限流. 
	 比如kjournald的例子
	 */
	if (current->flags & PF_KTHREAD)
		goto out;

	/*
	 * If a fatal signal is pending, this process should not throttle.
	 * It should return quickly so it can exit and free its memory
	 如果有kill之类的信号, 不应该限流.反而应该快点退出,好直接释放内存.
	 */
	if (fatal_signal_pending(current))
		goto out;
	/*
	 * Check if the pfmemalloc reserves are ok by finding the first node
	 * with a usable ZONE_NORMAL or lower zone. The expectation is that
	 * GFP_KERNEL will be required for allocating network buffers when
	 * swapping over the network so ZONE_HIGHMEM is unusable.
	 *
	 * Throttling is based on the first usable node and throttled processes
	 * wait on a queue until kswapd makes progress and wakes them. There
	 * is an affinity then between processes waking up and where reclaim
	 * progress has been made assuming the process wakes on the same node.
	 * More importantly, processes running on remote nodes will not compete
	 * for remote pfmemalloc reserves and processes on different nodes
	 * should make reasonable progress.
	 测试normal及以下的第一个zone的node是否允许直接回收(水位是否ok), 不ok的话会唤醒node上面
	 的kswap 
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_zone(gfp_mask), nodemask) {
		if (zone_idx(zone) > ZONE_NORMAL)
			continue;

		/* Throttle based on the first usable node */
		pgdat = zone->zone_pgdat;
		//发起node上面的kswap
		if (allow_direct_reclaim(pgdat))
			goto out;

		break;
	}
	/* 
	到这里说明,刚才测试的所有zone的node的水位都不ok, 并且已经唤醒了这些node的kswap
	 */
	/* If no zone was usable by the allocation flags then do not throttle */
	if (!pgdat)
		goto out;

	/* Account for the throttling
	记录一次直接回收阻塞的事件(无法回收, 期望唤醒kswap后可以成功)
	 */
	count_vm_event(PGSCAN_DIRECT_THROTTLE);

	/*
	 * If the caller cannot enter the filesystem, it's possible that it
	 * is due to the caller holding an FS lock or performing a journal
	 * transaction in the case of a filesystem like ext[3|4]. In this case,
	 * it is not safe to block on pfmemalloc_wait as kswapd could be
	 * blocked waiting on the same lock. Instead, throttle for up to a
	 * second before continuing.
	 */

	 //在pfmemalloc_wait的队列上面, 一直等待到allow_direct_reclaim发生, 也一直唤醒kswap
	if (!(gfp_mask & __GFP_FS))
		wait_event_interruptible_timeout(pgdat->pfmemalloc_wait,
			allow_direct_reclaim(pgdat), HZ);
	else
		/* Throttle until kswapd wakes the process */
		wait_event_killable(zone->zone_pgdat->pfmemalloc_wait,
			allow_direct_reclaim(pgdat));

	if (fatal_signal_pending(current))
		return true;

out:
	return false;
}
/* 
慢速回收等等
回收SWAP_CLUSTER_MAX,指定了order ...  */
unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
				gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned long nr_reclaimed;
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.gfp_mask = current_gfp_context(gfp_mask),
		.reclaim_idx = gfp_zone(gfp_mask),
		.order = order,
		.nodemask = nodemask,
		.priority = DEF_PRIORITY, 					//慢速回收12遍
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};
/* 
快速回收如下:	
与快速回收的不同
struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.priority = NODE_RECLAIM_PRIORITY, 						//尝试4遍, 快速回收的一个特征
		.may_writepage = !!(node_reclaim_mode & RECLAIM_WRITE),
		.may_unmap = !!(node_reclaim_mode & RECLAIM_UNMAP),
	}; */
	/*
	 * scan_control uses s8 fields for order, priority, and reclaim_idx.
	 * Confirm they are large enough for max values.
	 */
	BUILD_BUG_ON(MAX_ORDER >= S8_MAX);
	BUILD_BUG_ON(DEF_PRIORITY > S8_MAX);
	BUILD_BUG_ON(MAX_NR_ZONES > S8_MAX);

	/*
	 * Do not enter reclaim if fatal signal was delivered while throttled.
	 * 1 is returned so that the page allocator does not OOM kill at this
	 * point.
	    
	 */
	if (throttle_direct_reclaim(sc.gfp_mask, zonelist, nodemask))
		return 1;   //需要一直阻塞到kswap工作完成了

	set_task_reclaim_state(current, &sc.reclaim_state);
	trace_mm_vmscan_direct_reclaim_begin(order, sc.gfp_mask);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_direct_reclaim_end(nr_reclaimed);
	set_task_reclaim_state(current, NULL);

	return nr_reclaimed;
}

#ifdef CONFIG_MEMCG

/* 
soft回收机制的函数. 只在soft limit reclaim回收
Only used by soft limit reclaim. Do not reuse for anything else. */
unsigned long mem_cgroup_shrink_node(struct mem_cgroup *memcg,
						gfp_t gfp_mask, bool noswap,
						pg_data_t *pgdat,
						unsigned long *nr_scanned)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.target_mem_cgroup = memcg,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.may_swap = !noswap,
	};

	WARN_ON_ONCE(!current->reclaim_state);

	sc.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
			(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK);

	trace_mm_vmscan_memcg_softlimit_reclaim_begin(sc.order,
						      sc.gfp_mask);

	/*
	 * NOTE: Although we can get the priority field, using it
	 * here is not a good idea, since it limits the pages we can scan.
	 * if we don't reclaim here, the shrink_node from balance_pgdat
	 * will pick up pages from other mem cgroup's as well. We hack
	 * the priority and make it zero.
	 */
	shrink_lruvec(lruvec, &sc);

	trace_mm_vmscan_memcg_softlimit_reclaim_end(sc.nr_reclaimed);

	/* shrink_lruvec也会增加新sc的nr_scanned */
	*nr_scanned = sc.nr_scanned;

	return sc.nr_reclaimed;
}

/*nr_pages只是回收目标, 返回回收的页面数量.  */
unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
					   unsigned long nr_pages,
					   gfp_t gfp_mask,
					   unsigned int reclaim_options)
{
	unsigned long nr_reclaimed;
	unsigned int noreclaim_flag;
	/* 1. 先制定sc */
	struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.gfp_mask = (current_gfp_context(gfp_mask) & GFP_RECLAIM_MASK) |
				(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK),
		.reclaim_idx = MAX_NR_ZONES - 1,
		.target_mem_cgroup = memcg,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = !!(reclaim_options & MEMCG_RECLAIM_MAY_SWAP),
		.proactive = !!(reclaim_options & MEMCG_RECLAIM_PROACTIVE),
	};
	/*
	 * Traverse the ZONELIST_FALLBACK zonelist of the current node to put
	 * equal pressure on all the nodes. This is based on the assumption that
	 * the reclaim does not bail out early.
	 获取node的gfp指定的zonelist.
	 */
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);

	set_task_reclaim_state(current, &sc.reclaim_state);
	trace_mm_vmscan_memcg_reclaim_begin(0, sc.gfp_mask);
	noreclaim_flag = memalloc_noreclaim_save();
	/* 2. 然后直接do_try_to_free */
	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	memalloc_noreclaim_restore(noreclaim_flag);
	trace_mm_vmscan_memcg_reclaim_end(nr_reclaimed);
	set_task_reclaim_state(current, NULL);

	return nr_reclaimed;
}
#endif
/* 2024年09月09日15:44:23
Aging主要用来产生年轻一代。

MGLRU在kswapd_age_node进行了拦截调用lru_gen_age_node：
 */
static void kswapd_age_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *memcg;
	struct lruvec *lruvec;

	if (lru_gen_enabled()) {/* 如果启用了 */
		lru_gen_age_node(pgdat, sc);
		return;
	}

	if (!can_age_anon_pages(pgdat, sc))
		return;

	lruvec = mem_cgroup_lruvec(NULL, pgdat);
	if (!inactive_is_low(lruvec, LRU_INACTIVE_ANON))
		return;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		lruvec = mem_cgroup_lruvec(memcg, pgdat);
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
}

/* 查看node上面是不是有zone进行了boost了 */
static bool pgdat_watermark_boosted(pg_data_t *pgdat, int highest_zoneidx)
{
	int i;
	struct zone *zone;

	/*
	 * Check for watermark boosts top-down as the higher zones
	 * are more likely to be boosted. Both watermarks and boosts
	 * should not be checked at the same time as reclaim would
	 * start prematurely when there is no boosting and a lower
	 * zone is balanced.
	 */
	for (i = highest_zoneidx; i >= 0; i--) {
		zone = pgdat->node_zones + i;
		if (!managed_zone(zone))
			continue;

		if (zone->watermark_boost)
			return true;
	}

	return false;
}

/*
如何判断是否balanced?
通过判断高水位是否ok.
 * Returns true if there is an eligible zone balanced for the request order
 * and highest_zoneidx
 */
static bool pgdat_balanced(pg_data_t *pgdat, int order, int highest_zoneidx)
{
	int i;
	unsigned long mark = -1;
	struct zone *zone;
	/* notesss  这里hook一下, 计算是否需要shrink_pagecache
	需要的话, 就返回false?
	安全性稳定性? */
    


	


	/*
	 * Check watermarks bottom-up as lower zones are more likely to
	 * meet watermarks.
	 */
	for (i = 0; i <= highest_zoneidx; i++) {
		zone = pgdat->node_zones + i;

		if (!managed_zone(zone))
			continue;

		if (sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING)
			mark = wmark_pages(zone, WMARK_PROMO);
		else
			mark = high_wmark_pages(zone);
		
		/* 这里测试高水位是否ok. */
		if (zone_watermark_ok_safe(zone, order, mark, highest_zoneidx))
			return true;
	}

	/*
	 * If a node has no managed zone within highest_zoneidx, it does not
	 * need balancing by definition. This can happen if a zone-restricted
	 * allocation tries to wake a remote kswapd.
	 */
	if (mark == -1)
		return true;

	return false;
}

/* 
清空node的阻塞状态
Clear pgdat state for congested, dirty or under writeback.
待分析,什么时候置位这些bit? */
static void clear_pgdat_congested(pg_data_t *pgdat)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(NULL, pgdat);

	clear_bit(LRUVEC_NODE_CONGESTED, &lruvec->flags);
	clear_bit(LRUVEC_CGROUP_CONGESTED, &lruvec->flags);
	clear_bit(PGDAT_DIRTY, &pgdat->flags);
	clear_bit(PGDAT_WRITEBACK, &pgdat->flags);
}

/*
kswapd_try_to_sleep准备kswap休息. 
检查是否满足休息条件.
 * Prepare kswapd for sleeping. This verifies that there are no processes
 * waiting in throttle_direct_reclaim() and that watermarks have been met.
 *  检查是不是没有进程阻塞等待ksawp工作了， 检查是不是水位ok了
 * Returns true if kswapd is ready to sleep
  返回真, 代表ksswap可以休息
 */
static bool prepare_kswapd_sleep(pg_data_t *pgdat, int order,
				int highest_zoneidx)
{
	/*
	 * The throttled processes are normally woken up in balance_pgdat() as
	 * soon as allow_direct_reclaim() is true. 
	 一般来说,balance_pgdat发现allow_direct_reclaim之后,就会唤醒pfmemalloc_wait
	 But there is a potential
	 * race between when kswapd checks the watermarks and a process gets
	 * throttled. There is also a potential race if processes get
	 * throttled, kswapd wakes, a large process exits thereby balancing the
	 * zones, which causes kswapd to exit balance_pgdat() before reaching
	 * the wake up checks. 
	 但是可能会有race的情况, 导致ksawp的balance_pgdat没有来得及唤醒
	 If kswapd is going to sleep, no process should
	 * be sleeping on pfmemalloc_wait, so wake them now if necessary.
	 如果kswap要去休息, 那么这里就不该有进程 ,所以唤醒.
	  If
	 * the wake up is premature, processes will wake kswapd and get
	 * throttled again. The difference from wake ups in balance_pgdat() is
	 * that here we are under prepare_to_wait().

	 如果还有进程阻塞在这里.
	 */
	if (waitqueue_active(&pgdat->pfmemalloc_wait))
		wake_up_all(&pgdat->pfmemalloc_wait);

	/* Hopeless node, leave it to direct reclaim.
	kswapd不起作用了, 可以休息... */
	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
		return true;
	
	/*  */
	if (pgdat_balanced(pgdat, order, highest_zoneidx)) {
		clear_pgdat_congested(pgdat);
		return true;
	}

	return false;
}

/*
kswapd的shrink_node。
返回是否扫描了要求回收的页面数量. 
-------------
一次回收多少呢?
 * kswapd shrinks a node of pages that are at or below the highest usable
 * zone that is currently unbalanced.
 * 
 * Returns true if kswapd scanned at least the requested number of pages to
 * reclaim or if the lack of progress was due to pages under writeback.
 * This is used to determine if the scanning priority needs to be raised.
 */
static bool kswapd_shrink_node(pg_data_t *pgdat,
			       struct scan_control *sc)
{
	struct zone *zone;
	int z;

	/* Reclaim a number of pages proportional to the number of zones
	计算此node上面sc允许的zone的全部高水位之上的页面数量.  */
	/* kswap怎么判断停止呢 */
	/* kswap调用shrink_node前可以设置nr_to_reclaim */

	sc->nr_to_reclaim = 0;
	for (z = 0; z <= sc->reclaim_idx; z++) {
		zone = pgdat->node_zones + z;
		if (!managed_zone(zone))
			continue;

		sc->nr_to_reclaim += max(high_wmark_pages(zone), SWAP_CLUSTER_MAX);
	}

	/*
	 * Historically care was taken to put equal pressure on all zones but
	 * now pressure is applied based on node LRU order.
	 */
	shrink_node(pgdat, sc);

	/*
	 * Fragmentation may mean that the system cannot be rebalanced for
	 * high-order allocations. If twice the allocation size has been
	 * reclaimed then recheck watermarks only at order-0 to prevent
	 * excessive reclaim. Assume that a process requested a high-order
	 * can direct reclaim/compact.
	 太碎片化可能不能满足大order分配.
	 */
	if (sc->order && sc->nr_reclaimed >= compact_gap(sc->order))
		sc->order = 0;
	
	/* 进入此函数之前归零了nr_scanned.
	是不是可以说就是拿来看shrink_node扫描了多少页面呢??? */
	return sc->nr_scanned >= sc->nr_to_reclaim;
}

/* Page allocator PCP high watermark is lowered if reclaim is active.
设置的是zone的flag */
static inline void
update_reclaim_active(pg_data_t *pgdat, int highest_zoneidx, bool active)
{
	int i;
	struct zone *zone;

	for (i = 0; i <= highest_zoneidx; i++) {
		zone = pgdat->node_zones + i;

		if (!managed_zone(zone))
			continue;

		if (active)
			set_bit(ZONE_RECLAIM_ACTIVE, &zone->flags);
		else
			clear_bit(ZONE_RECLAIM_ACTIVE, &zone->flags);
	}
}

/* kswap开始回收前, 会调用这个来标记要回收的zones */
static inline void
set_reclaim_active(pg_data_t *pgdat, int highest_zoneidx)
{
	update_reclaim_active(pgdat, highest_zoneidx, true);
}

/* kswap结束后, 会取消自己标记的这些zones */
static inline void
clear_reclaim_active(pg_data_t *pgdat, int highest_zoneidx)
{
	update_reclaim_active(pgdat, highest_zoneidx, false);
}

/*
kswapd调用此函数来回收node. 
 返回回收完成后可以满足的order
 kswap的回收

 * For kswapd, balance_pgdat() will reclaim pages across a node from zones
 * that are eligible for use by the caller until at least one zone is
 * balanced.
 * 会回收此node一直到一个zone可以满足分配需求. 
 * Returns the order kswapd finished reclaiming at.
 * 返回可以满足的回收需求的order. 
 * kswapd scans the zones in the highmem->normal->dma direction.  It skips
 * zones which have free_pages > high_wmark_pages(zone), but once a zone is
 * found to have free_pages <= high_wmark_pages(zone), any page in that zone
 * or lower is eligible for reclaim until at least one usable zone is
 * balanced.
    
 */
static int balance_pgdat(pg_data_t *pgdat, int order, int highest_zoneidx)
{
	int i;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	unsigned long pflags;
	unsigned long nr_boost_reclaim;
	unsigned long zone_boosts[MAX_NR_ZONES] = { 0, };
	/* 回收前各个zone的boost之和 */
	bool boosted;
	struct zone *zone;
	/* 这里创建sc */
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.order = order,
		.may_unmap = 1,
	};

	set_task_reclaim_state(current, &sc.reclaim_state);
	psi_memstall_enter(&pflags);
	__fs_reclaim_acquire(_THIS_IP_);

	count_vm_event(PAGEOUTRUN);

	/*
	 * Account for the reclaim boost. Note that the zone boost is left in
	 * place so that parallel allocations that are near the watermark will
	 * stall or direct reclaim until kswapd is finished.

	 */
	nr_boost_reclaim = 0;
	for (i = 0; i <= highest_zoneidx; i++) {
		zone = pgdat->node_zones + i;
		if (!managed_zone(zone))
			continue;

		nr_boost_reclaim += zone->watermark_boost;
		zone_boosts[i] = zone->watermark_boost;
	}
	boosted = nr_boost_reclaim;

restart:
/* 标记这些要回收的zone, 表示他们正在被kswap回收 */
	set_reclaim_active(pgdat, highest_zoneidx);
	sc.priority = DEF_PRIORITY;

	/* 回收priority次数 */
	/* 开始进行回收 */
	do {
		/* 保存之前回收的数量 */
		unsigned long nr_reclaimed = sc.nr_reclaimed;
		/* 是否加急 */
		bool raise_priority = true;
		bool balanced;
		bool ret;

		sc.reclaim_idx = highest_zoneidx;

		/*
		 * If the number of buffer_heads exceeds the maximum allowed
		 * then consider reclaiming from all zones. This has a dual
		 * purpose -- on 64-bit systems it is expected that
		 * buffer_heads are stripped during active rotation. On 32-bit
		 * systems, highmem pages can pin lowmem memory and shrinking
		 * buffers can relieve lowmem pressure. Reclaim may still not
		 * go ahead if all eligible zones for the original allocation
		 * request are balanced to avoid excessive reclaim from kswapd.
		 */
		if (buffer_heads_over_limit) {/* 扩大sc的zone范围 */
			for (i = MAX_NR_ZONES - 1; i >= 0; i--) {
				zone = pgdat->node_zones + i;
				if (!managed_zone(zone))
					continue;

				sc.reclaim_idx = i;
				break;
			}
		}

		/*
		 * If the pgdat is imbalanced then ignore boosting and preserve
		 * the watermarks for a later time and restart. Note that the
		 * zone watermarks will be still reset at the end of balancing
		 * on the grounds that the normal reclaim should be enough to
		 * re-evaluate if boosting is required when kswapd next wakes.
		 如果还没平衡, 那就没必要boost.
		 如果平衡了,还需要回收的话,再boost来增大回收压力
		 */
		balanced = pgdat_balanced(pgdat, sc.order, highest_zoneidx);


		if (!balanced && nr_boost_reclaim) {/* 
		如果第一次没有回收成功, 就把nr_boost_reclaim置零重试.
		 */
			nr_boost_reclaim = 0;
			goto restart; //不是从这里重启
		}

		/* 到这里说明
		直接就是balanced
		第一次运行不是 */
		/* case1: 不平衡, 不boost
		case2: 平衡, boost或者不boost */
		/*
		 * If boosting is not active then only reclaim if there are no
		 * eligible zones. Note that sc.reclaim_idx is not used as
		 * buffer_heads_over_limit may have adjusted it.
		 */
		if (!nr_boost_reclaim && balanced)/* 已经平衡了,也不打算boost,
		算是完成工作了, */
			goto out;

		/* 没有balanced, 没有boost */

		/*  case1: 不平衡, 不boost
			case2: 平衡, boost */


		/* Limit the priority of boosting to avoid reclaim writeback.
		 */
		if (nr_boost_reclaim && sc.priority == DEF_PRIORITY - 2)/* 说明还没有balanced. */
			raise_priority = false;

		/*
		 * Do not writeback or swap pages for boosted reclaim. The
		 * intent is to relieve pressure not issue sub-optimal IO
		 * from reclaim context. If no pages are reclaimed, the
		 * reclaim will be aborted.
		 如果是boost的话, 不回写不交换.
		 */
		sc.may_writepage = !laptop_mode && !nr_boost_reclaim;
		sc.may_swap = !nr_boost_reclaim; //可惜可以swap ... todddo, 复用的话,尝试可以不可以关闭,
		// 或者通过设置boost来关闭 ?

		/*
		 * Do some background aging, to give pages a chance to be
		 * referenced before reclaiming. All pages are rotated
		 * regardless of classzone as this is about consistent aging.
		 老化一下. 
		 做一些age
		 */
		kswapd_age_node(pgdat, &sc);

		/*
		 * If we're getting trouble reclaiming, start doing writepage
		 * even in laptop mode.
		 次数不多了, 考虑回写. 
		 压力大了, 开启回写
		 */
		if (sc.priority < DEF_PRIORITY - 2)
			sc.may_writepage = 1;

		/* Call soft limit reclaim before calling shrink_node.
		还是先尝试一下soft reclaim */
		sc.nr_scanned = 0; /* shrink_node之前归零.... */
		nr_soft_scanned = 0;
		/* mglru开启下这里不起作用 */
		nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(pgdat, sc.order,
						sc.gfp_mask, &nr_soft_scanned);
		sc.nr_reclaimed += nr_soft_reclaimed;

		/*
		 * There should be no need to raise the scanning priority if
		 * enough pages are already being scanned that that high
		 * watermark would be met at 100% efficiency.
		 好像一次balance_pgdat只调用一次shrink差不多.
		 */
		if (kswapd_shrink_node(pgdat, &sc))
			raise_priority = false;/* 能回收到页面, 就不刻意加急了 */

		/*
		 * If the low watermark is met there is no need for processes
		 * to be throttled on pfmemalloc_wait as they should not be
		 * able to safely make forward progress. Wake them
		 如果满足了low水位, 可以唤醒因为水位太低阻塞的进程了.
		 */
		if (waitqueue_active(&pgdat->pfmemalloc_wait) &&
				allow_direct_reclaim(pgdat)
			)
			wake_up_all(&pgdat->pfmemalloc_wait);

		/* Check if kswapd should be suspending */
		__fs_reclaim_release(_THIS_IP_);
		ret = try_to_freeze();
		__fs_reclaim_acquire(_THIS_IP_);
		if (ret || kthread_should_stop())
			break;

		/*
		 * Raise priority if scanning rate is too low or there was no
		 * progress in reclaiming pages
		 */
		 /* 统计这次回收的数量 */
		nr_reclaimed = sc.nr_reclaimed - nr_reclaimed;
		/* 回收的boost的数量 */
		nr_boost_reclaim -= min(nr_boost_reclaim, nr_reclaimed);

		/*
		 * If reclaim made no progress for a boost, stop reclaim as
		 * IO cannot be queued and it could be an infinite loop in
		 * extreme circumstances.
		 在boost回收下,没有回收到页面,放弃.
		 */
		if (nr_boost_reclaim && !nr_reclaimed)
			break;
		
		/* 没回收到, 减少一次回收次数.
		如果可以加急,即使回收到了,也减少一次 */
		if (raise_priority || !nr_reclaimed)
			sc.priority--;

	} while (sc.priority >= 1);

	if (!sc.nr_reclaimed) /* 尝试多次也没有回收到内存 */
		pgdat->kswapd_failures++;

out:
//清除自己加的表示kswap正在回收的标记
	clear_reclaim_active(pgdat, highest_zoneidx);

	/* If reclaim was boosted, account for the reclaim done in this pass
	清理一下boost */
	if (boosted) {
		unsigned long flags;

		for (i = 0; i <= highest_zoneidx; i++) {
			if (!zone_boosts[i])
				continue;

			/* Increments are under the zone lock */
			zone = pgdat->node_zones + i;
			spin_lock_irqsave(&zone->lock, flags);
			zone->watermark_boost -= min(zone->watermark_boost, zone_boosts[i]);
			spin_unlock_irqrestore(&zone->lock, flags);
		}

		/*
		 * As there is now likely space, wakeup kcompact to defragment
		 * pageblocks.
		 */
		wakeup_kcompactd(pgdat, pageblock_order, highest_zoneidx);
	}

	snapshot_refaults(NULL, pgdat);
	__fs_reclaim_release(_THIS_IP_);
	psi_memstall_leave(&pflags);
	set_task_reclaim_state(current, NULL);

	/*
	 * Return the order kswapd stopped reclaiming at as
	 * prepare_kswapd_sleep() takes it into account. If another caller
	 * entered the allocator slow path while kswapd was awake, order will
	 * remain at the higher level.
	 */
	return sc.order;
}

/*
 * The pgdat->kswapd_highest_zoneidx is used to pass the highest zone index to
 * be reclaimed by kswapd from the waker. If the value is MAX_NR_ZONES which is
 * not a valid index then either kswapd runs for first time or kswapd couldn't
 * sleep after previous reclaim attempt (node is still unbalanced). In that
 * case return the zone index of the previous kswapd reclaim cycle.
 */
static enum zone_type kswapd_highest_zoneidx(pg_data_t *pgdat,
					   enum zone_type prev_highest_zoneidx)
{
	enum zone_type curr_idx = READ_ONCE(pgdat->kswapd_highest_zoneidx);

	return curr_idx == MAX_NR_ZONES ? prev_highest_zoneidx : curr_idx;
}
/* kswapd尝试睡眠
只要没有进程因为自己阻塞, 内存水位ok, 没有被很快叫醒, 就sleep. 
 */
static void kswapd_try_to_sleep(pg_data_t *pgdat, int alloc_order, int reclaim_order,
				unsigned int highest_zoneidx)
{
	long remaining = 0;
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;

	prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);

	/*
	 * Try to sleep for a short interval. Note that kcompactd will only be
	 * woken if it is possible to sleep for a short interval. This is
	 * deliberate on the assumption that if reclaim cannot keep an
	 * eligible zone balanced that it's also unlikely that compaction will
	 * succeed.
	   尝试睡眠一小会儿, 
	   意思是说如果kswap回收效果不好, kcompact也不会好?
	 */
	if (prepare_kswapd_sleep(pgdat, reclaim_order, highest_zoneidx)) {/* 如果kswapd
	可以休息. */
	/* 不过也不能长睡, 这里先短睡, 看看会不会被叫醒 */
		/*
		 * Compaction records what page blocks it recently failed to
		 * isolate pages from and skips them in the future scanning.
		 * When kswapd is going to sleep, it is reasonable to assume
		 * that pages and compaction may succeed so reset the cache.
		   规整会记录无法规整的页面
		   当kswap准备去休息时, 代表内存情况好一些了, 所以这里可以尝试一下.
		 */
		reset_isolation_suitable(pgdat);

		/*
		 * We have freed the memory, now we should compact it to make
		 * allocation of the requested order possible.
		 */
		 /* 规整一下 ... */
		wakeup_kcompactd(pgdat, alloc_order, highest_zoneidx);

		remaining = schedule_timeout(HZ/10);

		/*
		 * If woken prematurely then reset kswapd_highest_zoneidx and
		 * order. The values will either be from a wakeup request or
		 * the previous request that slept prematurely.
		 */
		if (remaining) {//短睡被叫醒了
			WRITE_ONCE(pgdat->kswapd_highest_zoneidx,
					kswapd_highest_zoneidx(pgdat,
							highest_zoneidx));

			if (READ_ONCE(pgdat->kswapd_order) < reclaim_order)
				WRITE_ONCE(pgdat->kswapd_order, reclaim_order);
		}

		finish_wait(&pgdat->kswapd_wait, &wait);
		prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
	}

	/*
	 * After a short sleep, check if it was a premature sleep. If not, then
	 * go fully to sleep until explicitly woken up.
	 */
	if (!remaining &&
	    prepare_kswapd_sleep(pgdat, reclaim_order, highest_zoneidx)) {
			//如果刚刚没有被叫醒, 内存情况不错, 这里去sleep
		trace_mm_vmscan_kswapd_sleep(pgdat->node_id);

		/*
		 * vmstat counters are not perfectly accurate and the estimated
		 * value for counters such as NR_FREE_PAGES can deviate from the
		 * true value by nr_online_cpus * threshold. To avoid the zone
		 * watermarks being breached while under pressure, we reduce the
		 * per-cpu vmstat threshold while kswapd is awake and restore
		 * them before going back to sleep.
		 */
		set_pgdat_percpu_threshold(pgdat, calculate_normal_threshold);

		if (!kthread_should_stop())
			schedule();

		set_pgdat_percpu_threshold(pgdat, calculate_pressure_threshold);
	} else { //短睡也被叫醒了
		if (remaining)
			count_vm_event(KSWAPD_LOW_WMARK_HIT_QUICKLY);
		else
			count_vm_event(KSWAPD_HIGH_WMARK_HIT_QUICKLY);
	}
	finish_wait(&pgdat->kswapd_wait, &wait);
}

/*
kswapd的工作函数. 

kswapd的运行条件:
不满足sleep条件就回收

 * The background pageout daemon, started as a kernel thread
 * from the init process.
 * kswap后台写回进程
 * This basically trickles out pages so that we have _some_
 * free memory available even if there is no other activity
 * that frees anything up. This is needed for things like routing
 * etc, where we otherwise might have all activity going on in
 * asynchronous contexts that cannot page things out.
 *  
 * If there are applications that are active memory-allocators
 * (most normal use), this basically shouldn't matter.
  
 */
static int kswapd(void *p)
{
	unsigned int alloc_order, reclaim_order;
	unsigned int highest_zoneidx = MAX_NR_ZONES - 1;
	/* 参数为一个node */
	pg_data_t *pgdat = (pg_data_t *)p;
	struct task_struct *tsk = current;

	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);

	/*
	 * Tell the memory management that we're a "memory allocator",
	 * and that if we need more memory we should get access to it
	 * regardless (see "__alloc_pages()"). "kswapd" should
	 * never get caught in the normal page freeing logic.
	 * 标记自己为kswap进程, 这样的话内存分配权限比较搞.
	 * (Kswapd normally doesn't need memory anyway, but sometimes
	 * you need a small amount of memory in order to be able to
	 * page out something else, and this flag essentially protects
	 * us from recursively trying to free more memory as we're
	 * trying to free the first piece of memory in the first place).
	   这样是为了防止kswap为了回收内存而分配一些内存的时间继续回收内存?
	 */
	tsk->flags |= PF_MEMALLOC | PF_KSWAPD;
	set_freezable();

	/* 设置默认的回收需求 */
	WRITE_ONCE(pgdat->kswapd_order, 0);
	WRITE_ONCE(pgdat->kswapd_highest_zoneidx, MAX_NR_ZONES);

	atomic_set(&pgdat->nr_writeback_throttled, 0);
	for ( ; ; ) {
		bool ret;

		alloc_order = reclaim_order = READ_ONCE(pgdat->kswapd_order);
		highest_zoneidx = kswapd_highest_zoneidx(pgdat,
							highest_zoneidx);

kswapd_try_sleep:
/* 尝试睡眠 */
		kswapd_try_to_sleep(pgdat, alloc_order, reclaim_order,
					highest_zoneidx);
//醒来工作
		/* Read the new order and highest_zoneidx */
		alloc_order = READ_ONCE(pgdat->kswapd_order);
		highest_zoneidx = kswapd_highest_zoneidx(pgdat,
							highest_zoneidx);
		WRITE_ONCE(pgdat->kswapd_order, 0);
		WRITE_ONCE(pgdat->kswapd_highest_zoneidx, MAX_NR_ZONES);

		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		/*
		 * We can speed up thawing tasks if we don't call balance_pgdat
		 * after returning from the refrigerator
		 */
		if (ret)
			continue;

		/*
		 * Reclaim begins at the requested order but if a high-order
		 * reclaim fails then kswapd falls back to reclaiming for
		 * order-0. If that happens, kswapd will consider sleeping
		 * for the order it finished reclaiming at (reclaim_order)
		 * but kcompactd is woken to compact for the original
		 * request (alloc_order).
		 */
		trace_mm_vmscan_kswapd_wake(pgdat->node_id, highest_zoneidx,
						alloc_order);
						/* 进行工作 */
		/* 这里开始回收
		一次回收多少?
		 */
		reclaim_order = balance_pgdat(pgdat, alloc_order,
						highest_zoneidx);
		if (reclaim_order < alloc_order)
			goto kswapd_try_sleep;
	}

	tsk->flags &= ~(PF_MEMALLOC | PF_KSWAPD);

	return 0;
}

/*
唤醒kswapd.
设置node的kswapd参数, 然后唤醒进程.
 * A zone is low on free memory or too fragmented for high-order memory.  If
 * kswapd should reclaim (direct reclaim is deferred), wake it up for the zone's
 * pgdat.  It will wake up kcompactd after reclaiming memory.  If kswapd reclaim
 * has failed or is not needed, still wake up kcompactd if only compaction is
 * needed.
 一个区域的空闲内存不足或对于高阶内存来说过于碎片化。如果 kswapd 应该进行回收（直接回收被延迟），
 则唤醒该区域的 pgdat 的 kswapd。
 它将在回收内存后唤醒 kcompactd。如果 kswapd 的回收失败或
 不需要回收，但仅需要内存压缩，仍然会唤醒 kcompactd。
 */
void wakeup_kswapd(struct zone *zone, gfp_t gfp_flags, int order,
		   enum zone_type highest_zoneidx)
{
	pg_data_t *pgdat;
	enum zone_type curr_idx;

	if (!managed_zone(zone))
		return;

	if (!cpuset_zone_allowed(zone, gfp_flags))
		return;

	pgdat = zone->zone_pgdat;
	curr_idx = READ_ONCE(pgdat->kswapd_highest_zoneidx);

	if (curr_idx == MAX_NR_ZONES || curr_idx < highest_zoneidx)
		WRITE_ONCE(pgdat->kswapd_highest_zoneidx, highest_zoneidx);

	if (READ_ONCE(pgdat->kswapd_order) < order)
		WRITE_ONCE(pgdat->kswapd_order, order);

	if (!waitqueue_active(&pgdat->kswapd_wait))/* 如果队列上没有kswapd进程
	在阻塞, 那就没有可唤醒的 */
		return;

	/* Hopeless node, leave it to direct reclaim if possible
	如果这个node上面, kswap效果不明显了 */
	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES ||
	    (pgdat_balanced(pgdat, order, highest_zoneidx) &&
	     !pgdat_watermark_boosted(pgdat, highest_zoneidx))) {/* kswapd不起作用了,
		 唤醒规整进程得了...返回 */
		/*
		 * There may be plenty of free memory available, but it's too
		 * fragmented for high-order allocations.  Wake up kcompactd
		 * and rely on compaction_suitable() to determine if it's
		 * needed.  If it fails, it will defer subsequent attempts to
		 * ratelimit its work.
		 */
		if (!(gfp_flags & __GFP_DIRECT_RECLAIM))
			wakeup_kcompactd(pgdat, order, highest_zoneidx);
		return;
	}

	trace_mm_vmscan_wakeup_kswapd(pgdat->node_id, highest_zoneidx, order,
				      gfp_flags);
					  /* 这里唤醒队列上面的kswap */
	wake_up_interruptible(&pgdat->kswapd_wait);
}

#ifdef CONFIG_HIBERNATION
/*
回收出这么多内存
系统范围回收指定数量内存. 返回回收的数量. 
 * Try to free `nr_to_reclaim' of memory, system-wide, and return the number of
 * freed pages.
 *
 * Rather than trying to age LRUs the aim is to preserve the overall
 * LRU order by reclaiming preferentially
 * inactive > active > active referenced > active mapped
 */
unsigned long shrink_all_memory(unsigned long nr_to_reclaim)
{
	struct scan_control sc = {
		.nr_to_reclaim = nr_to_reclaim,
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.priority = DEF_PRIORITY,
		/* 可以回写可以解除映射.  */
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.hibernation_mode = 1,
	};

	/* 回收的是全部的zone  */
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);
	unsigned long nr_reclaimed;
	unsigned int noreclaim_flag;

	fs_reclaim_acquire(sc.gfp_mask);
	noreclaim_flag = memalloc_noreclaim_save();
	set_task_reclaim_state(current, &sc.reclaim_state);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	set_task_reclaim_state(current, NULL);
	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(sc.gfp_mask);

	return nr_reclaimed;
}

#endif /* CONFIG_HIBERNATION */

/*
运行此node的kswapd
运行node上面的kswap
 * This kswapd start function will be called by init and node-hot-add.
 */
void __meminit kswapd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);

	pgdat_kswapd_lock(pgdat);
	if (!pgdat->kswapd) {
		pgdat->kswapd = kthread_run(kswapd, pgdat, "kswapd%d", nid);
		if (IS_ERR(pgdat->kswapd)) {
			/* failure at boot is fatal */
			BUG_ON(system_state < SYSTEM_RUNNING);
			pr_err("Failed to start kswapd on node %d\n", nid);
			pgdat->kswapd = NULL;
		}
	}
	pgdat_kswapd_unlock(pgdat);
}

/*
 * Called by memory hotplug when all memory in a node is offlined.  Caller must
 * be holding mem_hotplug_begin/done().
 */
void __meminit kswapd_stop(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	struct task_struct *kswapd;

	pgdat_kswapd_lock(pgdat);
	kswapd = pgdat->kswapd;
	if (kswapd) {
		kthread_stop(kswapd);
		pgdat->kswapd = NULL;
	}
	pgdat_kswapd_unlock(pgdat);
}

static int __init kswapd_init(void)
{
	int nid;

	swap_setup();
	for_each_node_state(nid, N_MEMORY)
 		kswapd_run(nid);
	return 0;
}

module_init(kswapd_init)

#ifdef CONFIG_NUMA
/*
可以有sysctl控制的对zone的回收方式.
控制node_reclaim函数的行为 
 * Node reclaim mode
 *
 * If non-zero call node_reclaim when the number of free pages falls below
 * the watermarks.
	如果非零的时候, 如果free页面太少会调用node_reclaim?
	那为0的时候, node_reclaim不起作用吗?
 */
int node_reclaim_mode __read_mostly;

/*
 * Priority for NODE_RECLAIM. This determines the fraction of pages
 * of a node considered for each zone_reclaim. 4 scans 1/16th of
 * a zone.
 这个次数好像偏小?
 快速回收
 */
#define NODE_RECLAIM_PRIORITY 4

/*
 * Percentage of pages in a zone that must be unmapped for node_reclaim to
 * occur.
 保留的pagecache页面比例?
 */
int sysctl_min_unmapped_ratio = 1;

/*
 * If the number of slab pages in a zone grows beyond this percentage then
 * slab reclaim needs to occur.
 */
int sysctl_min_slab_ratio = 5;

/* unmapped file pages是什么
计算pagecache页面比 mapped file页多的数量 */
/* 获取node上面unmap的文件页数量 */
static inline unsigned long node_unmapped_file_pages(struct pglist_data *pgdat)
{	
	/* 被映射的文件页数量 */
	unsigned long file_mapped = node_page_state(pgdat, NR_FILE_MAPPED);

	/* pagecache的文件页数量 */
	unsigned long file_lru = node_page_state(pgdat, NR_INACTIVE_FILE) +
		node_page_state(pgdat, NR_ACTIVE_FILE);

	/*
	 * It's possible for there to be more file mapped pages than
	 * accounted for by the pages on the file LRU lists because
	 * tmpfs pages accounted for as ANON can also be FILE_MAPPED
	 */
	return (file_lru > file_mapped) ? (file_lru - file_mapped) : 0;
}

/* Work out how many page cache pages we can reclaim in this reclaim_mode
计算在这个回收模式下面, 有多少pagecache页面可以回收.
可能会减去mapped file, dirty file ...  
计算节点上面可回收的文件页数量*/
static unsigned long node_pagecache_reclaimable(struct pglist_data *pgdat)
{
	unsigned long nr_pagecache_reclaimable;
	unsigned long delta = 0;

	/*
	 * If RECLAIM_UNMAP is set, then all file pages are considered
	 * potentially reclaimable. Otherwise, we have to worry about
	 * pages like swapcache and node_unmapped_file_pages() provides
	 * a better estimate
	 */
	if (node_reclaim_mode & RECLAIM_UNMAP) /* 如果可以解除,就是全部的file pages */
		nr_pagecache_reclaimable = node_page_state(pgdat, NR_FILE_PAGES);
	else /*不可以解除 , 计算pagecache页面比 mapped file页多的数量 */
		nr_pagecache_reclaimable = node_unmapped_file_pages(pgdat);

	/* If we can't clean pages, remove dirty pages from consideration
	 如果回收不可忆回写,那么不考虑脏页
	
	如果回收此节点的时候不能回写? */
	if (!(node_reclaim_mode & RECLAIM_WRITE))
		delta += node_page_state(pgdat, NR_FILE_DIRTY);

	/* Watch for any possible underflows due to delta */
	if (unlikely(delta > nr_pagecache_reclaimable))
		delta = nr_pagecache_reclaimable;

	return nr_pagecache_reclaimable - delta;
}

/*
分配内存时, 从node回收内存, 回收出满足order的量就行.
 * Try to free up some pages from this node through reclaim.
 */
static int __node_reclaim(struct pglist_data *pgdat, gfp_t gfp_mask, unsigned int order)
{
	/* Minimum pages needed in order to stay on node */
	const unsigned long nr_pages = 1 << order;
	struct task_struct *p = current;
	unsigned int noreclaim_flag;
	struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.gfp_mask = current_gfp_context(gfp_mask),
		.order = order,
		.priority = NODE_RECLAIM_PRIORITY, //尝试4遍, 快速回收的一个特征
		.may_writepage = !!(node_reclaim_mode & RECLAIM_WRITE),
		.may_unmap = !!(node_reclaim_mode & RECLAIM_UNMAP),
		.may_swap = 1,
		.reclaim_idx = gfp_zone(gfp_mask),
	};
	unsigned long pflags;

	trace_mm_vmscan_node_reclaim_begin(pgdat->node_id, order,
					   sc.gfp_mask);

	cond_resched();
	psi_memstall_enter(&pflags);
	
	fs_reclaim_acquire(sc.gfp_mask);
	/*
	 * We need to be able to allocate from the reserves for RECLAIM_UNMAP
	 */
	noreclaim_flag = memalloc_noreclaim_save();

	set_task_reclaim_state(p, &sc.reclaim_state);

	/* 好像是又检查一遍 ... */
	if (node_pagecache_reclaimable(pgdat) > pgdat->min_unmapped_pages ||
	    node_page_state_pages(pgdat, NR_SLAB_RECLAIMABLE_B) > pgdat->min_slab_pages) {
			/* 为什么计算这个, 难道这个回收路径会主要回收文件页? */
		/*
		 * Free memory by calling shrink node with increasing
		 * priorities until we have enough memory freed.
		 */
		/* 在priority次数范围内, 一直回收够 ... */
		do {
			shrink_node(pgdat, &sc);
		} while (sc.nr_reclaimed < nr_pages && --sc.priority >= 0);
	}

	set_task_reclaim_state(p, NULL);
	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(sc.gfp_mask);
	psi_memstall_leave(&pflags);

	trace_mm_vmscan_node_reclaim_end(sc.nr_reclaimed);

	return sc.nr_reclaimed >= nr_pages;
}

/* 这个是直接内存回收?
里面好像需要加锁. 这个运行条件也很苛刻.


如果可回收文件页太少,返回.
如果要求分配立即完成也返回
不夸numa
 */
/* 直接回收此node */
int node_reclaim(struct pglist_data *pgdat, gfp_t gfp_mask, unsigned int order)
{
	int ret;

	/*
	 * Node reclaim reclaims unmapped file backed pages and
	 * slab pages if we are over the defined limits.
	 * 会回收没有映射的文件交换页,和slab node_reclaim会回收未映射的文件页和 slab 页
	 * A small portion of unmapped file backed pages is needed for
	 * file I/O otherwise pages read by file I/O will be immediately
	 * thrown out if the node is overallocated. So we do not reclaim
	 * if less than a specified percentage of the node is used by
	 * unmapped file backed pages .
		为了文件 I/O 的需要，少量unmapped file backed页面是必需的，否则通过文件 
		I/O 读取的页面将在节点过度分配时立即被丢弃。因此，如果节点中用于
		未映射文件支持页面的比例低于指定的百分比，我们就不会进行回收。

	 一小部分未映射的文件支持页是文件 I/O必须的. 反而其他的文件 
	 I/O 读取的pagecache页是可以立即被丢弃的。
	 如果当前的pagecache页少于这个必须的百分比,就不回收
	 */
	if (node_pagecache_reclaimable(pgdat) <= pgdat->min_unmapped_pages &&
	    node_page_state_pages(pgdat, NR_SLAB_RECLAIMABLE_B) <= pgdat->min_slab_pages)
		/* 如果node可回收的太少了 */
		return NODE_RECLAIM_FULL;

	/*
	 * Do not scan if the allocation should not be delayed.
	 如果要求立即分配完成
	 */
	if (!gfpflags_allow_blocking(gfp_mask) || (current->flags & PF_MEMALLOC))
		return NODE_RECLAIM_NOSCAN;

	/*
	 * Only run node reclaim on the local node or on nodes that do not
	 * have associated processors. This will favor the local processor
	 * over remote processors and spread off node memory allocations
	 * as wide as possible.

	 */
	if (node_state(pgdat->node_id, N_CPU) && pgdat->node_id != numa_node_id())
		return NODE_RECLAIM_NOSCAN;
	

	/* 这种回收方式还有race吗 */
	if (test_and_set_bit(PGDAT_RECLAIM_LOCKED, &pgdat->flags))/* 如果已经被加锁了? */
		return NODE_RECLAIM_NOSCAN; 

	ret = __node_reclaim(pgdat, gfp_mask, order);
	/* 清除掉锁 */

	clear_bit(PGDAT_RECLAIM_LOCKED, &pgdat->flags);

	if (!ret)
		count_vm_event(PGSCAN_ZONE_RECLAIM_FAILED);

	return ret;
}
#endif

/**
把fbatch里面事实上已经evictable的folio移到合适的zone. 
 * check_move_unevictable_folios - Move evictable folios to appropriate zone
 * lru list
 * @fbatch: Batch of lru folios to check.
 *
 * Checks folios for evictability, if an evictable folio is in the unevictable
 * lru list, moves it to the appropriate evictable lru list. This function
 * should be only used for lru folios.
 */
void check_move_unevictable_folios(struct folio_batch *fbatch)
{
	struct lruvec *lruvec = NULL;
	int pgscanned = 0;
	int pgrescued = 0;
	int i;

	for (i = 0; i < fbatch->nr; i++) {
		struct folio * folio = fbatch->folios[i];
		int nr_pages = folio_nr_pages(folio);

		pgscanned += nr_pages;

		/* block memcg migration while the folio moves between lrus */
		if (!folio_test_clear_lru(folio))
			continue;

		/* 下面是本来有lru的情况 */
		lruvec = folio_lruvec_relock_irq(folio, lruvec);
		if (folio_evictable(folio) && folio_test_unevictable(folio)) {/* 如果folio
		实质上已经是evictable的了.  */
			lruvec_del_folio(lruvec, folio);
			folio_clear_unevictable(folio);
			lruvec_add_folio(lruvec, folio);
			pgrescued += nr_pages;
		}
		/* 重新设置lru标记 */
		folio_set_lru(folio);
	}

	if (lruvec) {
		__count_vm_events(UNEVICTABLE_PGRESCUED, pgrescued);
		__count_vm_events(UNEVICTABLE_PGSCANNED, pgscanned);
		unlock_page_lruvec_irq(lruvec);
	} else if (pgscanned) {
		count_vm_events(UNEVICTABLE_PGSCANNED, pgscanned);
	}
}
EXPORT_SYMBOL_GPL(check_move_unevictable_folios);
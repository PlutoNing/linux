// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/admin-guide/sysctl/vm.rst.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
#include <linux/memremap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/page_idle.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/pagemap.h>

/* How many pages do we try to swap or page in/out together? */
int page_cluster;

static DEFINE_PER_CPU(struct pagevec, lru_add_pvec);
static DEFINE_PER_CPU(struct pagevec, lru_rotate_pvecs);
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_file_pvecs);
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_pvecs);
static DEFINE_PER_CPU(struct pagevec, lru_lazyfree_pvecs);
#ifdef CONFIG_SMP
static DEFINE_PER_CPU(struct pagevec, activate_page_pvecs);
#endif

/*
 * This path almost never happens for VM activity - pages are normally
 * freed via pagevecs.  But it gets used by networking.
 */
static void __page_cache_release(struct page *page)
{
	if (PageLRU(page)) {
		pg_data_t *pgdat = page_pgdat(page);
		struct lruvec *lruvec;
		unsigned long flags;

		spin_lock_irqsave(&pgdat->lru_lock, flags);
		lruvec = mem_cgroup_page_lruvec(page, pgdat);
		VM_BUG_ON_PAGE(!PageLRU(page), page);
		__ClearPageLRU(page);
		del_page_from_lru_list(page, lruvec, page_off_lru(page));
		spin_unlock_irqrestore(&pgdat->lru_lock, flags);
	}
	__ClearPageWaiters(page);
}

static void __put_single_page(struct page *page)
{
	__page_cache_release(page);
	mem_cgroup_uncharge(page);
	free_unref_page(page);
}

static void __put_compound_page(struct page *page)
{
	compound_page_dtor *dtor;

	/*
	 * __page_cache_release() is supposed to be called for thp, not for
	 * hugetlb. This is because hugetlb page does never have PageLRU set
	 * (it's never listed to any LRU lists) and no memcg routines should
	 * be called for hugetlb (it has a separate hugetlb_cgroup.)
	 */
	if (!PageHuge(page))
		__page_cache_release(page);
	dtor = get_compound_page_dtor(page);
	(*dtor)(page);
}

void __put_page(struct page *page)
{
	if (is_zone_device_page(page)) {
		put_dev_pagemap(page->pgmap);

		/*
		 * The page belongs to the device that created pgmap. Do
		 * not return it to page allocator.
		 */
		return;
	}

	if (unlikely(PageCompound(page)))
		__put_compound_page(page);
	else
		__put_single_page(page);
}
EXPORT_SYMBOL(__put_page);

/**
2024年6月30日15:01:12
 * put_pages_list() - release a list of pages
 * @pages: list of pages threaded on page->lru
 *
 * Release a list of pages which are strung together on page.lru.  Currently
 * used by read_cache_pages() and related error recovery code.
 */
void put_pages_list(struct list_head *pages)
{
	while (!list_empty(pages)) {
		struct page *victim;

		victim = lru_to_page(pages);
		list_del(&victim->lru);
		put_page(victim);
	}
}
EXPORT_SYMBOL(put_pages_list);

/*
 * get_kernel_pages() - pin kernel pages in memory
 * @kiov:	An array of struct kvec structures
 * @nr_segs:	number of segments to pin
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_segs long.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with.
 */
int get_kernel_pages(const struct kvec *kiov, int nr_segs, int write,
		struct page **pages)
{
	int seg;

	for (seg = 0; seg < nr_segs; seg++) {
		if (WARN_ON(kiov[seg].iov_len != PAGE_SIZE))
			return seg;

		pages[seg] = kmap_to_page(kiov[seg].iov_base);
		get_page(pages[seg]);
	}

	return seg;
}
EXPORT_SYMBOL_GPL(get_kernel_pages);

/*
 * get_kernel_page() - pin a kernel page in memory
 * @start:	starting kernel address
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointer to the page pinned.
 *		Must be at least nr_segs long.
 *
 * Returns 1 if page is pinned. If the page was not pinned, returns
 * -errno. The page returned must be released with a put_page() call
 * when it is finished with.
 */
int get_kernel_page(unsigned long start, int write, struct page **pages)
{
	const struct kvec kiov = {
		.iov_base = (void *)start,
		.iov_len = PAGE_SIZE
	};

	return get_kernel_pages(&kiov, 1, write, pages);
}
EXPORT_SYMBOL_GPL(get_kernel_page);
/* 
2024年06月21日14:56:27
===================
其中move_fn会调用add_page_to_lru_list把page添加到lru，
而update_lru_size会更新对应的node和memcg的lru size
====================
找到pagevec所属的node，lruvec，lru之后，加入进去。
 */
static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct pglist_data *pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		struct pglist_data *pagepgdat = page_pgdat(page);
/*       pgdat记录的是上一次使用的node，如果当前处理的node和上一个
         node相同，则无需上锁；如果不同，则需要先将上一个node解锁，
         然后再讲当前node上锁。 */
		if (pagepgdat != pgdat) {
			if (pgdat)
				spin_unlock_irqrestore(&pgdat->lru_lock, flags);
			pgdat = pagepgdat;
			spin_lock_irqsave(&pgdat->lru_lock, flags);
		}
		/* 获取page对应的lruvec，获取node对应的lru链表，给钩子函数使用
		pgdat->lruvec
		 */
		lruvec = mem_cgroup_page_lruvec(page, pgdat);
		/* 添加到lru链表 */
		(*move_fn)(page, lruvec, arg);
	}
	if (pgdat)
		spin_unlock_irqrestore(&pgdat->lru_lock, flags);
	release_pages(pvec->pages, pvec->nr);
	pagevec_reinit(pvec);
}
/* 2024年06月25日15:59:11
 */
static void pagevec_move_tail_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	int *pgmoved = arg;

	if (PageLRU(page) && !PageUnevictable(page)) {
		del_page_from_lru_list(page, lruvec, page_lru(page));
		ClearPageActive(page);
		add_page_to_lru_list_tail(page, lruvec, page_lru(page));
		(*pgmoved)++;
	}
}

/*
2024年06月25日15:58:56

 * pagevec_move_tail() must be called with IRQ disabled.
 * Otherwise this may cause nasty races.
 */
static void pagevec_move_tail(struct pagevec *pvec)
{
	int pgmoved = 0;

	pagevec_lru_move_fn(pvec, pagevec_move_tail_fn, &pgmoved);
	__count_vm_events(PGROTATED, pgmoved);
}

/*
2024年06月25日15:56:39
将即将回写完成的page放入到非活跃链表的尾部，是为了加速其回收的速度。
 * Writeback is about to end against a page which has been marked for immediate
 * reclaim.  If it still appears to be reclaimable, move it to the tail of the
 * inactive list.
 */
void rotate_reclaimable_page(struct page *page)
{
	if (!PageLocked(page) && !PageDirty(page) &&
	    !PageUnevictable(page) && PageLRU(page)) {
		struct pagevec *pvec;
		unsigned long flags;

		get_page(page);
		local_irq_save(flags);
		pvec = this_cpu_ptr(&lru_rotate_pvecs);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}
}

static void update_page_reclaim_stat(struct lruvec *lruvec,
				     int file, int rotated)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	reclaim_stat->recent_scanned[file]++;
	if (rotated)
		reclaim_stat->recent_rotated[file]++;
}

static void __activate_page(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		int file = page_is_file_cache(page);
		int lru = page_lru_base_type(page);

		del_page_from_lru_list(page, lruvec, lru);
		SetPageActive(page);
		lru += LRU_ACTIVE;
		add_page_to_lru_list(page, lruvec, lru);
		trace_mm_lru_activate(page);

		__count_vm_event(PGACTIVATE);
		update_page_reclaim_stat(lruvec, file, 1);
	}
}

#ifdef CONFIG_SMP
static void activate_page_drain(int cpu)
{
	struct pagevec *pvec = &per_cpu(activate_page_pvecs, cpu);

	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, __activate_page, NULL);
}

static bool need_activate_page_drain(int cpu)
{
	return pagevec_count(&per_cpu(activate_page_pvecs, cpu)) != 0;
}

void activate_page(struct page *page)
{
	page = compound_head(page);
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(activate_page_pvecs);

		get_page(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, __activate_page, NULL);
		put_cpu_var(activate_page_pvecs);
	}
}

#else
static inline void activate_page_drain(int cpu)
{
}

void activate_page(struct page *page)
{
	pg_data_t *pgdat = page_pgdat(page);

	page = compound_head(page);
	spin_lock_irq(&pgdat->lru_lock);
	__activate_page(page, mem_cgroup_page_lruvec(page, pgdat), NULL);
	spin_unlock_irq(&pgdat->lru_lock);
}
#endif

static void __lru_cache_activate_page(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);
	int i;

	/*
	 * Search backwards on the optimistic assumption that the page being
	 * activated has just been added to this pagevec. Note that only
	 * the local pagevec is examined as a !PageLRU page could be in the
	 * process of being released, reclaimed, migrated or on a remote
	 * pagevec that is currently being drained. Furthermore, marking
	 * a remote pagevec's page PageActive potentially hits a race where
	 * a page is marked PageActive just after it is added to the inactive
	 * list causing accounting errors and BUG_ON checks to trigger.
	 */
	for (i = pagevec_count(pvec) - 1; i >= 0; i--) {
		struct page *pagevec_page = pvec->pages[i];

		if (pagevec_page == page) {
			SetPageActive(page);
			break;
		}
	}

	put_cpu_var(lru_add_pvec);
}

/*
2024年6月30日15:11:22
2024年7月1日23:08:30
设置页面是活跃的
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 *
 * When a newly allocated page is not yet visible, so safe for non-atomic ops,
 * __SetPageReferenced(page) may be substituted for mark_page_accessed(page).
 */
void mark_page_accessed(struct page *page)
{
	page = compound_head(page);
	if (!PageActive(page) && !PageUnevictable(page) &&
			PageReferenced(page)) {

		/*
		 * If the page is on the LRU, queue it for activation via
		 * activate_page_pvecs. Otherwise, assume the page is on a
		 * pagevec, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 */
		if (PageLRU(page))
			activate_page(page);
		else
			__lru_cache_activate_page(page);
		ClearPageReferenced(page);
		if (page_is_file_cache(page))
			workingset_activation(page);
	} else if (!PageReferenced(page)) {
		SetPageReferenced(page);
	}
	if (page_is_idle(page))
		clear_page_idle(page);
}
EXPORT_SYMBOL(mark_page_accessed);
/* 2024年6月24日23:41:30
将一个page添加到lru_add链表的实现。每个lru缓存都是CPU上的一个缓存，当该page加入到
lru缓存后，缓存已经满了，又或者这个page是一个复合类型的page（原因未知），
则直接将缓存的数据刷入到对应的lru链表中。
 */
static void __lru_cache_add(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);

	get_page(page);
	/*      尝试加入到lru_add缓存中，如果缓存已经满了或者page是复合类型（为什么？？？），则直接加入到lru链表中
*/
	if (!pagevec_add(pvec, page) || PageCompound(page))
		__pagevec_lru_add(pvec);
	put_cpu_var(lru_add_pvec);
}

/**
2024年07月03日14:51:49
 * lru_cache_add_anon - add a page to the page lists
 * @page: the page to add
 */
void lru_cache_add_anon(struct page *page)
{
	if (PageActive(page))
		ClearPageActive(page);
	__lru_cache_add(page);
}

void lru_cache_add_file(struct page *page)
{
	if (PageActive(page))
		ClearPageActive(page);
	__lru_cache_add(page);
}
EXPORT_SYMBOL(lru_cache_add_file);

/**
2024年6月24日23:41:05

加到page list？什么list？加到pagevec。

 * lru_cache_add - add a page to a page list
 * @page: the page to be added to the LRU.
 *
 * Queue the page for addition to the LRU via pagevec. The decision on whether
 * to add the page to the [in]active [file|anon] list is deferred until the
 * pagevec is drained. This gives a chance for the caller of lru_cache_add()
 * have the page added to the active list using mark_page_accessed().
 */
void lru_cache_add(struct page *page)
{
	VM_BUG_ON_PAGE(PageActive(page) && PageUnevictable(page), page);
	VM_BUG_ON_PAGE(PageLRU(page), page);
	__lru_cache_add(page);
}

/**
2024年06月21日14:53:42
lru记账的时机还是在缺页处理do_anonymous_page->lru_cache_add_active_or_unevictable
 * lru_cache_add_active_or_unevictable
 * @page:  the page to be added to LRU
 * @vma:   vma in which page is mapped for determining reclaimability
 *
 * Place @page on the active or unevictable LRU list, depending on its
 * evictability.  Note that if the page is not evictable, it goes
 * directly back onto it's zone's unevictable list, it does NOT use a
 * per cpu pagevec.
 */
void lru_cache_add_active_or_unevictable(struct page *page,
					 struct vm_area_struct *vma)
{
	VM_BUG_ON_PAGE(PageLRU(page), page);

	if (likely((vma->vm_flags & (VM_LOCKED | VM_SPECIAL)) != VM_LOCKED))
		SetPageActive(page);
	else if (!TestSetPageMlocked(page)) {
		/*
		 * We use the irq-unsafe __mod_zone_page_stat because this
		 * counter is not modified from interrupt context, and the pte
		 * lock is held(spinlock), which implies preemption disabled.
		 */
		__mod_zone_page_state(page_zone(page), NR_MLOCK,
				    hpage_nr_pages(page));
		count_vm_event(UNEVICTABLE_PGMLOCKED);
	}
	lru_cache_add(page);
}

/*
2024年06月25日15:18:04
lru_deactivate_file链表缓存是将一个文件页从活跃lru放入到非活跃lru中，只在当系统发现某
个文件页是无效时（没有被map？），才会放入到该缓存中，这是为了加速其被回收。如果该文件页被锁
在内存中，则不允许操作。如果该文件页的refcount是0，也即没有被使用，那无需处理；只有当文件
页被使用时，才需要放入到缓存链表中。当缓存链表已经满了或者该page是复合类型，则需刷入到lru链表中。
 * If the page can not be invalidated, it is moved to the
 * inactive list to speed up its reclaim.  It is moved to the
 * head of the list, rather than the tail, to give the flusher
 * threads some time to write it out, as this is much more
 * effective than the single-page writeout from reclaim.
 *
 * If the page isn't page_mapped and dirty/writeback, the page
 * could reclaim asap using PG_reclaim.
 *
 * 1. active, mapped page -> none
 * 2. active, dirty/writeback page -> inactive, head, PG_reclaim
 * 3. inactive, mapped page -> none
 * 4. inactive, dirty/writeback page -> inactive, head, PG_reclaim
 * 5. inactive, clean -> inactive, tail
 * 6. Others -> none
 *
 * In 4, why it moves inactive's head, the VM expects the page would
 * be write it out by flusher threads as this is much more effective
 * than the single-page writeout from reclaim.
 */
static void lru_deactivate_file_fn(struct page *page, struct lruvec *lruvec,
			      void *arg)
{
	int lru, file;
	bool active;

    // 如果page不在lru链表中，则直接退出
	if (!PageLRU(page))
		return;

	if (PageUnevictable(page))
		return;

	/* Some processes are using the page 
	如果page被进程映射，则跳过*/
	if (page_mapped(page))
		return;

	active = PageActive(page);
	file = page_is_file_cache(page);
	/* 是页缓存还是匿名页 */
	lru = page_lru_base_type(page);

	del_page_from_lru_list(page, lruvec, lru + active);
	ClearPageActive(page);
	ClearPageReferenced(page);

	if (PageWriteback(page) || PageDirty(page)) {
		/*
		 * PG_reclaim could be raced with end_page_writeback
		 * It can make readahead confusing.  But race window
		 * is _really_ small and  it's non-critical problem.
		 如果需要回写
		将page添加到lru的头部，因为page需要回写，需要一定的时间

		 */
		add_page_to_lru_list(page, lruvec, lru);
		/* todo */
		SetPageReclaim(page);
	} else {
		/*
		 * The page's writeback ends up during pagevec
		 * We moves tha page into tail of inactive.
		 将page添加到lru链表的尾部，尽快回收
		 */
		add_page_to_lru_list_tail(page, lruvec, lru);
		__count_vm_event(PGROTATED);
	}

	if (active)
		__count_vm_event(PGDEACTIVATE);
	update_page_reclaim_stat(lruvec, file, 0);
}
/* 2024年06月25日15:52:25
从活动链表中删除，然后放入到非活动链表中。
 */
static void lru_deactivate_fn(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	if (PageLRU(page) && PageActive(page) && !PageUnevictable(page)) {
		int file = page_is_file_cache(page);
		int lru = page_lru_base_type(page);
/*  */
		del_page_from_lru_list(page, lruvec, lru + LRU_ACTIVE);
		ClearPageActive(page);
		ClearPageReferenced(page);
		add_page_to_lru_list(page, lruvec, lru);

		__count_vm_events(PGDEACTIVATE, hpage_nr_pages(page));
		update_page_reclaim_stat(lruvec, file, 0);
	}
}
/* 2024年06月25日15:54:53
只会处理在lru中正在回写到swap分区的匿名页。使用场景页不多，内存回收场景不会使用到。
 */
static void lru_lazyfree_fn(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	if (PageLRU(page) && PageAnon(page) && PageSwapBacked(page) &&
	    !PageSwapCache(page) && !PageUnevictable(page)) {
		bool active = PageActive(page);

		del_page_from_lru_list(page, lruvec,
				       LRU_INACTIVE_ANON + active);
		ClearPageActive(page);
		ClearPageReferenced(page);
		/*
		 * lazyfree pages are clean anonymous pages. They have
		 * SwapBacked flag cleared to distinguish normal anonymous
		 * pages
		 */
		ClearPageSwapBacked(page);
		add_page_to_lru_list(page, lruvec, LRU_INACTIVE_FILE);

		__count_vm_events(PGLAZYFREE, hpage_nr_pages(page));
		count_memcg_page_event(page, PGLAZYFREE);
		update_page_reclaim_stat(lruvec, 1, 0);
	}
}

/*
2024年6月25日20:40:43
 *将原先加入到各个Per-CPU变量pagevec缓存中的page都转移到它们真正应该处
	 *lru链表上，同时将当时它们加入pagevec时递增的计数减下去(加入pagevec
	 *就说明有一条pagevec这个路径在引用这个page)
 * Drain pages out of the cpu's pagevecs.
 * Either "cpu" is the current CPU, and preemption has already been
 * disabled; or "cpu" is being hot-unplugged, and is already dead.
 */
void lru_add_drain_cpu(int cpu)
{
	struct pagevec *pvec = &per_cpu(lru_add_pvec, cpu);

	/* 将pagevec加到lru */
	if (pagevec_count(pvec))
		__pagevec_lru_add(pvec);

	pvec = &per_cpu(lru_rotate_pvecs, cpu);
	if (pagevec_count(pvec)) {
		unsigned long flags;

		/* No harm done if a racing interrupt already did this */
		local_irq_save(flags);
		pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}

	pvec = &per_cpu(lru_deactivate_file_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_file_fn, NULL);

	pvec = &per_cpu(lru_deactivate_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);

	pvec = &per_cpu(lru_lazyfree_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_lazyfree_fn, NULL);

	activate_page_drain(cpu);
}

/**
2024年06月25日15:13:23
lru_deactivate_file链表缓存是将一个文件页从活跃lru放入到非活跃lru中，只在当系统发现某个文件页是无效时
（没有被map？），才会放入到该缓存中，这是为了加速其被回收。如果该文件页被锁在内存中，则不允许操作。如果该
文件页的refcount是0，也即没有被使用，那无需处理；
只有当文件页被使用时，才需要放入到缓存链表中。当缓存链表已经满了或者该page是复合类型，则需刷入到lru链表中。
 * deactivate_file_page - forcefully deactivate a file page
 * @page: page to deactivate
 *
 * This function hints the VM that @page is a good reclaim candidate,
 * for example if its invalidation fails due to the page being dirty
 * or under writeback.
 */
void deactivate_file_page(struct page *page)
{
	/*
	 * In a workload with many unevictable page such as mprotect,
	 * unevictable page deactivation for accelerating reclaim is pointless.
	 */
	if (PageUnevictable(page))
		return;
/* // 如果page的refcount是0，则不处理，等待回收即可
    // 如果page的refcount非0，则refcount加上1 */
	if (likely(get_page_unless_zero(page))) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_file_pvecs);
/*  	将page放入到对应lru缓存中，如果缓存链表已经满了或者page是复合类型，
        则将缓存刷入到链表中 */
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_deactivate_file_fn, NULL);
		put_cpu_var(lru_deactivate_file_pvecs);
	}
}

/*
2024年06月25日15:50:04
lru_deactivate链表缓存是将一个活动页移动到非活动页链表中时使用。只有在文件系统场景中，系统发现一
些没有被映射的页时，才会加入到这个缓存，目的也是为了加速这些页的回收速度。使用场景比较受限，正常的回收流程不会走这个处理。
 * deactivate_page - deactivate a page
 * @page: page to deactivate
 *
 * deactivate_page() moves @page to the inactive list if @page was on the active
 * list and was not an unevictable page.  This is done to accelerate the reclaim
 * of @page.
 */
void deactivate_page(struct page *page)
{
	if (PageLRU(page) && PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_pvecs);

		get_page(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);
		put_cpu_var(lru_deactivate_pvecs);
	}
}

/**
2024年06月25日15:54:24
只会处理在lru中正在回写到swap分区的匿名页。使用场景页不多，内存回收场景不会使用到。
 * mark_page_lazyfree - make an anon page lazyfree
 * @page: page to deactivate
 *
 * mark_page_lazyfree() moves @page to the inactive file list.
 * This is done to accelerate the reclaim of @page.
 */
void mark_page_lazyfree(struct page *page)
{
	if (PageLRU(page) && PageAnon(page) && PageSwapBacked(page) &&
	    !PageSwapCache(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(lru_lazyfree_pvecs);

		get_page(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_lazyfree_fn, NULL);
		put_cpu_var(lru_lazyfree_pvecs);
	}
}
/* 2024年6月25日20:40:25 */
void lru_add_drain(void)
{
	lru_add_drain_cpu(get_cpu());
	put_cpu();
}

#ifdef CONFIG_SMP

static DEFINE_PER_CPU(struct work_struct, lru_add_drain_work);

static void lru_add_drain_per_cpu(struct work_struct *dummy)
{
	lru_add_drain();
}

/*
 * Doesn't need any cpu hotplug locking because we do rely on per-cpu
 * kworkers being shut down before our page_alloc_cpu_dead callback is
 * executed on the offlined cpu.
 * Calling this function with cpu hotplug locks held can actually lead
 * to obscure indirect dependencies via WQ context.
 */
void lru_add_drain_all(void)
{
	static DEFINE_MUTEX(lock);
	static struct cpumask has_work;
	int cpu;

	/*
	 * Make sure nobody triggers this path before mm_percpu_wq is fully
	 * initialized.
	 */
	if (WARN_ON(!mm_percpu_wq))
		return;

	mutex_lock(&lock);
	cpumask_clear(&has_work);

	for_each_online_cpu(cpu) {
		struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);

		if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
		    pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_file_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_lazyfree_pvecs, cpu)) ||
		    need_activate_page_drain(cpu)) {
			INIT_WORK(work, lru_add_drain_per_cpu);
			queue_work_on(cpu, mm_percpu_wq, work);
			cpumask_set_cpu(cpu, &has_work);
		}
	}

	for_each_cpu(cpu, &has_work)
		flush_work(&per_cpu(lru_add_drain_work, cpu));

	mutex_unlock(&lock);
}
#else
void lru_add_drain_all(void)
{
	lru_add_drain();
}
#endif

/**
2024年6月24日23:49:06
以进程退出时的uncharge流程来分析，通过unmap_vmas去unmap一段虚拟地址后，
会调用release_pages函数释放page，最终调用uncharge_page。
 * release_pages - batched put_page()
 * @pages: array of pages to release
 * @nr: number of pages
 *
 * Decrement the reference count on all the pages in @pages.  If it
 * fell to zero, remove the page from the LRU and free it.
 */
void release_pages(struct page **pages, int nr)
{
	int i;
	LIST_HEAD(pages_to_free);
	struct pglist_data *locked_pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long uninitialized_var(flags);
	unsigned int uninitialized_var(lock_batch);

	for (i = 0; i < nr; i++) {
		/* 一个一个换吗 */
		struct page *page = pages[i];

		/*
		 * Make sure the IRQ-safe lock-holding time does not get
		 * excessive with a continuous string of pages from the
		 * same pgdat. The lock is held only if pgdat != NULL.
		 */
		if (locked_pgdat && ++lock_batch == SWAP_CLUSTER_MAX) {
			spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
			locked_pgdat = NULL;
		}

		if (is_huge_zero_page(page))
			continue;

		if (is_zone_device_page(page)) {
			if (locked_pgdat) {
				spin_unlock_irqrestore(&locked_pgdat->lru_lock,
						       flags);
				locked_pgdat = NULL;
			}
			/*
			 * ZONE_DEVICE pages that return 'false' from
			 * put_devmap_managed_page() do not require special
			 * processing, and instead, expect a call to
			 * put_page_testzero().
			 */
			if (put_devmap_managed_page(page))
				continue;
		}

		page = compound_head(page);
		if (!put_page_testzero(page))
			continue;

		if (PageCompound(page)) {
			if (locked_pgdat) {
				spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
				locked_pgdat = NULL;
			}
			__put_compound_page(page);
			continue;
		}

		if (PageLRU(page)) {
			struct pglist_data *pgdat = page_pgdat(page);

			if (pgdat != locked_pgdat) {
				if (locked_pgdat)
					spin_unlock_irqrestore(&locked_pgdat->lru_lock,
									flags);
				lock_batch = 0;
				locked_pgdat = pgdat;
				spin_lock_irqsave(&locked_pgdat->lru_lock, flags);
			}

			lruvec = mem_cgroup_page_lruvec(page, locked_pgdat);
			VM_BUG_ON_PAGE(!PageLRU(page), page);
			__ClearPageLRU(page);
			/* 从lruvec移除 */
			del_page_from_lru_list(page, lruvec, page_off_lru(page));
		}

		/* Clear Active bit in case of parallel mark_page_accessed */
		__ClearPageActive(page);
		__ClearPageWaiters(page);

		list_add(&page->lru, &pages_to_free);
	}
	if (locked_pgdat)
		spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
		/* 还账准备释放的页面 */
	mem_cgroup_uncharge_list(&pages_to_free);
	/* free什么，还有还在记录的机制吗 */
	free_unref_page_list(&pages_to_free);
}
EXPORT_SYMBOL(release_pages);

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
	if (!pvec->percpu_pvec_drained) {
		lru_add_drain();
		pvec->percpu_pvec_drained = true;
	}
	release_pages(pvec->pages, pagevec_count(pvec));
	pagevec_reinit(pvec);
}
EXPORT_SYMBOL(__pagevec_release);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* used by __split_huge_page_refcount() */
void lru_add_page_tail(struct page *page, struct page *page_tail,
		       struct lruvec *lruvec, struct list_head *list)
{
	const int file = 0;

	VM_BUG_ON_PAGE(!PageHead(page), page);
	VM_BUG_ON_PAGE(PageCompound(page_tail), page);
	VM_BUG_ON_PAGE(PageLRU(page_tail), page);
	lockdep_assert_held(&lruvec_pgdat(lruvec)->lru_lock);

	if (!list)
		SetPageLRU(page_tail);

	if (likely(PageLRU(page)))
		list_add_tail(&page_tail->lru, &page->lru);
	else if (list) {
		/* page reclaim is reclaiming a huge page */
		get_page(page_tail);
		list_add_tail(&page_tail->lru, list);
	} else {
		/*
		 * Head page has not yet been counted, as an hpage,
		 * so we must account for each subpage individually.
		 *
		 * Put page_tail on the list at the correct position
		 * so they all end up in order.
		 */
		add_page_to_lru_list_tail(page_tail, lruvec,
					  page_lru(page_tail));
	}

	if (!PageUnevictable(page))
		update_page_reclaim_stat(lruvec, file, PageActive(page_tail));
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
/* 2024年06月25日14:54:33
将lru_add缓存链表中的页加入到lru链表中

 */
static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	enum lru_list lru;
	int was_unevictable = TestClearPageUnevictable(page);

	VM_BUG_ON_PAGE(PageLRU(page), page);
    // 由于page将要被加入到lru中，要设置PG_lru的标志

	SetPageLRU(page);
	/*
	 * Page becomes evictable in two ways:
	 * 1) Within LRU lock [munlock_vma_page() and __munlock_pagevec()].
	 * 2) Before acquiring LRU lock to put the page to correct LRU and then
	 *   a) do PageLRU check with lock [check_move_unevictable_pages]
	 *   b) do PageLRU check before lock [clear_page_mlock]
	 *
	 * (1) & (2a) are ok as LRU lock will serialize them. For (2b), we need
	 * following strict ordering:
	 *
	 * #0: __pagevec_lru_add_fn		#1: clear_page_mlock
	 *
	 * SetPageLRU()				TestClearPageMlocked()
	 * smp_mb() // explicit ordering	// above provides strict
	 *					// ordering
	 * PageMlocked()			PageLRU()
	 *
	 *
	 * if '#1' does not observe setting of PG_lru by '#0' and fails
	 * isolation, the explicit barrier will make sure that page_evictable
	 * check will put the page in correct LRU. Without smp_mb(), SetPageLRU
	 * can be reordered after PageMlocked check and can make '#1' to fail
	 * the isolation of the page whose Mlocked bit is cleared (#0 is also
	 * looking at the same page) and the evictable page will be stranded
	 * in an unevictable LRU.
	 */
	smp_mb();

	if (page_evictable(page)) {
		/* 根据page类型，获取到node上面不同的lru链表 */
		lru = page_lru(page);
		/* 更新一下reclaim stat？ */
		update_page_reclaim_stat(lruvec, page_is_file_cache(page),
					 PageActive(page));
		if (was_unevictable)
			count_vm_event(UNEVICTABLE_PGRESCUED);
	} else {
		lru = LRU_UNEVICTABLE;
		ClearPageActive(page);
		SetPageUnevictable(page);
		if (!was_unevictable)
			count_vm_event(UNEVICTABLE_PGCULLED);
	}
    // 将page放入到lru链表中，并更新链表中的页面数

	add_page_to_lru_list(page, lruvec, lru);
	trace_mm_lru_insertion(page, lru);
}

/*
2024年6月24日23:47:54

 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 将lru缓存pagevec中的页面添加到lru链表中，如果页面的count是0，则将页面归还给伙伴系统
    // 如果一个page的PG_active（不）置位，则加入到（非）活动链表中。如果PG_swapbacked置位，
    // 加入到（非）活动匿名页lru链表中，否则加入到（非）活动文件页lru链表中。
    // 如果PG_unevictable置位，则加入到LRU_UNEVICTABLE的lru链表中。
 */
void __pagevec_lru_add(struct pagevec *pvec)
{
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, NULL);
}
EXPORT_SYMBOL(__pagevec_lru_add);

/**
 * pagevec_lookup_entries - gang pagecache lookup
 * @pvec:	Where the resulting entries are placed
 * @mapping:	The address_space to search
 * @start:	The starting entry index
 * @nr_entries:	The maximum number of pages
 * @indices:	The cache indices corresponding to the entries in @pvec
 *
 * pagevec_lookup_entries() will search for and return a group of up
 * to @nr_pages pages and shadow entries in the mapping.  All
 * entries are placed in @pvec.  pagevec_lookup_entries() takes a
 * reference against actual pages in @pvec.
 *
 * The search returns a group of mapping-contiguous entries with
 * ascending indexes.  There may be holes in the indices due to
 * not-present entries.
 *
 * pagevec_lookup_entries() returns the number of entries which were
 * found.
 */
unsigned pagevec_lookup_entries(struct pagevec *pvec,
				struct address_space *mapping,
				pgoff_t start, unsigned nr_entries,
				pgoff_t *indices)
{
	pvec->nr = find_get_entries(mapping, start, nr_entries,
				    pvec->pages, indices);
	return pagevec_count(pvec);
}

/**
 * pagevec_remove_exceptionals - pagevec exceptionals pruning
 * @pvec:	The pagevec to prune
 *
 * pagevec_lookup_entries() fills both pages and exceptional radix
 * tree entries into the pagevec.  This function prunes all
 * exceptionals from @pvec without leaving holes, so that it can be
 * passed on to page-only pagevec operations.
 */
void pagevec_remove_exceptionals(struct pagevec *pvec)
{
	int i, j;

	for (i = 0, j = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		if (!xa_is_value(page))
			pvec->pages[j++] = page;
	}
	pvec->nr = j;
}

/**
 * pagevec_lookup_range - gang pagecache lookup
 * @pvec:	Where the resulting pages are placed
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @end:	The final page index
 *
 * pagevec_lookup_range() will search for & return a group of up to PAGEVEC_SIZE
 * pages in the mapping starting from index @start and upto index @end
 * (inclusive).  The pages are placed in @pvec.  pagevec_lookup() takes a
 * reference against the pages in @pvec.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages. We
 * also update @start to index the next page for the traversal.
 *
 * pagevec_lookup_range() returns the number of pages which were found. If this
 * number is smaller than PAGEVEC_SIZE, the end of specified range has been
 * reached.
 */
unsigned pagevec_lookup_range(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *start, pgoff_t end)
{
	pvec->nr = find_get_pages_range(mapping, start, end, PAGEVEC_SIZE,
					pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_range);

unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		xa_mark_t tag)
{
	pvec->nr = find_get_pages_range_tag(mapping, index, end, tag,
					PAGEVEC_SIZE, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_range_tag);

unsigned pagevec_lookup_range_nr_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		xa_mark_t tag, unsigned max_pages)
{
	pvec->nr = find_get_pages_range_tag(mapping, index, end, tag,
		min_t(unsigned int, max_pages, PAGEVEC_SIZE), pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_range_nr_tag);
/*
2024年07月04日15:10:57
 * Perform any setup for the swap system
 */
void __init swap_setup(void)
{
	unsigned long megs = totalram_pages() >> (20 - PAGE_SHIFT);

	/* Use a smaller cluster for small-memory machines */
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}

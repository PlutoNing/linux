// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/migrate.h>
#include <linux/vmalloc.h>
#include <linux/swap_slots.h>
#include <linux/huge_mm.h>
#include <linux/shmem_fs.h>
#include "internal.h"
#include "swap.h"

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_page_list.
 swap地址空间的ops
   swapper_space是一个虚构的东西，保留下来是为了简化vmscan的shrink_page_list路径。
 */
static const struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	/*  */
	.dirty_folio	= noop_dirty_folio,
#ifdef CONFIG_MIGRATION
	.migrate_folio	= migrate_folio,
#endif
};
// 这个swap设备的几个地址空间的数组
struct address_space *swapper_spaces[MAX_SWAPFILES] __read_mostly;
// 表示这个swap设备有几个地址空间
static unsigned int nr_swapper_spaces[MAX_SWAPFILES] __read_mostly;
static bool enable_vma_readahead __read_mostly = true;

#define SWAP_RA_WIN_SHIFT	(PAGE_SHIFT / 2)
#define SWAP_RA_HITS_MASK	((1UL << SWAP_RA_WIN_SHIFT) - 1)
#define SWAP_RA_HITS_MAX	SWAP_RA_HITS_MASK
#define SWAP_RA_WIN_MASK	(~PAGE_MASK & ~SWAP_RA_HITS_MASK)

#define SWAP_RA_HITS(v)		((v) & SWAP_RA_HITS_MASK)
#define SWAP_RA_WIN(v)		(((v) & SWAP_RA_WIN_MASK) >> SWAP_RA_WIN_SHIFT)
#define SWAP_RA_ADDR(v)		((v) & PAGE_MASK)

#define SWAP_RA_VAL(addr, win, hits)				\
	(((addr) & PAGE_MASK) |					\
	 (((win) << SWAP_RA_WIN_SHIFT) & SWAP_RA_WIN_MASK) |	\
	 ((hits) & SWAP_RA_HITS_MASK))

/* Initial readahead hits is 4 to start up with a small window */
#define GET_SWAP_RA_VAL(vma)					\
	(atomic_long_read(&(vma)->swap_readahead_info) ? : 4)

static atomic_t swapin_readahead_hits = ATOMIC_INIT(4);

void show_swap_cache_info(void)
{
	printk("%lu pages in swap cache\n", total_swapcache_pages());
	printk("Free swap  = %ldkB\n", K(get_nr_swap_pages()));
	printk("Total swap = %lukB\n", K(total_swap_pages));
}

// shadow是什么
void *get_shadow_from_swap_cache(swp_entry_t entry)
{
	struct address_space *address_space = swap_address_space(entry);
	pgoff_t idx = swp_offset(entry);
	struct page *page;

	// 读取xas数组
	page = xa_load(&address_space->i_pages, idx);
	if (xa_is_value(page))
		return page;
	return NULL;
}

/*
把页面加入到swap的mapping xas
========================
一种情况是shmem的mapping准备回写这个folio, entry是刚刚分配的swap slot,这
里把folio加入到swap 的mapping, 并且设置folio的swap cache page flag.
 * add_to_swap_cache resembles filemap_add_folio on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
   add_to_swap_cache类似于filemap_add_folio在swapper_space上，
   但是设置SwapCache标志和私有标志，而不是mapping和index。
   ==============
返回0表示成功
 */
int add_to_swap_cache(struct folio *folio, swp_entry_t entry,
			gfp_t gfp, void **shadowp)
{
	/*
	其实就是一个添加page到页缓存的过程
	这里是添加到swap的mapping
	*/
	// 先获取对应swapfile的mapping
	struct address_space *address_space = swap_address_space(entry);
	// 获取在swap file的idx
	pgoff_t idx = swp_offset(entry);
	// 初始化xas
	XA_STATE_ORDER(xas, &address_space->i_pages, idx, folio_order(folio));
	unsigned long i, nr = folio_nr_pages(folio);
	void *old;
	// 以后
	xas_set_update(&xas, workingset_update_node);

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(folio_test_swapcache(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_swapbacked(folio), folio);

	folio_ref_add(folio, nr);
	// 设置folio的swapcache标志, 表示这个页面是swap的, 并且现在在内存
	folio_set_swapcache(folio);
	folio->swap = entry;

	// 现在加入xas
	do {
		xas_lock_irq(&xas);
		xas_create_range(&xas);/* 预分配空间 */
		if (xas_error(&xas))
			goto unlock;
		for (i = 0; i < nr; i++) {
			VM_BUG_ON_FOLIO(xas.xa_index != idx + i, folio);
			old = xas_load(&xas);
			if (xa_is_value(old)) {
				if (shadowp)
					*shadowp = old;
			}
			xas_store(&xas, folio);/* 存入xas */
			xas_next(&xas);
		}
		address_space->nrpages += nr;
		__node_stat_mod_folio(folio, NR_FILE_PAGES, nr);
		__lruvec_stat_mod_folio(folio, NR_SWAPCACHE, nr);
unlock:
		xas_unlock_irq(&xas);
	} while (xas_nomem(&xas, gfp));

	if (!xas_error(&xas))
		return 0;

	// 如果出错了
	folio_clear_swapcache(folio);
	folio_ref_sub(folio, nr);
	return xas_error(&xas);
}

/*
 * This must be called only on folios that have
 * been verified to be in the swap cache.
  必须仅在已验证在swap mapping中的folio上调用此函数。
  从swap mapping移除folio,用于换出,释放pagecache等操作.
  ===================
  就是把swap mapping里面对应的slot设置为null
  然后去除folio的swap_cache flag, 表示不在swap mapping了
 */
void __delete_from_swap_cache(struct folio *folio,
			swp_entry_t entry, void *shadow)
{
	struct address_space *address_space = swap_address_space(entry);
	int i;
	long nr = folio_nr_pages(folio);
	pgoff_t idx = swp_offset(entry);
	XA_STATE(xas, &address_space->i_pages, idx);

	xas_set_update(&xas, workingset_update_node);

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_swapcache(folio), folio);
	VM_BUG_ON_FOLIO(folio_test_writeback(folio), folio);

	for (i = 0; i < nr; i++) { // 一个一个覆盖这些条目（实质的一种情况是
	// 用空值覆盖,应该就是删除了）
		void *entry = xas_store(&xas, shadow);
		VM_BUG_ON_PAGE(entry != folio, entry);
		xas_next(&xas);
	}
	folio->swap.val = 0;
	//清除标记位
	folio_clear_swapcache(folio);
	address_space->nrpages -= nr;
	/* 为啥这个也算到文件页里面? */
	__node_stat_mod_folio(folio, NR_FILE_PAGES, -nr);
	__lruvec_stat_mod_folio(folio, NR_SWAPCACHE, -nr);
}

/**
给folio分配swp空间, 加入swap mapping, 并设置为dirty
=============
算是把folio加入swap 机制?
 * add_to_swap - allocate swap space for a folio
 * @folio: folio we want to move to swap
 *
 * Allocate swap space for the folio and add the folio to the
 * swap cache.
 * 给页面分配交换空间, 并且加入到swap cache
 * Context: Caller needs to hold the folio lock.
 * Return: Whether the folio was added to the swap cache.
 */
bool add_to_swap(struct folio *folio)
{
	swp_entry_t entry;
	int err;

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_uptodate(folio), folio);

	//这里获取swap slot
	entry = folio_alloc_swap(folio);
	if (!entry.val)
		return false;

	/*
	 * XArray node allocations from PF_MEMALLOC contexts could
	 * completely exhaust the page allocator. __GFP_NOMEMALLOC
	 * stops emergency reserves from being allocated.
	 * xarray node分配可能完全耗尽页面分配器。__GFP_NOMEMALLOC
	 * 阻止分配紧急储备。
	 * TODO: this could cause a theoretical memory reclaim
	 * deadlock in the swap out path.
	 */
	/*
	 * Add it to the swap cache.
	  把folio添加到swap mapping?
	 */
	err = add_to_swap_cache(folio, entry,
			__GFP_HIGH|__GFP_NOMEMALLOC|__GFP_NOWARN, NULL);
	if (err)
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		  函数不会返回-EEXIST，因此我们可以安全地清除SWAP_HAS_CACHE标志。
		 */
		goto fail;
	/*
	 * Normally the folio will be dirtied in unmap because its
	 * pte should be dirty. A special case is MADV_FREE page. The
	 * page's pte could have dirty bit cleared but the folio's
	 * SwapBacked flag is still set because clearing the dirty bit
	 * and SwapBacked flag has no lock protected. For such folio,
	 * unmap will not set dirty bit for it, so folio reclaim will
	 * not write the folio out. This can cause data corruption when
	 * the folio is swapped in later. Always setting the dirty flag
	 * for the folio solves the problem.
	 刚刚把folio加入swap mapping的xas数组, 这里设置为dirty , 加快
	 刷新到swap file?
	 */
	folio_mark_dirty(folio);

	return true;

fail:
	put_swap_folio(folio, entry);
	return false;
}

/*
一种情况是folio是swap mapping里面的
 * This must be called only on folios that have
 * been verified to be in the swap cache and locked.
 * It will never put the folio into the free list,
 * the caller has a reference on the folio.
   这个函数必须仅在已验证在交换缓存中并锁定的folio上调用。
   它永远不会将folio放入空闲列表，调用者对folio有引用。
  从swapcache删除folio,并释放swap空间.
 */
void delete_from_swap_cache(struct folio *folio)
{
	swp_entry_t entry = folio->swap; // 找到交换条目
	struct address_space *address_space = swap_address_space(entry); // 获取所在的swap file的mapping

	xa_lock_irq(&address_space->i_pages); // 锁定mapping的xas数组, 开始操作
	__delete_from_swap_cache(folio, entry, NULL);// 从swap mapping xas移除
	xa_unlock_irq(&address_space->i_pages);

	put_swap_folio(folio, entry); // 移除后减少ref计数
	folio_ref_sub(folio, folio_nr_pages(folio));
}

// 从 swap mapping移除
void clear_shadow_from_swap_cache(int type, unsigned long begin,
				unsigned long end)
{
	unsigned long curr = begin;
	void *old;

	for (;;) {
		// 获取swap entry
		swp_entry_t entry = swp_entry(type, curr);
		// 在获取指定的mapping
		struct address_space *address_space = swap_address_space(entry);
		XA_STATE(xas, &address_space->i_pages, curr);

		xas_set_update(&xas, workingset_update_node);

		xa_lock_irq(&address_space->i_pages);
		xas_for_each(&xas, old, end) {
			if (!xa_is_value(old))
				continue;
			// 置为null
			xas_store(&xas, NULL);
		}
		xa_unlock_irq(&address_space->i_pages);

		/* search the next swapcache until we meet end */
		curr >>= SWAP_ADDRESS_SPACE_SHIFT;
		curr++;
		curr <<= SWAP_ADDRESS_SPACE_SHIFT;
		if (curr > end)
			break;
	}
}

/*
  释放这个页面所占的swap cache的空间,也就是从mapping移除
 * If we are the only user, then try to free up the swap cache.
 * 如果我们是唯一的用户，那么尝试释放交换缓存。
 * Its ok to check the swapcache flag without the folio lock
 * here because we are going to recheck again inside
 * folio_free_swap() _with_ the lock.
 * 					- Marcelo
 */
void free_swap_cache(struct page *page)
{
	struct folio *folio = page_folio(page);

	if (folio_test_swapcache(folio) && !folio_mapped(folio) &&
	    folio_trylock(folio)) { // 在交换缓存的没有被映射的页, 并且加锁成功
		folio_free_swap(folio);
		folio_unlock(folio);
	}
}

/*
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page.
   执行free_page()，如果这是页面的最后一个用户，则还会释放与此页面关联的任何交换缓存。
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	if (!is_huge_zero_page(page))
		put_page(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
   传递一个页面数组，将它们全部从交换缓存中删除，然后释放它们。
   如果这是它们的最后一次使用，则它们将从LRU中删除并释放。
 */
void free_pages_and_swap_cache(struct encoded_page **pages, int nr)
{
	// 把fbatch的排空
	lru_add_drain();
	for (int i = 0; i < nr; i++)
		free_swap_cache(encoded_page_ptr(pages[i]));
	release_pages(pages, nr);
}

static inline bool swap_use_vma_readahead(void)
{
	return READ_ONCE(enable_vma_readahead) && !atomic_read(&nr_rotate_swap);
}

/*
 * Lookup a swap entry in the swap cache. A found folio will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the folio
 * lock before returning.
 * 在交换缓存中查找一个交换项。找到的 folio 将被解锁并且其引用计数将被增加 -
  我们依赖于内核锁使得页面表操作原子化，即使我们在返回之前放弃 folio 锁。
 
 * Caller must lock the swap device or hold a reference to keep it valid.
 调用者必须锁定交换设备或持有引用以保持其有效。
 -----------------------
 entry是由页表的条目转换来的, 编码了swap和idx信息
 去swap的mapping找到页面,然后读入到返回的folio里面, 是个
 换入的过程
 ============
 只在mapping查找,没有就算了，可能返回null
 */
struct folio *swap_cache_get_folio(swp_entry_t entry,
		struct vm_area_struct *vma, unsigned long addr)
{
	struct folio *folio;
	// 从swap的mapping里面获取folio
	folio = filemap_get_folio(swap_address_space(entry), swp_offset(entry));
	if (!IS_ERR(folio)) {// 如果获取没问题
		bool vma_ra = swap_use_vma_readahead();
		bool readahead;

		/*
		 * At the moment, we don't support PG_readahead for anon THP
		 * so let's bail out rather than confusing the readahead stat.
		 */
		if (unlikely(folio_test_large(folio)))
			return folio;

		readahead = folio_test_clear_readahead(folio);
		if (vma && vma_ra) {
			unsigned long ra_val;
			int win, hits;

			ra_val = GET_SWAP_RA_VAL(vma);
			win = SWAP_RA_WIN(ra_val);
			hits = SWAP_RA_HITS(ra_val);
			if (readahead)
				hits = min_t(int, hits + 1, SWAP_RA_HITS_MAX);
			atomic_long_set(&vma->swap_readahead_info,
					SWAP_RA_VAL(addr, win, hits));
		}

		if (readahead) {
			count_vm_event(SWAP_RA_HIT);
			if (!vma || !vma_ra)
				atomic_inc(&swapin_readahead_hits);
		}
	} else {
		folio = NULL;
	}

	return folio;
}

/**
 * filemap_get_incore_folio - Find and get a folio from the page or swap caches.
   查找和获取页缓存或交换缓存中的 folio。
 * @mapping: The address_space to search.
 * @index: The page cache index.
 *
 * This differs from filemap_get_folio() in that it will also look for the
 * folio in the swap cache.
 *
 * Return: The found folio or %NULL.
 */
struct folio *filemap_get_incore_folio(struct address_space *mapping,
		pgoff_t index)
{
	swp_entry_t swp;
	struct swap_info_struct *si;
	struct folio *folio = filemap_get_entry(mapping, index);

	if (!folio)
		return ERR_PTR(-ENOENT);
	if (!xa_is_value(folio))
		return folio;
	if (!shmem_mapping(mapping))
		return ERR_PTR(-ENOENT);

	swp = radix_to_swp_entry(folio);
	/* There might be swapin error entries in shmem mapping. */
	if (non_swap_entry(swp))
		return ERR_PTR(-ENOENT);
	/* Prevent swapoff from happening to us */
	si = get_swap_device(swp);
	if (!si)
		return ERR_PTR(-ENOENT);
	index = swp_offset(swp);
	//
	folio = filemap_get_folio(swap_address_space(swp), index);
	put_swap_device(si);
	return folio;
}

// 查找entry对应的页面, 如果mapping没有,新申请页面加入swap mapping.
/*
把页面读入swap cache
*/
struct page *__read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated)
{
	struct swap_info_struct *si;
	struct folio *folio;
	struct page *page;
	void *shadow = NULL;

	*new_page_allocated = false;
	// 获取swap设备
	si = get_swap_device(entry);
	if (!si)
		return NULL;

	for (;;) {
		int err;
		/*
		 * First check the swap cache.  Since this is normally
		 * called after swap_cache_get_folio() failed, re-calling
		 * that would confuse statistics.
		 */
		 // 先看看swap cache有没有这个page
		folio = filemap_get_folio(swap_address_space(entry),
						swp_offset(entry));
		if (!IS_ERR(folio)) {// 如果有
			page = folio_file_page(folio, swp_offset(entry));
			goto got_page;
		}
		// 现在是没有这个page的情况
		/*
		 * Just skip read ahead for unused swap slot.
		 * During swap_off when swap_slot_cache is disabled,
		 * we have to handle the race between putting
		 * swap entry in swap cache and marking swap slot
		 * as SWAP_HAS_CACHE.  That's done in later part of code or
		 * else swap_off will be aborted if we return NULL.
		 */
		if (!swap_swapcount(si, entry) && swap_slot_cache_enabled)
			goto fail_put_swap;

		/*
		 * Get a new page to read into from swap.  Allocate it now,
		 * before marking swap_map SWAP_HAS_CACHE, when -EEXIST will
		 * cause any racers to loop around until we add it to cache.
		   获取一个新的页面。在将 swap_map 标记为 SWAP_HAS_CACHE 之前，
		   现在分配它，当 -EEXIST 会导致任何竞争者循环，直到我们将其添加到缓存中。
		 */
		folio = vma_alloc_folio(gfp_mask, 0, vma, addr, false);
		if (!folio)
            goto fail_put_swap;
		// 现在vma有这个page了

		/*
		 * Swap entry may have been freed since our caller observed it.
		   在调用者观察到它之后，交换条目可能已被释放。
		 */
		err = swapcache_prepare(entry); // 给条目引用+1
		if (!err)
			break;

		folio_put(folio);
		if (err != -EEXIST)
			goto fail_put_swap;

		/*
		 * We might race against __delete_from_swap_cache(), and
		 * stumble across a swap_map entry whose SWAP_HAS_CACHE
		 * has not yet been cleared.  Or race against another
		 * __read_swap_cache_async(), which has set SWAP_HAS_CACHE
		 * in swap_map, but not yet added its page to swap cache.
		 */
		schedule_timeout_uninterruptible(1);
	}

	/*
	 * The swap entry is ours to swap in. Prepare the new page.
	 现在是我们的交换条目。准备新页面。
	 */

	__folio_set_locked(folio);
	__folio_set_swapbacked(folio);

	// 进行swap charge
	if (mem_cgroup_swapin_charge_folio(folio, NULL, gfp_mask, entry))
		goto fail_unlock;

	/* May fail (-ENOMEM) if XArray node allocation failed.
	这里把page加入到swap的mapping
	*/
	if (add_to_swap_cache(folio, entry, gfp_mask & GFP_RECLAIM_MASK, &shadow))
		goto fail_unlock;
	// 这里uncharge swap条目
	mem_cgroup_swapin_uncharge_swap(entry);

	if (shadow)
		workingset_refault(folio, shadow);

	/* Caller will initiate read into locked folio */
	folio_add_lru(folio);
	*new_page_allocated = true;
	page = &folio->page;
got_page:
	put_swap_device(si);
	return page;

fail_unlock:
	put_swap_folio(folio, entry);
	folio_unlock(folio);
	folio_put(folio);
fail_put_swap:
	put_swap_device(si);
	return NULL;
}

/*
和swap换入的预读相关
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 *
 * get/put_swap_device() aren't needed to call this function, because
 * __read_swap_cache_async() call them and swap_readpage() holds the
 * swap cache folio lock.
 */
struct page *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
				   struct vm_area_struct *vma,
				   unsigned long addr, struct swap_iocb **plug)
{
	bool page_was_allocated;
	// 找到entry对应的page
	struct page *retpage = __read_swap_cache_async(entry, gfp_mask,
			vma, addr, &page_was_allocated);

	if (page_was_allocated) // 如果为真，说明刚刚一开始没找到, 申请的新页面加入到swap的mapping.
	// 所以现在需要把swap file的page读入这个新page
		swap_readpage(retpage, false, plug);

	return retpage;
}

// swap换入预读的计算页面数量
static unsigned int __swapin_nr_pages(unsigned long prev_offset,
				      unsigned long offset,
				      int hits,
				      int max_pages,
				      int prev_win)
{
	unsigned int pages, last_ra;

	/*
	 * This heuristic has been found to work well on both sequential and
	 * random loads, swapping to hard disk or to SSD: please don't ask
	 * what the "+ 2" means, it just happens to work well, that's all.
	 */
	pages = hits + 2;
	if (pages == 2) {
		/*
		 * We can have no readahead hits to judge by: but must not get
		 * stuck here forever, so check for an adjacent offset instead
		 * (and don't even bother to check whether swap type is same).
		 */
		if (offset != prev_offset + 1 && offset != prev_offset - 1)
			pages = 1;
	} else {
		unsigned int roundup = 4;
		while (roundup < pages)
			roundup <<= 1;
		pages = roundup;
	}

	if (pages > max_pages)
		pages = max_pages;

	/* Don't shrink readahead too fast */
	last_ra = prev_win / 2;
	if (pages < last_ra)
		pages = last_ra;

	return pages;
}

// 换入预读计算数量
static unsigned long swapin_nr_pages(unsigned long offset)
{
	static unsigned long prev_offset;
	unsigned int hits, pages, max_pages;
	static atomic_t last_readahead_pages;

	max_pages = 1 << READ_ONCE(page_cluster);
	if (max_pages <= 1)
		return 1;

	hits = atomic_xchg(&swapin_readahead_hits, 0);
	pages = __swapin_nr_pages(READ_ONCE(prev_offset), offset, hits,
				  max_pages,
				  atomic_read(&last_readahead_pages));
	if (!hits)
		WRITE_ONCE(prev_offset, offset);
	atomic_set(&last_readahead_pages, pages);

	return pages;
}

/**
 * swap_cluster_readahead - swap in pages in hope we need them soon
 swap预读
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * This has been extended to use the NUMA policies from the mm triggering
 * the readahead.
 *
 * Caller must hold read mmap_lock if vmf->vma is not NULL.
 */
struct page *swap_cluster_readahead(swp_entry_t entry, gfp_t gfp_mask,
				struct vm_fault *vmf)
{
	struct page *page;
	unsigned long entry_offset = swp_offset(entry);
	unsigned long offset = entry_offset;
	unsigned long start_offset, end_offset;
	unsigned long mask;
	struct swap_info_struct *si = swp_swap_info(entry);
	struct blk_plug plug;
	struct swap_iocb *splug = NULL;
	bool page_allocated;
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr = vmf->address;

	mask = swapin_nr_pages(offset) - 1;
	if (!mask)
		goto skip;

	/* Read a page_cluster sized and aligned cluster around offset.
	读取一个大小为page_cluster的size, 对齐.
	*/
	start_offset = offset & ~mask;
	end_offset = offset | mask;
	if (!start_offset)	/* First page is swap header. */
		start_offset++;
	if (end_offset >= si->max)
		end_offset = si->max - 1;

	blk_start_plug(&plug);
	for (offset = start_offset; offset <= end_offset ; offset++) {// 一个一个的读取
		/* Ok, do the async read-ahead now */
		page = __read_swap_cache_async(
			swp_entry(swp_type(entry), offset),
			gfp_mask, vma, addr, &page_allocated);
		if (!page) // 读取失败,处理下一个offset
			continue;
		// 从swap读取成功了（可能是swap mapping本来就有, 也可能是申请页面新加入swap mapping的（page还没有装入swap file的内容））
		if (page_allocated) {// 如果是申请页面新换入的（page的内容还不是swap file的对应page）
			swap_readpage(page, false, &splug); // 现在把swap file的页面读入到page
			if (offset != entry_offset) {
				SetPageReadahead(page);
				count_vm_event(SWAP_RA);
			}
		}
		put_page(page);
	}

	blk_finish_plug(&plug);
	swap_read_unplug(splug);

	lru_add_drain();	/* Push any new pages onto the LRU now */
skip:
	/* The page was likely read above, so no need for plugging here
	只需要读取一个页面
	*/
	return read_swap_cache_async(entry, gfp_mask, vma, addr, NULL);
}

//初始化这个swap设备的地址空间
int init_swap_address_space(unsigned int type, unsigned long nr_pages)
{
	struct address_space *spaces, *space;
	unsigned int i, nr;
	// 计算地址空间数量
	nr = DIV_ROUND_UP(nr_pages, SWAP_ADDRESS_SPACE_PAGES);
	spaces = kvcalloc(nr, sizeof(struct address_space), GFP_KERNEL);
	if (!spaces)
		return -ENOMEM;
	for (i = 0; i < nr; i++) { // 逐个初始化地址空间
		space = spaces + i;
		// 初始化地址空间的xas数组的flag
		xa_init_flags(&space->i_pages, XA_FLAGS_LOCK_IRQ);
		atomic_set(&space->i_mmap_writable, 0);
		space->a_ops = &swap_aops;
		/* swap cache doesn't use writeback related tags
		swap的地址空间不使用writeback相关的标记
		*/
		mapping_set_no_writeback_tags(space);
	}
	nr_swapper_spaces[type] = nr;
	swapper_spaces[type] = spaces;

	return 0;
}

void exit_swap_address_space(unsigned int type)
{
	int i;
	struct address_space *spaces = swapper_spaces[type];

	for (i = 0; i < nr_swapper_spaces[type]; i++)
		VM_WARN_ON_ONCE(!mapping_empty(&spaces[i]));
	kvfree(spaces);
	nr_swapper_spaces[type] = 0;
	swapper_spaces[type] = NULL;
}

#define SWAP_RA_ORDER_CEILING	5

struct vma_swap_readahead {
	unsigned short win;
	unsigned short offset;
	unsigned short nr_pte;
};

static void swap_ra_info(struct vm_fault *vmf,
			 struct vma_swap_readahead *ra_info)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long ra_val;
	unsigned long faddr, pfn, fpfn, lpfn, rpfn;
	unsigned long start, end;
	unsigned int max_win, hits, prev_win, win;

	max_win = 1 << min_t(unsigned int, READ_ONCE(page_cluster),
			     SWAP_RA_ORDER_CEILING);
	if (max_win == 1) {
		ra_info->win = 1;
		return;
	}

	faddr = vmf->address;
	fpfn = PFN_DOWN(faddr);
	ra_val = GET_SWAP_RA_VAL(vma);
	pfn = PFN_DOWN(SWAP_RA_ADDR(ra_val));
	prev_win = SWAP_RA_WIN(ra_val);
	hits = SWAP_RA_HITS(ra_val);
	ra_info->win = win = __swapin_nr_pages(pfn, fpfn, hits,
					       max_win, prev_win);
	atomic_long_set(&vma->swap_readahead_info,
			SWAP_RA_VAL(faddr, win, 0));
	if (win == 1)
		return;

	if (fpfn == pfn + 1) {
		lpfn = fpfn;
		rpfn = fpfn + win;
	} else if (pfn == fpfn + 1) {
		lpfn = fpfn - win + 1;
		rpfn = fpfn + 1;
	} else {
		unsigned int left = (win - 1) / 2;

		lpfn = fpfn - left;
		rpfn = fpfn + win - left;
	}
	start = max3(lpfn, PFN_DOWN(vma->vm_start),
		     PFN_DOWN(faddr & PMD_MASK));
	end = min3(rpfn, PFN_DOWN(vma->vm_end),
		   PFN_DOWN((faddr & PMD_MASK) + PMD_SIZE));

	ra_info->nr_pte = end - start;
	ra_info->offset = fpfn - start;
}

/**
 * swap_vma_readahead - swap in pages in hope we need them soon
   预读换入页面, swap mapping不存在的话,可能新申请页面然后读入
 * @fentry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read in a few pages whose
 * virtual addresses are around the fault address in the same vma.
 *
 * Caller must hold read mmap_lock if vmf->vma is not NULL.
 *
 */
static struct page *swap_vma_readahead(swp_entry_t fentry, gfp_t gfp_mask,
				       struct vm_fault *vmf)
{
	struct blk_plug plug;
	struct swap_iocb *splug = NULL;
	struct vm_area_struct *vma = vmf->vma;
	struct page *page;
	pte_t *pte = NULL, pentry;
	unsigned long addr;
	swp_entry_t entry;
	unsigned int i;
	bool page_allocated;
	struct vma_swap_readahead ra_info = {
		.win = 1,
	};

	// 构造预读信息
	swap_ra_info(vmf, &ra_info);
	if (ra_info.win == 1)
		goto skip;

	addr = vmf->address - (ra_info.offset * PAGE_SIZE);

	blk_start_plug(&plug);
	for (i = 0; i < ra_info.nr_pte; i++, addr += PAGE_SIZE) {
		if (!pte++) {
			pte = pte_offset_map(vmf->pmd, addr);
			if (!pte)
				break;
		}
		pentry = ptep_get_lockless(pte);
		if (!is_swap_pte(pentry))
			continue;
		entry = pte_to_swp_entry(pentry);
		if (unlikely(non_swap_entry(entry)))
			continue;
		pte_unmap(pte);
		pte = NULL;
		// 开始读写
		page = __read_swap_cache_async(entry, gfp_mask, vma,
					       addr, &page_allocated);
		if (!page)
			continue;
		if (page_allocated) {// 刚刚是新申请的swap mapping页面, 这里要读入
			swap_readpage(page, false, &splug);
			if (i != ra_info.offset) {
				SetPageReadahead(page);
				count_vm_event(SWAP_RA);
			}
		}
		put_page(page);
	}
	if (pte)
		pte_unmap(pte);
	blk_finish_plug(&plug);
	swap_read_unplug(splug);
	lru_add_drain();
skip:
	/* The page was likely read above, so no need for plugging here */
	return read_swap_cache_async(fentry, gfp_mask, vma, vmf->address,
				     NULL);
}

/**
 * swapin_readahead - swap in pages in hope we need them soon
   预读swap, 换入页面的预读
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * It's a main entry function for swap readahead. By the configuration,
 * it will read ahead blocks by cluster-based(ie, physical disk based)
 * or vma-based(ie, virtual address based on faulty address) readahead.
 */
struct page *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
				struct vm_fault *vmf)
{
	return swap_use_vma_readahead() ?
			swap_vma_readahead(entry, gfp_mask, vmf) :
			swap_cluster_readahead(entry, gfp_mask, vmf);
}

#ifdef CONFIG_SYSFS
static ssize_t vma_ra_enabled_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  enable_vma_readahead ? "true" : "false");
}
static ssize_t vma_ra_enabled_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	ssize_t ret;

	ret = kstrtobool(buf, &enable_vma_readahead);
	if (ret)
		return ret;

	return count;
}
static struct kobj_attribute vma_ra_enabled_attr = __ATTR_RW(vma_ra_enabled);

static struct attribute *swap_attrs[] = {
	&vma_ra_enabled_attr.attr,
	NULL,
};

static const struct attribute_group swap_attr_group = {
	.attrs = swap_attrs,
};

static int __init swap_init_sysfs(void)
{
	int err;
	struct kobject *swap_kobj;

	swap_kobj = kobject_create_and_add("swap", mm_kobj);
	if (!swap_kobj) {
		pr_err("failed to create swap kobject\n");
		return -ENOMEM;
	}
	err = sysfs_create_group(swap_kobj, &swap_attr_group);
	if (err) {
		pr_err("failed to register swap group\n");
		goto delete_obj;
	}
	return 0;

delete_obj:
	kobject_put(swap_kobj);
	return err;
}
subsys_initcall(swap_init_sysfs);
#endif

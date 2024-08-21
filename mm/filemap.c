// SPDX-License-Identifier: GPL-2.0-only
/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */

 /* 2024年07月18日12:43:20
 好像是主要操作mapping。
 
  */
#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/error-injection.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/cleancache.h>
#include <linux/shmem_fs.h>
#include <linux/rmap.h>
#include <linux/delayacct.h>
#include <linux/psi.h>
#include <linux/ramfs.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/filemap.h>

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for try_to_free_buffers */

#include <asm/mman.h>

/*
2024年07月18日12:42:16
todo
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_rwsem		(truncate_pagecache)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_lock		(exclusive_swap_page, others)
 *        ->i_pages lock
 *
 *  ->i_mutex
 *    ->i_mmap_rwsem		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_rwsem
 *      ->page_table_lock or pte_lock	(various, mainly in memory.c)
 *        ->i_pages lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->i_mutex			(generic_perform_write)
 *    ->mmap_sem		(fault_in_pages_readable->do_page_fault)
 *
 *  bdi->wb.list_lock
 *    sb_lock			(fs/fs-writeback.c)
 *    ->i_pages lock		(__sync_single_inode)
 *
 *  ->i_mmap_rwsem
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock	(anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock		(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->i_pages lock		(try_to_unmap_one)
 *    ->pgdat->lru_lock		(follow_page->mark_page_accessed)
 *    ->pgdat->lru_lock		(check_pte_range->isolate_lru_page)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->i_pages lock		(page_remove_rmap->set_page_dirty)
 *    bdi.wb->list_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode->i_lock		(page_remove_rmap->set_page_dirty)
 *    ->memcg->move_lock	(page_remove_rmap->lock_page_memcg)
 *    bdi.wb->list_lock		(zap_pte_range->set_page_dirty)
 *    ->inode->i_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 * ->i_mmap_rwsem
 *   ->tasklist_lock            (memory_failure, collect_procs_ao)
 2024年7月14日18:09:49
2024年07月29日11:19:34
shaow存储了page的一些信息，现在保存在page在xas原本的位置
 */

static void page_cache_delete(struct address_space *mapping,
				   struct page *page, void *shadow)
{
	XA_STATE(xas, &mapping->i_pages, page->index);
	unsigned int nr = 1;

	mapping_set_update(&xas, mapping);

	/* hugetlb pages are represented by a single entry in the xarray */
	if (!PageHuge(page)) {
		xas_set_order(&xas, page->index, compound_order(page));
		nr = compound_nr(page);
	}

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(nr != 1 && shadow, page);

	xas_store(&xas, shadow);
	xas_init_marks(&xas);
	/* step1 */
	page->mapping = NULL;
	/* Leave page->index set: truncation lookup relies upon it */

	if (shadow) {
		mapping->nrexceptional += nr;
		/*
		 * Make sure the nrexceptional update is committed before
		 * the nrpages update so that final truncate racing
		 * with reclaim does not see both counters 0 at the
		 * same time and miss a shadow entry.
		 */
		smp_wmb();
	}
	/* step2 */
	mapping->nrpages -= nr;
}
/* 2024年7月14日18:01:38 */
static void unaccount_page_cache_page(struct address_space *mapping,
				      struct page *page)
{
	int nr;

	/*
	 * if we're uptodate, flush out into the cleancache, otherwise
	 * invalidate any existing cleancache entries.  We can't leave
	 * stale data around in the cleancache once our page is gone
	 */
	if (PageUptodate(page) && PageMappedToDisk(page))
	/* 干净缓存页的路径 */
		cleancache_put_page(page);
	else
		cleancache_invalidate_page(mapping, page);

	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(page_mapped(page), page);

	if (!IS_ENABLED(CONFIG_DEBUG_VM) && unlikely(page_mapped(page))) {/* 文件页不像匿名页被映射，但也有 */
		/* 2024年7月14日18:04:37
		怎么可能是被mapped
		2024年08月21日15:15:22
		可能………… */
		int mapcount;

		pr_alert("BUG: Bad page cache in process %s  pfn:%05lx\n",
			 current->comm, page_to_pfn(page));
		dump_page(page, "still mapped when deleted");
		dump_stack();
		add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);

		mapcount = page_mapcount(page);
		if (mapping_exiting(mapping) &&
		    page_count(page) >= mapcount + 2) {
			/*
			 * All vmas have already been torn down, so it's
			 * a good bet that actually the page is unmapped,
			 * and we'd prefer not to leak it: if we're wrong,
			 * some other bad page check should catch it later.
			 */
			page_mapcount_reset(page);
			page_ref_sub(page, mapcount);
		}
	}

/* 下面是更新统计信息 */
	/* hugetlb pages do not participate in page cache accounting. */
	if (PageHuge(page))
		return;

	nr = hpage_nr_pages(page);
	/* 更新node的统计信息 */
	__mod_node_page_state(page_pgdat(page), NR_FILE_PAGES, -nr);

	if (PageSwapBacked(page)) {
		__mod_node_page_state(page_pgdat(page), NR_SHMEM, -nr);
		if (PageTransHuge(page))
			__dec_node_page_state(page, NR_SHMEM_THPS);
	} else if (PageTransHuge(page)) {
		__dec_node_page_state(page, NR_FILE_THPS);
		filemap_nr_thps_dec(mapping);
	}

	/*
	 * At this point page must be either written or cleaned by
	 * truncate.  Dirty page here signals a bug and loss of
	 * unwritten data.
	 *
	 * This fixes dirty accounting after removing the page entirely
	 * but leaves PageDirty set: it has no effect for truncated
	 * page and anyway will be cleared before returning page into
	 * buddy allocator.
	 */
	if (WARN_ON_ONCE(PageDirty(page)))
		account_page_cleaned(page, mapping, inode_to_wb(mapping->host));
}

/*
2024年7月14日18:01:18
 * Delete a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold the i_pages lock.
 */
void __delete_from_page_cache(struct page *page, void *shadow)
{
	struct address_space *mapping = page->mapping;

	trace_mm_filemap_delete_from_page_cache(page);
	/* 统计相关 */
	unaccount_page_cache_page(mapping, page);
	/* 置空page。mapping。 */
	page_cache_delete(mapping, page, shadow);
}
/* 2024年07月18日12:39:52
pagecache换页面的free操作
调用ops
减少引用，put
 */
static void page_cache_free_page(struct address_space *mapping,
				struct page *page)
{
	void (*freepage)(struct page *);

	freepage = mapping->a_ops->freepage;
	if (freepage)
		freepage(page);

	if (PageTransHuge(page) && !PageHuge(page)) {
		page_ref_sub(page, HPAGE_PMD_NR);
		VM_BUG_ON_PAGE(page_count(page) <= 0, page);
	} else {
		put_page(page);
	}
}

/**
2024年07月18日12:41:23
从页缓存移除页面
 * delete_from_page_cache - delete page from page cache
 * @page: the page which the kernel is trying to remove from page cache
 *
 * This must be called only on pages that have been verified to be in the page
 * cache and locked.  It will never put the page into the free list, the caller
 * has a reference on the page.
 */
void delete_from_page_cache(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	unsigned long flags;

	BUG_ON(!PageLocked(page));

	xa_lock_irqsave(&mapping->i_pages, flags);
	__delete_from_page_cache(page, NULL);
	xa_unlock_irqrestore(&mapping->i_pages, flags);

	page_cache_free_page(mapping, page);
}
EXPORT_SYMBOL(delete_from_page_cache);

/*
2024年07月18日12:37:41
从xas数组移除页面。
 * page_cache_delete_batch - delete several pages from page cache
 * @mapping: the mapping to which pages belong
 * @pvec: pagevec with pages to delete
 *
 * The function walks over mapping->i_pages and removes pages passed in @pvec
 * from the mapping. The function expects @pvec to be sorted by page index
 * and is optimised for it to be dense.
 * It tolerates holes in @pvec (mapping entries at those indices are not
 * modified). The function expects only THP head pages to be present in the
 * @pvec.
 *
 * The function expects the i_pages lock to be held.
 */
static void page_cache_delete_batch(struct address_space *mapping,
			     struct pagevec *pvec)
{
	XA_STATE(xas, &mapping->i_pages, pvec->pages[0]->index);
	int total_pages = 0;
	int i = 0;
	struct page *page;

	mapping_set_update(&xas, mapping);
	xas_for_each(&xas, page, ULONG_MAX) {
		/* 遍历xas */

		if (i >= pagevec_count(pvec))
		/* 删除够了 */
			break;

		/* A swap/dax/shadow entry got inserted? Skip it. */
		if (xa_is_value(page))
			continue;
		/*
		 * A page got inserted in our range? Skip it. We have our
		 * pages locked so they are protected from being removed.
		 * If we see a page whose index is higher than ours, it
		 * means our page has been removed, which shouldn't be
		 * possible because we're holding the PageLock.
		 2024年07月18日12:39:14 todo
		 */
		if (page != pvec->pages[i]) {
			VM_BUG_ON_PAGE(page->index > pvec->pages[i]->index,
					page);
			continue;
		}

		WARN_ON_ONCE(!PageLocked(page));

		if (page->index == xas.xa_index)
			page->mapping = NULL;
		/* Leave page->index set: truncation lookup relies on it */

		/*
		 * Move to the next page in the vector if this is a regular
		 * page or the index is of the last sub-page of this compound
		 * page.
		 */
		if (page->index + compound_nr(page) - 1 == xas.xa_index)
			i++;
		xas_store(&xas, NULL);
		total_pages++;
	}

	mapping->nrpages -= total_pages;
}
/* 2024年07月18日12:36:26
从pagacache的mapping移除页面。
 */
void delete_from_page_cache_batch(struct address_space *mapping,
				  struct pagevec *pvec)
{
	int i;
	unsigned long flags;

	if (!pagevec_count(pvec))
		return;

	xa_lock_irqsave(&mapping->i_pages, flags);
	for (i = 0; i < pagevec_count(pvec); i++) {
		trace_mm_filemap_delete_from_page_cache(pvec->pages[i]);
		/* 先account相关的操作 */
		unaccount_page_cache_page(mapping, pvec->pages[i]);
	}
	/* 执行删除 */
	page_cache_delete_batch(mapping, pvec);
	xa_unlock_irqrestore(&mapping->i_pages, flags);
	/* 这里是free什么
	好像是调用ops，进行put之类的
	*/
	for (i = 0; i < pagevec_count(pvec); i++)
		page_cache_free_page(mapping, pvec->pages[i]);
}
/* 2024年7月18日00:10:25
探测flags的一些标志位
 */
int filemap_check_errors(struct address_space *mapping)
{
	int ret = 0;
	/* Check for outstanding write errors */
	if (test_bit(AS_ENOSPC, &mapping->flags) &&
	    test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_bit(AS_EIO, &mapping->flags) &&
	    test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;
	return ret;
}
EXPORT_SYMBOL(filemap_check_errors);
/* 2024年07月18日12:36:05
 */
static int filemap_check_and_keep_errors(struct address_space *mapping)
{
	/* Check for outstanding write errors */
	if (test_bit(AS_EIO, &mapping->flags))
		return -EIO;
	if (test_bit(AS_ENOSPC, &mapping->flags))
		return -ENOSPC;
	return 0;
}

/**
2024年7月17日22:53:02
写回的函数？
2024年7月18日00:07:29写回一段范围内的数据
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:	address space structure to write
 * @start:	offset in bytes where the range starts
 * @end:	offset in bytes where the range ends (inclusive)
 * @sync_mode:	enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = LONG_MAX,
		.range_start = start,
		.range_end = end,
	};
	/* 如果设备不需要回写，没有响应标志位 */
	if (!mapping_cap_writeback_dirty(mapping) ||
	    !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		return 0;
	/* 给wbc添加wb也就是添加file，也就是这个mapp的host */
	wbc_attach_fdatawrite_inode(&wbc, mapping->host);
	/* 2024年7月17日23:25:11当场回写吗 */
	ret = do_writepages(mapping, &wbc);
	/* 写回完成，分离wbc的啥 */
	wbc_detach_inode(&wbc);

	return ret;
}
/* 2024年07月18日12:33:12 */
static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	/* 默认是全写 */
	return __filemap_fdatawrite_range(mapping, 0, LLONG_MAX, sync_mode);
}
/* 2024年07月18日12:32:56 */
int filemap_fdatawrite(struct address_space *mapping)
{
	/* 默认是SYNCALL */
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);
/* 2024年07月18日12:35:52 */
int filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite_range);

/**
2024年07月18日12:35:25
flush与wb区别？
 * filemap_flush - mostly a non-blocking flush
 * @mapping:	target address_space
 *
 * This is a mostly non-blocking flush.  Not suitable for data-integrity
 * purposes - I/O may not be started against all dirty pages.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

/**
2024年7月17日22:48:03
在范围内至少要有一个页面
 * filemap_range_has_page - check if a page exists in range.
 * @mapping:           address space within which to check
 * @start_byte:        offset in bytes where the range starts
 * @end_byte:          offset in bytes where the range ends (inclusive)
 *
 * Find at least one page in the range supplied, usually used to check if
 * direct writing in this range will trigger a writeback.
 *
 * Return: %true if at least one page exists in the specified range,
 * %false otherwise.
 */
bool filemap_range_has_page(struct address_space *mapping,
			   loff_t start_byte, loff_t end_byte)
{
	struct page *page;
	XA_STATE(xas, &mapping->i_pages, start_byte >> PAGE_SHIFT);
	pgoff_t max = end_byte >> PAGE_SHIFT;

	if (end_byte < start_byte)
		return false;

	rcu_read_lock();
	/* 读取pages都要rcu吗 */
	for (;;) {
		page = xas_find(&xas, max);
		if (xas_retry(&xas, page))
			continue;
		/* Shadow entries don't count */
		if (xa_is_value(page))
			continue;
		/*
		 * We don't need to try to pin this page; we're about to
		 * release the RCU lock anyway.  It is enough to know that
		 * there was a page here recently.
		 */
		break;
	}
	rcu_read_unlock();

	return page != NULL;
}
EXPORT_SYMBOL(filemap_range_has_page);
/* 2024年7月18日00:09:07
如何遍历？
如何等待？
 */
static void __filemap_fdatawait_range(struct address_space *mapping,
				     loff_t start_byte, loff_t end_byte)
{
	pgoff_t index = start_byte >> PAGE_SHIFT;
	pgoff_t end = end_byte >> PAGE_SHIFT;
	struct pagevec pvec;
	int nr_pages;

	if (end_byte < start_byte)
		return;

	pagevec_init(&pvec);
	while (index <= end) {
		unsigned i;
		/* 先把处于写回状态的page放到pvec，遍历完成 */
		nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index,
				end, PAGECACHE_TAG_WRITEBACK);
		if (!nr_pages)
			break;

		for (i = 0; i < nr_pages; i++) {
			/* 逐个等待 */
			struct page *page = pvec.pages[i];

			wait_on_page_writeback(page);
			ClearPageError(page);
		}
		/* 释放pvec */
		pagevec_release(&pvec);
		cond_resched();
	}
}

/**
2024年7月18日00:08:14
等待范围内写回完成
 * filemap_fdatawait_range - wait for writeback to complete
 * @mapping:		address space structure to wait for
 * @start_byte:		offset in bytes where the range starts
 * @end_byte:		offset in bytes where the range ends (inclusive)
 *遍历范围内页面，等待他们全部写回完成。
 * Walk the list of under-writeback pages of the given address space
 * in the given range and wait for all of them.  Check error status of
 * the address space and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 *
 * Return: error status of the address space.
 */
int filemap_fdatawait_range(struct address_space *mapping, loff_t start_byte,
			    loff_t end_byte)
{
	__filemap_fdatawait_range(mapping, start_byte, end_byte);
	return filemap_check_errors(mapping);
}
EXPORT_SYMBOL(filemap_fdatawait_range);

/**
2024年07月18日12:35:01
 * filemap_fdatawait_range_keep_errors - wait for writeback to complete
 * @mapping:		address space structure to wait for
 * @start_byte:		offset in bytes where the range starts
 * @end_byte:		offset in bytes where the range ends (inclusive)
 *
 * Walk the list of under-writeback pages of the given address space in the
 * given range and wait for all of them.  Unlike filemap_fdatawait_range(),
 * this function does not clear error status of the address space.
 *
 * Use this function if callers don't handle errors themselves.  Expected
 * call sites are system-wide / filesystem-wide data flushers: e.g. sync(2),
 * fsfreeze(8)
 */
int filemap_fdatawait_range_keep_errors(struct address_space *mapping,
		loff_t start_byte, loff_t end_byte)
{
	__filemap_fdatawait_range(mapping, start_byte, end_byte);
	return filemap_check_and_keep_errors(mapping);
}
EXPORT_SYMBOL(filemap_fdatawait_range_keep_errors);

/**
2024年07月18日12:34:22
wait file。。
 * file_fdatawait_range - wait for writeback to complete
 * @file:		file pointing to address space structure to wait for
 * @start_byte:		offset in bytes where the range starts
 * @end_byte:		offset in bytes where the range ends (inclusive)
 *
 * Walk the list of under-writeback pages of the address space that file
 * refers to, in the given range and wait for all of them.  Check error
 * status of the address space vs. the file->f_wb_err cursor and return it.
 *
 * Since the error status of the file is advanced by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 *
 * Return: error status of the address space vs. the file->f_wb_err cursor.
 */
int file_fdatawait_range(struct file *file, loff_t start_byte, loff_t end_byte)
{
	struct address_space *mapping = file->f_mapping;

	__filemap_fdatawait_range(mapping, start_byte, end_byte);

	return file_check_and_advance_wb_err(file);
}
EXPORT_SYMBOL(file_fdatawait_range);

/**
2024年07月18日12:34:12
 * filemap_fdatawait_keep_errors - wait for writeback without clearing errors
 * @mapping: address space structure to wait for
 *
 * Walk the list of under-writeback pages of the given address space
 * and wait for all of them.  Unlike filemap_fdatawait(), this function
 * does not clear error status of the address space.
 *
 * Use this function if callers don't handle errors themselves.  Expected
 * call sites are system-wide / filesystem-wide data flushers: e.g. sync(2),
 * fsfreeze(8)
 *
 * Return: error status of the address space.
 */
int filemap_fdatawait_keep_errors(struct address_space *mapping)
{
	__filemap_fdatawait_range(mapping, 0, LLONG_MAX);
	return filemap_check_and_keep_errors(mapping);
}
EXPORT_SYMBOL(filemap_fdatawait_keep_errors);

/* 
2024年7月17日22:50:52
是否需要写回或者已经在写回
Returns true if writeback might be needed or already in progress. */
static bool mapping_needs_writeback(struct address_space *mapping)
{

	if (dax_mapping(mapping))
	/* 直接io */
		return mapping->nrexceptional;
	/* 2024年7月17日22:52:39为什么nr pages可以拿来判断写回 */
	return mapping->nrpages;
}

/* 2024年07月18日12:19:56
 */
int filemap_write_and_wait(struct address_space *mapping)
{
	int err = 0;
/* 是说filemap-write就是写mapping吗，然后就是wb吗 */
	if (mapping_needs_writeback(mapping)) {
		err = filemap_fdatawrite(mapping);
		/*
		 * Even if the above returned error, the pages may be
		 * written partially (e.g. -ENOSPC), so we wait for it.
		 * But the -EIO is special case, it may indicate the worst
		 * thing (e.g. bug) happened, so we avoid waiting for it.
		 */
		if (err != -EIO) {
			int err2 = filemap_fdatawait(mapping);
			if (!err)
				err = err2;
		} else {
			/* Clear any previously stored errors */
			filemap_check_errors(mapping);
		}
	} else {
		/* 暂时不需要回写的话？就check一下吗。 */
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait);

/**
2024年7月17日22:50:14
 * filemap_write_and_wait_range - write out & wait on a file range
 * @mapping:	the address_space for the pages
 * @lstart:	offset in bytes where the range starts
 * @lend:	offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * Return: error status of the address space.
 */
int filemap_write_and_wait_range(struct address_space *mapping,
				 loff_t lstart, loff_t lend)
{
	int err = 0;

	if (mapping_needs_writeback(mapping)) {
		/* 写回一段范围内的数据 */
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		/* See comment of filemap_write_and_wait() */
		if (err != -EIO) {
			/* 等待写回完成 */
			int err2 = filemap_fdatawait_range(mapping,
						lstart, lend);
			if (!err)
				err = err2;
		} else {
			/* Clear any previously stored errors */
			filemap_check_errors(mapping);
		}
	} else {
		err = filemap_check_errors(mapping);
	}

	return err;

}


EXPORT_SYMBOL(filemap_write_and_wait_range);
/* 2024年07月18日10:46:37
设置mapping关联的wb err
 */
void __filemap_set_wb_err(struct address_space *mapping, int err)
{
	errseq_t eseq = errseq_set(&mapping->wb_err, err);

	trace_filemap_set_wb_err(mapping, eseq);
}
EXPORT_SYMBOL(__filemap_set_wb_err);

/**
2024年07月18日12:19:01
 * file_check_and_advance_wb_err - report wb error (if any) that was previously
 * 				   and advance wb_err to current one
 * @file: struct file on which the error is being reported
 *
 * When userland calls fsync (or something like nfsd does the equivalent), we
 * want to report any writeback errors that occurred since the last fsync (or
 * since the file was opened if there haven't been any).
 *
 * Grab the wb_err from the mapping. If it matches what we have in the file,
 * then just quickly return 0. The file is all caught up.
 *
 * If it doesn't match, then take the mapping value, set the "seen" flag in
 * it and try to swap it into place. If it works, or another task beat us
 * to it with the new value, then update the f_wb_err and return the error
 * portion. The error at this point must be reported via proper channels
 * (a'la fsync, or NFS COMMIT operation, etc.).
 *
 * While we handle mapping->wb_err with atomic operations, the f_wb_err
 * value is protected by the f_lock since we must ensure that it reflects
 * the latest value swapped in for this file descriptor.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int file_check_and_advance_wb_err(struct file *file)
{
	int err = 0;
	errseq_t old = READ_ONCE(file->f_wb_err);
	struct address_space *mapping = file->f_mapping;

	/* Locklessly handle the common case where nothing has changed */
	if (errseq_check(&mapping->wb_err, old)) {
		/* Something changed, must use slow path */
		spin_lock(&file->f_lock);
		old = file->f_wb_err;
		err = errseq_check_and_advance(&mapping->wb_err,
						&file->f_wb_err);
		trace_file_check_and_advance_wb_err(file, old);
		spin_unlock(&file->f_lock);
	}

	/*
	 * We're mostly using this function as a drop in replacement for
	 * filemap_check_errors. Clear AS_EIO/AS_ENOSPC to emulate the effect
	 * that the legacy code would have had on these flags.
	 */
	clear_bit(AS_EIO, &mapping->flags);
	clear_bit(AS_ENOSPC, &mapping->flags);
	return err;
}
EXPORT_SYMBOL(file_check_and_advance_wb_err);

/**
2024年07月18日12:17:25
 * file_write_and_wait_range - write out & wait on a file range
 * @file:	file pointing to address_space with pages
 * @lstart:	offset in bytes where the range starts
 * @lend:	offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * After writing out and waiting on the data, we check and advance the
 * f_wb_err cursor to the latest value, and return any errors detected there.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int file_write_and_wait_range(struct file *file, loff_t lstart, loff_t lend)
{
	int err = 0, err2;
	struct address_space *mapping = file->f_mapping;

	if (mapping_needs_writeback(mapping)) {
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		/* See comment of filemap_write_and_wait() */
		if (err != -EIO)
			__filemap_fdatawait_range(mapping, lstart, lend);
	}

	err2 = file_check_and_advance_wb_err(file);
	if (!err)
		err = err2;
	return err;
}
EXPORT_SYMBOL(file_write_and_wait_range);

/**
2024年07月18日12:14:32
有必要替换吗
 * replace_page_cache_page - replace a pagecache page with a new one
 * @old:	page to be replaced
 * @new:	page to replace with
 * @gfp_mask:	allocation mode
 *
 * This function replaces a page in the pagecache with a new one.  On
 * success it acquires the pagecache reference for the new page and
 * drops it for the old page.  Both the old and new pages must be
 * locked.  This function does not add the new page to the LRU, the
 * caller must do that.
 *
 * The remove + add is atomic.  This function cannot fail.
 *
 * Return: %0
 */
int replace_page_cache_page(struct page *old, struct page *new, gfp_t gfp_mask)
{
	/* 获取old的mapping和offset */
	struct address_space *mapping = old->mapping;
	void (*freepage)(struct page *) = mapping->a_ops->freepage;
	pgoff_t offset = old->index;
	/*  */
	XA_STATE(xas, &mapping->i_pages, offset);
	unsigned long flags;

	VM_BUG_ON_PAGE(!PageLocked(old), old);
	VM_BUG_ON_PAGE(!PageLocked(new), new);
	VM_BUG_ON_PAGE(new->mapping, new);

	get_page(new);
	/* 赋值指向old的index和mapping */
	new->mapping = mapping;
	new->index = offset;


	xas_lock_irqsave(&xas, flags);
	/* 页面存入xas */
	xas_store(&xas, new);
	old->mapping = NULL;
	/* hugetlb pages do not participate in page cache accounting. */
	if (!PageHuge(old))
		__dec_node_page_state(new, NR_FILE_PAGES);
	if (!PageHuge(new))
		__inc_node_page_state(new, NR_FILE_PAGES);

	if (PageSwapBacked(old))
		__dec_node_page_state(new, NR_SHMEM);
	if (PageSwapBacked(new))
		__inc_node_page_state(new, NR_SHMEM);

	xas_unlock_irqrestore(&xas, flags);


	/* memcg相关 */
	mem_cgroup_migrate(old, new);

	if (freepage)
		freepage(old);

	put_page(old);

	return 0;
}
EXPORT_SYMBOL_GPL(replace_page_cache_page);
/*
获取页面加入到mapping，相当于使用了新的文件页。
2024年06月20日16:11:29
涉及到memcg。
在页缓存分配页面，涉及到内存cg记账。
*/

static int __add_to_page_cache_locked(struct page *page,
				      struct address_space *mapping,
				      pgoff_t offset, gfp_t gfp_mask,
				      void **shadowp)
{

	XA_STATE(xas, &mapping->i_pages, offset);
	/*
	// Expands to
struct xa_state xas = { .xa = &mapping->i_pages,
            .xa_index = offset,
            .xa_shift = 0,
            .xa_sibs = 0,
            .xa_offset = 0,
            .xa_pad = 0,
            .xa_node = ((struct xa_node *)3UL),
            .xa_alloc = ((void *)0),
            .xa_update = ((void *)0) }
	*/
	int huge = PageHuge(page);
	struct mem_cgroup *memcg;
	int error;
	void *old;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageSwapBacked(page), page);
	mapping_set_update(&xas, mapping);

	if (!huge) {/* mem_cgroup_try_charge尝试内存记账，
	mem_cgroup_commit-charge提交内存记账 */
		error = mem_cgroup_try_charge(page, current->mm,
					      gfp_mask, &memcg, false);
		if (error)
			return error;
	}

	/* 加入mapping时get一次 */
	get_page(page);
	/* 设置page的属性 */
	page->mapping = mapping;
	page->index = offset;

	/* 再改变mapping（加入） */
	do {
		/* 进行mapping里面xas相关的存储 */
		xas_lock_irq(&xas);
		old = xas_load(&xas);
		if (old && !xa_is_value(old))
			xas_set_err(&xas, -EEXIST);
		/* xas是个数组，存储读写api */
		xas_store(&xas, page);
		if (xas_error(&xas))
			goto unlock;

		if (xa_is_value(old)) {
			mapping->nrexceptional--;
			if (shadowp)
				*shadowp = old;
		}

		/* 添加成功 */
		mapping->nrpages++;

		/* hugetlb pages do not participate in page cache accounting */
		if (!huge)
		/* 更新内存节点的东西 ，也就是页缓存页面数量*/
			__inc_node_page_state(page, NR_FILE_PAGES);
unlock:
		xas_unlock_irq(&xas);
	} while (xas_nomem(&xas, gfp_mask & GFP_RECLAIM_MASK));

	if (xas_error(&xas))
		goto error;

	if (!huge)
	/*  */
		mem_cgroup_commit_charge(page, memcg, false, false);


	trace_mm_filemap_add_to_page_cache(page);
	return 0;
error:
/* 出错的清理 */
	page->mapping = NULL;
	/* Leave page->index set: truncation relies upon it */
	if (!huge)
		mem_cgroup_cancel_charge(page, memcg, false);
	/* 减少引用计数 */
	put_page(page);
	return xas_error(&xas);
}
ALLOW_ERROR_INJECTION(__add_to_page_cache_locked, ERRNO);

/**
 * add_to_page_cache_locked - add a locked page to the pagecache
 * @page:	page to add
 * @mapping:	the page's address_space
 * @offset:	page index
 * @gfp_mask:	page allocation mode
 *
 * This function is used to add a page to the pagecache. It must be locked.
 * This function does not add the page to the LRU.  The caller must do that.
 *
 * Return: %0 on success, negative error code otherwise.
 2024年06月20日16:12:41

 */
int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	return __add_to_page_cache_locked(page, mapping, offset,
					  gfp_mask, NULL);
}
EXPORT_SYMBOL(add_to_page_cache_locked);
/* 2024年6月24日22:44:06
2024年07月18日11:43:46
pagecache与lru怎么结合。
2024年07月18日11:53:16
就是获得页面之后，先加入mapping，再加入lru。
 */
int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	void *shadow = NULL;
	int ret;

	__SetPageLocked(page);
	/* 这里加到file的地址空间里面的xas */
	ret = __add_to_page_cache_locked(page, mapping, offset,
					 gfp_mask, &shadow);

	if (unlikely(ret))
		__ClearPageLocked(page);
	else {
		/* 刚才是先加入mapping，没出错的话现在加入lru。 */
		/* 
		2024年6月30日11:47:19
		加入mapping里面成功之后到这里，
		加入lru？ */
		/*
		 * The page might have been evicted from cache only
		 * recently, in which case it should be activated like
		 * any other repeatedly accessed page.
		 * The exception is pages getting rewritten; evicting other
		 * data from the working set, only to cache data that will
		 * get overwritten with something else, is a waste of memory.
		 */
		WARN_ON_ONCE(PageActive(page));
		if (!(gfp_mask & __GFP_WRITE) && shadow)
			workingset_refault(page, shadow);

		/* 然后这里加入lru，但是参数只有page一个东西，那怎么找到哪个lru呢
		2024年07月18日11:52:47 哦哦忘了，page有lru相关属性 */
		lru_cache_add(page);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(add_to_page_cache_lru);

#ifdef CONFIG_NUMA
/* 2024年6月29日21:49:54
pagecache没有页面的时候申请
2024年7月16日00:09:39
 */
struct page *__page_cache_alloc(gfp_t gfp)
{
	int n;
	struct page *page;

	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = __alloc_pages_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	return alloc_pages(gfp, 0);
}
EXPORT_SYMBOL(__page_cache_alloc);
#endif

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
#define PAGE_WAIT_TABLE_BITS 8
#define PAGE_WAIT_TABLE_SIZE (1 << PAGE_WAIT_TABLE_BITS)
static wait_queue_head_t page_wait_table[PAGE_WAIT_TABLE_SIZE] __cacheline_aligned;
/* 2024年6月25日23:08:57
page的等待队列
2024年07月18日10:43:15
比如想获得锁的时候来等待
 */
static wait_queue_head_t *page_waitqueue(struct page *page)
{
	return &page_wait_table[hash_ptr(page, PAGE_WAIT_TABLE_BITS)];
}
/* 2024年07月18日11:21:07 */
void __init pagecache_init(void)
{
	int i;

	for (i = 0; i < PAGE_WAIT_TABLE_SIZE; i++)
		init_waitqueue_head(&page_wait_table[i]);
	/* 初始化写回线程 */
	page_writeback_init();
}

/* 
2024年07月18日11:08:44
This has the same layout as wait_bit_key - see fs/cachefiles/rdwr.c */
struct wait_page_key {
	/* 要等待的page？ */
	struct page *page
	/* 等待的bit位？ */;
	int bit_nr;
	/*  */
	int page_match;
};
/* 2024年07月18日11:20:02 */
struct wait_page_queue {
	struct page *page;
	int bit_nr;
	wait_queue_entry_t wait;
};
/* 2024年07月18日11:18:15
todo
什么时候调用？
 */
static int wake_page_function(wait_queue_entry_t *wait, unsigned mode, int sync, void *arg)
{
	struct wait_page_key *key = arg;
	struct wait_page_queue *wait_page
		= container_of(wait, struct wait_page_queue, wait);

	if (wait_page->page != key->page)
	       return 0;

	key->page_match = 1;

	if (wait_page->bit_nr != key->bit_nr)
		return 0;

	/*
	 * Stop walking if it's locked.
	 * Is this safe if put_and_wait_on_page_locked() is in use?
	 * Yes: the waker must hold a reference to this page, and if PG_locked
	 * has now already been set by another task, that task must also hold
	 * a reference to the *same usage* of this page; so there is no need
	 * to walk on to wake even the put_and_wait_on_page_locked() callers.
	 */
	if (test_bit(key->bit_nr, &key->page->flags))
		return -1;

	return autoremove_wake_function(wait, mode, sync, key);
}
/* 2024年07月18日11:07:45
 */
static void wake_up_page_bit(struct page *page, int bit_nr)
{
	wait_queue_head_t *q = page_waitqueue(page);
	struct wait_page_key key;
	unsigned long flags;
	wait_queue_entry_t bookmark;
	/* 设置查找的key？ */
	key.page = page;
	key.bit_nr = bit_nr;
	key.page_match = 0;

	/* 好像只是默认的初始化 */
	bookmark.flags = 0;
	bookmark.private = NULL;
	bookmark.func = NULL;
	INIT_LIST_HEAD(&bookmark.entry);

	spin_lock_irqsave(&q->lock, flags);
	/*  */
	__wake_up_locked_key_bookmark(q, TASK_NORMAL, &key, &bookmark);

	while (bookmark.flags & WQ_FLAG_BOOKMARK) {
		/*
		 * Take a breather from holding the lock,
		 * allow pages that finish wake up asynchronously
		 * to acquire the lock and remove themselves
		 * from wait queue
		 */
		spin_unlock_irqrestore(&q->lock, flags);
		cpu_relax();
		spin_lock_irqsave(&q->lock, flags);
		__wake_up_locked_key_bookmark(q, TASK_NORMAL, &key, &bookmark);
	}

	/*
	 * It is possible for other pages to have collided on the waitqueue
	 * hash, so in that case check for a page match. That prevents a long-
	 * term waiter
	 *
	 * It is still possible to miss a case here, when we woke page waiters
	 * and removed them from the waitqueue, but there are still other
	 * page waiters.
	 */
	if (!waitqueue_active(q) || !key.page_match) {
		ClearPageWaiters(page);
		/*
		 * It's possible to miss clearing Waiters here, when we woke
		 * our page waiters, but the hashed waitqueue has waiters for
		 * other pages on it.
		 *
		 * That's okay, it's a rare case. The next waker will clear it.
		 */
	}
	spin_unlock_irqrestore(&q->lock, flags);
}
/* 2024年07月18日11:06:23
唤醒某个bit的
 */
static void wake_up_page(struct page *page, int bit)
{
	if (!PageWaiters(page))
		return;

	wake_up_page_bit(page, bit);
}

/*
2024年07月18日11:03:36
 * A choice of three behaviors for wait_on_page_bit_common():
 */
enum behavior {
	EXCLUSIVE,	/* Hold ref to page and take the bit when woken, like
			 * __lock_page() waiting on then setting PG_locked.

			 */
	SHARED,		/* Hold ref to page and check the bit when woken, like
			 * wait_on_page_writeback() waiting on PG_writeback.
			 */
	DROP,		/* Drop ref to page before wait, no check when woken,
			 * like put_and_wait_on_page_locked() on PG_locked.
			 */
};
/* 2024年6月25日23:10:08
加入此page的等待队列q
todo，有点长
*/
static inline int wait_on_page_bit_common(wait_queue_head_t *q,
	struct page *page, int bit_nr, int state, enum behavior behavior)
{
	struct wait_page_queue wait_page;
	wait_queue_entry_t *wait = &wait_page.wait;
	bool bit_is_set;
	bool thrashing = false;
	bool delayacct = false;
	unsigned long pflags;
	int ret = 0;

	if (bit_nr == PG_locked &&
	    !PageUptodate(page) && PageWorkingset(page)) {
	
	/* 参数有PG_locked的情况 */
		if (!PageSwapBacked(page)) {
			delayacct_thrashing_start();
			delayacct = true;
		}
		
		psi_memstall_enter(&pflags);
		thrashing = true;
	}
	/* 如何wait */
	init_wait(wait);
	wait->flags = behavior == EXCLUSIVE ? WQ_FLAG_EXCLUSIVE : 0;
	wait->func = wake_page_function;
	wait_page.page = page;
	wait_page.bit_nr = bit_nr;

	for (;;) {
		spin_lock_irq(&q->lock);

		if (likely(list_empty(&wait->entry))) {
			__add_wait_queue_entry_tail(q, wait);
			SetPageWaiters(page);
		}

		set_current_state(state);

		spin_unlock_irq(&q->lock);

		bit_is_set = test_bit(bit_nr, &page->flags);
		if (behavior == DROP)
			put_page(page);

		if (likely(bit_is_set))
			io_schedule();

		if (behavior == EXCLUSIVE) {
			/* exclusive是set bit */
			if (!test_and_set_bit_lock(bit_nr, &page->flags))
				break;
		} else if (behavior == SHARED) {
			/* shared是test bit */
			if (!test_bit(bit_nr, &page->flags))
				break;
		}

		if (signal_pending_state(state, current)) {
			ret = -EINTR;
			break;
		}

		if (behavior == DROP) {
			/*
			 * We can no longer safely access page->flags:
			 * even if CONFIG_MEMORY_HOTREMOVE is not enabled,
			 * there is a risk of waiting forever on a page reused
			 * for something that keeps it locked indefinitely.
			 * But best check for -EINTR above before breaking.
			 */
			break;
		}
	}

	finish_wait(q, wait);

	if (thrashing) {
		if (delayacct)
			delayacct_thrashing_end();
		psi_memstall_leave(&pflags);
	}

	/*
	 * A signal could leave PageWaiters set. Clearing it here if
	 * !waitqueue_active would be possible (by open-coding finish_wait),
	 * but still fail to catch it in the case of wait hash collision. We
	 * already can fail to clear wait hash collision cases, so don't
	 * bother with signals either.
	 */

	return ret;
}
/* 2024年6月25日23:08:36
等待页面的某个bit位
 */
void wait_on_page_bit(struct page *page, int bit_nr)
{
	wait_queue_head_t *q = page_waitqueue(page);
	wait_on_page_bit_common(q, page, bit_nr, TASK_UNINTERRUPTIBLE, SHARED);
}
EXPORT_SYMBOL(wait_on_page_bit);
/* 2024年7月18日00:18:46 */
int wait_on_page_bit_killable(struct page *page, int bit_nr)
{
	wait_queue_head_t *q = page_waitqueue(page);
	return wait_on_page_bit_common(q, page, bit_nr, TASK_KILLABLE, SHARED);
}
EXPORT_SYMBOL(wait_on_page_bit_killable);

/**
2024年07月18日10:54:07
为什么put 可以和 等待锁一起出现。？和wait_on_page_bit_common有关。
 * put_and_wait_on_page_locked - Drop a reference and wait for it to be unlocked
 * @page: The page to wait for.
 *
 * The caller should hold a reference on @page.  They expect the page to
 * become unlocked relatively soon, but do not wish to hold up migration
 * (for example) by holding the reference while waiting for the page to
 * come unlocked.  After this function returns, the caller should not
 * dereference @page.
 */
void put_and_wait_on_page_locked(struct page *page)
{
	wait_queue_head_t *q;

	page = compound_head(page);
	q = page_waitqueue(page);
	wait_on_page_bit_common(q, page, PG_locked, TASK_UNINTERRUPTIBLE, DROP);
}

/**
2024年07月18日10:51:50
给page的wq添加等待的
 * add_page_wait_queue - Add an arbitrary waiter to a page's wait queue
 * @page: Page defining the wait queue of interest
 * @waiter: Waiter to add to the queue
 *
 * Add an arbitrary @waiter to the wait queue for the nominated @page.
 */
void add_page_wait_queue(struct page *page, wait_queue_entry_t *waiter)
{
	/* 获得wq */
	wait_queue_head_t *q = page_waitqueue(page);
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	/* 添加到wq */
	__add_wait_queue_entry_tail(q, waiter);
	/*  */
	SetPageWaiters(page);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL_GPL(add_page_wait_queue);

#ifndef clear_bit_unlock_is_negative_byte

/*
 * PG_waiters is the high bit in the same byte as PG_lock.
 *
 * On x86 (and on many other architectures), we can clear PG_lock and
 * test the sign bit at the same time. But if the architecture does
 * not support that special operation, we just do this all by hand
 * instead.
 *
 * The read of PG_waiters has to be after (or concurrently with) PG_locked
 * being cleared, but a memory barrier should be unneccssary since it is
 * in the same byte as PG_locked.
 */
static inline bool clear_bit_unlock_is_negative_byte(long nr, volatile void *mem)
{
	clear_bit_unlock(nr, mem);
	/* smp_mb__after_atomic(); */
	return test_bit(PG_waiters, mem);
}

#endif

/**
2024年07月18日10:51:09
unlock，唤醒wq。
 * unlock_page - unlock a locked page
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechanism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * Note that this depends on PG_waiters being the sign bit in the byte
 * that contains PG_locked - thus the BUILD_BUG_ON(). That allows us to
 * clear the PG_locked bit and test PG_waiters at the same time fairly
 * portably (architectures that do LL/SC can test any bit, while x86 can
 * test the sign bit).
 */
void unlock_page(struct page *page)
{
	BUILD_BUG_ON(PG_waiters != 7);
	page = compound_head(page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	/* 唤醒wq，让出锁 */
	if (clear_bit_unlock_is_negative_byte(PG_locked, &page->flags))
		wake_up_page_bit(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

/**
2024年07月18日10:49:54
wb有啥好end的？todo
 * end_page_writeback - end writeback against a page
 * @page: the page
 */
void end_page_writeback(struct page *page)
{
	/*
	 * TestClearPageReclaim could be used here but it is an atomic
	 * operation and overkill in this particular case. Failing to
	 * shuffle a page marked for immediate reclaim is too mild to
	 * justify taking an atomic operation penalty at the end of
	 * ever page writeback.
	 */
	if (PageReclaim(page)) {
		ClearPageReclaim(page);
		rotate_reclaimable_page(page);
	}

	if (!test_clear_page_writeback(page))
		BUG();

	smp_mb__after_atomic();
	/* 2024年07月18日10:50:28  wake up？ */
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

/*
2024年07月18日10:44:27
end io之后回调来更新flags？
 * After completing I/O on a page, call this routine to update the page
 * flags appropriately
 */
void page_endio(struct page *page, bool is_write, int err)
{
	if (!is_write) {
		/* 读的情况？ */
		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		/* 这个unlock对应哪个lock */
		unlock_page(page);
	} else {
		if (err) {
			struct address_space *mapping;

			SetPageError(page);
			mapping = page_mapping(page);
			if (mapping)
			/* 设置mapping的error */
				mapping_set_error(mapping, err);
		}
		end_page_writeback(page);
	}
}
EXPORT_SYMBOL_GPL(page_endio);

/**
2024年7月17日22:40:13
可能会睡眠
 * __lock_page - get a lock on the page, assuming we need to sleep to get it
 * @__page: the page to lock
 */
void __lock_page(struct page *__page)
{
	struct page *page = compound_head(__page);
	wait_queue_head_t *q = page_waitqueue(page);
	wait_on_page_bit_common(q, page, PG_locked, TASK_UNINTERRUPTIBLE,
				EXCLUSIVE);
}
EXPORT_SYMBOL(__lock_page);
/* 2024年07月18日10:42:50
在page的等待队列上等待获得
 */
int __lock_page_killable(struct page *__page)
{
	struct page *page = compound_head(__page);
	wait_queue_head_t *q = page_waitqueue(page);
	return wait_on_page_bit_common(q, page, PG_locked, TASK_KILLABLE,
					EXCLUSIVE);
}
EXPORT_SYMBOL_GPL(__lock_page_killable);

/*2024年07月18日10:33:54
todo
返回1，成功lock，持有mmap_sem；
返回0，没有lock。
 * Return values:
 * 1 - page is locked; mmap_sem is still held.
 * 0 - page is not locked.
 *     mmap_sem has been released (up_read()), unless flags had both
 *     FAULT_FLAG_ALLOW_RETRY and FAULT_FLAG_RETRY_NOWAIT set, in
 *     which case mmap_sem is still held.
 *
 * If neither ALLOW_RETRY nor KILLABLE are set, will always return 1
 * with the page locked and the mmap_sem unperturbed.
 */
int __lock_page_or_retry(struct page *page, struct mm_struct *mm,
			 unsigned int flags)
{
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		/*
		 * CAUTION! In this case, mmap_sem is not released
		 * even though return 0.
		 */
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return 0;

		up_read(&mm->mmap_sem);
		if (flags & FAULT_FLAG_KILLABLE)
			wait_on_page_locked_killable(page);
		else
			wait_on_page_locked(page);

		return 0;
	} else {
		/* 2024年07月18日10:42:17 todo */
		if (flags & FAULT_FLAG_KILLABLE) {
			int ret;

			ret = __lock_page_killable(page);
			if (ret) {
				up_read(&mm->mmap_sem);
				return 0;
			}
		} else
			__lock_page(page);
		return 1;
	}
}

/**
2024年07月17日16:06:30
pagecache的gap是什么
2024年07月18日10:30:23
与prev，next的区别？
 * page_cache_next_miss() - Find the next gap in the page cache.
 * @mapping: Mapping.
 * @index: Index.
 * @max_scan: Maximum range to search.
 *
 * Search the range [index, min(index + max_scan - 1, ULONG_MAX)] for the
 * gap with the lowest index.
 *
 * This function may be called under the rcu_read_lock.  However, this will
 * not atomically search a snapshot of the cache at a single point in time.
 * For example, if a gap is created at index 5, then subsequently a gap is
 * created at index 10, page_cache_next_miss covering both indices may
 * return 10 if called under the rcu_read_lock.
 *
 * Return: The index of the gap if found, otherwise an index outside the
 * range specified (in which case 'return - index >= max_scan' will be true).
 * In the rare case of index wrap-around, 0 will be returned.
 */
pgoff_t page_cache_next_miss(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	/*  */
	XA_STATE(xas, &mapping->i_pages, index);

	while (max_scan--) {
		void *entry = xas_next(&xas);
		if (!entry || xa_is_value(entry))
			break;
		if (xas.xa_index == 0)
			break;
	}

	return xas.xa_index;
}
EXPORT_SYMBOL(page_cache_next_miss);

/**
2024年7月17日22:06:09
gap是什么
2024年7月17日22:26:48
从xas倒着找，找到最大的？
 * page_cache_prev_miss() - Find the previous gap in the page cache.
 * @mapping: Mapping.
 * @index: Index.
 * @max_scan: Maximum range to search.
 *
 * Search the range [max(index - max_scan + 1, 0), index] for the
 * gap with the highest index.
 *
 * This function may be called under the rcu_read_lock.  However, this will
 * not atomically search a snapshot of the cache at a single point in time.
 * For example, if a gap is created at index 10, then subsequently a gap is
 * created at index 5, page_cache_prev_miss() covering both indices may
 * return 5 if called under the rcu_read_lock.
 *
 * Return: The index of the gap if found, otherwise an index outside the
 * range specified (in which case 'index - return >= max_scan' will be true).
 * In the rare case of wrap-around, ULONG_MAX will be returned.
 */
pgoff_t page_cache_prev_miss(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	XA_STATE(xas, &mapping->i_pages, index);

	while (max_scan--) {
		void *entry = xas_prev(&xas);
		if (!entry || xa_is_value(entry))
			break;
		if (xas.xa_index == ULONG_MAX)
			break;
	}

	return xas.xa_index;
}
EXPORT_SYMBOL(page_cache_prev_miss);

/**
2024年6月29日22:40:07
2024年7月13日14:37:07
在mapping的xas数组获得offset这个pgoff的页面
 * find_get_entry - find and get a page cache entry
 * @mapping: the address_space to search
 * @offset: the page cache index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned with an increased refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Return: the found page or shadow entry, %NULL if nothing is found.
 */
struct page *find_get_entry(struct address_space *mapping, pgoff_t offset)
{
	/* 获取mapping里的xas数组 */
	XA_STATE(xas, &mapping->i_pages, offset);
	struct page *page;

	rcu_read_lock();
repeat:
	xas_reset(&xas);
	page = xas_load(&xas);
	/* 需要重新读取的话  */
	if (xas_retry(&xas, page))
		goto repeat;
	/*
	 * A shadow entry of a recently evicted page, or a swap entry from
	 * shmem/tmpfs.  Return it without attempting to raise page count.
	 */
	if (!page || xa_is_value(page))
		goto out;
	/* 如果无法get引用计数 */
	if (!page_cache_get_speculative(page))
		goto repeat;

	/*
	 * Has the page moved or been split?
	 * This is part of the lockless pagecache protocol. See
	 * include/linux/pagemap.h for details.
	 */
	if (unlikely(page != xas_reload(&xas))) {
		put_page(page);
		goto repeat;
	}
	/* 不需要重新读取，存在，不是value，可以独占加锁，期间没有变化，就直接到这了，
	find subpage */
	/* 为什么还要subpage呢， */
	page = find_subpage(page, offset);
out:
	rcu_read_unlock();

	return page;
}
EXPORT_SYMBOL(find_get_entry);

/**
2024年07月18日10:13:14
find和lock
 * find_lock_entry - locate, pin and lock a page cache entry
 * @mapping: the address_space to search
 * @offset: the page cache index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned locked and with an increased
 * refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * find_lock_entry() may sleep.
 *
 * Return: the found page or shadow entry, %NULL if nothing is found.
 */
struct page *find_lock_entry(struct address_space *mapping, pgoff_t offset)
{
	struct page *page;

repeat:
	page = find_get_entry(mapping, offset);
	/* 刚才仅仅是get，没有加锁什么的 */
	if (page && !xa_is_value(page)) {
		/* page存在，且不是value */
		lock_page(page);
		/* Has the page been truncated? */
		if (unlikely(page_mapping(page) != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page_to_pgoff(page) != offset, page);
	}
	return page;
}
EXPORT_SYMBOL(find_lock_entry);

/**
2024年6月29日22:39:51

 * pagecache_get_page - find and get a page reference
 * @mapping: the address_space to search
 * @offset: the page index
 * @fgp_flags: PCG flags
 * @gfp_mask: gfp mask to use for the page cache data page allocation
 *
 * Looks up the page cache slot at @mapping & @offset.
 *
 * PCG flags modify how the page is returned.
 *
 * @fgp_flags can be:
 *
 * - FGP_ACCESSED: the page will be marked accessed
 * - FGP_LOCK: Page is return locked
 * - FGP_CREAT: If page is not present then a new page is allocated using
 *   @gfp_mask and added to the page cache and the VM's LRU
 *   list. The page is returned locked and with an increased
 *   refcount.
 * - FGP_FOR_MMAP: Similar to FGP_CREAT, only we want to allow the caller to do
 *   its own locking dance if the page is already in cache, or unlock the page
 *   before returning if we had to add the page to pagecache.
 *
 * If FGP_LOCK or FGP_CREAT are specified then the function may sleep even
 * if the GFP flags specified for FGP_CREAT are atomic.
 *
 * If there is a page cache page, it is returned with an increased refcount.
 *
 * Return: the found page or %NULL otherwise.
 2024年07月02日16:10:25
2024年7月16日00:05:47
查找页缓存页面。缺页的话会申请
 */
struct page *pagecache_get_page(struct address_space *mapping, pgoff_t offset,
	int fgp_flags, gfp_t gfp_mask)
{
	struct page *page;

repeat:
	page = find_get_entry(mapping, offset);
	if (xa_is_value(page))
		page = NULL;
	if (!page)
	/* 页缓存缺页 */
		goto no_page;

	if (fgp_flags & FGP_LOCK) {
		if (fgp_flags & FGP_NOWAIT) {
			if (!trylock_page(page)) {
				put_page(page);
				return NULL;
			}
		} else {
			lock_page(page);
		}

		/* Has the page been truncated? */
		if (unlikely(compound_head(page)->mapping != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page->index != offset, page);
	}

	if (fgp_flags & FGP_ACCESSED)
		mark_page_accessed(page);

no_page:
/* 页缓存里没找到page的情况 */
	if (!page && (fgp_flags & FGP_CREAT)) {
		int err;
		if ((fgp_flags & FGP_WRITE) && mapping_cap_account_dirty(mapping))
			gfp_mask |= __GFP_WRITE;
		if (fgp_flags & FGP_NOFS)
			gfp_mask &= ~__GFP_FS;
		/* 分配页面 */
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;

		if (WARN_ON_ONCE(!(fgp_flags & (FGP_LOCK | FGP_FOR_MMAP))))
			fgp_flags |= FGP_LOCK;

		/* Init accessed so avoid atomic mark_page_accessed later */
		if (fgp_flags & FGP_ACCESSED)
			__SetPageReferenced(page);
		/* 2024年6月29日23:13:45
		把页面加入mapping。
		并且加入lru。
		 */
		err = add_to_page_cache_lru(page, mapping, offset, gfp_mask);
		if (unlikely(err)) {
			/* 加入mapping和lru出错了 */
			put_page(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}

		/*
		 * add_to_page_cache_lru locks the page, and for mmap we expect
		 * an unlocked page.
		 */
		if (page && (fgp_flags & FGP_FOR_MMAP))
			unlock_page(page);
	}

	return page;
}
EXPORT_SYMBOL(pagecache_get_page);

/**
2024年07月18日10:09:12
todo
 * find_get_entries - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page cache index
 * @nr_entries:	The maximum number of entries
 * @entries:	Where the resulting entries are placed
 * @indices:	The cache indices corresponding to the entries in @entries
 *搜索返回mapping里的一些entries。
 * find_get_entries() will search for and return a group of up to
 * @nr_entries entries in the mapping.  The entries are placed at
 * @entries.  find_get_entries() takes a reference against any actual
 * pages it returns.
 *
 * The search returns a group of mapping-contiguous page cache entries
 * with ascending indexes.  There may be holes in the indices due to
 * not-present pages.
 *
 * Any shadow entries of evicted pages, or swap entries from
 * shmem/tmpfs, are included in the returned array.
 *
 * Return: the number of pages and shadow entries which were found.
 */
unsigned find_get_entries(struct address_space *mapping,
			  pgoff_t start, unsigned int nr_entries,
			  struct page **entries, pgoff_t *indices)
{
	XA_STATE(xas, &mapping->i_pages, start);
	struct page *page;
	unsigned int ret = 0;

	if (!nr_entries)
		return 0;

	rcu_read_lock();
	/* 遍历mapping里面的page */
	xas_for_each(&xas, page, ULONG_MAX) {
		if (xas_retry(&xas, page))
			continue;
		/*
		 * A shadow entry of a recently evicted page, a swap
		 * entry from shmem/tmpfs or a DAX entry.  Return it
		 * without attempting to raise page count.
		 */
		if (xa_is_value(page))
			goto export;

		if (!page_cache_get_speculative(page))
			goto retry;

		/* Has the page moved or been split? */
		if (unlikely(page != xas_reload(&xas)))
			goto put_page;
		page = find_subpage(page, xas.xa_index);

export:
		/* 保存获得的page和此page的位置吗 */
		indices[ret] = xas.xa_index;
		entries[ret] = page;

		/* 达到最大数量后返回 */
		if (++ret == nr_entries)
			break;
		continue;
put_page:
		put_page(page);
retry:
		xas_reset(&xas);
	}
	rcu_read_unlock();
	return ret;
}

/**
2024年07月18日10:01:10
 * find_get_pages_range - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @end:	The final page index (inclusive)
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *在start与end之间找到最多nr个页面，会增加引用计数。
 * find_get_pages_range() will search for and return a group of up to @nr_pages
 * pages in the mapping starting at index @start and up to index @end
 * (inclusive).  The pages are placed at @pages.  find_get_pages_range() takes
 * a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 会更新参数里面的start值
 * We also update @start to index the next page for the traversal.
 *返回找到的页面数量
 * Return: the number of pages which were found. If this number is
 * smaller than @nr_pages, the end of specified range has been
 * reached.
 */
unsigned find_get_pages_range(struct address_space *mapping, pgoff_t *start,
			      pgoff_t end, unsigned int nr_pages,
			      struct page **pages)
{
	XA_STATE(xas, &mapping->i_pages, *start);
	struct page *page;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
	/* 遍历xas */
	xas_for_each(&xas, page, end) {
		if (xas_retry(&xas, page))
			continue;
		/* Skip over shadow, swap and DAX entries */
		if (xa_is_value(page))
		/* 与find_get_pages_contig不同的地方，可以继续 */
			continue;
		/* 获得独占的锁 */
		if (!page_cache_get_speculative(page))
			goto retry;

		/* Has the page moved or been split? */
		if (unlikely(page != xas_reload(&xas)))
		/* 确保没有变 */
			goto put_page;
		/* 加入返回的结果里面 */
		pages[ret] = find_subpage(page, xas.xa_index);
		if (++ret == nr_pages) {
			*start = xas.xa_index + 1;
			goto out;
		}
		continue;
put_page:
		put_page(page);
retry:
		xas_reset(&xas);
	}

	/*
	 * We come here when there is no page beyond @end. We take care to not
	 * overflow the index @start as it confuses some of the callers. This
	 * breaks the iteration when there is a page at index -1 but that is
	 * already broken anyway.
	 */
	if (end == (pgoff_t)-1)
		*start = (pgoff_t)-1;
	else
		*start = end + 1;
out:
	rcu_read_unlock();

	return ret;
}

/**
2024年07月18日10:00:19
类似find_get_pages()，但是返回的是连续的
 * find_get_pages_contig - gang contiguous pagecache lookup
 * @mapping:	The address_space to search
 * @index:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages_contig() works exactly like find_get_pages(), except
 * that the returned number of pages are guaranteed to be contiguous.
 *
 * Return: the number of pages which were found.
 */
unsigned find_get_pages_contig(struct address_space *mapping, pgoff_t index,
			       unsigned int nr_pages, struct page **pages)
{
	XA_STATE(xas, &mapping->i_pages, index);
	struct page *page;
	unsigned int ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
	for (page = xas_load(&xas); page; page = xas_next(&xas)) {
		/* 遍历xas */

		if (xas_retry(&xas, page))
			continue;
		/*
		 * If the entry has been swapped out, we can stop looking.
		 * No current caller is looking for DAX entries.
		 */
		if (xa_is_value(page))
			break;
		/* 获得自己的独占的锁 */
		if (!page_cache_get_speculative(page))
			goto retry;

		/* Has the page moved or been split? */
		if (unlikely(page != xas_reload(&xas)))
			goto put_page;

		pages[ret] = find_subpage(page, xas.xa_index);
		if (++ret == nr_pages)
			break;

		continue;
put_page:
		put_page(page);
retry:
		xas_reset(&xas);
	}

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(find_get_pages_contig);

/**
2024年7月17日23:49:34
找到mapping里面符合tag的page放到pages里面
 * find_get_pages_range_tag - find and return pages in given range matching @tag
 * @mapping:	the address_space to search
 * @index:	the starting page index
 * @end:	The final page index (inclusive)
 * @tag:	the tag index
 * @nr_pages:	the maximum number of pages
 * @pages:	where the resulting pages are placed
 *
 * Like find_get_pages, except we only return pages which are tagged with
 * @tag.   We update @index to index the next page for the traversal.
 *
 * Return: the number of pages which were found.
 */
unsigned find_get_pages_range_tag(struct address_space *mapping, pgoff_t *index,
			pgoff_t end, xa_mark_t tag, unsigned int nr_pages,
			struct page **pages)
{
	XA_STATE(xas, &mapping->i_pages, *index);
	struct page *page;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();

	xas_for_each_marked(&xas, page, end, tag) {
		if (xas_retry(&xas, page))
			continue;
		/*
		 * Shadow entries should never be tagged, but this iteration
		 * is lockless so there is a window for page reclaim to evict
		 * a page we saw tagged.  Skip over it.
		 */
		if (xa_is_value(page))
			continue;

		if (!page_cache_get_speculative(page))
			goto retry;

		/* Has the page moved or been split? */
		if (unlikely(page != xas_reload(&xas)))
			goto put_page;
		/* 赋值到pvec的pages */
		pages[ret] = find_subpage(page, xas.xa_index);
		if (++ret == nr_pages) {
			*index = xas.xa_index + 1;
			goto out;
		}
		continue;
put_page:
		put_page(page);
retry:
		xas_reset(&xas);
	}

	/*
	 * We come here when we got to @end. We take care to not overflow the
	 * index @index as it confuses some of the callers. This breaks the
	 * iteration when there is a page at index -1 but that is already
	 * broken anyway.
	 */
	if (end == (pgoff_t)-1)
		*index = (pgoff_t)-1;
	else
		*index = end + 1;
out:
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(find_get_pages_range_tag);

/*
2024年7月18日00:42:03
 * CD/DVDs are error prone. When a medium error occurs, the driver may fail
 * a _large_ part of the i/o request. Imagine the worst scenario:
 *
 *      ---R__________________________________________B__________
 *         ^ reading here                             ^ bad block(assume 4k)
 *
 * read(R) => miss => readahead(R...B) => media error => frustrating retries
 * => failing the whole request => read(R) => read(R+1) =>
 * readahead(R+1...B+1) => bang => read(R+2) => read(R+3) =>
 * readahead(R+3...B+2) => bang => read(R+3) => read(R+4) =>
 * readahead(R+4...B+3) => bang => read(R+4) => read(R+5) => ......
 *
 * It is going insane. Fix it by quickly scaling down the readahead size.
 */
static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

/**
2024年6月29日22:23:02
2024年7月18日00:13:29
 * generic_file_buffered_read - generic file read routine
 * @iocb:	the iocb to read
 * @iter:	data destination
 * @written:	already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 *
 * Return:
 * * total number of bytes copied, including those the were already @written
 * * negative error code if nothing was copied
 */
static ssize_t generic_file_buffered_read(struct kiocb *iocb,
		struct iov_iter *iter, ssize_t written)
{
	struct file *filp = iocb->ki_filp;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	/* 预读控制块 */
	struct file_ra_state *ra = &filp->f_ra;
	loff_t *ppos = &iocb->ki_pos;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error = 0;

	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;
	/* 不能超过限制 */
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

	index = *ppos >> PAGE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}
		/* 所读取内容不在页缓存，这里分配页面并加入 */
		page = find_get_page(mapping, index);
		if (!page) {
			/* 给页缓存申请页面不成功 */
			if (iocb->ki_flags & IOCB_NOWAIT)
				goto would_block;
			/* 预读，中间也会给mapping申请缺少的页面 */
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
					/* 刚才预读的时候可能新申请页面了，所以这里重新获取一下 */
			page = find_get_page(mapping, index);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		/* 直接就已经在缓存了 */
		if (PageReadahead(page)) {
			/* 如果page有预读属性，那么异步预读，
			其实就是readpages()一些页面 */
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		/* 是说这是脏缓存吗？ */
		if (!PageUptodate(page)) {
			if (iocb->ki_flags & IOCB_NOWAIT) {
				put_page(page);
				goto would_block;
			}

			/*
			 * See comment in do_read_cache_page on why
			 * wait_on_page_locked is used to avoid unnecessarily
			 * serialisations and why it's safe.
			 */
			 /* 这个函数是先检查这个page是否有locked flag，如果有则会去等这个flag被clear，
			 所以此时这个线程有可能会睡眠被调度出去，
			 此时这个线程的状态被设置为TASK_KILLABLE，此后去查看这个线程的状态将是D状态。 */
			error = wait_on_page_locked_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (PageUptodate(page))
			/* 等待期间变新了？ */
				goto page_ok;

			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
					/* 什么逻辑？2024年7月18日00:21:40 */
				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages */
			if (unlikely(iov_iter_is_pipe(iter)))
				goto page_not_up_to_date;
			/* 为什么不能获得锁，就是dirty */
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);

		/* 脏页这一块好麻烦 */
		}
page_ok:
/* 好像页面变新了来到这 */
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			put_page(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.

		 */
		if (mapping_writably_mapped(mapping))
		/* 在用户空间有共享的vma */
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 拷贝数据
		 */

		ret = copy_page_to_iter(page, offset, nr, iter);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
		prev_offset = offset;

		put_page(page);
		written += ret;
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;

page_not_up_to_date:
		/* Get exclusive access to the page ...
		还要继续等吗 */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock?
		2024年7月18日00:29:42
		todo，删除的情况 */
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page.
		为什么还能用ops来read？哦哦是从file读到mapping吗， */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			/* 读取到mapping出错了？ */
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				/* 为啥到find page ？，可能是和ops回调有关*/
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			/*  */
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				/*  */
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					put_page(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 没有缓存页的情况
		 */
		page = page_cache_alloc(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			/* 失败情况 */
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

would_block:
/* 申请页面不成功，或者脏页 */
	error = -EAGAIN;
out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}

/**
2024年7月17日22:43:22
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iter:	destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code if nothing was read
 */
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	if (!count)
		goto out; /* skip atime */
	/* 为什么有这个if的特殊处理 */
	if (iocb->ki_flags & IOCB_DIRECT) {
		/* direct IO的路径？ */
		struct file *file = iocb->ki_filp;
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		loff_t size;

		size = i_size_read(inode);
		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (filemap_range_has_page(mapping, iocb->ki_pos,
						   iocb->ki_pos + count - 1))
						   /* 在范围内没有page */
				return -EAGAIN;
		} else {
			/* 在范围内有已存在的page
			2024年7月18日00:06:40
			里面挺深的
			好像主要是写回的作用， */
			retval = filemap_write_and_wait_range(mapping,
						iocb->ki_pos,
					        iocb->ki_pos + count - 1);
			if (retval < 0)
				goto out;
		}

		file_accessed(file);
		/* 又IO？ */
		retval = mapping->a_ops->direct_IO(iocb, iter);
		if (retval >= 0) {
			/* 返回值是写成功的数量 */
			iocb->ki_pos += retval;
			count -= retval;
		}
		iov_iter_revert(iter, count - iov_iter_count(iter));

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.  Buffered reads will not work for
		 * DAX files, so don't bother trying.
		 */
		if (retval < 0 || !count || iocb->ki_pos >= size ||
		    IS_DAX(inode))
			goto out;
	}

	retval = generic_file_buffered_read(iocb, iter, retval);
out:
	return retval;
}
EXPORT_SYMBOL(generic_file_read_iter);

#ifdef CONFIG_MMU
#define MMAP_LOTSAMISS  (100)
/* 2024年7月16日00:17:46
2024年07月17日15:58:36
 */
static struct file *maybe_unlock_mmap_for_io(struct vm_fault *vmf,
					     struct file *fpin)
{
	int flags = vmf->flags;

	if (fpin)
		return fpin;

	/*
	 * FAULT_FLAG_RETRY_NOWAIT means we don't want to wait on page locks or
	 * anything, so we only pin the file and drop the mmap_sem if only
	 * FAULT_FLAG_ALLOW_RETRY is set.
	 */
	if ((flags & (FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT)) ==
	    FAULT_FLAG_ALLOW_RETRY) {
			/* get 一下mmap的file */
		fpin = get_file(vmf->vma->vm_file);
		up_read(&vmf->vma->vm_mm->mmap_sem);
	}
	return fpin;
}

/*
2024年7月17日22:37:52
加锁
 * lock_page_maybe_drop_mmap - lock the page, possibly dropping the mmap_sem
 * @vmf - the vm_fault for this fault.
 * @page - the page to lock.
 * @fpin - the pointer to the file we may pin (or is already pinned).
 *
 * This works similar to lock_page_or_retry in that it can drop the mmap_sem.
 * It differs in that it actually returns the page locked if it returns 1 and 0
 * if it couldn't lock the page.  If we did have to drop the mmap_sem then fpin
 * will point to the pinned file and needs to be fput()'ed at a later point.
 */
static int lock_page_maybe_drop_mmap(struct vm_fault *vmf, struct page *page,
				     struct file **fpin)
{
	if (trylock_page(page))
		return 1;

	/*
	 * NOTE! This will make us return with VM_FAULT_RETRY, but with
	 * the mmap_sem still held. That's how FAULT_FLAG_RETRY_NOWAIT
	 * is supposed to work. We have way too many special cases..
	 */
	if (vmf->flags & FAULT_FLAG_RETRY_NOWAIT)
		return 0;
		/* 好像其实就是get一下file */
	*fpin = maybe_unlock_mmap_for_io(vmf, *fpin);
	if (vmf->flags & FAULT_FLAG_KILLABLE) {
		if (__lock_page_killable(page)) {
			/* todo */
			/*
			 * We didn't have the right flags to drop the mmap_sem,
			 * but all fault_handlers only check for fatal signals
			 * if we return VM_FAULT_RETRY, so we need to drop the
			 * mmap_sem here and return 0 if we don't have a fpin.
			 */
			if (*fpin == NULL)
				up_read(&vmf->vma->vm_mm->mmap_sem);
			return 0;
		}
	} else
	/* 刚才trylock失败了，这里可能会sleep来lock */
		__lock_page(page);

	
	return 1;
}


/*
2024年7月3日00:12:12
mmap文件映射缺页时的预读？
 * Synchronous readahead happens when we don't even find a page in the page
 * cache at all.  We don't want to perform IO under the mmap sem, so if we have
 * to drop the mmap sem we return the file that was pinned in order for us to do
 * that.  If we didn't pin a file then we return NULL.  The file that is
 * returned needs to be fput()'ed when we're done with it.
 */
static struct file *do_sync_mmap_readahead(struct vm_fault *vmf)
{
	/* 发生缺页的vma的mmap file */
	struct file *file = vmf->vma->vm_file;
	struct file_ra_state *ra = &file->f_ra;
	struct address_space *mapping = file->f_mapping;
	struct file *fpin = NULL;
	/* 缺页地址的pgoff */
	pgoff_t offset = vmf->pgoff;

	/* If we don't want any read-ahead, don't bother
	随机读，不预读 */
	if (vmf->vma->vm_flags & VM_RAND_READ)
		return fpin;
	/* 被映射的文件关闭了预读 */
	if (!ra->ra_pages)
		return fpin;

	if (vmf->vma->vm_flags & VM_SEQ_READ) {
		/* 顺序读的预读？ */
		fpin = maybe_unlock_mmap_for_io(vmf, fpin);
		page_cache_sync_readahead(mapping, ra, file, offset,
					  ra->ra_pages);
		return fpin;
	}

	/* Avoid banging the cache line if not needed */
	if (ra->mmap_miss < MMAP_LOTSAMISS * 10)
		ra->mmap_miss++;

	/*
	 * Do we miss much more than hit in this file? If so,
	 * stop bothering with read-ahead. It will only hurt.
	 */
	if (ra->mmap_miss > MMAP_LOTSAMISS)
		return fpin;

	/*
	 * mmap read-around
	 普遍意义的预读
	 */
	fpin = maybe_unlock_mmap_for_io(vmf, fpin);
	/* 设置预读参数 */
	ra->start = max_t(long, 0, offset - ra->ra_pages / 2);
	ra->size = ra->ra_pages;
	ra->async_size = ra->ra_pages / 4;
	/* 开始 */
	ra_submit(ra, mapping, file);
	return fpin;
}

/*
2024年7月16日00:16:02
异步预读
 * Asynchronous readahead happens when we find the page and PG_readahead,
 * so we want to possibly extend the readahead further.  We return the file that
 * was pinned if we have to drop the mmap_sem in order to do IO.
 */
static struct file *do_async_mmap_readahead(struct vm_fault *vmf,
					    struct page *page)
{
	struct file *file = vmf->vma->vm_file;
	struct file_ra_state *ra = &file->f_ra;
	struct address_space *mapping = file->f_mapping;
	/* fpin就是get了之后的mmap file */
	struct file *fpin = NULL;
	pgoff_t offset = vmf->pgoff;

	/* If we don't want any read-ahead, don't bother
	是说随机读取不预读吗 */
	if (vmf->vma->vm_flags & VM_RAND_READ)
		return fpin;

	if (ra->mmap_miss > 0)
		ra->mmap_miss--;
	/* page有预读标记 */
	if (PageReadahead(page)) {
		/* 把mmap file进行get之后赋值给fpin，表示pinned了？ */
		fpin = maybe_unlock_mmap_for_io(vmf, fpin);
		page_cache_async_readahead(mapping, ra, file,
					   page, offset, ra->ra_pages);
	}
	return fpin;
}

/**
2024年7月16日00:14:14
 * filemap_fault - read in file data for page fault handling
 * @vmf:	struct vm_fault containing details of the fault
 *
 * filemap_fault() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 *
 * vma->vm_mm->mmap_sem must be held on entry.
 *
 * If our return value has VM_FAULT_RETRY set, it's because the mmap_sem
 * may be dropped before doing I/O or by lock_page_maybe_drop_mmap().
 *
 * If our return value does not have VM_FAULT_RETRY set, the mmap_sem
 * has not been released.
 *
 * We never return with VM_FAULT_RETRY and a bit from VM_FAULT_ERROR set.
 *
 * Return: bitwise-OR of %VM_FAULT_ codes.
 */
vm_fault_t filemap_fault(struct vm_fault *vmf)
{
	int error;
	/* 产生fault的vma的file */
	struct file *file = vmf->vma->vm_file;
	struct file *fpin = NULL;
	struct address_space *mapping = file->f_mapping;
	/* 预读 */
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	pgoff_t offset = vmf->pgoff;
	pgoff_t max_off;
	struct page *page;
	vm_fault_t ret = 0;

	max_off = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(offset >= max_off))
		return VM_FAULT_SIGBUS;

	/*
	 * Do we have something in the page cache already?
	 */
	 /* 缺页的话会分配新页面 */
	page = find_get_page(mapping, offset);
	if (likely(page) && !(vmf->flags & FAULT_FLAG_TRIED)) {
		/*
		 * We found the page, so try async readahead before
		 * waiting for the lock.
		 
		 */
		fpin = do_async_mmap_readahead(vmf, page);
	} else if (!page) {
		/* 
		页缓存没有页面
		No page in the page cache at all */
		count_vm_event(PGMAJFAULT);
		count_memcg_event_mm(vmf->vma->vm_mm, PGMAJFAULT);
		ret = VM_FAULT_MAJOR;
		fpin = do_sync_mmap_readahead(vmf);
retry_find:
		page = pagecache_get_page(mapping, offset,
					  FGP_CREAT|FGP_FOR_MMAP,
					  vmf->gfp_mask);
		if (!page) {
			if (fpin)
				goto out_retry;
			return vmf_error(-ENOMEM);
		}
	}

	if (!lock_page_maybe_drop_mmap(vmf, page, &fpin))
		goto out_retry;

	/* Did it get truncated? */
	if (unlikely(compound_head(page)->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}
	VM_BUG_ON_PAGE(page_to_pgoff(page) != offset, page);

	/*
	 * We have a locked page in the page cache, now we need to check
	 * that it's up-to-date. If not, it is going to be due to an error.
	 */
	if (unlikely(!PageUptodate(page)))
		goto page_not_uptodate;

	/*
	 * We've made it this far and we had to drop our mmap_sem, now is the
	 * time to return to the upper layer and have it re-find the vma and
	 * redo the fault.
	 */
	if (fpin) {
		unlock_page(page);
		goto out_retry;
	}

	/*
	 * Found the page and have a reference on it.
	 * We must recheck i_size under page lock.
	 */
	max_off = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(offset >= max_off)) {
		unlock_page(page);
		put_page(page);
		return VM_FAULT_SIGBUS;
	}

	vmf->page = page;
	return ret | VM_FAULT_LOCKED;

page_not_uptodate:
	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	ClearPageError(page);
	fpin = maybe_unlock_mmap_for_io(vmf, fpin);
	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (!PageUptodate(page))
			error = -EIO;
	}
	if (fpin)
		goto out_retry;
	put_page(page);

	if (!error || error == AOP_TRUNCATED_PAGE)
		goto retry_find;

	/* Things didn't work out. Return zero to tell the mm layer so. */
	shrink_readahead_size_eio(file, ra);
	return VM_FAULT_SIGBUS;

out_retry:
	/*
	 * We dropped the mmap_sem, we need to return to the fault handler to
	 * re-find the vma and come back and find our hopefully still populated
	 * page.
	 */
	if (page)
		put_page(page);
	if (fpin)
		fput(fpin);
	return ret | VM_FAULT_RETRY;
}
EXPORT_SYMBOL(filemap_fault);
/* vma的vma ops的map_pages回调可能是这个函数 */
void filemap_map_pages(struct vm_fault *vmf,
		pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	/* 获得vma所map的file */
	struct file *file = vmf->vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	pgoff_t last_pgoff = start_pgoff;
	unsigned long max_idx;
	/* 获取map file的mapping */
	XA_STATE(xas, &mapping->i_pages, start_pgoff);
	struct page *page;

	rcu_read_lock();
	/* 遍历xas，每次存储到page */
	xas_for_each(&xas, page, end_pgoff) {
		if (xas_retry(&xas, page))
			continue;
		if (xa_is_value(page))
			goto next;

		/*
		 * Check for a locked page first, as a speculative
		 * reference may adversely influence page migration.
		 */
		if (PageLocked(page))
			goto next;
		if (!page_cache_get_speculative(page))
			goto next;

		/* Has the page moved or been split? */
		if (unlikely(page != xas_reload(&xas)))
			goto skip;

		page = find_subpage(page, xas.xa_index);

		if (!PageUptodate(page) ||
				PageReadahead(page) ||
				PageHWPoison(page))
			goto skip;
		if (!trylock_page(page))
			goto skip;

		if (page->mapping != mapping || !PageUptodate(page))
			goto unlock;

		max_idx = DIV_ROUND_UP(i_size_read(mapping->host), PAGE_SIZE);
		if (page->index >= max_idx)
			goto unlock;

		if (file->f_ra.mmap_miss > 0)
			file->f_ra.mmap_miss--;

		vmf->address += (xas.xa_index - last_pgoff) << PAGE_SHIFT;
		if (vmf->pte)
			vmf->pte += xas.xa_index - last_pgoff;
		last_pgoff = xas.xa_index;
		/* 在mapping找到了page，这里map（映射到）缺页地址处 */
		if (alloc_set_pte(vmf, NULL, page))
			goto unlock;
		unlock_page(page);
		goto next;
unlock:
		unlock_page(page);
skip:
		put_page(page);
next:
		/* Huge page is mapped? No need to proceed. */
		if (pmd_trans_huge(*vmf->pmd))
			break;
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(filemap_map_pages);

vm_fault_t filemap_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	vm_fault_t ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vmf->vma->vm_file);
	lock_page(page);
	if (page->mapping != inode->i_mapping) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}
	/*
	 * We mark the page dirty already here so that when freeze is in
	 * progress, we are guaranteed that writeback during freezing will
	 * see the dirty page and writeprotect it again.
	 */
	set_page_dirty(page);
	wait_for_stable_page(page);
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}
/* 2024年7月16日00:13:54 
2024年07月17日14:35:19
*/
const struct vm_operations_struct generic_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= filemap_page_mkwrite,
};

/* 
2024年7月16日00:12:08
This is used for a general mmap of a disk file */

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	/* 访问修改atime */
	file_accessed(file);

	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

/*
2024年7月16日00:11:43
 * This is for filesystems which do not implement ->writepage.
 */
int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;

	return generic_file_mmap(file, vma);
}
#else
vm_fault_t filemap_page_mkwrite(struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif /* CONFIG_MMU */

EXPORT_SYMBOL(filemap_page_mkwrite);
EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);
/* 2024年07月02日16:22:36
2024年7月16日00:10:27
等待页面回写完成
 */
static struct page *wait_on_page_read(struct page *page)
{
	if (!IS_ERR(page)) {
		/* 等待解锁 */
		wait_on_page_locked(page);

		if (!PageUptodate(page)) {
			/* 脏页 */
			put_page(page);
			page = ERR_PTR(-EIO);
		}
	}
	return page;
}
/* 2024年07月02日15:39:28
2024年7月16日00:04:32
read_cache_page的函数
 */
static struct page *do_read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data,
				gfp_t gfp)
{
	struct page *page;
	int err;
repeat:
/*    find_get_page查找page cache失败，而且页不允许申请新的page
 */
	page = find_get_page(mapping, index);
	if (!page) {
		/* 2024年07月02日16:12:30
		按理说find_get_page在缓存找不到的话，不是内部会申请页面吗？ */
		page = __page_cache_alloc(gfp);
		if (!page)
			return ERR_PTR(-ENOMEM);
		err = add_to_page_cache_lru(page, mapping, index, gfp);
		/*  */
		if (unlikely(err)) {
			put_page(page);
			if (err == -EEXIST)
				goto repeat;
			/* Presumably ENOMEM for xarray node */
			return ERR_PTR(err);
		}

filler:
		if (filler)
			err = filler(data, page);
		else
			err = mapping->a_ops->readpage(data, page);

		if (err < 0) {
			put_page(page);
			return ERR_PTR(err);
		}
		/* 等待页面回写 */
		page = wait_on_page_read(page);
		if (IS_ERR(page))
			return page;
		goto out;
	}
	if (PageUptodate(page))
		goto out;

	/*
	 * Page is not up to date and may be locked due one of the following
	 * case a: Page is being filled and the page lock is held
	 * case b: Read/write error clearing the page uptodate status
	 * case c: Truncation in progress (page locked)
	 * case d: Reclaim in progress
	 *
	 * Case a, the page will be up to date when the page is unlocked.
	 *    There is no need to serialise on the page lock here as the page
	 *    is pinned so the lock gives no additional protection. Even if the
	 *    the page is truncated, the data is still valid if PageUptodate as
	 *    it's a race vs truncate race.
	 * Case b, the page will not be up to date
	 * Case c, the page may be truncated but in itself, the data may still
	 *    be valid after IO completes as it's a read vs truncate race. The
	 *    operation must restart if the page is not uptodate on unlock but
	 *    otherwise serialising on page lock to stabilise the mapping gives
	 *    no additional guarantees to the caller as the page lock is
	 *    released before return.
	 * Case d, similar to truncation. If reclaim holds the page lock, it
	 *    will be a race with remove_mapping that determines if the mapping
	 *    is valid on unlock but otherwise the data is valid and there is
	 *    no need to serialise with page lock.
	 *
	 * As the page lock gives no additional guarantee, we optimistically
	 * wait on the page to be unlocked and check if it's up to date and
	 * use the page if it is. Otherwise, the page lock is required to
	 * distinguish between the different cases. The motivation is that we
	 * avoid spurious serialisations and wakeups when multiple processes
	 * wait on the same page for IO to complete.
	 */
	wait_on_page_locked(page);
	if (PageUptodate(page))
		goto out;

	/* Distinguish between all the cases under the safety of the lock */
	lock_page(page);

	/* Case c or d, restart the operation */
	if (!page->mapping) {
		unlock_page(page);
		put_page(page);
		goto repeat;
	}

	/* Someone else locked and filled the page in a very small window */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	goto filler;

out:
	mark_page_accessed(page);
	return page;
}

/**
2024年07月02日16:24:28
读取页缓存,缺页申请页面。可能是文件系统的实现会使用
 * read_cache_page - read into page cache, fill it if needed
 * @mapping:	the page's address_space
 * @index:	the page index
 * @filler:	function to perform the read
 * @data:	first arg to filler(data, page) function, often left as NULL
 *
 * Read into the page cache. If a page already exists, and PageUptodate() is
 * not set, try to fill the page and wait for it to become unlocked.
 *
 * If the page does not get brought uptodate, return -EIO.
 *
 * Return: up to date page on success, ERR_PTR() on failure.
 */
struct page *read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data)
{
	return do_read_cache_page(mapping, index, filler, data,
			mapping_gfp_mask(mapping));
}
EXPORT_SYMBOL(read_cache_page);

/**
2024年7月16日00:04:20
读pagecache
 * read_cache_page_gfp - read into page cache, using specified page allocation flags.
 * @mapping:	the page's address_space
 * @index:	the page index
 * @gfp:	the page allocator flags to use if allocating
 *
 * This is the same as "read_mapping_page(mapping, index, NULL)", but with
 * any new page allocations done using the specified allocation flags.
 *
 * If the page does not get brought uptodate, return -EIO.
 *
 * Return: up to date page on success, ERR_PTR() on failure.
 */
struct page *read_cache_page_gfp(struct address_space *mapping,
				pgoff_t index,
				gfp_t gfp)
{
	return do_read_cache_page(mapping, index, NULL, NULL, gfp);
}
EXPORT_SYMBOL(read_cache_page_gfp);

/*
2024年7月16日00:00:30
 * Don't operate on ranges the page cache doesn't support, and don't exceed the
 * LFS limits.  If pos is under the limit it becomes a short access.  If it
 * exceeds the limit we return -EFBIG.
 */
static int generic_write_check_limits(struct file *file, loff_t pos,
				      loff_t *count)
{
	struct inode *inode = file->f_mapping->host;
	loff_t max_size = inode->i_sb->s_maxbytes;
	loff_t limit = rlimit(RLIMIT_FSIZE);

	if (limit != RLIM_INFINITY) {
		if (pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		*count = min(*count, limit - pos);
	}

	if (!(file->f_flags & O_LARGEFILE))
		max_size = MAX_NON_LFS;
		/* 超过了文件系统最大文件限制 */
	if (unlikely(pos >= max_size))
		return -EFBIG;

	*count = min(*count, max_size - pos);

	return 0;
}

/*
2024年7月15日23:56:49
fops的write函数前的check
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
inline ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	loff_t count;
	int ret;

	if (IS_SWAPFILE(inode))
		return -ETXTBSY;

	if (!iov_iter_count(from))
		return 0;

	/* FIXME: this is for backwards compatibility with 2.4 */
	if (iocb->ki_flags & IOCB_APPEND)
	/* 附加写，获取写入位置 */
		iocb->ki_pos = i_size_read(inode);

	if ((iocb->ki_flags & IOCB_NOWAIT) && !(iocb->ki_flags & IOCB_DIRECT))
		return -EINVAL;
	/* 要写入的数量 */
	count = iov_iter_count(from);

	ret = generic_write_check_limits(file, iocb->ki_pos, &count);
	if (ret)
		return ret;
	/* 现在count是可以写入的大小，如果比from里面count小，就truncate */
	iov_iter_truncate(from, count);

	return iov_iter_count(from);
}
EXPORT_SYMBOL(generic_write_checks);

/*
 * Performs necessary checks before doing a clone.
 *
 * Can adjust amount of bytes to clone via @req_count argument.
 * Returns appropriate error code that caller should return or
 * zero in case the clone should be allowed.
 */
int generic_remap_checks(struct file *file_in, loff_t pos_in,
			 struct file *file_out, loff_t pos_out,
			 loff_t *req_count, unsigned int remap_flags)
{
	struct inode *inode_in = file_in->f_mapping->host;
	struct inode *inode_out = file_out->f_mapping->host;
	uint64_t count = *req_count;
	uint64_t bcount;
	loff_t size_in, size_out;
	loff_t bs = inode_out->i_sb->s_blocksize;
	int ret;

	/* The start of both ranges must be aligned to an fs block. */
	if (!IS_ALIGNED(pos_in, bs) || !IS_ALIGNED(pos_out, bs))
		return -EINVAL;

	/* Ensure offsets don't wrap. */
	if (pos_in + count < pos_in || pos_out + count < pos_out)
		return -EINVAL;

	size_in = i_size_read(inode_in);
	size_out = i_size_read(inode_out);

	/* Dedupe requires both ranges to be within EOF. */
	if ((remap_flags & REMAP_FILE_DEDUP) &&
	    (pos_in >= size_in || pos_in + count > size_in ||
	     pos_out >= size_out || pos_out + count > size_out))
		return -EINVAL;

	/* Ensure the infile range is within the infile. */
	if (pos_in >= size_in)
		return -EINVAL;
	count = min(count, size_in - (uint64_t)pos_in);

	ret = generic_write_check_limits(file_out, pos_out, &count);
	if (ret)
		return ret;

	/*
	 * If the user wanted us to link to the infile's EOF, round up to the
	 * next block boundary for this check.
	 *
	 * Otherwise, make sure the count is also block-aligned, having
	 * already confirmed the starting offsets' block alignment.
	 */
	if (pos_in + count == size_in) {
		bcount = ALIGN(size_in, bs) - pos_in;
	} else {
		if (!IS_ALIGNED(count, bs))
			count = ALIGN_DOWN(count, bs);
		bcount = count;
	}

	/* Don't allow overlapped cloning within the same file. */
	if (inode_in == inode_out &&
	    pos_out + bcount > pos_in &&
	    pos_out < pos_in + bcount)
		return -EINVAL;

	/*
	 * We shortened the request but the caller can't deal with that, so
	 * bounce the request back to userspace.
	 */
	if (*req_count != count && !(remap_flags & REMAP_FILE_CAN_SHORTEN))
		return -EINVAL;

	*req_count = count;
	return 0;
}


/*
 * Performs common checks before doing a file copy/clone
 * from @file_in to @file_out.
 */
int generic_file_rw_checks(struct file *file_in, struct file *file_out)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);

	/* Don't copy dirs, pipes, sockets... */
	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND))
		return -EBADF;

	return 0;
}

/*
 * Performs necessary checks before doing a file copy
 *
 * Can adjust amount of bytes to copy via @req_count argument.
 * Returns appropriate error code that caller should return or
 * zero in case the copy should be allowed.
 */
int generic_copy_file_checks(struct file *file_in, loff_t pos_in,
			     struct file *file_out, loff_t pos_out,
			     size_t *req_count, unsigned int flags)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	uint64_t count = *req_count;
	loff_t size_in;
	int ret;

	ret = generic_file_rw_checks(file_in, file_out);
	if (ret)
		return ret;

	/* Don't touch certain kinds of inodes */
	if (IS_IMMUTABLE(inode_out))
		return -EPERM;

	if (IS_SWAPFILE(inode_in) || IS_SWAPFILE(inode_out))
		return -ETXTBSY;

	/* Ensure offsets don't wrap. */
	if (pos_in + count < pos_in || pos_out + count < pos_out)
		return -EOVERFLOW;

	/* Shorten the copy to EOF */
	size_in = i_size_read(inode_in);
	if (pos_in >= size_in)
		count = 0;
	else
		count = min(count, size_in - (uint64_t)pos_in);

	ret = generic_write_check_limits(file_out, pos_out, &count);
	if (ret)
		return ret;

	/* Don't allow overlapped copying within the same file. */
	if (inode_in == inode_out &&
	    pos_out + count > pos_in &&
	    pos_out < pos_in + count)
		return -EINVAL;

	*req_count = count;
	return 0;
}

int pagecache_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_begin(file, mapping, pos, len, flags,
							pagep, fsdata);
}
EXPORT_SYMBOL(pagecache_write_begin);

int pagecache_write_end(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_end(file, mapping, pos, len, copied, page, fsdata);
}
EXPORT_SYMBOL(pagecache_write_end);
/* fops的generic direct IO函数 */
ssize_t
generic_file_direct_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	/* 要写的位置 */
	loff_t		pos = iocb->ki_pos;
	ssize_t		written;
	size_t		write_len;
	pgoff_t		end;

	/* 要写的数据大小 */
	write_len = iov_iter_count(from);
	/* 要写的end pgoff */
	end = (pos + write_len - 1) >> PAGE_SHIFT;

	if (iocb->ki_flags & IOCB_NOWAIT) {/* NO_WAIT的路径 */
		/* If there are pages to writeback, return */
		if (filemap_range_has_page(inode->i_mapping, pos,
					   pos + write_len - 1))
			return -EAGAIN;
	} else {
		/* 进行回写 */
		written = filemap_write_and_wait_range(mapping, pos,
							pos + write_len - 1);
		if (written)
			goto out;
	}

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * without clobbering -EIOCBQUEUED from ->direct_IO().
	 	todo
	 */
	written = invalidate_inode_pages2_range(mapping,
					pos >> PAGE_SHIFT, end);
	/*
	 * If a page can not be invalidated, return 0 to fall back
	 * to buffered write.
	 */
	if (written) {
		if (written == -EBUSY)
			return 0;
		goto out;
	}

	written = mapping->a_ops->direct_IO(iocb, from);

	/*
	 * Finally, try again to invalidate clean pages which might have been
	 * cached by non-direct readahead, or faulted in by get_user_pages()
	 * if the source of the write was an mmap'ed region of the file
	 * we're writing.  Either one is a pretty crazy thing to do,
	 * so we don't support it 100%.  If this invalidation
	 * fails, tough, the write still worked...
	 *
	 * Most of the time we do not need this since dio_complete() will do
	 * the invalidation for us. However there are some file systems that
	 * do not end up with dio_complete() being called, so let's not break
	 * them by removing it completely
	 */
	if (mapping->nrpages)
		invalidate_inode_pages2_range(mapping,
					pos >> PAGE_SHIFT, end);

	if (written > 0) {
		pos += written;
		write_len -= written;
		if (pos > i_size_read(inode) && !S_ISBLK(inode->i_mode)) {
			i_size_write(inode, pos);
			mark_inode_dirty(inode);
		}
		iocb->ki_pos = pos;
	}
	iov_iter_revert(from, write_len - iov_iter_count(from));
out:
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write);

/*
2024年08月08日17:21:26
mapping ops的write_begin函数调用
这个函数来get返回这个页面，确保要写入的页面存在，
 * Find or create a page at the given pagecache position. Return the locked
 * page. This function is specifically for buffered writes.
 */
struct page *grab_cache_page_write_begin(struct address_space *mapping,
					pgoff_t index, unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK|FGP_WRITE|FGP_CREAT;

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

	/* 获取页面 */
	page = pagecache_get_page(mapping, index, fgp_flags,
			mapping_gfp_mask(mapping));
	if (page)
		wait_for_stable_page(page);

	return page;
}
EXPORT_SYMBOL(grab_cache_page_write_begin);
/* 

执行写入
2024年08月08日17:01:38
fops的write回调的一般路径的函数，不是直接IO那个
就是从iov拷贝数据 */
ssize_t generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	/* 获取页缓存的ops */
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = 0;

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata;
		/* offset是页内偏移 */
		offset = (pos & (PAGE_SIZE - 1));

		/* 要写入的字节数，就是剩余要写的，和这个页面还能写入的容量（PAGE_SIZE-offset）取小 */
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}
		/* 调用mapping的write_begin回调 qwert1
		page好像会被赋值为要写的页面 */
		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);

		if (unlikely(status < 0))
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);
		/* 往page的offset写入len长度的i里面的数据 */
		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		flush_dcache_page(page);

		/* mapping的write_end回调 */
		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		
		if (unlikely(status < 0))
			break;
		copied = status;

		cond_resched();
		/* 向前seek刚才成功拷贝的数据量 */
		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			/*
			 * If we were unable to copy any data at all, we must
			 * fall back to a single segment length write.
			 *
			 * If we didn't fallback here, we could livelock
			 * because not all segments in the iov can be copied at
			 * once without a pagefault.
			 */
			bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		/* 继续seek此src */
		pos += copied;
		written += copied;

		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	return written ? written : status;
}
EXPORT_SYMBOL(generic_perform_write);

/**
2024年8月8日23:55:17
fops的generic write实现
rodo，直接io那一块。
 * __generic_file_write_iter - write data to a file
 * @iocb:	IO state structure (file, offset, etc.)
 * @from:	iov_iter with data to write
 *
 * This function does all the work needed for actually writing data to a
 * file. It does all basic checks, removes SUID from the file, updates
 * modification times and calls proper subroutines depending on whether we
 * do direct IO or a standard buffered write.
 *
 * It expects i_mutex to be grabbed unless we work on a block device or similar
 * object which does not need locking at all.
 *
 * This function does *not* take care of syncing data in case of O_SYNC write.
 * A caller has to handle it. This is mainly due to the fact that we want to
 * avoid syncing under i_mutex.
 *
 * Return:
 * * number of bytes written, even for truncated writes
 * * negative error code if no data has been written at all
 */
ssize_t __generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	/* 要写的文件？ */
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	/* We can write back this queue in page reclaim
	获取要写的磁盘 */
	current->backing_dev_info = inode_to_bdi(inode);
	/* 如有必要，移除privs */
	err = file_remove_privs(file);
	if (err)
		goto out;
	/* 更新时间 */
	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {/* 直接IO的路径
	发现设置了IOCB_DIRECT，则调用generic_file_direct_write，里面同样会调用
	address_space的direct_IO的函数，将数据直接写入硬盘。 */
		loff_t pos, endbyte;
		/* 进行direct IO */
		written = generic_file_direct_write(iocb, from);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
		/* 如果写完了，或者是直接IO的inode，或者written小于0， */
			goto out;

		status = generic_perform_write(file, from, pos = iocb->ki_pos);
		/*
		 * If generic_perform_write() returned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {/* 一般IO的路径 */
		written = generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}

out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(__generic_file_write_iter);

/**
2024年7月15日23:54:49
fops的写入回调
 * generic_file_write_iter - write data to a file
 * @iocb:	IO state structure
 * @from:	iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file
 * and acquires i_mutex as needed.
 * Return:
 * * negative error code if no data has been written at all of
 *   vfs_fsync_range() failed for a synchronous write
 * * number of bytes written, even for truncated writes
 */
ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	
	/* check，todo */
	ret = generic_write_checks(iocb, from);

	if (ret > 0)/* 调用generic write */
		ret = __generic_file_write_iter(iocb, from);
	
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
EXPORT_SYMBOL(generic_file_write_iter);

/**
2024年7月15日23:45:54
release old fs-specific metadata on a page；
 * try_to_release_page() - release old fs-specific metadata on a page
 *
 * @page: the page which the kernel is trying to free
 * @gfp_mask: memory allocation flags (and I/O mode)
 *
 * The address_space is to try to release any data against the page
 * (presumably at page->private).
 *
 * This may also be called if PG_fscache is set on a page, indicating that the
 * page is known to the local caching routines.
 *
 * The @gfp_mask argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block (__GFP_RECLAIM & __GFP_FS).
 *
 * Return: %1 if the release was successful, otherwise return zero.
 */
int try_to_release_page(struct page *page, gfp_t gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));

	if (PageWriteback(page))
		return 0;

	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	/* 其实就是清除priv数据 */
	return try_to_free_buffers(page);
}

EXPORT_SYMBOL(try_to_release_page);

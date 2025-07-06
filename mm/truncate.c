// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/truncate.c - code for taking down pages from address_spaces
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 10Sep2002	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/backing-dev.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/pagevec.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/shmem_fs.h>
#include <linux/rmap.h>
#include "internal.h"

/*
 * Regular page slots are stabilized by the page lock even without the tree
 * itself locked.  These unlocked entries need verification under the tree
 * lock.
 常规的页面插槽即使没有树本身被锁定，也可以通过页面锁稳定。这些未锁定的条目需要在树锁下进行验证。

 entry folio在mapping的索引是index. 这个folio是个不正常的slot
 */
static inline void __clear_shadow_entry(struct address_space *mapping,
				pgoff_t index, void *entry)
{
	XA_STATE(xas, &mapping->i_pages, index);

	xas_set_update(&xas, workingset_update_node);
	if (xas_load(&xas) != entry)
		return;
	xas_store(&xas, NULL);
}

static void clear_shadow_entry(struct address_space *mapping, pgoff_t index,
			       void *entry)
{
	spin_lock(&mapping->host->i_lock);
	xa_lock_irq(&mapping->i_pages);
	__clear_shadow_entry(mapping, index, entry);
	xa_unlock_irq(&mapping->i_pages);
	if (mapping_shrinkable(mapping))
		inode_add_lru(mapping->host);
	spin_unlock(&mapping->host->i_lock);
}

/*
 * Unconditionally remove exceptional entries. Usually called from truncate
 * path. Note that the folio_batch may be altered by this function by removing
 * exceptional entries similar to what folio_batch_remove_exceptionals() does.
 无条件的从fbatch删除异常条目。通常从截断路径调用。请注意，此函数可能通过删除异常条目而更改folio_batch，
 类似于folio_batch_remove_exceptionals()的操作。
 */
static void truncate_folio_batch_exceptionals(struct address_space *mapping,
				struct folio_batch *fbatch, pgoff_t *indices)
{
	int i, j;
	bool dax;

	/* Handled by shmem itself */
	if (shmem_mapping(mapping))
		return;

	for (j = 0; j < folio_batch_count(fbatch); j++)
		if (xa_is_value(fbatch->folios[j]))
			break;
	/* 现在0到j都是合法的 */

	if (j == folio_batch_count(fbatch))
		return; // 说明没有异常条目?

	dax = dax_mapping(mapping);
	if (!dax) {
		spin_lock(&mapping->host->i_lock);
		xa_lock_irq(&mapping->i_pages);
	}

	for (i = j; i < folio_batch_count(fbatch); i++) {/* 现在处理从j到末尾的 */
		struct folio *folio = fbatch->folios[i];
		pgoff_t index = indices[i];

		if (!xa_is_value(folio)) {// 如果是正常条目,就往前搬
			fbatch->folios[j++] = folio;
			continue;
		}

		if (unlikely(dax)) {
			dax_delete_mapping_entry(mapping, index);
			continue;
		}
		// 如果不正常的条目,执行clear_shadow_entry
		__clear_shadow_entry(mapping, index, folio);
	}

	if (!dax) {
		xa_unlock_irq(&mapping->i_pages);
		if (mapping_shrinkable(mapping))
			inode_add_lru(mapping->host);
		spin_unlock(&mapping->host->i_lock);
	}
	fbatch->nr = j;
}

/*
处理mapping的特殊页
 * Invalidate exceptional entry if easily possible. This handles exceptional
 * entries for invalidate_inode_pages().
 */
static int invalidate_exceptional_entry(struct address_space *mapping,
					pgoff_t index, void *entry)
{
	/* Handled by shmem itself, or for DAX we do nothing. */
	if (shmem_mapping(mapping) || dax_mapping(mapping))
		return 1;
	clear_shadow_entry(mapping, index, entry);
	return 1;
}

/*
 * Invalidate exceptional entry if clean. This handles exceptional entries for
 * invalidate_inode_pages2() so for DAX it evicts only clean entries.
 */
static int invalidate_exceptional_entry2(struct address_space *mapping,
					 pgoff_t index, void *entry)
{
	/* Handled by shmem itself */
	if (shmem_mapping(mapping))
		return 1;
	if (dax_mapping(mapping))
		return dax_invalidate_mapping_entry_sync(mapping, index);
	clear_shadow_entry(mapping, index, entry);
	return 1;
}

/**
 * folio_invalidate - Invalidate part or all of a folio.
 * @folio: The folio which is affected.
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * folio_invalidate() is called when all or part of the folio has become
 * invalidated by a truncate operation.
 *
 * folio_invalidate() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void folio_invalidate(struct folio *folio, size_t offset, size_t length)
{
	const struct address_space_operations *aops = folio->mapping->a_ops;

	if (aops->invalidate_folio)
		aops->invalidate_folio(folio, offset, length);
}
EXPORT_SYMBOL_GPL(folio_invalidate);

/*
从pagecache截断这个folio
=================
解除映射, 移除绑定的priv, 清除dirty
 * If truncate cannot remove the fs-private metadata from the page, the page
 * becomes orphaned.  It will be left on the LRU and may even be mapped into
 * user pagetables if we're racing with filemap_fault().
 * 如果截断无法从页面中删除fs-private元数据, 则页面将变为孤立的。它将保留在LRU上, 
 甚至可能映射到用户页表中, 如果我们正在与filemap_fault()竞争。
 
 * We need to bail out if page->mapping is no longer equal to the original
 * mapping.  This happens a) when the VM reclaimed the page while we waited on
 * its lock, b) when a concurrent invalidate_mapping_pages got there first and
 * c) when tmpfs swizzles a page between a tmpfs inode and swapper_space.
 我们需要退出, 如果page->mapping不再等于原始映射。这发生在a)当VM在我们等待其锁时回收页面时,
 */
static void truncate_cleanup_folio(struct folio *folio)
{
	if (folio_mapped(folio)) // 如果是mapped的文件页
		unmap_mapping_folio(folio); // 解除映射

	if (folio_has_private(folio)) // 如果有私有数据, 移除
		folio_invalidate(folio, 0, folio_size(folio));

	/*
	 * Some filesystems seem to re-dirty the page even after
	 * the VM has canceled the dirty bit (eg ext3 journaling).
	 * Hence dirty accounting check is placed after invalidation.
	 一些文件系统似乎在VM取消了脏位之后重新设置页面为脏页(例如ext3日志)。
	 因此, 在使无效之后放置了脏计数检查。
	 ==================
	 // 取消脏标志*/
	folio_cancel_dirty(folio); 
	folio_clear_mappedtodisk(folio);
}
/* 
从xas移除
取消page的脏位, 然后从xas移除
*/
int truncate_inode_folio(struct address_space *mapping, struct folio *folio)
{
	if (folio->mapping != mapping)
		return -EIO;

	/* 解除映射, 移除绑定的priv, 清除dirty */
	truncate_cleanup_folio(folio);
	filemap_remove_folio(folio); // 从xas移除
	return 0;
}

/*
 * Handle partial folios.  The folio may be entirely within the
 * range if a split has raced with us.  If not, we zero the part of the
 * folio that's within the [start, end] range, and then split the folio if
 * it's large.  split_page_range() will discard pages which now lie beyond
 * i_size, and we rely on the caller to discard pages which lie within a
 * newly created hole.
 * 处理部分folio。如果分裂与我们同时进行, folio可能完全在范围内。如果不是, 
 我们将清零在[start, end]范围内的folio的部分, 然后如果folio很大, 就分裂folio。
 * Returns false if splitting failed so the caller can avoid
 * discarding the entire folio which is stubbornly unsplit.
 返回false, 如果分裂失败, 这样调用者就可以避免丢弃顽固不分裂的整个folio。
 */
bool truncate_inode_partial_folio(struct folio *folio, loff_t start, loff_t end)
{
	loff_t pos = folio_pos(folio);
	unsigned int offset, length;

	if (pos < start)
		offset = start - pos;
	else
		offset = 0;
	length = folio_size(folio);
	if (pos + length <= (u64)end)
		length = length - offset;
	else
		length = end + 1 - pos - offset;

	folio_wait_writeback(folio);
	if (length == folio_size(folio)) {
		truncate_inode_folio(folio->mapping, folio);
		return true;
	}

	/*
	 * We may be zeroing pages we're about to discard, but it avoids
	 * doing a complex calculation here, and then doing the zeroing
	 * anyway if the page split fails.
	 */
	folio_zero_range(folio, offset, length);

	if (folio_has_private(folio))
		folio_invalidate(folio, offset, length);
	if (!folio_test_large(folio))
		return true;
	if (split_folio(folio) == 0)
		return true;
	if (folio_test_dirty(folio))
		return false;
	truncate_inode_folio(folio->mapping, folio);
	return true;
}

/*
 * Used to get rid of pages on hardware memory corruption.
 */
int generic_error_remove_page(struct address_space *mapping, struct page *page)
{
	VM_BUG_ON_PAGE(PageTail(page), page);

	if (!mapping)
		return -EINVAL;
	/*
	 * Only punch for normal data pages for now.
	 * Handling other types like directories would need more auditing.
	 */
	if (!S_ISREG(mapping->host->i_mode))
		return -EIO;
	return truncate_inode_folio(mapping, page_folio(page));
}
EXPORT_SYMBOL(generic_error_remove_page);

/* 
从pagecache移除这个folio
如果mapping是干净的, 并且没有处于回写状态
就移除folio的priv等成员
然后在mapping的xas里面屏蔽清零folio所在的条目
=========================================================
主要是内核很多fs实现会调用, 清理mapping的空间
==========================================================
返回0 ,表示没有移除 */
static long mapping_evict_folio(struct address_space *mapping,
		struct folio *folio)
{
	if (folio_test_dirty(folio) || folio_test_writeback(folio))
		return 0;
	/* The refcount will be elevated if any page in the folio is mapped
	说明这个页面还在被映射
	比如mmap, shmem什么的
	 */
	if (folio_ref_count(folio) >
			folio_nr_pages(folio) + folio_has_private(folio) + 1)
		return 0;
	//在驱逐之前, 释放相关priv等成员（比如绑定的buffer什么的)
	if (!filemap_release_folio(folio, 0))
		return 0;
	/*  把folio从所在的mapping移除, 
		把在xas的条目清零什么的 */
	return remove_mapping(mapping, folio);
}

/**
20250701005528
 * invalidate_inode_page() - Remove an unused page from the pagecache.
 从pagecache移除一个页面
 目前只有处理文件页缺页时如果被poisoned的话会调用
 * @page: The page to remove.
 *
 * Safely invalidate one page from its pagecache mapping.
 * It only drops clean, unused pages.
 *
 * Context: Page must be locked.
 * Return: The number of pages successfully removed.
 */
long invalidate_inode_page(struct page *page)
{
	struct folio *folio = page_folio(page);
	struct address_space *mapping = folio_mapping(folio);

	/* The page may have been truncated before it was locked */
	if (!mapping)
		return 0;
	return mapping_evict_folio(mapping, folio);
}

/**
 * truncate_inode_pages_range - truncate range of pages specified by start & end byte offsets
 戒断由开始和结束字节偏移量指定的页面范围
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 * @lend: offset to which to truncate (inclusive)
 *
 * Truncate the page cache, removing the pages that are between
 * specified offsets (and zeroing out partial pages
 * if lstart or lend + 1 is not page aligned).
 *截断页面缓存, 删除指定偏移量之间的页面(如果lstart或lend + 1不是页面对齐的, 则将部分页面清零)
 * Truncate takes two passes - the first pass is nonblocking.  It will not
 * block on page locks and it will not block on writeback.  The second pass
 * will wait.  This is to prevent as much IO as possible in the affected region.
 * The first pass will remove most pages, so the search cost of the second pass
 * is low.
 * 分为两个阶段, 第一阶段是非阻塞的, 不会阻塞在页面锁上, 也不会阻塞在写回上, 第二阶段会等待, 
 这是为了尽可能减少受影响区域的IO
 * We pass down the cache-hot hint to the page freeing code.  Even if the
 * mapping is large, it is probably the case that the final pages are the most
 * recently touched, and freeing happens in ascending file offset order.
 * 我们将缓存热提示传递给页面释放代码, 即使映射很大, 最终的页面可能是最近访问的, 并且释放按照
 升序文件偏移顺序进行
 * Note that since ->invalidate_folio() accepts range to invalidate
 * truncate_inode_pages_range is able to handle cases where lend + 1 is not
 * page aligned properly.
 注意, 由于->invalidate_folio()接受范围来使无效, truncate_inode_pages_range能够处理lend + 1
 不正确对齐的情况
 */
void truncate_inode_pages_range(struct address_space *mapping,
				loff_t lstart, loff_t lend)
{
	pgoff_t		start;		/* inclusive */
	pgoff_t		end;		/* exclusive */
	struct folio_batch fbatch;
	pgoff_t		indices[PAGEVEC_SIZE];
	pgoff_t		index;
	int		i;
	struct folio	*folio;
	bool		same_folio;

	if (mapping_empty(mapping))
		return;

	/*
	 * 'start' and 'end' always covers the range of pages to be fully
	 * truncated. Partial pages are covered with 'partial_start' at the
	 * start of the range and 'partial_end' at the end of the range.
	 * Note that 'end' is exclusive while 'lend' is inclusive.
	 开始和结束总是覆盖要完全截断的页面范围, 部分页面由范围开始处的'partial_start'
	 和范围结束处的'partial_end'覆盖
	 */
	start = (lstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (lend == -1)
		/*
		 * lend == -1 indicates end-of-file so we have to set 'end'
		 * to the highest possible pgoff_t and since the type is
		 * unsigned we're using -1.
		 */
		end = -1;
	else
		end = (lend + 1) >> PAGE_SHIFT;

	folio_batch_init(&fbatch);
	index = start;
	while (index < end && find_lock_entries(mapping, &index, end - 1,
			&fbatch, indices)) {// 先收拢一部分
			//先截断收拢的fbatch里面的异常条目
		truncate_folio_batch_exceptionals(mapping, &fbatch, indices);
		// 现在fbatch里面的都是正常的条目
		for (i = 0; i < folio_batch_count(&fbatch); i++)
			truncate_cleanup_folio(fbatch.folios[i]);
		// 开始删除fbatch里面的页,从xas里面删除
		delete_from_page_cache_batch(mapping, &fbatch);
		for (i = 0; i < folio_batch_count(&fbatch); i++)
			folio_unlock(fbatch.folios[i]);
		// 释放fbatch到buddy
		folio_batch_release(&fbatch);
		cond_resched();    
	}

	same_folio = (lstart >> PAGE_SHIFT) == (lend >> PAGE_SHIFT);
	folio = __filemap_get_folio(mapping, lstart >> PAGE_SHIFT, FGP_LOCK, 0);
	if (!IS_ERR(folio)) {
		same_folio = lend < folio_pos(folio) + folio_size(folio);
		if (!truncate_inode_partial_folio(folio, lstart, lend)) {
			start = folio_next_index(folio);
			if (same_folio)
				end = folio->index;
		}
		folio_unlock(folio);
		folio_put(folio);
		folio = NULL;
	}

	if (!same_folio) {
		folio = __filemap_get_folio(mapping, lend >> PAGE_SHIFT,
						FGP_LOCK, 0);
		if (!IS_ERR(folio)) {
			if (!truncate_inode_partial_folio(folio, lstart, lend))
				end = folio->index;
			folio_unlock(folio);
			folio_put(folio);
		}
	}

	index = start;
	while (index < end) {
		cond_resched();
		if (!find_get_entries(mapping, &index, end - 1, &fbatch,
				indices)) {
			/* If all gone from start onwards, we're done */
			if (index == start)
				break;
			/* Otherwise restart to make sure all gone */
			index = start;
			continue;
		}
		// 刚刚获得了一些到fbatch
        // 下面处理batch
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			struct folio *folio = fbatch.folios[i];

			/* We rely upon deletion not changing page->index */

			if (xa_is_value(folio))
				continue;

			folio_lock(folio);
			VM_BUG_ON_FOLIO(!folio_contains(folio, indices[i]), folio);
			folio_wait_writeback(folio);
			// 从xas移除
			truncate_inode_folio(mapping, folio);
			folio_unlock(folio);
		}
		// 这里继续调整batch内的元素, 忽略异常的, 把正常的往前搬
		truncate_folio_batch_exceptionals(mapping, &fbatch, indices);
		// 释放到buddy
		folio_batch_release(&fbatch);
	}
}
EXPORT_SYMBOL(truncate_inode_pages_range);

/**
 
 * truncate_inode_pages - truncate *all* the pages from an offset
 截断从偏移量开始的所有页面
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 *
 * Called under (and serialised by) inode->i_rwsem and
 * mapping->invalidate_lock.
 * 在inode->i_rwsem和mapping->invalidate_lock下调用(并串行化)。
 * Note: When this function returns, there can be a page in the process of
 * deletion (inside __filemap_remove_folio()) in the specified range.  Thus
 * mapping->nrpages can be non-zero when this function returns even after
 * truncation of the whole mapping.
 注意: 当此函数返回时, 指定范围内可能有一个正在删除的页面(在__filemap_remove_folio()中)。
 因此, 即使整个映射被截断, 当此函数返回时, mapping->nrpages可能不为零。
 */
void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
	truncate_inode_pages_range(mapping, lstart, (loff_t)-1);
}
EXPORT_SYMBOL(truncate_inode_pages);

/**
清除inode之前清除pagecache页面
 * truncate_inode_pages_final - truncate *all* pages before inode dies
 * @mapping: mapping to truncate
 *
 * Called under (and serialized by) inode->i_rwsem.
 *
 * Filesystems have to use this in the .evict_inode path to inform the
 * VM that this is the final truncate and the inode is going away.
 文件系统必须在.evict_inode路径中使用此函数来通知VM这是最终截断, 并且inode即将消失。
 */
void truncate_inode_pages_final(struct address_space *mapping)
{
	/*
	 * Page reclaim can not participate in regular inode lifetime
	 * management (can't call iput()) and thus can race with the
	 * inode teardown.  Tell it when the address space is exiting,
	 * so that it does not install eviction information after the
	 * final truncate has begun.
	  页面回收不能参与常规inode生命周期管理(不能调用iput()), 因此可能与inode的驱逐发生race。
	  告诉它address space何时退出, 以便在最终截断开始后不进行驱逐信息。
	 */
	mapping_set_exiting(mapping);

	if (!mapping_empty(mapping)) {
		/*
		 * As truncation uses a lockless tree lookup, cycle
		 * the tree lock to make sure any ongoing tree
		 * modification that does not see AS_EXITING is
		 * completed before starting the final truncate.
		 由于截断使用无锁树查找, 因此循环树锁以确保在开始最终截断之前完成任何不看到
		 AS_EXITING的正在进行的树修改。
		 */
		xa_lock_irq(&mapping->i_pages);
		xa_unlock_irq(&mapping->i_pages);
	}
	/*  */
	truncate_inode_pages(mapping, 0);
}
EXPORT_SYMBOL(truncate_inode_pages_final);

/**
 * mapping_try_invalidate - Invalidate all the evictable folios of one inode
 无效化inode的范围内的所有可驱逐的folio. 注意不是截断全部的folio
 =================
 很多fs实现都会调用这个函数, 清理mapping的缓存
 * @mapping: the address_space which holds the folios to invalidate
 * @start: the offset 'from' which to invalidate
 * @end: the offset 'to' which to invalidate (inclusive)
 * @nr_failed: How many folio invalidations failed
 *
 * This function is similar to invalidate_mapping_pages(), except that it
 * returns the number of folios which could not be evicted in @nr_failed.
 函数类似于invalidate_mapping_pages()，只是它返回无法驱逐的folio的数量
 */
unsigned long mapping_try_invalidate(struct address_space *mapping,
		pgoff_t start, pgoff_t end, unsigned long *nr_failed)
{
	pgoff_t indices[PAGEVEC_SIZE];
	struct folio_batch fbatch;
	pgoff_t index = start;
	unsigned long ret;
	unsigned long count = 0;
	int i;

	folio_batch_init(&fbatch);
	/* 从mapping数组里面的【index,end】范围内查找page放进fbatch, indices数组存储对应page的idx */
	while (find_lock_entries(mapping, &index, end, &fbatch, indices)) {
		/* 遍历刚才取到的批次 */
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			/* 取出批次里的一个folio */
			struct folio *folio = fbatch.folios[i];

			/* We rely upon deletion not changing folio->index */

			/* 这是mapping里的特殊页 */
			if (xa_is_value(folio)) {
				count += invalidate_exceptional_entry(mapping,
							     indices[i], folio);
				continue;
			}
			//从pagecache移除这个folio
			ret = mapping_evict_folio(mapping, folio);
			folio_unlock(folio);
			/*
			 * Invalidation is a hint that the folio is no longer
			 * of interest and try to speed up its reclaim.
			 */
			if (!ret) {// 没有成功移除的情况
				deactivate_file_folio(folio);
				/* Likely in the lru cache of a remote CPU */
				if (nr_failed)
					(*nr_failed)++;
			}
			count += ret;
		}
		// 处理fbatch, 跳过和整理搬移数组里面的可以free的条目
		folio_batch_remove_exceptionals(&fbatch);
		// 把这些清理掉的page归还到系统的伙伴系统
		folio_batch_release(&fbatch);
		cond_resched();
	}
	return count;
}

/**
 * invalidate_mapping_pages - Invalidate all clean, unlocked cache of one inode
 无效化inode的所有干净的未锁定的缓存
 =======================================================、
 很多调用
 * @mapping: the address_space which holds the cache to invalidate
 * @start: the offset 'from' which to invalidate
 * @end: the offset 'to' which to invalidate (inclusive)
 *
 * This function removes pages that are clean, unmapped and unlocked,
 * as well as shadow entries. It will not block on IO activity.
 * 这个函数删除干净的、未映射的、未锁定的页面，以及影子条目。它不会阻塞IO活动。
 * If you want to remove all the pages of one inode, regardless of
 * their use and writeback state, use truncate_inode_pages().
 * 如果要删除一个inode的所有页面，无论其使用和回写状态如何，请使用truncate_inode_pages()。
 * Return: The number of indices that had their contents invalidated
 */
unsigned long invalidate_mapping_pages(struct address_space *mapping,
		pgoff_t start, pgoff_t end)
{
	return mapping_try_invalidate(mapping, start, end, NULL);
}
EXPORT_SYMBOL(invalidate_mapping_pages);

/*
从mapping移除页面 (回写中的, 脏页不处理)

===========================

返回1表示成功
 * This is like invalidate_inode_page(), except it ignores the page's
 * refcount.  We do this because invalidate_inode_pages2() needs stronger
 * invalidation guarantees, and cannot afford to leave pages behind because
 * shrink_page_list() has a temp ref on them, or because they're transiently
 * sitting in the folio_add_lru() caches.
   这个函数类似于invalidate_inode_page(), 但是它忽略了页面的引用计数。
   我们这样做是因为invalidate_inode_pages2()需要更强的无效化保证, 不能因为shrink_page_list()
   对它们有一个临时引用 或者 因为它们暂时停留在folio_add_lru()缓存中而留下页面
 */
static int invalidate_complete_folio2(struct address_space *mapping,
					struct folio *folio)
{
	if (folio->mapping != mapping)
		return 0;

	// 检查是否有私有数据, 有的话, 移除
	if (!filemap_release_folio(folio, GFP_KERNEL))
		return 0;

	spin_lock(&mapping->host->i_lock);
	xa_lock_irq(&mapping->i_pages);
	// 不处理dirty的
	if (folio_test_dirty(folio))
		goto failed;

	BUG_ON(folio_has_private(folio));
	// 从xas移除
	__filemap_remove_folio(folio, NULL);
	xa_unlock_irq(&mapping->i_pages);
	if (mapping_shrinkable(mapping))
		inode_add_lru(mapping->host);
	spin_unlock(&mapping->host->i_lock);
	// 调用mapping的free_folio回调
	filemap_free_folio(mapping, folio);
	return 1;
failed:
	xa_unlock_irq(&mapping->i_pages);
	spin_unlock(&mapping->host->i_lock);
	return 0;
}

static int folio_launder(struct address_space *mapping, struct folio *folio)
{
	if (!folio_test_dirty(folio))
		return 0;
	if (folio->mapping != mapping || mapping->a_ops->launder_folio == NULL)
		return 0;
	return mapping->a_ops->launder_folio(folio);
}

/**

 * invalidate_inode_pages2_range - remove range of pages from an address_space
 从address_space中删除页面范围. 一个个的等待写回完成,解除映射?
 =============
 truncate也调用
 一种调用原因可能是, mapping的start,end范围内进行了直接io, 把这些缓存的内容给invalidate
 * @mapping: the address_space
 * @start: the page offset 'from' which to invalidate
 * @end: the page offset 'to' which to invalidate (inclusive)
 *
 * Any pages which are found to be mapped into pagetables are unmapped prior to
 * invalidation.
 * 任何发现映射到页表中的页面在使无效之前都会被取消映射。
 * Return: -EBUSY if any pages could not be invalidated.
 */
int invalidate_inode_pages2_range(struct address_space *mapping,
				  pgoff_t start, pgoff_t end)
{
	pgoff_t indices[PAGEVEC_SIZE];
	struct folio_batch fbatch;
	pgoff_t index;
	int i;
	int ret = 0;
	int ret2 = 0;
	int did_range_unmap = 0;

	if (mapping_empty(mapping))
		return 0;

	folio_batch_init(&fbatch);
	index = start;
	while (find_get_entries(mapping, &index, end, &fbatch, indices)) {/*
		收拢一些到fbatch */
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			struct folio *folio = fbatch.folios[i];
			/* We rely upon deletion not changing folio->index */
			if (xa_is_value(folio)) {/* 不是正常的pagecache页面 */
				if (!invalidate_exceptional_entry2(mapping,
						indices[i], folio)) //如果不可以忽略的话?
					ret = -EBUSY;
				continue; //跳过
			}
			/* 遇到被映射的文件页, 解除映射 */
			if (!did_range_unmap && folio_mapped(folio)) {
				/* 只会在遇到被映射的folio时进来执行一次
					执行的是解除映射 */
				/*
				 * If folio is mapped, before taking its lock,
				 * zap the rest of the file in one hit.
				 这个pagecache的folio被映射了(被映射的文件页)
				 解除映射
				 */
				unmap_mapping_pages(mapping, indices[i],
						(1 + end - indices[i]), false);
				did_range_unmap = 1;
			}
			folio_lock(folio);
			if (unlikely(folio->mapping != mapping)) {// 这是什么情况?
				folio_unlock(folio);
				continue;
			}
			VM_BUG_ON_FOLIO(!folio_contains(folio, indices[i]), folio);
			folio_wait_writeback(folio); // 等待写回完成

			if (folio_mapped(folio))
				unmap_mapping_folio(folio); // 这里遍历相关的全部vma, 然后遍历页表解除映射
			BUG_ON(folio_mapped(folio));

			/* 现在mapping里面的这个folio, 写回完成了, 映射解除了 */
			ret2 = folio_launder(mapping, folio);
			if (ret2 == 0) {
				if (!invalidate_complete_folio2(mapping, folio))
					ret2 = -EBUSY;
			}
			if (ret2 < 0)
				ret = ret2;
			folio_unlock(folio);
		}
		/* 去除batch里面is_value的folio */
		folio_batch_remove_exceptionals(&fbatch);
		folio_batch_release(&fbatch); // 释放到buddy
		cond_resched();
	}
	/*
	 * For DAX we invalidate page tables after invalidating page cache.  We
	 * could invalidate page tables while invalidating each entry however
	 * that would be expensive. And doing range unmapping before doesn't
	 * work as we have no cheap way to find whether page cache entry didn't
	 * get remapped later.
	 */
	if (dax_mapping(mapping)) {
		unmap_mapping_pages(mapping, start, end - start + 1, false);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2_range);

/**
 * invalidate_inode_pages2 - remove all pages from an address_space
  移除address_space中的所有页面
 * @mapping: the address_space
 *
 * Any pages which are found to be mapped into pagetables are unmapped prior to
 * invalidation.
 *
 * Return: -EBUSY if any pages could not be invalidated.
 */
int invalidate_inode_pages2(struct address_space *mapping)
{
	return invalidate_inode_pages2_range(mapping, 0, -1);
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2);

/**
 * truncate_pagecache - unmap and remove pagecache that has been truncated
  解除映射和删除已经被截断的pagecache
 * @inode: inode
 * @newsize: new file size
 *
 * inode's new i_size must already be written before truncate_pagecache
 * is called.
 *
 * This function should typically be called before the filesystem
 * releases resources associated with the freed range (eg. deallocates
 * blocks). This way, pagecache will always stay logically coherent
 * with on-disk format, and the filesystem would not have to deal with
 * situations such as writepage being called for a page that has already
 * had its underlying blocks deallocated.
 这个函数通常在文件系统释放与释放范围相关的资源之前调用(例如释放块)。
 这样, pagecache将始终在逻辑上与磁盘格式一致, 文件系统不必处理诸如writepage
 被调用的页面已经释放其基础块的情况。
--------------------------------------------------------------------------

 */
void truncate_pagecache(struct inode *inode, loff_t newsize)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t holebegin = round_up(newsize, PAGE_SIZE);

	/*
	 * unmap_mapping_range is called twice, first simply for
	 * efficiency so that truncate_inode_pages does fewer
	 * single-page unmaps.  However after this first call, and
	 * before truncate_inode_pages finishes, it is possible for
	 * private pages to be COWed, which remain after
	 * truncate_inode_pages finishes, hence the second
	 * unmap_mapping_range call must be made for correctness.
	 unmap_mapping_range被调用两次, 首先仅仅是为了效率, 以便truncate_inode_pages
	 做更少的单页解除映射。然而在第一次调用之后, 在truncate_inode_pages完成之前,
	 可能会对私有页面进行COW, 这些页面在truncate_inode_pages完成后仍然存在,
	 因此第二次unmap_mapping_range调用必须为了正确性。
	 */
	// 找到并遍历涉及的全部vma, 然后遍历页表解除映射
	unmap_mapping_range(mapping, holebegin, 0, 1);
	// 这里开始truncate操作
	truncate_inode_pages(mapping, newsize);
	unmap_mapping_range(mapping, holebegin, 0, 1);
}
EXPORT_SYMBOL(truncate_pagecache);

/**
 * truncate_setsize - update inode and pagecache for a new file size
 更新inode和pagecache的新文件大小
 * @inode: inode
 * @newsize: new file size
 *
 * truncate_setsize updates i_size and performs pagecache truncation (if
 * necessary) to @newsize. It will be typically be called from the filesystem's
 * setattr function when ATTR_SIZE is passed in.
 *
 * Must be called with a lock serializing truncates and writes (generally
 * i_rwsem but e.g. xfs uses a different lock) and before all filesystem
 * specific block truncation has been performed.
 */
void truncate_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize = inode->i_size;

	i_size_write(inode, newsize);
	if (newsize > oldsize)
		pagecache_isize_extended(inode, oldsize, newsize);
	truncate_pagecache(inode, newsize);
}
EXPORT_SYMBOL(truncate_setsize);

/**
 * pagecache_isize_extended - update pagecache after extension of i_size
 更新i_size后更新pagecache
 * @inode:	inode for which i_size was extended
 * @from:	original inode size
 * @to:		new inode size
 *
 * Handle extension of inode size either caused by extending truncate or by
 * write starting after current i_size. We mark the page straddling current
 * i_size RO so that page_mkwrite() is called on the nearest write access to
 * the page.  This way filesystem can be sure that page_mkwrite() is called on
 * the page before user writes to the page via mmap after the i_size has been
 * changed.
 *
 * The function must be called after i_size is updated so that page fault
 * coming after we unlock the page will already see the new i_size.
 * The function must be called while we still hold i_rwsem - this not only
 * makes sure i_size is stable but also that userspace cannot observe new
 * i_size value before we are prepared to store mmap writes at new inode size.
 */
void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to)
{
	int bsize = i_blocksize(inode);
	loff_t rounded_from;
	struct page *page;
	pgoff_t index;

	WARN_ON(to > inode->i_size);

	if (from >= to || bsize == PAGE_SIZE)
		return;
	/* Page straddling @from will not have any hole block created? */
	rounded_from = round_up(from, bsize);
	if (to <= rounded_from || !(rounded_from & (PAGE_SIZE - 1)))
		return;

	index = from >> PAGE_SHIFT;
	page = find_lock_page(inode->i_mapping, index);
	/* Page not cached? Nothing to do */
	if (!page)
		return;
	/*
	 * See clear_page_dirty_for_io() for details why set_page_dirty()
	 * is needed.
	 page_mkclean解除页表对这个page的脏位
	 set_page_dirty发起page的回写
	 */
	if (page_mkclean(page))
		set_page_dirty(page);
	unlock_page(page);
	put_page(page);
}
EXPORT_SYMBOL(pagecache_isize_extended);

/**
 * truncate_pagecache_range - unmap and remove pagecache that is hole-punched
 解除映射和删除被打洞的pagecache
 * @inode: inode
 * @lstart: offset of beginning of hole
 * @lend: offset of last byte of hole
 *
 * This function should typically be called before the filesystem
 * releases resources associated with the freed range (eg. deallocates
 * blocks). This way, pagecache will always stay logically coherent
 * with on-disk format, and the filesystem would not have to deal with
 * situations such as writepage being called for a page that has already
 * had its underlying blocks deallocated.
 */
void truncate_pagecache_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t unmap_start = round_up(lstart, PAGE_SIZE);
	loff_t unmap_end = round_down(1 + lend, PAGE_SIZE) - 1;
	/*
	 * This rounding is currently just for example: unmap_mapping_range
	 * expands its hole outwards, whereas we want it to contract the hole
	 * inwards.  However, existing callers of truncate_pagecache_range are
	 * doing their own page rounding first.  Note that unmap_mapping_range
	 * allows holelen 0 for all, and we allow lend -1 for end of file.
	 */

	/*
	 * Unlike in truncate_pagecache, unmap_mapping_range is called only
	 * once (before truncating pagecache), and without "even_cows" flag:
	 * hole-punching should not remove private COWed pages from the hole.
	 */
	if ((u64)unmap_end > (u64)unmap_start)
		unmap_mapping_range(mapping, unmap_start,
				    1 + unmap_end - unmap_start, 0);
	truncate_inode_pages_range(mapping, lstart, lend);
}
EXPORT_SYMBOL(truncate_pagecache_range);

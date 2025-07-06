// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>

#include <linux/mm.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/secretmem.h>

#include <linux/sched/signal.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/shmem_fs.h>

#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

#include "internal.h"

struct follow_page_context {
	struct dev_pagemap *pgmap;
	unsigned int page_mask;
};

static inline void sanity_check_pinned_pages(struct page **pages,
					     unsigned long npages)
{
	if (!IS_ENABLED(CONFIG_DEBUG_VM))
		return;

	/*
	 * We only pin anonymous pages if they are exclusive. Once pinned, we
	 * can no longer turn them possibly shared and PageAnonExclusive() will
	 * stick around until the page is freed.
	 *
	 * We'd like to verify that our pinned anonymous pages are still mapped
	 * exclusively. The issue with anon THP is that we don't know how
	 * they are/were mapped when pinning them. However, for anon
	 * THP we can assume that either the given page (PTE-mapped THP) or
	 * the head page (PMD-mapped THP) should be PageAnonExclusive(). If
	 * neither is the case, there is certainly something wrong.
	 */
	for (; npages; npages--, pages++) {
		struct page *page = *pages;
		struct folio *folio = page_folio(page);

		if (is_zero_page(page) ||
		    !folio_test_anon(folio))
			continue;
		if (!folio_test_large(folio) || folio_test_hugetlb(folio))
			VM_BUG_ON_PAGE(!PageAnonExclusive(&folio->page), page);
		else
			/* Either a PTE-mapped or a PMD-mapped THP. */
			VM_BUG_ON_PAGE(!PageAnonExclusive(&folio->page) &&
				       !PageAnonExclusive(page), page);
	}
}

/*
 * Return the folio with ref appropriately incremented,
 * or NULL if that failed.
 */
static inline struct folio *try_get_folio(struct page *page, int refs)
{
	struct folio *folio;

retry:
	folio = page_folio(page);
	if (WARN_ON_ONCE(folio_ref_count(folio) < 0))
		return NULL;
	if (unlikely(!folio_ref_try_add_rcu(folio, refs)))
		return NULL;

	/*
	 * At this point we have a stable reference to the folio; but it
	 * could be that between calling page_folio() and the refcount
	 * increment, the folio was split, in which case we'd end up
	 * holding a reference on a folio that has nothing to do with the page
	 * we were given anymore.
	 * So now that the folio is stable, recheck that the page still
	 * belongs to this folio.
	 */
	if (unlikely(page_folio(page) != folio)) {
		if (!put_devmap_managed_page_refs(&folio->page, refs))
			folio_put_refs(folio, refs);
		goto retry;
	}

	return folio;
}

/**
 * try_grab_folio() - Attempt to get or pin a folio.
 尝试去获取或者固定一个folio
 * @page:  pointer to page to be grabbed
 * @refs:  the value to (effectively) add to the folio's refcount
 * @flags: gup flags: these are the FOLL_* flag values.
 *
 * "grab" names in this file mean, "look at flags to decide whether to use
 * FOLL_PIN or FOLL_GET behavior, when incrementing the folio's refcount.
 *
 * Either FOLL_PIN or FOLL_GET (or neither) must be set, but not both at the
 * same time. (That's true throughout the get_user_pages*() and
 * pin_user_pages*() APIs.) Cases:
 *
 *    FOLL_GET: folio's refcount will be incremented by @refs.
 *
 *    FOLL_PIN on large folios: folio's refcount will be incremented by
 *    @refs, and its pincount will be incremented by @refs.
 *
 *    FOLL_PIN on single-page folios: folio's refcount will be incremented by
 *    @refs * GUP_PIN_COUNTING_BIAS.
 *
 * Return: The folio containing @page (with refcount appropriately
 * incremented) for success, or NULL upon failure. If neither FOLL_GET
 * nor FOLL_PIN was set, that's considered failure, and furthermore,
 * a likely bug in the caller, so a warning is also emitted.
 */
struct folio *try_grab_folio(struct page *page, int refs, unsigned int flags)
{
	struct folio *folio;

	if (WARN_ON_ONCE((flags & (FOLL_GET | FOLL_PIN)) == 0))
		return NULL;

	if (unlikely(!(flags & FOLL_PCI_P2PDMA) && is_pci_p2pdma_page(page)))
		return NULL;

	if (flags & FOLL_GET)
		return try_get_folio(page, refs);

	/* FOLL_PIN is set */

	/*
	 * Don't take a pin on the zero page - it's not going anywhere
	 * and it is used in a *lot* of places.
	 */
	if (is_zero_page(page))
		return page_folio(page);

	folio = try_get_folio(page, refs);
	if (!folio)
		return NULL;

	/*
	 * Can't do FOLL_LONGTERM + FOLL_PIN gup fast path if not in a
	 * right zone, so fail and let the caller fall back to the slow
	 * path.
	 */
	if (unlikely((flags & FOLL_LONGTERM) &&
		     !folio_is_longterm_pinnable(folio))) {
		if (!put_devmap_managed_page_refs(&folio->page, refs))
			folio_put_refs(folio, refs);
		return NULL;
	}

	/*
	 * When pinning a large folio, use an exact count to track it.
	 *
	 * However, be sure to *also* increment the normal folio
	 * refcount field at least once, so that the folio really
	 * is pinned.  That's why the refcount from the earlier
	 * try_get_folio() is left intact.
	 */
	if (folio_test_large(folio))
		atomic_add(refs, &folio->_pincount);
	else
		folio_ref_add(folio,
				refs * (GUP_PIN_COUNTING_BIAS - 1));
	/*
	 * Adjust the pincount before re-checking the PTE for changes.
	 * This is essentially a smp_mb() and is paired with a memory
	 * barrier in page_try_share_anon_rmap().
	 */
	smp_mb__after_atomic();

	node_stat_mod_folio(folio, NR_FOLL_PIN_ACQUIRED, refs);

	return folio;
}
// 释放被pin的folio? (unpin)
static void gup_put_folio(struct folio *folio, int refs, unsigned int flags)
{
	if (flags & FOLL_PIN) {
		if (is_zero_folio(folio))
			return;
		node_stat_mod_folio(folio, NR_FOLL_PIN_RELEASED, refs);
		if (folio_test_large(folio))
			atomic_sub(refs, &folio->_pincount);
		else
			refs *= GUP_PIN_COUNTING_BIAS;
	}

	if (!put_devmap_managed_page_refs(&folio->page, refs))
		folio_put_refs(folio, refs);
}

/**
增加page的ref
 * try_grab_page() - elevate a page's refcount by a flag-dependent amount
 * @page:    pointer to page to be grabbed
 * @flags:   gup flags: these are the FOLL_* flag values.
 *
 * This might not do anything at all, depending on the flags argument.
 *
 * "grab" names in this file mean, "look at flags to decide whether to use
 * FOLL_PIN or FOLL_GET behavior, when incrementing the page's refcount.
 *
 * Either FOLL_PIN or FOLL_GET (or neither) may be set, but not both at the same
 * time. Cases: please see the try_grab_folio() documentation, with
 * "refs=1".
 *
 * Return: 0 for success, or if no action was required (if neither FOLL_PIN
 * nor FOLL_GET was set, nothing is done). A negative error code for failure:
 *
 *   -ENOMEM		FOLL_GET or FOLL_PIN was set, but the page could not
 *			be grabbed.
 */
int __must_check try_grab_page(struct page *page, unsigned int flags)
{
	struct folio *folio = page_folio(page);

	if (WARN_ON_ONCE(folio_ref_count(folio) <= 0))
		return -ENOMEM;

	if (unlikely(!(flags & FOLL_PCI_P2PDMA) && is_pci_p2pdma_page(page)))
		return -EREMOTEIO;

	if (flags & FOLL_GET)
		folio_ref_inc(folio);
	else if (flags & FOLL_PIN) {
		/*
		 * Don't take a pin on the zero page - it's not going anywhere
		 * and it is used in a *lot* of places.
		 */
		if (is_zero_page(page))
			return 0;

		/*
		 * Similar to try_grab_folio(): be sure to *also*
		 * increment the normal page refcount field at least once,
		 * so that the page really is pinned.
		 */
		if (folio_test_large(folio)) {
			folio_ref_add(folio, 1);
			atomic_add(1, &folio->_pincount);
		} else {
			folio_ref_add(folio, GUP_PIN_COUNTING_BIAS);
		}

		node_stat_mod_folio(folio, NR_FOLL_PIN_ACQUIRED, 1);
	}

	return 0;
}

/**
释放一个dma-pinned page?
 * unpin_user_page() - release a dma-pinned page
 * @page:            pointer to page to be released
 *
 * Pages that were pinned via pin_user_pages*() must be released via either
 * unpin_user_page(), or one of the unpin_user_pages*() routines. This is so
 * that such pages can be separately tracked and uniquely handled. In
 * particular, interactions with RDMA and filesystems need special handling.
 被pin_user_pages*()固定的页面必须通过unpin_user_page()或unpin_user_pages*()之一释放。
 这样，这些页面可以被单独跟踪和唯一处理。特别是与RDMA和文件系统的交互需要特殊处理。
 */
void unpin_user_page(struct page *page)
{
	sanity_check_pinned_pages(&page, 1);
	gup_put_folio(page_folio(page), 1, FOLL_PIN);
}
EXPORT_SYMBOL(unpin_user_page);

/**
 * folio_add_pin - Try to get an additional pin on a pinned folio
 * @folio: The folio to be pinned
 *
 * Get an additional pin on a folio we already have a pin on.  Makes no change
 * if the folio is a zero_page.
 */
void folio_add_pin(struct folio *folio)
{
	if (is_zero_folio(folio))
		return;

	/*
	 * Similar to try_grab_folio(): be sure to *also* increment the normal
	 * page refcount field at least once, so that the page really is
	 * pinned.
	 */
	if (folio_test_large(folio)) {
		WARN_ON_ONCE(atomic_read(&folio->_pincount) < 1);
		folio_ref_inc(folio);
		atomic_inc(&folio->_pincount);
	} else {
		WARN_ON_ONCE(folio_ref_count(folio) < GUP_PIN_COUNTING_BIAS);
		folio_ref_add(folio, GUP_PIN_COUNTING_BIAS);
	}
}

static inline struct folio *gup_folio_range_next(struct page *start,
		unsigned long npages, unsigned long i, unsigned int *ntails)
{
	struct page *next = nth_page(start, i);
	struct folio *folio = page_folio(next);
	unsigned int nr = 1;

	if (folio_test_large(folio))
		nr = min_t(unsigned int, npages - i,
			   folio_nr_pages(folio) - folio_page_idx(folio, next));

	*ntails = nr;
	return folio;
}
/* list这个page数组大小是npages, i是当前的索引, ntails这次的folio大小? */
static inline struct folio *gup_folio_next(struct page **list,
		unsigned long npages, unsigned long i, unsigned int *ntails)
{
	struct folio *folio = page_folio(list[i]);
	unsigned int nr;

	for (nr = i + 1; nr < npages; nr++) { //遍历余下的page
		if (page_folio(list[nr]) != folio)
			break; // 一直遍历到不属于同一个folio的page
	}

	*ntails = nr - i;
	return folio;
}

/**
在gup机制pin了, 并且修改了其他进程的页面之后
调用这个函数来收尾 (unpin + 写回)
 * unpin_user_pages_dirty_lock() - release and optionally dirty gup-pinned pages
 * @pages:  array of pages to be maybe marked dirty, and definitely released.
 * @npages: number of pages in the @pages array.
 * @make_dirty: whether to mark the pages dirty
 *
 * "gup-pinned page" refers to a page that has had one of the get_user_pages()
 * variants called on that page.
 *
 * For each page in the @pages array, make that page (or its head page, if a
 * compound page) dirty, if @make_dirty is true, and if the page was previously
 * listed as clean. In any case, releases all pages using unpin_user_page(),
 * possibly via unpin_user_pages(), for the non-dirty case.
 *
 * Please see the unpin_user_page() documentation for details.
 *
 * set_page_dirty_lock() is used internally. If instead, set_page_dirty() is
 * required, then the caller should a) verify that this is really correct,
 * because _lock() is usually required, and b) hand code it:
 * set_page_dirty_lock(), unpin_user_page().
 *
 */
void unpin_user_pages_dirty_lock(struct page **pages, unsigned long npages,
				 bool make_dirty)
{
	unsigned long i;
	struct folio *folio;
	unsigned int nr;

	if (!make_dirty) {
		/* 没有修改页面, 直接unpin就好 */
		unpin_user_pages(pages, npages);
		return;
	}

	sanity_check_pinned_pages(pages, npages);
	for (i = 0; i < npages; i += nr) {
		folio = gup_folio_next(pages, npages, i, &nr);
		/*
		 * Checking PageDirty at this point may race with
		 * clear_page_dirty_for_io(), but that's OK. Two key
		 * cases:
		 *
		 * 1) This code sees the page as already dirty, so it
		 * skips the call to set_page_dirty(). That could happen
		 * because clear_page_dirty_for_io() called
		 * page_mkclean(), followed by set_page_dirty().
		 * However, now the page is going to get written back,
		 * which meets the original intention of setting it
		 * dirty, so all is well: clear_page_dirty_for_io() goes
		 * on to call TestClearPageDirty(), and write the page
		 * back.
		 *
		 * 2) This code sees the page as clean, so it calls
		 * set_page_dirty(). The page stays dirty, despite being
		 * written back, so it gets written back again in the
		 * next writeback cycle. This is harmless.
		 修改了页面 ,需要回写
		 */
		if (!folio_test_dirty(folio)) {
			folio_lock(folio);
			folio_mark_dirty(folio);
			folio_unlock(folio);
		}
		gup_put_folio(folio, nr, FOLL_PIN);
	}
}
EXPORT_SYMBOL(unpin_user_pages_dirty_lock);

/**
===================
主要是一些driver调用
 * unpin_user_page_range_dirty_lock() - release and optionally dirty
 * gup-pinned page range
 *
 * @page:  the starting page of a range maybe marked dirty, and definitely released.
 * @npages: number of consecutive pages to release.
 * @make_dirty: whether to mark the pages dirty
 *
 * "gup-pinned page range" refers to a range of pages that has had one of the
 * pin_user_pages() variants called on that page.
 *
 * For the page ranges defined by [page .. page+npages], make that range (or
 * its head pages, if a compound page) dirty, if @make_dirty is true, and if the
 * page range was previously listed as clean.
 *
 * set_page_dirty_lock() is used internally. If instead, set_page_dirty() is
 * required, then the caller should a) verify that this is really correct,
 * because _lock() is usually required, and b) hand code it:
 * set_page_dirty_lock(), unpin_user_page().
 *
 */
void unpin_user_page_range_dirty_lock(struct page *page, unsigned long npages,
				      bool make_dirty)
{
	unsigned long i;
	struct folio *folio;
	unsigned int nr;

	for (i = 0; i < npages; i += nr) {
		folio = gup_folio_range_next(page, npages, i, &nr);
		if (make_dirty && !folio_test_dirty(folio)) {
			folio_lock(folio);
			/* 发起回写 */
			folio_mark_dirty(folio);
			folio_unlock(folio);
		}
		gup_put_folio(folio, nr, FOLL_PIN);
	}
}
EXPORT_SYMBOL(unpin_user_page_range_dirty_lock);
/*
pages里面是npages个page,是gup的fast-path一级一级检查页表
直到pte层面返回的
===============
为什么这里又put了呢
*/
static void unpin_user_pages_lockless(struct page **pages, unsigned long npages)
{
	unsigned long i;
	struct folio *folio;
	unsigned int nr;

	/*
	 * Don't perform any sanity checks because we might have raced with
	 * fork() and some anonymous pages might now actually be shared --
	 * which is why we're unpinning after all.
	   不执行任何健全性检查，因为我们可能与fork()发生了竞争，一些匿名页面现在
	   可能实际上是共享的——这就是我们之后要取消固定的原因。
	 */
	for (i = 0; i < npages; i += nr) {
		folio = gup_folio_next(pages, npages, i, &nr);
		gup_put_folio(folio, nr, FOLL_PIN);
	}
}

/**
 * unpin_user_pages() - release an array of gup-pinned pages.
 * @pages:  array of pages to be marked dirty and released.
 * @npages: number of pages in the @pages array.
 *
 * For each page in the @pages array, release the page using unpin_user_page().
 *
 * Please see the unpin_user_page() documentation for details.
 */
void unpin_user_pages(struct page **pages, unsigned long npages)
{
	unsigned long i;
	struct folio *folio;
	unsigned int nr;

	/*
	 * If this WARN_ON() fires, then the system *might* be leaking pages (by
	 * leaving them pinned), but probably not. More likely, gup/pup returned
	 * a hard -ERRNO error to the caller, who erroneously passed it here.
	 */
	if (WARN_ON(IS_ERR_VALUE(npages)))
		return;

	sanity_check_pinned_pages(pages, npages);
	for (i = 0; i < npages; i += nr) {
		folio = gup_folio_next(pages, npages, i, &nr);
		gup_put_folio(folio, nr, FOLL_PIN);
	}
}
EXPORT_SYMBOL(unpin_user_pages);

/*
 * Set the MMF_HAS_PINNED if not set yet; after set it'll be there for the mm's
 * lifecycle.  Avoid setting the bit unless necessary, or it might cause write
 * cache bouncing on large SMP machines for concurrent pinned gups.
 设置MMF_HAS_PINNED标志位，如果还没有设置的话；设置之后，它将在mm的生命周期内一直存在。
 除非有必要，否则避免设置该位，否则可能会导致在大型SMP机器上并发固定gups时写缓存反弹。
 */
static inline void mm_set_has_pinned_flag(unsigned long *mm_flags)
{
	if (!test_bit(MMF_HAS_PINNED, mm_flags))
		set_bit(MMF_HAS_PINNED, mm_flags);
}

#ifdef CONFIG_MMU
static struct page *no_page_table(struct vm_area_struct *vma,
		unsigned int flags)
{
	/*
	 * When core dumping an enormous anonymous area that nobody
	 * has touched so far, we don't want to allocate unnecessary pages or
	 * page tables.  Return error instead of NULL to skip handle_mm_fault,
	 * then get_dump_page() will return NULL to leave a hole in the dump.
	 * But we can only make this optimization where a hole would surely
	 * be zero-filled if handle_mm_fault() actually did handle it.
	 */
	if ((flags & FOLL_DUMP) &&
			(vma_is_anonymous(vma) || !vma->vm_ops->fault))
		return ERR_PTR(-EFAULT);
	return NULL;
}

/* 调用这个函数可能是因为刚刚没有找到 pte对应的pfn对应的page结构体
================
这里只是修改pte的属性
还是不返回page
 */
static int follow_pfn_pte(struct vm_area_struct *vma, unsigned long address,
		pte_t *pte, unsigned int flags)
{
	/* 这里会修改pte
	make_young make_dirty等等 */
	if (flags & FOLL_TOUCH) {
		/* 获取pte的备份值 */
		pte_t orig_entry = ptep_get(pte);
		pte_t entry = orig_entry;

		if (flags & FOLL_WRITE)
			entry = pte_mkdirty(entry);
		entry = pte_mkyoung(entry);

		if (!pte_same(orig_entry, entry)) {
			set_pte_at(vma->vm_mm, address, pte, entry);
			update_mmu_cache(vma, address, pte);
		}
	}

	/* Proper page table entry exists, but no corresponding struct page */
	return -EEXIST;
}

/* FOLL_FORCE can write to even unwritable PTEs in COW mappings.
检测follow_page的时候能不能write pte? */
static inline bool can_follow_write_pte(pte_t pte, struct page *page,
					struct vm_area_struct *vma,
					unsigned int flags)
{
	/* If the pte is writable, we can write to the page. */
	if (pte_write(pte))
		return true;

	/* Maybe FOLL_FORCE is set to override it? */
	if (!(flags & FOLL_FORCE))
		return false;

	/* But FOLL_FORCE has no effect on shared mappings */
	if (vma->vm_flags & (VM_MAYSHARE | VM_SHARED))
		return false;

	/* ... or read-only private ones */
	if (!(vma->vm_flags & VM_MAYWRITE))
		return false;

	/* ... or already writable ones that just need to take a write fault */
	if (vma->vm_flags & VM_WRITE)
		return false;

	/*
	 * See can_change_pte_writable(): we broke COW and could map the page
	 * writable if we have an exclusive anonymous page ...
	 */
	if (!page || !PageAnon(page) || !PageAnonExclusive(page))
		return false;

	/* ... and a write-fault isn't required for other reasons. */
	if (vma_soft_dirty_enabled(vma) && !pte_soft_dirty(pte))
		return false;
	return !userfaultfd_pte_wp(vma, pte);
}

/* 
获取addr对应的page
=========
Q:为什么也mark_page_accessed
如果用户发起follow的时候, 指定了touch, 会mark_page_accessed
*/
static struct page *follow_page_pte(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd, unsigned int flags,
		struct dev_pagemap **pgmap)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	spinlock_t *ptl;
	pte_t *ptep, pte;
	int ret;

	/* FOLL_GET and FOLL_PIN are mutually exclusive. */
	if (WARN_ON_ONCE((flags & (FOLL_PIN | FOLL_GET)) ==
			 (FOLL_PIN | FOLL_GET)))
		return ERR_PTR(-EINVAL);

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (!ptep)
		return no_page_table(vma, flags);
	// 从pte指针读取出pte条目
	pte = ptep_get(ptep);
	/* 如果这个页面被换出了 */
	if (!pte_present(pte))
		goto no_page;
	if (pte_protnone(pte) && !gup_can_follow_protnone(vma, flags))
		goto no_page;

	/* 返回pte对应的page */
	page = vm_normal_page(vma, address, pte);

	/*
	 * We only care about anon pages in can_follow_write_pte() and don't
	 * have to worry about pte_devmap() because they are never anon.
	 
	 如果参数要求FOLL_WRITE, 但是事实上不能can_follow_write_pte
	 就返回*/
	if ((flags & FOLL_WRITE) &&
	    !can_follow_write_pte(pte, page, vma, flags)) {
		page = NULL;
		goto out;
	}
	/*  */

	if (!page && pte_devmap(pte) && (flags & (FOLL_GET | FOLL_PIN))) {
		/* 如果刚刚没有follow到page, 并且还是devmap的情况 */
		/*
		 * Only return device mapping pages in the FOLL_GET or FOLL_PIN
		 * case since they are only valid while holding the pgmap
		 * reference.
		 */
		*pgmap = get_dev_pagemap(pte_pfn(pte), *pgmap);
		if (*pgmap)
			page = pte_page(pte);
		else
			goto no_page;
	} else if (unlikely(!page)) {
		/* 没有找到pte对应的pfn对应的page结构体的情况
		这里检查是不是因为zero pfn
		然后就是根据参数,是否修改一下pte, 直接返回了也是 */
		/* 为什么没有page结构体的情况是少见的? */
		if (flags & FOLL_DUMP) {
			/* Avoid special (like zero) pages in core dumps */
			page = ERR_PTR(-EFAULT);
			goto out;
		}

		if (is_zero_pfn(pte_pfn(pte))) {
			page = pte_page(pte);
		} else {
			/* 这里修改pte属性, page结构体不存在就是不存在了 */
			ret = follow_pfn_pte(vma, address, ptep, flags);
			page = ERR_PTR(ret);
			goto out;
		}
	}

	if (!pte_write(pte) && gup_must_unshare(vma, flags, page)) {
		page = ERR_PTR(-EMLINK);
		goto out;
	}

	VM_BUG_ON_PAGE((flags & FOLL_PIN) && PageAnon(page) &&
		       !PageAnonExclusive(page), page);

	/* try_grab_page() does nothing unless FOLL_GET or FOLL_PIN is set.
	这里尝试增加ref */
	ret = try_grab_page(page, flags);
	if (unlikely(ret)) {
		page = ERR_PTR(ret);
		goto out;
	}

	/*
	 * We need to make the page accessible if and only if we are going
	 * to access its content (the FOLL_PIN case).  Please see
	 * Documentation/core-api/pin_user_pages.rst for details.
	 */
	if (flags & FOLL_PIN) {
		ret = arch_make_page_accessible(page);
		if (ret) {
			unpin_user_page(page);
			page = ERR_PTR(ret);
			goto out;
		}
	}
	/* 如果用户发起follow的时候, 指定了touch, 会mark_page_accessed */
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) &&
		    !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page); /* 这里为什么必须pte和page都不dirty的时候才设置page dirty呢
			==================
			如果pte和page都是不dirty的, 就调用mapping回调, 置脏page (也可能在io和mapping置脏folio) */
		/*
		 * pte_mkyoung() would be more correct here, but atomic care
		 * is needed to avoid losing the dirty bit: it is easier to use
		 * mark_page_accessed().
		 标记页面为accessed (更多的作用是提升页面稳定性)*/
		mark_page_accessed(page);
	}
out:
	pte_unmap_unlock(ptep, ptl);
	return page;

no_page:
	/* 没找到页面, 被换出了, 或者不存在 */
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
		return NULL;
	return no_page_table(vma, flags);
}

/*
查找用户地址空间的页面
在pud的基础上查找pmd
*/
static struct page *follow_pmd_mask(struct vm_area_struct *vma,
				    unsigned long address, pud_t *pudp,
				    unsigned int flags,
				    struct follow_page_context *ctx)
{
	pmd_t *pmd, pmdval;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;
	// 获得pmd的指针
	pmd = pmd_offset(pudp, address);
	// pmd条目
	pmdval = pmdp_get_lockless(pmd);
	// 用户地址空间还没有这个页面
	if (pmd_none(pmdval))
		return no_page_table(vma, flags);
	// 用户这个地址还不在内存
	if (!pmd_present(pmdval))
		return no_page_table(vma, flags);
	/* devmap相关 */
	if (pmd_devmap(pmdval)) {
		ptl = pmd_lock(mm, pmd);
		page = follow_devmap_pmd(vma, address, pmd, flags, &ctx->pgmap);
		spin_unlock(ptl);
		if (page)
			return page;
	}
	if (likely(!pmd_trans_huge(pmdval))) // 不是巨页的情况
		return follow_page_pte(vma, address, pmd, flags, &ctx->pgmap);

	// 下面是如果是巨页的情况
	if (pmd_protnone(pmdval) && !gup_can_follow_protnone(vma, flags))
		return no_page_table(vma, flags);

	ptl = pmd_lock(mm, pmd);
	if (unlikely(!pmd_present(*pmd))) {
		spin_unlock(ptl);
		return no_page_table(vma, flags);
	}
	if (unlikely(!pmd_trans_huge(*pmd))) {
		spin_unlock(ptl);
		return follow_page_pte(vma, address, pmd, flags, &ctx->pgmap);
	}
	if (flags & FOLL_SPLIT_PMD) {
		spin_unlock(ptl);
		split_huge_pmd(vma, pmd, address);
		/* If pmd was left empty, stuff a page table in there quickly */
		return pte_alloc(mm, pmd) ? ERR_PTR(-ENOMEM) :
			follow_page_pte(vma, address, pmd, flags, &ctx->pgmap);
	}
	page = follow_trans_huge_pmd(vma, address, pmd, flags);
	spin_unlock(ptl);
	ctx->page_mask = HPAGE_PMD_NR - 1;
	return page;
}

/* 查找用户地址空间的页面
follow
*/
static struct page *follow_pud_mask(struct vm_area_struct *vma,
				    unsigned long address, p4d_t *p4dp,
				    unsigned int flags,
				    struct follow_page_context *ctx)
{
	pud_t *pud;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	pud = pud_offset(p4dp, address);
	if (pud_none(*pud))
		return no_page_table(vma, flags);
	/* devmap相关的 */
	if (pud_devmap(*pud)) {
		ptl = pud_lock(mm, pud);
		page = follow_devmap_pud(vma, address, pud, flags, &ctx->pgmap);
		spin_unlock(ptl);
		if (page)
			return page;
	}
	if (unlikely(pud_bad(*pud)))
		return no_page_table(vma, flags);
	// pud存在并且不是bad, 继续查找
	return follow_pmd_mask(vma, address, pud, flags, ctx);
}

/*
查找用户地址空间的页面
*/
static struct page *follow_p4d_mask(struct vm_area_struct *vma,
				    unsigned long address, pgd_t *pgdp,
				    unsigned int flags,
				    struct follow_page_context *ctx)
{
	p4d_t *p4d;

	p4d = p4d_offset(pgdp, address);
	if (p4d_none(*p4d))
		return no_page_table(vma, flags);
	BUILD_BUG_ON(p4d_huge(*p4d));
	if (unlikely(p4d_bad(*p4d)))
		return no_page_table(vma, flags);
	// p4d存在并且不是bad, 继续查找
	return follow_pud_mask(vma, address, p4d, flags, ctx);
}

/**
 * follow_page_mask - look up a page descriptor from a user-virtual address
 查找用户地址空间的地址对应的页面
 * @vma: vm_area_struct mapping @address
 * @address: virtual address to look up
 * @flags: flags modifying lookup behaviour
 * @ctx: contains dev_pagemap for %ZONE_DEVICE memory pinning and a
 *       pointer to output page_mask
 *
 * @flags can have FOLL_ flags set, defined in <linux/mm.h>
 *
 * When getting pages from ZONE_DEVICE memory, the @ctx->pgmap caches
 * the device's dev_pagemap metadata to avoid repeating expensive lookups.
 *
 * When getting an anonymous page and the caller has to trigger unsharing
 * of a shared anonymous page first, -EMLINK is returned. The caller should
 * trigger a fault with FAULT_FLAG_UNSHARE set. Note that unsharing is only
 * relevant with FOLL_PIN and !FOLL_WRITE.
 *
 * On output, the @ctx->page_mask is set according to the size of the page.
 *
 * Return: the mapped (struct page *), %NULL if no mapping exists, or
 * an error pointer if there is a mapping to something not represented
 * by a page descriptor (see also vm_normal_page()).
 */
static struct page *follow_page_mask(struct vm_area_struct *vma,
			      unsigned long address, unsigned int flags,
			      struct follow_page_context *ctx)
{
	pgd_t *pgd;
	struct mm_struct *mm = vma->vm_mm;

	ctx->page_mask = 0;

	/*
	 * Call hugetlb_follow_page_mask for hugetlb vmas as it will use
	 * special hugetlb page table walking code.  This eliminates the
	 * need to check for hugetlb entries in the general walking code.
	 */
	if (is_vm_hugetlb_page(vma))
		return hugetlb_follow_page_mask(vma, address, flags,
						&ctx->page_mask);

	/* 获取地址的页目录 */
	pgd = pgd_offset(mm, address);

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return no_page_table(vma, flags);
	// pgd存在并且不是bad, 继续查找
	return follow_p4d_mask(vma, address, pgd, flags, ctx);
}

/* addr位于vma
==========
找到vma的addr对应的page
 */
struct page *follow_page(struct vm_area_struct *vma, unsigned long address,
			 unsigned int foll_flags)
{
	struct follow_page_context ctx = { NULL };
	struct page *page;

	if (vma_is_secretmem(vma))
		return NULL;

	if (WARN_ON_ONCE(foll_flags & FOLL_PIN))
		return NULL;

	/*
	 * We never set FOLL_HONOR_NUMA_FAULT because callers don't expect
	 * to fail on PROT_NONE-mapped pages.
	 查找对应的page
	 */
	page = follow_page_mask(vma, address, foll_flags, &ctx);
	if (ctx.pgmap)
		put_dev_pagemap(ctx.pgmap);
	return page;
}

static int get_gate_page(struct mm_struct *mm, unsigned long address,
		unsigned int gup_flags, struct vm_area_struct **vma,
		struct page **page)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t entry;
	int ret = -EFAULT;

	/* user gate pages are read-only */
	if (gup_flags & FOLL_WRITE)
		return -EFAULT;
	if (address > TASK_SIZE)
		pgd = pgd_offset_k(address);
	else
		pgd = pgd_offset_gate(mm, address);
	if (pgd_none(*pgd))
		return -EFAULT;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		return -EFAULT;
	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return -EFAULT;
	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return -EFAULT;
	pte = pte_offset_map(pmd, address);
	if (!pte)
		return -EFAULT;
	entry = ptep_get(pte);
	if (pte_none(entry))
		goto unmap;
	*vma = get_gate_vma(mm);
	if (!page)
		goto out;
	*page = vm_normal_page(*vma, address, entry);
	if (!*page) {
		if ((gup_flags & FOLL_DUMP) || !is_zero_pfn(pte_pfn(entry)))
			goto unmap;
		*page = pte_page(entry);
	}
	ret = try_grab_page(*page, gup_flags);
	if (unlikely(ret))
		goto unmap;
out:
	ret = 0;
unmap:
	pte_unmap(pte);
	return ret;
}

/*
必须持有mmap_lock才能进入
 * mmap_lock must be held on entry.  If @flags has FOLL_UNLOCKABLE but not
 * FOLL_NOWAIT, the mmap_lock may be released.  If it is, *@locked will be set
 * to 0 and -EBUSY returned.
 */
static int faultin_page(struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, bool unshare,
		int *locked)
{
	unsigned int fault_flags = 0;
	vm_fault_t ret;

	if (*flags & FOLL_NOFAULT)
		return -EFAULT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (*flags & FOLL_UNLOCKABLE) {
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
		/*
		 * FAULT_FLAG_INTERRUPTIBLE is opt-in. GUP callers must set
		 * FOLL_INTERRUPTIBLE to enable FAULT_FLAG_INTERRUPTIBLE.
		 * That's because some callers may not be prepared to
		 * handle early exits caused by non-fatal signals.
		 */
		if (*flags & FOLL_INTERRUPTIBLE)
			fault_flags |= FAULT_FLAG_INTERRUPTIBLE;
	}
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		/*
		 * Note: FAULT_FLAG_ALLOW_RETRY and FAULT_FLAG_TRIED
		 * can co-exist
		 */
		fault_flags |= FAULT_FLAG_TRIED;
	}
	if (unshare) {
		fault_flags |= FAULT_FLAG_UNSHARE;
		/* FAULT_FLAG_WRITE and FAULT_FLAG_UNSHARE are incompatible */
		VM_BUG_ON(fault_flags & FAULT_FLAG_WRITE);
	}
	/* 解决pf */
	ret = handle_mm_fault(vma, address, fault_flags, NULL);

	if (ret & VM_FAULT_COMPLETED) {
		/*
		 * With FAULT_FLAG_RETRY_NOWAIT we'll never release the
		 * mmap lock in the page fault handler. Sanity check this.
		 */
		WARN_ON_ONCE(fault_flags & FAULT_FLAG_RETRY_NOWAIT);
		*locked = 0;

		/*
		 * We should do the same as VM_FAULT_RETRY, but let's not
		 * return -EBUSY since that's not reflecting the reality of
		 * what has happened - we've just fully completed a page
		 * fault, with the mmap lock released.  Use -EAGAIN to show
		 * that we want to take the mmap lock _again_.
		 */
		return -EAGAIN;
	}

	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, *flags);

		if (err)
			return err;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		if (!(fault_flags & FAULT_FLAG_RETRY_NOWAIT))
			*locked = 0;
		return -EBUSY;
	}

	return 0;
}

/*
 * Writing to file-backed mappings which require folio dirty tracking using GUP
 * is a fundamentally broken operation, as kernel write access to GUP mappings
 * do not adhere to the semantics expected by a file system.
 *
 * Consider the following scenario:-
 *
 * 1. A folio is written to via GUP which write-faults the memory, notifying
 *    the file system and dirtying the folio.
 * 2. Later, writeback is triggered, resulting in the folio being cleaned and
 *    the PTE being marked read-only.
 * 3. The GUP caller writes to the folio, as it is mapped read/write via the
 *    direct mapping.
 * 4. The GUP caller, now done with the page, unpins it and sets it dirty
 *    (though it does not have to).
 *
 * This results in both data being written to a folio without writenotify, and
 * the folio being dirtied unexpectedly (if the caller decides to do so).
 */
static bool writable_file_mapping_allowed(struct vm_area_struct *vma,
					  unsigned long gup_flags)
{
	/*
	 * If we aren't pinning then no problematic write can occur. A long term
	 * pin is the most egregious case so this is the case we disallow.
	 */
	if ((gup_flags & (FOLL_PIN | FOLL_LONGTERM)) !=
	    (FOLL_PIN | FOLL_LONGTERM))
		return true;

	/*
	 * If the VMA does not require dirty tracking then no problematic write
	 * can occur either.
	 */
	return !vma_needs_dirty_tracking(vma);
}
/*
检查刚刚根据@gup_flags获取的vma是否符合要求
 */
static int check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags)
{
	vm_flags_t vm_flags = vma->vm_flags;
	int write = (gup_flags & FOLL_WRITE);
	int foreign = (gup_flags & FOLL_REMOTE);
	bool vma_anon = vma_is_anonymous(vma);

	if (vm_flags & (VM_IO | VM_PFNMAP))
		return -EFAULT;

		// 如果gup
	if ((gup_flags & FOLL_ANON) && !vma_anon)
		return -EFAULT;

	if ((gup_flags & FOLL_LONGTERM) && vma_is_fsdax(vma))
		return -EOPNOTSUPP;

	if (vma_is_secretmem(vma))
		return -EFAULT;

	if (write) {
		if (!vma_anon &&
		    !writable_file_mapping_allowed(vma, gup_flags))
			return -EFAULT;

		if (!(vm_flags & VM_WRITE) || (vm_flags & VM_SHADOW_STACK)) {
			if (!(gup_flags & FOLL_FORCE))
				return -EFAULT;
			/* hugetlb does not support FOLL_FORCE|FOLL_WRITE. */
			if (is_vm_hugetlb_page(vma))
				return -EFAULT;
			/*
			 * We used to let the write,force case do COW in a
			 * VM_MAYWRITE VM_SHARED !VM_WRITE vma, so ptrace could
			 * set a breakpoint in a read-only mapping of an
			 * executable, without corrupting the file (yet only
			 * when that file had been opened for writing!).
			 * Anon pages in shared mappings are surprising: now
			 * just reject it.
			 */
			if (!is_cow_mapping(vm_flags))
				return -EFAULT;
		}
	} else if (!(vm_flags & VM_READ)) {
		if (!(gup_flags & FOLL_FORCE))
			return -EFAULT;
		/*
		 * Is there actually any vma we can reach here which does not
		 * have VM_MAYREAD set?
		 */
		if (!(vm_flags & VM_MAYREAD))
			return -EFAULT;
	}
	/*
	 * gups are always data accesses, not instruction
	 * fetches, so execute=false here
	 */
	if (!arch_vma_access_permitted(vma, write, false, foreign))
		return -EFAULT;
	return 0;
}

/*
 * This is "vma_lookup()", but with a warning if we would have
 * historically expanded the stack in the GUP code.
  是一个查询vma的函数, 不过如果我们在GUP代码中扩展了栈的话, 就会有一个警告
 */
static struct vm_area_struct *gup_vma_lookup(struct mm_struct *mm,
	 unsigned long addr)
{
#ifdef CONFIG_STACK_GROWSUP
	return vma_lookup(mm, addr);
#else
	static volatile unsigned long next_warn;
	struct vm_area_struct *vma;
	unsigned long now, next;

	vma = find_vma(mm, addr);
	if (!vma || (addr >= vma->vm_start))
		return vma;

	/* Only warn for half-way relevant accesses */
	if (!(vma->vm_flags & VM_GROWSDOWN))
		return NULL;
	if (vma->vm_start - addr > 65536)
		return NULL;

	/* Let's not warn more than once an hour.. */
	now = jiffies; next = next_warn;
	if (next && time_before(now, next))
		return NULL;
	next_warn = now + 60*60*HZ;

	/* Let people know things may have changed. */
	pr_warn("GUP no longer grows the stack in %s (%d): %lx-%lx (%lx)\n",
		current->comm, task_pid_nr(current),
		vma->vm_start, vma->vm_end, addr);
	dump_stack();
	return NULL;
#endif
}

/**
 * __get_user_pages() - pin user pages in memory
 获取用户页在内存中的页框
 一个一个follow page, 加入到pages数组
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying pin behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @locked:     whether we're still with the mmap_lock held
 *
 * Returns either number of pages pinned (which may be less than the
 * number requested), or an error. Details about the return value:
 *
 * -- If nr_pages is 0, returns 0.
 * -- If nr_pages is >0, but no pages were pinned, returns -errno.
 * -- If nr_pages is >0, and some pages were pinned, returns the number of
 *    pages pinned. Again, this may be less than nr_pages.
 * -- 0 return value is possible when the fault would need to be retried.
 *
 * The caller is responsible for releasing returned @pages, via put_page().
 *
 * Must be called with mmap_lock held.  It may be released.  See below.
 *
 * __get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * __get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re-faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If @gup_flags & FOLL_WRITE == 0, the page must not be written to. If
 * the page is written to, set_page_dirty (or set_page_dirty_lock, as
 * appropriate) must be called after the page is finished with, and
 * before put_page is called.
 *
 * If FOLL_UNLOCKABLE is set without FOLL_NOWAIT then the mmap_lock may
 * be released. If this happens *@locked will be set to 0 on return.
 *
 * A caller using such a combination of @gup_flags must therefore hold the
 * mmap_lock for reading only, and recognize when it's been released. Otherwise,
 * it must be held for either reading or writing and will not be released.
 *
 * In most cases, get_user_pages or get_user_pages_fast should be used
 * instead of __get_user_pages. __get_user_pages should be used only if
 * you need some special @gup_flags.
 */
static long __get_user_pages(struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		int *locked)
{
	long ret = 0, i = 0;
	struct vm_area_struct *vma = NULL;
	struct follow_page_context ctx = { NULL };

	if (!nr_pages)
		return 0;

	start = untagged_addr_remote(mm, start);

	VM_BUG_ON(!!pages != !!(gup_flags & (FOLL_GET | FOLL_PIN)));

	do {
		struct page *page;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		/* first iteration or cross vma bound
		*/
		if (!vma || start >= vma->vm_end) {/* 1, 函数刚刚开始循环,vma还是空的
			2, 或者这个vma遍历完了 
			*/
			// 查找相应的vma
			vma = gup_vma_lookup(mm, start);
			if (!vma && in_gate_area(mm, start)) {
				ret = get_gate_page(mm, start & PAGE_MASK,
						gup_flags, &vma,
						pages ? &page : NULL);
				if (ret)
					goto out;
				ctx.page_mask = 0;
				goto next_page;
			}

			if (!vma) { // 没找到vma
				ret = -EFAULT;
				goto out; // 直接返回
			}
			// 找到了vma
			ret = check_vma_flags(vma, gup_flags);
			if (ret) // 找到的vma有问题
				goto out;
		}
		// 现在找到了对应的vma
retry:
		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
		cond_resched();
		// 在vma里面找到start地址对应的page
		page = follow_page_mask(vma, start, foll_flags, &ctx);
		if (!page || PTR_ERR(page) == -EMLINK) {
			ret = faultin_page(vma, start, &foll_flags,
					   PTR_ERR(page) == -EMLINK, locked);
			switch (ret) {
			case 0:
				goto retry;
			case -EBUSY:
			case -EAGAIN:
				ret = 0;
				fallthrough;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				goto out;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			/*
			 * Proper page table entry exists, but no corresponding
			 * struct page. If the caller expects **pages to be
			 * filled in, bail out now, because that can't be done
			 * for this page.
			 */
			if (pages) {
				ret = PTR_ERR(page);
				goto out;
			}
		} else if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			goto out;
		}
		// 找到了一个page
next_page:
		page_increm = 1 + (~(start >> PAGE_SHIFT) & ctx.page_mask);
		if (page_increm > nr_pages)
			page_increm = nr_pages;

		if (pages) {
			struct page *subpage;
			unsigned int j;

			/*
			 * This must be a large folio (and doesn't need to
			 * be the whole folio; it can be part of it), do
			 * the refcount work for all the subpages too.
			 *
			 * NOTE: here the page may not be the head page
			 * e.g. when start addr is not thp-size aligned.
			 * try_grab_folio() should have taken care of tail
			 * pages.
			 */
			if (page_increm > 1) {
				struct folio *folio;

				/*
				 * Since we already hold refcount on the
				 * large folio, this should never fail.
				 */
				folio = try_grab_folio(page, page_increm - 1,
						       foll_flags);
				if (WARN_ON_ONCE(!folio)) {
					/*
					 * Release the 1st page ref if the
					 * folio is problematic, fail hard.
					 */
					gup_put_folio(page_folio(page), 1,
						      foll_flags);
					ret = -EFAULT;
					goto out;
				}
			}

			for (j = 0; j < page_increm; j++) {// 添加到pages数组
				subpage = nth_page(page, j);
				pages[i + j] = subpage;
				flush_anon_page(vma, subpage, start + j * PAGE_SIZE);
				flush_dcache_page(subpage);
			}
		}

		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);
out:
	if (ctx.pgmap)
		put_dev_pagemap(ctx.pgmap);
	return i ? i : ret;
}

static bool vma_permits_fault(struct vm_area_struct *vma,
			      unsigned int fault_flags)
{
	bool write   = !!(fault_flags & FAULT_FLAG_WRITE);
	bool foreign = !!(fault_flags & FAULT_FLAG_REMOTE);
	vm_flags_t vm_flags = write ? VM_WRITE : VM_READ;

	if (!(vm_flags & vma->vm_flags))
		return false;

	/*
	 * The architecture might have a hardware protection
	 * mechanism other than read/write that can deny access.
	 *
	 * gup always represents data access, not instruction
	 * fetches, so execute=false here:
	 */
	if (!arch_vma_access_permitted(vma, write, false, foreign))
		return false;

	return true;
}

/**
 * fixup_user_fault() - manually resolve a user page fault
 * @mm:		mm_struct of target mm
 * @address:	user address
 * @fault_flags:flags to pass down to handle_mm_fault()
 * @unlocked:	did we unlock the mmap_lock while retrying, maybe NULL if caller
 *		does not allow retry. If NULL, the caller must guarantee
 *		that fault_flags does not contain FAULT_FLAG_ALLOW_RETRY.
 *
 * This is meant to be called in the specific scenario where for locking reasons
 * we try to access user memory in atomic context (within a pagefault_disable()
 * section), this returns -EFAULT, and we want to resolve the user fault before
 * trying again.
 *
 * Typically this is meant to be used by the futex code.
 *
 * The main difference with get_user_pages() is that this function will
 * unconditionally call handle_mm_fault() which will in turn perform all the
 * necessary SW fixup of the dirty and young bits in the PTE, while
 * get_user_pages() only guarantees to update these in the struct page.
 *
 * This is important for some architectures where those bits also gate the
 * access permission to the page because they are maintained in software.  On
 * such architectures, gup() will not be enough to make a subsequent access
 * succeed.
 *
 * This function will not return with an unlocked mmap_lock. So it has not the
 * same semantics wrt the @mm->mmap_lock as does filemap_fault().
 */
int fixup_user_fault(struct mm_struct *mm,
		     unsigned long address, unsigned int fault_flags,
		     bool *unlocked)
{
	struct vm_area_struct *vma;
	vm_fault_t ret;

	address = untagged_addr_remote(mm, address);

	if (unlocked)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

retry:
	vma = gup_vma_lookup(mm, address);
	if (!vma)
		return -EFAULT;

	if (!vma_permits_fault(vma, fault_flags))
		return -EFAULT;

	if ((fault_flags & FAULT_FLAG_KILLABLE) &&
	    fatal_signal_pending(current))
		return -EINTR;

	ret = handle_mm_fault(vma, address, fault_flags, NULL);

	if (ret & VM_FAULT_COMPLETED) {
		/*
		 * NOTE: it's a pity that we need to retake the lock here
		 * to pair with the unlock() in the callers. Ideally we
		 * could tell the callers so they do not need to unlock.
		 */
		mmap_read_lock(mm);
		*unlocked = true;
		return 0;
	}

	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, 0);

		if (err)
			return err;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		mmap_read_lock(mm);
		*unlocked = true;
		fault_flags |= FAULT_FLAG_TRIED;
		goto retry;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(fixup_user_fault);

/*
 * GUP always responds to fatal signals.  When FOLL_INTERRUPTIBLE is
 * specified, it'll also respond to generic signals.  The caller of GUP
 * that has FOLL_INTERRUPTIBLE should take care of the GUP interruption.
 */
static bool gup_signal_pending(unsigned int flags)
{
	if (fatal_signal_pending(current))
		return true;

	if (!(flags & FOLL_INTERRUPTIBLE))
		return false;

	return signal_pending(current);
}

/*
获取其他进程的页
一个一个follow page, 加入到pages数组
不是FOLL_LONGTERM的情况下, 会调用__get_user_pages_locked
 * Locking: (*locked == 1) means that the mmap_lock has already been acquired by
 * the caller. This function may drop the mmap_lock. If it does so, then it will
 * set (*locked = 0).
 * locked=1表示caller已经提前加锁, 这个函数可能会释放锁, 如果释放了, 那么会设置locked=0
 * (*locked == 0) means that the caller expects this function to acquire and
 * drop the mmap_lock. Therefore, the value of *locked will still be zero when
 * the function returns, even though it may have changed temporarily during
 * function execution.
 * locked=0表示caller期望这个函数获取并释放mmap_lock, 因此当函数返回时, locked的值仍然为0, 
 * 即使在函数执行期间它可能会临时改变。
 * Please note that this function, unlike __get_user_pages(), will not return 0
 * for nr_pages > 0, unless FOLL_NOWAIT is used.
 */
static __always_inline long __get_user_pages_locked(struct mm_struct *mm,
						unsigned long start,
						unsigned long nr_pages,
						struct page **pages,
						int *locked,
						unsigned int flags)
{
	long ret, pages_done;
	bool must_unlock = false;

	/*
	 * The internal caller expects GUP to manage the lock internally and the
	 * lock must be released when this returns.
	   内部调用者期望GUP在内部管理锁，并且在返回时必须释放锁。
	 */
	if (!*locked) {// 如果caller没有提前加锁
		if (mmap_read_lock_killable(mm))
			return -EAGAIN; // 获取mmap_lock失败
		// 现在获取mmap_lock成功
		must_unlock = true;
		*locked = 1;
	}
	else
		mmap_assert_locked(mm);

	if (flags & FOLL_PIN)
		mm_set_has_pinned_flag(&mm->flags);

	/*
	 * FOLL_PIN and FOLL_GET are mutually exclusive. Traditional behavior
	 * is to set FOLL_GET if the caller wants pages[] filled in (but has
	 * carelessly failed to specify FOLL_GET), so keep doing that, but only
	 * for FOLL_GET, not for the newer FOLL_PIN.
	 *
	 * FOLL_PIN always expects pages to be non-null, but no need to assert
	 * that here, as any failures will be obvious enough.
	 */
	if (pages && !(flags & FOLL_PIN))
		flags |= FOLL_GET;

	pages_done = 0;
	for (;;) {
		/* 获取和pin */
		ret = __get_user_pages(mm, start, nr_pages, flags, pages,
				       locked);
		if (!(flags & FOLL_UNLOCKABLE)) {
			/* VM_FAULT_RETRY couldn't trigger, bypass */
			pages_done = ret;
			break;
		}

		/* VM_FAULT_RETRY or VM_FAULT_COMPLETED cannot return errors */
		if (!*locked) {
			BUG_ON(ret < 0);
			BUG_ON(ret >= nr_pages);
		}

		if (ret > 0) {
			nr_pages -= ret;
			pages_done += ret;
			if (!nr_pages)
				break;
		}
		if (*locked) {
			/*
			 * VM_FAULT_RETRY didn't trigger or it was a
			 * FOLL_NOWAIT.
			 */
			if (!pages_done)
				pages_done = ret;
			break;
		}
		/*
		 * VM_FAULT_RETRY triggered, so seek to the faulting offset.
		 * For the prefault case (!pages) we only update counts.
		 */
		if (likely(pages))
			pages += ret;
		start += ret << PAGE_SHIFT;

		/* The lock was temporarily dropped, so we must unlock later */
		must_unlock = true;

retry:
		/*
		 * Repeat on the address that fired VM_FAULT_RETRY
		 * with both FAULT_FLAG_ALLOW_RETRY and
		 * FAULT_FLAG_TRIED.  Note that GUP can be interrupted
		 * by fatal signals of even common signals, depending on
		 * the caller's request. So we need to check it before we
		 * start trying again otherwise it can loop forever.
		 */
		if (gup_signal_pending(flags)) {
			if (!pages_done)
				pages_done = -EINTR;
			break;
		}
		// 重新获取mmap_lock
		ret = mmap_read_lock_killable(mm);
		if (ret) {
			BUG_ON(ret > 0);
			if (!pages_done)
				pages_done = ret;
			break;
		}

		*locked = 1;
		/*  */
		ret = __get_user_pages(mm, start, 1, flags | FOLL_TRIED,
				       pages, locked);
		if (!*locked) {
			/* Continue to retry until we succeeded */
			BUG_ON(ret != 0);
			goto retry;
		}
		if (ret != 1) {
			BUG_ON(ret > 1);
			if (!pages_done)
				pages_done = ret;
			break;
		}
		nr_pages--;
		pages_done++;
		if (!nr_pages)
			break;
		if (likely(pages))
			pages++;
		start += PAGE_SIZE;
	}
	if (must_unlock && *locked) {
		/*
		 * We either temporarily dropped the lock, or the caller
		 * requested that we both acquire and drop the lock. Either way,
		 * we must now unlock, and notify the caller of that state.
		 */
		mmap_read_unlock(mm);
		*locked = 0;
	}
	return pages_done;
}

/**
 * populate_vma_page_range() -  populate a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 * @locked: whether the mmap_lock is still held
 *
 * This takes care of mlocking the pages too if VM_LOCKED is set.
 *
 * Return either number of pages pinned in the vma, or a negative error
 * code on error.
 *
 * vma->vm_mm->mmap_lock must be held.
 *
 * If @locked is NULL, it may be held for read or write and will
 * be unperturbed.
 *
 * If @locked is non-NULL, it must held for read only and may be
 * released.  If it's released, *@locked will be set to 0.
 */
long populate_vma_page_range(struct vm_area_struct *vma,
		unsigned long start, unsigned long end, int *locked)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int local_locked = 1;
	int gup_flags;
	long ret;

	VM_BUG_ON(!PAGE_ALIGNED(start));
	VM_BUG_ON(!PAGE_ALIGNED(end));
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	mmap_assert_locked(mm);

	/*
	 * Rightly or wrongly, the VM_LOCKONFAULT case has never used
	 * faultin_page() to break COW, so it has no work to do here.
	 */
	if (vma->vm_flags & VM_LOCKONFAULT)
		return nr_pages;

	gup_flags = FOLL_TOUCH;
	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma_is_accessible(vma))
		gup_flags |= FOLL_FORCE;

	if (locked)
		gup_flags |= FOLL_UNLOCKABLE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	ret = __get_user_pages(mm, start, nr_pages, gup_flags,
			       NULL, locked ? locked : &local_locked);
	lru_add_drain();
	return ret;
}

/*
 * faultin_vma_page_range() - populate (prefault) page tables inside the
 *			      given VMA range readable/writable
 *
 * This takes care of mlocking the pages, too, if VM_LOCKED is set.
 *
 * @vma: target vma
 * @start: start address
 * @end: end address
 * @write: whether to prefault readable or writable
 * @locked: whether the mmap_lock is still held
 *
 * Returns either number of processed pages in the vma, or a negative error
 * code on error (see __get_user_pages()).
 *
 * vma->vm_mm->mmap_lock must be held. The range must be page-aligned and
 * covered by the VMA. If it's released, *@locked will be set to 0.
 */
long faultin_vma_page_range(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end, bool write, int *locked)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;
	long ret;

	VM_BUG_ON(!PAGE_ALIGNED(start));
	VM_BUG_ON(!PAGE_ALIGNED(end));
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end > vma->vm_end, vma);
	mmap_assert_locked(mm);

	/*
	 * FOLL_TOUCH: Mark page accessed and thereby young; will also mark
	 *	       the page dirty with FOLL_WRITE -- which doesn't make a
	 *	       difference with !FOLL_FORCE, because the page is writable
	 *	       in the page table.
	 * FOLL_HWPOISON: Return -EHWPOISON instead of -EFAULT when we hit
	 *		  a poisoned page.
	 * !FOLL_FORCE: Require proper access permissions.
	 */
	gup_flags = FOLL_TOUCH | FOLL_HWPOISON | FOLL_UNLOCKABLE;
	if (write)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want to report -EINVAL instead of -EFAULT for any permission
	 * problems or incompatible mappings.
	 */
	if (check_vma_flags(vma, gup_flags))
		return -EINVAL;

	ret = __get_user_pages(mm, start, nr_pages, gup_flags,
			       NULL, locked);
	lru_add_drain();
	return ret;
}

/*
 * __mm_populate - populate and/or mlock pages within a range of address space.
 *
 * This is used to implement mlock() and the MAP_POPULATE / MAP_LOCKED mmap
 * flags. VMAs must be already marked with the desired vm_flags, and
 * mmap_lock must not be held.
 */
int __mm_populate(unsigned long start, unsigned long len, int ignore_errors)
{
	struct mm_struct *mm = current->mm;
	unsigned long end, nstart, nend;
	struct vm_area_struct *vma = NULL;
	int locked = 0;
	long ret = 0;

	end = start + len;

	for (nstart = start; nstart < end; nstart = nend) {
		/*
		 * We want to fault in pages for [nstart; end) address range.
		 * Find first corresponding VMA.
		 */
		if (!locked) {
			locked = 1;
			mmap_read_lock(mm);
			vma = find_vma_intersection(mm, nstart, end);
		} else if (nstart >= vma->vm_end)
			vma = find_vma_intersection(mm, vma->vm_end, end);

		if (!vma)
			break;
		/*
		 * Set [nstart; nend) to intersection of desired address
		 * range with the first VMA. Also, skip undesirable VMA types.
		 */
		nend = min(end, vma->vm_end);
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		if (nstart < vma->vm_start)
			nstart = vma->vm_start;
		/*
		 * Now fault in a range of pages. populate_vma_page_range()
		 * double checks the vma flags, so that it won't mlock pages
		 * if the vma was already munlocked.
		 */
		ret = populate_vma_page_range(vma, nstart, nend, &locked);
		if (ret < 0) {
			if (ignore_errors) {
				ret = 0;
				continue;	/* continue at next VMA */
			}
			break;
		}
		nend = nstart + ret * PAGE_SIZE;
		ret = 0;
	}
	if (locked)
		mmap_read_unlock(mm);
	return ret;	/* 0 or negative error code */
}
#else /* CONFIG_MMU */
static long __get_user_pages_locked(struct mm_struct *mm, unsigned long start,
		unsigned long nr_pages, struct page **pages,
		int *locked, unsigned int foll_flags)
{
	struct vm_area_struct *vma;
	bool must_unlock = false;
	unsigned long vm_flags;
	long i;

	if (!nr_pages)
		return 0;

	/*
	 * The internal caller expects GUP to manage the lock internally and the
	 * lock must be released when this returns.
	 */
	if (!*locked) {
		if (mmap_read_lock_killable(mm))
			return -EAGAIN;
		must_unlock = true;
		*locked = 1;
	}

	/* calculate required read or write permissions.
	 * If FOLL_FORCE is set, we only require the "MAY" flags.
	 */
	vm_flags  = (foll_flags & FOLL_WRITE) ?
			(VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	vm_flags &= (foll_flags & FOLL_FORCE) ?
			(VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);

	for (i = 0; i < nr_pages; i++) {
		vma = find_vma(mm, start);
		if (!vma)
			break;

		/* protect what we can, including chardevs */
		if ((vma->vm_flags & (VM_IO | VM_PFNMAP)) ||
		    !(vm_flags & vma->vm_flags))
			break;

		if (pages) {
			pages[i] = virt_to_page((void *)start);
			if (pages[i])
				get_page(pages[i]);
		}

		start = (start + PAGE_SIZE) & PAGE_MASK;
	}

	if (must_unlock && *locked) {
		mmap_read_unlock(mm);
		*locked = 0;
	}

	return i ? : -EFAULT;
}
#endif /* !CONFIG_MMU */

/**
 * fault_in_writeable - fault in userspace address range for writing
 * @uaddr: start of address range
 * @size: size of address range
 *
 * Returns the number of bytes not faulted in (like copy_to_user() and
 * copy_from_user()).
 */
size_t fault_in_writeable(char __user *uaddr, size_t size)
{
	char __user *start = uaddr, *end;

	if (unlikely(size == 0))
		return 0;
	if (!user_write_access_begin(uaddr, size))
		return size;
	if (!PAGE_ALIGNED(uaddr)) {
		unsafe_put_user(0, uaddr, out);
		uaddr = (char __user *)PAGE_ALIGN((unsigned long)uaddr);
	}
	end = (char __user *)PAGE_ALIGN((unsigned long)start + size);
	if (unlikely(end < start))
		end = NULL;
	while (uaddr != end) {
		unsafe_put_user(0, uaddr, out);
		uaddr += PAGE_SIZE;
	}

out:
	user_write_access_end();
	if (size > uaddr - start)
		return size - (uaddr - start);
	return 0;
}
EXPORT_SYMBOL(fault_in_writeable);

/**
 * fault_in_subpage_writeable - fault in an address range for writing
 * @uaddr: start of address range
 * @size: size of address range
 *
 * Fault in a user address range for writing while checking for permissions at
 * sub-page granularity (e.g. arm64 MTE). This function should be used when
 * the caller cannot guarantee forward progress of a copy_to_user() loop.
 *
 * Returns the number of bytes not faulted in (like copy_to_user() and
 * copy_from_user()).
 */
size_t fault_in_subpage_writeable(char __user *uaddr, size_t size)
{
	size_t faulted_in;

	/*
	 * Attempt faulting in at page granularity first for page table
	 * permission checking. The arch-specific probe_subpage_writeable()
	 * functions may not check for this.
	 */
	faulted_in = size - fault_in_writeable(uaddr, size);
	if (faulted_in)
		faulted_in -= probe_subpage_writeable(uaddr, faulted_in);

	return size - faulted_in;
}
EXPORT_SYMBOL(fault_in_subpage_writeable);

/*
 * fault_in_safe_writeable - fault in an address range for writing
 * @uaddr: start of address range
 * @size: length of address range
 *
 * Faults in an address range for writing.  This is primarily useful when we
 * already know that some or all of the pages in the address range aren't in
 * memory.
 *
 * Unlike fault_in_writeable(), this function is non-destructive.
 *
 * Note that we don't pin or otherwise hold the pages referenced that we fault
 * in.  There's no guarantee that they'll stay in memory for any duration of
 * time.
 *
 * Returns the number of bytes not faulted in, like copy_to_user() and
 * copy_from_user().
 */
size_t fault_in_safe_writeable(const char __user *uaddr, size_t size)
{
	unsigned long start = (unsigned long)uaddr, end;
	struct mm_struct *mm = current->mm;
	bool unlocked = false;

	if (unlikely(size == 0))
		return 0;
	end = PAGE_ALIGN(start + size);
	if (end < start)
		end = 0;

	mmap_read_lock(mm);
	do {
		if (fixup_user_fault(mm, start, FAULT_FLAG_WRITE, &unlocked))
			break;
		start = (start + PAGE_SIZE) & PAGE_MASK;
	} while (start != end);
	mmap_read_unlock(mm);

	if (size > (unsigned long)uaddr - start)
		return size - ((unsigned long)uaddr - start);
	return 0;
}
EXPORT_SYMBOL(fault_in_safe_writeable);

/**
 * fault_in_readable - fault in userspace address range for reading
 * @uaddr: start of user address range
 * @size: size of user address range
 *
 * Returns the number of bytes not faulted in (like copy_to_user() and
 * copy_from_user()).
 */
size_t fault_in_readable(const char __user *uaddr, size_t size)
{
	const char __user *start = uaddr, *end;
	volatile char c;

	if (unlikely(size == 0))
		return 0;
	if (!user_read_access_begin(uaddr, size))
		return size;
	if (!PAGE_ALIGNED(uaddr)) {
		unsafe_get_user(c, uaddr, out);
		uaddr = (const char __user *)PAGE_ALIGN((unsigned long)uaddr);
	}
	end = (const char __user *)PAGE_ALIGN((unsigned long)start + size);
	if (unlikely(end < start))
		end = NULL;
	while (uaddr != end) {
		unsafe_get_user(c, uaddr, out);
		uaddr += PAGE_SIZE;
	}

out:
	user_read_access_end();
	(void)c;
	if (size > uaddr - start)
		return size - (uaddr - start);
	return 0;
}
EXPORT_SYMBOL(fault_in_readable);

/**
 * get_dump_page() - pin user page in memory while writing it to core dump
 * @addr: user address
 *
 * Returns struct page pointer of user page pinned for dump,
 * to be freed afterwards by put_page().
 *
 * Returns NULL on any kind of failure - a hole must then be inserted into
 * the corefile, to preserve alignment with its headers; and also returns
 * NULL wherever the ZERO_PAGE, or an anonymous pte_none, has been found -
 * allowing a hole to be left in the corefile to save disk space.
 *
 * Called without mmap_lock (takes and releases the mmap_lock by itself).
 */
#ifdef CONFIG_ELF_CORE
struct page *get_dump_page(unsigned long addr)
{
	struct page *page;
	int locked = 0;
	int ret;

	ret = __get_user_pages_locked(current->mm, addr, 1, &page, &locked,
				      FOLL_FORCE | FOLL_DUMP | FOLL_GET);
	return (ret == 1) ? page : NULL;
}
#endif /* CONFIG_ELF_CORE */

#ifdef CONFIG_MIGRATION
/*
 * Returns the number of collected pages. Return value is always >= 0.
 判断哪些是不能LONGTERM_PIN的,一般是比较"灵活的"
 就从lru移除, 收集到movable_page_list上面
 */
static unsigned long collect_longterm_unpinnable_pages(
					struct list_head *movable_page_list,
					unsigned long nr_pages,
					struct page **pages)
{
	unsigned long i, collected = 0;
	struct folio *prev_folio = NULL;
	bool drain_allow = true;

	for (i = 0; i < nr_pages; i++) {
		struct folio *folio = page_folio(pages[i]);

		if (folio == prev_folio)
			continue;// 有可能连续的几个页面是同一个folio
		prev_folio = folio;

		if (folio_is_longterm_pinnable(folio))
			continue;

		// 找到了不能被固定的page
		// 感觉比较灵活的都是不能LONGTERM_PIN的
		collected++;

		if (folio_is_device_coherent(folio))
			continue;

		if (folio_test_hugetlb(folio)) {
			isolate_hugetlb(folio, movable_page_list);
			continue;
		}

		// 如果folio还不在lru上面?
		if (!folio_test_lru(folio) && drain_allow) {
			lru_add_drain_all(); // 排空pcp的lru缓存
			drain_allow = false;
		}
		// 排空之后应该在了

		// 清除folio的lru flag
		if (!folio_isolate_lru(folio))
			continue;// 如果本来不在lru上面

		// 这是个本来在lru的folio
		// 下面把它收集起来
		list_add_tail(&folio->lru, movable_page_list);
		node_stat_mod_folio(folio,
				    NR_ISOLATED_ANON + folio_is_file_lru(folio),
				    folio_nr_pages(folio));
	}

	return collected;
}

/*
movalbe_page_list上面的页面都是从pages里面筛选的不能LONGTERM_PIN的,是刚刚
从lru移除,收集到movable_page_list上面的,一般是比较"灵活的"
================
这里unpin全部的页面,然后把movable_page_list上面的页面迁移,然后再重新放回lru
 * Unpins all pages and migrates device coherent pages and movable_page_list.
 * Returns -EAGAIN if all pages were successfully migrated or -errno for failure
 * (or partial success).
 unpin全部的页面,迁移device coherent的页面和movable_page_list上面的
 如果所有页面都成功迁移,返回-EAGAIN,否则返回-errno
 */
static int migrate_longterm_unpinnable_pages(
					struct list_head *movable_page_list,
					unsigned long nr_pages,
					struct page **pages)
{
	int ret;
	unsigned long i;

	for (i = 0; i < nr_pages; i++) {
		struct folio *folio = page_folio(pages[i]);

		if (folio_is_device_coherent(folio)) {
			/*
			 * Migration will fail if the page is pinned, so convert
			 * the pin on the source page to a normal reference.
			 */
			pages[i] = NULL;
			folio_get(folio);
			gup_put_folio(folio, 1, FOLL_PIN);

			if (migrate_device_coherent_page(&folio->page)) {
				ret = -EBUSY;
				goto err;
			}

			continue;
		}

		/*
		 * We can't migrate pages with unexpected references, so drop
		 * the reference obtained by __get_user_pages_locked().
		 * Migrating pages have been added to movable_page_list after
		 * calling folio_isolate_lru() which takes a reference so the
		 * page won't be freed if it's migrating.
		 */
		unpin_user_page(pages[i]);
		pages[i] = NULL;
	}

	if (!list_empty(movable_page_list)) {// 如果有需要迁移的
		struct migration_target_control mtc = {
			.nid = NUMA_NO_NODE,
			.gfp_mask = GFP_USER | __GFP_NOWARN,
		};

		// 移动页面
		if (migrate_pages(movable_page_list, alloc_migration_target,
				  NULL, (unsigned long)&mtc, MIGRATE_SYNC,
				  MR_LONGTERM_PIN, NULL)) {
			ret = -ENOMEM;
			goto err;
		}
	}
	// 放回lru
	putback_movable_pages(movable_page_list);

	return -EAGAIN;

err:
	for (i = 0; i < nr_pages; i++)
		if (pages[i])
			unpin_user_page(pages[i]);
	putback_movable_pages(movable_page_list);

	return ret;
}

/*
把数组里面的不能LONGTERM_PIN的页面收集起来,然后迁移,然后重新放回lru
 * Check whether all pages are *allowed* to be pinned. Rather confusingly, all
 * pages in the range are required to be pinned via FOLL_PIN, before calling
 * this routine.
 * 检查所有页面是否允许被固定。令人困惑的是，在调用此例程之前，所有页面都需要通过FOLL_PIN固定。
 * If any pages in the range are not allowed to be pinned, then this routine
 * will migrate those pages away, unpin all the pages in the range and return
 * -EAGAIN. The caller should re-pin the entire range with FOLL_PIN and then
 * call this routine again.
 * 如果范围内的任何页面不允许被固定，则此例程将迁移这些页面，取消固定范围内的所有页面并返回-EAGAIN。
 * 调用者应重新使用FOLL_PIN固定整个范围，然后再次调用此例程。
 * If an error other than -EAGAIN occurs, this indicates a migration failure.
 * The caller should give up, and propagate the error back up the call stack.
 *
 * If everything is OK and all pages in the range are allowed to be pinned, then
 * this routine leaves all pages pinned and returns zero for success.
 */
static long check_and_migrate_movable_pages(unsigned long nr_pages,
					    struct page **pages)
{
	unsigned long collected;
	LIST_HEAD(movable_page_list);
	// 先收集
	collected = collect_longterm_unpinnable_pages(&movable_page_list,
						nr_pages, pages);
	if (!collected)
		return 0; // 很好, 一个也没有
	// unppin全部的页面,然后把movable_page_list上面的页面迁移,然后再重新放回lru
	return migrate_longterm_unpinnable_pages(&movable_page_list, nr_pages,
						pages);
}
#else
static long check_and_migrate_movable_pages(unsigned long nr_pages,
					    struct page **pages)
{
	return 0;
}
#endif /* CONFIG_MIGRATION */

/*
一个一个follow page (可以起到pin的作用?), 加入到pages数组
 * __gup_longterm_locked() is a wrapper for __get_user_pages_locked which
 * allows us to process the FOLL_LONGTERM flag.
   是一个__get_user_pages_locked的包装器，允许我们处理FOLL_LONGTERM标志。
 */
static long __gup_longterm_locked(struct mm_struct *mm,
				  unsigned long start,
				  unsigned long nr_pages,
				  struct page **pages,
				  int *locked,
				  unsigned int gup_flags)
{
	unsigned int flags;
	long rc, nr_pinned_pages;

	if (!(gup_flags & FOLL_LONGTERM)) // 如果不是LONGTERM
		return __get_user_pages_locked(mm, start, nr_pages, pages,
					       locked, gup_flags);
	// 如果是LONGTERM
	flags = memalloc_pin_save();
	do {
		// 获取一些pages
		nr_pinned_pages = __get_user_pages_locked(mm, start, nr_pages,
							  pages, locked,
							  gup_flags);
		if (nr_pinned_pages <= 0) {
			rc = nr_pinned_pages;
			break;
		}

		/* FOLL_LONGTERM implies FOLL_PIN */
		// 把pages里面不能LONGTERM_PIN的收集起来,然后迁移,然后重新放回lru
		rc = check_and_migrate_movable_pages(nr_pinned_pages, pages);
		// 返回0是没事
	} while (rc == -EAGAIN);
	memalloc_pin_restore(flags);
	return rc ? rc : nr_pinned_pages;
}

/*
什么算是valid?
 * Check that the given flags are valid for the exported gup/pup interface, and
 * update them with the required flags that the caller must have set.
 */
static bool is_valid_gup_args(struct page **pages, int *locked,
			      unsigned int *gup_flags_p, unsigned int to_set)
{
	unsigned int gup_flags = *gup_flags_p;

	/*
	 * These flags not allowed to be specified externally to the gup
	 * interfaces:
	 * - FOLL_PIN/FOLL_TRIED/FOLL_FAST_ONLY are internal only
	 * - FOLL_REMOTE is internal only and used on follow_page()
	 * - FOLL_UNLOCKABLE is internal only and used if locked is !NULL
	 */
	if (WARN_ON_ONCE(gup_flags & (FOLL_PIN | FOLL_TRIED | FOLL_UNLOCKABLE |
				      FOLL_REMOTE | FOLL_FAST_ONLY)))
		return false;

	gup_flags |= to_set;
	if (locked) {
		/* At the external interface locked must be set */
		if (WARN_ON_ONCE(*locked != 1))
			return false;

		gup_flags |= FOLL_UNLOCKABLE;
	}

	/* FOLL_GET and FOLL_PIN are mutually exclusive. */
	if (WARN_ON_ONCE((gup_flags & (FOLL_PIN | FOLL_GET)) ==
			 (FOLL_PIN | FOLL_GET)))
		return false;

	/* LONGTERM can only be specified when pinning */
	if (WARN_ON_ONCE(!(gup_flags & FOLL_PIN) && (gup_flags & FOLL_LONGTERM)))
		return false;

	/* Pages input must be given if using GET/PIN */
	if (WARN_ON_ONCE((gup_flags & (FOLL_GET | FOLL_PIN)) && !pages))
		return false;

	/* We want to allow the pgmap to be hot-unplugged at all times */
	if (WARN_ON_ONCE((gup_flags & FOLL_LONGTERM) &&
			 (gup_flags & FOLL_PCI_P2PDMA)))
		return false;

	*gup_flags_p = gup_flags;
	return true;
}

#ifdef CONFIG_MMU
/**
读取其他进程地址空间的一个页面
读取mm的start地址开始的nr_pages个页面，存放到pages
 * get_user_pages_remote() - pin user pages in memory
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying lookup behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @locked:	pointer to lock flag indicating whether lock is held and
 *		subsequently whether VM_FAULT_RETRY functionality can be
 *		utilised. Lock must initially be held.
 *
 * Returns either number of pages pinned (which may be less than the
 * number requested), or an error. Details about the return value:
 *
 * -- If nr_pages is 0, returns 0.
 * -- If nr_pages is >0, but no pages were pinned, returns -errno.
 * -- If nr_pages is >0, and some pages were pinned, returns the number of
 *    pages pinned. Again, this may be less than nr_pages.
 *
 * The caller is responsible for releasing returned @pages, via put_page().
 *
 * Must be called with mmap_lock held for read or write.
 *
 * get_user_pages_remote walks a process's page tables and takes a reference
 * to each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 * 函数遍历进程的页表，获取每个用户地址对应的struct page的引用
 * 也就是说，获取用户线程在给定时刻访问给定用户虚拟地址时将访问的页面
 * This does not guarantee that the page exists in the user mappings when
 * get_user_pages_remote returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re-faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If gup_flags & FOLL_WRITE == 0, the page must not be written to. If the page
 * is written to, set_page_dirty (or set_page_dirty_lock, as appropriate) must
 * be called after the page is finished with, and before put_page is called.
 *
 * get_user_pages_remote is typically used for fewer-copy IO operations,
 * to get a handle on the memory by some means other than accesses
 * via the user virtual addresses. The pages may be submitted for
 * DMA to devices or accessed via their kernel linear mapping (via the
 * kmap APIs). Care should be taken to use the correct cache flushing APIs.
 *
 * See also get_user_pages_fast, for performance critical applications.
 *
 * get_user_pages_remote should be phased out in favor of
 * get_user_pages_locked|unlocked or get_user_pages_fast. Nothing
 * should use get_user_pages_remote because it cannot pass
 * FAULT_FLAG_ALLOW_RETRY to handle_mm_fault.
 */
long get_user_pages_remote(struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		int *locked)
{
	int local_locked = 1;

	if (!is_valid_gup_args(pages, locked, &gup_flags,
			       FOLL_TOUCH | FOLL_REMOTE))
		return -EINVAL;

	/* 开始获取 */
	return __get_user_pages_locked(mm, start, nr_pages, pages,
				       locked ? locked : &local_locked,
				       gup_flags);
}
EXPORT_SYMBOL(get_user_pages_remote);

#else /* CONFIG_MMU */
long get_user_pages_remote(struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked)
{
	return 0;
}
#endif /* !CONFIG_MMU */

/**
 * get_user_pages() - pin user pages in memory
 * @start:      starting user address
 * @nr_pages:   number of pages from start to pin
 * @gup_flags:  flags modifying lookup behaviour
 * @pages:      array that receives pointers to the pages pinned.
 *              Should be at least nr_pages long. Or NULL, if caller
 *              only intends to ensure the pages are faulted in.
 *
 * This is the same as get_user_pages_remote(), just with a less-flexible
 * calling convention where we assume that the mm being operated on belongs to
 * the current task, and doesn't allow passing of a locked parameter.  We also
 * obviously don't pass FOLL_REMOTE in here.
 */
long get_user_pages(unsigned long start, unsigned long nr_pages,
		    unsigned int gup_flags, struct page **pages)
{
	int locked = 1;

	if (!is_valid_gup_args(pages, NULL, &gup_flags, FOLL_TOUCH))
		return -EINVAL;

	return __get_user_pages_locked(current->mm, start, nr_pages, pages,
				       &locked, gup_flags);
}
EXPORT_SYMBOL(get_user_pages);

/*
 * get_user_pages_unlocked() is suitable to replace the form:
 *
 *      mmap_read_lock(mm);
 *      get_user_pages(mm, ..., pages, NULL);
 *      mmap_read_unlock(mm);
 *
 *  with:
 *
 *      get_user_pages_unlocked(mm, ..., pages);
 *
 * It is functionally equivalent to get_user_pages_fast so
 * get_user_pages_fast should be used instead if specific gup_flags
 * (e.g. FOLL_FORCE) are not required.
 */
long get_user_pages_unlocked(unsigned long start, unsigned long nr_pages,
			     struct page **pages, unsigned int gup_flags)
{
	int locked = 0;

	if (!is_valid_gup_args(pages, NULL, &gup_flags,
			       FOLL_TOUCH | FOLL_UNLOCKABLE))
		return -EINVAL;

	return __get_user_pages_locked(current->mm, start, nr_pages, pages,
				       &locked, gup_flags);
}
EXPORT_SYMBOL(get_user_pages_unlocked);

/*
 * Fast GUP
 *
 * get_user_pages_fast attempts to pin user pages by walking the page
 * tables directly and avoids taking locks. Thus the walker needs to be
 * protected from page table pages being freed from under it, and should
 * block any THP splits.
 *
 * One way to achieve this is to have the walker disable interrupts, and
 * rely on IPIs from the TLB flushing code blocking before the page table
 * pages are freed. This is unsuitable for architectures that do not need
 * to broadcast an IPI when invalidating TLBs.
 *
 * Another way to achieve this is to batch up page table containing pages
 * belonging to more than one mm_user, then rcu_sched a callback to free those
 * pages. Disabling interrupts will allow the fast_gup walker to both block
 * the rcu_sched callback, and an IPI that we broadcast for splitting THPs
 * (which is a relatively rare event). The code below adopts this strategy.
 *
 * Before activating this code, please be aware that the following assumptions
 * are currently made:
 *
 *  *) Either MMU_GATHER_RCU_TABLE_FREE is enabled, and tlb_remove_table() is used to
 *  free pages containing page tables or TLB flushing requires IPI broadcast.
 *
 *  *) ptes can be read atomically by the architecture.
 *
 *  *) access_ok is sufficient to validate userspace address ranges.
 *
 * The last two assumptions can be relaxed by the addition of helper functions.
 *
 * This code is based heavily on the PowerPC implementation by Nick Piggin.
 */
#ifdef CONFIG_HAVE_FAST_GUP

/*
在gup-fast路径中使用，用于确定是否允许为特定的folio固定页。
 * Used in the GUP-fast path to determine whether a pin is permitted for a
 * specific folio.
 *
 * This call assumes the caller has pinned the folio, that the lowest page table
 * level still points to this folio, and that interrupts have been disabled.
 * 这个调用假设调用者已经固定了folio，最低的页表级别仍然指向这个folio，并且中断已经被禁用。
 * Writing to pinned file-backed dirty tracked folios is inherently problematic
 * (see comment describing the writable_file_mapping_allowed() function). We
 * therefore try to avoid the most egregious case of a long-term mapping doing
 * so.
 * 写入固定的文件支持的脏跟踪folio本质上是有问题的（请参阅描述writable_file_mapping_allowed()
 函数的注释）。
 * 因此，我们尝试避免长期映射这样做的最严重情况。
 * This function cannot be as thorough as that one as the VMA is not available
 * in the fast path, so instead we whitelist known good cases and if in doubt,
 * fall back to the slow path.
 */
static bool folio_fast_pin_allowed(struct folio *folio, unsigned int flags)
{
	struct address_space *mapping;
	unsigned long mapping_flags;

	/*
	 * If we aren't pinning then no problematic write can occur. A long term
	 * pin is the most egregious case so this is the one we disallow.
	 如果我们不固定，那么不会发生任何问题的写入。
	 长期固定是最严重的情况，所以我们不允许这种情况。
	 */
	if ((flags & (FOLL_PIN | FOLL_LONGTERM | FOLL_WRITE)) !=
	    (FOLL_PIN | FOLL_LONGTERM | FOLL_WRITE))
		return true;

	/* 如果是LONGTERM的PIN WRITE就往下
	 */
	/* The folio is pinned, so we can safely access folio fields. */

	if (WARN_ON_ONCE(folio_test_slab(folio)))
		return false;

	/* hugetlb mappings do not require dirty-tracking. */
	if (folio_test_hugetlb(folio))
		return true;

	/*
	 * GUP-fast disables IRQs. When IRQS are disabled, RCU grace periods
	 * cannot proceed, which means no actions performed under RCU can
	 * proceed either.
	 * GUP-fast禁用IRQS。当禁用IRQS时，RCU宽限期无法继续，这意味着在RCU下执行的操作也无法继续。
	 * inodes and thus their mappings are freed under RCU, which means the
	 * mapping cannot be freed beneath us and thus we can safely dereference
	 * it.
	 inodes和它们的映射在RCU下被释放，这意味着映射不能在我们下面被释放，因此我们
	 可以安全地对其进行解引用。
	 */
	lockdep_assert_irqs_disabled();

	/*
	 * However, there may be operations which _alter_ the mapping, so ensure
	 * we read it once and only once.
	 * 但是，可能有操作会更改映射，因此确保我们只读取一次。
	 */
	mapping = READ_ONCE(folio->mapping);

	/*
	 * The mapping may have been truncated, in any case we cannot determine
	 * if this mapping is safe - fall back to slow path to determine how to
	 * proceed.
	 mapping可能已经被截断，无论如何，我们无法确定这个映射是否安全-退回到慢路径以确定如何继续。
	 */
	if (!mapping)
		return false;

	/* Anonymous folios pose no problem. */
	mapping_flags = (unsigned long)mapping & PAGE_MAPPING_FLAGS;
	if (mapping_flags)
		return mapping_flags & PAGE_MAPPING_ANON;

	/*
	 * At this point, we know the mapping is non-null and points to an
	 * address_space object. The only remaining whitelisted file system is
	 * shmem.
	 此时，我们知道映射是非空的，并且指向一个address_space对象。 
	 唯一剩下的白名单文件系统是shmem。
	 */
	return shmem_mapping(mapping);
}

static void __maybe_unused undo_dev_pagemap(int *nr, int nr_start,
					    unsigned int flags,
					    struct page **pages)
{
	while ((*nr) - nr_start) {
		struct page *page = pages[--(*nr)];

		ClearPageReferenced(page);
		if (flags & FOLL_PIN)
			unpin_user_page(page);
		else
			put_page(page);
	}
}

#ifdef CONFIG_ARCH_HAS_PTE_SPECIAL
/*
开始处理pmd上面的pte
 * Fast-gup relies on pte change detection to avoid concurrent pgtable
 * operations.
 * fast-gup依赖于pte更改检测，以避免并发的pgtable操作。
 * To pin the page, fast-gup needs to do below in order:
 * (1) pin the page (by prefetching pte), then (2) check pte not changed.
 * 为了固定页面，fast-gup需要按顺序执行以下操作：
 * （1）固定页面（通过预取pte），然后（2）检查pte未更改。
 * For the rest of pgtable operations where pgtable updates can be racy
 * with fast-gup, we need to do (1) clear pte, then (2) check whether page
 * is pinned.
 * 对于pgtable更新可能与fast-gup竞争的其他pgtable操作，我们需要执行（1）清除pte，
 * 然后（2）检查页面是否被固定。
 * Above will work for all pte-level operations, including THP split.
 *
 * For THP collapse, it's a bit more complicated because fast-gup may be
 * walking a pgtable page that is being freed (pte is still valid but pmd
 * can be cleared already).  To avoid race in such condition, we need to
 * also check pmd here to make sure pmd doesn't change (corresponds to
 * pmdp_collapse_flush() in the THP collapse code path).
 */
static int gup_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
			 unsigned long end, unsigned int flags,
			 struct page **pages, int *nr)
{
	struct dev_pagemap *pgmap = NULL;
	int nr_start = *nr, ret = 0;
	pte_t *ptep, *ptem;

	ptem = ptep = pte_offset_map(&pmd, addr);
	if (!ptep)
		return 0;
	do {
		// 读取pte条目
		pte_t pte = ptep_get_lockless(ptep);
		struct page *page;
		struct folio *folio;

		/*
		 * Always fallback to ordinary GUP on PROT_NONE-mapped pages:
		 * pte_access_permitted() better should reject these pages
		 * either way: otherwise, GUP-fast might succeed in
		 * cases where ordinary GUP would fail due to VMA access
		 * permissions.
		 一直回退到普通的GUP，因为pte_access_permitted()应该拒绝这些页面，
		 否则GUP-fast可能会成功，而普通的GUP由于VMA访问权限而失败。
		 */
		if (pte_protnone(pte))
			goto pte_unmap;

		if (!pte_access_permitted(pte, flags & FOLL_WRITE))
			goto pte_unmap;
		/* 现在pte还是rw,present,user的 */


		// 处理两个特殊情况
		if (pte_devmap(pte)) {
			if (unlikely(flags & FOLL_LONGTERM))
				goto pte_unmap;

			pgmap = get_dev_pagemap(pte_pfn(pte), pgmap);
			if (unlikely(!pgmap)) {
				undo_dev_pagemap(nr, nr_start, flags, pages);
				goto pte_unmap;
			}
		} else if (pte_special(pte))
			goto pte_unmap;

		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte); // 获取pte对应的page

		folio = try_grab_folio(page, 1, flags);
		if (!folio)
			goto pte_unmap;

		if (unlikely(folio_is_secretmem(folio))) {
			gup_put_folio(folio, 1, flags);
			goto pte_unmap;
		}

		if (unlikely(pmd_val(pmd) != pmd_val(*pmdp)) ||
		    unlikely(pte_val(pte) != pte_val(ptep_get(ptep)))) {/*
				如果获取之后, pmd和pte更改了, 放弃
				*/
			gup_put_folio(folio, 1, flags);
			goto pte_unmap;
		}

		if (!folio_fast_pin_allowed(folio, flags)) {// 如果不允许
			gup_put_folio(folio, 1, flags);
			goto pte_unmap;
		}

		if (!pte_write(pte) && gup_must_unshare(NULL, flags, page)) {
			gup_put_folio(folio, 1, flags);
			goto pte_unmap;
		}

		/*
		 * We need to make the page accessible if and only if we are
		 * going to access its content (the FOLL_PIN case).  Please
		 * see Documentation/core-api/pin_user_pages.rst for
		 * details.
		   我们需要使页面可访问，如果且仅当我们将访问其内容（FOLL_PIN情况）。
		   请参阅Documentation/core-api/pin_user_pages.rst了解详细信息。
		 */
		if (flags & FOLL_PIN) {
			ret = arch_make_page_accessible(page);
			if (ret) {
				gup_put_folio(folio, 1, flags);
				goto pte_unmap;
			}
		}
		// 设置referenced标志
		folio_set_referenced(folio);
		pages[*nr] = page;
		(*nr)++;
	} while (ptep++, addr += PAGE_SIZE, addr != end);

	ret = 1;

pte_unmap:
	if (pgmap)
		put_dev_pagemap(pgmap);
	pte_unmap(ptem);
	return ret;
}
#else

/*
 * If we can't determine whether or not a pte is special, then fail immediately
 * for ptes. Note, we can still pin HugeTLB and THP as these are guaranteed not
 * to be special.
 *
 * For a futex to be placed on a THP tail page, get_futex_key requires a
 * get_user_pages_fast_only implementation that can pin pages. Thus it's still
 * useful to have gup_huge_pmd even if we can't operate on ptes.
 */
static int gup_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
			 unsigned long end, unsigned int flags,
			 struct page **pages, int *nr)
{
	return 0;
}
#endif /* CONFIG_ARCH_HAS_PTE_SPECIAL */

#if defined(CONFIG_ARCH_HAS_PTE_DEVMAP) && defined(CONFIG_TRANSPARENT_HUGEPAGE)
static int __gup_device_huge(unsigned long pfn, unsigned long addr,
			     unsigned long end, unsigned int flags,
			     struct page **pages, int *nr)
{
	int nr_start = *nr;
	struct dev_pagemap *pgmap = NULL;

	do {
		struct page *page = pfn_to_page(pfn);

		pgmap = get_dev_pagemap(pfn, pgmap);
		if (unlikely(!pgmap)) {
			undo_dev_pagemap(nr, nr_start, flags, pages);
			break;
		}

		if (!(flags & FOLL_PCI_P2PDMA) && is_pci_p2pdma_page(page)) {
			undo_dev_pagemap(nr, nr_start, flags, pages);
			break;
		}

		SetPageReferenced(page);
		pages[*nr] = page;
		if (unlikely(try_grab_page(page, flags))) {
			undo_dev_pagemap(nr, nr_start, flags, pages);
			break;
		}
		(*nr)++;
		pfn++;
	} while (addr += PAGE_SIZE, addr != end);

	put_dev_pagemap(pgmap);
	return addr == end;
}

static int __gup_device_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
				 unsigned long end, unsigned int flags,
				 struct page **pages, int *nr)
{
	unsigned long fault_pfn;
	int nr_start = *nr;

	fault_pfn = pmd_pfn(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (!__gup_device_huge(fault_pfn, addr, end, flags, pages, nr))
		return 0;

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		undo_dev_pagemap(nr, nr_start, flags, pages);
		return 0;
	}
	return 1;
}

static int __gup_device_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
				 unsigned long end, unsigned int flags,
				 struct page **pages, int *nr)
{
	unsigned long fault_pfn;
	int nr_start = *nr;

	fault_pfn = pud_pfn(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (!__gup_device_huge(fault_pfn, addr, end, flags, pages, nr))
		return 0;

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		undo_dev_pagemap(nr, nr_start, flags, pages);
		return 0;
	}
	return 1;
}
#else
static int __gup_device_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
				 unsigned long end, unsigned int flags,
				 struct page **pages, int *nr)
{
	BUILD_BUG();
	return 0;
}

static int __gup_device_huge_pud(pud_t pud, pud_t *pudp, unsigned long addr,
				 unsigned long end, unsigned int flags,
				 struct page **pages, int *nr)
{
	BUILD_BUG();
	return 0;
}
#endif

static int record_subpages(struct page *page, unsigned long addr,
			   unsigned long end, struct page **pages)
{
	int nr;

	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
		pages[nr] = nth_page(page, nr);

	return nr;
}

#ifdef CONFIG_ARCH_HAS_HUGEPD
static unsigned long hugepte_addr_end(unsigned long addr, unsigned long end,
				      unsigned long sz)
{
	unsigned long __boundary = (addr + sz) & ~(sz-1);
	return (__boundary - 1 < end - 1) ? __boundary : end;
}

static int gup_hugepte(pte_t *ptep, unsigned long sz, unsigned long addr,
		       unsigned long end, unsigned int flags,
		       struct page **pages, int *nr)
{
	unsigned long pte_end;
	struct page *page;
	struct folio *folio;
	pte_t pte;
	int refs;

	pte_end = (addr + sz) & ~(sz-1);
	if (pte_end < end)
		end = pte_end;

	pte = huge_ptep_get(ptep);

	if (!pte_access_permitted(pte, flags & FOLL_WRITE))
		return 0;

	/* hugepages are never "special" */
	VM_BUG_ON(!pfn_valid(pte_pfn(pte)));

	page = nth_page(pte_page(pte), (addr & (sz - 1)) >> PAGE_SHIFT);
	refs = record_subpages(page, addr, end, pages + *nr);

	folio = try_grab_folio(page, refs, flags);
	if (!folio)
		return 0;

	if (unlikely(pte_val(pte) != pte_val(ptep_get(ptep)))) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!folio_fast_pin_allowed(folio, flags)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!pte_write(pte) && gup_must_unshare(NULL, flags, &folio->page)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	*nr += refs;
	folio_set_referenced(folio);
	return 1;
}

static int gup_huge_pd(hugepd_t hugepd, unsigned long addr,
		unsigned int pdshift, unsigned long end, unsigned int flags,
		struct page **pages, int *nr)
{
	pte_t *ptep;
	unsigned long sz = 1UL << hugepd_shift(hugepd);
	unsigned long next;

	ptep = hugepte_offset(hugepd, addr, pdshift);
	do {
		next = hugepte_addr_end(addr, end, sz);
		if (!gup_hugepte(ptep, sz, addr, end, flags, pages, nr))
			return 0;
	} while (ptep++, addr = next, addr != end);

	return 1;
}
#else
static inline int gup_huge_pd(hugepd_t hugepd, unsigned long addr,
		unsigned int pdshift, unsigned long end, unsigned int flags,
		struct page **pages, int *nr)
{
	return 0;
}
#endif /* CONFIG_ARCH_HAS_HUGEPD */

static int gup_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
			unsigned long end, unsigned int flags,
			struct page **pages, int *nr)
{
	struct page *page;
	struct folio *folio;
	int refs;

	if (!pmd_access_permitted(orig, flags & FOLL_WRITE))
		return 0;

	if (pmd_devmap(orig)) {
		if (unlikely(flags & FOLL_LONGTERM))
			return 0;
		return __gup_device_huge_pmd(orig, pmdp, addr, end, flags,
					     pages, nr);
	}

	page = nth_page(pmd_page(orig), (addr & ~PMD_MASK) >> PAGE_SHIFT);
	refs = record_subpages(page, addr, end, pages + *nr);

	folio = try_grab_folio(page, refs, flags);
	if (!folio)
		return 0;

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!folio_fast_pin_allowed(folio, flags)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}
	if (!pmd_write(orig) && gup_must_unshare(NULL, flags, &folio->page)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	*nr += refs;
	folio_set_referenced(folio);
	return 1;
}

static int gup_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
			unsigned long end, unsigned int flags,
			struct page **pages, int *nr)
{
	struct page *page;
	struct folio *folio;
	int refs;

	if (!pud_access_permitted(orig, flags & FOLL_WRITE))
		return 0;

	if (pud_devmap(orig)) {
		if (unlikely(flags & FOLL_LONGTERM))
			return 0;
		return __gup_device_huge_pud(orig, pudp, addr, end, flags,
					     pages, nr);
	}

	page = nth_page(pud_page(orig), (addr & ~PUD_MASK) >> PAGE_SHIFT);
	refs = record_subpages(page, addr, end, pages + *nr);

	folio = try_grab_folio(page, refs, flags);
	if (!folio)
		return 0;

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!folio_fast_pin_allowed(folio, flags)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!pud_write(orig) && gup_must_unshare(NULL, flags, &folio->page)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	*nr += refs;
	folio_set_referenced(folio);
	return 1;
}

static int gup_huge_pgd(pgd_t orig, pgd_t *pgdp, unsigned long addr,
			unsigned long end, unsigned int flags,
			struct page **pages, int *nr)
{
	int refs;
	struct page *page;
	struct folio *folio;

	if (!pgd_access_permitted(orig, flags & FOLL_WRITE))
		return 0;

	BUILD_BUG_ON(pgd_devmap(orig));

	page = nth_page(pgd_page(orig), (addr & ~PGDIR_MASK) >> PAGE_SHIFT);
	refs = record_subpages(page, addr, end, pages + *nr);

	folio = try_grab_folio(page, refs, flags);
	if (!folio)
		return 0;

	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!pgd_write(orig) && gup_must_unshare(NULL, flags, &folio->page)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	if (!folio_fast_pin_allowed(folio, flags)) {
		gup_put_folio(folio, refs, flags);
		return 0;
	}

	*nr += refs;
	folio_set_referenced(folio);
	return 1;
}
// 一级一级的迭代页表,如果有空页表就返回, 最后把pte层面经过检查的页面操作之后,放入pages数组
static int gup_pmd_range(pud_t *pudp, pud_t pud, unsigned long addr, unsigned long end,
		unsigned int flags, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset_lockless(pudp, pud, addr);
	do {
		pmd_t pmd = pmdp_get_lockless(pmdp);

		next = pmd_addr_end(addr, end);
		if (!pmd_present(pmd))
			return 0;

		if (unlikely(pmd_trans_huge(pmd) || pmd_huge(pmd) ||
			     pmd_devmap(pmd))) {
			/* See gup_pte_range() */
			if (pmd_protnone(pmd))
				return 0;

			if (!gup_huge_pmd(pmd, pmdp, addr, next, flags,
				pages, nr))
				return 0;

		} else if (unlikely(is_hugepd(__hugepd(pmd_val(pmd))))) {
			/*
			 * architecture have different format for hugetlbfs
			 * pmd format and THP pmd format
			 */
			if (!gup_huge_pd(__hugepd(pmd_val(pmd)), addr,
					 PMD_SHIFT, next, flags, pages, nr))
				return 0;
		// 开始处理pte层面的
		} else if (!gup_pte_range(pmd, pmdp, addr, next, flags, pages, nr))
			return 0;
	} while (pmdp++, addr = next, addr != end);

	return 1;
}
// 一级一级的迭代页表, 如果有空页表就返回, 最后把pmd层面经过检查的页面操作之后,放入pages数组
static int gup_pud_range(p4d_t *p4dp, p4d_t p4d, unsigned long addr, unsigned long end,
			 unsigned int flags, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset_lockless(p4dp, p4d, addr);
	do {
		// 读取pud条目
		pud_t pud = READ_ONCE(*pudp);

		next = pud_addr_end(addr, end);
		if (unlikely(!pud_present(pud)))
			return 0;
		if (unlikely(pud_huge(pud) || pud_devmap(pud))) {
			if (!gup_huge_pud(pud, pudp, addr, next, flags,
					  pages, nr))
				return 0;
		} else if (unlikely(is_hugepd(__hugepd(pud_val(pud))))) {
			if (!gup_huge_pd(__hugepd(pud_val(pud)), addr,
					 PUD_SHIFT, next, flags, pages, nr))
				return 0;
		} else if (!gup_pmd_range(pudp, pud, addr, next, flags, pages, nr))
			return 0;
	} while (pudp++, addr = next, addr != end);

	return 1;
}
// 一级一级的迭代页表, 是做什么呢?
/*
返回0表示有不存在的页表?
最后在pte层面经过检查的页面操作之后,放入pages数组
*/
static int gup_p4d_range(pgd_t *pgdp, pgd_t pgd, unsigned long addr, unsigned long end,
			 unsigned int flags, struct page **pages, int *nr)
{
	unsigned long next;
	p4d_t *p4dp;

	p4dp = p4d_offset_lockless(pgdp, pgd, addr);
	do {
		// 读取p4d条目
		p4d_t p4d = READ_ONCE(*p4dp);

		next = p4d_addr_end(addr, end);
		if (p4d_none(p4d))
			return 0;
		BUILD_BUG_ON(p4d_huge(p4d));
		if (unlikely(is_hugepd(__hugepd(p4d_val(p4d))))) {
			if (!gup_huge_pd(__hugepd(p4d_val(p4d)), addr,
					 P4D_SHIFT, next, flags, pages, nr))
				return 0;
		} else if (!gup_pud_range(p4dp, p4d, addr, next, flags, pages, nr))
			return 0;
	} while (p4dp++, addr = next, addr != end);

	return 1;
}

static void gup_pgd_range(unsigned long addr, unsigned long end,
		unsigned int flags, struct page **pages, int *nr)
{
	unsigned long next;
	pgd_t *pgdp;

	pgdp = pgd_offset(current->mm, addr);
	do {
		/* 从pgd指针读取pgd条目 */
		pgd_t pgd = READ_ONCE(*pgdp);

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			return;
		if (unlikely(pgd_huge(pgd))) {// huge的情况
			if (!gup_huge_pgd(pgd, pgdp, addr, next, flags,
					  pages, nr))
				return;
		} else if (unlikely(is_hugepd(__hugepd(pgd_val(pgd))))) {
			if (!gup_huge_pd(__hugepd(pgd_val(pgd)), addr,
					 PGDIR_SHIFT, next, flags, pages, nr))
				return;
		// 直接把要执行的操作放在了if里面
		} else if (!gup_p4d_range(pgdp, pgd, addr, next, flags, pages, nr))
			return;
	} while (pgdp++, addr = next, addr != end); // 处理下一个pgd
}
#else
static inline void gup_pgd_range(unsigned long addr, unsigned long end,
		unsigned int flags, struct page **pages, int *nr)
{
}
#endif /* CONFIG_HAVE_FAST_GUP */

#ifndef gup_fast_permitted
/*
 * Check if it's allowed to use get_user_pages_fast_only() for the range, or
 * we need to fall back to the slow version:
 */
static bool gup_fast_permitted(unsigned long start, unsigned long end)
{
	return true;
}
#endif
// pin住范围内的page, 保存在pages中
static unsigned long lockless_pages_from_mm(unsigned long start,
					    unsigned long end,
					    unsigned int gup_flags,
					    struct page **pages)
{
	unsigned long flags;
	int nr_pinned = 0;
	unsigned seq;

	if (!IS_ENABLED(CONFIG_HAVE_FAST_GUP) ||
	    !gup_fast_permitted(start, end))
		return 0;

	if (gup_flags & FOLL_PIN) {
		seq = raw_read_seqcount(&current->mm->write_protect_seq);
		if (seq & 1)
			return 0;
	}

	/*
	 * Disable interrupts. The nested form is used, in order to allow full,
	 * general purpose use of this routine.
	 * 关中断, 用了嵌套形式, 以便允许完全的、通用的使用这个函数
	 * With interrupts disabled, we block page table pages from being freed
	 * from under us. See struct mmu_table_batch comments in
	 * include/asm-generic/tlb.h for more details.
	 * 关中断是为了阻止页表页在我们下面被释放. 更多细节见include/asm-generic/tlb.h中的
	 struct mmu_table_batch注释
	 * We do not adopt an rcu_read_lock() here as we also want to block IPIs
	 * that come from THPs splitting.
	 */
	local_irq_save(flags);
	// 这里开始pin? 这里是fast-path, 一级一级检查页表
	// 如果有空页表就返回
	// 最后把pte层面经过检查的页面操作之后,放入pages数组
	gup_pgd_range(start, end, gup_flags, pages, &nr_pinned);
	local_irq_restore(flags);

	/*
	 * When pinning pages for DMA there could be a concurrent write protect
	 * from fork() via copy_page_range(), in this case always fail fast GUP.
	   当为DMA固定页面时，可能会有一个并发的写保护来自fork()通过copy_page_range()，
	   在这种情况下，总是快速失败GUP。
	 */
	if (gup_flags & FOLL_PIN) {
		if (read_seqcount_retry(&current->mm->write_protect_seq, seq)) {
			unpin_user_pages_lockless(pages, nr_pinned);
			return 0;
		} else {
			sanity_check_pinned_pages(pages, nr_pinned);
		}
	}
	return nr_pinned;
}
// pin住start开始的nr_pages个page, 保存在pages中
static int internal_get_user_pages_fast(unsigned long start,
					unsigned long nr_pages,
					unsigned int gup_flags,
					struct page **pages)
{
	unsigned long len, end;
	unsigned long nr_pinned;
	int locked = 0;
	int ret;

	if (WARN_ON_ONCE(gup_flags & ~(FOLL_WRITE | FOLL_LONGTERM |
				       FOLL_FORCE | FOLL_PIN | FOLL_GET |
				       FOLL_FAST_ONLY | FOLL_NOFAULT |
				       FOLL_PCI_P2PDMA | FOLL_HONOR_NUMA_FAULT)))
		return -EINVAL;

	if (gup_flags & FOLL_PIN)
		mm_set_has_pinned_flag(&current->mm->flags);

	if (!(gup_flags & FOLL_FAST_ONLY))
		might_lock_read(&current->mm->mmap_lock);

	start = untagged_addr(start) & PAGE_MASK;
	len = nr_pages << PAGE_SHIFT;
	if (check_add_overflow(start, len, &end))
		return -EOVERFLOW;
	if (end > TASK_SIZE_MAX)
		return -EFAULT;
	if (unlikely(!access_ok((void __user *)start, len)))
		return -EFAULT;
	// 先尝试fast-path
	nr_pinned = lockless_pages_from_mm(start, end, gup_flags, pages);
	if (nr_pinned == nr_pages || gup_flags & FOLL_FAST_ONLY)
		return nr_pinned;
	/* pinned还不够, 并且不限制只能fast-path */
	/* Slow path: try to get the remaining pages with get_user_pages */
	start += nr_pinned << PAGE_SHIFT;
	pages += nr_pinned;
	// 一个一个follow page, 加入pages
	ret = __gup_longterm_locked(current->mm, start, nr_pages - nr_pinned,
				    pages, &locked,
				    gup_flags | FOLL_TOUCH | FOLL_UNLOCKABLE);
	if (ret < 0) {
		/*
		 * The caller has to unpin the pages we already pinned so
		 * returning -errno is not an option
		 */
		if (nr_pinned)
			return nr_pinned;
		return ret;
	}
	// 返回实际pin的页面
	return ret + nr_pinned;
}

/**
 * get_user_pages_fast_only() - pin user pages in memory
   pin住内存中的用户页面
 * @start:      starting user address
 * @nr_pages:   number of pages from start to pin
 * @gup_flags:  flags modifying pin behaviour
 * @pages:      array that receives pointers to the pages pinned.
 *              Should be at least nr_pages long.
 *
 * Like get_user_pages_fast() except it's IRQ-safe in that it won't fall back to
 * the regular GUP.
 * 就像get_user_pages_fast()一样，只是它是IRQ安全的，因为它不会回退到常规GUP。
 * If the architecture does not support this function, simply return with no
 * pages pinned.
 * 如果架构不支持此功能，则只需返回而不固定页面。
 * Careful, careful! COW breaking can go either way, so a non-write
 * access can get ambiguous page results. If you call this function without
 * 'write' set, you'd better be sure that you're ok with that ambiguity.
 */
int get_user_pages_fast_only(unsigned long start, int nr_pages,
			     unsigned int gup_flags, struct page **pages)
{
	/*
	 * Internally (within mm/gup.c), gup fast variants must set FOLL_GET,
	 * because gup fast is always a "pin with a +1 page refcount" request.
	 *
	 * FOLL_FAST_ONLY is required in order to match the API description of
	 * this routine: no fall back to regular ("slow") GUP.
	 */
	if (!is_valid_gup_args(pages, NULL, &gup_flags,
			       FOLL_GET | FOLL_FAST_ONLY))
		return -EINVAL;

	return internal_get_user_pages_fast(start, nr_pages, gup_flags, pages);
}
EXPORT_SYMBOL_GPL(get_user_pages_fast_only);

/**
获取用户地址空间的页面, 并且pin住
 * get_user_pages_fast() - pin user pages in memory
 * @start:      starting user address
 * @nr_pages:   number of pages from start to pin
 * @gup_flags:  flags modifying pin behaviour
 * @pages:      array that receives pointers to the pages pinned.
 *              Should be at least nr_pages long.
 *
 * Attempt to pin user pages in memory without taking mm->mmap_lock.
 * If not successful, it will fall back to taking the lock and
 * calling get_user_pages().
 * 尝试去pin住用户地址空间的页面, 不需要获取mm->mmap_lock
   如果不成功, 会获取锁并调用get_user_pages()
 * Returns number of pages pinned. This may be fewer than the number requested.
 * If nr_pages is 0 or negative, returns 0. If no pages were pinned, returns
 * -errno.
 */
int get_user_pages_fast(unsigned long start, int nr_pages,
			unsigned int gup_flags, struct page **pages)
{
	/*
	 * The caller may or may not have explicitly set FOLL_GET; either way is
	 * OK. However, internally (within mm/gup.c), gup fast variants must set
	 * FOLL_GET, because gup fast is always a "pin with a +1 page refcount"
	 * request.
	 */
	if (!is_valid_gup_args(pages, NULL, &gup_flags, FOLL_GET))
		return -EINVAL;
	return internal_get_user_pages_fast(start, nr_pages, gup_flags, pages);
}
EXPORT_SYMBOL_GPL(get_user_pages_fast);

/**
addr是iter的空间. 把他习惯的有些pages pin到pages
 * pin_user_pages_fast() - pin user pages in memory without taking locks
 *
 * @start:      starting user address
 * @nr_pages:   number of pages from start to pin
 * @gup_flags:  flags modifying pin behaviour
 * @pages:      array that receives pointers to the pages pinned.
 *              Should be at least nr_pages long.
 *
 * Nearly the same as get_user_pages_fast(), except that FOLL_PIN is set. See
 * get_user_pages_fast() for documentation on the function arguments, because
 * the arguments here are identical.
 * 与get_user_pages_fast()几乎相同，只是设置了FOLL_PIN。请参阅get_user_pages_fast()以
 获取有关函数参数的文档，因为这里的参数是相同的。
 * FOLL_PIN means that the pages must be released via unpin_user_page(). Please
 * see Documentation/core-api/pin_user_pages.rst for further details.
 * FOLL_PIN表示必须通过unpin_user_page()释放页面。请参阅
 * 有关详细信息，请参阅Documentation/core-api/pin_user_pages.rst。
 * Note that if a zero_page is amongst the returned pages, it will not have
 * pins in it and unpin_user_page() will not remove pins from it.
 */
int pin_user_pages_fast(unsigned long start, int nr_pages,
			unsigned int gup_flags, struct page **pages)
{
	if (!is_valid_gup_args(pages, NULL, &gup_flags, FOLL_PIN))
		return -EINVAL;
	return internal_get_user_pages_fast(start, nr_pages, gup_flags, pages);
}
EXPORT_SYMBOL_GPL(pin_user_pages_fast);

/**
pin住mm这个进程的start开始的nr_pages个页面, 放在pages里面
 * pin_user_pages_remote() - pin pages of a remote process
 *
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying lookup behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long.
 * @locked:	pointer to lock flag indicating whether lock is held and
 *		subsequently whether VM_FAULT_RETRY functionality can be
 *		utilised. Lock must initially be held.
 *
 * Nearly the same as get_user_pages_remote(), except that FOLL_PIN is set. See
 * get_user_pages_remote() for documentation on the function arguments, because
 * the arguments here are identical.
 *
 * FOLL_PIN means that the pages must be released via unpin_user_page(). Please
 * see Documentation/core-api/pin_user_pages.rst for details.
 *
 * Note that if a zero_page is amongst the returned pages, it will not have
 * pins in it and unpin_user_page*() will not remove pins from it.
 */
long pin_user_pages_remote(struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked)
{
	int local_locked = 1;

	if (!is_valid_gup_args(pages, locked, &gup_flags,
			       FOLL_PIN | FOLL_TOUCH | FOLL_REMOTE))
		return 0;
	/* 开始pin */
	return __gup_longterm_locked(mm, start, nr_pages, pages,
				     locked ? locked : &local_locked,
				     gup_flags);
}
EXPORT_SYMBOL(pin_user_pages_remote);

/**
 * pin_user_pages() - pin user pages in memory for use by other devices
 *
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying lookup behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long.
 *
 * Nearly the same as get_user_pages(), except that FOLL_TOUCH is not set, and
 * FOLL_PIN is set.
 *
 * FOLL_PIN means that the pages must be released via unpin_user_page(). Please
 * see Documentation/core-api/pin_user_pages.rst for details.
 *
 * Note that if a zero_page is amongst the returned pages, it will not have
 * pins in it and unpin_user_page*() will not remove pins from it.
 */
long pin_user_pages(unsigned long start, unsigned long nr_pages,
		    unsigned int gup_flags, struct page **pages)
{
	int locked = 1;

	if (!is_valid_gup_args(pages, NULL, &gup_flags, FOLL_PIN))
		return 0;
	return __gup_longterm_locked(current->mm, start, nr_pages,
				     pages, &locked, gup_flags);
}
EXPORT_SYMBOL(pin_user_pages);

/*
 * pin_user_pages_unlocked() is the FOLL_PIN variant of
 * get_user_pages_unlocked(). Behavior is the same, except that this one sets
 * FOLL_PIN and rejects FOLL_GET.
 *
 * Note that if a zero_page is amongst the returned pages, it will not have
 * pins in it and unpin_user_page*() will not remove pins from it.
 */
long pin_user_pages_unlocked(unsigned long start, unsigned long nr_pages,
			     struct page **pages, unsigned int gup_flags)
{
	int locked = 0;

	if (!is_valid_gup_args(pages, NULL, &gup_flags,
			       FOLL_PIN | FOLL_TOUCH | FOLL_UNLOCKABLE))
		return 0;

	return __gup_longterm_locked(current->mm, start, nr_pages, pages,
				     &locked, gup_flags);
}
EXPORT_SYMBOL(pin_user_pages_unlocked);

// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include "internal.h"

static inline bool not_found(struct page_vma_mapped_walk *pvmw)
{
	page_vma_mapped_walk_done(pvmw);
	return false;
}
/* 2024年8月11日16:35:12
todo */
static bool map_pte(struct page_vma_mapped_walk *pvmw)
{
	/* 找到pvmw的addr的pte */
	pvmw->pte = pte_offset_map(pvmw->pmd, pvmw->address);

	if (!(pvmw->flags & PVMW_SYNC)) {
		if (pvmw->flags & PVMW_MIGRATION) {
			if (!is_swap_pte(*pvmw->pte))
				return false;
		} else {
			/*
			 * We get here when we are trying to unmap a private
			 * device page from the process address space. Such
			 * page is not CPU accessible and thus is mapped as
			 * a special swap entry, nonetheless it still does
			 * count as a valid regular mapping for the page (and
			 * is accounted as such in page maps count).
			 *
			 * So handle this special case as if it was a normal
			 * page mapping ie lock CPU page table and returns
			 * true.
			 *
			 * For more details on device private memory see HMM
			 * (include/linux/hmm.h or mm/hmm.c).
			 */
			if (is_swap_pte(*pvmw->pte)) {
				swp_entry_t entry;

				/* Handle un-addressable ZONE_DEVICE memory */
				entry = pte_to_swp_entry(*pvmw->pte);
				if (!is_device_private_entry(entry))
					return false;
			} else if (!pte_present(*pvmw->pte))
				return false;
		}
	}
	pvmw->ptl = pte_lockptr(pvmw->vma->vm_mm, pvmw->pmd);
	spin_lock(pvmw->ptl);
	return true;
}
/* 2024年07月26日11:03:35 */
static inline bool pfn_in_hpage(struct page *hpage, unsigned long pfn)
{
	/* 获取page的pfn */
	unsigned long hpage_pfn = page_to_pfn(hpage);

	/* THP can be referenced by any subpage */
	return pfn >= hpage_pfn && pfn - hpage_pfn < hpage_nr_pages(hpage);
}

/**
检查pte映射的是不是page
 * check_pte - check if @pvmw->page is mapped at the @pvmw->pte
 *
 * page_vma_mapped_walk() found a place where @pvmw->page is *potentially*
 * mapped. check_pte() has to validate this.
 *
 * @pvmw->pte may point to empty PTE, swap PTE or PTE pointing to arbitrary
 * page.
 *
 * If PVMW_MIGRATION flag is set, returns true if @pvmw->pte contains migration
 * entry that points to @pvmw->page or any subpage in case of THP.
 *
 * If PVMW_MIGRATION flag is not set, returns true if @pvmw->pte points to
 * @pvmw->page or any subpage in case of THP.
 *
 * Otherwise, return false.
 *
 */
static bool check_pte(struct page_vma_mapped_walk *pvmw)
{
	unsigned long pfn;

	/* 迁移中 */
	if (pvmw->flags & PVMW_MIGRATION) {
		swp_entry_t entry;
		if (!is_swap_pte(*pvmw->pte))
			return false;
		entry = pte_to_swp_entry(*pvmw->pte);

		if (!is_migration_entry(entry))
			return false;

		pfn = migration_entry_to_pfn(entry);
	} else if (is_swap_pte(*pvmw->pte)) {
		/* swap条目情况 */
		swp_entry_t entry;

		/* Handle un-addressable ZONE_DEVICE memory */
		entry = pte_to_swp_entry(*pvmw->pte);
		if (!is_device_private_entry(entry))
			return false;

		pfn = device_private_entry_to_pfn(entry);
	} else {
		/* 正常情况，直接获取pfn */
		if (!pte_present(*pvmw->pte))
			return false;

		pfn = pte_pfn(*pvmw->pte);
	}
	/* 刚才好像都是为了获取pte的pfn，现在开始比较 */
	return pfn_in_hpage(pvmw->page, pfn);
}

/**
在pvmw的vma，相关的页表范围里面一直找到一个可以指向page的pte。
 * page_vma_mapped_walk - check if @pvmw->page is mapped in @pvmw->vma at
 * @pvmw->address
 * @pvmw: pointer to struct page_vma_mapped_walk. page, vma, address and flags
 * must be set. pmd, pte and ptl must be NULL.
 *
 * Returns true if the page is mapped in the vma. @pvmw->pmd and @pvmw->pte point
 * to relevant page table entries. @pvmw->ptl is locked. @pvmw->address is
 * adjusted if needed (for PTE-mapped THPs).
 *
 * If @pvmw->pmd is set but @pvmw->pte is not, you have found PMD-mapped page
 * (usually THP). For PTE-mapped THP, you should run page_vma_mapped_walk() in
 * a loop to find all PTEs that map the THP.
 *
 * For HugeTLB pages, @pvmw->pte is set to the relevant page table entry
 * regardless of which page table level the page is mapped at. @pvmw->pmd is
 * NULL.
 *
 * Retruns false if there are no more page table entries for the page in
 * the vma. @pvmw->ptl is unlocked and @pvmw->pte is unmapped.
 *
 * If you need to stop the walk before page_vma_mapped_walk() returned false,
 * use page_vma_mapped_walk_done(). It will do the housekeeping.
   2024年7月2日23:55:07
rmap_walk_anon给出了vma、address和folio，但没有得到PTE，这个任务只能由rwc的回调函数自行完成，
不过内核提供了page_vma_mapped_walk函数辅助完成该任务。	
 */
bool page_vma_mapped_walk(struct page_vma_mapped_walk *pvmw)
{
	struct mm_struct *mm = pvmw->vma->vm_mm;
	struct page *page = pvmw->page;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t pmde;

	/* The only possible pmd mapping has been handled on last iteration */
	if (pvmw->pmd && !pvmw->pte)
		return not_found(pvmw);

	if (pvmw->pte)
		goto next_pte;

	if (unlikely(PageHuge(pvmw->page))) {
		/* when pud is not present, pte will be NULL */
		pvmw->pte = huge_pte_offset(mm, pvmw->address, page_size(page));
		if (!pvmw->pte)
			return false;

		pvmw->ptl = huge_pte_lockptr(page_hstate(page), mm, pvmw->pte);
		spin_lock(pvmw->ptl);
		if (!check_pte(pvmw))
			return not_found(pvmw);
		return true;
	}
restart:
	/* 找到mm在address对应的pgd */
	pgd = pgd_offset(mm, pvmw->address);
	if (!pgd_present(*pgd))
		return false;
	p4d = p4d_offset(pgd, pvmw->address);
	if (!p4d_present(*p4d))
		return false;
	pud = pud_offset(p4d, pvmw->address);
	if (!pud_present(*pud))
		return false;
	/* 找到addr的pmd */
	pvmw->pmd = pmd_offset(pud, pvmw->address);
	/*
	 * Make sure the pmd value isn't cached in a register by the
	 * compiler and used as a stale value after we've observed a
	 * subsequent update.
	 */
	 /* 获取pmd条目 */
	pmde = READ_ONCE(*pvmw->pmd);
	if (pmd_trans_huge(pmde) || is_pmd_migration_entry(pmde)) {
		/* 巨页好迁移的特殊情况 */
		pvmw->ptl = pmd_lock(mm, pvmw->pmd);
		if (likely(pmd_trans_huge(*pvmw->pmd))) {
			if (pvmw->flags & PVMW_MIGRATION)
				return not_found(pvmw);
			if (pmd_page(*pvmw->pmd) != page)
				return not_found(pvmw);
			return true;
		} else if (!pmd_present(*pvmw->pmd)) {
			if (thp_migration_supported()) {
				if (!(pvmw->flags & PVMW_MIGRATION))
					return not_found(pvmw);
				if (is_migration_entry(pmd_to_swp_entry(*pvmw->pmd))) {
					swp_entry_t entry = pmd_to_swp_entry(*pvmw->pmd);

					if (migration_entry_to_page(entry) != page)
						return not_found(pvmw);
					return true;
				}
			}
			return not_found(pvmw);
		} else {
			/* THP pmd was split under us: handle on pte level */
			spin_unlock(pvmw->ptl);
			pvmw->ptl = NULL;
		}
	} else if (!pmd_present(pmde)) {
		return false;
	}

	/* 刚才的工作好像就是找到pte，下面就是对比pte是不是指向的page，当前这个
	没指向的话，就next_pte，不过这个next的选择逻辑是什么？ */


	/*  */
	if (!map_pte(pvmw))
		goto next_pte;


	while (1) {
		if (check_pte(pvmw))
			return true;
next_pte:
		/* Seek to next pte only makes sense for THP */
		if (!PageTransHuge(pvmw->page) || PageHuge(pvmw->page))
			return not_found(pvmw);


		/* 选择next_pte的逻辑好像就是va不断+=page_size，
		pte也伴随++
		一直到pte不为空，就是找到了下一个pte。
		其实就是pte++到不为空，va的+=page_size只是哦判断有没有越界或者下一个页表 */
		do {
			pvmw->address += PAGE_SIZE;
			if (pvmw->address >= pvmw->vma->vm_end ||
			    pvmw->address >=
					__vma_address(pvmw->page, pvmw->vma) +
					hpage_nr_pages(pvmw->page) * PAGE_SIZE)
				return not_found(pvmw);
			/* Did we cross page table boundary? */
			if (pvmw->address % PMD_SIZE == 0) {
				pte_unmap(pvmw->pte);
				if (pvmw->ptl) {
					spin_unlock(pvmw->ptl);
					pvmw->ptl = NULL;
				}
				goto restart;
			} else {
				pvmw->pte++;
			}
		} while (pte_none(*pvmw->pte));

		if (!pvmw->ptl) {
			pvmw->ptl = pte_lockptr(mm, pvmw->pmd);
			spin_lock(pvmw->ptl);
		}
	}
}

/**
2024年8月11日16:29:28
检查page是不是映射到了vma
 * page_mapped_in_vma - check whether a page is really mapped in a VMA
 * @page: the page to test
 * @vma: the VMA to test
 *
 * Returns 1 if the page is mapped into the page tables of the VMA, 0
 * if the page is not mapped into the page tables of this VMA.  Only
 * valid for normal file or anonymous VMAs.
 */
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma)
{
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.flags = PVMW_SYNC,
	};
	unsigned long start, end;
	/* 找到page在这vma的va */
	start = __vma_address(page, vma);
	end = start + PAGE_SIZE * (hpage_nr_pages(page) - 1);

	if (unlikely(end < vma->vm_start || start >= vma->vm_end))/* 如果page对应的地址
	范围恰好在vma的地址范围左边or右边，那肯定没有映射 */
		return 0;
	/* 现在page和vma的地址范围，肯定是有交叉的 */	
	pvmw.address = max(start, vma->vm_start);

	if (!page_vma_mapped_walk(&pvmw))/* 如果vma里面找不到任何pte指向
	这个page地址 */
		return 0;
	/* 到这里，说明vma内部有一个pte指向page，这应该就是函数的功能，是不是真的mapped to this
	vma */
	page_vma_mapped_walk_done(&pvmw);
	return 1;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 *              Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 *
 * Aug/Sep 2004 Changed to four level page tables (Andi Kleen)
 */
/* 2024年7月28日01:13:59 */
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/dma-debug.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>
#include <linux/numa.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "internal.h"

#if defined(LAST_CPUPID_NOT_IN_PAGE_FLAGS) && !defined(CONFIG_COMPILE_TEST)
#warning Unfortunate NUMA and NUMA Balancing config, growing page-frame for last_cpupid.
#endif

#ifndef CONFIG_NEED_MULTIPLE_NODES
/* use the per-pgdat data instead for discontigmem - mbligh */
unsigned long max_mapnr;
EXPORT_SYMBOL(max_mapnr);

struct page *mem_map;
EXPORT_SYMBOL(mem_map);
#endif

/*
 * A number of key systems in x86 including ioremap() rely on the assumption
 * that high_memory defines the upper bound on direct map memory, then end
 * of ZONE_NORMAL.  Under CONFIG_DISCONTIG this means that max_low_pfn and
 * highstart_pfn must be the same; there must be no gap between ZONE_NORMAL
 * and ZONE_HIGHMEM.
 */
void *high_memory;
EXPORT_SYMBOL(high_memory);

/*
 * Randomize the address space (stacks, mmaps, brk, etc.).
 *
 * ( When CONFIG_COMPAT_BRK=y we exclude brk from randomization,
 *   as ancient (libc5 based) binaries can segfault. )
 */
int randomize_va_space __read_mostly =
#ifdef CONFIG_COMPAT_BRK
					1;
#else
					2;
#endif

static int __init disable_randmaps(char *s)
{
	randomize_va_space = 0;
	return 1;
}
__setup("norandmaps", disable_randmaps);

unsigned long zero_pfn __read_mostly;
EXPORT_SYMBOL(zero_pfn);

unsigned long highest_memmap_pfn __read_mostly;

/*
2024年7月28日01:13:36
 * CONFIG_MMU architectures set up ZERO_PAGE in their paging_init()
 */
static int __init init_zero_pfn(void)
{
	zero_pfn = page_to_pfn(ZERO_PAGE(0));
	return 0;
}
core_initcall(init_zero_pfn);


#if defined(SPLIT_RSS_COUNTING)
/* 2024年7月28日01:13:20 */
void sync_mm_rss(struct mm_struct *mm)
{
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++) {
		if (current->rss_stat.count[i]) {
			add_mm_counter(mm, i, current->rss_stat.count[i]);
			current->rss_stat.count[i] = 0;
		}
	}
	current->rss_stat.events = 0;
}
/*  记录rss */
static void add_mm_counter_fast(struct mm_struct *mm, int member, int val)
{
	struct task_struct *task = current;

	if (likely(task->mm == mm))
		task->rss_stat.count[member] += val;
	else
		add_mm_counter(mm, member, val);
}
#define inc_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, 1)
#define dec_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, -1)

/* sync counter once per 64 page faults */
#define TASK_RSS_EVENTS_THRESH	(64)
static void check_sync_rss_stat(struct task_struct *task)
{
	if (unlikely(task != current))
		return;
	if (unlikely(task->rss_stat.events++ > TASK_RSS_EVENTS_THRESH))
		sync_mm_rss(task->mm);
}
#else /* SPLIT_RSS_COUNTING */

#define inc_mm_counter_fast(mm, member) inc_mm_counter(mm, member)
#define dec_mm_counter_fast(mm, member) dec_mm_counter(mm, member)

static void check_sync_rss_stat(struct task_struct *task)
{
}

#endif /* SPLIT_RSS_COUNTING */

/*
2024年7月28日01:09:09
释放vma的页表，逐级迭代 

@tlb：一个什么gather
@pmd：pmd条目地址。
@addr：addr在这个pmd条目范围里面

 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
static void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			   unsigned long addr)
{
	/* 获得pmd对应的页表page */
	pgtable_t token = pmd_pgtable(*pmd);
	/* 这里就清空这个pmd项吗，只为了释放这一个地址会不会代价太大了，为了解除一个
	pte，其他511个被牵连了吗？ */
	pmd_clear(pmd);
	/*  */
	pte_free_tlb(tlb, token, addr);
	
	mm_dec_nr_ptes(tlb->mm);
}
/* 释放vma的页表，逐级迭代 

@tlb：一个什么gather
@pud：p4d条目
@addr：addr在这个pud条目范围里面
@end：是下一个pud的起始地址，也是这个pud的结束吧应该。差一。
@【fllor，ceiling】这次释放页表最大“波及”的范围。
*/
static inline void free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	/* 获取pmd地址 */
	pmd = pmd_offset(pud, addr);

	do {
		/*  */
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		/*  */
		free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	pmd_free_tlb(tlb, pmd, start);
	mm_dec_nr_pmds(tlb->mm);
}
/* 释放vma的页表，逐级迭代
@tlb：一个什么gather
@p4d：p4d条目
@addr：addr在这个p4d条目范围里面
@end：是下一个p4d的起始地址，也是这个p4d的结束吧应该。差一。
@【fllor，ceiling】这次释放页表最大“波及”的范围。 */
static inline void free_pud_range(struct mmu_gather *tlb, p4d_t *p4d,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	/* 获取addr在p4d对应的pud */
	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		free_pmd_range(tlb, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= P4D_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= P4D_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = pud_offset(p4d, start);
	p4d_clear(p4d);
	pud_free_tlb(tlb, pud, start);
	mm_dec_nr_puds(tlb->mm);
}
/* 释放vma的页表，逐级迭代
@tlb：一个什么gather
@pgd：pgd条目
@addr：addr在这个pgd条目范围里面
@end：是下一个pgd的起始地址，也是这个pgd的结束吧应该。差一。
@【fllor，ceiling】这次释放页表最大“波及”的范围。
  */
static inline void free_p4d_range(struct mmu_gather *tlb, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	p4d_t *p4d;
	unsigned long next;
	unsigned long start;

	start = addr;
	/* 获取addr在pgd对应的p4d？但是好像这个架构里p4d就是pgd，直接返回pgd */
	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		free_pud_range(tlb, p4d, addr, next, floor, ceiling);
	} while (p4d++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	p4d = p4d_offset(pgd, start);
	pgd_clear(pgd);
	p4d_free_tlb(tlb, p4d, start);
}

/*
2024年7月19日00:57:49
释放vma的页表
【addr，end】vma的地址范围
@floor：可能同一批被释放的第一个vma的起始地址。（释放vma可能是批量释放
一链表的vma，逐个调用这个函数，floor是第一个vma的起始地址）
@ceiling：可能是下一个vma的起始地址
 * This function frees user-level page tables of a process.

free_pgd_range
->free_p4d_range 
    ->free_pud_range 
        ->free_pmd_range  
            ->free_pte_range  
                -> ....
            -> pud_clear(pud);  ////清除pud页目录中的对应的pud表项
                pmd_free_tlb(tlb, pmd, start); //pmd页目录的物理页放入 页表的积聚结构中
                mm_dec_nr_pmds(tlb->mm) //进程使用的页表的物理页统计减1
        ->p4d_clear(p4d);  //清除p4d页目录中的对应的p4d表项
           pud_free_tlb(tlb, pud, start)  //pud页目录的物理页放入 页表的积聚结构中
    -> pgd_clear(pgd);  //清除pgd页目录中的对应的pgd表项
        p4d_free_tlb(tlb, p4d, start); //p4d页目录的物理页放入 页表的积聚结构中（存在p4d页目录的话）
 */
void free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */
	/* 对齐vma的起始地址 */
	addr &= PMD_MASK;
	if (addr < floor) {/* 说明floor和addr可能在同一个pmd？ */
		addr += PMD_SIZE;/* 这里addr步进一个pmdsize是干什么？ */
		if (!addr)
			return;
	}
	if (ceiling) {/* ceiling也对齐，现在是旧值所在pmd的起始地址值 */
		ceiling &= PMD_MASK;
		if (!ceiling)
			return;
	}

	if (end - 1 > ceiling - 1)/* end可能超过ceiling吗。ceiling是下一个vma的起始地址 */
		end -= PMD_SIZE;

	if (addr > end - 1)
		return;


	/* 现在addr是pmd对齐的 */
	/*
	 * We add page table cache pages with PAGE_SIZE,
	 * (see pte_free_tlb()), flush the tlb if we need
	 */
	tlb_change_page_size(tlb, PAGE_SIZE);
	/* 获取对应pgd条目的地址 */
	pgd = pgd_offset(tlb->mm, addr);
	do {
		/* 保存下一个pgd的起始地址 */
		next = pgd_addr_end(addr, end);

		if (pgd_none_or_clear_bad(pgd))
			continue;
		free_p4d_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}
/* 2024年7月19日00:16:48
在解除映射之后，这个函数释放页表。
@vma：起始vma
【floor，ceiling】地址范围。
---------------、
遍历vma解除av与mapping，然后释放页表
 */
void free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *vma,
		unsigned long floor, unsigned long ceiling)
{
	while (vma) {/* 迭代每个vma */
		struct vm_area_struct *next = vma->vm_next;
		unsigned long addr = vma->vm_start;

		/*
		 * Hide vma from rmap and truncate_pagecache before freeing
		 * pgtables
		 */
		 /* 移除vma关联的全部av */
		unlink_anon_vmas(vma);
		/* 好像是移除关联的mapping */
		unlink_file_vma(vma);	

		if (is_vm_hugetlb_page(vma)) {/* 巨页的路径 */
			hugetlb_free_pgd_range(tlb, addr, vma->vm_end,
				floor, next ? next->vm_start : ceiling);
		} else {
			/*
			 * Optimization: gather nearby vmas into one call down
			 */
			while (next && next->vm_start <= vma->vm_end + PMD_SIZE
			       && !is_vm_hugetlb_page(next)) {
				vma = next;
				next = vma->vm_next;
				unlink_anon_vmas(vma);
				unlink_file_vma(vma);
			}
			/* 释放页表？ */
			free_pgd_range(tlb, addr, vma->vm_end,
				floor, next ? next->vm_start : ceiling);
		}


		vma = next;
	}
}
/* 2024年08月15日09:55:31
给mm的这个pmd项分配pte页表page */
int __pte_alloc(struct mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *ptl;
	/* 分配pte页表，对应与一个pmd项。 */
	pgtable_t new = pte_alloc_one(mm);
	
	if (!new)
		return -ENOMEM;

	/*
	 * Ensure all pte setup (eg. pte page lock and page clearing) are
	 * visible before the pte is made visible to other CPUs by being
	 * put into page tables.
	 *
	 * The other side of the story is the pointer chasing in the page
	 * table walking code (when walking the page table without locking;
	 * ie. most of the time). Fortunately, these data accesses consist
	 * of a chain of data-dependent loads, meaning most CPUs (alpha
	 * being the notable exception) will already guarantee loads are
	 * seen in-order. See the alpha page table accessors for the
	 * smp_read_barrier_depends() barriers in page table walking code.
	 */
	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */


	ptl = pmd_lock(mm, pmd);
	if (likely(pmd_none(*pmd))) {	/*检查检查有没有被其他populate。 Has another populated it ? */
		mm_inc_nr_ptes(mm);
		/* 把申请的pte页表new赋值给pmd项 */
		pmd_populate(mm, pmd, new);
		new = NULL;
	}
	spin_unlock(ptl);


	if (new)/* 说明刚才执行失败了，这里释放申请的页表页面 */
		pte_free(mm, new);
	return 0;
}

/* 2024年7月28日00:07:52 */
int __pte_alloc_kernel(pmd_t *pmd)
{
	/*  */
	pte_t *new = pte_alloc_one_kernel(&init_mm);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&init_mm.page_table_lock);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		/* 填充这个pte到pmd */
		pmd_populate_kernel(&init_mm, pmd, new);
		new = NULL;
	}
	spin_unlock(&init_mm.page_table_lock);

	if (new)
		pte_free_kernel(&init_mm, new);
	return 0;
}

/*  */
static inline void init_rss_vec(int *rss)
{
	memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}
/*  */
static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
	int i;

	if (current->mm == mm)
		sync_mm_rss(mm);
	for (i = 0; i < NR_MM_COUNTERS; i++)
		if (rss[i])
			add_mm_counter(mm, i, rss[i]);
}

/*
 * This function is called to print an error when a bad pte
 * is found. For example, we might have a PFN-mapped pte in
 * a region that doesn't allow it.
 *
 * The calling function must still handle the error.
 */
static void print_bad_pte(struct vm_area_struct *vma, unsigned long addr,
			  pte_t pte, struct page *page)
{
	pgd_t *pgd = pgd_offset(vma->vm_mm, addr);
	p4d_t *p4d = p4d_offset(pgd, addr);
	pud_t *pud = pud_offset(p4d, addr);
	pmd_t *pmd = pmd_offset(pud, addr);
	struct address_space *mapping;
	pgoff_t index;
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			return;
		}
		if (nr_unshown) {
			pr_alert("BUG: Bad page map: %lu messages suppressed\n",
				 nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	mapping = vma->vm_file ? vma->vm_file->f_mapping : NULL;
	index = linear_page_index(vma, addr);

	pr_alert("BUG: Bad page map in process %s  pte:%08llx pmd:%08llx\n",
		 current->comm,
		 (long long)pte_val(pte), (long long)pmd_val(*pmd));
	if (page)
		dump_page(page, "bad pte");
	pr_alert("addr:%px vm_flags:%08lx anon_vma:%px mapping:%px index:%lx\n",
		 (void *)addr, vma->vm_flags, vma->anon_vma, mapping, index);
	pr_alert("file:%pD fault:%ps mmap:%ps readpage:%ps\n",
		 vma->vm_file,
		 vma->vm_ops ? vma->vm_ops->fault : NULL,
		 vma->vm_file ? vma->vm_file->f_op->mmap : NULL,
		 mapping ? mapping->a_ops->readpage : NULL);
	dump_stack();
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

/*

 * vm_normal_page -- This function gets the "struct page" associated with a pte.
 *
 * "Special" mappings do not wish to be associated with a "struct page" (either
 * it doesn't exist, or it exists but they don't want to touch it). In this
 * case, NULL is returned here. "Normal" mappings do have a struct page.
 *
 * There are 2 broad cases. Firstly, an architecture may define a pte_special()
 * pte bit, in which case this function is trivial. Secondly, an architecture
 * may not have a spare pte bit, which requires a more complicated scheme,
 * described below.
 *
 * A raw VM_PFNMAP mapping (ie. one that is not COWed) is always considered a
 * special mapping (even if there are underlying and valid "struct pages").
 * COWed pages of a VM_PFNMAP are always normal.
 *
 * The way we recognize COWed pages within VM_PFNMAP mappings is through the
 * rules set up by "remap_pfn_range()": the vma will have the VM_PFNMAP bit
 * set, and the vm_pgoff will point to the first PFN mapped: thus every special
 * mapping will always honor the rule
 *
 *	pfn_of_page == vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT)
 *
 * And for normal mappings this is false.
 *
 * This restricts such mappings to be a linear translation from virtual address
 * to pfn. To get around this restriction, we allow arbitrary mappings so long
 * as the vma is not a COW mapping; in that case, we know that all ptes are
 * special (because none can have been COWed).
 *
 *
 * In order to support COW of arbitrary special mappings, we have VM_MIXEDMAP.
 *
 * VM_MIXEDMAP mappings can likewise contain memory with or without "struct
 * page" backing, however the difference is that _all_ pages with a struct
 * page (that is, those where pfn_valid is true) are refcounted and considered
 * normal pages by the VM. The disadvantage is that pages are refcounted
 * (which can be slower and simply not an option for some PFNMAP users). The
 * advantage is that we don't have to follow the strict linearity rule of
 * PFNMAP mappings in order to support COWable mappings.
 *2024年7月1日23:07:33
根据pte返回page数据结构
2024年7月2日22:54:52
vm_normal_page根据pte来返回normal paging页面的struct page结构。

一些特殊映射的页面是不会返回struct page结构的，这些页面不希望被参与
到内存管理的一些活动中，如页面回收、页迁移和KSM等。
 */
struct page *vm_normal_page(struct vm_area_struct *vma, unsigned long addr,
			    pte_t pte)
{
	unsigned long pfn = pte_pfn(pte);

	if (IS_ENABLED(CONFIG_ARCH_HAS_PTE_SPECIAL)) {
		/* //正常的页面都没有PTE_SPECIAL */
		if (likely(!pte_special(pte)))
			goto check_pfn;
		if (vma->vm_ops && vma->vm_ops->find_special_page)
			return vma->vm_ops->find_special_page(vma, addr);
		if (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP))
			return NULL;
		if (is_zero_pfn(pfn))
			return NULL;
		if (pte_devmap(pte))
			return NULL;

		print_bad_pte(vma, addr, pte, NULL);
		return NULL;
	}

	/* !CONFIG_ARCH_HAS_PTE_SPECIAL case follows: */

	if (unlikely(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP))) {
		if (vma->vm_flags & VM_MIXEDMAP) {
			if (!pfn_valid(pfn))
				return NULL;
			goto out;
		} else {
			unsigned long off;
			off = (addr - vma->vm_start) >> PAGE_SHIFT;
			if (pfn == vma->vm_pgoff + off)
				return NULL;
			if (!is_cow_mapping(vma->vm_flags))
				return NULL;
		}
	}

	if (is_zero_pfn(pfn))
		return NULL;

check_pfn:
	if (unlikely(pfn > highest_memmap_pfn)) {
		print_bad_pte(vma, addr, pte, NULL);
		return NULL;
	}

	/*
	 * NOTE! We still have PageReserved() pages in the page tables.
	 * eg. VDSO mappings can cause them to exist.
	 */
out:
	return pfn_to_page(pfn);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
struct page *vm_normal_page_pmd(struct vm_area_struct *vma, unsigned long addr,
				pmd_t pmd)
{
	unsigned long pfn = pmd_pfn(pmd);

	/*
	 * There is no pmd_special() but there may be special pmds, e.g.
	 * in a direct-access (dax) mapping, so let's just replicate the
	 * !CONFIG_ARCH_HAS_PTE_SPECIAL case from vm_normal_page() here.
	 */
	if (unlikely(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP))) {
		if (vma->vm_flags & VM_MIXEDMAP) {
			if (!pfn_valid(pfn))
				return NULL;
			goto out;
		} else {
			unsigned long off;
			off = (addr - vma->vm_start) >> PAGE_SHIFT;
			if (pfn == vma->vm_pgoff + off)
				return NULL;
			if (!is_cow_mapping(vma->vm_flags))
				return NULL;
		}
	}

	if (pmd_devmap(pmd))
		return NULL;
	if (is_zero_pfn(pfn))
		return NULL;
	if (unlikely(pfn > highest_memmap_pfn))
		return NULL;

	/*
	 * NOTE! We still have PageReserved() pages in the page tables.
	 * eg. VDSO mappings can cause them to exist.
	 */
out:
	return pfn_to_page(pfn);
}
#endif

/*
在mm之间拷贝pte。
 * copy one vm_area from one task to the other. Assumes the page tables
 * already present in the new task to be cleared in the whole range
 * covered by this vma.
 */

static inline unsigned long
copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
		unsigned long addr, int *rss)
{
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;

	/* pte contains position in swap or file, so copy. */
	if (unlikely(!pte_present(pte))) {
		/* src的pte是空的情况 */
		swp_entry_t entry = pte_to_swp_entry(pte);
		/* 先找swap */
		if (likely(!non_swap_entry(entry))) {
			/* 存在 */

			if (swap_duplicate(entry) < 0)
				return entry.val;

			/* make sure dst_mm is on swapoff's mmlist. */
			if (unlikely(list_empty(&dst_mm->mmlist))) {
				spin_lock(&mmlist_lock);
				if (list_empty(&dst_mm->mmlist))
					list_add(&dst_mm->mmlist,
							&src_mm->mmlist);
				spin_unlock(&mmlist_lock);
			}
			rss[MM_SWAPENTS]++;
		} else if (is_migration_entry(entry)) {
			page = migration_entry_to_page(entry);

			rss[mm_counter(page)]++;

			if (is_write_migration_entry(entry) &&
					is_cow_mapping(vm_flags)) {
				/*
				 * COW mappings require pages in both
				 * parent and child to be set to read.
				 */
				make_migration_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				if (pte_swp_soft_dirty(*src_pte))
					pte = pte_swp_mksoft_dirty(pte);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		} else if (is_device_private_entry(entry)) {
			page = device_private_entry_to_page(entry);

			/*
			 * Update rss count even for unaddressable pages, as
			 * they should treated just like normal pages in this
			 * respect.
			 *
			 * We will likely want to have some new rss counters
			 * for unaddressable pages, at some point. But for now
			 * keep things as they are.
			 */
			get_page(page);
			rss[mm_counter(page)]++;
			page_dup_rmap(page, false);

			/*
			 * We do not preserve soft-dirty information, because so
			 * far, checkpoint/restore is the only feature that
			 * requires that. And checkpoint/restore does not work
			 * when a device driver is involved (you cannot easily
			 * save and restore device driver state).
			 */
			if (is_write_device_private_entry(entry) &&
			    is_cow_mapping(vm_flags)) {
				make_device_private_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		}
		goto out_set_pte;
	}/* src pte不存在的情况 */

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	if (is_cow_mapping(vm_flags) && pte_write(pte)) {
		ptep_set_wrprotect(src_mm, addr, src_pte);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child
	 */
	if (vm_flags & VM_SHARED)
	/* 使其不dirty */
		pte = pte_mkclean(pte);
	/* 也清除刚刚访问的标记位 */
	pte = pte_mkold(pte);
	/* 楼上这些清除的考虑是什么呢 */

	/* 找到src pte的页面，开始复制 */
	page = vm_normal_page(vma, addr, pte);
	if (page) {
		/* 找到了src page */
		get_page(page);
		page_dup_rmap(page, false);
		rss[mm_counter(page)]++;
	} else if (pte_devmap(pte)) {
		/* 没找到page，可能是特殊映射 */
		page = pte_page(pte);
	}


/* 出口这里设置dst pte的映射。 */
out_set_pte:
	set_pte_at(dst_mm, addr, dst_pte, pte);
	return 0;
}
/* 拷贝范围内的pte */
static int copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		   pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
		   unsigned long addr, unsigned long end)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int progress = 0;
	int rss[NR_MM_COUNTERS];
	swp_entry_t entry = (swp_entry_t){0};

again:
	init_rss_vec(rss);
	/* 找到目标pte */
	dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	if (!dst_pte)
		return -ENOMEM;
	/* 这里不加锁吗 */
	src_pte = pte_offset_map(src_pmd, addr);
	src_ptl = pte_lockptr(src_mm, src_pmd);
	spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();
	/* 两边pte准备好了 */
	do {
		/*
		 * We are holding two locks at this point - either of them
		 * could generate latencies in another task on another CPU.
		 */
		if (progress >= 32) {
			progress = 0;
			if (need_resched() ||
			    spin_needbreak(src_ptl) || spin_needbreak(dst_ptl))
				break;
		}

		if (pte_none(*src_pte)) {
			/* src pte没有page映射。 那就跳过去，处理下一个pte*/
			progress++;
			continue;
		}
		/* 这里开始拷贝pte */
		entry.val = copy_one_pte(dst_mm, src_mm, dst_pte, src_pte,
							vma, addr, rss);
		if (entry.val)
			break;
		progress += 8;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	spin_unlock(src_ptl);
	pte_unmap(orig_src_pte);
	add_mm_rss_vec(dst_mm, rss);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	cond_resched();

	if (entry.val) {
		if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
			return -ENOMEM;
		progress = 0;
	}
	if (addr != end)
		goto again;
	return 0;
}
/* mm之间拷贝页面，逐级的找各级页表进行处理拷贝 */
static inline int copy_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pud_t *dst_pud, pud_t *src_pud, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	
	do {
		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*src_pmd) || pmd_trans_huge(*src_pmd)
			|| pmd_devmap(*src_pmd)) {
			int err;
			VM_BUG_ON_VMA(next-addr != HPAGE_PMD_SIZE, vma);
			err = copy_huge_pmd(dst_mm, src_mm,
					    dst_pmd, src_pmd, addr, vma);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}

		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		/* 拷贝pte */
		if (copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}
/* 看来两个mm之间拷贝页面，也是逐级的找各级页表进行处理 */
static inline int copy_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		p4d_t *dst_p4d, p4d_t *src_p4d, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_alloc(dst_mm, dst_p4d, addr);
	if (!dst_pud)
		return -ENOMEM;
	src_pud = pud_offset(src_p4d, addr);
	/* 找到了双方的pud */
	do {
		next = pud_addr_end(addr, end);
		/* 是pud开始支持大页的吗 */
		if (pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) {
			int err;

			VM_BUG_ON_VMA(next-addr != HPAGE_PUD_SIZE, vma);
			err = copy_huge_pud(dst_mm, src_mm,
					    dst_pud, src_pud, addr, vma);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}
/* 两个mm之间拷贝页面，也是逐级的找各级页表
	进行处理 */
static inline int copy_p4d_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pgd_t *dst_pgd, pgd_t *src_pgd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	p4d_t *src_p4d, *dst_p4d;
	unsigned long next;

	dst_p4d = p4d_alloc(dst_mm, dst_pgd, addr);
	if (!dst_p4d)
		return -ENOMEM;
	src_p4d = p4d_offset(src_pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(src_p4d))
			continue;
		if (copy_pud_range(dst_mm, src_mm, dst_p4d, src_p4d,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_p4d++, src_p4d++, addr = next, addr != end);
	return 0;
}
/*  */
int copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	struct mmu_notifier_range range;
	bool is_cow;
	int ret;

	/*
	 * Don't copy ptes where a page fault will fill them correctly.
	 * Fork becomes much lighter when there are big shared or private
	 * readonly mappings. The tradeoff is that copy_page_range is more
	 * efficient than faulting.
	 如果不是这三个其中之一，并且没有av。
	 */
	if (!(vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) &&
			!vma->anon_vma)
		return 0;

	/* 大页路径 */
	if (is_vm_hugetlb_page(vma))
		return copy_hugetlb_page_range(dst_mm, src_mm, vma);

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		/* pfn的map的话，就走pfnmap的路径，可能是直接拷贝复制物理页面？ */
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		ret = track_pfn_copy(vma);
		if (ret)
			return ret;
	}

	/*
	 * We need to invalidate the secondary MMU mappings only when
	 * there could be a permission downgrade on the ptes of the
	 * parent mm. And a permission downgrade will only happen if
	 * is_cow_mapping() returns true.
	 */
	is_cow = is_cow_mapping(vma->vm_flags);

	if (is_cow) {
		mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
					0, vma, src_mm, addr, end);
		mmu_notifier_invalidate_range_start(&range);
	}

	/* 找到双方的pgd */
	ret = 0;
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);

	/* 看来两个mm之间拷贝页面，也是逐级的找各级页表
	进行处理 */
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(copy_p4d_range(dst_mm, src_mm, dst_pgd, src_pgd,
					    vma, addr, next))) {
							/* 出错了 */
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	if (is_cow)
		mmu_notifier_invalidate_range_end(&range);
	return ret;
}


/* 2024年07月26日15:32:35
该函数的作用是将在pmd中从虚拟地址address开始，长度为size的内存块通过循环调用
pte_clear将其页表项清零，
调用free_pte将所含空间中的物理内存或交换空间中的虚存页释放掉。
在释放之前，必须检查从address开始长度为size的内存块有无越过PMD_SIZE.
(溢出则可使指针逃出0～1023的区间)。
2024年7月27日22:48:20
太长不看23333，todo。
 */
static unsigned long zap_pte_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	struct mm_struct *mm = tlb->mm;
	int force_flush = 0;
	int rss[NR_MM_COUNTERS];
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;
	swp_entry_t entry;

	tlb_change_page_size(tlb, PAGE_SIZE);
again:
	init_rss_vec(rss);
	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	flush_tlb_batched_pending(mm);
	arch_enter_lazy_mmu_mode();
	do {
		pte_t ptent = *pte;
		if (pte_none(ptent))
			continue;

		if (need_resched())
			break;

		if (pte_present(ptent)) {
			struct page *page;

			page = vm_normal_page(vma, addr, ptent);
			if (unlikely(details) && page) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping &&
				    details->check_mapping != page_rmapping(page))
					continue;
			}
			ptent = ptep_get_and_clear_full(mm, addr, pte,
							tlb->fullmm);
			tlb_remove_tlb_entry(tlb, pte, addr);
			if (unlikely(!page))
				continue;

			if (!PageAnon(page)) {
				if (pte_dirty(ptent)) {
					force_flush = 1;
					set_page_dirty(page);
				}
				if (pte_young(ptent) &&
				    likely(!(vma->vm_flags & VM_SEQ_READ)))
					mark_page_accessed(page);
			}
			rss[mm_counter(page)]--;
			page_remove_rmap(page, false);
			if (unlikely(page_mapcount(page) < 0))
				print_bad_pte(vma, addr, ptent, page);
			if (unlikely(__tlb_remove_page(tlb, page))) {
				force_flush = 1;
				addr += PAGE_SIZE;
				break;
			}
			continue;
		}

		entry = pte_to_swp_entry(ptent);
		if (non_swap_entry(entry) && is_device_private_entry(entry)) {
			struct page *page = device_private_entry_to_page(entry);

			if (unlikely(details && details->check_mapping)) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping !=
				    page_rmapping(page))
					continue;
			}

			pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
			rss[mm_counter(page)]--;
			page_remove_rmap(page, false);
			put_page(page);
			continue;
		}

		/* If details->check_mapping, we leave swap entries. */
		if (unlikely(details))
			continue;

		if (!non_swap_entry(entry))
			rss[MM_SWAPENTS]--;
		else if (is_migration_entry(entry)) {
			struct page *page;

			page = migration_entry_to_page(entry);
			rss[mm_counter(page)]--;
		}
		if (unlikely(!free_swap_and_cache(entry)))
			print_bad_pte(vma, addr, ptent, NULL);
		pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	add_mm_rss_vec(mm, rss);
	arch_leave_lazy_mmu_mode();

	/* Do the actual TLB flush before dropping ptl */
	if (force_flush)
		tlb_flush_mmu_tlbonly(tlb);
	pte_unmap_unlock(start_pte, ptl);

	/*
	 * If we forced a TLB flush (either due to running out of
	 * batch buffers or because we needed to flush dirty TLB
	 * entries before releasing the ptl), free the batched
	 * memory too. Restart if we didn't do everything.
	 */
	if (force_flush) {
		force_flush = 0;
		tlb_flush_mmu(tlb);
	}

	if (addr != end) {
		cond_resched();
		goto again;
	}

	return addr;
}

/* 2024年07月26日15:34:34
通过调用zap_pte_range完成对所有落在address到address+size区间中的所有pte的清零工作。
zap_pmd_range至多清除4M空间的物理内存。 */
static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {

		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
			if (next - addr != HPAGE_PMD_SIZE)
				__split_huge_pmd(vma, pmd, addr, false, NULL);
			else if (zap_huge_pmd(tlb, vma, pmd, addr))
				goto next;
			/* fall through */
		}
		/*
		 * Here there can be other concurrent MADV_DONTNEED or
		 * trans huge page faults running, and if the pmd is
		 * none or trans huge it can change under us. This is
		 * because MADV_DONTNEED holds the mmap_sem in read
		 * mode.
		 */
		if (pmd_none_or_trans_huge_or_clear_bad(pmd))
			goto next;
		next = zap_pte_range(tlb, vma, pmd, addr, next, details);
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	return addr;
}
/* zap=清空
解除范围内的映射 */
static inline unsigned long zap_pud_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, p4d_t *p4d,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_trans_huge(*pud) || pud_devmap(*pud)) {
			if (next - addr != HPAGE_PUD_SIZE) {
				VM_BUG_ON_VMA(!rwsem_is_locked(&tlb->mm->mmap_sem), vma);
				split_huge_pud(vma, pud, addr);
			} else if (zap_huge_pud(tlb, vma, pud, addr))
				goto next;
			/* fall through */
		}
		if (pud_none_or_clear_bad(pud))
			continue;
		next = zap_pmd_range(tlb, vma, pud, addr, next, details);
next:
		cond_resched();
	} while (pud++, addr = next, addr != end);

	return addr;
}
/* 2024年7月18日23:27:54
zap就是清空的意思
 */
static inline unsigned long zap_p4d_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		next = zap_pud_range(tlb, vma, p4d, addr, next, details);
	} while (p4d++, addr = next, addr != end);

	return addr;
}

/* 2024年7月18日23:24:06
unmap此vma的范围内映射
就是逐级处理此进程的页表，一直找到pte，然后处理
这里是清零pte

 */
void unmap_page_range(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end,
			     struct zap_details *details)
{
	pgd_t *pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	/* 为什么这些都是空操作 */
	tlb_start_vma(tlb, vma);
	/*Expands to
((vma->vm_mm)->pgd + (((((addr))) >> 39) & (512 - 1))) */
	pgd = pgd_offset(vma->vm_mm, addr);

	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		next = zap_p4d_range(tlb, vma, pgd, addr, next, details);
	} while (pgd++, addr = next, addr != end);

	tlb_end_vma(tlb, vma);
}

/* 2024年7月19日00:12:34
解除vma页面的映射。
如果是pfn类型的vma，就是释放memtype。
如果是page管理的vma，就是迭代页表，解除映射（清零pte的值）。
 */
static void unmap_single_vma(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr,
		struct zap_details *details)
{
	unsigned long start = max(vma->vm_start, start_addr);
	unsigned long end;

	if (start >= vma->vm_end)
		return;
	end = min(vma->vm_end, end_addr);
	if (end <= vma->vm_start)
		return;

	if (vma->vm_file)
		uprobe_munmap(vma, start, end);


	/* vma是pfn映射的话，这里多一下特殊处理，归还这些pfn页面（这里
	归还不是准确的说法，涉及那个memtype红黑树）*/
	if (unlikely(vma->vm_flags & VM_PFNMAP))
		untrack_pfn(vma, 0, 0);
	/* 上面是pfn类型的vma的unmap方法，通过memtype这些来管理。 */

	if (start != end) {
		if (unlikely(is_vm_hugetlb_page(vma))) {
			/*
			巨页路径
			 * It is undesirable to test vma->vm_file as it
			 * should be non-null for valid hugetlb area.
			 * However, vm_file will be NULL in the error
			 * cleanup path of mmap_region. When
			 * hugetlbfs ->mmap method fails,
			 * mmap_region() nullifies vma->vm_file
			 * before calling this function to clean up.
			 * Since no pte has actually been setup, it is
			 * safe to do nothing in this case.
			 */
			if (vma->vm_file) {
				i_mmap_lock_write(vma->vm_file->f_mapping);
				__unmap_hugepage_range_final(tlb, vma, start, end, NULL);
				i_mmap_unlock_write(vma->vm_file->f_mapping);
			}
		} else
			unmap_page_range(tlb, vma, start, end, details);
	}
}

/**
2024年7月19日00:11:28
解除这些vma的映射，地址范围【start_addr，end_addr】
对每个vma调用unmap_single_vma，清零pte的值
 * unmap_vmas - unmap a range of memory covered by a list of vma's
 * @tlb: address of the caller's struct mmu_gather
 * @vma: the starting vma
 * @start_addr: virtual address at which to start unmapping
 * @end_addr: virtual address at which to end unmapping
 *
 * Unmap all pages in the vma list.
 *
 * Only addresses between `start' and `end' will be unmapped.
 *
 * The VMA list must be sorted in ascending virtual address order.
 *
 * unmap_vmas() assumes that the caller will flush the whole unmapped address
 * range after unmap_vmas() returns.  So the only responsibility here is to
 * ensure that any thus-far unmapped pages are flushed before unmap_vmas()
 * drops the lock and schedules.
 */
void unmap_vmas(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr)
{
	struct mmu_notifier_range range;

	mmu_notifier_range_init(&range, MMU_NOTIFY_UNMAP, 0, vma, vma->vm_mm,
				start_addr, end_addr);
	mmu_notifier_invalidate_range_start(&range);
	/* 遍历list，逐个unmap */
	for ( ; vma && vma->vm_start < end_addr; vma = vma->vm_next)
		unmap_single_vma(tlb, vma, start_addr, end_addr, NULL);

	mmu_notifier_invalidate_range_end(&range);
}

/**
2024年07月26日15:35:53
函数结构与前两个函数类似。将任务从address开始到address+size长度内的所有对应的pmd都清零。
zap_page_range的主要功能是在进行内存收缩、释放内存、退出虚存映射或移动页表的过程中，
将不在使用的物理内存从进程的三级页表中清除。
（在讨论clear_page_tables时，就提到过当进程退出时，释放页表之前，先保证将页表对应项清零，
保证在处于退出状态时，进程不占用0～3G的空间。）
 * zap_page_range - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @start: starting address of pages to zap
 * @size: number of bytes to zap
 *
 * Caller must protect the VMA list
 */
void zap_page_range(struct vm_area_struct *vma, unsigned long start,
		unsigned long size)
{
	struct mmu_notifier_range range;
	struct mmu_gather tlb;

	lru_add_drain();
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
				start, start + size);
	tlb_gather_mmu(&tlb, vma->vm_mm, start, range.end);
	update_hiwater_rss(vma->vm_mm);
	mmu_notifier_invalidate_range_start(&range);
	/* 一直解除映射到range的end。 */
	for ( ; vma && vma->vm_start < range.end; vma = vma->vm_next)
		unmap_single_vma(&tlb, vma, start, range.end, NULL);
	mmu_notifier_invalidate_range_end(&range);
	tlb_finish_mmu(&tlb, start, range.end);
}

/**
解除vma的范围内的映射
 * zap_page_range_single - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @address: starting address of pages to zap
 * @size: number of bytes to zap
 * @details: details of shared cache invalidation
 *
 * The range must fit into one VMA.
 */
static void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *details)
{
	struct mmu_notifier_range range;
	struct mmu_gather tlb;

	lru_add_drain();
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
				address, address + size);
	tlb_gather_mmu(&tlb, vma->vm_mm, address, range.end);
	update_hiwater_rss(vma->vm_mm);
	mmu_notifier_invalidate_range_start(&range);
	/* unmap的函数 */
	unmap_single_vma(&tlb, vma, address, range.end, details);
	
	mmu_notifier_invalidate_range_end(&range);
	tlb_finish_mmu(&tlb, address, range.end);
}

/**
移除vma的全部pte
 * zap_vma_ptes - remove ptes mapping the vma
 * @vma: vm_area_struct holding ptes to be zapped
 * @address: starting address of pages to zap
 * @size: number of bytes to zap
 *
 * This function only unmaps ptes assigned to VM_PFNMAP vmas.
 *
 * The entire address range must be fully contained within the vma.
 *
 */
void zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
		unsigned long size)
{
	if (address < vma->vm_start || address + size > vma->vm_end ||
	    		!(vma->vm_flags & VM_PFNMAP))
		return;

	zap_page_range_single(vma, address, size, NULL);
}
EXPORT_SYMBOL_GPL(zap_vma_ptes);
/* 从mm里面获取addr的pte。
 */
pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
			spinlock_t **ptl)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return NULL;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return NULL;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	VM_BUG_ON(pmd_trans_huge(*pmd));
	/* 一直查询到pmd来获取pte */

	return pte_alloc_map_lock(mm, pmd, addr, ptl);
}

/*
把page映射到vma的addr
 * This is the old fallback for page remapping.
 *
 * For historical reasons, it only allows reserved pages. Only
 * old drivers should use this, and they needed to mark their
 * pages reserved for the old functions anyway.
 */
static int insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page, pgprot_t prot)
{
	struct mm_struct *mm = vma->vm_mm;
	int retval;
	pte_t *pte;
	spinlock_t *ptl;

	retval = -EINVAL;
	if (PageAnon(page) || PageSlab(page) || page_has_type(page))
		goto out;

	retval = -ENOMEM;

	flush_dcache_page(page);
	/* 获得对应的pte */
	pte = get_locked_pte(mm, addr, &ptl);
	
	if (!pte)
		goto out;
	retval = -EBUSY;
	if (!pte_none(*pte))
	/* 此pte已经有映射了 */
		goto out_unlock;

	/* Ok, finally just insert the thing..
	可以开始把page映射到这个pte了 */
	get_page(page);
	inc_mm_counter_fast(mm, mm_counter_file(page));
	/* 设置page的mapping，rmap，其实就是指向vma的av */
	page_add_file_rmap(page, false);
	/* 设置pte的值了 */
	set_pte_at(mm, addr, pte, mk_pte(page, prot));

	retval = 0;
out_unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return retval;
}

/**
插入page到vma的addr
 * vm_insert_page - insert single page into user vma
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @page: source kernel page
 *
 * This allows drivers to insert individual pages they've allocated
 * into a user vma.
 *
 * The page has to be a nice clean _individual_ kernel allocation.
 * If you allocate a compound page, you need to have marked it as
 * such (__GFP_COMP), or manually just split the page up yourself
 * (see split_page()).
 *
 * NOTE! Traditionally this was done with "remap_pfn_range()" which
 * took an arbitrary page protection parameter. This doesn't allow
 * that. Your vma protection will have to be set up correctly, which
 * means that if you want a shared writable mapping, you'd better
 * ask for a shared writable mapping!
 *
 * The page does not need to be reserved.
 *
 * Usually this function is called from f_op->mmap() handler
 * under mm->mmap_sem write-lock, so it can change vma->vm_flags.
 * Caller must set VM_MIXEDMAP on vma if it wants to call this
 * function from other places, for example from page-fault handler.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int vm_insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page)
{
	if (addr < vma->vm_start || addr >= vma->vm_end)
		return -EFAULT;
	if (!page_count(page))
		return -EINVAL;
	if (!(vma->vm_flags & VM_MIXEDMAP)) {
		/* 不支持混合映射 */
		BUG_ON(down_read_trylock(&vma->vm_mm->mmap_sem));
		BUG_ON(vma->vm_flags & VM_PFNMAP);
		/* 直接改变vma为支持 */
		vma->vm_flags |= VM_MIXEDMAP;
	}

	return insert_page(vma, addr, page, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_insert_page);

/*
映射多个内核page到vma
 * __vm_map_pages - maps range of kernel pages into user vma
 * @vma: user vma to map to
 * @pages: pointer to array of source kernel pages
 * @num: number of pages in page array
 * @offset: user's requested vm_pgoff
 *
 * This allows drivers to map range of kernel pages into a user vma.
 *
 * Return: 0 on success and error code otherwise.
 */
static int __vm_map_pages(struct vm_area_struct *vma, struct page **pages,
				unsigned long num, unsigned long offset)
{
	unsigned long count = vma_pages(vma);
	unsigned long uaddr = vma->vm_start;
	int ret, i;

	/* Fail if the user requested offset is beyond the end of the object */
	if (offset >= num)
		return -ENXIO;

	/* Fail if the user requested size exceeds available object size */
	if (count > num - offset)
		return -ENXIO;

	for (i = 0; i < count; i++) {
		/* 就是一个一个映射 
		这里offset含义todo，2024年7月27日22:33:52*/
		ret = vm_insert_page(vma, uaddr, pages[offset + i]);
		if (ret < 0)
			return ret;
		uaddr += PAGE_SIZE;
	}

	return 0;
}

/**
2024年7月27日22:30:38
 * vm_map_pages - maps range of kernel pages starts with non zero offset
 * @vma: user vma to map to
 * @pages: pointer to array of source kernel pages
 * @num: number of pages in page array
 *
 * Maps an object consisting of @num pages, catering for the user's
 * requested vm_pgoff
 *
 * If we fail to insert any page into the vma, the function will return
 * immediately leaving any previously inserted pages present.  Callers
 * from the mmap handler may immediately return the error as their caller
 * will destroy the vma, removing any successfully inserted pages. Other
 * callers should make their own arrangements for calling unmap_region().
 *
 * Context: Process context. Called by mmap handlers.
 * Return: 0 on success and error code otherwise.
 */
int vm_map_pages(struct vm_area_struct *vma, struct page **pages,
				unsigned long num)
{
	return __vm_map_pages(vma, pages, num, vma->vm_pgoff);
}
EXPORT_SYMBOL(vm_map_pages);

/**
？zero offset是什么？
 * vm_map_pages_zero - map range of kernel pages starts with zero offset
 * @vma: user vma to map to
 * @pages: pointer to array of source kernel pages
 * @num: number of pages in page array
 *也是map pages。但是offset设为0，可能是驱动不要求考虑在文件的映射偏移pgoff什么的
 * Similar to vm_map_pages(), except that it explicitly sets the offset
 * to 0. This function is intended for the drivers that did not consider
 * vm_pgoff.
 *
 * Context: Process context. Called by mmap handlers.
 * Return: 0 on success and error code otherwise.
 */
int vm_map_pages_zero(struct vm_area_struct *vma, struct page **pages,
				unsigned long num)
{
	return __vm_map_pages(vma, pages, num, 0);
}
EXPORT_SYMBOL(vm_map_pages_zero);
/* 把pfn映射到vma的addr对应的pte，
突然想到这个addr要求对齐page size吗 */
static vm_fault_t insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			pfn_t pfn, pgprot_t prot, bool mkwrite)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte, entry;
	spinlock_t *ptl;

	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
		return VM_FAULT_OOM;
	if (!pte_none(*pte)) {
		if (mkwrite) {
			/* mkwrite参数是什么意思 */
			/*
			 * For read faults on private mappings the PFN passed
			 * in may not match the PFN we have mapped if the
			 * mapped PFN is a writeable COW page.  In the mkwrite
			 * case we are creating a writable PTE for a shared
			 * mapping and we expect the PFNs to match. If they
			 * don't match, we are likely racing with block
			 * allocation and mapping invalidation so just skip the
			 * update.
			 */
			if (pte_pfn(*pte) != pfn_t_to_pfn(pfn)) {
				/* 说明当前已经映射的pfn不等于准备映射的pfn？ */
				WARN_ON_ONCE(!is_zero_pfn(pte_pfn(*pte)));
				goto out_unlock;
			}
			/* 说明当前已经映射的pfn就是准备映射的pfn */
			entry = pte_mkyoung(*pte);
			/* mkwrite到底是什么 */
			entry = maybe_mkwrite(pte_mkdirty(entry), vma);
			if (ptep_set_access_flags(vma, addr, pte, entry, 1))
				update_mmu_cache(vma, addr, pte);
		}
		goto out_unlock;
	}/* pte已经映射了page的情况 */

	/* Ok, finally just insert the thing..
	pte还没有映射page，直接开始映射到pfn。 */
	if (pfn_t_devmap(pfn))
		entry = pte_mkdevmap(pfn_t_pte(pfn, prot));
	else
		entry = pte_mkspecial(pfn_t_pte(pfn, prot));
	/* 生成pte entry */
	if (mkwrite) {
		entry = pte_mkyoung(entry);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	}
	/* 映射到这个pfn对应的entry */
	set_pte_at(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte); /* XXX: why not for insert_page? */

out_unlock:
	pte_unmap_unlock(pte, ptl);
	return VM_FAULT_NOPAGE;
}

/**
 * vmf_insert_pfn_prot - insert single pfn into user vma with specified pgprot
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @pfn: source kernel pfn
 * @pgprot: pgprot flags for the inserted page
 *
 * This is exactly like vmf_insert_pfn(), except that it allows drivers to
 * to override pgprot on a per-page basis.
 *
 * This only makes sense for IO mappings, and it makes no sense for
 * COW mappings.  In general, using multiple vmas is preferable;
 * vmf_insert_pfn_prot should only be used if using multiple VMAs is
 * impractical.
 *
 * Context: Process context.  May allocate using %GFP_KERNEL.
 * Return: vm_fault_t value.
 */
vm_fault_t vmf_insert_pfn_prot(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t pgprot)
{
	/*
	 * Technically, architectures with pte_special can avoid all these
	 * restrictions (same for remap_pfn_range).  However we would like
	 * consistency in testing and feature parity among all, so we should
	 * try to keep these invariants in place for everybody.
	 */
	BUG_ON(!(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)));
	BUG_ON((vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)) ==
						(VM_PFNMAP|VM_MIXEDMAP));
	BUG_ON((vma->vm_flags & VM_PFNMAP) && is_cow_mapping(vma->vm_flags));
	BUG_ON((vma->vm_flags & VM_MIXEDMAP) && pfn_valid(pfn));

	if (addr < vma->vm_start || addr >= vma->vm_end)
		return VM_FAULT_SIGBUS;

	if (!pfn_modify_allowed(pfn, pgprot))
		return VM_FAULT_SIGBUS;

	track_pfn_insert(vma, &pgprot, __pfn_to_pfn_t(pfn, PFN_DEV));

	return insert_pfn(vma, addr, __pfn_to_pfn_t(pfn, PFN_DEV), pgprot,
			false);
}
EXPORT_SYMBOL(vmf_insert_pfn_prot);

/**
 * vmf_insert_pfn - insert single pfn into user vma
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @pfn: source kernel pfn
 *
 * Similar to vm_insert_page, this allows drivers to insert individual pages
 * they've allocated into a user vma. Same comments apply.
 *
 * This function should only be called from a vm_ops->fault handler, and
 * in that case the handler should return the result of this function.
 *
 * vma cannot be a COW mapping.
 *
 * As this is called only for pages that do not currently exist, we
 * do not need to flush old virtual caches or the TLB.
 *
 * Context: Process context.  May allocate using %GFP_KERNEL.
 * Return: vm_fault_t value.
 */
vm_fault_t vmf_insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn)
{
	return vmf_insert_pfn_prot(vma, addr, pfn, vma->vm_page_prot);
}
EXPORT_SYMBOL(vmf_insert_pfn);
/*  */
static bool vm_mixed_ok(struct vm_area_struct *vma, pfn_t pfn)
{
	/* these checks mirror the abort conditions in vm_normal_page */
	if (vma->vm_flags & VM_MIXEDMAP)
		return true;

	if (pfn_t_devmap(pfn))
		return true;

	if (pfn_t_special(pfn))
		return true;

	if (is_zero_pfn(pfn_t_to_pfn(pfn)))
		return true;
	return false;
}
/* 2024年7月27日19:51:31
给vma的addr地址设置映射pfn
*/
static vm_fault_t __vm_insert_mixed(struct vm_area_struct *vma,
		unsigned long addr, pfn_t pfn, bool mkwrite)
{
	pgprot_t pgprot = vma->vm_page_prot;
	int err;

	BUG_ON(!vm_mixed_ok(vma, pfn));

	/* 越界 */
	if (addr < vma->vm_start || addr >= vma->vm_end)
		return VM_FAULT_SIGBUS;
	/*  */
	track_pfn_insert(vma, &pgprot, pfn);

	if (!pfn_modify_allowed(pfn_t_to_pfn(pfn), pgprot))
		return VM_FAULT_SIGBUS;

	/*
	 * If we don't have pte special, then we have to use the pfn_valid()
	 * based VM_MIXEDMAP scheme (see vm_normal_page), and thus we *must*
	 * refcount the page if pfn_valid is true (hence insert_page rather
	 * than insert_pfn).  If a zero_pfn were inserted into a VM_MIXEDMAP
	 * without pte special, it would there be refcounted as a normal page.
	 */
	if (!IS_ENABLED(CONFIG_ARCH_HAS_PTE_SPECIAL) &&
	    !pfn_t_devmap(pfn) && pfn_t_valid(pfn)) {
			/* 判断了pfn合法，然后把pfn插入vma，
			所以对vma和系统设置，以及pfn的位置有一些要求？ */
		struct page *page;

		/*
		 * At this point we are committed to insert_page()
		 * regardless of whether the caller specified flags that
		 * result in pfn_t_has_page() == false.
		 */
		 /* 不属于特殊映射吗，为什么有对应的page？
		 2024年7月27日21:50:21
		 不属于 */
		page = pfn_to_page(pfn_t_to_pfn(pfn));
		/* 把vma的addr对应的pte映射到page */
		err = insert_page(vma, addr, page, pgprot);
	} else {
		/* 特殊映射的情况，没有page管理，所以不是insert-page，
		而是insert-pfn。 */
		return insert_pfn(vma, addr, pfn, pgprot, mkwrite);
	}

	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	if (err < 0 && err != -EBUSY)
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

/* 给vma的addr地址设置映射pfn */
vm_fault_t vmf_insert_mixed(struct vm_area_struct *vma, unsigned long addr,
		pfn_t pfn)
{
	return __vm_insert_mixed(vma, addr, pfn, false);
}
EXPORT_SYMBOL(vmf_insert_mixed);

/*
2024年7月27日18:05:57
给vma的addr地址设置映射pfn
 *  If the insertion of PTE failed because someone else already added a
 *  different entry in the mean time, we treat that as success as we assume
 *  the same entry was actually inserted.
 */
vm_fault_t vmf_insert_mixed_mkwrite(struct vm_area_struct *vma,
		unsigned long addr, pfn_t pfn)
{
	return __vm_insert_mixed(vma, addr, pfn, true);
}
EXPORT_SYMBOL(vmf_insert_mixed_mkwrite);

/*
remap此页表的映射？map到一段物理内存。
 * maps a range of physical memory into the requested pages. the old
 * mappings are removed. any references to nonexistent pages results
 * in null mappings (currently treated as "copy-on-access")
 */
static int remap_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pte_t *pte;
	spinlock_t *ptl;
	int err = 0;
	/* 找到pmd上面的addr对应的pte表指针，*pte就是物理页地址 */
	pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
		return -ENOMEM;
	arch_enter_lazy_mmu_mode();
	
	do {
		/* 这个时候pte有映射不也是正常的吗 */
		BUG_ON(!pte_none(*pte));
		if (!pfn_modify_allowed(pfn, prot)) {
			err = -EACCES;
			break;
		}
		/* 设置pte项 */
		set_pte_at(mm, addr, pte, 
		/* 预留的内存，所以设置special吗 */
		pte_mkspecial(pfn_pte(pfn, prot)));
		/* 注意捋清这里的，pfn++，pte++，addr+=PAGE_SIZE，其实都是一一对应的，一致的 */
		pfn++;
		/* pte++，就是指向下一个物理页。 */
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	
	pte_unmap_unlock(pte - 1, ptl);
	return err;
}
/* remap此页表的映射？ */
static inline int remap_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		err = remap_pte_range(mm, pmd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);
	return 0;
}
/* remap此页表的映射？ */
static inline int remap_pud_range(struct mm_struct *mm, p4d_t *p4d,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		err = remap_pmd_range(mm, pud, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);
	return 0;
}
/* remap此页表的映射？ */
static inline int remap_p4d_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		err = remap_pud_range(mm, p4d, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

/**
映射内核内存到用户空间
 * remap_pfn_range - remap kernel memory to userspace
 * @vma: user vma to map to
 * @addr: target user address to start at
 * @pfn: physical address of kernel memory
 * @size: size of map area
 * @prot: page protection flags for this mapping
 *
 * Note: this is only safe if the mm semaphore is held when called.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	unsigned long remap_pfn = pfn;
	int err;

	/*
	 * Physically remapped pages are special. Tell the
	 * rest of the world about it:
	 *   VM_IO tells people not to look at these pages
	 *	(accesses can have side effects).
	 *   VM_PFNMAP tells the core MM that the base pages are just
	 *	raw PFN mappings, and do not have a "struct page" associated
	 *	with them.
	 *   VM_DONTEXPAND
	 *      Disable vma merging and expanding with mremap().
	 *   VM_DONTDUMP
	 *      Omit vma from core dump, even when VM_IO turned off.
	 *
	 * There's a horrible special case to handle copy-on-write
	 * behaviour that some programs depend on. We mark the "original"
	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
	 * See vm_normal_page() for details.
	 */
	if (is_cow_mapping(vma->vm_flags)) {
		if (addr != vma->vm_start || end != vma->vm_end)
			return -EINVAL;
		/* 这里vm-pgoff代表什么 */
		vma->vm_pgoff = pfn;
	}
	/* 这里是预留内存的操作 */
	err = track_pfn_remap(vma, &prot, remap_pfn, addr, PAGE_ALIGN(size));
	if (err)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

	BUG_ON(addr >= end);
	pfn -= addr >> PAGE_SHIFT;
	pgd = pgd_offset(mm, addr);

	flush_cache_range(vma, addr, end);
	/* 更新页表吗，使得指向预留的页面 */
	do {
		next = pgd_addr_end(addr, end);
		err = remap_p4d_range(mm, pgd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	if (err)
		untrack_pfn(vma, remap_pfn, PAGE_ALIGN(size));

	return err;
}
EXPORT_SYMBOL(remap_pfn_range);

/**
2024年7月27日16:07:17
remap内存到用户空间？remap到此vma
 * vm_iomap_memory - remap memory to userspace
 * @vma: user vma to map to
 * @start: start of area
 * @len: size of area
 *
 * This is a simplified io_remap_pfn_range() for common driver use. The
 * driver just needs to give us the physical memory range to be mapped,
 * we'll figure out the rest from the vma information.
 *
 * NOTE! Some drivers might want to tweak vma->vm_page_prot first to get
 * whatever write-combining details or similar.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int vm_iomap_memory(struct vm_area_struct *vma, phys_addr_t start, unsigned long len)
{
	unsigned long vm_len, pfn, pages;

	/* Check that the physical memory area passed in looks valid */
	if (start + len < start)
		return -EINVAL;
	/*
	 * You *really* shouldn't map things that aren't page-aligned,
	 * but we've historically allowed it because IO memory might
	 * just have smaller alignment.
	 */

	/* start & ~PAGE_MASK就是start除以page大小的余数，比如4099的话就是3？ */
	len += start & ~PAGE_MASK;

	pfn = start >> PAGE_SHIFT;

	pages = (len + ~PAGE_MASK) >> PAGE_SHIFT;
	/*                                                start
											   8192    8300|---len---------|
	------------------------------------------------------------------------
	                                             |--------len--------------|
	
	 */
	if (pfn + pages < pfn)
		return -EINVAL;

	/* We start the mapping 'vm_pgoff' pages into the area */
	if (vma->vm_pgoff > pages)
		return -EINVAL;

	pfn += vma->vm_pgoff;
	pages -= vma->vm_pgoff;

	/* Can we fit all of the mapping? */
	vm_len = vma->vm_end - vma->vm_start;
	if (vm_len >> PAGE_SHIFT > pages)
		return -EINVAL;

	/* Ok, let it rip */
	return io_remap_pfn_range(vma, vma->vm_start, pfn, vm_len, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_iomap_memory);
/* 扫描一段虚拟地址空间，有必要的时候填充页表，调用每个最底层页表提供的函数。 */
static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	pte_t *pte;
	int err;
	spinlock_t *uninitialized_var(ptl);
	/* pte应该是最后一级指针
	…………|p4d|pud|pmd|pte|页内偏移
	 */
	pte = (mm == &init_mm) ?
		pte_alloc_kernel(pmd, addr) :
		pte_alloc_map_lock(mm, pmd, addr, &ptl);
	
	if (!pte)
		return -ENOMEM;

	BUG_ON(pmd_huge(*pmd));

	arch_enter_lazy_mmu_mode();

	do {
		/* 针对表项主机调用fn，参数为data */
		err = fn(pte++, addr, data);
		if (err)
			break;
	} while (addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();

	if (mm != &init_mm)
		pte_unmap_unlock(pte-1, ptl);
	return err;
}
/* 扫描一段虚拟地址空间，有必要的时候填充页表，调用每个最底层页表提供的函数。 */
static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	BUG_ON(pud_huge(*pud));
	/*  */
	pmd = pmd_alloc(mm, pud, addr);
	
	if (!pmd)
		return -ENOMEM;
	
	do {
		next = pmd_addr_end(addr, end);
		err = apply_to_pte_range(mm, pmd, addr, next, fn, data);
		if (err)
			break;
	} while (pmd++, addr = next, addr != end);
	return err;
}
/* 扫描一段虚拟地址空间，有必要的时候填充页表，调用每个最底层页表提供的函数。 */
static int apply_to_pud_range(struct mm_struct *mm, p4d_t *p4d,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	pud_t *pud;
	unsigned long next;
	int err;
	/*  */
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	
	do {
		next = pud_addr_end(addr, end);
		err = apply_to_pmd_range(mm, pud, addr, next, fn, data);
		if (err)
			break;
	} while (pud++, addr = next, addr != end);
	return err;
}
/* 扫描一段虚拟地址空间，有必要的时候填充页表，调用每个最底层页表提供的函数。 */
static int apply_to_p4d_range(struct mm_struct *mm, pgd_t *pgd,
				     unsigned long addr, unsigned long end,
				     pte_fn_t fn, void *data)
{
	p4d_t *p4d;
	unsigned long next;
	int err;
	/* 基本等价于p4d_offset(pgd, address) */
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		err = apply_to_pud_range(mm, p4d, addr, next, fn, data);
		if (err)
			break;
	} while (p4d++, addr = next, addr != end);
	return err;
}

/*
扫描一段虚拟地址空间，有必要的时候填充页表，调用每个最底层页表提供的函数。
 * Scan a region of virtual memory, filling in page tables as necessary
 * and calling a provided function on each leaf page table.
 */
int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
			unsigned long size, pte_fn_t fn, void *data)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + size;
	int err;

	if (WARN_ON(addr >= end))
		return -EINVAL;
	/* 获得pgd */
	pgd = pgd_offset(mm, addr);

	do {
		next = pgd_addr_end(addr, end);
		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	return err;
}
EXPORT_SYMBOL_GPL(apply_to_page_range);

/*
2024年07月03日12:15:34
todo
 * handle_pte_fault chooses page fault handler according to an entry which was
 * read non-atomically.  Before making any commitment, on those architectures
 * or configurations (e.g. i386 with PAE) which might give a mix of unmatched
 * parts, 
 do_swap_page must check under lock before unmapping the pte and proceeding 
 (but do_wp_page is only called after already making such a check;
  and do_anonymous_page can safely check later on).
 */
static inline int pte_unmap_same(struct mm_struct *mm, pmd_t *pmd,
				pte_t *page_table, pte_t orig_pte)
{
	int same = 1;
#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT)
	if (sizeof(pte_t) > sizeof(unsigned long)) {
		
		spinlock_t *ptl = pte_lockptr(mm, pmd);
		
		spin_lock(ptl);
		/* 检查现在的pte指针内容是不是还和之前的orig_pte条目一样 */
		same = pte_same(*page_table, orig_pte);
		
		spin_unlock(ptl);
	}
#endif
	pte_unmap(page_table);
	/* ((void)(page_table)) */
	return same;
}


/* 拷贝页面数据 */
static inline void cow_user_page(struct page *dst, struct page *src, unsigned long va, struct vm_area_struct *vma)
{
	debug_dma_assert_idle(src);

	/*
	 * If the source page was a PFN mapping, we don't have
	 * a "struct page" for it. We do a best-effort copy by
	 * just copying from the original user address. If that
	 * fails, we just zero-fill it. Live with it.
	 特殊映射，没有page。
	 */
	if (unlikely(!src)) {
		void *kaddr = kmap_atomic(dst);
		void __user *uaddr = (void __user *)(va & PAGE_MASK);

		/*
		 * This really shouldn't fail, because the page is there
		 * in the page tables. But it might just be unreadable,
		 * in which case we just give up and fill the result with
		 * zeroes.
		 */
		if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE))
			clear_page(kaddr);
		kunmap_atomic(kaddr);
		flush_dcache_page(dst);
	} else
		copy_user_highpage(dst, src, va, vma);
}
/* 获得mapping的gfp掩码 */
static gfp_t __get_fault_gfp_mask(struct vm_area_struct *vma)
{
	struct file *vm_file = vma->vm_file;

	if (vm_file)
		return mapping_gfp_mask(vm_file->f_mapping) | __GFP_FS | __GFP_IO;

	/*
	 * Special mappings (e.g. VDSO) do not have any file so fakE
	 * a default GFP_KERNEL for them.
	 */
	return GFP_KERNEL;
}

/*
2024年7月27日15:08:23 
 * Notify the address space that the page is about to become writable so that
 * it can prohibit this or wait for the page to get into an appropriate state.
 *
 * We do this without the lock held, so that it can sleep if it needs to.
 */
static vm_fault_t do_page_mkwrite(struct vm_fault *vmf)
{
	vm_fault_t ret;
	struct page *page = vmf->page;
	unsigned int old_flags = vmf->flags;

	vmf->flags = FAULT_FLAG_WRITE|FAULT_FLAG_MKWRITE;

	if (vmf->vma->vm_file &&
	    IS_SWAPFILE(vmf->vma->vm_file->f_mapping->host))
		return VM_FAULT_SIGBUS;

	ret = vmf->vma->vm_ops->page_mkwrite(vmf);
	/* Restore original flags so that caller is not surprised */
	vmf->flags = old_flags;
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))
	/* 返回了这几个错误类型 */
		return ret;

	if (unlikely(!(ret & VM_FAULT_LOCKED))) {
		/* 如果不是VM_FAULT_LOCKED这个错误类型 */
		lock_page(page);
		if (!page->mapping) {
			unlock_page(page);
			return 0; /* retry */
		}
		/* 给ret加上这个错误类型 */
		ret |= VM_FAULT_LOCKED;
	} else
	/*  */
		VM_BUG_ON_PAGE(!PageLocked(page), page);
	return ret;
}

/*
设置页的脏标志位，表示页的数据被修改。如果文件所属文件系统没有注册虚拟内存操作集合方法
那么更新方法的修改时间
 * Handle dirtying of a page in shared file mapping on a write fault.
 *
 * The function expects the page to be locked and unlocks it.
 */
static void fault_dirty_shared_page(struct vm_area_struct *vma,
				    struct page *page)
{
	struct address_space *mapping;
	bool dirtied;
	bool page_mkwrite = vma->vm_ops && vma->vm_ops->page_mkwrite;
	/* 置脏 */
	dirtied = set_page_dirty(page);

	VM_BUG_ON_PAGE(PageAnon(page), page);
	/*
	 * Take a local copy of the address_space - page.mapping may be zeroed
	 * by truncate after unlock_page().   The address_space itself remains
	 * pinned by vma->vm_file's reference.  We rely on unlock_page()'s
	 * release semantics to prevent the compiler from undoing this copying.
	 */
	mapping = page_rmapping(page);
	unlock_page(page);

	if ((dirtied || page_mkwrite) && mapping) {
		/*
		 * Some device drivers do not set page.mapping
		 * but still dirty their pages
		 */
		balance_dirty_pages_ratelimited(mapping);
	}

	if (!page_mkwrite)
		file_update_time(vma->vm_file);
}

/*
当vma的pages可复用时候（比如共享可写的特殊映射）的处理？
2024年7月27日12:01:51
在复用什么呢。
 * Handle write page faults for pages that can be reused in the current vma
 *发生情况是1mapping共享，2最后一个page的引用。
 标记为page可写，更新相关的。
 所以复用的是page？
 * This can happen either due to the mapping being with the VM_SHARED flag,
 * or due to us being the last reference standing to the page. In either
 * case, all we need to do here is to mark the page as writable and update
 * any related book-keeping.
 */
static inline void wp_page_reuse(struct vm_fault *vmf)
	__releases(vmf->ptl)
{
	struct vm_area_struct *vma = vmf->vma;
	/* 这个时候虽然是处理缺页来到这里，但是其实页面是存在的，
	只是一开始对当前进程不存在（比如不能写什么的） */
	struct page *page = vmf->page;
	pte_t entry;
	/*
	 * Clear the pages cpupid information as the existing
	 * information potentially belongs to a now completely
	 * unrelated process.
	 */
	if (page)
		page_cpupid_xchg_last(page, (1 << LAST_CPUPID_SHIFT) - 1);
	/* 空函数？ */
	flush_cache_page(vma, vmf->address, pte_pfn(vmf->orig_pte));
	
	entry = pte_mkyoung(vmf->orig_pte);

	entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	if (ptep_set_access_flags(vma, vmf->address, vmf->pte, entry, 1))
	/* 如果变化了 */
		update_mmu_cache(vma, vmf->address, vmf->pte);
	pte_unmap_unlock(vmf->pte, vmf->ptl);
}

/*
2024年7月2日23:02:10
如果是私有的可写特殊映射，调用函数 wp_page_copy 以复制物理页，
然后把虚拟页映射到新的物理页
 * Handle the case of a page which we actually need to copy to a new page.
 *
 * Called with mmap_sem locked and the old page referenced, but
 * without the ptl held.
 *
 * High level logic flow:
 *
 * - Allocate a page, copy the content of the old page to the new one.
 * - Handle book keeping and accounting - cgroups, mmu-notifiers, etc.
 * - Take the PTL. If the pte changed, bail out and release the allocated page
 * - If the pte is still the way we remember it, update the page table and all
 *   relevant references. This includes dropping the reference the page-table
 *   held to the old page, as well as updating the rmap.
 * - In any case, unlock the PTL and drop the reference we took to the old page.
 */
static vm_fault_t wp_page_copy(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;
	/* 需要拷贝物理页 */
	struct page *old_page = vmf->page;
	struct page *new_page = NULL;
	pte_t entry;
	int page_copied = 0;
	struct mem_cgroup *memcg;
	struct mmu_notifier_range range;

	if (unlikely(anon_vma_prepare(vma)))
		goto oom;

	if (is_zero_pfn(pte_pfn(vmf->orig_pte))) {
		/* 这个出错的vma的出错的orig-pte还没有指向什么物理页面
		这里来分配一个 ，
		后续好拷贝页面到这里*/
		new_page = alloc_zeroed_user_highpage_movable(vma,
							      vmf->address);
		if (!new_page)
			goto oom;
	} else {
		/* 为什么这里又申请？*/
		new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma,
				vmf->address);
		if (!new_page)
			goto oom;
		/* 复制数据 */
		cow_user_page(new_page, old_page, vmf->address, vma);
	}

	/* 重要工作都做完了 */

	/* 内存记账 */
	if (mem_cgroup_try_charge_delay(new_page, mm, GFP_KERNEL, &memcg, false))
		goto oom_free_new;

	__SetPageUptodate(new_page);

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, mm,
				vmf->address & PAGE_MASK,
				(vmf->address & PAGE_MASK) + PAGE_SIZE);
	mmu_notifier_invalidate_range_start(&range);

	/*
	 * Re-check the pte - we dropped the lock
	 */
	vmf->pte = pte_offset_map_lock(mm, vmf->pmd, vmf->address, &vmf->ptl);
	if (likely(pte_same(*vmf->pte, vmf->orig_pte))) {


		/* 大概率应该还是同一个pte，因为是写时复制，似乎也没做别的啥
		就是给分了个页面来拷贝数据 */
		if (old_page) {

			if (!PageAnon(old_page)) {
				/*  */
				dec_mm_counter_fast(mm,
						mm_counter_file(old_page));
				inc_mm_counter_fast(mm, MM_ANONPAGES);
			}
		
		} else {
			inc_mm_counter_fast(mm, MM_ANONPAGES);
		}

		flush_cache_page(vma, vmf->address, pte_pfn(vmf->orig_pte));
		entry = mk_pte(new_page, vma->vm_page_prot);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		/*
		 * Clear the pte entry and flush it first, before updating the
		 * pte with the new entry. This will avoid a race condition
		 * seen in the presence of one thread doing SMC and another
		 * thread doing COW.
		 */
		ptep_clear_flush_notify(vma, vmf->address, vmf->pte);
		/* 设置page的mapping，rmap */
		page_add_new_anon_rmap(new_page, vma, vmf->address, false);
		/*  */
		mem_cgroup_commit_charge(new_page, memcg, false, false);
		/* 加入到lru，根据page来确定node，memcg，lruvec，lru。 */
		lru_cache_add_active_or_unevictable(new_page, vma);
		/*
		 * We call the notify macro here because, when using secondary
		 * mmu page tables (such as kvm shadow page tables), we want the
		 * new page to be mapped directly into the secondary page table.
		 */
		set_pte_at_notify(mm, vmf->address, vmf->pte, entry);
		update_mmu_cache(vma, vmf->address, vmf->pte);
		if (old_page) {
			/*  */
			/*
			 * Only after switching the pte to the new page may
			 * we remove the mapcount here. Otherwise another
			 * process may come and find the rmap count decremented
			 * before the pte is switched to the new page, and
			 * "reuse" the old page writing into it while our pte
			 * here still points into it and can be read by other
			 * threads.
			 *
			 * The critical issue is to order this
			 * page_remove_rmap with the ptp_clear_flush above.
			 * Those stores are ordered by (if nothing else,)
			 * the barrier present in the atomic_add_negative
			 * in page_remove_rmap.
			 *
			 * Then the TLB flush in ptep_clear_flush ensures that
			 * no process can access the old page before the
			 * decremented mapcount is visible. And the old page
			 * cannot be reused until after the decremented
			 * mapcount is visible. So transitively, TLBs to
			 * old page will be flushed before it can be reused.
			 */
			 /* 为什么这里要remove一下呢， */
			page_remove_rmap(old_page, false);
		}

		/* Free the old page.. */
		new_page = old_page;
		page_copied = 1;
	}/* 还是同一个pte的情况 */
	
	 else {

		mem_cgroup_cancel_charge(new_page, memcg, false);
	}

	if (new_page)
		put_page(new_page);

	pte_unmap_unlock(vmf->pte, vmf->ptl);
	/*
	 * No need to double call mmu_notifier->invalidate_range() callback as
	 * the above ptep_clear_flush_notify() did already call it.
	 */
	mmu_notifier_invalidate_range_only_end(&range);
	
	if (old_page) {
		/*
		 * Don't let another task, with possibly unlocked vma,
		 * keep the mlocked page.
		 */
		if (page_copied && (vma->vm_flags & VM_LOCKED)) {
			lock_page(old_page);	/* LRU manipulation */
			if (PageMlocked(old_page))
				/* 会从lru移出 */
				munlock_vma_page(old_page);
			unlock_page(old_page);
		}
		put_page(old_page);
	}
	return page_copied ? VM_FAULT_WRITE : 0;

oom_free_new:
	put_page(new_page);
oom:
	if (old_page)
		put_page(old_page);
	return VM_FAULT_OOM;
}

/**
调用mkwrite函数后成功的处理
 * finish_mkwrite_fault - finish page fault for a shared mapping, making PTE
 *			  writeable once the page is prepared
 *
 * @vmf: structure describing the fault
 *
 * This function handles all that is needed to finish a write page fault in a
 * shared mapping due to PTE being read-only once the mapped page is prepared.
 * It handles locking of PTE and modifying it.
 *
 * The function expects the page to be locked or other protection against
 * concurrent faults / writeback (such as DAX radix tree locks).
 *
 * Return: %VM_FAULT_WRITE on success, %0 when PTE got changed before
 * we acquired PTE lock.
 */
vm_fault_t finish_mkwrite_fault(struct vm_fault *vmf)
{
	WARN_ON_ONCE(!(vmf->vma->vm_flags & VM_SHARED));
	
	/* 获取pte，获取ptl并lock */
	vmf->pte = pte_offset_map_lock(vmf->vma->vm_mm, vmf->pmd, vmf->address,
				       &vmf->ptl);
	/*
	 * We might have raced with another page fault while we released the
	 * pte_offset_map_lock.
	 竞争情况，可能别人线程处理了
	 */
	if (!pte_same(*vmf->pte, vmf->orig_pte)) {
		/* unlock此ptl，并且置空pte？ */
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		return VM_FAULT_NOPAGE;
	}

	wp_page_reuse(vmf);
	return 0;
}

/*
如果是共享的可写特殊映射，那么是共享的，不需要复制物理页，
调用函数 wp_pfn_shared 来设置页表项的写权限位。
 * Handle write page faults for VM_MIXEDMAP or VM_PFNMAP for a VM_SHARED
 * mapping
 */
static vm_fault_t wp_pfn_shared(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;

	if (vma->vm_ops && vma->vm_ops->pfn_mkwrite) {
		/* 此函数让mmap的文件页可写？ */
		vm_fault_t ret;

		/* unlock，并且置空pte */
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		vmf->flags |= FAULT_FLAG_MKWRITE;
		ret = vma->vm_ops->pfn_mkwrite(vmf);
		if (ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE))
		/* ret是这些错误的一种 */
			return ret;
		return finish_mkwrite_fault(vmf);
	}
	/* 复用 */
	wp_page_reuse(vmf);
	
	return VM_FAULT_WRITE;
}
/* 可写且共享的普通页面：wp_page_shared */
static vm_fault_t wp_page_shared(struct vm_fault *vmf)
	__releases(vmf->ptl)
{
	struct vm_area_struct *vma = vmf->vma;

	get_page(vmf->page);

	if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
		vm_fault_t tmp;

		pte_unmap_unlock(vmf->pte, vmf->ptl);
		tmp = do_page_mkwrite(vmf);
		if (unlikely(!tmp || (tmp &
				      (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))) {
			put_page(vmf->page);
			return tmp;
		}
		tmp = finish_mkwrite_fault(vmf);
		if (unlikely(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE))) {
			unlock_page(vmf->page);
			put_page(vmf->page);
			return tmp;
		}
	} else {

		wp_page_reuse(vmf);
		lock_page(vmf->page);
	}
	/* 设置page为dirty */
	fault_dirty_shared_page(vma, vmf->page);
	put_page(vmf->page);

	return VM_FAULT_WRITE;
}

/*
2024年7月2日22:53:51
处理子进程写时复制
有两种情况会执行写时复制：

1 进程分叉生成子进程的时候，为了避免复制物理页，子进程和父进程以只读方式共享所有
私有的匿名页和文件页。当其中一个进程试图写只读页时，触发页错误异常，页错误异常处理
程序分配新的物理页，把旧的物理页的数据复制到新的物理页，然后把虚拟页映射到新的物理页。

2 进程创建私有的文件映射，然后读访问，触发页错误异常，异常处理程序把文件读到页缓存，
然后以只读模式把虚拟页映射到文件的页缓存中的物理页。接着执行写访问，触发页错误异常，
异常处理程序执行写时复制，为文件的页缓存中的物理页创建一个副本，把虚拟页映射到副本。
这个副本是进程的私有匿名页，和文件脱离关系，修改副本不会导致文件变化。

 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), with pte both mapped and locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static vm_fault_t do_wp_page(struct vm_fault *vmf)
	__releases(vmf->ptl)
{
	struct vm_area_struct *vma = vmf->vma;

	/* 看看orig-pte有无page 
	调用函数 vm_normal_page ，从pte得到pfn，然后得到pfn对应的page。
	特殊映射不希望关联page，直接使用pfn，
	所以这个函数执行结果可能是因为page不存在，也可能是因为不想使用page。*/
	vmf->page = vm_normal_page(vma, vmf->address, vmf->orig_pte);
	if (!vmf->page) {
		/* orig-pte没有页面，page不存在，
		说明是特殊映射 */
		/*
		 * VM_MIXEDMAP !pfn_valid() case, or VM_SOFTDIRTY clear on a
		 * VM_PFNMAP VMA.
		 *
		 * We should not cow pages in a shared writeable mapping.
		 * Just mark the pages writable and/or call ops->pfn_mkwrite.
		 */
		 /* 如果仅仅是共享可写的，没有其他属性。
		 如果是共享的可写特殊映射，不需要复制物理页，
		 调用函数 wp_pfn_shared 来设置页表项的写权限位。*/
		if ((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
				     (VM_WRITE|VM_SHARED))
			
			return wp_pfn_shared(vmf);

		pte_unmap_unlock(vmf->pte, vmf->ptl);
		
		/* 如果是私有的可写特殊映射，调用函数 wp_page_copy 以复制物理页，
		然后把虚拟页映射到新的物理页。 */
		return wp_page_copy(vmf);
	}

	/*
	 * Take out anonymous pages first, anonymous shared vmas are
	 * not dirty accountable.
	 */

	/*运行到这里， 说明找到page结构体，也就是使用页描述符的正常映射 */
	if (PageAnon(vmf->page)) {
		/* 如果是匿名页 */
		int total_map_swapcount;
		if (PageKsm(vmf->page) && (PageSwapCache(vmf->page) ||
					   page_count(vmf->page) != 1))
			goto copy;

		/*  */	
		if (!trylock_page(vmf->page)) {
			get_page(vmf->page);
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			lock_page(vmf->page);

			vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
					vmf->address, &vmf->ptl);
			if (!pte_same(*vmf->pte, vmf->orig_pte)) {
				unlock_page(vmf->page);
				pte_unmap_unlock(vmf->pte, vmf->ptl);
				put_page(vmf->page);
				return 0;
			}
			put_page(vmf->page);
		}

		
		/* ksm路径 */
		if (PageKsm(vmf->page)) {
			bool reused = reuse_ksm_page(vmf->page, vmf->vma,
						     vmf->address);
			unlock_page(vmf->page);
			if (!reused)
				goto copy;
			wp_page_reuse(vmf);
			return VM_FAULT_WRITE;
		}

		if (reuse_swap_page(vmf->page, &total_map_swapcount)) {
			if (total_map_swapcount == 1) {
				/*
				 * The page is all ours. Move it to
				 * our anon_vma so the rmap code will
				 * not search our parent or siblings.
				 * Protected against the rmap code by
				 * the page lock.
				 */
				page_move_anon_rmap(vmf->page, vma);
			}
			unlock_page(vmf->page);
			wp_page_reuse(vmf);
			return VM_FAULT_WRITE;
		}

		unlock_page(vmf->page);
	} 
	else if (unlikely((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
					(VM_WRITE|VM_SHARED))) {
		/* 
		若发生缺页异常的页面是一个特殊页面，即vm_normal_page返回位NULL，如果VMA的属性是可写并且是共享的，那么就调用wp_pfn_shared
		如果可写并共享 */
		return wp_page_shared(vmf);
	}
copy:
	/*
	 * Ok, we need to copy. Oh, well..
	 */
	get_page(vmf->page);

	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return wp_page_copy(vmf);
}
/* 解除vma的范围内的映射 */
static void unmap_mapping_range_vma(struct vm_area_struct *vma,
		unsigned long start_addr, unsigned long end_addr,
		struct zap_details *details)
{
	zap_page_range_single(vma, start_addr, end_addr - start_addr, details);
}
/* 处理root这个红黑树上的全部vma，解除pte映射 */
static inline void unmap_mapping_range_tree(struct rb_root_cached *root,
					    struct zap_details *details)
{
	struct vm_area_struct *vma;
	pgoff_t vba, vea, zba, zea;

	/* 遍历root树上范围内的每个节点，赋值到vma */
	vma_interval_tree_foreach(vma, root,
			details->first_index, details->last_index) {

		/* vma在mapping file对应的起始偏移位置 */
		vba = vma->vm_pgoff;
		/* 这个是对应的结束位置 */
		vea = vba + vma_pages(vma) - 1;
		/* 那zba是调用者指定的要解除映射的页面开始索引 */
		zba = details->first_index;
		
		if (zba < vba)
		/* zba小于vba，那怎么可能，
			人家总共也没那么多，所以就从vba开始 */
			zba = vba;

		zea = details->last_index;
		if (zea > vea)
		/* 一样的原因，调用者指定越界了，就只能到vea这个末尾 */
			zea = vea;
		/* 解除mapping的页面映射，归根结底是解除mapping关联的vma的映射 */
		/* 注意这里单位变了，刚才是pgoff，现在是addr */
		unmap_mapping_range_vma(vma,
			((zba - vba) << PAGE_SHIFT) + vma->vm_start,
			((zea - vba + 1) << PAGE_SHIFT) + vma->vm_start,
				details);
	}
}

/**
unmap此mapping的全部vma
找到vma进行unmap，解除pte的映射
 * unmap_mapping_pages() - Unmap pages from processes.
 * @mapping: The address space containing pages to be unmapped.
 * @start: Index of first page to be unmapped.开始页
 * @nr: Number of pages to be unmapped.  0 to unmap to end of file.页面数量
 * @even_cows: Whether to unmap even private COWed pages.
 *
 * Unmap the pages in this address space from any userspace process which
 * has them mmaped.  Generally, you want to remove COWed pages as well when
 * a file is being truncated, but not when invalidating pages from the page
 * cache.
 */
void unmap_mapping_pages(struct address_space *mapping, pgoff_t start,
		pgoff_t nr, bool even_cows)
{
	struct zap_details details = { };

	details.check_mapping = even_cows ? NULL : mapping;
	details.first_index = start;
	details.last_index = start + nr - 1;

	/* 则默认到end */
	if (details.last_index < details.first_index)
		details.last_index = ULONG_MAX;

	i_mmap_lock_write(mapping);
	/* 好像是mapping的i-mmap这个红黑树关联了很多vma */
	if (unlikely(!RB_EMPTY_ROOT(&mapping->i_mmap.rb_root)))
		unmap_mapping_range_tree(&mapping->i_mmap, &details);
	i_mmap_unlock_write(mapping);
}

/**
2024年7月27日10:15:54
unmap指定mapping的指定范围的映射？
解除mapping的页面映射，归根结底是解除mapping关联的vma的映射
所以是遍历mapping的i-mmap红黑树，挨个处理vma，解除vma的pte映射。
 * unmap_mapping_range - unmap the portion of all mmaps in the specified
 * address_space corresponding to the specified byte range in the underlying
 * file.
 *
 * @mapping: the address space containing mmaps to be unmapped.
 * @holebegin: byte in first page to unmap, relative to the start of
 * the underlying file.  This will be rounded down to a PAGE_SIZE
 * boundary.  Note that this is different from truncate_pagecache(), which
 * must keep the partial page.  In contrast, we must get rid of
 * partial pages.是个page_size整数大小的地址，从这里开始整页整页的解除。
 * @holelen: size of prospective hole in bytes.  This will be rounded
 * up to a PAGE_SIZE boundary.  A holelen of zero truncates to the
 * end of the file.
 * @even_cows: 1 when truncating a file, unmap even private COWed pages;
 * but 0 when invalidating pagecache, don't throw away private data.
 */
void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows)
{

	/* 为什么命名hba呢，还有h是什么含义，todo
	hollow begin address。 */
	pgoff_t hba = holebegin >> PAGE_SHIFT;
	pgoff_t hlen = (holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* Check for overflow. */
	if (sizeof(holelen) > sizeof(hlen)) {
		long long holeend =
			(holebegin + holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (holeend & ~(long long)ULONG_MAX)
			hlen = ULONG_MAX - hba + 1;
	}
	/*  */
	unmap_mapping_pages(mapping, hba, hlen, even_cows);
}
EXPORT_SYMBOL(unmap_mapping_range);

/*
2024年07月03日12:14:50
匿名页面被换出到交换分区后，如果应用程序需要读
写这个页面，则会发生缺页中断，由于PTE中的present位
显示该页面不在内存中，但PTE不为空，说明该页面在交
换分区中，因此调用do_swap_page()函数重新读取该页面
的内容。
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with pte unmapped and unlocked.
 *
 * We return with the mmap_sem locked or unlocked in the same cases
 * as does filemap_fault().
 */
vm_fault_t do_swap_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = NULL, *swapcache;
	struct mem_cgroup *memcg;
	swp_entry_t entry;
	pte_t pte;
	int locked;
	int exclusive = 0;
	vm_fault_t ret = 0;
	/* 看看现在的*pte有没有变，还和之前的pte条目一样不。 */
	if (!pte_unmap_same(vma->vm_mm, vmf->pmd, vmf->pte, vmf->orig_pte))
		goto out;

	/* 这是个swp缺页，那么发生缺页时候的orig_pte保存的就是swp相关 */
	entry = pte_to_swp_entry(vmf->orig_pte);
	if (unlikely(non_swap_entry(entry))) {
		/* 为什么会no swap entry
		反正就是特殊情况吧 */
		if (is_migration_entry(entry)) {
			migration_entry_wait(vma->vm_mm, vmf->pmd,
					     vmf->address);
		} else if (is_device_private_entry(entry)) {
			vmf->page = device_private_entry_to_page(entry);
			ret = vmf->page->pgmap->ops->migrate_to_ram(vmf);
		} else if (is_hwpoison_entry(entry)) {
			ret = VM_FAULT_HWPOISON;
		} else {
			print_bad_pte(vma, vmf->address, vmf->orig_pte, NULL);
			ret = VM_FAULT_SIGBUS;
		}
		goto out;
	}


	delayacct_set_flag(DELAYACCT_PF_SWAPIN);
	/* 从swapfile的mapping读取page */
	page = lookup_swap_cache(entry, vma, vmf->address);
	swapcache = page;

	if (!page) {
		/* 2024年07月03日14:35:49
		为什么会没有page呢 
		2024年8月9日22:51:40
		好像是说明swp mapping没有这个页面
		新申请一个页面
		*/
		struct swap_info_struct *si = swp_swap_info(entry);

		if (si->flags & SWP_SYNCHRONOUS_IO &&
				__swap_count(entry) == 1) {/* 如果可以容忍同步读取 */
			/* skip swapcache */
			page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma,
							vmf->address);
			if (page) {
				__SetPageLocked(page);
				__SetPageSwapBacked(page);
				/* 设置page的swap位置相关字段 */
				set_page_private(page, entry.val);
				/*  */
				lru_cache_add_anon(page);
				/* 这里吧swp file里的page内容读取到刚刚申请的page内存区域里面 */
				swap_readpage(page, true);
			}
		} else {
			/* 这里是异步读取page内容 */
			page = swapin_readahead(entry, GFP_HIGHUSER_MOVABLE,
						vmf);
			swapcache = page;
		}

		if (!page) {
			/*
			这里为什么还能空？
			 * Back out if somebody else faulted in this pte
			 * while we released the pte lock.
			 */
			vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
					vmf->address, &vmf->ptl);
			if (likely(pte_same(*vmf->pte, vmf->orig_pte)))
				ret = VM_FAULT_OOM;
			delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
			goto unlock;
		}

		/* Had to read the page from swap area: Major fault */
		ret = VM_FAULT_MAJOR;
		count_vm_event(PGMAJFAULT);
		count_memcg_event_mm(vma->vm_mm, PGMAJFAULT);
	} else if (PageHWPoison(page)) {
		/*
		 * hwpoisoned dirty swapcache pages are kept for killing
		 * owner processes (which may be unknown at hwpoison time)
		 */
		ret = VM_FAULT_HWPOISON;
		delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
		goto out_release;
	}

	locked = lock_page_or_retry(page, vma->vm_mm, vmf->flags);

	delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
	if (!locked) {
		ret |= VM_FAULT_RETRY;
		goto out_release;
	}

	/*
	 * Make sure try_to_free_swap or reuse_swap_page or swapoff did not
	 * release the swapcache from under us.  The page pin, and pte_same
	 * test below, are not enough to exclude that.  Even if it is still
	 * swapcache, we need to check that the page's swap has not changed.
	 */
	if (unlikely((!PageSwapCache(page) ||
			page_private(page) != entry.val)) && swapcache)
		goto out_page;

	page = ksm_might_need_to_copy(page, vma, vmf->address);
	if (unlikely(!page)) {
		ret = VM_FAULT_OOM;
		page = swapcache;
		goto out_page;
	}

	if (mem_cgroup_try_charge_delay(page, vma->vm_mm, GFP_KERNEL,
					&memcg, false)) {
		ret = VM_FAULT_OOM;
		goto out_page;
	}

	/*
	 * Back out if somebody else already faulted in this pte.
	 */
	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
			&vmf->ptl);
	if (unlikely(!pte_same(*vmf->pte, vmf->orig_pte)))
		goto out_nomap;

	if (unlikely(!PageUptodate(page))) {
		ret = VM_FAULT_SIGBUS;
		goto out_nomap;
	}

	/*
	 * The page isn't present yet, go ahead with the fault.
	 *
	 * Be careful about the sequence of operations here.
	 * To get its accounting right, reuse_swap_page() must be called
	 * while the page is counted on swap but not yet in mapcount i.e.
	 * before page_add_anon_rmap() and swap_free(); try_to_free_swap()
	 * must be called after the swap_free(), or it will never succeed.
	 */

	inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
	dec_mm_counter_fast(vma->vm_mm, MM_SWAPENTS);
	pte = mk_pte(page, vma->vm_page_prot);
	if ((vmf->flags & FAULT_FLAG_WRITE) && reuse_swap_page(page, NULL)) {
		pte = maybe_mkwrite(pte_mkdirty(pte), vma);
		vmf->flags &= ~FAULT_FLAG_WRITE;
		ret |= VM_FAULT_WRITE;
		exclusive = RMAP_EXCLUSIVE;
	}
	flush_icache_page(vma, page);
	if (pte_swp_soft_dirty(vmf->orig_pte))
		pte = pte_mksoft_dirty(pte);
	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
	vmf->orig_pte = pte;

	/* ksm created a completely new copy */
	if (unlikely(page != swapcache && swapcache)) {
		page_add_new_anon_rmap(page, vma, vmf->address, false);
		mem_cgroup_commit_charge(page, memcg, false, false);
		lru_cache_add_active_or_unevictable(page, vma);
	} else {
		do_page_add_anon_rmap(page, vma, vmf->address, exclusive);
		mem_cgroup_commit_charge(page, memcg, true, false);
		activate_page(page);
	}

	swap_free(entry);
	if (mem_cgroup_swap_full(page) ||
	    (vma->vm_flags & VM_LOCKED) || PageMlocked(page))
		try_to_free_swap(page);
	unlock_page(page);
	if (page != swapcache && swapcache) {
		/*
		 * Hold the lock to avoid the swap entry to be reused
		 * until we take the PT lock for the pte_same() check
		 * (to avoid false positives from pte_same). For
		 * further safety release the lock after the swap_free
		 * so that the swap count won't change under a
		 * parallel locked swapcache.
		 */
		unlock_page(swapcache);
		put_page(swapcache);
	}

	if (vmf->flags & FAULT_FLAG_WRITE) {
		ret |= do_wp_page(vmf);
		if (ret & VM_FAULT_ERROR)
			ret &= VM_FAULT_ERROR;
		goto out;
	}

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, vmf->address, vmf->pte);
unlock:
	pte_unmap_unlock(vmf->pte, vmf->ptl);
out:
	return ret;
out_nomap:
	mem_cgroup_cancel_charge(page, memcg, false);
	pte_unmap_unlock(vmf->pte, vmf->ptl);
out_page:
	unlock_page(page);
out_release:
	put_page(page);
	if (page != swapcache && swapcache) {
		unlock_page(swapcache);
		put_page(swapcache);
	}
	return ret;
}

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 2024年6月17日23:39:57
 2024年6月24日23:36:00
 发生缺页异常时，内核会去分配内存并将页表填好。此时就会考虑到从哪里去分配内存，
 在这个时候就会去参考之前设置的numa策略。
 */
static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	/* 内存记账相关 */
	struct mem_cgroup *memcg;
	struct page *page;
	vm_fault_t ret = 0;
	pte_t entry;

	/* File mapping without ->vm_ops ? */
	if (vma->vm_flags & VM_SHARED)
		return VM_FAULT_SIGBUS;

	/*
	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under down_write(mmap_sem) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have down_read(mmap_sem).
	 */
	if (pte_alloc(vma->vm_mm, vmf->pmd))
		return VM_FAULT_OOM;

	/* See the comment in pte_alloc_one_map() */
	if (unlikely(pmd_trans_unstable(vmf->pmd)))
		return 0;

	/* Use the zero-page for reads */
	if (!(vmf->flags & FAULT_FLAG_WRITE) &&
			!mm_forbids_zeropage(vma->vm_mm)) {
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address),
						vma->vm_page_prot));
		vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
				vmf->address, &vmf->ptl);
		if (!pte_none(*vmf->pte))
			goto unlock;
		ret = check_stable_address_space(vma->vm_mm);
		if (ret)
			goto unlock;
		/* Deliver the page fault to userland, check inside PT lock */
		if (userfaultfd_missing(vma)) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			return handle_userfault(vmf, VM_UFFD_MISSING);
		}
		goto setpte;
	}

	/* Allocate our own private page. */
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;
	page = alloc_zeroed_user_highpage_movable(vma, vmf->address);
	if (!page)
		goto oom;

	if (mem_cgroup_try_charge_delay(page, vma->vm_mm, GFP_KERNEL, &memcg,
					false))
		goto oom_free_page;

	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceeding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__SetPageUptodate(page);

	entry = mk_pte(page, vma->vm_page_prot);
	if (vma->vm_flags & VM_WRITE)
		entry = pte_mkwrite(pte_mkdirty(entry));

	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
			&vmf->ptl);
	if (!pte_none(*vmf->pte))
		goto release;

	ret = check_stable_address_space(vma->vm_mm);
	if (ret)
		goto release;

	/* Deliver the page fault to userland, check inside PT lock */
	if (userfaultfd_missing(vma)) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		mem_cgroup_cancel_charge(page, memcg, false);
		put_page(page);
		return handle_userfault(vmf, VM_UFFD_MISSING);
	}

	inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
	page_add_new_anon_rmap(page, vma, vmf->address, false);
	mem_cgroup_commit_charge(page, memcg, false, false);
	/* lru记账的时机还是在缺页处理do_anonymous_page->lru_cache_add_active_or_unevictable */
	lru_cache_add_active_or_unevictable(page, vma);
setpte:
	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, vmf->address, vmf->pte);
unlock:
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return ret;
release:
	mem_cgroup_cancel_charge(page, memcg, false);
	put_page(page);
	goto unlock;
oom_free_page:
	put_page(page);
oom:
	return VM_FAULT_OOM;
}

/*
2024年7月1日23:15:40
真正为异常地址分配页面
 * The mmap_sem must have been held on entry, and may have been
 * released depending on flags and vma->vm_ops->fault() return value.
 * See filemap_fault() and __lock_page_retry().
 */
static vm_fault_t __do_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret;

	/*
	 * Preallocate pte before we take page_lock because this might lead to
	 * deadlocks for memcg reclaim which waits for pages under writeback:
	 *				lock_page(A)
	 *				SetPageWriteback(A)
	 *				unlock_page(A)
	 * lock_page(B)
	 *				lock_page(B)
	 * pte_alloc_pne
	 *   shrink_page_list
	 *     wait_on_page_writeback(A)
	 *				SetPageWriteback(B)
	 *				unlock_page(B)
	 *				# flush A, B to clear the writeback
	 */
	if (pmd_none(*vmf->pmd) && !vmf->prealloc_pte) {
		/* 预先分配pte */
		vmf->prealloc_pte = pte_alloc_one(vmf->vma->vm_mm);
		if (!vmf->prealloc_pte)
			return VM_FAULT_OOM;
		smp_wmb(); /* See comment in __pte_alloc() */
	}
	/* 调用falut函数把文件内容读取到vmf的page里面？ */
	ret = vma->vm_ops->fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY |
			    VM_FAULT_DONE_COW)))
		return ret;

	if (unlikely(PageHWPoison(vmf->page))) {
		if (ret & VM_FAULT_LOCKED)
			unlock_page(vmf->page);
		put_page(vmf->page);
		vmf->page = NULL;
		return VM_FAULT_HWPOISON;
	}

	if (unlikely(!(ret & VM_FAULT_LOCKED)))
		lock_page(vmf->page);
	else
		VM_BUG_ON_PAGE(!PageLocked(vmf->page), vmf->page);

	return ret;
}

/*
 * The ordering of these checks is important for pmds with _PAGE_DEVMAP set.
 * If we check pmd_trans_unstable() first we will trip the bad_pmd() check
 * inside of pmd_none_or_trans_huge_or_clear_bad(). This will end up correctly
 * returning 1 but not before it spams dmesg with the pmd_clear_bad() output.
 */
static int pmd_devmap_trans_unstable(pmd_t *pmd)
{
	return pmd_devmap(*pmd) || pmd_trans_unstable(pmd);
}
/* 

好像功能就是设置vmf的pte？
 */
static vm_fault_t pte_alloc_one_map(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;

	if (!pmd_none(*vmf->pmd))
		goto map_pte;
	
	/* 到这说明vmf->pmd为空？ */
	if (vmf->prealloc_pte) {
		vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
		if (unlikely(!pmd_none(*vmf->pmd))) {
			/* 又不为空了 */
			spin_unlock(vmf->ptl);
			goto map_pte;
		}

		mm_inc_nr_ptes(vma->vm_mm);
		/* 真正把pte放到pmd上面？ */
		pmd_populate(vma->vm_mm, vmf->pmd, vmf->prealloc_pte);

		spin_unlock(vmf->ptl);
		vmf->prealloc_pte = NULL;
	} else if (unlikely(pte_alloc(vma->vm_mm, vmf->pmd))) {
		return VM_FAULT_OOM;
	}


map_pte:
/* 已经有了pmd的话，到这 */
	/*
	 * If a huge pmd materialized under us just retry later.  Use
	 * pmd_trans_unstable() via pmd_devmap_trans_unstable() instead of
	 * pmd_trans_huge() to ensure the pmd didn't become pmd_trans_huge
	 * under us and then back to pmd_none, as a result of MADV_DONTNEED
	 * running immediately after a huge pmd fault in a different thread of
	 * this mm, in turn leading to a misleading pmd_trans_huge() retval.
	 * All we have to ensure is that it is a regular pmd that we can walk
	 * with pte_offset_map() and we can do that through an atomic read in
	 * C, which is what pmd_trans_unstable() provides.
	 */
	if (pmd_devmap_trans_unstable(vmf->pmd))
		return VM_FAULT_NOPAGE;

	/*
	 * At this point we know that our vmf->pmd points to a page of ptes
	 * and it cannot become pmd_none(), pmd_devmap() or pmd_trans_huge()
	 * for the duration of the fault.  If a racing MADV_DONTNEED runs and
	 * we zap the ptes pointed to by our vmf->pmd, the vmf->ptl will still
	 * be valid and we will re-check to make sure the vmf->pte isn't
	 * pte_none() under vmf->ptl protection when we return to
	 * alloc_set_pte().

	 */
	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
			&vmf->ptl);
	return 0;
}

#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
/* todo */
static void deposit_prealloc_pte(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;

	pgtable_trans_huge_deposit(vma->vm_mm, vmf->pmd, vmf->prealloc_pte);
	/*
	 * We are going to consume the prealloc table,
	 * count that as nr_ptes.
	 */
	mm_inc_nr_ptes(vma->vm_mm);
	vmf->prealloc_pte = NULL;
}
/* vmf设置pmd、
2024年7月27日01:32:41
有点复杂
是给page设置pmd吗
 */
static vm_fault_t do_set_pmd(struct vm_fault *vmf, struct page *page)
{
	struct vm_area_struct *vma = vmf->vma;
	bool write = vmf->flags & FAULT_FLAG_WRITE;
	unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
	pmd_t entry;
	int i;
	vm_fault_t ret;

	if (!transhuge_vma_suitable(vma, haddr))
		return VM_FAULT_FALLBACK;

	ret = VM_FAULT_FALLBACK;
	page = compound_head(page);

	/*
	 * Archs like ppc64 need additonal space to store information
	 * related to pte entry. Use the preallocated table for that.
	 */
	if (arch_needs_pgtable_deposit() && !vmf->prealloc_pte) {
		vmf->prealloc_pte = pte_alloc_one(vma->vm_mm);

		if (!vmf->prealloc_pte)
			return VM_FAULT_OOM;
		smp_wmb(); /* See comment in __pte_alloc() */
	}

	vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
	if (unlikely(!pmd_none(*vmf->pmd)))
		goto out;

	for (i = 0; i < HPAGE_PMD_NR; i++)
		flush_icache_page(vma, page + i);

	entry = mk_huge_pmd(page, vma->vm_page_prot);
	if (write)
	/* 只是更新一下pmd属性 */
		entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
	
	/* 更新mm的rss计数器 */
	add_mm_counter(vma->vm_mm, mm_counter_file(page), HPAGE_PMD_NR);
	/* 做了什么 */
	page_add_file_rmap(page, true);
	/*
	 * deposit and withdraw with pmd lock held
	 */
	if (arch_needs_pgtable_deposit())
		deposit_prealloc_pte(vmf);

	set_pmd_at(vma->vm_mm, haddr, vmf->pmd, entry);


	update_mmu_cache_pmd(vma, haddr, vmf->pmd);

	/* fault is handled */
	ret = 0;
	count_vm_event(THP_FILE_MAPPED);
out:
	spin_unlock(vmf->ptl);
	return ret;
}
#else
static vm_fault_t do_set_pmd(struct vm_fault *vmf, struct page *page)
{
	BUILD_BUG();
	return 0;
}
#endif

/**
 * alloc_set_pte - setup new PTE entry for given page and add reverse page
 * mapping. If needed, the fucntion allocates page table or use pre-allocated.
 *
 * @vmf: fault environment
 * @memcg: memcg to charge page (only for private mappings)
 * @page: page to map
 *
 * Caller must take care of unlocking vmf->ptl, if vmf->pte is non-NULL on
 * return.
 *
 * Target users are page handler itself and implementations of
 * vm_ops->map_pages.
 *
 * Return: %0 on success, %VM_FAULT_ code in case of error.
 2024年7月1日23:19:47
 为虚拟地址和物理页面建立映射
 */
vm_fault_t alloc_set_pte(struct vm_fault *vmf, struct mem_cgroup *memcg,
		struct page *page)
{
	struct vm_area_struct *vma = vmf->vma;
	bool write = vmf->flags & FAULT_FLAG_WRITE;
	pte_t entry;
	vm_fault_t ret;

	if (pmd_none(*vmf->pmd) && PageTransCompound(page) &&
			IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE)) {
		/* THP on COW? */
		VM_BUG_ON_PAGE(memcg, page);
		/* pmd不存在的情况，设置pmd */
		ret = do_set_pmd(vmf, page);
		if (ret != VM_FAULT_FALLBACK)
			return ret;
	}

	if (!vmf->pte) {
		/*  */
		ret = pte_alloc_one_map(vmf);
		if (ret)
			return ret;
	}

	/* Re-check under ptl */
	if (unlikely(!pte_none(*vmf->pte)))
		return VM_FAULT_NOPAGE;

	flush_icache_page(vma, page);
	entry = mk_pte(page, vma->vm_page_prot);
	if (write)
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	/* copy-on-write page */
	if (write && !(vma->vm_flags & VM_SHARED)) {
		inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
		page_add_new_anon_rmap(page, vma, vmf->address, false);
		mem_cgroup_commit_charge(page, memcg, false, false);
		lru_cache_add_active_or_unevictable(page, vma);
	} else {
		inc_mm_counter_fast(vma->vm_mm, mm_counter_file(page));
		page_add_file_rmap(page, false);
	}
	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

	/* no need to invalidate: a not-present page won't be cached */
	update_mmu_cache(vma, vmf->address, vmf->pte);

	return 0;
}


/**
 * finish_fault - finish page fault once we have prepared the page to fault
 *
 * @vmf: structure describing the fault
 *
 * This function handles all that is needed to finish a page fault once the
 * page to fault in is prepared. It handles locking of PTEs, inserts PTE for
 * given page, adds reverse page mapping, handles memcg charges and LRU
 * addition.
 *
 * The function expects the page to be locked and on success it consumes a
 * reference of a page being mapped (for the PTE which maps it).
 *
 * Return: %0 on success, %VM_FAULT_ code in case of error.
 2024年7月1日23:19:01
2024年7月1日23:38:19
 调用此，给cow page创建pte，添加rmap

 */
vm_fault_t finish_fault(struct vm_fault *vmf)
{
	struct page *page;
	vm_fault_t ret = 0;

	/* Did we COW the page? */
	if ((vmf->flags & FAULT_FLAG_WRITE) &&
	    !(vmf->vma->vm_flags & VM_SHARED))
		page = vmf->cow_page;
	else
		page = vmf->page;

	/*
	 * check even for read faults because we might have lost our CoWed
	 * page。

	 */
	if (!(vmf->vma->vm_flags & VM_SHARED))
		ret = check_stable_address_space(vmf->vma->vm_mm);

	if (!ret)
	/* 为虚拟地址和物理页面建立映射 */
		ret = alloc_set_pte(vmf, vmf->memcg, page);

	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	return ret;
}

static unsigned long fault_around_bytes __read_mostly =
	rounddown_pow_of_two(65536);

#ifdef CONFIG_DEBUG_FS
static int fault_around_bytes_get(void *data, u64 *val)
{
	*val = fault_around_bytes;
	return 0;
}

/*
 * fault_around_bytes must be rounded down to the nearest page order as it's
 * what do_fault_around() expects to see.
 */
static int fault_around_bytes_set(void *data, u64 val)
{
	if (val / PAGE_SIZE > PTRS_PER_PTE)
		return -EINVAL;
	if (val > PAGE_SIZE)
		fault_around_bytes = rounddown_pow_of_two(val);
	else
		fault_around_bytes = PAGE_SIZE; /* rounddown_pow_of_two(0) is undefined */
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(fault_around_bytes_fops,
		fault_around_bytes_get, fault_around_bytes_set, "%llu\n");

static int __init fault_around_debugfs(void)
{
	debugfs_create_file_unsafe("fault_around_bytes", 0644, NULL, NULL,
				   &fault_around_bytes_fops);
	return 0;
}
late_initcall(fault_around_debugfs);
#endif

/*
 * do_fault_around() tries to map few pages around the fault address. The hope
 * is that the pages will be needed soon and this will lower the number of
 * faults to handle.
 *
 * It uses vm_ops->map_pages() to map the pages, which skips the page if it's
 * not ready to be mapped: not up-to-date, locked, etc.
 *
 * This function is called with the page table lock taken. In the split ptlock
 * case the page table lock only protects only those entries which belong to
 * the page table corresponding to the fault address.
 *
 * This function doesn't cross the VMA boundaries, in order to call map_pages()
 * only once.
 *
 * fault_around_bytes defines how many bytes we'll try to map.
 * do_fault_around() expects it to be set to a power of two less than or equal
 * to PTRS_PER_PTE.
 *
 * The virtual address of the area that we map is naturally aligned to
 * fault_around_bytes rounded down to the machine page size
 * (and therefore to page order).  This way it's easier to guarantee
 * that we don't cross page table boundaries.
 2024年7月1日23:13:40
类似预读，预先建立内存映射，加快速度

 */
static vm_fault_t do_fault_around(struct vm_fault *vmf)
{
	unsigned long address = vmf->address, nr_pages, mask;
	pgoff_t start_pgoff = vmf->pgoff;
	pgoff_t end_pgoff;
	int off;
	vm_fault_t ret = 0;

	nr_pages = READ_ONCE(fault_around_bytes) >> PAGE_SHIFT;
	mask = ~(nr_pages * PAGE_SIZE - 1) & PAGE_MASK;

	vmf->address = max(address & mask, vmf->vma->vm_start);
	off = ((address - vmf->address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
	start_pgoff -= off;

	/*
	 *  end_pgoff is either the end of the page table, the end of
	 *  the vma or nr_pages from start_pgoff, depending what is nearest.
	 */
	end_pgoff = start_pgoff -
		((vmf->address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)) +
		PTRS_PER_PTE - 1;
	end_pgoff = min3(end_pgoff, vma_pages(vmf->vma) + vmf->vma->vm_pgoff - 1,
			start_pgoff + nr_pages - 1);

	if (pmd_none(*vmf->pmd)) {
		vmf->prealloc_pte = pte_alloc_one(vmf->vma->vm_mm);
		if (!vmf->prealloc_pte)
			goto out;
		smp_wmb(); /* See comment in __pte_alloc() */
	}

	vmf->vma->vm_ops->map_pages(vmf, start_pgoff, end_pgoff);

	/* Huge page is mapped? Page fault is solved */
	if (pmd_trans_huge(*vmf->pmd)) {
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	/* ->map_pages() haven't done anything useful. Cold page cache? */
	if (!vmf->pte)
		goto out;

	/* check if the page fault is solved */
	vmf->pte -= (vmf->address >> PAGE_SHIFT) - (address >> PAGE_SHIFT);
	if (!pte_none(*vmf->pte))
		ret = VM_FAULT_NOPAGE;
	pte_unmap_unlock(vmf->pte, vmf->ptl);
out:
	vmf->address = address;
	vmf->pte = NULL;
	return ret;
}
/* 2024年7月1日23:12:07

 */
static vm_fault_t do_read_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret = 0;

	/*
	 * Let's call ->map_pages() first and use ->fault() as fallback
	 * if page by the offset is not ready to be mapped (cold cache or
	 * something).
	 如果vma提供了mappages函数，可以在缺页地址尽可能多提供页面
	 */
	if (vma->vm_ops->map_pages && fault_around_bytes >> PAGE_SHIFT > 1) {
		ret = do_fault_around(vmf);
		if (ret)
			return ret;
	}

	ret = __do_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;

	ret |= finish_fault(vmf);
	unlock_page(vmf->page);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		put_page(vmf->page);
	return ret;
}
/* 2024年7月1日23:23:45
处理写内存导致的缺页异常
处理私有映射的vma发生了写时复制
 */
static vm_fault_t do_cow_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret;
	/* 检查rmap */
	if (unlikely(anon_vma_prepare(vma)))
		return VM_FAULT_OOM;
		/* 分配cow page */
	vmf->cow_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->address);
	if (!vmf->cow_page)
		return VM_FAULT_OOM;

	if (mem_cgroup_try_charge_delay(vmf->cow_page, vma->vm_mm, GFP_KERNEL,
				&vmf->memcg, false)) {
		put_page(vmf->cow_page);
		return VM_FAULT_OOM;
	}
/* 读取文件内容到vmf-page里面 */
	ret = __do_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;
	if (ret & VM_FAULT_DONE_COW)
		return ret;
/* 把flaut page复制到cow page里面 */
	copy_user_highpage(vmf->cow_page, vmf->page, vmf->address, vma);
	__SetPageUptodate(vmf->cow_page);
	/* 调用此，给cow page创建pte，添加rmap */
	ret |= finish_fault(vmf);
	unlock_page(vmf->page);
	put_page(vmf->page);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;
	return ret;
uncharge_out:
	mem_cgroup_cancel_charge(vmf->cow_page, vmf->memcg, false);
	put_page(vmf->cow_page);
	return ret;
}
/*  */
static vm_fault_t do_shared_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret, tmp;
	/*  */
	ret = __do_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		return ret;

	/*
	 * Check if the backing address space wants to know that the page is
	 * about to become writable
	 */
	if (vma->vm_ops->page_mkwrite) {
		unlock_page(vmf->page);
		tmp = do_page_mkwrite(vmf);
		if (unlikely(!tmp ||
				(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))) {
			put_page(vmf->page);
			return tmp;
		}
	}

	ret |= finish_fault(vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE |
					VM_FAULT_RETRY))) {
		unlock_page(vmf->page);
		put_page(vmf->page);
		return ret;
	}

	fault_dirty_shared_page(vma, vmf->page);
	return ret;
}

/*
缺页处理
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults).
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 * If mmap_sem is released, vma may become invalid (for example
 * by other thread calling munmap()).
 */
static vm_fault_t do_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *vm_mm = vma->vm_mm;
	vm_fault_t ret;

	/*
	 * The VMA was not fully populated on mmap() or missing VM_DONTEXPAND
	 */
	if (!vma->vm_ops->fault) {
		/*
		 * If we find a migration pmd entry or a none pmd entry, which
		 * should never happen, return SIGBUS
		 */
		if (unlikely(!pmd_present(*vmf->pmd)))
			ret = VM_FAULT_SIGBUS;
		else {
			vmf->pte = pte_offset_map_lock(vmf->vma->vm_mm,
						       vmf->pmd,
						       vmf->address,
						       &vmf->ptl);
			/*
			 * Make sure this is not a temporary clearing of pte
			 * by holding ptl and checking again. A R/M/W update
			 * of pte involves: take ptl, clearing the pte so that
			 * we don't have concurrent modification by hardware
			 * followed by an update.
			 */
			if (unlikely(pte_none(*vmf->pte)))
				ret = VM_FAULT_SIGBUS;
			else
				ret = VM_FAULT_NOPAGE;

			pte_unmap_unlock(vmf->pte, vmf->ptl);
		}
	} else if (!(vmf->flags & FAULT_FLAG_WRITE))
		ret = do_read_fault(vmf);
	else if (!(vma->vm_flags & VM_SHARED))
		ret = do_cow_fault(vmf);
	else
		ret = do_shared_fault(vmf);

	/* preallocated pagetable is unused: free it */
	if (vmf->prealloc_pte) {
		pte_free(vm_mm, vmf->prealloc_pte);
		vmf->prealloc_pte = NULL;
	}
	return ret;
}
/*  */
static int numa_migrate_prep(struct page *page, struct vm_area_struct *vma,
				unsigned long addr, int page_nid,
				int *flags)
{
	get_page(page);

	count_vm_numa_event(NUMA_HINT_FAULTS);
	if (page_nid == numa_node_id()) {
		count_vm_numa_event(NUMA_HINT_FAULTS_LOCAL);
		*flags |= TNF_FAULT_LOCAL;
	}
	/* 返回适合此vma的addr的nid */
	return mpol_misplaced(page, vma, addr);
}
/* 
2024年7月26日23:29:45
好复杂
todo */
static vm_fault_t do_numa_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = NULL;
	int page_nid = NUMA_NO_NODE;
	int last_cpupid;
	int target_nid;
	bool migrated = false;
	pte_t pte, old_pte;
	bool was_writable = pte_savedwrite(vmf->orig_pte);
	int flags = 0;

	/*
	 * The "pte" at this point cannot be used safely without
	 * validation through pte_unmap_same(). It's of NUMA type but
	 * the pfn may be screwed if the read is non atomic.
	 */
	vmf->ptl = pte_lockptr(vma->vm_mm, vmf->pmd);


	spin_lock(vmf->ptl);
	if (unlikely(!pte_same(*vmf->pte, vmf->orig_pte))) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		goto out;
	}

	/*
	 * Make it present again, Depending on how arch implementes non
	 * accessible ptes, some can allow access by kernel mode.
	 */
	old_pte = ptep_modify_prot_start(vma, vmf->address, vmf->pte);

	pte = pte_modify(old_pte, vma->vm_page_prot);
	pte = pte_mkyoung(pte);
	if (was_writable)
		pte = pte_mkwrite(pte);
	ptep_modify_prot_commit(vma, vmf->address, vmf->pte, old_pte, pte);
	update_mmu_cache(vma, vmf->address, vmf->pte);

	page = vm_normal_page(vma, vmf->address, pte);
	if (!page) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		return 0;
	}

	/* TODO: handle PTE-mapped THP */
	if (PageCompound(page)) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		return 0;
	}

	/*
	 * Avoid grouping on RO pages in general. RO pages shouldn't hurt as
	 * much anyway since they can be in shared cache state. This misses
	 * the case where a mapping is writable but the process never writes
	 * to it but pte_write gets cleared during protection updates and
	 * pte_dirty has unpredictable behaviour between PTE scan updates,
	 * background writeback, dirty balancing and application behaviour.
	 */
	if (!pte_write(pte))
		flags |= TNF_NO_GROUP;

	/*
	 * Flag if the page is shared between multiple address spaces. This
	 * is later used when determining whether to group tasks together
	 */
	if (page_mapcount(page) > 1 && (vma->vm_flags & VM_SHARED))
		flags |= TNF_SHARED;

	last_cpupid = page_cpupid_last(page);
	page_nid = page_to_nid(page);
	target_nid = numa_migrate_prep(page, vma, vmf->address, page_nid,
			&flags);
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	if (target_nid == NUMA_NO_NODE) {
		put_page(page);
		goto out;
	}

	/* Migrate to the requested node */
	migrated = migrate_misplaced_page(page, vma, target_nid);
	if (migrated) {
		page_nid = target_nid;
		flags |= TNF_MIGRATED;
	} else
		flags |= TNF_MIGRATE_FAIL;

out:
	if (page_nid != NUMA_NO_NODE)
		task_numa_fault(last_cpupid, page_nid, 1, flags);
	return 0;
}

static inline vm_fault_t create_huge_pmd(struct vm_fault *vmf)
{
	if (vma_is_anonymous(vmf->vma))
		return do_huge_pmd_anonymous_page(vmf);
	if (vmf->vma->vm_ops->huge_fault)
		return vmf->vma->vm_ops->huge_fault(vmf, PE_SIZE_PMD);
	return VM_FAULT_FALLBACK;
}

/* `inline' is required to avoid gcc 4.1.2 build error */
static inline vm_fault_t wp_huge_pmd(struct vm_fault *vmf, pmd_t orig_pmd)
{
	if (vma_is_anonymous(vmf->vma))
		return do_huge_pmd_wp_page(vmf, orig_pmd);
	if (vmf->vma->vm_ops->huge_fault)
		return vmf->vma->vm_ops->huge_fault(vmf, PE_SIZE_PMD);

	/* COW handled on pte level: split pmd */
	VM_BUG_ON_VMA(vmf->vma->vm_flags & VM_SHARED, vmf->vma);
	__split_huge_pmd(vmf->vma, vmf->pmd, vmf->address, false, NULL);

	return VM_FAULT_FALLBACK;
}
/* 可读，可写，可执行 */
static inline bool vma_is_accessible(struct vm_area_struct *vma)
{
	return vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE);
}

static vm_fault_t create_huge_pud(struct vm_fault *vmf)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	/* No support for anonymous transparent PUD pages yet */
	if (vma_is_anonymous(vmf->vma))
		return VM_FAULT_FALLBACK;
	if (vmf->vma->vm_ops->huge_fault)
		return vmf->vma->vm_ops->huge_fault(vmf, PE_SIZE_PUD);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
	return VM_FAULT_FALLBACK;
}
/*  */
static vm_fault_t wp_huge_pud(struct vm_fault *vmf, pud_t orig_pud)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	/* No support for anonymous transparent PUD pages yet */
	if (vma_is_anonymous(vmf->vma))
		return VM_FAULT_FALLBACK;
	if (vmf->vma->vm_ops->huge_fault)
		return vmf->vma->vm_ops->huge_fault(vmf, PE_SIZE_PUD);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
	return VM_FAULT_FALLBACK;
}

/*
2024年8月9日22:30:49
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes, but allow
 * concurrent faults).
 *
 * The mmap_sem may have been released depending on flags and our return value.
 * See filemap_fault() and __lock_page_or_retry().
 */
static vm_fault_t handle_pte_fault(struct vm_fault *vmf)
{
	pte_t entry;

	if (unlikely(pmd_none(*vmf->pmd))) {/* pmd都是空的 */
		/*
		 * Leave __pte_alloc() until later: because vm_ops->fault may
		 * want to allocate huge page, and if we expose page table
		 * for an instant, it will be difficult to retract from
		 * concurrent faults and from rmap lookups.
		 */
		vmf->pte = NULL;
	} else {
		/* pmd存在 */
		/* See comment in pte_alloc_one_map() */
		if (pmd_devmap_trans_unstable(vmf->pmd))
			return 0;
		/*
		 * A regular pmd is established and it can't morph into a huge
		 * pmd from under us anymore at this point because we hold the
		 * mmap_sem read mode and khugepaged takes it in write mode.
		 * So now it's safe to run pte_offset_map().
		 */

		 /* 找到pte条目地址 */
		vmf->pte = pte_offset_map(vmf->pmd, vmf->address);
		/* 获取条目上的值 */
		vmf->orig_pte = *vmf->pte;

		/*
		 * some architectures can have larger ptes than wordsize,
		 * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and
		 * CONFIG_32BIT=y, so READ_ONCE cannot guarantee atomic
		 * accesses.  The code below just needs a consistent view
		 * for the ifs and we later double check anyway with the
		 * ptl lock held. So here a barrier will do.
		 */
		barrier();
		if (pte_none(vmf->orig_pte)) {
			pte_unmap(vmf->pte);
			vmf->pte = NULL;
		}
	}

	/* 刚刚找到了pte条目位置 */

	/* pte是空的，但是不能是其他情况吗 */
	if (!vmf->pte) {
		if (vma_is_anonymous(vmf->vma))
			/* 匿名页？ */
			return do_anonymous_page(vmf);
		else
		/* 文件页？ */
			return do_fault(vmf);
	}

	/* 下面是有pte的情况，看代码逻辑好像这种情况就是
	1交换
	2numa
	 */
	if (!pte_present(vmf->orig_pte))
		return do_swap_page(vmf);

	if (pte_protnone(vmf->orig_pte) && vma_is_accessible(vmf->vma))
		return do_numa_page(vmf);
	/* 下面是哪些子进程写时复制什么的情况 */
	vmf->ptl = pte_lockptr(vmf->vma->vm_mm, vmf->pmd);
	spin_lock(vmf->ptl);
	entry = vmf->orig_pte;
	if (unlikely(!pte_same(*vmf->pte, entry)))
		goto unlock;
	if (vmf->flags & FAULT_FLAG_WRITE) {
		if (!pte_write(entry))
			return do_wp_page(vmf);
		entry = pte_mkdirty(entry);
	}
	entry = pte_mkyoung(entry);
	if (ptep_set_access_flags(vmf->vma, vmf->address, vmf->pte, entry,
				vmf->flags & FAULT_FLAG_WRITE)) {
		update_mmu_cache(vmf->vma, vmf->address, vmf->pte);
	} else {
		/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */
		if (vmf->flags & FAULT_FLAG_WRITE)
			flush_tlb_fix_spurious_fault(vmf->vma, vmf->address);
	}
unlock:
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return 0;
}

/*
2024年07月03日19:05:22
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags)
{
	////暂存异常过程中的信息
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
		.gfp_mask = __get_fault_gfp_mask(vma),
	};
	unsigned int dirty = flags & FAULT_FLAG_WRITE;
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	vm_fault_t ret;

	pgd = pgd_offset(mm, address);
	//只考虑三级页表的情况，这里的p4d就是pgd
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	vmf.pud = pud_alloc(mm, p4d, address);
	if (!vmf.pud)
		return VM_FAULT_OOM;
	if (pud_none(*vmf.pud) && __transparent_hugepage_enabled(vma)) {
		ret = create_huge_pud(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pud_t orig_pud = *vmf.pud;

		barrier();
		if (pud_trans_huge(orig_pud) || pud_devmap(orig_pud)) {

			/* NUMA case for anonymous PUDs would go here */

			if (dirty && !pud_write(orig_pud)) {
				ret = wp_huge_pud(&vmf, orig_pud);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pud_set_accessed(&vmf, orig_pud);
				return 0;
			}
		}
	}
//如果pmd在pud中不存在就分配一个，并且写到pud中
	vmf.pmd = pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;
	if (pmd_none(*vmf.pmd) && __transparent_hugepage_enabled(vma)) {
		ret = create_huge_pmd(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pmd_t orig_pmd = *vmf.pmd;

		barrier();
		if (unlikely(is_swap_pmd(orig_pmd))) {
			VM_BUG_ON(thp_migration_supported() &&
					  !is_pmd_migration_entry(orig_pmd));
			if (is_pmd_migration_entry(orig_pmd))
				pmd_migration_entry_wait(mm, vmf.pmd);
			return 0;
		}
		if (pmd_trans_huge(orig_pmd) || pmd_devmap(orig_pmd)) {
			if (pmd_protnone(orig_pmd) && vma_is_accessible(vma))
				return do_huge_pmd_numa_page(&vmf, orig_pmd);

			if (dirty && !pmd_write(orig_pmd)) {
				ret = wp_huge_pmd(&vmf, orig_pmd);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pmd_set_accessed(&vmf, orig_pmd);
				return 0;
			}
		}
	}

	return handle_pte_fault(&vmf);
}

/*
2024年7月1日23:03:50
缺页异常处理函数
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_sem may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */
vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
		unsigned int flags)
{
	vm_fault_t ret;

	__set_current_state(TASK_RUNNING);

	count_vm_event(PGFAULT);
	count_memcg_event_mm(vma->vm_mm, PGFAULT);

	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);

	if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
					    flags & FAULT_FLAG_INSTRUCTION,
					    flags & FAULT_FLAG_REMOTE))
		return VM_FAULT_SIGSEGV;

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	if (unlikely(is_vm_hugetlb_page(vma)))
		ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	else
	/* 处理缺页 */
		ret = __handle_mm_fault(vma, address, flags);

	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_exit_user_fault();
		/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		memcg恢复oom后清理？
		 */
		if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
			mem_cgroup_oom_synchronize(false);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(handle_mm_fault);

#ifndef __PAGETABLE_P4D_FOLDED
/*
 * Allocate p4d page table.
 * We've already handled the fast-path in-line.
 */
int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	p4d_t *new = p4d_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		p4d_free(mm, new);
	else
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}
#endif /* __PAGETABLE_P4D_FOLDED */

#ifndef __PAGETABLE_PUD_FOLDED
/*
分配pud，填充到p4d
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
#ifndef __ARCH_HAS_5LEVEL_HACK
	if (!p4d_present(*p4d)) {
		mm_inc_nr_puds(mm);

		p4d_populate(mm, p4d, new);
	} else	/* Another has populated it */
		pud_free(mm, new);
#else
	if (!pgd_present(*p4d)) {
		mm_inc_nr_puds(mm);
		pgd_populate(mm, p4d, new);
	} else	/* Another has populated it */
		pud_free(mm, new);
#endif /* __ARCH_HAS_5LEVEL_HACK */
	spin_unlock(&mm->page_table_lock);
	return 0;
}
#endif /* __PAGETABLE_PUD_FOLDED */

#ifndef __PAGETABLE_PMD_FOLDED
/*
2024年7月26日22:53:41
分配pmd
感觉就是分配这个pmd所用的页面之后，使用；
使用，就是让pud来指向它，使之present。
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	spinlock_t *ptl;

	
	pmd_t *new = pmd_alloc_one(mm, address);
	
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	ptl = pud_lock(mm, pud);
#ifndef __ARCH_HAS_4LEVEL_HACK
	if (!pud_present(*pud)) {
		/* 更新mm属性 */
		mm_inc_nr_pmds(mm);
		/* “使用”这个new */
		pud_populate(mm, pud, new);
	} else	/* Another has populated it */
		pmd_free(mm, new);
#else
	if (!pgd_present(*pud)) {
		mm_inc_nr_pmds(mm);
		pgd_populate(mm, pud, new);
	} else /* Another has populated it */
		pmd_free(mm, new);
#endif /* __ARCH_HAS_4LEVEL_HACK */
	spin_unlock(ptl);
	return 0;
}
#endif /* __PAGETABLE_PMD_FOLDED */
/* 处理mm的address。
@pmdpp：可能为空 ，巨页才需要这个参数。

找到address对应的pte，赋值到ptepp。*/
static int __follow_pte_pmd(struct mm_struct *mm, unsigned long address,
			    struct mmu_notifier_range *range,
			    pte_t **ptepp, pmd_t **pmdpp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		goto out;

	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));

	if (pmd_huge(*pmd)) {/* 巨页的路径，todo */
		if (!pmdpp)
			goto out;

		if (range) {
			mmu_notifier_range_init(range, MMU_NOTIFY_CLEAR, 0,
						NULL, mm, address & PMD_MASK,
						(address & PMD_MASK) + PMD_SIZE);
			mmu_notifier_invalidate_range_start(range);
		}
		*ptlp = pmd_lock(mm, pmd);
		if (pmd_huge(*pmd)) {
			*pmdpp = pmd;
			return 0;
		}
		spin_unlock(*ptlp);
		if (range)
			mmu_notifier_invalidate_range_end(range);
	}

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto out;

	if (range) {
		mmu_notifier_range_init(range, MMU_NOTIFY_CLEAR, 0, NULL, mm,
					address & PAGE_MASK,
					(address & PAGE_MASK) + PAGE_SIZE);
		mmu_notifier_invalidate_range_start(range);
	}
	/* 找到对应的pte */
	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!pte_present(*ptep))
		goto unlock;
	*ptepp = ptep;
	return 0;
unlock:
	pte_unmap_unlock(ptep, *ptlp);
	if (range)
		mmu_notifier_invalidate_range_end(range);
out:
	return -EINVAL;
}
/* 参数只是mm和它的某个address。
使ptepp指向addres的页表项。
 */
static inline int follow_pte(struct mm_struct *mm, unsigned long address,
			     pte_t **ptepp, spinlock_t **ptlp)
{
	int res;

	/* (void) is needed to make gcc happy */
	(void) __cond_lock(*ptlp,
			   !(res = __follow_pte_pmd(mm, address, NULL,
						    ptepp, NULL, ptlp)));
	return res;
}
/*  */
int follow_pte_pmd(struct mm_struct *mm, unsigned long address,
		   struct mmu_notifier_range *range,
		   pte_t **ptepp, pmd_t **pmdpp, spinlock_t **ptlp)
{
	int res;

	/* (void) is needed to make gcc happy */
	(void) __cond_lock(*ptlp,
			   !(res = __follow_pte_pmd(mm, address, range,
						    ptepp, pmdpp, ptlp)));
	return res;
}
EXPORT_SYMBOL(follow_pte_pmd);

/**
找到vma的addr对应的pfn？
 * follow_pfn - look up PFN at a user virtual address
 * @vma: memory mapping
 * @address: user virtual address
 * @pfn: location to store found PFN
 *
 * Only IO mappings and raw PFN mappings are allowed.
 *
 * Return: zero and the pfn at @pfn on success, -ve otherwise.
 */
int follow_pfn(struct vm_area_struct *vma, unsigned long address,
	unsigned long *pfn)
{
	int ret = -EINVAL;
	spinlock_t *ptl;
	pte_t *ptep;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		return ret;
	/* 这是先找pte吗？ */
	ret = follow_pte(vma->vm_mm, address, &ptep, &ptl);
	if (ret)
		return ret;
	*pfn = pte_pfn(*ptep);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(follow_pfn);

#ifdef CONFIG_HAVE_IOREMAP_PROT
/* 
@vma：是pfn映射类型的。
@address：可能是vma的起始地址。

找到address的pte，然后找到物理地址，存储到phys
*/
int follow_phys(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags,
		unsigned long *prot, resource_size_t *phys)
{
	int ret = -EINVAL;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))/* 至少要是pfnmap类型的或者这什么VM_IO */
		goto out;
	/* 找到address的页表项，存储到ptep */
	if (follow_pte(vma->vm_mm, address, &ptep, &ptl))
		goto out;
	/* 获取pte表项 */
	pte = *ptep;


	if ((flags & FOLL_WRITE) && !pte_write(pte))
		goto unlock;
	/* 获取pte的proto */
	*prot = pgprot_val(pte_pgprot(pte));
	/* 获取pte的pfn然后phys */
	*phys = (resource_size_t)pte_pfn(pte) << PAGE_SHIFT;

	ret = 0;
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return ret;
}
/* todo */
int generic_access_phys(struct vm_area_struct *vma, unsigned long addr,
			void *buf, int len, int write)
{
	resource_size_t phys_addr;
	unsigned long prot = 0;
	void __iomem *maddr;
	int offset = addr & (PAGE_SIZE-1);

	if (follow_phys(vma, addr, write, &prot, &phys_addr))
		return -EINVAL;

	maddr = ioremap_prot(phys_addr, PAGE_ALIGN(len + offset), prot);
	if (!maddr)
		return -ENOMEM;

	if (write)
		memcpy_toio(maddr + offset, buf, len);
	else
		memcpy_fromio(buf, maddr + offset, len);
	iounmap(maddr);

	return len;
}
EXPORT_SYMBOL_GPL(generic_access_phys);
#endif

/*
访问其他进程的地址空间

---------------
pin住页面之后，拷贝到user space的buf里面
 * Access another process' address space as given in mm.  If non-NULL, use the
 * given task for page fault accounting.
 */
int __access_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long addr, void *buf, int len, unsigned int gup_flags)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;
	int write = gup_flags & FOLL_WRITE;

	if (down_read_killable(&mm->mmap_sem))
		return 0;

	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;
		/* pin住这些页面 */
		ret = get_user_pages_remote(tsk, mm, addr, 1,
				gup_flags, &page, &vma, NULL);

		if (ret <= 0) {
			/* 一个也没pin上 */

#ifndef CONFIG_HAVE_IOREMAP_PROT
			break;
#else
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
				break;
			bytes = ret;
#endif
		} else {
			/* pin住了1个页面 */
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;
			/* 拷贝到用户的buf里面 */
			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			put_page(page);
		}


		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}

/**
 * access_remote_vm - access another process' address space
 * @mm:		the mm_struct of the target address space
 * @addr:	start address to access
 * @buf:	source or destination buffer
 * @len:	number of bytes to transfer
 * @gup_flags:	flags modifying lookup behaviour
 *
 * The caller must hold a reference on @mm.
 *
 * Return: number of bytes copied from source to destination.
 */
int access_remote_vm(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, unsigned int gup_flags)
{
	return __access_remote_vm(NULL, mm, addr, buf, len, gup_flags);
}

/*
访问其他进程地址空间？
 * Access another process' address space.
 * Source/target buffer must be kernel space,
 * Do not walk the page table directly, use get_user_pages
 */
int access_process_vm(struct task_struct *tsk, unsigned long addr,
		void *buf, int len, unsigned int gup_flags)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = __access_remote_vm(tsk, mm, addr, buf, len, gup_flags);
	/* get tsk mm里面会进行get */
	mmput(mm);

	return ret;
}
EXPORT_SYMBOL_GPL(access_process_vm);

/*
2024年7月26日21:57:12
 * Print the name of a VMA.
 */
void print_vma_addr(char *prefix, unsigned long ip)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	/*
	 * we might be running from an atomic context so we cannot sleep
	 */
	if (!down_read_trylock(&mm->mmap_sem))
		return;

	vma = find_vma(mm, ip);
	if (vma && vma->vm_file) {
		struct file *f = vma->vm_file;
		char *buf = (char *)__get_free_page(GFP_NOWAIT);
		if (buf) {
			char *p;

			p = file_path(f, buf, PAGE_SIZE);
			if (IS_ERR(p))
				p = "?";
			printk("%s%s[%lx+%lx]", prefix, kbasename(p),
					vma->vm_start,
					vma->vm_end - vma->vm_start);
			free_page((unsigned long)buf);
		}
	}
	up_read(&mm->mmap_sem);
}

#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_DEBUG_ATOMIC_SLEEP)
void __might_fault(const char *file, int line)
{
	/*
	 * Some code (nfs/sunrpc) uses socket ops on kernel memory while
	 * holding the mmap_sem, this is safe because kernel memory doesn't
	 * get paged out, therefore we'll never actually fault, and the
	 * below annotations will generate false positives.
	 */
	if (uaccess_kernel())
		return;
	if (pagefault_disabled())
		return;
	__might_sleep(file, line, 0);
#if defined(CONFIG_DEBUG_ATOMIC_SLEEP)
	if (current->mm)
		might_lock_read(&current->mm->mmap_sem);
#endif
}
EXPORT_SYMBOL(__might_fault);
#endif

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
/*
 * Process all subpages of the specified huge page with the specified
 * operation.  The target subpage will be processed last to keep its
 * cache lines hot.
 */
static inline void process_huge_page(
	unsigned long addr_hint, unsigned int pages_per_huge_page,
	void (*process_subpage)(unsigned long addr, int idx, void *arg),
	void *arg)
{
	int i, n, base, l;
	unsigned long addr = addr_hint &
		~(((unsigned long)pages_per_huge_page << PAGE_SHIFT) - 1);

	/* Process target subpage last to keep its cache lines hot */
	might_sleep();
	n = (addr_hint - addr) / PAGE_SIZE;
	if (2 * n <= pages_per_huge_page) {
		/* If target subpage in first half of huge page */
		base = 0;
		l = n;
		/* Process subpages at the end of huge page */
		for (i = pages_per_huge_page - 1; i >= 2 * n; i--) {
			cond_resched();
			process_subpage(addr + i * PAGE_SIZE, i, arg);
		}
	} else {
		/* If target subpage in second half of huge page */
		base = pages_per_huge_page - 2 * (pages_per_huge_page - n);
		l = pages_per_huge_page - n;
		/* Process subpages at the begin of huge page */
		for (i = 0; i < base; i++) {
			cond_resched();
			process_subpage(addr + i * PAGE_SIZE, i, arg);
		}
	}
	/*
	 * Process remaining subpages in left-right-left-right pattern
	 * towards the target subpage
	 */
	for (i = 0; i < l; i++) {
		int left_idx = base + i;
		int right_idx = base + 2 * l - 1 - i;

		cond_resched();
		process_subpage(addr + left_idx * PAGE_SIZE, left_idx, arg);
		cond_resched();
		process_subpage(addr + right_idx * PAGE_SIZE, right_idx, arg);
	}
}

static void clear_gigantic_page(struct page *page,
				unsigned long addr,
				unsigned int pages_per_huge_page)
{
	int i;
	struct page *p = page;

	might_sleep();
	for (i = 0; i < pages_per_huge_page;
	     i++, p = mem_map_next(p, page, i)) {
		cond_resched();
		clear_user_highpage(p, addr + i * PAGE_SIZE);
	}
}

static void clear_subpage(unsigned long addr, int idx, void *arg)
{
	struct page *page = arg;

	clear_user_highpage(page + idx, addr);
}

void clear_huge_page(struct page *page,
		     unsigned long addr_hint, unsigned int pages_per_huge_page)
{
	unsigned long addr = addr_hint &
		~(((unsigned long)pages_per_huge_page << PAGE_SHIFT) - 1);

	if (unlikely(pages_per_huge_page > MAX_ORDER_NR_PAGES)) {
		clear_gigantic_page(page, addr, pages_per_huge_page);
		return;
	}

	process_huge_page(addr_hint, pages_per_huge_page, clear_subpage, page);
}

static void copy_user_gigantic_page(struct page *dst, struct page *src,
				    unsigned long addr,
				    struct vm_area_struct *vma,
				    unsigned int pages_per_huge_page)
{
	int i;
	struct page *dst_base = dst;
	struct page *src_base = src;

	for (i = 0; i < pages_per_huge_page; ) {
		cond_resched();
		copy_user_highpage(dst, src, addr + i*PAGE_SIZE, vma);

		i++;
		dst = mem_map_next(dst, dst_base, i);
		src = mem_map_next(src, src_base, i);
	}
}

struct copy_subpage_arg {
	struct page *dst;
	struct page *src;
	struct vm_area_struct *vma;
};

static void copy_subpage(unsigned long addr, int idx, void *arg)
{
	struct copy_subpage_arg *copy_arg = arg;

	copy_user_highpage(copy_arg->dst + idx, copy_arg->src + idx,
			   addr, copy_arg->vma);
}
/*  */
void copy_user_huge_page(struct page *dst, struct page *src,
			 unsigned long addr_hint, struct vm_area_struct *vma,
			 unsigned int pages_per_huge_page)
{
	unsigned long addr = addr_hint &
		~(((unsigned long)pages_per_huge_page << PAGE_SHIFT) - 1);
	struct copy_subpage_arg arg = {
		.dst = dst,
		.src = src,
		.vma = vma,
	};

	if (unlikely(pages_per_huge_page > MAX_ORDER_NR_PAGES)) {
		copy_user_gigantic_page(dst, src, addr, vma,
					pages_per_huge_page);
		return;
	}

	process_huge_page(addr_hint, pages_per_huge_page, copy_subpage, &arg);
}
/*  */
long copy_huge_page_from_user(struct page *dst_page,
				const void __user *usr_src,
				unsigned int pages_per_huge_page,
				bool allow_pagefault)
{
	void *src = (void *)usr_src;
	void *page_kaddr;
	unsigned long i, rc = 0;
	unsigned long ret_val = pages_per_huge_page * PAGE_SIZE;

	for (i = 0; i < pages_per_huge_page; i++) {
		if (allow_pagefault)
			page_kaddr = kmap(dst_page + i);
		else
			page_kaddr = kmap_atomic(dst_page + i);
		
		/* 从src拷贝到内核虚拟地址 */
		rc = copy_from_user(page_kaddr,
				(const void __user *)(src + i * PAGE_SIZE),
				PAGE_SIZE);

		if (allow_pagefault)
			kunmap(dst_page + i);
		else
			kunmap_atomic(page_kaddr);

		ret_val -= (PAGE_SIZE - rc);
		if (rc)
			break;

		cond_resched();
	}
	return ret_val;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_HUGETLBFS */

#if USE_SPLIT_PTE_PTLOCKS && ALLOC_SPLIT_PTLOCKS

static struct kmem_cache *page_ptl_cachep;

void __init ptlock_cache_init(void)
{
	page_ptl_cachep = kmem_cache_create("page->ptl", sizeof(spinlock_t), 0,
			SLAB_PANIC, NULL);
}

bool ptlock_alloc(struct page *page)
{
	spinlock_t *ptl;

	ptl = kmem_cache_alloc(page_ptl_cachep, GFP_KERNEL);
	if (!ptl)
		return false;
	page->ptl = ptl;
	return true;
}

void ptlock_free(struct page *page)
{
	kmem_cache_free(page_ptl_cachep, page->ptl);
}
#endif

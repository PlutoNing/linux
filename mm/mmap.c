// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/mmap.c
 *
 * Written by obz.
 *
 * Address space accounting code	<alan@lxorguk.ukuu.org.uk>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/shmem_fs.h>
#include <linux/profile.h>
#include <linux/export.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/mmdebug.h>
#include <linux/perf_event.h>
#include <linux/audit.h>
#include <linux/khugepaged.h>
#include <linux/uprobes.h>
#include <linux/notifier.h>
#include <linux/memory.h>
#include <linux/printk.h>
#include <linux/userfaultfd_k.h>
#include <linux/moduleparam.h>
#include <linux/pkeys.h>
#include <linux/oom.h>
#include <linux/sched/mm.h>
#include <linux/ksm.h>

#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mmap.h>

#include "internal.h"

#ifndef arch_mmap_check
#define arch_mmap_check(addr, len, flags)	(0)
#endif

#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
const int mmap_rnd_bits_min = CONFIG_ARCH_MMAP_RND_BITS_MIN;
const int mmap_rnd_bits_max = CONFIG_ARCH_MMAP_RND_BITS_MAX;
int mmap_rnd_bits __read_mostly = CONFIG_ARCH_MMAP_RND_BITS;
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
const int mmap_rnd_compat_bits_min = CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN;
const int mmap_rnd_compat_bits_max = CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX;
int mmap_rnd_compat_bits __read_mostly = CONFIG_ARCH_MMAP_RND_COMPAT_BITS;
#endif

static bool ignore_rlimit_data;
core_param(ignore_rlimit_data, ignore_rlimit_data, bool, 0644);

static void unmap_region(struct mm_struct *mm, struct ma_state *mas,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		struct vm_area_struct *next, unsigned long start,
		unsigned long end, unsigned long tree_end, bool mm_wr_locked);

static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
	return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

/* Update vma->vm_page_prot to reflect vma->vm_flags. */
void vma_set_page_prot(struct vm_area_struct *vma)
{
	unsigned long vm_flags = vma->vm_flags;
	pgprot_t vm_page_prot;

	vm_page_prot = vm_pgprot_modify(vma->vm_page_prot, vm_flags);
	if (vma_wants_writenotify(vma, vm_page_prot)) {
		vm_flags &= ~VM_SHARED;
		vm_page_prot = vm_pgprot_modify(vm_page_prot, vm_flags);
	}
	/* remove_protection_ptes reads vma->vm_page_prot without mmap_lock */
	WRITE_ONCE(vma->vm_page_prot, vm_page_prot);
}

/*
要销毁这个vma了
vma->file->mapping
把vma从mapping的i_mmap中删除
 * Requires inode->i_mapping->i_mmap_rwsem
 */
static void __remove_shared_vm_struct(struct vm_area_struct *vma,
		struct file *file, struct address_space *mapping)
{
	if (vma->vm_flags & VM_SHARED)
		mapping_unmap_writable(mapping);

	flush_dcache_mmap_lock(mapping);
	/* 从tree删除 */
	vma_interval_tree_remove(vma, &mapping->i_mmap);
	flush_dcache_mmap_unlock(mapping);
}

/*
销毁vma的时候
删除file
 * Unlink a file-based vm structure from its interval tree, to hide
 * vma from rmap and vmtruncate before freeing its page tables.
 */
void unlink_file_vma(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;

	if (file) {
		struct address_space *mapping = file->f_mapping;
		i_mmap_lock_write(mapping);
		__remove_shared_vm_struct(vma, file, mapping);
		i_mmap_unlock_write(mapping);
	}
}

/*
退出进程的时候
销毁vma
 * Close a vm structure and free it.
 */
static void remove_vma(struct vm_area_struct *vma, bool unreachable)
{
	might_sleep();
	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);
	if (vma->vm_file)
		fput(vma->vm_file);
	mpol_put(vma_policy(vma));
	if (unreachable)
		__vm_area_free(vma);
	else
		vm_area_free(vma);
}

static inline struct vm_area_struct *vma_prev_limit(struct vma_iterator *vmi,
						    unsigned long min)
{
	return mas_prev(&vmi->mas, min);
}

/*
brk申请内存前检查
 * check_brk_limits() - Use platform specific check of range & verify mlock
 * limits.
 * @addr: The address to check
 * @len: The size of increase.
 *
 * Return: 0 on success.
 */
static int check_brk_limits(unsigned long addr, unsigned long len)
{
	unsigned long mapped_addr;

	mapped_addr = get_unmapped_area(NULL, addr, len, 0, MAP_FIXED);
	if (IS_ERR_VALUE(mapped_addr))
		return mapped_addr;

	return mlock_future_ok(current->mm, current->mm->def_flags, len)
		? 0 : -EAGAIN;
}
static int do_brk_flags(struct vma_iterator *vmi, struct vm_area_struct *brkvma,
		unsigned long addr, unsigned long request, unsigned long flags);
SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	unsigned long newbrk, oldbrk, origbrk;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *brkvma, *next = NULL;
	unsigned long min_brk;
	bool populate = false;
	LIST_HEAD(uf);
	struct vma_iterator vmi;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	origbrk = mm->brk;

#ifdef CONFIG_COMPAT_BRK
	/*
	 * CONFIG_COMPAT_BRK can still be overridden by setting
	 * randomize_va_space to 2, which will still cause mm->start_brk
	 * to be arbitrarily shifted
	 */
	if (current->brk_randomized)
		min_brk = mm->start_brk;
	else
		min_brk = mm->end_data;
#else
	min_brk = mm->start_brk;
#endif
	if (brk < min_brk)
		goto out;

	/*
	 * Check against rlimit here. If this check is done later after the test
	 * of oldbrk with newbrk then it can escape the test and let the data
	 * segment grow beyond its set limit the in case where the limit is
	 * not page aligned -Ram Gupta
	 */
	if (check_data_rlimit(rlimit(RLIMIT_DATA), brk, mm->start_brk,
			      mm->end_data, mm->start_data))
		goto out;

	newbrk = PAGE_ALIGN(brk);
	oldbrk = PAGE_ALIGN(mm->brk);
	if (oldbrk == newbrk) {
		mm->brk = brk;
		goto success;
	}

	/* Always allow shrinking brk. */
	if (brk <= mm->brk) {
		/* Search one past newbrk */
		vma_iter_init(&vmi, mm, newbrk);
		brkvma = vma_find(&vmi, oldbrk);
		if (!brkvma || brkvma->vm_start >= oldbrk)
			goto out; /* mapping intersects with an existing non-brk vma. */
		/*
		 * mm->brk must be protected by write mmap_lock.
		 * do_vma_munmap() will drop the lock on success,  so update it
		 * before calling do_vma_munmap().
		 */
		mm->brk = brk;
		if (do_vma_munmap(&vmi, brkvma, newbrk, oldbrk, &uf, true))
			goto out;

		goto success_unlocked;
	}

	if (check_brk_limits(oldbrk, newbrk - oldbrk))
		goto out;

	/*
	 * Only check if the next VMA is within the stack_guard_gap of the
	 * expansion area
	 */
	vma_iter_init(&vmi, mm, oldbrk);
	next = vma_find(&vmi, newbrk + PAGE_SIZE + stack_guard_gap);
	if (next && newbrk + PAGE_SIZE > vm_start_gap(next))
		goto out;

	brkvma = vma_prev_limit(&vmi, mm->start_brk);
	/* Ok, looks good - let it rip. */
	if (do_brk_flags(&vmi, brkvma, oldbrk, newbrk - oldbrk, 0) < 0)
		goto out;

	mm->brk = brk;
	if (mm->def_flags & VM_LOCKED)
		populate = true;

success:
	mmap_write_unlock(mm);
success_unlocked:
	userfaultfd_unmap_complete(mm, &uf);
	if (populate)
		mm_populate(oldbrk, newbrk - oldbrk);
	return brk;

out:
	mm->brk = origbrk;
	mmap_write_unlock(mm);
	return origbrk;
}

#if defined(CONFIG_DEBUG_VM_MAPLE_TREE)
static void validate_mm(struct mm_struct *mm)
{
	int bug = 0;
	int i = 0;
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);

	mt_validate(&mm->mm_mt);
	for_each_vma(vmi, vma) {
#ifdef CONFIG_DEBUG_VM_RB
		struct anon_vma *anon_vma = vma->anon_vma;
		struct anon_vma_chain *avc;
#endif
		unsigned long vmi_start, vmi_end;
		bool warn = 0;

		vmi_start = vma_iter_addr(&vmi);
		vmi_end = vma_iter_end(&vmi);
		if (VM_WARN_ON_ONCE_MM(vma->vm_end != vmi_end, mm))
			warn = 1;

		if (VM_WARN_ON_ONCE_MM(vma->vm_start != vmi_start, mm))
			warn = 1;

		if (warn) {
			pr_emerg("issue in %s\n", current->comm);
			dump_stack();
			dump_vma(vma);
			pr_emerg("tree range: %px start %lx end %lx\n", vma,
				 vmi_start, vmi_end - 1);
			vma_iter_dump_tree(&vmi);
		}

#ifdef CONFIG_DEBUG_VM_RB
		if (anon_vma) {
			anon_vma_lock_read(anon_vma);
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				anon_vma_interval_tree_verify(avc);
			anon_vma_unlock_read(anon_vma);
		}
#endif
		i++;
	}
	if (i != mm->map_count) {
		pr_emerg("map_count %d vma iterator %d\n", mm->map_count, i);
		bug = 1;
	}
	VM_BUG_ON_MM(bug, mm);
}

#else /* !CONFIG_DEBUG_VM_MAPLE_TREE */
#define validate_mm(mm) do { } while (0)
#endif /* CONFIG_DEBUG_VM_MAPLE_TREE */

/*
 * vma has some anon_vma assigned, and is already inserted on that
 * anon_vma's interval trees.
 * vma已经有了一些anon_vma, 并且已经插入到了anon_vma的interval tree中
 * Before updating the vma's vm_start / vm_end / vm_pgoff fields, the
 * vma must be removed from the anon_vma's interval trees using
 * anon_vma_interval_tree_pre_update_vma().
 * 在更新vma的vm_start / vm_end / vm_pgoff字段之前, 必须使用
 * anon_vma_interval_tree_pre_update_vma()从anon_vma的interval tree中删除vma。
 * After the update, the vma will be reinserted using
 * anon_vma_interval_tree_post_update_vma().
 * 更新后, vma将使用anon_vma_interval_tree_post_update_vma()重新插入。
 * The entire update must be protected by exclusive mmap_lock and by
 * the root anon_vma's mutex.
 * 整个更新必须由独占的mmap_lock和根anon_vma的互斥锁保护。
 */
static inline void
anon_vma_interval_tree_pre_update_vma(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;

	list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
		anon_vma_interval_tree_remove(avc, &avc->anon_vma->rb_root);
}

static inline void
anon_vma_interval_tree_post_update_vma(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;

	list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
		anon_vma_interval_tree_insert(avc, &avc->anon_vma->rb_root);
}

// 计算mm的vma页面数量
static unsigned long count_vma_pages_range(struct mm_struct *mm,
		unsigned long addr, unsigned long end)
{
	VMA_ITERATOR(vmi, mm, addr);
	struct vm_area_struct *vma;
	unsigned long nr_pages = 0;

	for_each_vma_range(vmi, vma, end) {
		unsigned long vm_start = max(addr, vma->vm_start);
		unsigned long vm_end = min(end, vma->vm_end);

		nr_pages += PHYS_PFN(vm_end - vm_start);
	}

	return nr_pages;
}

// vma映射了file, mapping属于file
// 这里把vma插入mapping的i_mmap
static void __vma_link_file(struct vm_area_struct *vma,
			    struct address_space *mapping)
{
	if (vma->vm_flags & VM_SHARED)
		mapping_allow_writable(mapping);

	flush_dcache_mmap_lock(mapping);
	vma_interval_tree_insert(vma, &mapping->i_mmap);
	flush_dcache_mmap_unlock(mapping);
}

//把vma插入mm中
static int vma_link(struct mm_struct *mm, struct vm_area_struct *vma)
{
	// 一个对mm的vma的迭代器
	VMA_ITERATOR(vmi, mm, 0);
	struct address_space *mapping = NULL;

	vma_iter_config(&vmi, vma->vm_start, vma->vm_end);
	if (vma_iter_prealloc(&vmi, vma))
		return -ENOMEM;
	// 加锁
	vma_start_write(vma);

	vma_iter_store(&vmi, vma);

	// 如果vma有file, 那么把vma插入到file的mapping的i_mmap中
	if (vma->vm_file) {
		mapping = vma->vm_file->f_mapping;
		i_mmap_lock_write(mapping);
		__vma_link_file(vma, mapping);
		i_mmap_unlock_write(mapping);
	}

	mm->map_count++;
	validate_mm(mm);
	return 0;
}

/*
 * init_multi_vma_prep() - Initializer for struct vma_prepare
 初始化vma_prepare
 * @vp: The vma_prepare struct
 * @vma: The vma that will be altered once locked
 * @next: The next vma if it is to be adjusted
 * @remove: The first vma to be removed
 * @remove2: The second vma to be removed
 */
static inline void init_multi_vma_prep(struct vma_prepare *vp,
		struct vm_area_struct *vma, struct vm_area_struct *next,
		struct vm_area_struct *remove, struct vm_area_struct *remove2)
{
	memset(vp, 0, sizeof(struct vma_prepare));
	vp->vma = vma;
	vp->anon_vma = vma->anon_vma;
	vp->remove = remove;
	vp->remove2 = remove2;
	vp->adj_next = next;
	if (!vp->anon_vma && next)
		vp->anon_vma = next->anon_vma;

	vp->file = vma->vm_file;
	if (vp->file)
		vp->mapping = vma->vm_file->f_mapping;

}

/*
 * init_vma_prep() - Initializer wrapper for vma_prepare struct
 * @vp: The vma_prepare struct
 * @vma: The vma that will be altered once locked
 */
static inline void init_vma_prep(struct vma_prepare *vp,
				 struct vm_area_struct *vma)
{
	init_multi_vma_prep(vp, vma, NULL, NULL, NULL);
}


/*
 * vma_prepare() - Helper function for handling locking VMAs prior to altering
   在真正变动之前预先加锁
 * @vp: The initialized vma_prepare struct
 */
static inline void vma_prepare(struct vma_prepare *vp)
{
	if (vp->file) {
		uprobe_munmap(vp->vma, vp->vma->vm_start, vp->vma->vm_end);

		if (vp->adj_next)
			uprobe_munmap(vp->adj_next, vp->adj_next->vm_start,
				      vp->adj_next->vm_end);

		i_mmap_lock_write(vp->mapping);
		if (vp->insert && vp->insert->vm_file) {
			/*
			 * Put into interval tree now, so instantiated pages
			 * are visible to arm/parisc __flush_dcache_page
			 * throughout; but we cannot insert into address
			 * space until vma start or end is updated.
			 */
			__vma_link_file(vp->insert,
					vp->insert->vm_file->f_mapping);
		}
	}

	if (vp->anon_vma) {
		anon_vma_lock_write(vp->anon_vma);
		anon_vma_interval_tree_pre_update_vma(vp->vma);
		if (vp->adj_next)
			anon_vma_interval_tree_pre_update_vma(vp->adj_next);
	}

	if (vp->file) {
		flush_dcache_mmap_lock(vp->mapping);
		vma_interval_tree_remove(vp->vma, &vp->mapping->i_mmap);
		if (vp->adj_next)
			vma_interval_tree_remove(vp->adj_next,
						 &vp->mapping->i_mmap);
	}

}

/*
 * vma_complete- Helper function for handling the unlocking after altering VMAs,
 * or for inserting a VMA.
 * 扩展完毕后解锁
 * @vp: The vma_prepare struct
 * @vmi: The vma iterator
 * @mm: The mm_struct
 */
static inline void vma_complete(struct vma_prepare *vp,
				struct vma_iterator *vmi, struct mm_struct *mm)
{
	if (vp->file) {
		if (vp->adj_next)
			vma_interval_tree_insert(vp->adj_next,
						 &vp->mapping->i_mmap);
		vma_interval_tree_insert(vp->vma, &vp->mapping->i_mmap);
		flush_dcache_mmap_unlock(vp->mapping);
	}

	if (vp->remove && vp->file) {
		__remove_shared_vm_struct(vp->remove, vp->file, vp->mapping);
		if (vp->remove2)
			__remove_shared_vm_struct(vp->remove2, vp->file,
						  vp->mapping);
	} else if (vp->insert) {
		/*
		 * split_vma has split insert from vma, and needs
		 * us to insert it before dropping the locks
		 * (it may either follow vma or precede it).
		 */
		vma_iter_store(vmi, vp->insert);
		mm->map_count++;
	}

	if (vp->anon_vma) {
		anon_vma_interval_tree_post_update_vma(vp->vma);
		if (vp->adj_next)
			anon_vma_interval_tree_post_update_vma(vp->adj_next);
		anon_vma_unlock_write(vp->anon_vma);
	}

	if (vp->file) {
		i_mmap_unlock_write(vp->mapping);
		uprobe_mmap(vp->vma);

		if (vp->adj_next)
			uprobe_mmap(vp->adj_next);
	}

	if (vp->remove) {
again:
		vma_mark_detached(vp->remove, true);
		if (vp->file) {
			uprobe_munmap(vp->remove, vp->remove->vm_start,
				      vp->remove->vm_end);
			fput(vp->file);
		}
		if (vp->remove->anon_vma)
			anon_vma_merge(vp->vma, vp->remove);
		mm->map_count--;
		mpol_put(vma_policy(vp->remove));
		if (!vp->remove2)
			WARN_ON_ONCE(vp->vma->vm_end < vp->remove->vm_end);
		vm_area_free(vp->remove);

		/*
		 * In mprotect's case 6 (see comments on vma_merge),
		 * we are removing both mid and next vmas
		 */
		if (vp->remove2) {
			vp->remove = vp->remove2;
			vp->remove2 = NULL;
			goto again;
		}
	}
	if (vp->insert && vp->file)
		uprobe_mmap(vp->insert);
	validate_mm(mm);
}

/*
 * dup_anon_vma() - Helper function to duplicate anon_vma
 为啥要dup这个av? 理解的一种情况是,扩展vma的情况, 就是扩展dst要包住src了,所以需要复制和吸纳av的rmap信息
 ====================================================
 一种调用情况是,扩展dst这个vma, src是后面的vma, dst要扩展到刚好包住src
 * @dst: The destination VMA
 * @src: The source VMA
 * @dup: Pointer to the destination VMA when successful.
 *
 * Returns: 0 on success.
 */
static inline int dup_anon_vma(struct vm_area_struct *dst,
		struct vm_area_struct *src, struct vm_area_struct **dup)
{
	/*
	 * Easily overlooked: when mprotect shifts the boundary, make sure the
	 * expanding vma has anon_vma set if the shrinking vma had, to cover any
	 * anon pages imported.
	 */
	if (src->anon_vma && !dst->anon_vma) {
		int ret;

		vma_assert_write_locked(dst);
		dst->anon_vma = src->anon_vma; // 就是指针赋值?
		ret = anon_vma_clone(dst, src);
		if (ret)
			return ret;

		*dup = dst;
	}

	return 0;
}

/*
 * vma_expand - Expand an existing VMA
 * 扩展一个现存的vma
 * @vmi: The vma iterator
 * @vma: The vma to expand
 * @start: The start of the vma,这里是要扩展到的地址
 * @end: The exclusive end of the vma,这里是要扩展到的地址
 * @pgoff: The page offset of vma
 * @next: The current of next vma.
 *
 * Expand @vma to @start and @end.  Can expand off the start and end.  Will
 * expand over @next if it's different from @vma and @end == @next->vm_end.
 * Checking if the @vma can expand and merge with @next needs to be handled by
 * the caller.
 * 扩展vma到start和end。可以扩展到start和end。如果end==next->vm_end,则可以扩展到next上。
 * 检查vma是否可以扩展并与next合并需要由调用者处理。
 * Returns: 0 on success
 */
int vma_expand(struct vma_iterator *vmi, struct vm_area_struct *vma,
	       unsigned long start, unsigned long end, pgoff_t pgoff,
	       struct vm_area_struct *next)
{
	struct vm_area_struct *anon_dup = NULL;
	bool remove_next = false;
	struct vma_prepare vp;

	vma_start_write(vma);
	if (next && (vma != next) && (end == next->vm_end)) { //mmap的情况有可能是这样
		// 如果prev也可以merge的情况
		// start          addr--------addr+len            end  
		// prev_start---prev_end      next_start-----next_end
		// vma_start                  next这个vma      
		// vma这个vma
		int ret;

		remove_next = true;
		vma_start_write(next); // 对next也加写锁
		// 一种情况是vma要往后扩展包住next了,这里把av信息拷贝过来
		ret = dup_anon_vma(vma, next, &anon_dup);
		if (ret) // 出错了
			return ret;
	}
	// vp有啥用?
	init_multi_vma_prep(&vp, vma, NULL, remove_next ? next : NULL, NULL);
	/* Not merging but overwriting any part of next is not handled. */
	VM_WARN_ON(next && !vp.remove &&
		  next != vma && end > next->vm_start);
	/* Only handles expanding */
	VM_WARN_ON(vma->vm_start < start || vma->vm_end > end);

	/* Note: vma iterator must be pointing to 'start' */
	vma_iter_config(vmi, start, end);
	if (vma_iter_prealloc(vmi, vma))
		goto nomem;

	vma_prepare(&vp);  //进行提前加锁
	vma_adjust_trans_huge(vma, start, end, 0);
	// 难道扩展就是直接改变属性吗?
	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_pgoff = pgoff;
	vma_iter_store(vmi, vma);

	vma_complete(&vp, vmi, vma->vm_mm);
	return 0;

nomem:
	if (anon_dup)
		unlink_anon_vmas(anon_dup);
	return -ENOMEM;
}

/*
 * vma_shrink() - Reduce an existing VMAs memory area
 * @vmi: The vma iterator
 * @vma: The VMA to modify
 * @start: The new start
 * @end: The new end
 *
 * Returns: 0 on success, -ENOMEM otherwise
 */
int vma_shrink(struct vma_iterator *vmi, struct vm_area_struct *vma,
	       unsigned long start, unsigned long end, pgoff_t pgoff)
{
	struct vma_prepare vp;

	WARN_ON((vma->vm_start != start) && (vma->vm_end != end));

	if (vma->vm_start < start)
		vma_iter_config(vmi, vma->vm_start, start);
	else
		vma_iter_config(vmi, end, vma->vm_end);

	if (vma_iter_prealloc(vmi, NULL))
		return -ENOMEM;

	vma_start_write(vma);

	init_vma_prep(&vp, vma);
	vma_prepare(&vp);
	vma_adjust_trans_huge(vma, start, end, 0);

	vma_iter_clear(vmi);
	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_pgoff = pgoff;
	vma_complete(&vp, vmi, vma->vm_mm);
	return 0;
}

/*
 * If the vma has a ->close operation then the driver probably needs to release
 * per-vma resources, so we don't attempt to merge those if the caller indicates
 * the current vma may be removed as part of the merge.
 */
static inline bool is_mergeable_vma(struct vm_area_struct *vma,
		struct file *file, unsigned long vm_flags,
		struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
		struct anon_vma_name *anon_name, bool may_remove_vma)
{
	/*
	 * VM_SOFTDIRTY should not prevent from VMA merging, if we
	 * match the flags but dirty bit -- the caller should mark
	 * merged VMA as dirty. If dirty bit won't be excluded from
	 * comparison, we increase pressure on the memory system forcing
	 * the kernel to generate new VMAs when old one could be
	 * extended instead.
	 */
	if ((vma->vm_flags ^ vm_flags) & ~VM_SOFTDIRTY)
		return false;
	if (vma->vm_file != file)
		return false;
	if (may_remove_vma && vma->vm_ops && vma->vm_ops->close)
		return false;
	if (!is_mergeable_vm_userfaultfd_ctx(vma, vm_userfaultfd_ctx))
		return false;
	if (!anon_vma_name_eq(anon_vma_name(vma), anon_name))
		return false;
	return true;
}

static inline bool is_mergeable_anon_vma(struct anon_vma *anon_vma1,
		 struct anon_vma *anon_vma2, struct vm_area_struct *vma)
{
	/*
	 * The list_is_singular() test is to avoid merging VMA cloned from
	 * parents. This can improve scalability caused by anon_vma lock.
	 */
	if ((!anon_vma1 || !anon_vma2) && (!vma ||
		list_is_singular(&vma->anon_vma_chain)))
		return true;
	return anon_vma1 == anon_vma2;
}

/*
是否可以往前合并这个vma
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * in front of (at a lower virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We don't check here for the merged mmap wrapping around the end of pagecache
 * indices (16TB on ia32) because do_mmap() does not permit mmap's which
 * wrap, nor mmaps which cover the final page at index -1UL.
 *
 * We assume the vma may be removed as part of the merge.
 */
static bool
can_vma_merge_before(struct vm_area_struct *vma, unsigned long vm_flags,
		struct anon_vma *anon_vma, struct file *file,
		pgoff_t vm_pgoff, struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
		struct anon_vma_name *anon_name)
{
	if (is_mergeable_vma(vma, file, vm_flags, vm_userfaultfd_ctx, anon_name, true) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma, vma)) {
		if (vma->vm_pgoff == vm_pgoff)
			return true;
	}
	return false;
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * beyond (at a higher virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We assume that vma is not removed as part of the merge.
 */
static bool
can_vma_merge_after(struct vm_area_struct *vma, unsigned long vm_flags,
		struct anon_vma *anon_vma, struct file *file,
		pgoff_t vm_pgoff, struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
		struct anon_vma_name *anon_name)
{
	if (is_mergeable_vma(vma, file, vm_flags, vm_userfaultfd_ctx, anon_name, false) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma, vma)) {
		pgoff_t vm_pglen;
		vm_pglen = vma_pages(vma);
		if (vma->vm_pgoff + vm_pglen == vm_pgoff)
			return true;
	}
	return false;
}

/*
 * Given a mapping request (addr,end,vm_flags,file,pgoff,anon_name),
 * figure out whether that can be merged with its predecessor or its
 * successor.  Or both (it neatly fills a hole).
 *
 * In most cases - when called for mmap, brk or mremap - [addr,end) is
 * certain not to be mapped by the time vma_merge is called; but when
 * called for mprotect, it is certain to be already mapped (either at
 * an offset within prev, or at the start of next), and the flags of
 * this area are about to be changed to vm_flags - and the no-change
 * case has already been eliminated.
 *
 * The following mprotect cases have to be considered, where **** is
 * the area passed down from mprotect_fixup, never extending beyond one
 * vma, PPPP is the previous vma, CCCC is a concurrent vma that starts
 * at the same address as **** and is of the same or larger span, and
 * NNNN the next vma after ****:
 *
 *     ****             ****                   ****
 *    PPPPPPNNNNNN    PPPPPPNNNNNN       PPPPPPCCCCCC
 *    cannot merge    might become       might become
 *                    PPNNNNNNNNNN       PPPPPPPPPPCC
 *    mmap, brk or    case 4 below       case 5 below
 *    mremap move:
 *                        ****               ****
 *                    PPPP    NNNN       PPPPCCCCNNNN
 *                    might become       might become
 *                    PPPPPPPPPPPP 1 or  PPPPPPPPPPPP 6 or
 *                    PPPPPPPPNNNN 2 or  PPPPPPPPNNNN 7 or
 *                    PPPPNNNNNNNN 3     PPPPNNNNNNNN 8
 *
 * It is important for case 8 that the vma CCCC overlapping the
 * region **** is never going to extended over NNNN. Instead NNNN must
 * be extended in region **** and CCCC must be removed. This way in
 * all cases where vma_merge succeeds, the moment vma_merge drops the
 * rmap_locks, the properties of the merged vma will be already
 * correct for the whole merged range. Some of those properties like
 * vm_page_prot/vm_flags may be accessed by rmap_walks and they must
 * be correct for the whole merged range immediately after the
 * rmap_locks are released. Otherwise if NNNN would be removed and
 * CCCC would be extended over the NNNN range, remove_migration_ptes
 * or other rmap walkers (if working on addresses beyond the "end"
 * parameter) may establish ptes with the wrong permissions of CCCC
 * instead of the right permissions of NNNN.
 *
 * In the code below:
 * PPPP is represented by *prev
 * CCCC is represented by *curr or not represented at all (NULL)
 * NNNN is represented by *next or not represented at all (NULL)
 * **** is not represented - it will be merged and the vma containing the
 *      area is returned, or the function will return NULL
 =================================
prev是范围的前一个vma
 remap到addr end的范围
 */
struct vm_area_struct *vma_merge(struct vma_iterator *vmi, struct mm_struct *mm,
			struct vm_area_struct *prev, unsigned long addr,
			unsigned long end, unsigned long vm_flags,
			struct anon_vma *anon_vma, struct file *file,
			pgoff_t pgoff, struct mempolicy *policy,
			struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
			struct anon_vma_name *anon_name)
{
	struct vm_area_struct *curr, *next, *res;
	struct vm_area_struct *vma, *adjust, *remove, *remove2;
	struct vm_area_struct *anon_dup = NULL;
	struct vma_prepare vp;
	pgoff_t vma_pgoff;
	int err = 0;
	bool merge_prev = false;
	bool merge_next = false;
	bool vma_expanded = false;
	unsigned long vma_start = addr;
	unsigned long vma_end = end;
	pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
	long adj_start = 0;

	/*
	 * We later require that vma->vm_flags == vm_flags,
	 * so this tests vma->vm_flags & VM_SPECIAL, too.
	 */
	if (vm_flags & VM_SPECIAL)
		return NULL;

	/* Does the input range span an existing VMA? (cases 5 - 8)
	找到prev的尾巴到本次映射范围结束地址交叉的第一个vma
	*/
	curr = find_vma_intersection(mm, prev ? prev->vm_end : 0, end);
/* 
            |--------|
	|-----|		

*/
	if (!curr ||			/*如果没有[prev_end, new_end ]交叉的vma， cases 1 - 4 */
	    end == curr->vm_end)	/*有交叉，但是交叉的vma与本次映射范围的屁股是对齐的
		 cases 6 - 8, adjacent VMA */
		next = vma_lookup(mm, end);/* 如果是这两种情况， 就找到new_end所在的vma */
	else
		next = NULL;		/*有交叉的vma，并且屁股也不是对齐的 case 5 */

	if (prev) {/* 如果存在prev， 看看能不能合并 */
		vma_start = prev->vm_start;
		vma_pgoff = prev->vm_pgoff;

		/* Can we merge the predecessor? */
		if (addr == prev->vm_end /* 地址范围对齐 */
			 && mpol_equal(vma_policy(prev), policy)
		    && can_vma_merge_after(prev, vm_flags, anon_vma, file,
					   pgoff, vm_userfaultfd_ctx, anon_name)) {
			merge_prev = true;/* 决定与prev合并 */
			vma_prev(vmi);
		}
	}

	/* Can we merge the successor? 
	是否与下一个合并
	*/
	if (next && mpol_equal(policy, vma_policy(next)) &&
	    can_vma_merge_before(next, vm_flags, anon_vma, file, pgoff+pglen,
				 vm_userfaultfd_ctx, anon_name)) {
		merge_next = true;
	}

	/* Verify some invariant that must be enforced by the caller. */
	VM_WARN_ON(prev && addr <= prev->vm_start);
	VM_WARN_ON(curr && (addr != curr->vm_start || end > curr->vm_end));
	VM_WARN_ON(addr >= end);

	if (!merge_prev && !merge_next)
		return NULL; /* Not mergeable. */

	if (merge_prev)
		vma_start_write(prev);

	res = vma = prev;
	remove = remove2 = adjust = NULL;

	/* Can we merge both the predecessor and the successor? */
	if (merge_prev && merge_next &&
	    is_mergeable_anon_vma(prev->anon_vma, next->anon_vma, NULL)) {
		vma_start_write(next);
		remove = next;				/* case 1 */
		vma_end = next->vm_end;
		err = dup_anon_vma(prev, next, &anon_dup);
		if (curr) {				/* case 6 */
			vma_start_write(curr);
			remove = curr;
			remove2 = next;
			if (!next->anon_vma)
				err = dup_anon_vma(prev, curr, &anon_dup);
		}
	} else if (merge_prev) {			/* case 2 */
		if (curr) {
			vma_start_write(curr);
			err = dup_anon_vma(prev, curr, &anon_dup);
			if (end == curr->vm_end) {	/* case 7 */
				remove = curr;
			} else {			/* case 5 */
				adjust = curr;
				adj_start = (end - curr->vm_start);
			}
		}
	} else { /* merge_next */
		vma_start_write(next);
		res = next;
		if (prev && addr < prev->vm_end) {	/* case 4 */
			vma_start_write(prev);
			vma_end = addr;
			adjust = next;
			adj_start = -(prev->vm_end - addr);
			err = dup_anon_vma(next, prev, &anon_dup);
		} else {
			/*
			 * Note that cases 3 and 8 are the ONLY ones where prev
			 * is permitted to be (but is not necessarily) NULL.
			 */
			vma = next;			/* case 3 */
			vma_start = addr;
			vma_end = next->vm_end;
			vma_pgoff = next->vm_pgoff - pglen;
			if (curr) {			/* case 8 */
				vma_pgoff = curr->vm_pgoff;
				vma_start_write(curr);
				remove = curr;
				err = dup_anon_vma(next, curr, &anon_dup);
			}
		}
	}

	/* Error in anon_vma clone. */
	if (err)
		goto anon_vma_fail;

	if (vma_start < vma->vm_start || vma_end > vma->vm_end)
		vma_expanded = true;

	if (vma_expanded) {
		vma_iter_config(vmi, vma_start, vma_end);
	} else {
		vma_iter_config(vmi, adjust->vm_start + adj_start,
				adjust->vm_end);
	}

	if (vma_iter_prealloc(vmi, vma))
		goto prealloc_fail;

	init_multi_vma_prep(&vp, vma, adjust, remove, remove2);
	VM_WARN_ON(vp.anon_vma && adjust && adjust->anon_vma &&
		   vp.anon_vma != adjust->anon_vma);

	vma_prepare(&vp);
	vma_adjust_trans_huge(vma, vma_start, vma_end, adj_start);

	vma->vm_start = vma_start;
	vma->vm_end = vma_end;
	vma->vm_pgoff = vma_pgoff;

	if (vma_expanded)
		vma_iter_store(vmi, vma);

	if (adj_start) {
		adjust->vm_start += adj_start;
		adjust->vm_pgoff += adj_start >> PAGE_SHIFT;
		if (adj_start < 0) {
			WARN_ON(vma_expanded);
			vma_iter_store(vmi, next);
		}
	}

	vma_complete(&vp, vmi, mm);
	khugepaged_enter_vma(res, vm_flags);
	return res;

prealloc_fail:
	if (anon_dup)
		unlink_anon_vmas(anon_dup);

anon_vma_fail:
	vma_iter_set(vmi, addr);
	vma_iter_load(vmi);
	return NULL;
}

/*
 * Rough compatibility check to quickly see if it's even worth looking
 * at sharing an anon_vma.
 *
 * They need to have the same vm_file, and the flags can only differ
 * in things that mprotect may change.
 *
 * NOTE! The fact that we share an anon_vma doesn't _have_ to mean that
 * we can merge the two vma's. For example, we refuse to merge a vma if
 * there is a vm_ops->close() function, because that indicates that the
 * driver is doing some kind of reference counting. But that doesn't
 * really matter for the anon_vma sharing case.
 */
static int anon_vma_compatible(struct vm_area_struct *a, struct vm_area_struct *b)
{
	return a->vm_end == b->vm_start &&
		mpol_equal(vma_policy(a), vma_policy(b)) &&
		a->vm_file == b->vm_file &&
		!((a->vm_flags ^ b->vm_flags) & ~(VM_ACCESS_FLAGS | VM_SOFTDIRTY)) &&
		b->vm_pgoff == a->vm_pgoff + ((b->vm_start - a->vm_start) >> PAGE_SHIFT);
}

/*
 * Do some basic sanity checking to see if we can re-use the anon_vma
 * from 'old'. The 'a'/'b' vma's are in VM order - one of them will be
 * the same as 'old', the other will be the new one that is trying
 * to share the anon_vma.
 *
 * NOTE! This runs with mmap_lock held for reading, so it is possible that
 * the anon_vma of 'old' is concurrently in the process of being set up
 * by another page fault trying to merge _that_. But that's ok: if it
 * is being set up, that automatically means that it will be a singleton
 * acceptable for merging, so we can do all of this optimistically. But
 * we do that READ_ONCE() to make sure that we never re-load the pointer.
 *
 * IOW: that the "list_is_singular()" test on the anon_vma_chain only
 * matters for the 'stable anon_vma' case (ie the thing we want to avoid
 * is to return an anon_vma that is "complex" due to having gone through
 * a fork).
 *
 * We also make sure that the two vma's are compatible (adjacent,
 * and with the same memory policies). That's all stable, even with just
 * a read lock on the mmap_lock.
 */
static struct anon_vma *reusable_anon_vma(struct vm_area_struct *old, struct vm_area_struct *a, struct vm_area_struct *b)
{
	if (anon_vma_compatible(a, b)) {
		struct anon_vma *anon_vma = READ_ONCE(old->anon_vma);

		if (anon_vma && list_is_singular(&old->anon_vma_chain))
			return anon_vma;
	}
	return NULL;
}

/*
 * find_mergeable_anon_vma is used by anon_vma_prepare, to check
 * neighbouring vmas for a suitable anon_vma, before it goes off
 * to allocate a new anon_vma.  It checks because a repetitive
 * sequence of mprotects and faults may otherwise lead to distinct
 * anon_vmas being allocated, preventing vma merge in subsequent
 * mprotect.
   被用于anon_vma_prepare，用于检查相邻的vma是否有合适的anon_vma，
   在分配一个新的anon_vma之前。它检查是因为重复的mprotect和fault
   可能会导致分配不同的anon_vma，从而阻止后续的mprotect中的vma合并。

 */
struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *vma)
{
	MA_STATE(mas, &vma->vm_mm->mm_mt, vma->vm_end, vma->vm_end);
	/*
	struct ma_state name = {					\
		.tree = mt,						\
		.index = first,						\
		.last = end,						\
		.node = MAS_START,					\
		.min = 0,						\
		.max = ULONG_MAX,					\
		.alloc = NULL,						\
		.mas_flags = 0,						\
	}

	
	 */
	struct anon_vma *anon_vma = NULL;
	struct vm_area_struct *prev, *next;

	/* Try next first. */
	next = mas_walk(&mas);
	if (next) {
		anon_vma = reusable_anon_vma(next, vma, next);
		if (anon_vma)
			return anon_vma;
	}

	prev = mas_prev(&mas, 0);
	VM_BUG_ON_VMA(prev != vma, vma);
	prev = mas_prev(&mas, 0);
	/* Try prev next. */
	if (prev)
		anon_vma = reusable_anon_vma(prev, prev, vma);

	/*
	 * We might reach here with anon_vma == NULL if we can't find
	 * any reusable anon_vma.
	 * There's no absolute need to look only at touching neighbours:
	 * we could search further afield for "compatible" anon_vmas.
	 * But it would probably just be a waste of time searching,
	 * or lead to too many vmas hanging off the same anon_vma.
	 * We're trying to allow mprotect remerging later on,
	 * not trying to minimize memory used for anon_vmas.
	 */
	return anon_vma;
}

/*
 * If a hint addr is less than mmap_min_addr change hint to be as
 * low as possible but still greater than mmap_min_addr
 */
static inline unsigned long round_hint_to_min(unsigned long hint)
{
	hint &= PAGE_MASK;
	if (((void *)hint != NULL) &&
	    (hint < mmap_min_addr))
		return PAGE_ALIGN(mmap_min_addr);
	return hint;
}

bool mlock_future_ok(struct mm_struct *mm, unsigned long flags,
			unsigned long bytes)
{
	unsigned long locked_pages, limit_pages;

	if (!(flags & VM_LOCKED) || capable(CAP_IPC_LOCK))
		return true;

	locked_pages = bytes >> PAGE_SHIFT;
	locked_pages += mm->locked_vm;

	limit_pages = rlimit(RLIMIT_MEMLOCK);
	limit_pages >>= PAGE_SHIFT;

	return locked_pages <= limit_pages;
}

// 一个文件的mmap最大大小
static inline u64 file_mmap_size_max(struct file *file, struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		return MAX_LFS_FILESIZE;

	if (S_ISBLK(inode->i_mode))
		return MAX_LFS_FILESIZE;

	if (S_ISSOCK(inode->i_mode))
		return MAX_LFS_FILESIZE;

	/* Special "we do even unsigned file positions" case */
	if (file->f_mode & FMODE_UNSIGNED_OFFSET)
		return 0;

	/* Yes, random drivers might want more. But I'm tired of buggy drivers */
	return ULONG_MAX;
}

// 检查mmap的大小是否合法
static inline bool file_mmap_ok(struct file *file, struct inode *inode,
				unsigned long pgoff, unsigned long len)
{
	u64 maxsize = file_mmap_size_max(file, inode);

	if (maxsize && len > maxsize)
		return false;
	maxsize -= len;
	if (pgoff > maxsize >> PAGE_SHIFT)
		return false;
	return true;
}

/*
执行mmap系统调用
 * The caller must write-lock current->mm->mmap_lock.
 */
unsigned long do_mmap(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vm_flags_t vm_flags,
			unsigned long pgoff, unsigned long *populate,
			struct list_head *uf)
{
	struct mm_struct *mm = current->mm;
	int pkey = 0;

	*populate = 0;

	if (!len)
		return -EINVAL;

	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC?
	 *
	 * (the exception is when the underlying filesystem is noexec
	 *  mounted, in which case we dont add PROT_EXEC.)
	 */
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && path_noexec(&file->f_path)))
			prot |= PROT_EXEC;

	/* force arch specific MAP_FIXED handling in get_unmapped_area
	这里在get_unmapped_area中强制了arch特定的MAP_FIXED处理
	 */
	if (flags & MAP_FIXED_NOREPLACE)
		flags |= MAP_FIXED;

	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	/* Too many mappings? */
	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 获取要映射到的地址。我们验证（或选择）它，并确保它表示地址空间的有效部分。
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	if (flags & MAP_FIXED_NOREPLACE) {
		if (find_vma_intersection(mm, addr, addr + len))
			return -EEXIST; // 如果要求不能交叉, 但是找到的地址其实是有交叉的?,返回?
	}

	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(mm);
		if (pkey < 0)
			pkey = 0;
	}

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags |= calc_vm_prot_bits(prot, pkey) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	if (flags & MAP_LOCKED)
		if (!can_do_mlock())
			return -EPERM;

	if (!mlock_future_ok(mm, vm_flags, len))
		return -EAGAIN;

	if (file) { // 说明是有文件的mmap?
		struct inode *inode = file_inode(file);
		unsigned long flags_mask;

		if (!file_mmap_ok(file, inode, pgoff, len))
			return -EOVERFLOW;

		flags_mask = LEGACY_MAP_MASK | file->f_op->mmap_supported_flags;

		switch (flags & MAP_TYPE) {
		case MAP_SHARED:// 共享的文件映射
			/*
			 * Force use of MAP_SHARED_VALIDATE with non-legacy
			 * flags. E.g. MAP_SYNC is dangerous to use with
			 * MAP_SHARED as you don't know which consistency model
			 * you will get. We silently ignore unsupported flags
			 * with MAP_SHARED to preserve backward compatibility.
			 */
			flags &= LEGACY_MAP_MASK;
			fallthrough;
		case MAP_SHARED_VALIDATE:
			if (flags & ~flags_mask)
				return -EOPNOTSUPP;
			if (prot & PROT_WRITE) {
				if (!(file->f_mode & FMODE_WRITE))
					return -EACCES;
				if (IS_SWAPFILE(file->f_mapping->host))
					return -ETXTBSY;
			}

			/*
			 * Make sure we don't allow writing to an append-only
			 * file..
			 */
			if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);
			fallthrough;
		case MAP_PRIVATE:// 私有文件mmap
			if (!(file->f_mode & FMODE_READ))
				return -EACCES;
			if (path_noexec(&file->f_path)) { // 不可执行
				if (vm_flags & VM_EXEC) // 但是是代码段?
					return -EPERM;
				vm_flags &= ~VM_MAYEXEC;
			}

			if (!file->f_op->mmap)
				return -ENODEV;
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
				return -EINVAL;
			break;

		default:
			return -EINVAL;
		}
	} else { // 匿名页的情况?
		switch (flags & MAP_TYPE) {
		case MAP_SHARED: // 共享的匿名, ipc?
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
				return -EINVAL;
			/*
			 * Ignore pgoff.
			 */
			pgoff = 0;
			vm_flags |= VM_SHARED | VM_MAYSHARE;
			break;
		case MAP_PRIVATE: // 私有匿名页, 应该就是内存吧
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}

	/*
	 * Set 'VM_NORESERVE' if we should not account for the
	 * memory use of this mapping.
	 设置'VM_NORESERVE'，如果我们不应该计算此映射的内存使用。
	 */
	if (flags & MAP_NORESERVE) {
		/* We honor MAP_NORESERVE if allowed to overcommit */
		if (sysctl_overcommit_memory != OVERCOMMIT_NEVER)
			vm_flags |= VM_NORESERVE;

		/* hugetlb applies strict overcommit unless MAP_NORESERVE */
		if (file && is_file_hugepages(file))
			vm_flags |= VM_NORESERVE;
	}
// 这里开始mmap
	addr = mmap_region(file, addr, len, vm_flags, pgoff, uf);
	if (!IS_ERR_VALUE(addr) &&
	    ((vm_flags & VM_LOCKED) ||
	     (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
		*populate = len;
	return addr;
}

// 似乎是addr开始的len, 想mmap到fd的pgoff开始
unsigned long ksys_mmap_pgoff(unsigned long addr, unsigned long len,
			      unsigned long prot, unsigned long flags,
			      unsigned long fd, unsigned long pgoff)
{
	struct file *file = NULL;
	unsigned long retval;

	if (!(flags & MAP_ANONYMOUS)) {// 如果不是匿名的, 映射具体文件
		// 设置一下文件
		audit_mmap_fd(fd, flags);
		file = fget(fd);
		if (!file)
			return -EBADF;
		if (is_file_hugepages(file)) {
			len = ALIGN(len, huge_page_size(hstate_file(file)));
		} else if (unlikely(flags & MAP_HUGETLB)) {
			retval = -EINVAL;
			goto out_fput;
		}
	} else if (flags & MAP_HUGETLB) {// 巨页相关
		struct hstate *hs;

		hs = hstate_sizelog((flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (!hs)
			return -EINVAL;

		len = ALIGN(len, huge_page_size(hs));
		/*
		 * VM_NORESERVE is used because the reservations will be
		 * taken when vm_ops->mmap() is called
		 */
		file = hugetlb_file_setup(HUGETLB_ANON_FILE, len,
				VM_NORESERVE,
				HUGETLB_ANONHUGE_INODE,
				(flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (IS_ERR(file))
			return PTR_ERR(file);
	}
	// 执行mmap
	retval = vm_mmap_pgoff(file, addr, len, prot, flags, pgoff);
out_fput:
	if (file)
		fput(file);
	return retval;
}

SYSCALL_DEFINE6(mmap_pgoff, 
	unsigned long, addr, 
	unsigned long, len,
		unsigned long, prot, 
		unsigned long, flags,
		unsigned long, fd, 
		unsigned long, pgoff)
{
	return ksys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}

#ifdef __ARCH_WANT_SYS_OLD_MMAP
struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

SYSCALL_DEFINE1(old_mmap, struct mmap_arg_struct __user *, arg)
{
	struct mmap_arg_struct a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (offset_in_page(a.offset))
		return -EINVAL;

	return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd,
			       a.offset >> PAGE_SHIFT);
}
#endif /* __ARCH_WANT_SYS_OLD_MMAP */

static bool vm_ops_needs_writenotify(const struct vm_operations_struct *vm_ops)
{
	return vm_ops && (vm_ops->page_mkwrite || vm_ops->pfn_mkwrite);
}

static bool vma_is_shared_writable(struct vm_area_struct *vma)
{
	return (vma->vm_flags & (VM_WRITE | VM_SHARED)) ==
		(VM_WRITE | VM_SHARED);
}

static bool vma_fs_can_writeback(struct vm_area_struct *vma)
{
	/* No managed pages to writeback. */
	if (vma->vm_flags & VM_PFNMAP)
		return false;

	return vma->vm_file && vma->vm_file->f_mapping &&
		mapping_can_writeback(vma->vm_file->f_mapping);
}

/*
 * Does this VMA require the underlying folios to have their dirty state
 * tracked?
 */
bool vma_needs_dirty_tracking(struct vm_area_struct *vma)
{
	/* Only shared, writable VMAs require dirty tracking. */
	if (!vma_is_shared_writable(vma))
		return false;

	/* Does the filesystem need to be notified? */
	if (vm_ops_needs_writenotify(vma->vm_ops))
		return true;

	/*
	 * Even if the filesystem doesn't indicate a need for writenotify, if it
	 * can writeback, dirty tracking is still required.
	 */
	return vma_fs_can_writeback(vma);
}

/*
 * Some shared mappings will want the pages marked read-only
 * to track write events. If so, we'll downgrade vm_page_prot
 * to the private version (using protection_map[] without the
 * VM_SHARED bit).
 */
int vma_wants_writenotify(struct vm_area_struct *vma, pgprot_t vm_page_prot)
{
	/* If it was private or non-writable, the write bit is already clear */
	if (!vma_is_shared_writable(vma))
		return 0;

	/* The backer wishes to know when pages are first written to? */
	if (vm_ops_needs_writenotify(vma->vm_ops))
		return 1;

	/* The open routine did something to the protections that pgprot_modify
	 * won't preserve? */
	if (pgprot_val(vm_page_prot) !=
	    pgprot_val(vm_pgprot_modify(vm_page_prot, vma->vm_flags)))
		return 0;

	/*
	 * Do we need to track softdirty? hugetlb does not support softdirty
	 * tracking yet.
	 */
	if (vma_soft_dirty_enabled(vma) && !is_vm_hugetlb_page(vma))
		return 1;

	/* Do we need write faults for uffd-wp tracking? */
	if (userfaultfd_wp(vma))
		return 1;

	/* Can the mapping track the dirty pages? */
	return vma_fs_can_writeback(vma);
}

/*
 * We account for memory if it's a private writeable mapping,
 * not hugepages and VM_NORESERVE wasn't set.
   如果是个私有可写映射, 不是巨页, 且VM_NORESERVE没有设置, 我们就会计算内存
 */
static inline int accountable_mapping(struct file *file, vm_flags_t vm_flags)
{
	/*
	 * hugetlb has its own accounting separate from the core VM
	 * VM_HUGETLB may not be set yet so we cannot check for that flag.
	 */
	if (file && is_file_hugepages(file))
		return 0;

	return (vm_flags & (VM_NORESERVE | VM_SHARED | VM_WRITE)) == VM_WRITE;
}

/**
找一段满足要求的未映射地址范围
 * unmapped_area() - Find an area between the low_limit and the high_limit with
 * the correct alignment and offset, all from @info. Note: current->mm is used
 * for the search.
 *
 * @info: The unmapped area information including the range [low_limit -
 * high_limit), the alignment offset and mask.
 *
 * Return: A memory address or -ENOMEM.
 */
static unsigned long unmapped_area(struct vm_unmapped_area_info *info)
{
	unsigned long length, gap;
	unsigned long low_limit, high_limit;
	struct vm_area_struct *tmp;

	MA_STATE(mas, &current->mm->mm_mt, 0, 0);

	/* Adjust search length to account for worst case alignment overhead */
	length = info->length + info->align_mask;
	if (length < info->length)
		return -ENOMEM;

	low_limit = info->low_limit;
	if (low_limit < mmap_min_addr)
		low_limit = mmap_min_addr;
	high_limit = info->high_limit;
retry:
	if (mas_empty_area(&mas, low_limit, high_limit - 1, length))
		return -ENOMEM;

	gap = mas.index;
	gap += (info->align_offset - gap) & info->align_mask;
	tmp = mas_next(&mas, ULONG_MAX);
	if (tmp && (tmp->vm_flags & VM_STARTGAP_FLAGS)) { /* Avoid prev check if possible */
		if (vm_start_gap(tmp) < gap + length - 1) {
			low_limit = tmp->vm_end;
			mas_reset(&mas);
			goto retry;
		}
	} else {
		tmp = mas_prev(&mas, 0);
		if (tmp && vm_end_gap(tmp) > gap) {
			low_limit = vm_end_gap(tmp);
			mas_reset(&mas);
			goto retry;
		}
	}

	return gap;
}

/**
找一段范围内的未映射地址范围
 * unmapped_area_topdown() - Find an area between the low_limit and the
 * high_limit with the correct alignment and offset at the highest available
 * address, all from @info. Note: current->mm is used for the search.
 *
 * @info: The unmapped area information including the range [low_limit -
 * high_limit), the alignment offset and mask.
 *
 * Return: A memory address or -ENOMEM.
 */
static unsigned long unmapped_area_topdown(struct vm_unmapped_area_info *info)
{
	unsigned long length, gap, gap_end;
	unsigned long low_limit, high_limit;
	struct vm_area_struct *tmp;

	MA_STATE(mas, &current->mm->mm_mt, 0, 0);
	/* Adjust search length to account for worst case alignment overhead */
	length = info->length + info->align_mask;
	if (length < info->length)
		return -ENOMEM;

	low_limit = info->low_limit;
	if (low_limit < mmap_min_addr)
		low_limit = mmap_min_addr;
	high_limit = info->high_limit;
	/* 调整范围和要找的长度 */
retry:
	if (mas_empty_area_rev(&mas, low_limit, high_limit - 1, length))
		return -ENOMEM;

	gap = mas.last + 1 - info->length;
	gap -= (gap - info->align_offset) & info->align_mask;
	gap_end = mas.last;
	tmp = mas_next(&mas, ULONG_MAX);
	if (tmp && (tmp->vm_flags & VM_STARTGAP_FLAGS)) { /* Avoid prev check if possible */
		if (vm_start_gap(tmp) <= gap_end) {
			high_limit = vm_start_gap(tmp);
			mas_reset(&mas);
			goto retry;
		}
	} else {
		tmp = mas_prev(&mas, 0);
		if (tmp && vm_end_gap(tmp) > gap) {
			high_limit = tmp->vm_start;
			mas_reset(&mas);
			goto retry;
		}
	}

	return gap;
}

/*
找一段还没有被map的地址范围
 * Search for an unmapped address range.
 *
 * We are looking for a range that:
 * - does not intersect with any VMA;
 * - is contained within the [low_limit, high_limit) interval;
 * - is at least the desired size.
 * - satisfies (begin_addr & align_mask) == (align_offset & align_mask)
 */
unsigned long vm_unmapped_area(struct vm_unmapped_area_info *info)
{
	unsigned long addr;

	if (info->flags & VM_UNMAPPED_AREA_TOPDOWN)
		addr = unmapped_area_topdown(info);
	else
		addr = unmapped_area(info);

	trace_vm_unmapped_area(addr, info);
	return addr;
}

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
unsigned long
generic_get_unmapped_area(struct file *filp, unsigned long addr,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	struct vm_unmapped_area_info info;
	const unsigned long mmap_end = arch_get_mmap_end(addr, len, flags);

	if (len > mmap_end - mmap_min_addr)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma_prev(mm, addr, &prev);
		if (mmap_end - len >= addr && addr >= mmap_min_addr &&
		    (!vma || addr + len <= vm_start_gap(vma)) &&
		    (!prev || addr >= vm_end_gap(prev)))
			return addr;
	}

	info.flags = 0;
	info.length = len;
	info.low_limit = mm->mmap_base;
	info.high_limit = mmap_end;
	info.align_mask = 0;
	info.align_offset = 0;
	return vm_unmapped_area(&info);
}

#ifndef HAVE_ARCH_UNMAPPED_AREA
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		       unsigned long len, unsigned long pgoff,
		       unsigned long flags)
{
	return generic_get_unmapped_area(filp, addr, len, pgoff, flags);
}
#endif

/*
 * This mmap-allocator allocates new areas top-down from below the
 * stack's low limit (the base):
 */
unsigned long
generic_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
				  unsigned long len, unsigned long pgoff,
				  unsigned long flags)
{
	struct vm_area_struct *vma, *prev;
	struct mm_struct *mm = current->mm;
	struct vm_unmapped_area_info info;
	const unsigned long mmap_end = arch_get_mmap_end(addr, len, flags);

	/* requested length too big for entire address space */
	if (len > mmap_end - mmap_min_addr)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma_prev(mm, addr, &prev);
		if (mmap_end - len >= addr && addr >= mmap_min_addr &&
				(!vma || addr + len <= vm_start_gap(vma)) &&
				(!prev || addr >= vm_end_gap(prev)))
			return addr;
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = arch_get_mmap_base(addr, mm->mmap_base);
	info.align_mask = 0;
	info.align_offset = 0;
	addr = vm_unmapped_area(&info);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	if (offset_in_page(addr)) {
		VM_BUG_ON(addr != -ENOMEM);
		info.flags = 0;
		info.low_limit = TASK_UNMAPPED_BASE;
		info.high_limit = mmap_end;
		addr = vm_unmapped_area(&info);
	}

	return addr;
}

#ifndef HAVE_ARCH_UNMAPPED_AREA_TOPDOWN
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
			       unsigned long len, unsigned long pgoff,
			       unsigned long flags)
{
	return generic_get_unmapped_area_topdown(filp, addr, len, pgoff, flags);
}
#endif
/* 找到一段可以map的地址
希望map到[addr，addr+len]
file是现存的一个vma的file， pgoff是vma的old addr的pgoff */
unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *, unsigned long,
				  unsigned long, unsigned long, unsigned long);

	unsigned long error = arch_mmap_check(addr, len, flags);
	if (error)
		return error;

	/* Careful about overflows.. */
	if (len > TASK_SIZE)
		return -ENOMEM;

	/* mm提供了get area回调 */
	get_area = current->mm->get_unmapped_area;
	if (file) {/* 如果是文件映射， 使用file的get area回调 */
		if (file->f_op->get_unmapped_area)
			get_area = file->f_op->get_unmapped_area;
	} else if (flags & MAP_SHARED) {
		/* 为啥这还是个特殊情况 */
		/*
		 * mmap_region() will call shmem_zero_setup() to create a file,
		 * so use shmem's get_unmapped_area in case it can be huge.
		 * do_mmap() will clear pgoff, so match alignment.
		 */
		pgoff = 0;
		get_area = shmem_get_unmapped_area;
	}

	/* 获取可映射区域 */
	addr = get_area(file, addr, len, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	if (addr > TASK_SIZE - len)
		return -ENOMEM;
	if (offset_in_page(addr))
		return -EINVAL;

	error = security_mmap_addr(addr);
	return error ? error : addr;
}

EXPORT_SYMBOL(get_unmapped_area);

/**
 * find_vma_intersection() - Look up the first VMA which intersects the interval
   查找与区间交集的第一个VMA
 * @mm: The process address space.
 * @start_addr: The inclusive start user address.
 * @end_addr: The exclusive end user address.
 *
 * Returns: The first VMA within the provided range, %NULL otherwise.  Assumes
 * start_addr < end_addr.
 */
struct vm_area_struct *find_vma_intersection(struct mm_struct *mm,
					     unsigned long start_addr,
					     unsigned long end_addr)
{
	unsigned long index = start_addr;

	mmap_assert_locked(mm);
	/* 可能返回空 */
	return mt_find(&mm->mm_mt, &index, end_addr - 1);
}
EXPORT_SYMBOL(find_vma_intersection);

/**
 * find_vma() - Find the VMA for a given address, or the next VMA.
   获取地址addr对应的VMA，如果没有则返回下一个VMA
 * @mm: The mm_struct to check
 * @addr: The address
 *
 * Returns: The VMA associated with addr, or the next VMA.
 * May return %NULL in the case of no VMA at addr or above.
 */
struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr)
{
	unsigned long index = addr;

	mmap_assert_locked(mm);
	return mt_find(&mm->mm_mt, &index, ULONG_MAX);
}
EXPORT_SYMBOL(find_vma);

/**
 * find_vma_prev() - 查找给定地址的VMA，
 或者下一个VMA，并将%pprev设置为前一个VMA（如果有的话）。
 * @mm: The mm_struct to check
 * @addr: The address
 * @pprev: The pointer to set to the previous VMA
 *
 * Note that RCU lock is missing here since the external mmap_lock() is used
 * instead.
 *
 * Returns: The VMA associated with @addr, or the next vma.
 * May return %NULL in the case of no vma at addr or above.
 */
struct vm_area_struct *
find_vma_prev(struct mm_struct *mm, unsigned long addr,
			struct vm_area_struct **pprev)
{
	struct vm_area_struct *vma;
	/* 找到vma tree */
	MA_STATE(mas, &mm->mm_mt, addr, addr);

	vma = mas_walk(&mas);
	*pprev = mas_prev(&mas, 0);
	if (!vma)
		vma = mas_next(&mas, ULONG_MAX);
	return vma;
}

/*
@size: vma的新size
@grow: 增长的页数
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 检查栈增长是否可接受并更新计数。这适用于增长和减少的情况。
 */
static int acct_stack_growth(struct vm_area_struct *vma,
			     unsigned long size, unsigned long grow)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long new_start;

	/* address space limit tests */
	if (!may_expand_vm(mm, vma->vm_flags, grow))
		return -ENOMEM;

	/* Stack limit test */
	if (size > rlimit(RLIMIT_STACK))
		return -ENOMEM;

	/* mlock limit tests */
	if (!mlock_future_ok(mm, vma->vm_flags, grow << PAGE_SHIFT))
		return -ENOMEM;

	/* Check to ensure the stack will not grow into a hugetlb-only region */
	new_start = (vma->vm_flags & VM_GROWSUP) ? vma->vm_start :
			vma->vm_end - size;
	if (is_hugepage_only_range(vma->vm_mm, new_start, size))
		return -EFAULT;

	/*
	 * Overcommit..  This must be the final test, as it will
	 * update security statistics.
	 */
	if (security_vm_enough_memory_mm(mm, grow))
		return -ENOMEM;

	return 0;
}

#if defined(CONFIG_STACK_GROWSUP) || defined(CONFIG_IA64)
/*
 * PA-RISC uses this for its stack; IA64 for its Register Backing Store.
 * vma is the last one with address > vma->vm_end.  Have to extend vma.
 */
static int expand_upwards(struct vm_area_struct *vma, unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *next;
	unsigned long gap_addr;
	int error = 0;
	MA_STATE(mas, &mm->mm_mt, vma->vm_start, address);

	if (!(vma->vm_flags & VM_GROWSUP))
		return -EFAULT;

	/* Guard against exceeding limits of the address space. */
	address &= PAGE_MASK;
	if (address >= (TASK_SIZE & PAGE_MASK))
		return -ENOMEM;
	address += PAGE_SIZE;

	/* Enforce stack_guard_gap */
	gap_addr = address + stack_guard_gap;

	/* Guard against overflow */
	if (gap_addr < address || gap_addr > TASK_SIZE)
		gap_addr = TASK_SIZE;

	next = find_vma_intersection(mm, vma->vm_end, gap_addr);
	if (next && vma_is_accessible(next)) {
		if (!(next->vm_flags & VM_GROWSUP))
			return -ENOMEM;
		/* Check that both stack segments have the same anon_vma? */
	}

	if (next)
		mas_prev_range(&mas, address);

	__mas_set_range(&mas, vma->vm_start, address - 1);
	if (mas_preallocate(&mas, vma, GFP_KERNEL))
		return -ENOMEM;

	/* We must make sure the anon_vma is allocated. */
	if (unlikely(anon_vma_prepare(vma))) {
		mas_destroy(&mas);
		return -ENOMEM;
	}

	/* Lock the VMA before expanding to prevent concurrent page faults */
	vma_start_write(vma);
	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_lock in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 */
	anon_vma_lock_write(vma->anon_vma);

	/* Somebody else might have raced and expanded it already */
	if (address > vma->vm_end) {
		unsigned long size, grow;

		size = address - vma->vm_start;
		grow = (address - vma->vm_end) >> PAGE_SHIFT;

		error = -ENOMEM;
		if (vma->vm_pgoff + (size >> PAGE_SHIFT) >= vma->vm_pgoff) {
			error = acct_stack_growth(vma, size, grow);
			if (!error) {
				/*
				 * We only hold a shared mmap_lock lock here, so
				 * we need to protect against concurrent vma
				 * expansions.  anon_vma_lock_write() doesn't
				 * help here, as we don't guarantee that all
				 * growable vmas in a mm share the same root
				 * anon vma.  So, we reuse mm->page_table_lock
				 * to guard against concurrent vma expansions.
				 */
				spin_lock(&mm->page_table_lock);
				if (vma->vm_flags & VM_LOCKED)
					mm->locked_vm += grow;
				vm_stat_account(mm, vma->vm_flags, grow);
				anon_vma_interval_tree_pre_update_vma(vma);
				vma->vm_end = address;
				/* Overwrite old entry in mtree. */
				mas_store_prealloc(&mas, vma);
				anon_vma_interval_tree_post_update_vma(vma);
				spin_unlock(&mm->page_table_lock);

				perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);
	khugepaged_enter_vma(vma, vma->vm_flags);
	mas_destroy(&mas);
	validate_mm(mm);
	return error;
}
#endif /* CONFIG_STACK_GROWSUP || CONFIG_IA64 */

/*
扩展这个vma的栈
 * vma is the first one with address < vma->vm_start.  Have to extend vma.
 * mmap_lock held for writing.
 vma是第一个地址小于vma->vm_start的vma。必须扩展vma。持有写入的mmap_lock。
 因为address小于vma的start, 调用此函数扩展
 */
int expand_downwards(struct vm_area_struct *vma, unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	MA_STATE(mas, &mm->mm_mt, vma->vm_start, vma->vm_start);
	struct vm_area_struct *prev;
	int error = 0;

	if (!(vma->vm_flags & VM_GROWSDOWN))
		return -EFAULT;

	address &= PAGE_MASK;
	if (address < mmap_min_addr || address < FIRST_USER_ADDRESS)
		return -EPERM;

	/* Enforce stack_guard_gap */
	prev = mas_prev(&mas, 0);
	/* Check that both stack segments have the same anon_vma? */
	if (prev) {
		if (!(prev->vm_flags & VM_GROWSDOWN) &&
		    vma_is_accessible(prev) &&
		    (address - prev->vm_end < stack_guard_gap))
			return -ENOMEM;
	}

	if (prev)
		mas_next_range(&mas, vma->vm_start);

	__mas_set_range(&mas, address, vma->vm_end - 1);
	if (mas_preallocate(&mas, vma, GFP_KERNEL))
		return -ENOMEM;

	/* We must make sure the anon_vma is allocated. */
	if (unlikely(anon_vma_prepare(vma))) {
		mas_destroy(&mas);
		return -ENOMEM;
	}

	/* Lock the VMA before expanding to prevent concurrent page faults
	锁住VMA以防止并发页面故障
	*/
	vma_start_write(vma);
	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_lock in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 */
	anon_vma_lock_write(vma->anon_vma);

	/* Somebody else might have raced and expanded it already

	*/
	if (address < vma->vm_start) {
		unsigned long size, grow;
		/*
		            size
		    |---------------------------|
		   old_vma_start
		      |-------------------------|
		|-------------------------------|
    new_vma_start
		*/
		/* size是vma的新size
		grow是需要增加的页面数量 */
		size = vma->vm_end - address;
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = -ENOMEM;
		if (grow <= vma->vm_pgoff) {
			error = acct_stack_growth(vma, size, grow);
			if (!error) {
				/*
				 * We only hold a shared mmap_lock lock here, so
				 * we need to protect against concurrent vma
				 * expansions.  anon_vma_lock_write() doesn't
				 * help here, as we don't guarantee that all
				 * growable vmas in a mm share the same root
				 * anon vma.  So, we reuse mm->page_table_lock
				 * to guard against concurrent vma expansions.
				 */
				spin_lock(&mm->page_table_lock);
				if (vma->vm_flags & VM_LOCKED)
					mm->locked_vm += grow;
				vm_stat_account(mm, vma->vm_flags, grow);
				// rmap相关
				anon_vma_interval_tree_pre_update_vma(vma);
				vma->vm_start = address;
				vma->vm_pgoff -= grow;
				/* Overwrite old entry in mtree. */
				mas_store_prealloc(&mas, vma);
				anon_vma_interval_tree_post_update_vma(vma);
				spin_unlock(&mm->page_table_lock);

				perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);
	khugepaged_enter_vma(vma, vma->vm_flags);
	mas_destroy(&mas);
	validate_mm(mm);
	return error;
}

/* enforced gap between the expanding stack and other mappings. */
unsigned long stack_guard_gap = 256UL<<PAGE_SHIFT;

static int __init cmdline_parse_stack_guard_gap(char *p)
{
	unsigned long val;
	char *endptr;

	val = simple_strtoul(p, &endptr, 10);
	if (!*endptr)
		stack_guard_gap = val << PAGE_SHIFT;

	return 1;
}
__setup("stack_guard_gap=", cmdline_parse_stack_guard_gap);

#ifdef CONFIG_STACK_GROWSUP
int expand_stack_locked(struct vm_area_struct *vma, unsigned long address)
{
	return expand_upwards(vma, address);
}

struct vm_area_struct *find_extend_vma_locked(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma, *prev;

	addr &= PAGE_MASK;
	vma = find_vma_prev(mm, addr, &prev);
	if (vma && (vma->vm_start <= addr))
		return vma;
	if (!prev)
		return NULL;
	if (expand_stack_locked(prev, addr))
		return NULL;
	if (prev->vm_flags & VM_LOCKED)
		populate_vma_page_range(prev, addr, prev->vm_end, NULL);
	return prev;
}
#else
int expand_stack_locked(struct vm_area_struct *vma, unsigned long address)
{
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN)))
		return -EINVAL;
	return expand_downwards(vma, address);
}

struct vm_area_struct *find_extend_vma_locked(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma;
	unsigned long start;

	addr &= PAGE_MASK;
	vma = find_vma(mm, addr);
	if (!vma)
		return NULL;
	if (vma->vm_start <= addr)
		return vma;
	start = vma->vm_start;
	if (expand_stack_locked(vma, addr))
		return NULL;
	if (vma->vm_flags & VM_LOCKED)
		populate_vma_page_range(vma, addr, start, NULL);
	return vma;
}
#endif

/*
 * IA64 has some horrid mapping rules: it can expand both up and down,
 * but with various special rules.
 *
 * We'll get rid of this architecture eventually, so the ugliness is
 * temporary.
 */
#ifdef CONFIG_IA64
static inline bool vma_expand_ok(struct vm_area_struct *vma, unsigned long addr)
{
	return REGION_NUMBER(addr) == REGION_NUMBER(vma->vm_start) &&
		REGION_OFFSET(addr) < RGN_MAP_LIMIT;
}

/*
 * IA64 stacks grow down, but there's a special register backing store
 * that can grow up. Only sequentially, though, so the new address must
 * match vm_end.
 */
static inline int vma_expand_up(struct vm_area_struct *vma, unsigned long addr)
{
	if (!vma_expand_ok(vma, addr))
		return -EFAULT;
	if (vma->vm_end != (addr & PAGE_MASK))
		return -EFAULT;
	return expand_upwards(vma, addr);
}

static inline bool vma_expand_down(struct vm_area_struct *vma, unsigned long addr)
{
	if (!vma_expand_ok(vma, addr))
		return -EFAULT;
	return expand_downwards(vma, addr);
}

#elif defined(CONFIG_STACK_GROWSUP)

#define vma_expand_up(vma,addr) expand_upwards(vma, addr)
#define vma_expand_down(vma, addr) (-EFAULT)

#else

#define vma_expand_up(vma,addr) (-EFAULT)
#define vma_expand_down(vma, addr) expand_downwards(vma, addr)

#endif

/*
 * expand_stack(): legacy interface for page faulting. Don't use unless
 * you have to.
 *
 * This is called with the mm locked for reading, drops the lock, takes
 * the lock for writing, tries to look up a vma again, expands it if
 * necessary, and downgrades the lock to reading again.
 *
 * If no vma is found or it can't be expanded, it returns NULL and has
 * dropped the lock.
 */
struct vm_area_struct *expand_stack(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma, *prev;

	mmap_read_unlock(mm);
	if (mmap_write_lock_killable(mm))
		return NULL;

	vma = find_vma_prev(mm, addr, &prev);
	if (vma && vma->vm_start <= addr)
		goto success;

	if (prev && !vma_expand_up(prev, addr)) {
		vma = prev;
		goto success;
	}

	if (vma && !vma_expand_down(vma, addr))
		goto success;

	mmap_write_unlock(mm);
	return NULL;

success:
	mmap_write_downgrade(mm);
	return vma;
}

/*
 * Ok - we have the memory areas we should free on a maple tree so release them,
 * and do the vma updates.
 *
 * Called with the mm semaphore held.
 */
static inline void remove_mt(struct mm_struct *mm, struct ma_state *mas)
{
	unsigned long nr_accounted = 0;
	struct vm_area_struct *vma;

	/* Update high watermark before we lower total_vm */
	update_hiwater_vm(mm);
	mas_for_each(mas, vma, ULONG_MAX) {
		long nrpages = vma_pages(vma);

		if (vma->vm_flags & VM_ACCOUNT)
			nr_accounted += nrpages;
		vm_stat_account(mm, vma->vm_flags, -nrpages);
		remove_vma(vma, false);
	}
	vm_unacct_memory(nr_accounted);
}

/*
 * Get rid of page table information in the indicated region.
 * unmap这些vma, 释放页表
 * Called with the mm semaphore held.
 要unmap的vma都在mas存着, tree_end个,地址范围在start到end
 @vma是第一个vma
prev和next还不清楚
 */
static void unmap_region(struct mm_struct *mm, struct ma_state *mas,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		struct vm_area_struct *next, unsigned long start,
		unsigned long end, unsigned long tree_end, bool mm_wr_locked)
{
	struct mmu_gather tlb;
	unsigned long mt_start = mas->index;

	lru_add_drain();
	tlb_gather_mmu(&tlb, mm);
	update_hiwater_rss(mm);
	// unmap这些vma
	unmap_vmas(&tlb, mas, vma, start, end, tree_end, mm_wr_locked);
	mas_set(mas, mt_start);
	free_pgtables(&tlb, mas, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
				 next ? next->vm_start : USER_PGTABLES_CEILING,
				 mm_wr_locked);
	tlb_finish_mmu(&tlb);
}

/*
 * __split_vma() bypasses sysctl_max_map_count checking.  We use this where it
 * has already been checked or doesn't make sense to fail.
 * VMA Iterator will point to the end VMA.
 */
int __split_vma(struct vma_iterator *vmi, struct vm_area_struct *vma,
		unsigned long addr, int new_below)
{
	struct vma_prepare vp;
	struct vm_area_struct *new;
	int err;

	WARN_ON(vma->vm_start >= addr);
	WARN_ON(vma->vm_end <= addr);

	if (vma->vm_ops && vma->vm_ops->may_split) {
		err = vma->vm_ops->may_split(vma, addr);
		if (err)
			return err;
	}

	new = vm_area_dup(vma);
	if (!new)
		return -ENOMEM;

	if (new_below) {
		new->vm_end = addr;
	} else {
		new->vm_start = addr;
		new->vm_pgoff += ((addr - vma->vm_start) >> PAGE_SHIFT);
	}

	err = -ENOMEM;
	vma_iter_config(vmi, new->vm_start, new->vm_end);
	if (vma_iter_prealloc(vmi, new))
		goto out_free_vma;

	err = vma_dup_policy(vma, new);
	if (err)
		goto out_free_vmi;

	err = anon_vma_clone(new, vma);
	if (err)
		goto out_free_mpol;

	if (new->vm_file)
		get_file(new->vm_file);

	if (new->vm_ops && new->vm_ops->open)
		new->vm_ops->open(new);

	vma_start_write(vma);
	vma_start_write(new);

	init_vma_prep(&vp, vma);
	vp.insert = new;
	vma_prepare(&vp);
	vma_adjust_trans_huge(vma, vma->vm_start, addr, 0);

	if (new_below) {
		vma->vm_start = addr;
		vma->vm_pgoff += (addr - new->vm_start) >> PAGE_SHIFT;
	} else {
		vma->vm_end = addr;
	}

	/* vma_complete stores the new vma */
	vma_complete(&vp, vmi, vma->vm_mm);

	/* Success. */
	if (new_below)
		vma_next(vmi);
	return 0;

out_free_mpol:
	mpol_put(vma_policy(new));
out_free_vmi:
	vma_iter_free(vmi);
out_free_vma:
	vm_area_free(new);
	return err;
}

/*
为啥要split vma
 * Split a vma into two pieces at address 'addr', a new vma is allocated
 * either for the first part or the tail.
 */
int split_vma(struct vma_iterator *vmi, struct vm_area_struct *vma,
	      unsigned long addr, int new_below)
{
	if (vma->vm_mm->map_count >= sysctl_max_map_count)
		return -ENOMEM;

	return __split_vma(vmi, vma, addr, new_below);
}

/*
 * do_vmi_align_munmap() - munmap the aligned region from @start to @end.
 unmap范围从start到end
 先加锁mm找到这些vma,detach加入mas,.然后再unmap
 * @vmi: The vma iterator
 * @vma: The starting vm_area_struct, 范围内第一个vma
 * @mm: The mm_struct
 * @start: The aligned start address to munmap.
 * @end: The aligned end address to munmap.
 * @uf: The userfaultfd list_head
 * @unlock: Set to true to drop the mmap_lock.  unlocking only happens on
 * success.
 *
 * Return: 0 on success and drops the lock if so directed, error and leaves the
 * lock held otherwise.
 */
static int
do_vmi_align_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
		    struct mm_struct *mm, unsigned long start,
		    unsigned long end, struct list_head *uf, bool unlock)
{
	struct vm_area_struct *prev, *next = NULL;
	struct maple_tree mt_detach;
	int count = 0;
	int error = -ENOMEM;
	unsigned long locked_vm = 0;
	MA_STATE(mas_detach, &mt_detach, 0, 0);
	// 初始化mt_detach这个maple tree
	mt_init_flags(&mt_detach, vmi->mas.tree->ma_flags & MT_FLAGS_LOCK_MASK);
	mt_on_stack(mt_detach);

	/*
	 * If we need to split any vma, do it now to save pain later.
	 *
	 * Note: mremap's move_vma VM_ACCOUNT handling assumes a partially
	 * unmapped vm_area_struct will remain in use: so lower split_vma
	 * places tmp vma above, and higher split_vma places tmp vma below.
	 */

	/* Does it split the first one? */
	if (start > vma->vm_start) {

		/*
		 * Make sure that map_count on return from munmap() will
		 * not exceed its limit; but let map_count go just above
		 * its limit temporarily, to help free resources as expected.
		 */
		if (end < vma->vm_end && mm->map_count >= sysctl_max_map_count)
			goto map_count_exceeded;

		error = __split_vma(vmi, vma, start, 1);
		if (error)
			goto start_split_failed;
	}

	/*
	 * Detach a range of VMAs from the mm. Using next as a temp variable as
	 * it is always overwritten.
	 */
	next = vma;
	do {
		/* Does it split the end? */
		if (next->vm_end > end) {
			error = __split_vma(vmi, next, end, 0);
			if (error)
				goto end_split_failed;
		}
		vma_start_write(next);
		// count是一种类似idx的东西
		mas_set(&mas_detach, count);
		// 把当前这个vma存储到detach这个mt
		error = mas_store_gfp(&mas_detach, next, GFP_KERNEL);
		if (error)
			goto munmap_gather_failed;
		// 标记为已经detached
		vma_mark_detached(next, true);
		if (next->vm_flags & VM_LOCKED)
			locked_vm += vma_pages(next);

		count++;
		if (unlikely(uf)) {
			/*
			 * If userfaultfd_unmap_prep returns an error the vmas
			 * will remain split, but userland will get a
			 * highly unexpected error anyway. This is no
			 * different than the case where the first of the two
			 * __split_vma fails, but we don't undo the first
			 * split, despite we could. This is unlikely enough
			 * failure that it's not worth optimizing it for.
			 */
			error = userfaultfd_unmap_prep(next, start, end, uf);

			if (error)
				goto userfaultfd_error;
		}
#ifdef CONFIG_DEBUG_VM_MAPLE_TREE
		BUG_ON(next->vm_start < start);
		BUG_ON(next->vm_start > end);
#endif
	} for_each_vma_range(*vmi, next, end);

#if defined(CONFIG_DEBUG_VM_MAPLE_TREE)
	/* Make sure no VMAs are about to be lost. */
	{
		MA_STATE(test, &mt_detach, 0, 0);
		struct vm_area_struct *vma_mas, *vma_test;
		int test_count = 0;

		vma_iter_set(vmi, start);
		rcu_read_lock();
		vma_test = mas_find(&test, count - 1);
		for_each_vma_range(*vmi, vma_mas, end) {
			BUG_ON(vma_mas != vma_test);
			test_count++;
			vma_test = mas_next(&test, count - 1);
		}
		rcu_read_unlock();
		BUG_ON(count != test_count);
	}
#endif

	while (vma_iter_addr(vmi) > start)
		vma_iter_prev_range(vmi); // 往前移动vmi的mas状态的index

	error = vma_iter_clear_gfp(vmi, start, end, GFP_KERNEL);
	if (error)
		goto clear_tree_failed;

	/* Point of no return */
	mm->locked_vm -= locked_vm;
	mm->map_count -= count;
	if (unlock)
		mmap_write_downgrade(mm);

	prev = vma_iter_prev_range(vmi);
	next = vma_next(vmi);
	if (next)
		vma_iter_prev_range(vmi);
	// 刚才在加锁的情况下
	// detach这个mt上存储了vma, 现在要把这些vma从mm上删除
	/*
	 * We can free page tables without write-locking mmap_lock because VMAs
	 * were isolated before we downgraded mmap_lock.
	 我们可以
	 */
	mas_set(&mas_detach, 1);
	// 这里开始unmap?
	unmap_region(mm, &mas_detach, vma, prev, next, start, end, count,
		     !unlock);
	/* Statistics and freeing VMAs */
	mas_set(&mas_detach, 0);
	remove_mt(mm, &mas_detach);
	validate_mm(mm);
	if (unlock)
		mmap_read_unlock(mm);

	__mt_destroy(&mt_detach);
	return 0;

clear_tree_failed:
userfaultfd_error:
munmap_gather_failed:
end_split_failed:
	mas_set(&mas_detach, 0);
	mas_for_each(&mas_detach, next, end)
		vma_mark_detached(next, false);

	__mt_destroy(&mt_detach);
start_split_failed:
map_count_exceeded:
	validate_mm(mm);
	return error;
}

/*
 * do_vmi_munmap() - munmap a given range.
   unmap指定的地址范围
 * @vmi: The vma iterator, 是对mm的vma的迭代器
 * @mm: The mm_struct
 * @start: The start address to munmap
 * @len: The length of the range to munmap
 * @uf: The userfaultfd list_head
 * @unlock: set to true if the user wants to drop the mmap_lock on success
 *
 * This function takes a @mas that is either pointing to the previous VMA or set
 * to MA_START and sets it up to remove the mapping(s).  The @len will be
 * aligned and any arch_unmap work will be preformed.
 * 这个函数接受一个mas, 它要么指向前一个VMA, 要么设置为MA_START, 用来删除映射
  len会被对齐, arch_unmap工作会被执行
 * Return: 0 on success and drops the lock if so directed, error and leaves the
 * lock held otherwise.
  返回0表示成功
 */
int do_vmi_munmap(struct vma_iterator *vmi, struct mm_struct *mm,
		  unsigned long start, size_t len, struct list_head *uf,
		  bool unlock)
{
	unsigned long end;
	struct vm_area_struct *vma;

	if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;
	// 确定地址范围, 都是页对齐的
	end = start + PAGE_ALIGN(len);
	if (end == start)
		return -EINVAL;

	 /* arch_unmap() might do unmaps itself.  */
	arch_unmap(mm, start, end);

	/* Find the first overlapping VMA
	找到第一个与start有交集的VMA
	*/
	vma = vma_find(vmi, end);
	if (!vma) {// 没有有交叉的vma, 没必要继续了
		if (unlock)
			mmap_write_unlock(mm);
		return 0;
	}

	return do_vmi_align_munmap(vmi, vma, mm, start, end, uf, unlock);
}

/* do_munmap() - Wrapper function for non-maple tree aware do_munmap() calls.
 * @mm: The mm_struct
 * @start: The start address to munmap
 * @len: The length to be munmapped.
 * @uf: The userfaultfd list_head
 *
 * Return: 0 on success, error otherwise.
 */
int do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
	      struct list_head *uf)
{
	VMA_ITERATOR(vmi, mm, start);

	return do_vmi_munmap(&vmi, mm, start, len, uf, false);
}

//mmap文件和vma
unsigned long mmap_region(struct file *file, unsigned long addr,
		unsigned long len, vm_flags_t vm_flags, unsigned long pgoff,
		struct list_head *uf)
{
	// 是current的mm吗
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = NULL;
	struct vm_area_struct *next, *prev, *merge;
	pgoff_t pglen = len >> PAGE_SHIFT;
	unsigned long charged = 0;
	unsigned long end = addr + len;
	unsigned long merge_start = addr, merge_end = end;
	pgoff_t vm_pgoff;
	int error;
	// 这里是maple tree相关的, 生成一个有状态的mas迭代器指向mm的vma那些
	// 马上方便查找和删除
	VMA_ITERATOR(vmi, mm, addr);

	/* Check against address space limit.
	检查地址空间的限制
	*/
	if (!may_expand_vm(mm, vm_flags, len >> PAGE_SHIFT)) {
		unsigned long nr_pages;

		/*
		 * MAP_FIXED may remove pages of mappings that intersects with
		 * requested mapping. Account for the pages it would unmap.
		   MAP_FIXED可能会删除与请求映射相交的映射的页面。计算它将取消映射的页面。
		 */
		nr_pages = count_vma_pages_range(mm, addr, end);

		if (!may_expand_vm(mm, vm_flags,
					(len >> PAGE_SHIFT) - nr_pages))
			return -ENOMEM;
	}

	/* Unmap any existing mapping in the area
	先把范围内的vma全部unmap
	理解是因为要重新映射,用户肯定是不要这些旧的了
	*/
	if (do_vmi_munmap(&vmi, mm, addr, len, uf, false))
		return -ENOMEM;

	/*
	 * Private writable mapping: check memory availability
	   私有可写映射：检查内存可用性
	 */
	if (accountable_mapping(file, vm_flags)) {
		charged = len >> PAGE_SHIFT;
		if (security_vm_enough_memory_mm(mm, charged))
			return -ENOMEM;
		vm_flags |= VM_ACCOUNT;
	}

	next = vma_next(&vmi);
	prev = vma_prev(&vmi);
	if (vm_flags & VM_SPECIAL) {
		if (prev)
			vma_iter_next_range(&vmi);
		goto cannot_expand;
	}

	/* Attempt to expand an old mapping */
	/* Check next
	如果下一个vma的起始地址刚好是我们新范围的末尾
	尝试合并
	*/
	if (next && next->vm_start == end && !vma_policy(next) &&
	    can_vma_merge_before(next, vm_flags, NULL, file, pgoff+pglen,
				 NULL_VM_UFFD_CTX, NULL)) {
		merge_end = next->vm_end;
		vma = next;
		// 如果可以merge的话, vm_pgoff就是新vma的pgoff
		// 计算方式就是next的pgoff减去len的这些页数
		vm_pgoff = next->vm_pgoff - pglen;
	}

	/* Check prev
	如果上一个vma的结束地址刚好是我们新范围的起始
	==============================
	这个判断是和上一个判断有关系的, 所以需要结合vma是不是null（能不能与next合并）
	来改变这里merge_after的判断方式
	*/
	if (prev && prev->vm_end == addr && !vma_policy(prev) &&
	    (vma ? /* vma不为null, 就是可以与next合并 */
			can_vma_merge_after(prev, vm_flags, vma->anon_vma, file,pgoff, vma->vm_userfaultfd_ctx, NULL) :
		    can_vma_merge_after(prev, vm_flags, NULL, file, pgoff,
				       NULL_VM_UFFD_CTX, NULL)
		)
	) {
		merge_start = prev->vm_start; // 如果可以merge prev,那么新vma的start就是prev的start
		vma = prev; // 如果prev可以merge, 马上vma_expand的起始vma参数就是prev了
		vm_pgoff = prev->vm_pgoff; // 相应的pgoff也要更新
	} else if (prev) {
		vma_iter_next_range(&vmi);
	}

	/* Actually expand, if possible */
	if (vma && // 只要vma不为null, 就是可以merge.
		// 其中的vma, merge_start, merge_end, vm_pgoff这些参数刚才都考虑到prev和next的merge情况改变了
		// 所以这里直接开始merge
	    !vma_expand(&vmi, vma, merge_start, merge_end, vm_pgoff, next)) {
		khugepaged_enter_vma(vma, vm_flags);
		goto expanded; // 扩展成功直接跳过新建vma的步骤
	}

	if (vma == prev)
		vma_iter_set(&vmi, addr);

// 这里是需要新建vma的情况
cannot_expand:

	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	vma = vm_area_alloc(mm);
	if (!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}

	vma_iter_config(&vmi, addr, end);
	vma->vm_start = addr; // 这里的范围就是一开始的mmap系统调用要求的范围了
	vma->vm_end = end;
	vm_flags_init(vma, vm_flags);
	vma->vm_page_prot = vm_get_page_prot(vm_flags);
	vma->vm_pgoff = pgoff;

	if (file) {//如果是有文件的mmap
		if (vm_flags & VM_SHARED) { // 共享的非匿名的映射
			error = mapping_map_writable(file->f_mapping);
			if (error)
				goto free_vma;
		}

		vma->vm_file = get_file(file);
		/* 调用fops的mmap回调
		建立他俩的mmap的关系
		==============
		一般file的fops mmap回调会给vma设置上自定义的ops（包含map, fault等）
		规定缺页的时候, 需要map的时候, 如何执行具体过程, 获取文件页面 */
		error = call_mmap(file, vma);
		if (error)
			goto unmap_and_free_vma;

		/*
		 * Expansion is handled above, merging is handled below.
		 * Drivers should not alter the address of the VMA.
		 */
		error = -EINVAL;
		if (WARN_ON((addr != vma->vm_start)))
			goto close_and_free_vma;

		vma_iter_config(&vmi, addr, end);
		/*
		 * If vm_flags changed after call_mmap(), we should try merge
		 * vma again as we may succeed this time.
		 */
		if (unlikely(vm_flags != vma->vm_flags && prev)) {
			merge = vma_merge(&vmi, mm, prev, vma->vm_start,
				    vma->vm_end, vma->vm_flags, NULL,
				    vma->vm_file, vma->vm_pgoff, NULL,
				    NULL_VM_UFFD_CTX, NULL);
			if (merge) {
				/*
				 * ->mmap() can change vma->vm_file and fput
				 * the original file. So fput the vma->vm_file
				 * here or we would add an extra fput for file
				 * and cause general protection fault
				 * ultimately.
				 */
				fput(vma->vm_file);
				vm_area_free(vma);
				vma = merge;
				/* Update vm_flags to pick up the change. */
				vm_flags = vma->vm_flags;
				goto unmap_writable;
			}
		}

		vm_flags = vma->vm_flags;
	} else if (vm_flags & VM_SHARED) { // 如果是共享的内存分配映射
		error = shmem_zero_setup(vma);
		if (error)
			goto free_vma;
	} else { // 这里就是私有的匿名的情况?
		vma_set_anonymous(vma);
	}

	if (map_deny_write_exec(vma, vma->vm_flags)) {
		error = -EACCES;
		goto close_and_free_vma;
	}

	/* Allow architectures to sanity-check the vm_flags */
	error = -EINVAL;
	if (!arch_validate_flags(vma->vm_flags))
		goto close_and_free_vma;

	error = -ENOMEM;
	if (vma_iter_prealloc(&vmi, vma))
		goto close_and_free_vma;

	/* Lock the VMA since it is modified after insertion into VMA tree */
	vma_start_write(vma);
	vma_iter_store(&vmi, vma);
	mm->map_count++;
	if (vma->vm_file) {
		i_mmap_lock_write(vma->vm_file->f_mapping);
		if (vma->vm_flags & VM_SHARED)
			mapping_allow_writable(vma->vm_file->f_mapping);

		flush_dcache_mmap_lock(vma->vm_file->f_mapping);
		vma_interval_tree_insert(vma, &vma->vm_file->f_mapping->i_mmap);
		flush_dcache_mmap_unlock(vma->vm_file->f_mapping);
		i_mmap_unlock_write(vma->vm_file->f_mapping);
	}

	/*
	 * vma_merge() calls khugepaged_enter_vma() either, the below
	 * call covers the non-merge case.
	 */
	khugepaged_enter_vma(vma, vma->vm_flags);

	/* Once vma denies write, undo our temporary denial count */
unmap_writable:
	if (file && vm_flags & VM_SHARED)
		mapping_unmap_writable(file->f_mapping);
	file = vma->vm_file;
	ksm_add_vma(vma);
expanded:
	perf_event_mmap(vma);

	vm_stat_account(mm, vm_flags, len >> PAGE_SHIFT);
	if (vm_flags & VM_LOCKED) {
		if ((vm_flags & VM_SPECIAL) || vma_is_dax(vma) ||
					is_vm_hugetlb_page(vma) ||
					vma == get_gate_vma(current->mm))
			vm_flags_clear(vma, VM_LOCKED_MASK);
		else
			mm->locked_vm += (len >> PAGE_SHIFT);
	}

	if (file)
		uprobe_mmap(vma);

	/*
	 * New (or expanded) vma always get soft dirty status.
	 * Otherwise user-space soft-dirty page tracker won't
	 * be able to distinguish situation when vma area unmapped,
	 * then new mapped in-place (which must be aimed as
	 * a completely new data area).
	 */
	vm_flags_set(vma, VM_SOFTDIRTY);

	vma_set_page_prot(vma);

	validate_mm(mm);
	return addr;

close_and_free_vma:
	if (file && vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);

	if (file || vma->vm_file) {
unmap_and_free_vma:
		fput(vma->vm_file);
		vma->vm_file = NULL;

		vma_iter_set(&vmi, vma->vm_end);
		/* Undo any partial mapping done by a device driver. */
		unmap_region(mm, &vmi.mas, vma, prev, next, vma->vm_start,
			     vma->vm_end, vma->vm_end, true);
	}
	if (file && (vm_flags & VM_SHARED))
		mapping_unmap_writable(file->f_mapping);
free_vma:
	vm_area_free(vma);
unacct_error:
	if (charged)
		vm_unacct_memory(charged);
	validate_mm(mm);
	return error;
}

/* unmap指定的地址范围 */
static int __vm_munmap(unsigned long start, size_t len, bool unlock)
{
	int ret;
	struct mm_struct *mm = current->mm;
	LIST_HEAD(uf);
	VMA_ITERATOR(vmi, mm, start);

	if (mmap_write_lock_killable(mm))
		return -EINTR;
	/* unmap这个范围 */
	ret = do_vmi_munmap(&vmi, mm, start, len, &uf, unlock);
	if (ret || !unlock)
		mmap_write_unlock(mm);

	userfaultfd_unmap_complete(mm, &uf);
	return ret;
}

int vm_munmap(unsigned long start, size_t len)
{
	return __vm_munmap(start, len, false);
}
EXPORT_SYMBOL(vm_munmap);

SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	addr = untagged_addr(addr);
	return __vm_munmap(addr, len, true);
}


/*
 * Emulation of deprecated remap_file_pages() syscall.
 
 */
SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
		unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
{

	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long populate = 0;
	unsigned long ret = -EINVAL;
	struct file *file;

	pr_warn_once("%s (%d) uses deprecated remap_file_pages() syscall. See Documentation/mm/remap_file_pages.rst.\n",
		     current->comm, current->pid);

	if (prot)
		return ret;
	start = start & PAGE_MASK;
	size = size & PAGE_MASK;

	if (start + size <= start)
		return ret;

	/* Does pgoff wrap? */
	if (pgoff + (size >> PAGE_SHIFT) < pgoff)
		return ret;

	if (mmap_write_lock_killable(mm))
		return -EINTR;
		//查找vma
	vma = vma_lookup(mm, start);

	if (!vma || !(vma->vm_flags & VM_SHARED))
		goto out;

	if (start + size > vma->vm_end) {
		VMA_ITERATOR(vmi, mm, vma->vm_end);
		struct vm_area_struct *next, *prev = vma;

		for_each_vma_range(vmi, next, start + size) {
			/* hole between vmas ? */
			if (next->vm_start != prev->vm_end)
				goto out;

			if (next->vm_file != vma->vm_file)
				goto out;

			if (next->vm_flags != vma->vm_flags)
				goto out;

			if (start + size <= next->vm_end)
				break;

			prev = next;
		}

		if (!next)
			goto out;
	}

	prot |= vma->vm_flags & VM_READ ? PROT_READ : 0;
	prot |= vma->vm_flags & VM_WRITE ? PROT_WRITE : 0;
	prot |= vma->vm_flags & VM_EXEC ? PROT_EXEC : 0;

	flags &= MAP_NONBLOCK;
	flags |= MAP_SHARED | MAP_FIXED | MAP_POPULATE;
	if (vma->vm_flags & VM_LOCKED)
		flags |= MAP_LOCKED;

	file = get_file(vma->vm_file);
	/* 进行mmap */
	ret = do_mmap(vma->vm_file, start, size,
			prot, flags, 0, pgoff, &populate, NULL);
	fput(file);
out:
	mmap_write_unlock(mm);
	if (populate)
		mm_populate(ret, populate);
	if (!IS_ERR_VALUE(ret))
		ret = 0;
	return ret;
}

/*
unmap指定vma 的一部分或者全部
 * do_vma_munmap() - Unmap a full or partial vma.
 * @vmi: The vma iterator pointing at the vma
 * @vma: The first vma to be munmapped
 * @start: the start of the address to unmap
 * @end: The end of the address to unmap
 * @uf: The userfaultfd list_head
 * @unlock: Drop the lock on success
 *
 * unmaps a VMA mapping when the vma iterator is already in position.
 * Does not handle alignment.
 *
 * Return: 0 on success drops the lock of so directed, error on failure and will
 * still hold the lock.
 */
int do_vma_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
		unsigned long start, unsigned long end, struct list_head *uf,
		bool unlock)
{
	struct mm_struct *mm = vma->vm_mm;

	arch_unmap(mm, start, end);
	return do_vmi_align_munmap(vmi, vma, mm, start, end, uf, unlock);
}

/*
 * do_brk_flags() - Increase the brk vma if the flags match.
 提升brk边界
 * @vmi: The vma iterator
 * @addr: The start address
 * @len: The length of the increase
 * @vma: The vma,
 * @flags: The VMA Flags
 *
 * Extend the brk VMA from addr to addr + len.  If the VMA is NULL or the flags
 * do not match then create a new anonymous VMA.  Eventually we may be able to
 * do some brk-specific accounting here.
 */
static int do_brk_flags(struct vma_iterator *vmi, struct vm_area_struct *vma,
		unsigned long addr, unsigned long len, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vma_prepare vp;

	/*
	 * Check against address space limits by the changed size
	 * Note: This happens *after* clearing old mappings in some code paths.
	 */
	flags |= VM_DATA_DEFAULT_FLAGS | VM_ACCOUNT | mm->def_flags;
	if (!may_expand_vm(mm, flags, len >> PAGE_SHIFT))
		return -ENOMEM;

	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	if (security_vm_enough_memory_mm(mm, len >> PAGE_SHIFT))
		return -ENOMEM;

	/*
	 * Expand the existing vma if possible; Note that singular lists do not
	 * occur after forking, so the expand will only happen on new VMAs.
	   看看能不能扩展现有的vma. 
	 */
	if (vma && vma->vm_end == addr && !vma_policy(vma) &&
	    can_vma_merge_after(vma, flags, NULL, NULL,
				addr >> PAGE_SHIFT, NULL_VM_UFFD_CTX, NULL)) {
		
		vma_iter_config(vmi, vma->vm_start, addr + len);
		if (vma_iter_prealloc(vmi, vma))
			goto unacct_fail;

		vma_start_write(vma); //加锁

		init_vma_prep(&vp, vma);
		vma_prepare(&vp);
		vma_adjust_trans_huge(vma, vma->vm_start, addr + len, 0);
		vma->vm_end = addr + len; //调整结束后, 改变vma的边界
		vm_flags_set(vma, VM_SOFTDIRTY);
		vma_iter_store(vmi, vma);

		vma_complete(&vp, vmi, mm);
		khugepaged_enter_vma(vma, flags);

		//以调整
		goto out;
	}

	// 后面以创建新vma来调整brk
	if (vma)
		vma_iter_next_range(vmi);
	/* create a vma struct for an anonymous mapping */
	vma = vm_area_alloc(mm);
	if (!vma)
		goto unacct_fail;

	vma_set_anonymous(vma);
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_pgoff = addr >> PAGE_SHIFT;
	vm_flags_init(vma, flags);
	vma->vm_page_prot = vm_get_page_prot(flags);
	vma_start_write(vma);
	if (vma_iter_store_gfp(vmi, vma, GFP_KERNEL))
		goto mas_store_fail;

	mm->map_count++;
	validate_mm(mm);
	ksm_add_vma(vma);

out:
	perf_event_mmap(vma);
	mm->total_vm += len >> PAGE_SHIFT;
	mm->data_vm += len >> PAGE_SHIFT;
	if (flags & VM_LOCKED)
		mm->locked_vm += (len >> PAGE_SHIFT);
	vm_flags_set(vma, VM_SOFTDIRTY);
	
	return 0;

mas_store_fail:
	vm_area_free(vma);
unacct_fail:
	vm_unacct_memory(len >> PAGE_SHIFT);
	return -ENOMEM;
}

/*brk分配内存
request是申请的长度  */
int vm_brk_flags(unsigned long addr, unsigned long request, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = NULL;
	unsigned long len;
	int ret;
	bool populate;
	LIST_HEAD(uf);
	VMA_ITERATOR(vmi, mm, addr);

	len = PAGE_ALIGN(request);
	if (len < request)
		return -ENOMEM;
	if (!len)
		return 0;

	/* Until we need other flags, refuse anything except VM_EXEC. */
	if ((flags & (~VM_EXEC)) != 0)
		return -EINVAL;

	if (mmap_write_lock_killable(mm))
		return -EINTR;
	/* 进行一些检查 */
	ret = check_brk_limits(addr, len);
	if (ret)
		goto limits_failed;
	/* 为什么这里要unmap */
	ret = do_vmi_munmap(&vmi, mm, addr, len, &uf, 0);
	if (ret)
		goto munmap_failed;

	vma = vma_prev(&vmi);
	//分配内存时,调整brk的边界
	ret = do_brk_flags(&vmi, vma, addr, len, flags);
	populate = ((mm->def_flags & VM_LOCKED) != 0);
	mmap_write_unlock(mm);
	userfaultfd_unmap_complete(mm, &uf);
	if (populate && !ret)
		mm_populate(addr, len);
	return ret;

munmap_failed:
limits_failed:
	mmap_write_unlock(mm);
	return ret;
}
EXPORT_SYMBOL(vm_brk_flags);

//brk分配内存
int vm_brk(unsigned long addr, unsigned long len)
{
	return vm_brk_flags(addr, len, 0);
}
EXPORT_SYMBOL(vm_brk);

/* Release all mmaps.
退出mmap是干什么？
进程退出
*/
void exit_mmap(struct mm_struct *mm)
{
	struct mmu_gather tlb;
	struct vm_area_struct *vma;
	unsigned long nr_accounted = 0;
	MA_STATE(mas, &mm->mm_mt, 0, 0);
	int count = 0;

	/* mm's last user has gone, and its about to be pulled down */
	mmu_notifier_release(mm);

	mmap_read_lock(mm);
	arch_exit_mmap(mm);

	vma = mas_find(&mas, ULONG_MAX);
	if (!vma) {
		/* Can happen if dup_mmap() received an OOM */
		mmap_read_unlock(mm);
		return;
	}

	lru_add_drain();
	flush_cache_mm(mm);
	tlb_gather_mmu_fullmm(&tlb, mm);
	/* update_hiwater_rss(mm) here? but nobody should be looking */
	/* Use ULONG_MAX here to ensure all VMAs in the mm are unmapped
	解除映射全部的vma
	*/
	unmap_vmas(&tlb, &mas, vma, 0, 
		ULONG_MAX, ULONG_MAX, false);
	mmap_read_unlock(mm);

	/*
	 * Set MMF_OOM_SKIP to hide this task from the oom killer/reaper
	 * because the memory has been already freed.
	 */
	set_bit(MMF_OOM_SKIP, &mm->flags);
	mmap_write_lock(mm);
	mt_clear_in_rcu(&mm->mm_mt);
	mas_set(&mas, vma->vm_end);
	/* 释放页表 */
	free_pgtables(&tlb, &mas, vma, FIRST_USER_ADDRESS,
		      USER_PGTABLES_CEILING, true);
	tlb_finish_mmu(&tlb);

	/*
	 * Walk the list again, actually closing and freeing it, with preemption
	 * enabled, without holding any MM locks besides the unreachable
	 * mmap_write_lock.
	 */
	mas_set(&mas, vma->vm_end);
	do {
		if (vma->vm_flags & VM_ACCOUNT)
			nr_accounted += vma_pages(vma);
		/* 从mm移除这个vma？ */
		remove_vma(vma, true);
		count++;
		cond_resched();
	} while ((vma = mas_find(&mas, ULONG_MAX)) != NULL);

	BUG_ON(count != mm->map_count);

	trace_exit_mmap(mm);
	__mt_destroy(&mm->mm_mt);
	mmap_write_unlock(mm);
	vm_unacct_memory(nr_accounted);
}

/* Insert vm structure into process list sorted by address
 * and into the inode's i_mmap tree.  If vm_file is non-NULL
 * then i_mmap_rwsem is taken here.
   把vm结构插入到进程列表中, 按地址排序, 并插入到inode的i_mmap树中
   如果vm_file不为NULL, 那么i_mmap_rwsem在这里被获取
 */
int insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma)
{
	unsigned long charged = vma_pages(vma);


	if (find_vma_intersection(mm, vma->vm_start, vma->vm_end))
		return -ENOMEM;/* 如果有现存的vma与这个新vma是交叉的 */

	if ((vma->vm_flags & VM_ACCOUNT) &&
	     security_vm_enough_memory_mm(mm, charged))
		return -ENOMEM;

	/*
	 * The vm_pgoff of a purely anonymous vma should be irrelevant
	 * until its first write fault, when page's anon_vma and index
	 * are set.  But now set the vm_pgoff it will almost certainly
	 * end up with (unless mremap moves it elsewhere before that
	 * first wfault), so /proc/pid/maps tells a consistent story.
	 *
	 * By setting it to reflect the virtual start address of the
	 * vma, merges and splits can happen in a seamless way, just
	 * using the existing file pgoff checks and manipulations.
	 * Similarly in do_mmap and in do_brk_flags.
	 */
	if (vma_is_anonymous(vma)) {
		BUG_ON(vma->anon_vma);
		vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
	}

	if (vma_link(mm, vma)) {/* 这里真正把vma插入mm */
		vm_unacct_memory(charged);
		return -ENOMEM;
	}

	return 0;
}

/*
要从vmap指定的vma进行remap
从pgoff对应的addr，remap到addr和len
==
感觉就是新建一个目标范围的vma，然后直接设置pgoff？
 * Copy the vma structure to a new location in the same mm,
 * prior to moving page table entries, to effect an mremap move.
 */
struct vm_area_struct *copy_vma(struct vm_area_struct **vmap,
	unsigned long addr, unsigned long len, pgoff_t pgoff,
	bool *need_rmap_locks)
{
	struct vm_area_struct *vma = *vmap;
	unsigned long vma_start = vma->vm_start;
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *new_vma, *prev;
	bool faulted_in_anon_vma = true;
	VMA_ITERATOR(vmi, mm, addr);

	/*
	 * If anonymous vma has not yet been faulted, update new pgoff
	 * to match new location, to increase its chance of merging.
	 */
	if (unlikely(vma_is_anonymous(vma) && !vma->anon_vma)) {
		pgoff = addr >> PAGE_SHIFT;
		faulted_in_anon_vma = false;
	}

	/*  */
	new_vma = find_vma_prev(mm, addr, &prev);
	/* new vma可能是addr所在的vma，也可能是下一个vma */
	if (new_vma && new_vma->vm_start < addr + len)
		return NULL;	/* 说明是addr处没有vma，下一个vma与参数指定
	范围交叉了，should never get here */

	/* 现在要么是new vma包含addr
	要么是new vma是[addr，addr+len]后面的vma */
	new_vma = vma_merge(&vmi, mm, prev,
				 addr, addr + len, vma->vm_flags,
			    vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma),
			    vma->vm_userfaultfd_ctx, anon_vma_name(vma));
	if (new_vma) {/* 如果是合并了 */
		/*
		 * Source vma may have been merged into new_vma
		 */
		if (unlikely(vma_start >= new_vma->vm_start &&
			     vma_start < new_vma->vm_end)) {
			/*
			 * The only way we can get a vma_merge with
			 * self during an mremap is if the vma hasn't
			 * been faulted in yet and we were allowed to
			 * reset the dst vma->vm_pgoff to the
			 * destination address of the mremap to allow
			 * the merge to happen. mremap must change the
			 * vm_pgoff linearity between src and dst vmas
			 * (in turn preventing a vma_merge) to be
			 * safe. It is only safe to keep the vm_pgoff
			 * linear if there are no pages mapped yet.
			 */
			VM_BUG_ON_VMA(faulted_in_anon_vma, new_vma);
			*vmap = vma = new_vma;
		}
		*need_rmap_locks = (new_vma->vm_pgoff <= vma->vm_pgoff);
	} else {/* 没有合并 */
		new_vma = vm_area_dup(vma);
		if (!new_vma)
			goto out;
		/* new vma的范围直接就是remap的范围
		pgoff就是老范围的pgoff
		表示是re map */
		new_vma->vm_start = addr;
		new_vma->vm_end = addr + len;
		new_vma->vm_pgoff = pgoff;
		if (vma_dup_policy(vma, new_vma))
			goto out_free_vma;
		if (anon_vma_clone(new_vma, vma))
			goto out_free_mempol;
		/* 这个属性直接是刚才复制vma的时候memcpy的？ */
		if (new_vma->vm_file)
			get_file(new_vma->vm_file);
		if (new_vma->vm_ops && new_vma->vm_ops->open)
			new_vma->vm_ops->open(new_vma);
		/* 把新vma插入mm */
		if (vma_link(mm, new_vma))
			goto out_vma_link;
		*need_rmap_locks = false;
	}
	return new_vma;

out_vma_link:
	if (new_vma->vm_ops && new_vma->vm_ops->close)
		new_vma->vm_ops->close(new_vma);

	if (new_vma->vm_file)
		fput(new_vma->vm_file);

	unlink_anon_vmas(new_vma);
out_free_mempol:
	mpol_put(vma_policy(new_vma));
out_free_vma:
	vm_area_free(new_vma);
out:
	return NULL;
}

/*
 * Return true if the calling process may expand its vm space by the passed
 * number of pages
   检查这个进程是否可以扩展它的vm空间
 */
bool may_expand_vm(struct mm_struct *mm, vm_flags_t flags, unsigned long npages)
{
	if (mm->total_vm + npages > rlimit(RLIMIT_AS) >> PAGE_SHIFT)
		return false;

	if (is_data_mapping(flags) &&
	    mm->data_vm + npages > rlimit(RLIMIT_DATA) >> PAGE_SHIFT) {
		/* Workaround for Valgrind */
		if (rlimit(RLIMIT_DATA) == 0 &&
		    mm->data_vm + npages <= rlimit_max(RLIMIT_DATA) >> PAGE_SHIFT)
			return true;

		pr_warn_once("%s (%d): VmData %lu exceed data ulimit %lu. Update limits%s.\n",
			     current->comm, current->pid,
			     (mm->data_vm + npages) << PAGE_SHIFT,
			     rlimit(RLIMIT_DATA),
			     ignore_rlimit_data ? "" : " or use boot option ignore_rlimit_data");

		if (!ignore_rlimit_data)
			return false;
	}

	return true;
}

// 扩展vma的时候,统计mm的内存使用信息
void vm_stat_account(struct mm_struct *mm, vm_flags_t flags, long npages)
{
	WRITE_ONCE(mm->total_vm, READ_ONCE(mm->total_vm)+npages);

	if (is_exec_mapping(flags))
		mm->exec_vm += npages;
	else if (is_stack_mapping(flags))
		mm->stack_vm += npages;
	else if (is_data_mapping(flags))
		mm->data_vm += npages;
}

static vm_fault_t special_mapping_fault(struct vm_fault *vmf);

/*
为什么是空函数
 * Having a close hook prevents vma merging regardless of flags.
 */
static void special_mapping_close(struct vm_area_struct *vma)
{
}

static const char *special_mapping_name(struct vm_area_struct *vma)
{
	return ((struct vm_special_mapping *)vma->vm_private_data)->name;
}
/* special vma的remap回调函数
也是调用vma的sm的remap回调 */
static int special_mapping_mremap(struct vm_area_struct *new_vma)
{
	struct vm_special_mapping *sm = new_vma->vm_private_data;

	if (WARN_ON_ONCE(current->mm != new_vma->vm_mm))
		return -EFAULT;

	if (sm->mremap)
		return sm->mremap(sm, new_vma);

	return 0;
}
/* special vma的ops的回调 */
static int special_mapping_split(struct vm_area_struct *vma, unsigned long addr)
{
	/*
	 * Forbid splitting special mappings - kernel has expectations over
	 * the number of pages in mapping. Together with VM_DONTEXPAND
	 * the size of vma should stay the same over the special mapping's
	 * lifetime.
	 */
	return -EINVAL;
}
/* special mapping的ops */
static const struct vm_operations_struct special_mapping_vmops = {
	.close = special_mapping_close,
	.fault = special_mapping_fault,
	.mremap = special_mapping_mremap,
	.name = special_mapping_name,
	/* vDSO code relies that VVAR can't be accessed remotely */
	.access = NULL,
	.may_split = special_mapping_split,
};

static const struct vm_operations_struct legacy_special_mapping_vmops = {
	.close = special_mapping_close,
	.fault = special_mapping_fault,
};
/* special vma的fault函数
这种vma的缺页不是去申请，而是从vma的一个page数组里面拿 */
static vm_fault_t special_mapping_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	pgoff_t pgoff;
	struct page **pages;

	if (vma->vm_ops == &legacy_special_mapping_vmops) {
		pages = vma->vm_private_data;
	} else {
		struct vm_special_mapping *sm = vma->vm_private_data;

		if (sm->fault)
			return sm->fault(sm, vmf->vma, vmf);

		pages = sm->pages;
	}

	for (pgoff = vmf->pgoff; pgoff && *pages; ++pages)
		pgoff--;

	if (*pages) {
		struct page *page = *pages;
		get_page(page);
		vmf->page = page;
		return 0;
	}

	return VM_FAULT_SIGBUS;
}
/* 什么是special mapping？
感觉就是手动创建一个指定范围地址的vma插入mm了， 估计用作特殊用途吧*/
static struct vm_area_struct *__install_special_mapping(
	struct mm_struct *mm,
	unsigned long addr, unsigned long len,
	unsigned long vm_flags, void *priv,
	const struct vm_operations_struct *ops)
{
	int ret;
	struct vm_area_struct *vma;

	/* 创建一个vma，这个mm的vma， 就是从slab创建vma， 建立与mm的关系 */
	vma = vm_area_alloc(mm);
	if (unlikely(vma == NULL))
		return ERR_PTR(-ENOMEM);

	vma->vm_start = addr;
	vma->vm_end = addr + len;

	vm_flags_init(vma, (vm_flags | mm->def_flags |
		      VM_DONTEXPAND | VM_SOFTDIRTY) & ~VM_LOCKED_MASK);
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	vma->vm_ops = ops;
	vma->vm_private_data = priv;

	/* 把这个vma插入这个mm */
	ret = insert_vm_struct(mm, vma);
	if (ret)
		goto out;

	vm_stat_account(mm, vma->vm_flags, len >> PAGE_SHIFT);

	perf_event_mmap(vma);

	return vma;

out:
	vm_area_free(vma);
	return ERR_PTR(ret);
}

/* 判断是不是special mapping？ */
bool vma_is_special_mapping(const struct vm_area_struct *vma,
	const struct vm_special_mapping *sm)
{
	return vma->vm_private_data == sm &&
		(vma->vm_ops == &special_mapping_vmops ||
		 vma->vm_ops == &legacy_special_mapping_vmops);
}

/*
 * Called with mm->mmap_lock held for writing.
 * Insert a new vma covering the given region, with the given flags.
 * Its pages are supplied by the given array of struct page *.
 * The array can be shorter than len >> PAGE_SHIFT if it's null-terminated.
 * The region past the last page supplied will always produce SIGBUS.
 * The array pointer and the pages it points to are assumed to stay alive
 * for as long as this mapping might exist.
 */
struct vm_area_struct *_install_special_mapping(
	struct mm_struct *mm,
	unsigned long addr, unsigned long len,
	unsigned long vm_flags, const struct vm_special_mapping *spec)
{
	return __install_special_mapping(mm, addr, len, vm_flags, (void *)spec,
					&special_mapping_vmops);
}

int install_special_mapping(struct mm_struct *mm,
			    unsigned long addr, unsigned long len,
			    unsigned long vm_flags, struct page **pages)
{
	struct vm_area_struct *vma = __install_special_mapping(
		mm, addr, len, vm_flags, (void *)pages,
		&legacy_special_mapping_vmops);

	return PTR_ERR_OR_ZERO(vma);
}

static DEFINE_MUTEX(mm_all_locks_mutex);
/* 锁住mm的一个vma的av */
static void vm_lock_anon_vma(struct mm_struct *mm, struct anon_vma *anon_vma)
{
	if (!test_bit(0, (unsigned long *) &anon_vma->root->rb_root.rb_root.rb_node)) {
		/*
		 * The LSB of head.next can't change from under us
		 * because we hold the mm_all_locks_mutex.
		 */
		down_write_nest_lock(&anon_vma->root->rwsem, &mm->mmap_lock);
		/*
		 * We can safely modify head.next after taking the
		 * anon_vma->root->rwsem. If some other vma in this mm shares
		 * the same anon_vma we won't take it again.
		 *
		 * No need of atomic instructions here, head.next
		 * can't change from under us thanks to the
		 * anon_vma->root->rwsem.
		 */
		if (__test_and_set_bit(0, (unsigned long *)
				       &anon_vma->root->rb_root.rb_root.rb_node))
			BUG();
	}
}
/* mapping是是属于mm的其中一个vma的， 这里加锁这个mapping */
static void vm_lock_mapping(struct mm_struct *mm, struct address_space *mapping)
{
	if (!test_bit(AS_MM_ALL_LOCKS, &mapping->flags)) {
		/*
		 * AS_MM_ALL_LOCKS can't change from under us because
		 * we hold the mm_all_locks_mutex.
		 *
		 * Operations on ->flags have to be atomic because
		 * even if AS_MM_ALL_LOCKS is stable thanks to the
		 * mm_all_locks_mutex, there may be other cpus
		 * changing other bitflags in parallel to us.
		 */
		if (test_and_set_bit(AS_MM_ALL_LOCKS, &mapping->flags))
			BUG();
		down_write_nest_lock(&mapping->i_mmap_rwsem, &mm->mmap_lock);
	}
}

/*
 * 此操作会锁定针对某个 mm 上可能发生的所有 pte/vma/mm 相关操作。
 * 这包括 vmtruncate、try_to_unmap 和所有页面错误。
 *
 * The caller must take the mmap_lock in write mode before calling
 * mm_take_all_locks(). The caller isn't allowed to release the
 * mmap_lock until mm_drop_all_locks() returns.
 *
 * mmap_lock in write mode is required in order to block all operations
 * that could modify pagetables and free pages without need of
 * altering the vma layout. It's also needed in write mode to avoid new
 * anon_vmas to be associated with existing vmas.
 *
 * A single task can't take more than one mm_take_all_locks() in a row
 * or it would deadlock.
 *
 * The LSB in anon_vma->rb_root.rb_node and the AS_MM_ALL_LOCKS bitflag in
 * mapping->flags avoid to take the same lock twice, if more than one
 * vma in this mm is backed by the same anon_vma or address_space.
 *
 * We take locks in following order, accordingly to comment at beginning
 * of mm/rmap.c:
 *   - all hugetlbfs_i_mmap_rwsem_key locks (aka mapping->i_mmap_rwsem for
 *     hugetlb mapping);
 *   - all vmas marked locked
 *   - all i_mmap_rwsem locks;
 *   - all anon_vma->rwseml
 *
 * We can take all locks within these types randomly because the VM code
 * doesn't nest them and we protected from parallel mm_take_all_locks() by
 * mm_all_locks_mutex.
 *
 * mm_take_all_locks() and mm_drop_all_locks are expensive operations
 * that may have to take thousand of locks.
 *
 * mm_take_all_locks() can fail if it's interrupted by signals.
 */
int mm_take_all_locks(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct anon_vma_chain *avc;
	MA_STATE(mas, &mm->mm_mt, 0, 0);

	mmap_assert_write_locked(mm);

	mutex_lock(&mm_all_locks_mutex);

	/*
	 * vma_start_write() does not have a complement in mm_drop_all_locks()
	 * because vma_start_write() is always asymmetrical; it marks a VMA as
	 * being written to until mmap_write_unlock() or mmap_write_downgrade()
	 * is reached.
	 */
	/* 遍历mm的每一个vma */
	mas_for_each(&mas, vma, ULONG_MAX) {
		if (signal_pending(current))
			goto out_unlock;
		/* 加写锁 */
		vma_start_write(vma);
	}

	mas_set(&mas, 0);
	/* 锁住mm的每一个巨页的文件映射vma */
	mas_for_each(&mas, vma, ULONG_MAX) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->vm_file && vma->vm_file->f_mapping &&
				is_vm_hugetlb_page(vma))
			vm_lock_mapping(mm, vma->vm_file->f_mapping);
	}

	mas_set(&mas, 0);
	/* 锁住mm的每一个非巨页的文件映射vma */
	mas_for_each(&mas, vma, ULONG_MAX) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->vm_file && vma->vm_file->f_mapping &&
				!is_vm_hugetlb_page(vma))
			vm_lock_mapping(mm, vma->vm_file->f_mapping);
	}

	mas_set(&mas, 0);
	/* 这里是锁住每一个匿名的vma */
	mas_for_each(&mas, vma, ULONG_MAX) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->anon_vma)
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				vm_lock_anon_vma(mm, avc->anon_vma);
	}

	return 0;

out_unlock:
	mm_drop_all_locks(mm);
	return -EINTR;
}
/* 解锁匿名vma？ */
static void vm_unlock_anon_vma(struct anon_vma *anon_vma)
{
	if (test_bit(0, (unsigned long *) &anon_vma->root->rb_root.rb_root.rb_node)) {
		/*
		 * The LSB of head.next can't change to 0 from under
		 * us because we hold the mm_all_locks_mutex.
		 *
		 * We must however clear the bitflag before unlocking
		 * the vma so the users using the anon_vma->rb_root will
		 * never see our bitflag.
		 *
		 * No need of atomic instructions here, head.next
		 * can't change from under us until we release the
		 * anon_vma->root->rwsem.
		 */
		if (!__test_and_clear_bit(0, (unsigned long *)
					  &anon_vma->root->rb_root.rb_root.rb_node))
			BUG();
		anon_vma_unlock_write(anon_vma);
	}
}
/* 解锁映射文件的vma？ */
static void vm_unlock_mapping(struct address_space *mapping)
{
	if (test_bit(AS_MM_ALL_LOCKS, &mapping->flags)) {
		/*
		 * AS_MM_ALL_LOCKS can't change to 0 from under us
		 * because we hold the mm_all_locks_mutex.
		 */
		i_mmap_unlock_write(mapping);
		if (!test_and_clear_bit(AS_MM_ALL_LOCKS,
					&mapping->flags))
			BUG();
	}
}

/* 解锁mm， 释放所有vma的锁
 * The mmap_lock cannot be released by the caller until
 * mm_drop_all_locks() returns.
 */
void mm_drop_all_locks(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct anon_vma_chain *avc;
	/* 获取mm的vma tree */
	MA_STATE(mas, &mm->mm_mt, 0, 0);

	mmap_assert_write_locked(mm);
	BUG_ON(!mutex_is_locked(&mm_all_locks_mutex));
	/* 遍历mm的每一个vma */
	mas_for_each(&mas, vma, ULONG_MAX) {
		if (vma->anon_vma)
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				vm_unlock_anon_vma(avc->anon_vma);
		if (vma->vm_file && vma->vm_file->f_mapping)/* 如果是映射文件的vma */
			vm_unlock_mapping(vma->vm_file->f_mapping);
	}

	mutex_unlock(&mm_all_locks_mutex);
}

/*初始化pcp的vm计数器
 * initialise the percpu counter for VM
 */
void __init mmap_init(void)
{
	int ret;

	ret = percpu_counter_init(&vm_committed_as, 0, GFP_KERNEL);
	VM_BUG_ON(ret);
}

/*
内存增减后，重新初始化user reserve
 * Initialise sysctl_user_reserve_kbytes.
 *
 * This is intended to prevent a user from starting a single memory hogging
 * process, such that they cannot recover (kill the hog) in OVERCOMMIT_NEVER
 * mode.
 *
 * The default value is min(3% of free memory, 128MB)
 * 128MB is enough to recover with sshd/login, bash, and top/kill.
 */
static int init_user_reserve(void)
{
	unsigned long free_kbytes;

	free_kbytes = K(global_zone_page_state(NR_FREE_PAGES));

	sysctl_user_reserve_kbytes = min(free_kbytes / 32, 1UL << 17);
	return 0;
}
subsys_initcall(init_user_reserve);

/*内存热插拔之后重新初始化admin reserve
 * Initialise sysctl_admin_reserve_kbytes.
 *
 * The purpose of sysctl_admin_reserve_kbytes is to allow the sys admin
 * to log in and kill a memory hogging process.
 *
 * Systems with more than 256MB will reserve 8MB, enough to recover
 * with sshd, bash, and top in OVERCOMMIT_GUESS. Smaller systems will
 * only reserve 3% of free pages by default.
 */
static int init_admin_reserve(void)
{
	unsigned long free_kbytes;

	free_kbytes = K(global_zone_page_state(NR_FREE_PAGES));

	sysctl_admin_reserve_kbytes = min(free_kbytes / 32, 1UL << 13);
	return 0;
}
subsys_initcall(init_admin_reserve);

/*
 * 如果内存被添加或移除，则重新初始化user和admin保留。
 *
 * 默认的用户保留最大值是128MB，管理员保留的默认最大值是8MB。
 * 这些通常（但不总是）足够通过使用login/sshd、一个shell以及像top这样的工具
 * 从内存占用过多的进程中恢复。根据是否存在交换空间或恢复工具的变化，
 * 增加甚至禁用保留可能是合理的。因此，管理员可能已经更改了它们。
 *
 * If memory is added and the reserves have been eliminated or increased above
 * the default max, then we'll trust the admin.
 *
 * If memory is removed and there isn't enough free memory, then we
 * need to reset the reserves.
 *
 * Otherwise keep the reserve set by the admin.
 */
static int reserve_mem_notifier(struct notifier_block *nb,
			     unsigned long action, void *data)
{
	unsigned long tmp, free_kbytes;

	switch (action) {
	case MEM_ONLINE:
		/* Default max is 128MB. Leave alone if modified by operator. */
		tmp = sysctl_user_reserve_kbytes;
		if (0 < tmp && tmp < (1UL << 17))
			init_user_reserve();

		/* Default max is 8MB.  Leave alone if modified by operator. */
		tmp = sysctl_admin_reserve_kbytes;
		if (0 < tmp && tmp < (1UL << 13))
			init_admin_reserve();

		break;
	case MEM_OFFLINE:
		free_kbytes = K(global_zone_page_state(NR_FREE_PAGES));

		if (sysctl_user_reserve_kbytes > free_kbytes) {
			init_user_reserve();
			pr_info("vm.user_reserve_kbytes reset to %lu\n",
				sysctl_user_reserve_kbytes);
		}

		if (sysctl_admin_reserve_kbytes > free_kbytes) {
			init_admin_reserve();
			pr_info("vm.admin_reserve_kbytes reset to %lu\n",
				sysctl_admin_reserve_kbytes);
		}
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}
/* 内存热插拔的回调函数， 重新初始化reserve 内存 */
static int __meminit init_reserve_notifier(void)
{
	if (hotplug_memory_notifier(reserve_mem_notifier, DEFAULT_CALLBACK_PRI))
		pr_err("Failed registering memory add/remove notifier for admin reserve\n");

	return 0;
}
subsys_initcall(init_reserve_notifier);

/*
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *		 2000-2001 Christoph Rohland
 *		 2000-2001 SAP AG
 *		 2002 Red Hat Inc.
 * Copyright (C) 2002-2011 Hugh Dickins.
 * Copyright (C) 2011 Google Inc.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * tiny-shmem:
 * Copyright (c) 2004, 2008 Matt Mackall <mpm@selenic.com>
 *
 * This file is released under the GPL.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fileattr.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/export.h>
#include <linux/shmem_fs.h>
#include <linux/swap.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/fs_parser.h>
#include <linux/swapfile.h>
#include <linux/iversion.h>
#include "swap.h"

static struct vfsmount *shm_mnt;

#ifdef CONFIG_SHMEM
/*
 * This virtual memory filesystem is heavily based on the ramfs. It
 * extends ramfs by the ability to use swap and honor resource limits
 * which makes it a completely usable filesystem.
 */

#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/mman.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/percpu_counter.h>
#include <linux/falloc.h>
#include <linux/splice.h>
#include <linux/security.h>
#include <linux/swapops.h>
#include <linux/mempolicy.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/migrate.h>
#include <linux/highmem.h>
#include <linux/seq_file.h>
#include <linux/magic.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <uapi/linux/memfd.h>
#include <linux/rmap.h>
#include <linux/uuid.h>
#include <linux/quotaops.h>

#include <linux/uaccess.h>

#include "internal.h"

#define BLOCKS_PER_PAGE  (PAGE_SIZE/512)
#define VM_ACCT(size)    (PAGE_ALIGN(size) >> PAGE_SHIFT)

/* Pretend that each entry is of this size in directory's i_size */
#define BOGO_DIRENT_SIZE 20

/* Pretend that one inode + its dentry occupy this much memory */
#define BOGO_INODE_SIZE 1024

/* Symlink up to this size is kmalloc'ed instead of using a swappable page */
#define SHORT_SYMLINK_LEN 128

/*
 * shmem_fallocate communicates with shmem_fault or shmem_writepage via
 * inode->i_private (with i_rwsem making sure that it has only one user at
 * a time): we would prefer not to enlarge the shmem inode just for that.
 */
struct shmem_falloc {
	wait_queue_head_t *waitq; /* faults into hole wait for punch to end */
	pgoff_t start;		/* start of range currently being fallocated */
	pgoff_t next;		/* the next page offset to be fallocated */
	pgoff_t nr_falloced;	/* how many new pages have been fallocated */
	pgoff_t nr_unswapped;	/* how often writepage refused to swap out */
};

struct shmem_options {
	unsigned long long blocks;
	unsigned long long inodes;
	struct mempolicy *mpol;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	bool full_inums;
	int huge;
	int seen;
	bool noswap;
	unsigned short quota_types;
	struct shmem_quota_limits qlimits;
#define SHMEM_SEEN_BLOCKS 1
#define SHMEM_SEEN_INODES 2
#define SHMEM_SEEN_HUGE 4
#define SHMEM_SEEN_INUMS 8
#define SHMEM_SEEN_NOSWAP 16
#define SHMEM_SEEN_QUOTA 32
};

#ifdef CONFIG_TMPFS
static unsigned long shmem_default_max_blocks(void)
{
	return totalram_pages() / 2;
}

static unsigned long shmem_default_max_inodes(void)
{
	unsigned long nr_pages = totalram_pages();

	return min3(nr_pages - totalhigh_pages(), nr_pages / 2,
			ULONG_MAX / BOGO_INODE_SIZE);
}
#endif

static int shmem_swapin_folio(struct inode *inode, pgoff_t index,
			     struct folio **foliop, enum sgp_type sgp,
			     gfp_t gfp, struct vm_area_struct *vma,
			     vm_fault_t *fault_type);

static inline struct shmem_sb_info *SHMEM_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * shmem_file_setup pre-accounts the whole fixed size of a VM object,
 * for shared memory and for shared anonymous (/dev/zero) mappings
 * (unless MAP_NORESERVE and sysctl_overcommit_memory <= 1),
 * consistent with the pre-accounting of private mappings ...
 */
static inline int shmem_acct_size(unsigned long flags, loff_t size)
{
	return (flags & VM_NORESERVE) ?
		0 : security_vm_enough_memory_mm(current->mm, VM_ACCT(size));
}

static inline void shmem_unacct_size(unsigned long flags, loff_t size)
{
	if (!(flags & VM_NORESERVE))
		vm_unacct_memory(VM_ACCT(size));
}

static inline int shmem_reacct_size(unsigned long flags,
		loff_t oldsize, loff_t newsize)
{
	if (!(flags & VM_NORESERVE)) {
		if (VM_ACCT(newsize) > VM_ACCT(oldsize))
			return security_vm_enough_memory_mm(current->mm,
					VM_ACCT(newsize) - VM_ACCT(oldsize));
		else if (VM_ACCT(newsize) < VM_ACCT(oldsize))
			vm_unacct_memory(VM_ACCT(oldsize) - VM_ACCT(newsize));
	}
	return 0;
}

/*
 * ... whereas tmpfs objects are accounted incrementally as
 * pages are allocated, in order to allow large sparse files.
 * shmem_get_folio reports shmem_acct_block failure as -ENOSPC not -ENOMEM,
 * so that a failure on a sparse tmpfs mapping will give SIGBUS not OOM.
 */
static inline int shmem_acct_block(unsigned long flags, long pages)
{
	if (!(flags & VM_NORESERVE))
		return 0;

	return security_vm_enough_memory_mm(current->mm,
			pages * VM_ACCT(PAGE_SIZE));
}

static inline void shmem_unacct_blocks(unsigned long flags, long pages)
{
	if (flags & VM_NORESERVE)
		vm_unacct_memory(pages * VM_ACCT(PAGE_SIZE));
}
/* 内存的记账 */
static int shmem_inode_acct_block(struct inode *inode, long pages)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	int err = -ENOSPC;

	if (shmem_acct_block(info->flags, pages))
		return err;

	might_sleep();	/* when quotas */
	if (sbinfo->max_blocks) {
		if (percpu_counter_compare(&sbinfo->used_blocks,
					   sbinfo->max_blocks - pages) > 0)
			goto unacct;

		err = dquot_alloc_block_nodirty(inode, pages);
		if (err)
			goto unacct;

		percpu_counter_add(&sbinfo->used_blocks, pages);
	} else {
		err = dquot_alloc_block_nodirty(inode, pages);
		if (err)
			goto unacct;
	}

	return 0;

unacct:
	shmem_unacct_blocks(info->flags, pages);
	return err;
}

static void shmem_inode_unacct_blocks(struct inode *inode, long pages)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);

	might_sleep();	/* when quotas */
	dquot_free_block_nodirty(inode, pages);

	if (sbinfo->max_blocks)
		percpu_counter_sub(&sbinfo->used_blocks, pages);
	shmem_unacct_blocks(info->flags, pages);
}

static const struct super_operations shmem_ops;
const struct address_space_operations shmem_aops;
static const struct file_operations shmem_file_operations;
static const struct inode_operations shmem_inode_operations;
static const struct inode_operations shmem_dir_inode_operations;
static const struct inode_operations shmem_special_inode_operations;
static const struct vm_operations_struct shmem_vm_ops;
static const struct vm_operations_struct shmem_anon_vm_ops;
static struct file_system_type shmem_fs_type;

bool vma_is_anon_shmem(struct vm_area_struct *vma)
{
	return vma->vm_ops == &shmem_anon_vm_ops;
}
/* 
vma的ops是shmem_vm_ops或者shmem_anon_vm_ops
*/
bool vma_is_shmem(struct vm_area_struct *vma)
{
	return vma_is_anon_shmem(vma) || vma->vm_ops == &shmem_vm_ops;
}

// 系统全部的shmem inode挂接在这里?
static LIST_HEAD(shmem_swaplist);
static DEFINE_MUTEX(shmem_swaplist_mutex);

#ifdef CONFIG_TMPFS_QUOTA

static int shmem_enable_quotas(struct super_block *sb,
			       unsigned short quota_types)
{
	int type, err = 0;

	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE | DQUOT_NOLIST_DIRTY;
	for (type = 0; type < SHMEM_MAXQUOTAS; type++) {
		if (!(quota_types & (1 << type)))
			continue;
		err = dquot_load_quota_sb(sb, type, QFMT_SHMEM,
					  DQUOT_USAGE_ENABLED |
					  DQUOT_LIMITS_ENABLED);
		if (err)
			goto out_err;
	}
	return 0;

out_err:
	pr_warn("tmpfs: failed to enable quota tracking (type=%d, err=%d)\n",
		type, err);
	for (type--; type >= 0; type--)
		dquot_quota_off(sb, type);
	return err;
}

static void shmem_disable_quotas(struct super_block *sb)
{
	int type;

	for (type = 0; type < SHMEM_MAXQUOTAS; type++)
		dquot_quota_off(sb, type);
}

static struct dquot **shmem_get_dquots(struct inode *inode)
{
	return SHMEM_I(inode)->i_dquot;
}
#endif /* CONFIG_TMPFS_QUOTA */

/*
 * shmem_reserve_inode() performs bookkeeping to reserve a shmem inode, and
 * produces a novel ino for the newly allocated inode.
 * 函数执行一些预留inode的工作, 为新分配的inode产生一个新的ino
 * It may also be called when making a hard link to permit the space needed by
 * each dentry. However, in that case, no new inode number is needed since that
 * internally draws from another pool of inode numbers (currently global
 * get_next_ino()). This case is indicated by passing NULL as inop.
 */
#define SHMEM_INO_BATCH 1024
static int shmem_reserve_inode(struct super_block *sb, ino_t *inop)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	ino_t ino;

	if (!(sb->s_flags & SB_KERNMOUNT)) {
		raw_spin_lock(&sbinfo->stat_lock);
		if (sbinfo->max_inodes) {
			if (sbinfo->free_ispace < BOGO_INODE_SIZE) {
				raw_spin_unlock(&sbinfo->stat_lock);
				return -ENOSPC;
			}
			sbinfo->free_ispace -= BOGO_INODE_SIZE;
		}
		if (inop) {
			ino = sbinfo->next_ino++;
			if (unlikely(is_zero_ino(ino)))
				ino = sbinfo->next_ino++;
			if (unlikely(!sbinfo->full_inums &&
				     ino > UINT_MAX)) {
				/*
				 * Emulate get_next_ino uint wraparound for
				 * compatibility
				 */
				if (IS_ENABLED(CONFIG_64BIT))
					pr_warn("%s: inode number overflow on device %d, consider using inode64 mount option\n",
						__func__, MINOR(sb->s_dev));
				sbinfo->next_ino = 1;
				ino = sbinfo->next_ino++;
			}
			*inop = ino;
		}
		raw_spin_unlock(&sbinfo->stat_lock);
	} else if (inop) {
		/*
		 * __shmem_file_setup, one of our callers, is lock-free: it
		 * doesn't hold stat_lock in shmem_reserve_inode since
		 * max_inodes is always 0, and is called from potentially
		 * unknown contexts. As such, use a per-cpu batched allocator
		 * which doesn't require the per-sb stat_lock unless we are at
		 * the batch boundary.
		 *
		 * We don't need to worry about inode{32,64} since SB_KERNMOUNT
		 * shmem mounts are not exposed to userspace, so we don't need
		 * to worry about things like glibc compatibility.
		 */
		ino_t *next_ino;

		next_ino = per_cpu_ptr(sbinfo->ino_batch, get_cpu());
		ino = *next_ino;
		if (unlikely(ino % SHMEM_INO_BATCH == 0)) {
			raw_spin_lock(&sbinfo->stat_lock);
			ino = sbinfo->next_ino;
			sbinfo->next_ino += SHMEM_INO_BATCH;
			raw_spin_unlock(&sbinfo->stat_lock);
			if (unlikely(is_zero_ino(ino)))
				ino++;
		}
		*inop = ino;
		*next_ino = ++ino;
		put_cpu();
	}

	return 0;
}

// shmem释放inode
static void shmem_free_inode(struct super_block *sb, size_t freed_ispace)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	if (sbinfo->max_inodes) {
		raw_spin_lock(&sbinfo->stat_lock);
		sbinfo->free_ispace += BOGO_INODE_SIZE + freed_ispace;
		raw_spin_unlock(&sbinfo->stat_lock);
	}
}

/**
 * shmem_recalc_inode - recalculate the block usage of an inode
 重新计算inode的块使用情况?
 * @inode: inode to recalc
 * @alloced: the change in number of pages allocated to inode
 * @swapped: the change in number of pages swapped from inode
 *
 * We have to calculate the free blocks since the mm can drop
 * undirtied hole pages behind our back.
 *
 * But normally   info->alloced == inode->i_mapping->nrpages + info->swapped
 * So mm freed is info->alloced - (inode->i_mapping->nrpages + info->swapped)
 */
static void shmem_recalc_inode(struct inode *inode, long alloced, long swapped)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	long freed;

	spin_lock(&info->lock);
	info->alloced += alloced;
	info->swapped += swapped;
	freed = info->alloced - info->swapped -
		READ_ONCE(inode->i_mapping->nrpages);
	/*
	 * Special case: whereas normally shmem_recalc_inode() is called
	 * after i_mapping->nrpages has already been adjusted (up or down),
	 * shmem_writepage() has to raise swapped before nrpages is lowered -
	 * to stop a racing shmem_recalc_inode() from thinking that a page has
	 * been freed.  Compensate here, to avoid the need for a followup call.
	 */
	if (swapped > 0)
		freed += swapped;
	if (freed > 0)
		info->alloced -= freed;
	spin_unlock(&info->lock);

	/* The quota case may block */
	if (freed > 0)
		shmem_inode_unacct_blocks(inode, freed);
}

bool shmem_charge(struct inode *inode, long pages)
{
	struct address_space *mapping = inode->i_mapping;

	if (shmem_inode_acct_block(inode, pages))
		return false;

	/* nrpages adjustment first, then shmem_recalc_inode() when balanced */
	xa_lock_irq(&mapping->i_pages);
	mapping->nrpages += pages;
	xa_unlock_irq(&mapping->i_pages);

	shmem_recalc_inode(inode, pages, 0);
	return true;
}

void shmem_uncharge(struct inode *inode, long pages)
{
	/* pages argument is currently unused: keep it to help debugging */
	/* nrpages adjustment done by __filemap_remove_folio() or caller */

	shmem_recalc_inode(inode, 0, 0);
}

/*
把mapping的index处的value替换掉
这个值现在应该是expected, 准备使用replacement替换
 * Replace item expected in xarray by a new item, while holding xa_lock.
 */
static int shmem_replace_entry(struct address_space *mapping,
			pgoff_t index, void *expected, void *replacement)
{
	XA_STATE(xas, &mapping->i_pages, index);
	void *item;

	VM_BUG_ON(!expected);
	VM_BUG_ON(!replacement);
	item = xas_load(&xas);
	if (item != expected)
		return -ENOENT;
	xas_store(&xas, replacement);
	return 0;
}

/*
 * Sometimes, before we decide whether to proceed or to fail, we must check
 * that an entry was not already brought back from swap by a racing thread.
 * 有时，在决定是继续还是失败之前，我们必须检查是否已经有一个条目被竞争线程从交换中带回。
 *
 * Checking page is not enough: by the time a SwapCache page is locked, it
 * might be reused, and again be SwapCache, using the same swap as before.
 */
static bool shmem_confirm_swap(struct address_space *mapping,
			       pgoff_t index, swp_entry_t swap)
{
	return xa_load(&mapping->i_pages, index) == swp_to_radix_entry(swap);
}

/*
 * Definitions for "huge tmpfs": tmpfs mounted with the huge= option
 *
 * SHMEM_HUGE_NEVER:
 *	disables huge pages for the mount;
 * SHMEM_HUGE_ALWAYS:
 *	enables huge pages for the mount;
 * SHMEM_HUGE_WITHIN_SIZE:
 *	only allocate huge pages if the page will be fully within i_size,
 *	also respect fadvise()/madvise() hints;
 * SHMEM_HUGE_ADVISE:
 *	only allocate huge pages if requested with fadvise()/madvise();
 */

#define SHMEM_HUGE_NEVER	0
#define SHMEM_HUGE_ALWAYS	1
#define SHMEM_HUGE_WITHIN_SIZE	2
#define SHMEM_HUGE_ADVISE	3

/*
 * Special values.
 * Only can be set via /sys/kernel/mm/transparent_hugepage/shmem_enabled:
 *
 * SHMEM_HUGE_DENY:
 *	disables huge on shm_mnt and all mounts, for emergency use;
 * SHMEM_HUGE_FORCE:
 *	enables huge on shm_mnt and all mounts, w/o needing option, for testing;
 *
 */
#define SHMEM_HUGE_DENY		(-1)
#define SHMEM_HUGE_FORCE	(-2)

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* ifdef here to avoid bloating shmem.o when not necessary */

static int shmem_huge __read_mostly = SHMEM_HUGE_NEVER;

bool shmem_is_huge(struct inode *inode, pgoff_t index, bool shmem_huge_force,
		   struct mm_struct *mm, unsigned long vm_flags)
{
	loff_t i_size;

	if (!S_ISREG(inode->i_mode))
		return false;
	if (mm && ((vm_flags & VM_NOHUGEPAGE) || test_bit(MMF_DISABLE_THP, &mm->flags)))
		return false;
	if (shmem_huge == SHMEM_HUGE_DENY)
		return false;
	if (shmem_huge_force || shmem_huge == SHMEM_HUGE_FORCE)
		return true;

	switch (SHMEM_SB(inode->i_sb)->huge) {
	case SHMEM_HUGE_ALWAYS:
		return true;
	case SHMEM_HUGE_WITHIN_SIZE:
		index = round_up(index + 1, HPAGE_PMD_NR);
		i_size = round_up(i_size_read(inode), PAGE_SIZE);
		if (i_size >> PAGE_SHIFT >= index)
			return true;
		fallthrough;
	case SHMEM_HUGE_ADVISE:
		if (mm && (vm_flags & VM_HUGEPAGE))
			return true;
		fallthrough;
	default:
		return false;
	}
}

#if defined(CONFIG_SYSFS)
static int shmem_parse_huge(const char *str)
{
	if (!strcmp(str, "never"))
		return SHMEM_HUGE_NEVER;
	if (!strcmp(str, "always"))
		return SHMEM_HUGE_ALWAYS;
	if (!strcmp(str, "within_size"))
		return SHMEM_HUGE_WITHIN_SIZE;
	if (!strcmp(str, "advise"))
		return SHMEM_HUGE_ADVISE;
	if (!strcmp(str, "deny"))
		return SHMEM_HUGE_DENY;
	if (!strcmp(str, "force"))
		return SHMEM_HUGE_FORCE;
	return -EINVAL;
}
#endif

#if defined(CONFIG_SYSFS) || defined(CONFIG_TMPFS)
static const char *shmem_format_huge(int huge)
{
	switch (huge) {
	case SHMEM_HUGE_NEVER:
		return "never";
	case SHMEM_HUGE_ALWAYS:
		return "always";
	case SHMEM_HUGE_WITHIN_SIZE:
		return "within_size";
	case SHMEM_HUGE_ADVISE:
		return "advise";
	case SHMEM_HUGE_DENY:
		return "deny";
	case SHMEM_HUGE_FORCE:
		return "force";
	default:
		VM_BUG_ON(1);
		return "bad_val";
	}
}
#endif

//回收shmem的空间
static unsigned long shmem_unused_huge_shrink(struct shmem_sb_info *sbinfo,
		struct shrink_control *sc, unsigned long nr_to_split)
{
	LIST_HEAD(list), *pos, *next;
	LIST_HEAD(to_remove);
	struct inode *inode;
	struct shmem_inode_info *info;
	struct folio *folio;
	unsigned long batch = sc ? sc->nr_to_scan : 128;
	int split = 0;

	if (list_empty(&sbinfo->shrinklist))
		return SHRINK_STOP;

	spin_lock(&sbinfo->shrinklist_lock);
	list_for_each_safe(pos, next, &sbinfo->shrinklist) {

		//取下来一个shmem fs的inode
		info = list_entry(pos, struct shmem_inode_info, shrinklist);

		/* pin the inode */
		inode = igrab(&info->vfs_inode);

		/* inode is about to be evicted */
		if (!inode) {
			list_del_init(&info->shrinklist);
			goto next;
		}

		/* Check if there's anything to gain */
		if (round_up(inode->i_size, PAGE_SIZE) ==
				round_up(inode->i_size, HPAGE_PMD_SIZE)) {
			//准备回收这个inode
			list_move(&info->shrinklist, &to_remove);
			goto next;
		}

		list_move(&info->shrinklist, &list);
next:
		sbinfo->shrinklist_len--;
		if (!--batch)
			break;
	}
	spin_unlock(&sbinfo->shrinklist_lock);



//开始shrink了
	list_for_each_safe(pos, next, &to_remove) {
		//获取shmem inode
		info = list_entry(pos, struct shmem_inode_info, shrinklist);
		//获取里面包着的vfs inode
		inode = &info->vfs_inode;
		list_del_init(&info->shrinklist);
		iput(inode);
	}

	list_for_each_safe(pos, next, &list) {
		int ret;
		pgoff_t index;

		info = list_entry(pos, struct shmem_inode_info, shrinklist);
		inode = &info->vfs_inode;

		if (nr_to_split && split >= nr_to_split)
			goto move_back;

		index = (inode->i_size & HPAGE_PMD_MASK) >> PAGE_SHIFT;
		folio = filemap_get_folio(inode->i_mapping, index);
		if (IS_ERR(folio))
			goto drop;

		/* No huge page at the end of the file: nothing to split */
		if (!folio_test_large(folio)) {
			folio_put(folio);
			goto drop;
		}

		/*
		 * Move the inode on the list back to shrinklist if we failed
		 * to lock the page at this time.
		 *
		 * Waiting for the lock may lead to deadlock in the
		 * reclaim path.
		 */
		if (!folio_trylock(folio)) {
			folio_put(folio);
			goto move_back;
		}

		ret = split_folio(folio);
		folio_unlock(folio);
		folio_put(folio);

		/* If split failed move the inode on the list back to shrinklist */
		if (ret)
			goto move_back;

		split++;
drop:
		list_del_init(&info->shrinklist);
		goto put;
move_back:
		/*
		 * Make sure the inode is either on the global list or deleted
		 * from any local list before iput() since it could be deleted
		 * in another thread once we put the inode (then the local list
		 * is corrupted).
		 */
		spin_lock(&sbinfo->shrinklist_lock);
		list_move(&info->shrinklist, &sbinfo->shrinklist);
		sbinfo->shrinklist_len++;
		spin_unlock(&sbinfo->shrinklist_lock);
put:
		iput(inode);
	}

	return split;
}

static long shmem_unused_huge_scan(struct super_block *sb,
		struct shrink_control *sc)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);

	if (!READ_ONCE(sbinfo->shrinklist_len))
		return SHRINK_STOP;

	return shmem_unused_huge_shrink(sbinfo, sc, 0);
}

static long shmem_unused_huge_count(struct super_block *sb,
		struct shrink_control *sc)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	return READ_ONCE(sbinfo->shrinklist_len);
}
#else /* !CONFIG_TRANSPARENT_HUGEPAGE */

#define shmem_huge SHMEM_HUGE_DENY

bool shmem_is_huge(struct inode *inode, pgoff_t index, bool shmem_huge_force,
		   struct mm_struct *mm, unsigned long vm_flags)
{
	return false;
}

static unsigned long shmem_unused_huge_shrink(struct shmem_sb_info *sbinfo,
		struct shrink_control *sc, unsigned long nr_to_split)
{
	return 0;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/*
shmem fs加入新page到pagecache的过程
其实就是把folio加入到mapping的index位置
 * Like filemap_add_folio, but error if expected item has gone.
 */
static int shmem_add_to_page_cache(struct folio *folio,
				   struct address_space *mapping,
				   pgoff_t index, void *expected, gfp_t gfp,
				   struct mm_struct *charge_mm)
{
	XA_STATE_ORDER(xas, &mapping->i_pages, index, folio_order(folio));
	long nr = folio_nr_pages(folio);
	int error;

	VM_BUG_ON_FOLIO(index != round_down(index, nr), folio);
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_swapbacked(folio), folio);
	VM_BUG_ON(expected && folio_test_large(folio));

	// 设置folio的属性
	folio_ref_add(folio, nr);
	folio->mapping = mapping;
	folio->index = index;

	if (!folio_test_swapcache(folio)) {// 如果不是swap page的情况
		error = mem_cgroup_charge(folio, charge_mm, gfp);
		if (error) { // charge出错了就报告一下错误, 返回
			if (folio_test_pmd_mappable(folio)) {
				count_vm_event(THP_FILE_FALLBACK);
				count_vm_event(THP_FILE_FALLBACK_CHARGE);
			}
			goto error;
		}
	}
	folio_throttle_swaprate(folio, gfp);

	/* 加入xas */
	do {
		xas_lock_irq(&xas);
		if (expected != xas_find_conflict(&xas)) {
			xas_set_err(&xas, -EEXIST);
			goto unlock;
		}
		if (expected && xas_find_conflict(&xas)) {
			xas_set_err(&xas, -EEXIST);
			goto unlock;
		}
		// 存入mapping
		xas_store(&xas, folio);
		if (xas_error(&xas))
			goto unlock;
		if (folio_test_pmd_mappable(folio)) {
			count_vm_event(THP_FILE_ALLOC);
			__lruvec_stat_mod_folio(folio, NR_SHMEM_THPS, nr);
		}
		/* shmem算文件页, 算shmem */
		mapping->nrpages += nr;
		__lruvec_stat_mod_folio(folio, NR_FILE_PAGES, nr);
		__lruvec_stat_mod_folio(folio, NR_SHMEM, nr);
unlock:
		xas_unlock_irq(&xas);
	} while (xas_nomem(&xas, gfp));

	if (xas_error(&xas)) {
		error = xas_error(&xas);
		goto error;
	}

	return 0;
error:
// 出错了, 重置folio的属性
	folio->mapping = NULL;
	folio_ref_sub(folio, nr);
	return error;
}

/*刚刚把folio加入swap的mapping了,这里在shmem的mapping的folio位置替换为swap ent
 * Like delete_from_page_cache, but substitutes swap for @folio.
   就像delete_from_page_cache一样, 但是用swap替换@folio
   是因为把folio回写到了swap
   ============================================
 */
static void shmem_delete_from_page_cache(struct folio *folio, void *radswap)
{
	// 这个mapping是shmem 的mapping
	struct address_space *mapping = folio->mapping;
	long nr = folio_nr_pages(folio);
	int error;

	// 锁住mapping的xa, 然后在里面替换掉本来的folio entry
	xa_lock_irq(&mapping->i_pages);
	error = shmem_replace_entry(mapping, folio->index, folio, radswap);
	folio->mapping = NULL; // 在刚刚把folio加到了swap 的mapping里面, 所以这里要清空
	/* 添加的逆过程, 减少相关的计数 */
	mapping->nrpages -= nr;
	__lruvec_stat_mod_folio(folio, NR_FILE_PAGES, -nr);
	__lruvec_stat_mod_folio(folio, NR_SHMEM, -nr);
	xa_unlock_irq(&mapping->i_pages);
	folio_put(folio);
	BUG_ON(error);
}

/*
shmem文件的mapping的index位置的folio被换出了?
这里释放
==========
truncate这个shmem文件的时候会调用这个
 * Remove swap entry from page cache, free the swap and its page cache.
 */
static int shmem_free_swap(struct address_space *mapping,
			   pgoff_t index, void *radswap)
{
	void *old;
	// 为啥这里还要保证一下, 哪里会race?
	old = xa_cmpxchg_irq(&mapping->i_pages, index, radswap, NULL, 0);
	if (old != radswap)
		return -ENOENT;
	// 这里先把找到的radswap转为swap entry
	free_swap_and_cache(radix_to_swp_entry(radswap)); // 释放交换空间
	return 0;
}

/*
 * Determine (in bytes) how many of the shmem object's pages mapped by the
 * given offsets are swapped out.
 *
 * This is safe to call without i_rwsem or the i_pages lock thanks to RCU,
 * as long as the inode doesn't go away and racy results are not a problem.
 */
unsigned long shmem_partial_swap_usage(struct address_space *mapping,
						pgoff_t start, pgoff_t end)
{
	XA_STATE(xas, &mapping->i_pages, start);
	struct page *page;
	unsigned long swapped = 0;
	unsigned long max = end - 1;

	rcu_read_lock();
	xas_for_each(&xas, page, max) {
		if (xas_retry(&xas, page))
			continue;
		if (xa_is_value(page))
			swapped++;
		if (xas.xa_index == max)
			break;
		if (need_resched()) {
			xas_pause(&xas);
			cond_resched_rcu();
		}
	}

	rcu_read_unlock();

	return swapped << PAGE_SHIFT;
}

/*
 * Determine (in bytes) how many of the shmem object's pages mapped by the
 * given vma is swapped out.
 *
 * This is safe to call without i_rwsem or the i_pages lock thanks to RCU,
 * as long as the inode doesn't go away and racy results are not a problem.
 */
unsigned long shmem_swap_usage(struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(vma->vm_file);
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct address_space *mapping = inode->i_mapping;
	unsigned long swapped;

	/* Be careful as we don't hold info->lock */
	swapped = READ_ONCE(info->swapped);

	/*
	 * The easier cases are when the shmem object has nothing in swap, or
	 * the vma maps it whole. Then we can simply use the stats that we
	 * already track.
	 */
	if (!swapped)
		return 0;

	if (!vma->vm_pgoff && vma->vm_end - vma->vm_start >= inode->i_size)
		return swapped << PAGE_SHIFT;

	/* Here comes the more involved part */
	return shmem_partial_swap_usage(mapping, vma->vm_pgoff,
					vma->vm_pgoff + vma_pages(vma));
}

/*
 * SysV IPC SHM_UNLOCK restore Unevictable pages to their evictable lists.
 */
void shmem_unlock_mapping(struct address_space *mapping)
{
	struct folio_batch fbatch;
	pgoff_t index = 0;

	folio_batch_init(&fbatch);
	/*
	 * Minor point, but we might as well stop if someone else SHM_LOCKs it.
	 */
	while (!mapping_unevictable(mapping) &&
	       filemap_get_folios(mapping, &index, ~0UL, &fbatch)) {
		check_move_unevictable_folios(&fbatch);
		folio_batch_release(&fbatch);
		cond_resched();
	}
}

/* partial folio是什么 */
static struct folio *shmem_get_partial_folio(struct inode *inode, pgoff_t index)
{
	struct folio *folio;

	/*
	 * At first avoid shmem_get_folio(,,,SGP_READ): that fails
	 * beyond i_size, and reports fallocated folios as holes.
	 */
	folio = filemap_get_entry(inode->i_mapping, index);
	if (!folio)
		return folio;
	if (!xa_is_value(folio)) {
		folio_lock(folio);
		if (folio->mapping == inode->i_mapping)
			return folio;
		/* The folio has been swapped out */
		folio_unlock(folio);
		folio_put(folio);
	}
	/* 到这里:
	被交换了
	正常页面, 但是被从mapping截断了? */
	/*
	 * But read a folio back from swap if any of it is within i_size
	 * (although in some cases this is just a waste of time).
	 */
	folio = NULL;
	/*  */
	shmem_get_folio(inode, index, &folio, SGP_READ);
	return folio;
}

/*
truncate这个shmem inode的范围
==============================
这里只是清理xas, 移除swap, 释放内存到buddy
 * Remove range of pages and swap entries from page cache, and free them.
 * If !unfalloc, truncate or punch hole; if unfalloc, undo failed fallocate.
   从page cache中删除范围内的页面和交换条目，并释放它们。
 */
static void shmem_undo_range(struct inode *inode, loff_t lstart, loff_t lend,
								 bool unfalloc)
{
	struct address_space *mapping = inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	// 把范围转为pgoff
	pgoff_t start = (lstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pgoff_t end = (lend + 1) >> PAGE_SHIFT;
	struct folio_batch fbatch;
	pgoff_t indices[PAGEVEC_SIZE];
	struct folio *folio;
	bool same_folio;
	long nr_swaps_freed = 0;
	pgoff_t index;
	int i;

	if (lend == -1)
		end = -1;	/* unsigned, so actually very big */

	if (info->fallocend > start && info->fallocend <= end && !unfalloc)
		info->fallocend = start;

	folio_batch_init(&fbatch);
	index = start;
	while (index < end && find_lock_entries(mapping, &index, end - 1,
			&fbatch, indices)) { // 找到范围内的条目加到fbatch
		for (i = 0; i < folio_batch_count(&fbatch); i++) { // 一个一个处理找到的folio
			folio = fbatch.folios[i];

			// 这个folio是个存储在swap的交换条目
			if (xa_is_value(folio)) {
				if (unfalloc)
					continue;
				// 释放交换空间, 好像是swap file的空间, 还有swap mapping的空间?
				nr_swaps_freed += !shmem_free_swap(mapping,
							indices[i], folio);
				continue;
			}


			/*  现在是明确了folio是mapping里的folio了? */
			if (!unfalloc || !folio_test_uptodate(folio))
				truncate_inode_folio(mapping, folio);

			folio_unlock(folio);
		}
		folio_batch_remove_exceptionals(&fbatch);
		/* 释放folio的内存 */
		folio_batch_release(&fbatch);
		cond_resched();
	}

	/*
	 * When undoing a failed fallocate, we want none of the partial folio
	 * zeroing and splitting below, but shall want to truncate the whole
	 * folio when !uptodate indicates that it was added by this fallocate,
	 * even when [lstart, lend] covers only a part of the folio.
	   当撤销失败的fallocate时，我们不希望下面的部分folio清零和拆分，
	   但是当!uptodate表明它是由这个fallocate添加的时，
	   我们将希望在[lstart, lend]仅覆盖folio的一部分时截断整个folio。
	 */
	if (unfalloc)
		goto whole_folios;
	// 这里好像是fallocate的情况,. 以后
	same_folio = (lstart >> PAGE_SHIFT) == (lend >> PAGE_SHIFT);
	folio = shmem_get_partial_folio(inode, lstart >> PAGE_SHIFT);
	if (folio) {
		same_folio = lend < folio_pos(folio) + folio_size(folio);
		folio_mark_dirty(folio);
		if (!truncate_inode_partial_folio(folio, lstart, lend)) {
			start = folio_next_index(folio);
			if (same_folio)
				end = folio->index;
		}
		folio_unlock(folio);
		folio_put(folio);
		folio = NULL;
	}

	if (!same_folio)
		folio = shmem_get_partial_folio(inode, lend >> PAGE_SHIFT);
	if (folio) {
		folio_mark_dirty(folio);
		if (!truncate_inode_partial_folio(folio, lstart, lend))
			end = folio->index;
		folio_unlock(folio);
		folio_put(folio);
	}

whole_folios:

	index = start;
	while (index < end) {
		cond_resched();

		// 搜索一批次present的folio
		if (!find_get_entries(mapping, &index, end - 1, &fbatch,
				indices)) {
			/* If all gone or hole-punch or unfalloc, we're done */
			if (index == start || end != -1)
				break;
			/* But if truncating, restart to make sure all gone */
			index = start;
			continue;
		}
		// 处理批次
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			folio = fbatch.folios[i];

			if (xa_is_value(folio)) {
				if (unfalloc)
					continue;
				if (shmem_free_swap(mapping, indices[i], folio)) {
					/* Swap was replaced by page: retry */
					index = indices[i];
					break;
				}
				nr_swaps_freed++;
				continue;
			}

			folio_lock(folio);

			if (!unfalloc || !folio_test_uptodate(folio)) {
				if (folio_mapping(folio) != mapping) {
					/* Page was replaced by swap: retry */
					folio_unlock(folio);
					index = indices[i];
					break;
				}
				VM_BUG_ON_FOLIO(folio_test_writeback(folio),
						folio);
				truncate_inode_folio(mapping, folio);
			}
			folio_unlock(folio);
		}
		folio_batch_remove_exceptionals(&fbatch);
		folio_batch_release(&fbatch);
	}

	shmem_recalc_inode(inode, 0, -nr_swaps_freed);
}

// truncate这个shmem inode的mapping全部
void shmem_truncate_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	// 执行truncate
	shmem_undo_range(inode, lstart, lend, false);
	inode->i_mtime = inode_set_ctime_current(inode);
	inode_inc_iversion(inode);
}
EXPORT_SYMBOL_GPL(shmem_truncate_range);

// 好像是存储在stat里面
static int shmem_getattr(struct mnt_idmap *idmap,
			 const struct path *path, struct kstat *stat,
			 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = path->dentry->d_inode;
	struct shmem_inode_info *info = SHMEM_I(inode);

	if (info->alloced - info->swapped != inode->i_mapping->nrpages)
		shmem_recalc_inode(inode, 0, 0);

	if (info->fsflags & FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (info->fsflags & FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (info->fsflags & FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;
	stat->attributes_mask |= (STATX_ATTR_APPEND |
			STATX_ATTR_IMMUTABLE |
			STATX_ATTR_NODUMP);
	generic_fillattr(idmap, request_mask, inode, stat);

	if (shmem_is_huge(inode, 0, false, NULL, 0))
		stat->blksize = HPAGE_PMD_SIZE;

	if (request_mask & STATX_BTIME) {
		stat->result_mask |= STATX_BTIME;
		stat->btime.tv_sec = info->i_crtime.tv_sec;
		stat->btime.tv_nsec = info->i_crtime.tv_nsec;
	}

	return 0;
}

static int shmem_setattr(struct mnt_idmap *idmap,
			 struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct shmem_inode_info *info = SHMEM_I(inode);
	int error;
	bool update_mtime = false;
	bool update_ctime = true;

	error = setattr_prepare(idmap, dentry, attr);
	if (error)
		return error;

	if ((info->seals & F_SEAL_EXEC) && (attr->ia_valid & ATTR_MODE)) {
		if ((inode->i_mode ^ attr->ia_mode) & 0111) {
			return -EPERM;
		}
	}

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		loff_t oldsize = inode->i_size;
		loff_t newsize = attr->ia_size;

		/* protected by i_rwsem */
		if ((newsize < oldsize && (info->seals & F_SEAL_SHRINK)) ||
		    (newsize > oldsize && (info->seals & F_SEAL_GROW)))
			return -EPERM;

		if (newsize != oldsize) {
			error = shmem_reacct_size(SHMEM_I(inode)->flags,
					oldsize, newsize);
			if (error)
				return error;
			i_size_write(inode, newsize);
			update_mtime = true;
		} else {
			update_ctime = false;
		}
		if (newsize <= oldsize) {
			loff_t holebegin = round_up(newsize, PAGE_SIZE);
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
							holebegin, 0, 1);
			if (info->alloced)
				shmem_truncate_range(inode,
							newsize, (loff_t)-1);
			/* unmap again to remove racily COWed private pages */
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
							holebegin, 0, 1);
		}
	}

	if (is_quota_modification(idmap, inode, attr)) {
		error = dquot_initialize(inode);
		if (error)
			return error;
	}

	/* Transfer quota accounting */
	if (i_uid_needs_update(idmap, attr, inode) ||
	    i_gid_needs_update(idmap, attr, inode)) {
		error = dquot_transfer(idmap, inode, attr);

		if (error)
			return error;
	}

	setattr_copy(idmap, inode, attr);
	if (attr->ia_valid & ATTR_MODE)
		error = posix_acl_chmod(idmap, dentry, inode->i_mode);
	if (!error && update_ctime) {
		inode_set_ctime_current(inode);
		if (update_mtime)
			inode->i_mtime = inode_get_ctime(inode);
		inode_inc_iversion(inode);
	}
	return error;
}

// 如何evict inode?
// 好像就是写回内容,然后删除?
static void shmem_evict_inode(struct inode *inode)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	size_t freed = 0;

	if (shmem_mapping(inode->i_mapping)) { // 如果是个shmem 的mapping
		shmem_unacct_size(info->flags, inode->i_size);
		inode->i_size = 0;
		// 设置mapping为exiting
		mapping_set_exiting(inode->i_mapping);
		// 先truncate这个inode, 处理mapping, 释放里面的页面和交换条目, 释放交换空间
		shmem_truncate_range(inode, 0, (loff_t)-1);
		if (!list_empty(&info->shrinklist)) {
			spin_lock(&sbinfo->shrinklist_lock);
			if (!list_empty(&info->shrinklist)) {
				list_del_init(&info->shrinklist);
				sbinfo->shrinklist_len--;
			}
			spin_unlock(&sbinfo->shrinklist_lock);
		}
		while (!list_empty(&info->swaplist)) {
			/* Wait while shmem_unuse() is scanning this inode... */
			wait_var_event(&info->stop_eviction,
				       !atomic_read(&info->stop_eviction));
			mutex_lock(&shmem_swaplist_mutex);
			/* ...but beware of the race if we peeked too early */
			if (!atomic_read(&info->stop_eviction))
				list_del_init(&info->swaplist);
			mutex_unlock(&shmem_swaplist_mutex);
		}
	}

	simple_xattrs_free(&info->xattrs, sbinfo->max_inodes ? &freed : NULL);
	// 释放inode
	shmem_free_inode(inode->i_sb, freed);
	WARN_ON(inode->i_blocks);
	clear_inode(inode);
#ifdef CONFIG_TMPFS_QUOTA
	dquot_free_inode(inode);
	dquot_drop(inode);
#endif
}

// 在shmem mapping中找到swap的entry
static int shmem_find_swap_entries(struct address_space *mapping,
				   pgoff_t start, struct folio_batch *fbatch,
				   pgoff_t *indices, unsigned int type)
{
	XA_STATE(xas, &mapping->i_pages, start);
	struct folio *folio;
	swp_entry_t entry;

	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) { // 遍历全部的folio
		if (xas_retry(&xas, folio))
			continue;

		if (!xa_is_value(folio))
			continue;
		// 把mapp里面查到的条目转为实际值
		entry = radix_to_swp_entry(folio);
		/*
		 * swapin error entries can be found in the mapping. But they're
		 * deliberately ignored here as we've done everything we can do.
		 */
		 // 看来shmem mapping里面直接存储的swap entry?
		if (swp_type(entry) != type)
			continue;

		indices[folio_batch_count(fbatch)] = xas.xa_index;
		if (!folio_batch_add(fbatch, folio))
			break;

		if (need_resched()) {
			xas_pause(&xas);
			cond_resched_rcu();
		}
	}
	rcu_read_unlock();

	return xas.xa_index;
}

/*
fbatch是shmem mapping里面找到的一组swap条目
这里换入
======================================================================
 * Move the swapped pages for an inode to page cache. Returns the count
 * of pages swapped in, or the error in case of failure.
   移动inode的swap页面到page cache，返回移动的页面数，或者失败的错误
 */
static int shmem_unuse_swap_entries(struct inode *inode,
		struct folio_batch *fbatch, pgoff_t *indices)
{
	int i = 0;
	int ret = 0;
	int error = 0;
	struct address_space *mapping = inode->i_mapping;

	for (i = 0; i < folio_batch_count(fbatch); i++) {
		// fbatch存储的是shmem的mapping里面找到的swap entry
		struct folio *folio = fbatch->folios[i];

		if (!xa_is_value(folio))
			continue;
		// 把这个inode mapping的这个folio换入
		error = shmem_swapin_folio(inode, indices[i],
					  &folio, SGP_CACHE,
					  mapping_gfp_mask(mapping),
					  NULL, NULL);
		if (error == 0) {
			folio_unlock(folio);
			folio_put(folio);
			ret++;
		}
		if (error == -ENOMEM)
			break;
		error = 0;
	}
	return error ? error : ret;
}

/*
 * If swap found in inode, free it and move page from swapcache to filecache.
 如果在inode中找到swap，释放它，并将页面从swapcache移动到filecache
 ===========
 停用swap之前, 把shmem的交换内容换进去
 */
static int shmem_unuse_inode(struct inode *inode, unsigned int type)
{
	struct address_space *mapping = inode->i_mapping;
	pgoff_t start = 0;
	struct folio_batch fbatch;
	pgoff_t indices[PAGEVEC_SIZE];
	int ret = 0;

	do {
		folio_batch_init(&fbatch);
		// 在mapping中找到swap的entry
		shmem_find_swap_entries(mapping, start, &fbatch, indices, type);
		if (folio_batch_count(&fbatch) == 0) {// 这个inode没有交换页
			ret = 0;
			break;
		}
		// 现在停用这些swap entries
		ret = shmem_unuse_swap_entries(inode, &fbatch, indices);
		if (ret < 0)
			break;

		start = indices[folio_batch_count(&fbatch) - 1]; // 从刚才处理的最后一个swap index开始
	} while (true);

	return ret;
}

/*
 * Read all the shared memory data that resides in the swap
 * device 'type' back into memory, so the swap device can be
 * unused.
   读取所有的共享内存数据，这些数据都在swap设备上，读取到内存中，
   这样swap设备就可以被释放了
 */
int shmem_unuse(unsigned int type)
{
	struct shmem_inode_info *info, *next;
	int error = 0;

	if (list_empty(&shmem_swaplist))
		return 0;

	mutex_lock(&shmem_swaplist_mutex);
	list_for_each_entry_safe(info, next, &shmem_swaplist, swaplist) { // 找到全部的使用了
		// swap的shmem inode
		if (!info->swapped) {
			list_del_init(&info->swaplist);
			continue;
		}
		/*
		 * Drop the swaplist mutex while searching the inode for swap;
		 * but before doing so, make sure shmem_evict_inode() will not
		 * remove placeholder inode from swaplist, nor let it be freed
		 * (igrab() would protect from unlink, but not from unmount).
		 */
		atomic_inc(&info->stop_eviction);
		mutex_unlock(&shmem_swaplist_mutex);
		// 这把这个shmem inode的交换页换进来
		error = shmem_unuse_inode(&info->vfs_inode, type);
		cond_resched();

		mutex_lock(&shmem_swaplist_mutex);
		next = list_next_entry(info, swaplist);
		if (!info->swapped)
			list_del_init(&info->swaplist);
		if (atomic_dec_and_test(&info->stop_eviction))
			wake_up_var(&info->stop_eviction);
		if (error)
			break;
	}
	mutex_unlock(&shmem_swaplist_mutex);

	return error;
}

/*
shmem也是支持回写的.
=========================================
shmem的mapping的写回writepage函数回调的实现, 
回收shmem会使用swap
用于写回shmem mapping的脏页
 * Move the page from the page cache to the swap cache.
   shmem把page从页缓存移到swap cache
   2025年3月11日15:36:06
 */
static int shmem_writepage(struct page *page, struct writeback_control *wbc)
{
	struct folio *folio = page_folio(page);
	struct address_space *mapping = folio->mapping;
	struct inode *inode = mapping->host;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	swp_entry_t swap;
	pgoff_t index;

	/*
	 * Our capabilities prevent regular writeback or sync from ever calling
	 * shmem_writepage; but a stacking filesystem might use ->writepage of
	 * its underlying filesystem, in which case tmpfs should write out to
	 * swap only in response to memory pressure, and not for the writeback
	 * threads or sync.
	 */
	if (WARN_ON_ONCE(!wbc->for_reclaim))
		goto redirty;

	if (WARN_ON_ONCE((info->flags & VM_LOCKED) || sbinfo->noswap))
		goto redirty;

	if (!total_swap_pages)
		goto redirty;

	/*
	 * If /sys/kernel/mm/transparent_hugepage/shmem_enabled is "always" or
	 * "force", drivers/gpu/drm/i915/gem/i915_gem_shmem.c gets huge pages,
	 * and its shmem_writeback() needs them to be split when swapping.
	   如果shmem_enabled是always或者force, 那么shmem_writeback()需要把huge page拆分
	   驱动gpu/drm/i915/gem/i915_gem_shmem.c会得到huge pages 
	 */
	if (folio_test_large(folio)) {
		/* Ensure the subpages are still dirty */
		folio_test_set_dirty(folio);
		if (split_huge_page(page) < 0)
			goto redirty;
		folio = page_folio(page);
		folio_clear_dirty(folio);
	}

	index = folio->index;

	/*
	 * This is somewhat ridiculous, but without plumbing a SWAP_MAP_FALLOC
	 * value into swapfile.c, the only way we can correctly account for a
	 * fallocated folio arriving here is now to initialize it and write it.
	 *
	 * That's okay for a folio already fallocated earlier, but if we have
	 * not yet completed the fallocation, then (a) we want to keep track
	 * of this folio in case we have to undo it, and (b) it may not be a
	 * good idea to continue anyway, once we're pushing into swap.  So
	 * reactivate the folio, and let shmem_fallocate() quit when too many.
	 */
	/* 如果写回shmem的脏页时,发现不是up-to-date的, 这是什么情况? */
	if (!folio_test_uptodate(folio)) {
		if (inode->i_private) {
			struct shmem_falloc *shmem_falloc;
			spin_lock(&inode->i_lock);
			shmem_falloc = inode->i_private;
			if (shmem_falloc &&
			    !shmem_falloc->waitq &&
			    index >= shmem_falloc->start &&
			    index < shmem_falloc->next)
				shmem_falloc->nr_unswapped++;
			else
				shmem_falloc = NULL;
			spin_unlock(&inode->i_lock);
			if (shmem_falloc)
				goto redirty;
		}
		folio_zero_range(folio, 0, folio_size(folio));
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
	}
	// 分配一个swap slot
	swap = folio_alloc_swap(folio);
	if (!swap.val)
		goto redirty;

	/*
	 * Add inode to shmem_unuse()'s list of swapped-out inodes,
	 * if it's not already there.  Do it now before the folio is
	 * moved to swap cache, when its pagelock no longer protects
	 * the inode from eviction.  But don't unlock the mutex until
	 * we've incremented swapped, because shmem_unuse_inode() will
	 * prune a !swapped inode from the swaplist under this mutex.
	 */
	mutex_lock(&shmem_swaplist_mutex);
	if (list_empty(&info->swaplist))
		list_add(&info->swaplist, &shmem_swaplist);

	/* // 这里把folio加入到swap的mapping的xas,成功了 */
	if (add_to_swap_cache(folio, swap,
			__GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN,
			NULL) == 0) {
		shmem_recalc_inode(inode, 0, 1);
		// 把swap entry ref打上shmem的标签,表示把这个swap entry分配给shmem了
		swap_shmem_alloc(swap); 
		/* 用swap条目值代替xas里面原本的folio值, 因为被交换出去了
		这样下次读取到，就知道这是被交换了 */
		shmem_delete_from_page_cache(folio, swp_to_radix_entry(swap));

		mutex_unlock(&shmem_swaplist_mutex);
		BUG_ON(folio_mapped(folio));
		// 回写这个page,提交bio
		swap_writepage(&folio->page, wbc);
		// 
		return 0;
	}
	// 这里是要回写的shmem mapping的folio加入到swap mapping 出错了的情况
	mutex_unlock(&shmem_swaplist_mutex);
	put_swap_folio(folio, swap);
redirty:
	folio_mark_dirty(folio);
	if (wbc->for_reclaim)
		return AOP_WRITEPAGE_ACTIVATE;	/* Return with folio locked */
	folio_unlock(folio);
	return 0;
}

#if defined(CONFIG_NUMA) && defined(CONFIG_TMPFS)
static void shmem_show_mpol(struct seq_file *seq, struct mempolicy *mpol)
{
	char buffer[64];

	if (!mpol || mpol->mode == MPOL_DEFAULT)
		return;		/* show nothing */

	mpol_to_str(buffer, sizeof(buffer), mpol);

	seq_printf(seq, ",mpol=%s", buffer);
}

static struct mempolicy *shmem_get_sbmpol(struct shmem_sb_info *sbinfo)
{
	struct mempolicy *mpol = NULL;
	if (sbinfo->mpol) {
		raw_spin_lock(&sbinfo->stat_lock);	/* prevent replace/use races */
		mpol = sbinfo->mpol;
		mpol_get(mpol);
		raw_spin_unlock(&sbinfo->stat_lock);
	}
	return mpol;
}
#else /* !CONFIG_NUMA || !CONFIG_TMPFS */
static inline void shmem_show_mpol(struct seq_file *seq, struct mempolicy *mpol)
{
}
static inline struct mempolicy *shmem_get_sbmpol(struct shmem_sb_info *sbinfo)
{
	return NULL;
}
#endif /* CONFIG_NUMA && CONFIG_TMPFS */
#ifndef CONFIG_NUMA
#define vm_policy vm_private_data
#endif

static void shmem_pseudo_vma_init(struct vm_area_struct *vma,
		struct shmem_inode_info *info, pgoff_t index)
{
	/* Create a pseudo vma that just contains the policy */
	vma_init(vma, NULL);
	/* Bias interleave by inode number to distribute better across nodes */
	vma->vm_pgoff = index + info->vfs_inode.i_ino;
	vma->vm_policy = mpol_shared_policy_lookup(&info->policy, index);
}

static void shmem_pseudo_vma_destroy(struct vm_area_struct *vma)
{
	/* Drop reference taken by mpol_shared_policy_lookup() */
	mpol_cond_put(vma->vm_policy);
}

// shmem换入 新申请页面加入swap mapping
static struct folio *shmem_swapin(swp_entry_t swap, gfp_t gfp,
			struct shmem_inode_info *info, pgoff_t index)
{
	struct vm_area_struct pvma;
	struct page *page;
	struct vm_fault vmf = {
		.vma = &pvma,
	};

	shmem_pseudo_vma_init(&pvma, info, index);
	// shmem读入这个swap的page,换入
	page = swap_cluster_readahead(swap, gfp, &vmf);
	shmem_pseudo_vma_destroy(&pvma);
	// 现在page就是swap的内容了, page是swap mapping的page
	if (!page)
		return NULL;
	return page_folio(page);
}

/*
 * Make sure huge_gfp is always more limited than limit_gfp.
 * Some of the flags set permissions, while others set limitations.
 */
static gfp_t limit_gfp_mask(gfp_t huge_gfp, gfp_t limit_gfp)
{
	gfp_t allowflags = __GFP_IO | __GFP_FS | __GFP_RECLAIM;
	gfp_t denyflags = __GFP_NOWARN | __GFP_NORETRY;
	gfp_t zoneflags = limit_gfp & GFP_ZONEMASK;
	gfp_t result = huge_gfp & ~(allowflags | GFP_ZONEMASK);

	/* Allow allocations only from the originally specified zones. */
	result |= zoneflags;

	/*
	 * Minimize the result gfp by taking the union with the deny flags,
	 * and the intersection of the allow flags.
	 */
	result |= (limit_gfp & denyflags);
	result |= (huge_gfp & limit_gfp) & allowflags;

	return result;
}

//shmem分配大页
static struct folio *shmem_alloc_hugefolio(gfp_t gfp,
		struct shmem_inode_info *info, pgoff_t index)
{
	struct vm_area_struct pvma;
	struct address_space *mapping = info->vfs_inode.i_mapping;
	pgoff_t hindex;
	struct folio *folio;

	hindex = round_down(index, HPAGE_PMD_NR);
	if (xa_find(&mapping->i_pages, &hindex, hindex + HPAGE_PMD_NR - 1,
								XA_PRESENT))
		return NULL;

	shmem_pseudo_vma_init(&pvma, info, hindex);
	folio = vma_alloc_folio(gfp, HPAGE_PMD_ORDER, &pvma, 0, true);
	shmem_pseudo_vma_destroy(&pvma);
	if (!folio)
		count_vm_event(THP_FILE_FALLBACK);
	return folio;
}
/* 
shmem分配页面
*/
static struct folio *shmem_alloc_folio(gfp_t gfp,
			struct shmem_inode_info *info, pgoff_t index)
{
	struct vm_area_struct pvma;
	struct folio *folio;

	shmem_pseudo_vma_init(&pvma, info, index);
	/* 通过一个伪vma来分配页面 */
	folio = vma_alloc_folio(gfp, 0, &pvma, 0, false);
	shmem_pseudo_vma_destroy(&pvma);

	return folio;
}

static struct folio *shmem_alloc_and_acct_folio(gfp_t gfp, struct inode *inode,
		pgoff_t index, bool huge)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct folio *folio;
	int nr;
	int err;

	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		huge = false;
	nr = huge ? HPAGE_PMD_NR : 1;

	err = shmem_inode_acct_block(inode, nr);
	if (err)
		goto failed;

	if (huge)
		folio = shmem_alloc_hugefolio(gfp, info, index);
	else
		folio = shmem_alloc_folio(gfp, info, index);
	if (folio) {
		__folio_set_locked(folio);
		__folio_set_swapbacked(folio);
		return folio;
	}

	err = -ENOMEM;
	shmem_inode_unacct_blocks(inode, nr);
failed:
	return ERR_PTR(err);
}

/*
 * When a page is moved from swapcache to shmem filecache (either by the
 * usual swapin of shmem_get_folio_gfp(), or by the less common swapoff of
 * shmem_unuse_inode()), it may have been read in earlier from swap, in
 * ignorance of the mapping it belongs to.  If that mapping has special
 * constraints (like the gma500 GEM driver, which requires RAM below 4GB),
 * we may need to copy to a suitable page before moving to filecache.
 * 当一个页面从swapcache移动到shmem文件缓存时（通过shmem_get_folio_gfp()的常规swapin，
 * 或通过shmem_unuse_inode()的不太常见的swapoff），它可能早些时候从swap中读取，
 * 而不知道它所属的映射。如果该映射具有特殊约束（例如gma500 GEM驱动程序，
 * 它要求RAM低于4GB），我们可能需要在移动到文件缓存之前复制到合适的页面。
 * In a future release, this may well be extended to respect cpuset and
 * NUMA mempolicy, and applied also to anonymous pages in do_swap_page();
 * but for now it is a simple matter of zone.
 */
static bool shmem_should_replace_folio(struct folio *folio, gfp_t gfp)
{
	return folio_zonenum(folio) > gfp_zone(gfp);
}

/* shmem在mapping替换folio? */
static int shmem_replace_folio(struct folio **foliop, gfp_t gfp,
				struct shmem_inode_info *info, pgoff_t index)
{
	struct folio *old, *new;
	struct address_space *swap_mapping;
	swp_entry_t entry;
	pgoff_t swap_index;
	int error;

	old = *foliop;
	entry = old->swap;
	swap_index = swp_offset(entry);
	swap_mapping = swap_address_space(entry);

	/*
	 * We have arrived here because our zones are constrained, so don't
	 * limit chance of success by further cpuset and node constraints.
	 */
	gfp &= ~GFP_CONSTRAINT_MASK;
	VM_BUG_ON_FOLIO(folio_test_large(old), old);
	new = shmem_alloc_folio(gfp, info, index);
	if (!new)
		return -ENOMEM;

	folio_get(new);
	folio_copy(new, old);
	flush_dcache_folio(new);

	__folio_set_locked(new);
	__folio_set_swapbacked(new);
	folio_mark_uptodate(new);
	new->swap = entry;
	folio_set_swapcache(new);

	/*
	 * Our caller will very soon move newpage out of swapcache, but it's
	 * a nice clean interface for us to replace oldpage by newpage there.
	 */
	xa_lock_irq(&swap_mapping->i_pages);
	/* 替换条目 */
	error = shmem_replace_entry(swap_mapping, swap_index, old, new);
	if (!error) {
		mem_cgroup_migrate(old, new);
		__lruvec_stat_mod_folio(new, NR_FILE_PAGES, 1);
		__lruvec_stat_mod_folio(new, NR_SHMEM, 1);
		__lruvec_stat_mod_folio(old, NR_FILE_PAGES, -1);
		__lruvec_stat_mod_folio(old, NR_SHMEM, -1);
	}
	xa_unlock_irq(&swap_mapping->i_pages);

	if (unlikely(error)) {
		/*
		 * Is this possible?  I think not, now that our callers check
		 * both PageSwapCache and page_private after getting page lock;
		 * but be defensive.  Reverse old to newpage for clear and free.
		 */
		old = new;
	} else {
		folio_add_lru(new);
		*foliop = new;
	}

	folio_clear_swapcache(old);
	old->private = NULL;

	folio_unlock(old);
	folio_put_refs(old, 2);
	return error;
}

static void shmem_set_folio_swapin_error(struct inode *inode, pgoff_t index,
					 struct folio *folio, swp_entry_t swap)
{
	struct address_space *mapping = inode->i_mapping;
	swp_entry_t swapin_error;
	void *old;

	swapin_error = make_poisoned_swp_entry();
	old = xa_cmpxchg_irq(&mapping->i_pages, index,
			     swp_to_radix_entry(swap),
			     swp_to_radix_entry(swapin_error), 0);
	if (old != swp_to_radix_entry(swap))
		return;

	folio_wait_writeback(folio);
	delete_from_swap_cache(folio);
	/*
	 * Don't treat swapin error folio as alloced. Otherwise inode->i_blocks
	 * won't be 0 when inode is released and thus trigger WARN_ON(i_blocks)
	 * in shmem_evict_inode().
	 */
	shmem_recalc_inode(inode, -1, -1);
	swap_free(swap);
}

/*

shmem查找mapping, 如果发现是is_value, 就换入
这里是从swap换入, 可能已经位于swap mapping,
也可能不在,那就从swap file里换入读入swap mapping,然后也会加入shmem的mapping
 * Swap in the folio pointed to by *foliop.
 * Caller has to make sure that *foliop contains a valid swapped folio.
 * Returns 0 and the folio in foliop if success. On failure, returns the
 * error code and NULL in *foliop.
 foliop是inode的mapping的条目,是个交换条目, index是索引、.
 */
static int shmem_swapin_folio(struct inode *inode, pgoff_t index,
			     struct folio **foliop, enum sgp_type sgp,
			     gfp_t gfp, struct vm_area_struct *vma,
			     vm_fault_t *fault_type)
{
	struct address_space *mapping = inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct mm_struct *charge_mm = vma ? vma->vm_mm : NULL;
	struct swap_info_struct *si;
	struct folio *folio = NULL;
	swp_entry_t swap;
	int error;

	VM_BUG_ON(!*foliop || !xa_is_value(*foliop));
	// 把foliop转为交换条目
	swap = radix_to_swp_entry(*foliop);
	*foliop = NULL;

	if (is_poisoned_swp_entry(swap))
		return -EIO;

	si = get_swap_device(swap);
	if (!si) {
		if (!shmem_confirm_swap(mapping, index, swap))
			return -EEXIST;
		else
			return -EINVAL;
	}

	/* Look it up and read it in..
	这里先从swap cache查询读取*/
	folio = swap_cache_get_folio(swap, NULL, 0);
	if (!folio) {
		/* 说明现在不在swap cache */
		/* Or update major stats only when swapin succeeds?? */
		if (fault_type) {
			*fault_type |= VM_FAULT_MAJOR;
			count_vm_event(PGMAJFAULT);
			count_memcg_event_mm(charge_mm, PGMAJFAULT);
		}
		/* Here we actually start the io
		这里我们实际开始io操作了
		就是从swap file换入页面
		*/
		folio = shmem_swapin(swap, gfp, info, index);
		if (!folio) {
			error = -ENOMEM;
			goto failed;
		}
	}

	/* We have to do this with folio locked to prevent races */
	folio_lock(folio);
	if (!folio_test_swapcache(folio) ||
	    folio->swap.val != swap.val ||
	    !shmem_confirm_swap(mapping, index, swap)) {
		error = -EEXIST;
		goto unlock;
	}
	// 到这里 folio_test_swapcache && folio->swap.val == swap.val && shmem_confirm_swap
	if (!folio_test_uptodate(folio)) {
		error = -EIO;
		goto failed;
	}
	folio_wait_writeback(folio);

	/*
	 * Some architectures may have to restore extra metadata to the
	 * folio after reading from swap.
	 */
	arch_swap_restore(swap, folio);

	if (shmem_should_replace_folio(folio, gfp)) {// 什么叫replace?
		error = shmem_replace_folio(&folio, gfp, info, index);
		if (error)
			goto failed;
	}
	// 加入到page cache,加入的是shmem inode的mapping
	// 一开始的参数foliop指向的是类似swap entry的东西, 现在folio已经是真正的页面指针了,
	// 指向swap mapping的页面, 这个页面也位于swap mapping
	// 包含了最新的swap file刚刚读入的对应page的内容
	// 这里把这个folio指针真正加入shmem inode的mapping
	error = shmem_add_to_page_cache(folio, mapping, index,
					swp_to_radix_entry(swap), gfp,
					charge_mm);
	if (error)
		goto failed;

	shmem_recalc_inode(inode, 0, -1);

	if (sgp == SGP_WRITE)
		folio_mark_accessed(folio);
	// 现在是shmem mapping直接指向页面了, 不需要经过swap了
	delete_from_swap_cache(folio);
	folio_mark_dirty(folio);
	swap_free(swap);
	put_swap_device(si);

	*foliop = folio;
	return 0;
failed:
	if (!shmem_confirm_swap(mapping, index, swap))
		error = -EEXIST;
	if (error == -EIO)
		shmem_set_folio_swapin_error(inode, index, folio, swap);
unlock:
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
	put_swap_device(si);

	return error;
}

/*
获取shmem mapping的某个页,在就是在, 不在的话就换入,换入也不行的话,就分配新页
----------------
从文件映射中获取页,如果页不在文件映射中,则从交换缓存中获取页,如果页不在交换缓存中,则分配新页
 * shmem_get_folio_gfp - find page in cache, or get from swap, or allocate
 *
 * If we allocate a new one we do not mark it dirty. That's up to the
 * vm. If we swap it in we mark it dirty since we also free the swap
 * entry since a page cannot live in both the swap and page cache.
 * 如果我们分配一个新的,我们不会标记它为脏页,这是由vm来决定的,如果我们从交换缓存
   中获取页,我们会标记它为脏页,因为我们也会释放交换条目,因为一个页不能同时存在于
   交换缓存和页缓存中
 * vma, vmf, and fault_type are only supplied by shmem_fault:
 * otherwise they are NULL.
 ------------------
 shmem mmap缺页时来到这里, 看来是vma映射mapping里面的页
 */
static int shmem_get_folio_gfp(struct inode *inode, pgoff_t index,
		struct folio **foliop, enum sgp_type sgp, gfp_t gfp,
		struct vm_area_struct *vma, struct vm_fault *vmf,
		vm_fault_t *fault_type)
{
	// 操作的是inode的mapping, shmem文件的mapping
	struct address_space *mapping = inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo;
	struct mm_struct *charge_mm;
	struct folio *folio;
	pgoff_t hindex;
	gfp_t huge_gfp;
	int error;
	int once = 0;
	int alloced = 0;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG;
repeat:
	if (sgp <= SGP_CACHE &&
	    ((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		return -EINVAL;
	}

	sbinfo = SHMEM_SB(inode->i_sb);
	charge_mm = vma ? vma->vm_mm : NULL;

	/* 从mmap文件的缓存里查找 */
	folio = filemap_get_entry(mapping, index);
	/* 处理与uffd机制相关的东西 */
	if (folio && vma && userfaultfd_minor(vma)) {
		if (!xa_is_value(folio))
			folio_put(folio);
		*fault_type = handle_userfault(vmf, VM_UFFD_MINOR);
		return 0;
	}

	/* shmem的mapping里面这个page被换出了 */
	if (xa_is_value(folio)) {
		error = shmem_swapin_folio(inode, index, &folio,
					  sgp, gfp, vma, fault_type);// 函数会读这个
		//swap mapping（也可能从swap file新读入）, 然后把这个swap mapping的页面加入到shmem mapping
		if (error == -EEXIST)
			goto repeat;

		*foliop = folio;
		return error; // 从交换缓存读了,这里直接返回就行
		/* 之所以直接返回, 因为肯定是新的? */
	}

	/* 到这里说明是, 直接从shmem的mapping获取的, 没有经历换入什么的 */
	if (folio) {
		folio_lock(folio);

		/* Has the folio been truncated or swapped out? */
		if (unlikely(folio->mapping != mapping)) { //可能是被截断或者被交换出去了
			folio_unlock(folio);
			folio_put(folio);
			goto repeat;
		}
		/* 这里为什么仅仅写入才mark accessed
		读取shmem的read iter函数走到这里的sgp是read */
		if (sgp == SGP_WRITE)
			folio_mark_accessed(folio);

		if (folio_test_uptodate(folio))
			goto out;

			/* 到这里 可能是 读 写 cache fallocate */
		/* fallocated folio */
		if (sgp != SGP_READ)
			goto clear;
		/* page不新, 并且是read */
		folio_unlock(folio);
		folio_put(folio);
	}

	// 到这里可能是shmem mapping没有folio, 也不是被交换了 （文件需要扩大?）
	// 如果有了folio, 就是read不新的page的情况
	/*
	 * SGP_READ: succeed on hole, with NULL folio, letting caller zero.
	 * SGP_NOALLOC: fail on hole, with NULL folio, letting caller fail.
	 */
	*foliop = NULL;
	/*  */
	if (sgp == SGP_READ)
		return 0;

	/* 到这里就是shmem不存在页面 */
	if (sgp == SGP_NOALLOC)
		return -ENOENT;

	/* 到这里就是shmem mapping不存在页面, 这里准备分配 */
	/*
	 * Fast cache lookup and swap lookup did not find it: allocate.
	 */

	if (vma && userfaultfd_missing(vma)) {
		*fault_type = handle_userfault(vmf, VM_UFFD_MISSING);
		return 0;
	}

	//下面是开始分配了?
	if (!shmem_is_huge(inode, index, false,
			   vma ? vma->vm_mm : NULL, vma ? vma->vm_flags : 0))
		goto alloc_nohuge;
	//这里是分配巨页
	huge_gfp = vma_thp_gfp_mask(vma);
	huge_gfp = limit_gfp_mask(huge_gfp, gfp);
	folio = shmem_alloc_and_acct_folio(huge_gfp, inode, index, true);

	if (IS_ERR(folio)) {

alloc_nohuge:
	//如果不是巨页的话,从这里分配
		folio = shmem_alloc_and_acct_folio(gfp, inode, index, false);
	}

//已经尝试第一次页面分配了

	if (IS_ERR(folio)) {//如果第一次页面分配出错了
		int retry = 5;

		error = PTR_ERR(folio);
		folio = NULL;
		if (error != -ENOSPC)
			goto unlock;

		//因为空间不足分配新页失败, 这里多试几次.
		/*
		 * Try to reclaim some space by splitting a large folio
		 * beyond i_size on the filesystem.
		   尝试通过在文件系统上i_size之外拆分大folio来回收一些空间。
		 */
		while (retry--) {
			int ret;

			ret = shmem_unused_huge_shrink(sbinfo, NULL, 1);
			if (ret == SHRINK_STOP)
				break;
			if (ret)
				goto alloc_nohuge;
		}

		//重试很多次也是不行
		goto unlock;
	}

//到这, 新的folio分配成功了

	hindex = round_down(index, folio_nr_pages(folio));

	if (sgp == SGP_WRITE)
		__folio_set_referenced(folio);

	//加入pagecache, 把新分配的folio加入到inode的mapping的xas里面
	error = shmem_add_to_page_cache(folio, mapping, hindex,
					NULL, gfp & GFP_RECLAIM_MASK,
					charge_mm);
	if (error)
		goto unacct;

	folio_add_lru(folio);
	shmem_recalc_inode(inode, folio_nr_pages(folio), 0);
	alloced = true;

	if (folio_test_pmd_mappable(folio) &&
	    DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE) <
					folio_next_index(folio) - 1) {
		/*
		 * Part of the large folio is beyond i_size: subject
		 * to shrink under memory pressure.
		 */
		spin_lock(&sbinfo->shrinklist_lock);
		/*
		 * _careful to defend against unlocked access to
		 * ->shrink_list in shmem_unused_huge_shrink()
		 */
		if (list_empty_careful(&info->shrinklist)) {
			list_add_tail(&info->shrinklist,
				      &sbinfo->shrinklist);
			sbinfo->shrinklist_len++;
		}
		spin_unlock(&sbinfo->shrinklist_lock);
	}

	/*
	 * Let SGP_FALLOC use the SGP_WRITE optimization on a new folio.
	 */
	if (sgp == SGP_FALLOC)
		sgp = SGP_WRITE;
clear:
	/*
	 * Let SGP_WRITE caller clear ends if write does not fill folio;
	 * but SGP_FALLOC on a folio fallocated earlier must initialize
	 * it now, lest undo on failure cancel our earlier guarantee.
	 */
	if (sgp != SGP_WRITE && !folio_test_uptodate(folio)) {
		long i, n = folio_nr_pages(folio);

		for (i = 0; i < n; i++)
			clear_highpage(folio_page(folio, i));
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
	}

	/* Perhaps the file has been truncated since we checked */
	if (sgp <= SGP_CACHE &&
	    ((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		if (alloced) {
			folio_clear_dirty(folio);
			filemap_remove_folio(folio);
			shmem_recalc_inode(inode, 0, 0);
		}
		error = -EINVAL;
		goto unlock;
	}
out:
// 如果找到了uptodate的folio, 会来到这里
	*foliop = folio;
	return 0;

	/*
	 * Error recovery.
	 */
unacct:
	shmem_inode_unacct_blocks(inode, folio_nr_pages(folio));

	if (folio_test_large(folio)) {
		folio_unlock(folio);
		folio_put(folio);
		goto alloc_nohuge;
	}
unlock:
//失败的处理, 直接跳到这里
//shmem分配新页时发生除了空间不足之外的错误, 或者空间不足但是重试了很多次也不行. 总之无法分配新页
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
	if (error == -ENOSPC && !once++) {
		//还重试???
		shmem_recalc_inode(inode, 0, 0);
		goto repeat;
	}

	if (error == -EEXIST)
		goto repeat;

	return error;
}

/*  
获取shmem的mapping页面. 赋值到foliop
是一个很通用很频繁的接口
1 直接找, 2 换入, 3 分配新页加入mapping
===========================
读取shmem文件时, 会调用这个
 */
int shmem_get_folio(struct inode *inode, pgoff_t index, struct folio **foliop,
		enum sgp_type sgp)
{
	return shmem_get_folio_gfp(inode, index, foliop, sgp,mapping_gfp_mask(inode->i_mapping),
	 NULL, NULL, NULL);
}

/*
 * This is like autoremove_wake_function, but it removes the wait queue
 * entry unconditionally - even if something else had already woken the
 * target.
   类似于autoremove_wake_function，但是它无条件地删除等待队列条目-即使其他东西已经唤醒了目标。
 */
static int synchronous_wake_function(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	int ret = default_wake_function(wait, mode, sync, key);
	list_del_init(&wait->entry);
	return ret;
}

/*
 shmem mmap的vma缺页的处理函数
 映射到shmem文件的vma缺页时, 会执行这个回调.
 */
static vm_fault_t shmem_fault(struct vm_fault *vmf)
{
	/* 进程发生缺页的vma */
	struct vm_area_struct *vma = vmf->vma;
	/* 被vma映射的shmem文件 */
	struct inode *inode = file_inode(vma->vm_file);
	gfp_t gfp = mapping_gfp_mask(inode->i_mapping);
	struct folio *folio = NULL;
	int err;
	vm_fault_t ret = VM_FAULT_LOCKED;

	/*
	 * Trinity finds that probing a hole which tmpfs is punching can
	 * prevent the hole-punch from ever completing: which in turn
	 * locks writers out with its hold on i_rwsem.  So refrain from
	 * faulting pages into the hole while it's being punched.  Although
	 * shmem_undo_range() does remove the additions, it may be unable to
	 * keep up, as each new page needs its own unmap_mapping_range() call,
	 * and the i_mmap tree grows ever slower to scan if new vmas are added.
	 * 翻译: Trinity发现，探测tmpfs正在打孔的空洞可能会阻止孔的完成：
	 这反过来又通过持有i_rwsem锁定了写入者。因此，在打孔时避免将页面故障到空洞中。
	 尽管shmem_undo_range()确实删除了这些添加，但它可能无法跟上，因为每个新页面都
	 需要自己的unmap_mapping_range()调用，如果添加了新的vmas，则i_mmap树扫描速度
	 会变得越来越慢。
	 * It does not matter if we sometimes reach this check just before the
	 * hole-punch begins, so that one fault then races with the punch:
	 * we just need to make racing faults a rare case.
	 * 如果我们有时在孔打孔开始之前到达这个检查点，那么这个检查点就不重要，
	 * 因此一个故障就会与打孔竞争：我们只需要使竞争故障成为一种罕见情况。
	 
	 * The implementation below would be much simpler if we just used a
	 * standard mutex or completion: but we cannot take i_rwsem in fault,
	 * and bloating every shmem inode for this unlikely case would be sad.
	 	下面的实现将更简单，如果我们只使用标准的互斥锁或完成：但我们不能在故障中
		使用i_rwsem，并且为这种不太可能的情况膨胀每个shmem inode将是令人沮丧的。

	 */
	if (unlikely(inode->i_private)) {
		struct shmem_falloc *shmem_falloc;

		spin_lock(&inode->i_lock);
		shmem_falloc = inode->i_private;
		if (shmem_falloc &&
		    shmem_falloc->waitq &&
		    vmf->pgoff >= shmem_falloc->start &&
		    vmf->pgoff < shmem_falloc->next) { //如果pgoff位于falloc的范围内
			struct file *fpin;
			wait_queue_head_t *shmem_falloc_waitq;

			//定义shellm_fault_wait
			DEFINE_WAIT_FUNC(shmem_fault_wait, synchronous_wake_function);

			ret = VM_FAULT_NOPAGE;
			fpin = maybe_unlock_mmap_for_io(vmf, NULL);
			if (fpin)
				ret = VM_FAULT_RETRY;

			shmem_falloc_waitq = shmem_falloc->waitq;
			prepare_to_wait(shmem_falloc_waitq, &shmem_fault_wait,
					TASK_UNINTERRUPTIBLE);
			spin_unlock(&inode->i_lock);
			schedule();

			/*
			 * shmem_falloc_waitq points into the shmem_fallocate()
			 * stack of the hole-punching task: shmem_falloc_waitq
			 * is usually invalid by the time we reach here, but
			 * finish_wait() does not dereference it in that case;
			 * though i_lock needed lest racing with wake_up_all().
			 * shmem_falloc_waitq指向shmem_fallocate()的堆栈，
			 * 通常在我们到达这里时shmem_falloc_waitq无效，
			 * 但是finish_wait()在这种情况下不会解引用它；
			 * 虽然i_lock需要与wake_up_all()竞争。
			 */
			spin_lock(&inode->i_lock);
			finish_wait(shmem_falloc_waitq, &shmem_fault_wait);
			spin_unlock(&inode->i_lock);

			if (fpin)
				fput(fpin);
			return ret;
		}
		spin_unlock(&inode->i_lock);
	}

	//从shmem的mapping获取页面, 并把获取到的页面赋值到vmf->page
	// 内核下一步会把这个vmf->page映射到vma对应的的页表项
	err = shmem_get_folio_gfp(inode, vmf->pgoff, &folio, SGP_CACHE,
				  gfp, vma, vmf, &ret);
	if (err)
		return vmf_error(err);
	if (folio)
		vmf->page = folio_file_page(folio, vmf->pgoff);
	return ret;
}

/* shmem fs的常规文件的get_unmapped_area回调 */
unsigned long shmem_get_unmapped_area(struct file *file,
				      unsigned long uaddr, unsigned long len,
				      unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *,
		unsigned long, unsigned long, unsigned long, unsigned long);
	unsigned long addr;
	unsigned long offset;
	unsigned long inflated_len;
	unsigned long inflated_addr;
	unsigned long inflated_offset;

	if (len > TASK_SIZE)
		return -ENOMEM;

	get_area = current->mm->get_unmapped_area;
	addr = get_area(file, uaddr, len, pgoff, flags);

	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return addr;
	if (IS_ERR_VALUE(addr))
		return addr;
	if (addr & ~PAGE_MASK)
		return addr;
	if (addr > TASK_SIZE - len)
		return addr;

	if (shmem_huge == SHMEM_HUGE_DENY)
		return addr;
	if (len < HPAGE_PMD_SIZE)
		return addr;
	if (flags & MAP_FIXED)
		return addr;
	/*
	 * Our priority is to support MAP_SHARED mapped hugely;
	 * and support MAP_PRIVATE mapped hugely too, until it is COWed.
	 * But if caller specified an address hint and we allocated area there
	 * successfully, respect that as before.
	 */
	if (uaddr == addr)
		return addr;

	if (shmem_huge != SHMEM_HUGE_FORCE) {
		struct super_block *sb;

		if (file) {
			VM_BUG_ON(file->f_op != &shmem_file_operations);
			sb = file_inode(file)->i_sb;
		} else {
			/*
			 * Called directly from mm/mmap.c, or drivers/char/mem.c
			 * for "/dev/zero", to create a shared anonymous object.
			 */
			if (IS_ERR(shm_mnt))
				return addr;
			sb = shm_mnt->mnt_sb;
		}
		if (SHMEM_SB(sb)->huge == SHMEM_HUGE_NEVER)
			return addr;
	}

	offset = (pgoff << PAGE_SHIFT) & (HPAGE_PMD_SIZE-1);
	if (offset && offset + len < 2 * HPAGE_PMD_SIZE)
		return addr;
	if ((addr & (HPAGE_PMD_SIZE-1)) == offset)
		return addr;

	inflated_len = len + HPAGE_PMD_SIZE - PAGE_SIZE;
	if (inflated_len > TASK_SIZE)
		return addr;
	if (inflated_len < len)
		return addr;

	inflated_addr = get_area(NULL, uaddr, inflated_len, 0, flags);
	if (IS_ERR_VALUE(inflated_addr))
		return addr;
	if (inflated_addr & ~PAGE_MASK)
		return addr;

	inflated_offset = inflated_addr & (HPAGE_PMD_SIZE-1);
	inflated_addr += offset - inflated_offset;
	if (inflated_offset > offset)
		inflated_addr += HPAGE_PMD_SIZE;

	if (inflated_addr > TASK_SIZE - len)
		return addr;
	return inflated_addr;
}

#ifdef CONFIG_NUMA
static int shmem_set_policy(struct vm_area_struct *vma, struct mempolicy *mpol)
{
	struct inode *inode = file_inode(vma->vm_file);
	return mpol_set_shared_policy(&SHMEM_I(inode)->policy, vma, mpol);
}

static struct mempolicy *shmem_get_policy(struct vm_area_struct *vma,
					  unsigned long addr)
{
	struct inode *inode = file_inode(vma->vm_file);
	pgoff_t index;

	index = ((addr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	return mpol_shared_policy_lookup(&SHMEM_I(inode)->policy, index);
}
#endif

// 主要用于ipc
int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
{
	struct inode *inode = file_inode(file);
	struct shmem_inode_info *info = SHMEM_I(inode);
	int retval = -ENOMEM;

	/*
	 * What serializes the accesses to info->flags?
	 * ipc_lock_object() when called from shmctl_do_lock(),
	 * no serialization needed when called from shm_destroy().
	 */
	if (lock && !(info->flags & VM_LOCKED)) {
		if (!user_shm_lock(inode->i_size, ucounts))
			goto out_nomem;
		info->flags |= VM_LOCKED;
		mapping_set_unevictable(file->f_mapping);
	}
	if (!lock && (info->flags & VM_LOCKED) && ucounts) {
		user_shm_unlock(inode->i_size, ucounts);
		info->flags &= ~VM_LOCKED;
		mapping_clear_unevictable(file->f_mapping);
	}
	retval = 0;

out_nomem:
	return retval;
}

/* shmem 的fops, mmap回调
mmap这个文件, 参数@vma要映射地址空间到这个文件 */
static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct shmem_inode_info *info = SHMEM_I(inode);
	int ret;

	ret = seal_check_future_write(info->seals, vma);
	if (ret)
		return ret;

	/* arm64 - allow memory tagging on RAM-based files */
	vm_flags_set(vma, VM_MTE_ALLOWED);

	file_accessed(file);
	/* This is anonymous shared memory if it is unlinked at the time of mmap
	i_nlink, 这里i_nlink是什么, 20250702153329
	 */
	if (inode->i_nlink)
		vma->vm_ops = &shmem_vm_ops;  //文件的shmem
	else
		vma->vm_ops = &shmem_anon_vm_ops; //为什么还有匿名的shmem? 20250702152530
	return 0;
}
/* shmem fs的常规文件open ops
============
这里没什么特别的工作.
 */
static int shmem_file_open(struct inode *inode, struct file *file)
{
	file->f_mode |= FMODE_CAN_ODIRECT;
	return generic_file_open(inode, file);
}

#ifdef CONFIG_TMPFS_XATTR
static int shmem_initxattrs(struct inode *, const struct xattr *, void *);

/*
 * chattr's fsflags are unrelated to extended attributes,
 * but tmpfs has chosen to enable them under the same config option.
 */
static void shmem_set_inode_flags(struct inode *inode, unsigned int fsflags)
{
	unsigned int i_flags = 0;

	if (fsflags & FS_NOATIME_FL)
		i_flags |= S_NOATIME;
	if (fsflags & FS_APPEND_FL)
		i_flags |= S_APPEND;
	if (fsflags & FS_IMMUTABLE_FL)
		i_flags |= S_IMMUTABLE;
	/*
	 * But FS_NODUMP_FL does not require any action in i_flags.
	 */
	inode_set_flags(inode, i_flags, S_NOATIME | S_APPEND | S_IMMUTABLE);
}
#else
static void shmem_set_inode_flags(struct inode *inode, unsigned int fsflags)
{
}
#define shmem_initxattrs NULL
#endif

static struct offset_ctx *shmem_get_offset_ctx(struct inode *inode)
{
	return &SHMEM_I(inode)->dir_offsets;
}

/* shmem fs分配inode */
static struct inode *__shmem_get_inode(struct mnt_idmap *idmap,
					     struct super_block *sb,
					     struct inode *dir, umode_t mode,
					     dev_t dev, unsigned long flags)
{
	struct inode *inode;
	struct shmem_inode_info *info;
	// 取出文件系统特定sb
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	ino_t ino;
	int err;
	// 分配inode, 这里先获取inode号,好像其实也已经“预留了”
	err = shmem_reserve_inode(sb, &ino);
	if (err)
		return ERR_PTR(err);

	// 新建inode
	inode = new_inode(sb);
	if (!inode) {
		shmem_free_inode(sb, 0);
		return ERR_PTR(-ENOSPC);
	}

	inode->i_ino = ino;
	inode_init_owner(idmap, inode, dir, mode);
	inode->i_blocks = 0;
	inode->i_atime = inode->i_mtime = inode_set_ctime_current(inode);
	inode->i_generation = get_random_u32();
	info = SHMEM_I(inode);
	memset(info, 0, (char *)inode - (char *)info);
	spin_lock_init(&info->lock);
	atomic_set(&info->stop_eviction, 0);
	info->seals = F_SEAL_SEAL;
	info->flags = flags & VM_NORESERVE;
	info->i_crtime = inode->i_mtime;
	info->fsflags = (dir == NULL) ? 0 :
		SHMEM_I(dir)->fsflags & SHMEM_FL_INHERITED;
	if (info->fsflags)
		shmem_set_inode_flags(inode, info->fsflags);
	INIT_LIST_HEAD(&info->shrinklist);
	INIT_LIST_HEAD(&info->swaplist);
	INIT_LIST_HEAD(&info->swaplist);
	if (sbinfo->noswap) // 没有swap的情况
		mapping_set_unevictable(inode->i_mapping);
	simple_xattrs_init(&info->xattrs);
	cache_no_acl(inode);
	mapping_set_large_folios(inode->i_mapping);

	switch (mode & S_IFMT) {
	default:
		inode->i_op = &shmem_special_inode_operations;
		init_special_inode(inode, mode, dev);
		break;
	case S_IFREG:
	/* 常规文件 */
		inode->i_mapping->a_ops = &shmem_aops;
		inode->i_op = &shmem_inode_operations;
		inode->i_fop = &shmem_file_operations;
		mpol_shared_policy_init(&info->policy,
					 shmem_get_sbmpol(sbinfo));
		break;
	case S_IFDIR:
	/* 文件夹 */
		inc_nlink(inode);
		/* Some things misbehave if size == 0 on a directory */
		inode->i_size = 2 * BOGO_DIRENT_SIZE;
		inode->i_op = &shmem_dir_inode_operations;
		inode->i_fop = &simple_offset_dir_operations;
		simple_offset_init(shmem_get_offset_ctx(inode));
		break;
	case S_IFLNK:
		/*
		 * Must not load anything in the rbtree,
		 * mpol_free_shared_policy will not be called.
		 */
		mpol_shared_policy_init(&info->policy, NULL);
		break;
	}

	lockdep_annotate_inode_mutex_key(inode);
	return inode;
}

#ifdef CONFIG_TMPFS_QUOTA
// shmem fs分配新inode
static struct inode *shmem_get_inode(struct mnt_idmap *idmap,
				     struct super_block *sb, struct inode *dir,
				     umode_t mode, dev_t dev, unsigned long flags)
{
	int err;
	struct inode *inode;
	// 这里分配新inode
	inode = __shmem_get_inode(idmap, sb, dir, mode, dev, flags);
	if (IS_ERR(inode))
		return inode;

	err = dquot_initialize(inode);
	if (err)
		goto errout;

	err = dquot_alloc_inode(inode);
	if (err) {
		dquot_drop(inode);
		goto errout;
	}
	return inode;

errout:
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	return ERR_PTR(err);
}
#else
static inline struct inode *shmem_get_inode(struct mnt_idmap *idmap,
				     struct super_block *sb, struct inode *dir,
				     umode_t mode, dev_t dev, unsigned long flags)
{
	return __shmem_get_inode(idmap, sb, dir, mode, dev, flags);
}
#endif /* CONFIG_TMPFS_QUOTA */

#ifdef CONFIG_USERFAULTFD
/* 
把页面添加到shmem的mapping，uffd安装pte */
int shmem_mfill_atomic_pte(pmd_t *dst_pmd,
			   struct vm_area_struct *dst_vma,
			   unsigned long dst_addr,
			   unsigned long src_addr,
			   uffd_flags_t flags,
			   struct folio **foliop)
{
	struct inode *inode = file_inode(dst_vma->vm_file);
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfp = mapping_gfp_mask(mapping);
	/* 获取到dst addr对应的pgoff */
	pgoff_t pgoff = linear_page_index(dst_vma, dst_addr);
	void *page_kaddr;
	struct folio *folio;
	int ret;
	pgoff_t max_off;
	/* 
	内存的记账？
	*/
	if (shmem_inode_acct_block(inode, 1)) {
		/*
		 * We may have got a page, returned -ENOENT triggering a retry,
		 * and now we find ourselves with -ENOMEM. Release the page, to
		 * avoid a BUG_ON in our caller.
		 */
		if (unlikely(*foliop)) {
			folio_put(*foliop);
			*foliop = NULL;
		}
		return -ENOMEM;
	}

	if (!*foliop) {/* 如果folio还没有页面 */
		ret = -ENOMEM;
		/* 分配一个页面 */
		folio = shmem_alloc_folio(gfp, info, pgoff);
		if (!folio)
			goto out_unacct_blocks;

		if (uffd_flags_mode_is(flags, MFILL_ATOMIC_COPY)) {/* 
			如果是copy的uffd
			把用户src处的数据copy到这个页面
			*/
			page_kaddr = kmap_local_folio(folio, 0);
			/*
			 * The read mmap_lock is held here.  Despite the
			 * mmap_lock being read recursive a deadlock is still
			 * possible if a writer has taken a lock.  For example:
			 *
			 * process A thread 1 takes read lock on own mmap_lock
			 * process A thread 2 calls mmap, blocks taking write lock
			 * process B thread 1 takes page fault, read lock on own mmap lock
			 * process B thread 2 calls mmap, blocks taking write lock
			 * process A thread 1 blocks taking read lock on process B
			 * process B thread 1 blocks taking read lock on process A
			 *
			 * Disable page faults to prevent potential deadlock
			 * and retry the copy outside the mmap_lock.
			 */
			/* 先关闭pf，然后拷贝数据 */
			pagefault_disable();
			ret = copy_from_user(page_kaddr,
					     (const void __user *)src_addr,
					     PAGE_SIZE);
			pagefault_enable();
			kunmap_local(page_kaddr);

			/* fallback to copy_from_user outside mmap_lock */
			if (unlikely(ret)) {
				*foliop = folio;
				ret = -ENOENT;
				/* don't free the page */
				goto out_unacct_blocks;
			}

			flush_dcache_folio(folio);
		} else {		/* ZEROPAGE */
			clear_user_highpage(&folio->page, dst_addr);
		}
	} else {/* 参数的folio直接有页面了 */
		folio = *foliop;
		VM_BUG_ON_FOLIO(folio_test_large(folio), folio);
		*foliop = NULL;
	}

	VM_BUG_ON(folio_test_locked(folio));
	VM_BUG_ON(folio_test_swapbacked(folio));
	__folio_set_locked(folio);
	__folio_set_swapbacked(folio);
	__folio_mark_uptodate(folio);

	ret = -EFAULT;
	max_off = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(pgoff >= max_off))
		goto out_release;
	/* 这里是把这个页面加入到shmem的mapping */
	ret = shmem_add_to_page_cache(folio, mapping, pgoff, NULL,
				      gfp & GFP_RECLAIM_MASK, dst_vma->vm_mm);
	if (ret)
		goto out_release;
	/* 安装pte */
	ret = mfill_atomic_install_pte(dst_pmd, dst_vma, dst_addr,
				       &folio->page, true, flags);
	if (ret)
		goto out_delete_from_cache;

	shmem_recalc_inode(inode, 1, 0);
	folio_unlock(folio);
	return 0;
out_delete_from_cache:
	filemap_remove_folio(folio);
out_release:
	folio_unlock(folio);
	folio_put(folio);
out_unacct_blocks:
	shmem_inode_unacct_blocks(inode, 1);
	return ret;
}
#endif /* CONFIG_USERFAULTFD */

#ifdef CONFIG_TMPFS
static const struct inode_operations shmem_symlink_inode_operations;
static const struct inode_operations shmem_short_symlink_operations;


//
/*
shmem的write begin fops, 准备写出到文件时, 会调用mapping的这个write_begin函数
其实一般也就是根据mapping和pos, 在xas里面找到对应index的folio,赋值到page
status = a_ops->write_begin(file, mapping, pos, bytes,
						&page, &fsdata);
====================================
找到要写的page,存入pagep参数
file: 文件
mapping: 文件的mapping
pos和len: 写入的位置和长度
page似乎是要写入到这个页
fsdata: 似乎是存储一些fs自己 的信息
=================
shmem有后备文件可以算是swap
 */
static int
shmem_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len,
			struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct shmem_inode_info *info = SHMEM_I(inode);
	/* pos为要写入的文件位置, 这里转为mapping的idx */
	pgoff_t index = pos >> PAGE_SHIFT;
	struct folio *folio;
	int ret = 0;

	/* i_rwsem is held by caller */
	if (unlikely(info->seals & (F_SEAL_GROW |
				   F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
		if (info->seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))
			return -EPERM;
		if ((info->seals & F_SEAL_GROW) && pos + len > inode->i_size)
			return -EPERM;
	}
	/* 找到pgoff为index的folio, 存入foliop */
	ret = shmem_get_folio(inode, index, &folio, SGP_WRITE);

	if (ret)
		return ret;
	// 这里获取到page之后好像也没做啥
	*pagep = folio_file_page(folio, index);
	if (PageHWPoison(*pagep)) {
		folio_unlock(folio);
		folio_put(folio);
		*pagep = NULL;
		return -EIO;
	}

	return 0;
}

/*
 对应与 write_begin
 ====================
 内核调用write_begin找到要回写的page, 然后拷贝, 然后这里进行回写等操作? */
static int shmem_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	/* folio刚刚已经被内核拷贝了新数据进去 */
	/* 获取要写回的folio和对应的inode文件 */
	struct folio *folio = page_folio(page);
	struct inode *inode = mapping->host;

	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);

	/* page刚刚被内核拷贝新内容进去
	然后内核调用自己执行写入过程的end操作
	这里检测到页面还不是up-to-date （按理说应该是了, 是对于写入过程的up-to-date, 对于
	后备文件, 则是需要回写的)
	===========
	所以这里会把page设置为up-to-date */
	if (!folio_test_uptodate(folio)) {
		if (copied < folio_size(folio)) {
			size_t from = offset_in_folio(folio, pos);
			folio_zero_segments(folio, 0, from,
					from + copied, folio_size(folio));
		}
		folio_mark_uptodate(folio);
	}
	/* 然后设置dirty */
	folio_mark_dirty(folio);
	folio_unlock(folio);
	folio_put(folio);

	return copied;
}
/* shmem fs的read iter回调函数 */
static ssize_t shmem_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	/* 要读取的shmem file */
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	/* shmem file的mapping */
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;
	unsigned long offset;
	int error = 0;
	ssize_t retval = 0;
	loff_t *ppos = &iocb->ki_pos;

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct folio *folio = NULL;
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}
		/* 找到要读的folio
		==================
		直接从mapping查找对应idx, 有的话就返回, 也可能是被换出了就换入. */
		error = shmem_get_folio(inode, index, &folio, SGP_READ);
		if (error) {
			if (error == -EINVAL)
				error = 0;
			break;
		}
		/* 如果成功找到了要读的page */
		if (folio) {
			folio_unlock(folio);

			page = folio_file_page(folio, index);
			if (PageHWPoison(page)) {
				folio_put(folio);
				error = -EIO;
				break;
			}
		}

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_rwsem protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (folio)
					folio_put(folio);
				break;
			}
		}
		nr -= offset;

		/* 把读到的mapping folio拷贝到用户空间 */
		if (folio) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 标记被访问了
			 */
			if (!offset)
				folio_mark_accessed(folio);
			/*
			 * Ok, we have the page, and it's up-to-date, so
			 * now we can copy it to user space... 
			 现在把要读的page的内容拷贝一下
			 拷贝到用户空间
			 */
			ret = copy_page_to_iter(page, offset, nr, to);
			folio_put(folio);

		} else if (user_backed_iter(to)) {
			/*
			 * Copy to user tends to be so well optimized, but
			 * clear_user() not so much, that it is noticeably
			 * faster to copy the zero page instead of clearing.
			 */
			ret = copy_page_to_iter(ZERO_PAGE(0), offset, nr, to);
		} else {
			/*
			 * But submitting the same page twice in a row to
			 * splice() - or others? - can result in confusion:
			 * so don't attempt that optimization on pipes etc.
			 */
			ret = iov_iter_zero(nr, to);
		}

		retval += ret;
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		if (!iov_iter_count(to))
			break;
		if (ret < nr) {
			error = -EFAULT;
			break;
		}
		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(file);
	return retval ? retval : error;
}

//shmem写入文件的fops
static ssize_t shmem_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto unlock;
	ret = file_remove_privs(file);
	if (ret)
		goto unlock;
	ret = file_update_time(file);
	if (ret)
		goto unlock;

	//开始写入
	ret = generic_perform_write(iocb, from);
unlock:
	inode_unlock(inode);
	return ret;
}

static bool zero_pipe_buf_get(struct pipe_inode_info *pipe,
			      struct pipe_buffer *buf)
{
	return true;
}

static void zero_pipe_buf_release(struct pipe_inode_info *pipe,
				  struct pipe_buffer *buf)
{
}

static bool zero_pipe_buf_try_steal(struct pipe_inode_info *pipe,
				    struct pipe_buffer *buf)
{
	return false;
}

static const struct pipe_buf_operations zero_pipe_buf_ops = {
	.release	= zero_pipe_buf_release,
	.try_steal	= zero_pipe_buf_try_steal,
	.get		= zero_pipe_buf_get,
};

static size_t splice_zeropage_into_pipe(struct pipe_inode_info *pipe,
					loff_t fpos, size_t size)
{
	size_t offset = fpos & ~PAGE_MASK;

	size = min_t(size_t, size, PAGE_SIZE - offset);

	if (!pipe_full(pipe->head, pipe->tail, pipe->max_usage)) {
		struct pipe_buffer *buf = pipe_head_buf(pipe);

		*buf = (struct pipe_buffer) {
			.ops	= &zero_pipe_buf_ops,
			.page	= ZERO_PAGE(0),
			.offset	= offset,
			.len	= size,
		};
		pipe->head++;
	}

	return size;
}

/* shmem的fops的零拷贝读的回调 */
static ssize_t shmem_file_splice_read(struct file *in, loff_t *ppos,
				      struct pipe_inode_info *pipe,
				      size_t len, unsigned int flags)
{
	struct inode *inode = file_inode(in);
	struct address_space *mapping = inode->i_mapping;
	struct folio *folio = NULL;
	size_t total_spliced = 0, used, npages, n, part;
	loff_t isize;
	int error = 0;

	/* Work out how much data we can actually add into the pipe */
	used = pipe_occupancy(pipe->head, pipe->tail);
	npages = max_t(ssize_t, pipe->max_usage - used, 0);
	len = min_t(size_t, len, npages * PAGE_SIZE);

	do {
		if (*ppos >= i_size_read(inode))
			break;

		/* 读取shmem的内容
		一般读文件disk file -> mapping -> buffer */
		error = shmem_get_folio(inode, *ppos / PAGE_SIZE, &folio,
					SGP_READ);
		if (error) {
			if (error == -EINVAL)
				error = 0;
			break;
		}
		/* hwpoison的情况 */
		if (folio) {
			folio_unlock(folio);

			if (folio_test_hwpoison(folio) ||
			    (folio_test_large(folio) &&
			     folio_test_has_hwpoisoned(folio))) {
				error = -EIO;
				break;
			}
		}

		/*
		 * i_size must be checked after we know the pages are Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		isize = i_size_read(inode);
		if (unlikely(*ppos >= isize))
			break;
		part = min_t(loff_t, isize - *ppos, len);

		if (folio) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_folio(folio);
			/* 被读取了, 设置accessed */
			folio_mark_accessed(folio);
			/*
			 * Ok, we have the page, and it's up-to-date, so we can
			 * now splice it into the pipe.
			 */
			n = splice_folio_into_pipe(pipe, folio, *ppos, part);
			folio_put(folio);
			folio = NULL;
		} else {
			/* 没在shmem mapping找到page的情况 */
			n = splice_zeropage_into_pipe(pipe, *ppos, part);
		}

		if (!n)
			break;
		len -= n;
		total_spliced += n;
		*ppos += n;
		in->f_ra.prev_pos = *ppos;
		/*  */
		if (pipe_full(pipe->head, pipe->tail, pipe->max_usage))
			break;

		cond_resched();
	} while (len);

	if (folio)
		folio_put(folio);

	file_accessed(in);
	return total_spliced ? total_spliced : error;
}

// shmem fops的seek回调
static loff_t shmem_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;

	if (whence != SEEK_DATA && whence != SEEK_HOLE)
		return generic_file_llseek_size(file, offset, whence,
					MAX_LFS_FILESIZE, i_size_read(inode));

	/* 用户的seek是SEEK_DATA或者SEEK_HOLE */
	if (offset < 0)
		return -ENXIO;

	inode_lock(inode);
	/* We're holding i_rwsem so we can access i_size directly */
	offset = mapping_seek_hole_data(mapping, offset, inode->i_size, whence);
	if (offset >= 0)
		offset = vfs_setpos(file, offset, MAX_LFS_FILESIZE);
	inode_unlock(inode);
	return offset;
}

// shmem file执行fallocate的回调
static long shmem_fallocate(struct file *file, int mode, loff_t offset,
							 loff_t len)
{
	// 先获取file的inode, 这都是一体的
	struct inode *inode = file_inode(file);
	// 获取inode的sb
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	// 一般来讲特定fs的inode实现会包含inode, container_of可以获取
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_falloc shmem_falloc;
	pgoff_t start, index, end, undo_fallocend;
	int error;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	inode_lock(inode);

	if (mode & FALLOC_FL_PUNCH_HOLE) {// 如果是打孔类型的fallocate
		struct address_space *mapping = file->f_mapping;
		loff_t unmap_start = round_up(offset, PAGE_SIZE);
		loff_t unmap_end = round_down(offset + len, PAGE_SIZE) - 1;
		DECLARE_WAIT_QUEUE_HEAD_ONSTACK(shmem_falloc_waitq);

		/* protected by i_rwsem */
		if (info->seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) {
			error = -EPERM;
			goto out;
		}

		shmem_falloc.waitq = &shmem_falloc_waitq;
		shmem_falloc.start = (u64)unmap_start >> PAGE_SHIFT;
		shmem_falloc.next = (unmap_end + 1) >> PAGE_SHIFT;
		spin_lock(&inode->i_lock);
		inode->i_private = &shmem_falloc;
		spin_unlock(&inode->i_lock);

		// mapping层面截断
		if ((u64)unmap_end > (u64)unmap_start)
			unmap_mapping_range(mapping, unmap_start,
					    1 + unmap_end - unmap_start, 0);
		// 文件层面截断
		shmem_truncate_range(inode, offset, offset + len - 1);
		/* No need to unmap again: hole-punching leaves COWed pages */

		spin_lock(&inode->i_lock);
		inode->i_private = NULL;
		wake_up_all(&shmem_falloc_waitq);
		WARN_ON_ONCE(!list_empty(&shmem_falloc_waitq.head));
		spin_unlock(&inode->i_lock);
		error = 0;
		goto out;
	}
	// 如果是其他类型的fallocate
	/* We need to check rlimit even when FALLOC_FL_KEEP_SIZE */
	error = inode_newsize_ok(inode, offset + len);
	if (error)
		goto out;

	if ((info->seals & F_SEAL_GROW) && offset + len > inode->i_size) {
		error = -EPERM;
		goto out;
	}

	start = offset >> PAGE_SHIFT;
	end = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	/* Try to avoid a swapstorm if len is impossible to satisfy */
	if (sbinfo->max_blocks && end - start > sbinfo->max_blocks) {
		error = -ENOSPC;
		goto out;
	}

	shmem_falloc.waitq = NULL;
	shmem_falloc.start = start;
	shmem_falloc.next  = start;
	shmem_falloc.nr_falloced = 0;
	shmem_falloc.nr_unswapped = 0;
	spin_lock(&inode->i_lock);
	inode->i_private = &shmem_falloc;
	spin_unlock(&inode->i_lock);

	/*
	 * info->fallocend is only relevant when huge pages might be
	 * involved: to prevent split_huge_page() freeing fallocated
	 * pages when FALLOC_FL_KEEP_SIZE committed beyond i_size.
	 */
	undo_fallocend = info->fallocend;
	if (info->fallocend < end)
		info->fallocend = end;

	for (index = start; index < end; ) {
		struct folio *folio;

		/*
		 * Good, the fallocate(2) manpage permits EINTR: we may have
		 * been interrupted because we are using up too much memory.
		 */
		if (signal_pending(current))
			error = -EINTR;
		else if (shmem_falloc.nr_unswapped > shmem_falloc.nr_falloced)
			error = -ENOMEM;
		else // 获取一个folio
			error = shmem_get_folio(inode, index, &folio,
						SGP_FALLOC);
		if (error) {// 出错了就撤销刚刚分配的
			info->fallocend = undo_fallocend;
			/* Remove the !uptodate folios we added */
			if (index > start) {
				shmem_undo_range(inode,
				    (loff_t)start << PAGE_SHIFT,
				    ((loff_t)index << PAGE_SHIFT) - 1, true);
			}
			goto undone;
		}

		/*
		 * Here is a more important optimization than it appears:
		 * a second SGP_FALLOC on the same large folio will clear it,
		 * making it uptodate and un-undoable if we fail later.
		 */
		index = folio_next_index(folio);
		/* Beware 32-bit wraparound */
		if (!index)
			index--;

		/*
		 * Inform shmem_writepage() how far we have reached.
		 * No need for lock or barrier: we have the page lock.
		 */
		if (!folio_test_uptodate(folio))
			shmem_falloc.nr_falloced += index - shmem_falloc.next;
		shmem_falloc.next = index;

		/*
		 * If !uptodate, leave it that way so that freeable folios
		 * can be recognized if we need to rollback on error later.
		 * But mark it dirty so that memory pressure will swap rather
		 * than free the folios we are allocating (and SGP_CACHE folios
		 * might still be clean: we now need to mark those dirty too).
		 */
		folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
		cond_resched();
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && offset + len > inode->i_size)
		i_size_write(inode, offset + len);
undone:
	spin_lock(&inode->i_lock);
	inode->i_private = NULL;
	spin_unlock(&inode->i_lock);
out:
	if (!error)
		file_modified(file);
	inode_unlock(inode);
	return error;
}

// fops的statfs回调
static int shmem_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(dentry->d_sb);

	buf->f_type = TMPFS_MAGIC;
	buf->f_bsize = PAGE_SIZE;
	buf->f_namelen = NAME_MAX;
	if (sbinfo->max_blocks) {
		buf->f_blocks = sbinfo->max_blocks;
		buf->f_bavail =
		buf->f_bfree  = sbinfo->max_blocks -
				percpu_counter_sum(&sbinfo->used_blocks);
	}
	if (sbinfo->max_inodes) {
		buf->f_files = sbinfo->max_inodes;
		buf->f_ffree = sbinfo->free_ispace / BOGO_INODE_SIZE;
	}
	/* else leave those fields 0 like simple_statfs */

	buf->f_fsid = uuid_to_fsid(dentry->d_sb->s_uuid.b);

	return 0;
}

/*
 * File creation. Allocate an inode, and we're done..
shmem分配inode mknod回调
 */
static int shmem_mknod(struct mnt_idmap *idmap, struct inode *dir,
	    struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode *inode;
	int error;
	// 获取inode
	inode = shmem_get_inode(idmap, dir->i_sb, dir, mode, dev, VM_NORESERVE);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	error = simple_acl_create(dir, inode);
	if (error)
		goto out_iput;
	error = security_inode_init_security(inode, dir,
					     &dentry->d_name,
					     shmem_initxattrs, NULL);
	if (error && error != -EOPNOTSUPP)
		goto out_iput;

	error = simple_offset_add(shmem_get_offset_ctx(dir), dentry);
	if (error)
		goto out_iput;

	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_mtime = inode_set_ctime_current(dir);
	inode_inc_iversion(dir);
	// 填充信息
	d_instantiate(dentry, inode);
	dget(dentry); /* Extra count - pin the dentry in core */
	return error;

out_iput:
	iput(inode);
	return error;
}

// shmem 创建tmpfile的回调
static int shmem_tmpfile(struct mnt_idmap *idmap, struct inode *dir,
	      struct file *file, umode_t mode)
{
	struct inode *inode;
	int error;

	// 一样的获取inode
	inode = shmem_get_inode(idmap, dir->i_sb, dir, mode, 0, VM_NORESERVE);

	if (IS_ERR(inode)) {
		error = PTR_ERR(inode);
		goto err_out;
	}

	error = security_inode_init_security(inode, dir,
					     NULL,
					     shmem_initxattrs, NULL);
	if (error && error != -EOPNOTSUPP)
		goto out_iput;
	error = simple_acl_create(dir, inode);
	if (error)
		goto out_iput;
	// 参数是已经有的file和新建的inode
	// 这个回调一般什么事调用呢
	d_tmpfile(file, inode);

err_out:
	return finish_open_simple(file, error);
out_iput:
	iput(inode);
	return error;
}

// shmem创建目录的回调, 好像就是把inode的mode设置为目录
static int shmem_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	int error;

	error = shmem_mknod(idmap, dir, dentry, mode | S_IFDIR, 0);
	if (error)
		return error;
	inc_nlink(dir);
	return 0;
}

// 创建文件
static int shmem_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	return shmem_mknod(idmap, dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 好像是硬链接
 三个参数分别是什么?
 */
static int shmem_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);
	int ret = 0;

	/*
	 * No ordinary (disk based) filesystem counts links as inodes;
	 * but each new link needs a new dentry, pinning lowmem, and
	 * tmpfs dentries cannot be pruned until they are unlinked.
	 * But if an O_TMPFILE file is linked into the tmpfs, the
	 * first link must skip that, to get the accounting right.
	 */
	if (inode->i_nlink) {
		ret = shmem_reserve_inode(inode->i_sb, NULL);
		if (ret)
			goto out;
	}

	ret = simple_offset_add(shmem_get_offset_ctx(dir), dentry);
	if (ret) {
		if (inode->i_nlink)
			shmem_free_inode(inode->i_sb, 0);
		goto out;
	}

	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_mtime = inode_set_ctime_to_ts(dir,
					     inode_set_ctime_current(inode));
	inode_inc_iversion(dir);
	inc_nlink(inode);
	ihold(inode);	/* New dentry reference */
	dget(dentry);		/* Extra pinning count for the created dentry */
	d_instantiate(dentry, inode);
out:
	return ret;
}

static int shmem_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	if (inode->i_nlink > 1 && !S_ISDIR(inode->i_mode))
		shmem_free_inode(inode->i_sb, 0);

	simple_offset_remove(shmem_get_offset_ctx(dir), dentry);

	dir->i_size -= BOGO_DIRENT_SIZE;
	dir->i_mtime = inode_set_ctime_to_ts(dir,
					     inode_set_ctime_current(inode));
	inode_inc_iversion(dir);
	drop_nlink(inode);
	dput(dentry);	/* Undo the count from "create" - this does all the work */
	return 0;
}

static int shmem_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	drop_nlink(d_inode(dentry));
	drop_nlink(dir);
	return shmem_unlink(dir, dentry);
}

static int shmem_whiteout(struct mnt_idmap *idmap,
			  struct inode *old_dir, struct dentry *old_dentry)
{
	struct dentry *whiteout;
	int error;

	whiteout = d_alloc(old_dentry->d_parent, &old_dentry->d_name);
	if (!whiteout)
		return -ENOMEM;

	error = shmem_mknod(idmap, old_dir, whiteout,
			    S_IFCHR | WHITEOUT_MODE, WHITEOUT_DEV);
	dput(whiteout);
	if (error)
		return error;

	/*
	 * Cheat and hash the whiteout while the old dentry is still in
	 * place, instead of playing games with FS_RENAME_DOES_D_MOVE.
	 *
	 * d_lookup() will consistently find one of them at this point,
	 * not sure which one, but that isn't even important.
	 */
	d_rehash(whiteout);
	return 0;
}

/*
 * The VFS layer already does all the dentry stuff for rename,
 * we just have to decrement the usage count for the target if
 * it exists so that the VFS layer correctly free's it when it
 * gets overwritten.
 */
static int shmem_rename2(struct mnt_idmap *idmap,
			 struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	struct inode *inode = d_inode(old_dentry);
	int they_are_dirs = S_ISDIR(inode->i_mode);
	int error;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	if (flags & RENAME_EXCHANGE)
		return simple_offset_rename_exchange(old_dir, old_dentry,
						     new_dir, new_dentry);

	if (!simple_empty(new_dentry))
		return -ENOTEMPTY;

	if (flags & RENAME_WHITEOUT) {
		error = shmem_whiteout(idmap, old_dir, old_dentry);
		if (error)
			return error;
	}

	simple_offset_remove(shmem_get_offset_ctx(old_dir), old_dentry);
	error = simple_offset_add(shmem_get_offset_ctx(new_dir), old_dentry);
	if (error)
		return error;

	if (d_really_is_positive(new_dentry)) {
		(void) shmem_unlink(new_dir, new_dentry);
		if (they_are_dirs) {
			drop_nlink(d_inode(new_dentry));
			drop_nlink(old_dir);
		}
	} else if (they_are_dirs) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	old_dir->i_size -= BOGO_DIRENT_SIZE;
	new_dir->i_size += BOGO_DIRENT_SIZE;
	simple_rename_timestamp(old_dir, old_dentry, new_dir, new_dentry);
	inode_inc_iversion(old_dir);
	inode_inc_iversion(new_dir);
	return 0;
}

/* shmem fs的建立符号链接的fops? */
static int shmem_symlink(struct mnt_idmap *idmap, struct inode *dir,
			 struct dentry *dentry, const char *symname)
{
	int error;
	int len;
	struct inode *inode;
	struct folio *folio;

	len = strlen(symname) + 1;
	if (len > PAGE_SIZE)
		return -ENAMETOOLONG;

	inode = shmem_get_inode(idmap, dir->i_sb, dir, S_IFLNK | 0777, 0,
				VM_NORESERVE);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	error = security_inode_init_security(inode, dir, &dentry->d_name,
					     shmem_initxattrs, NULL);
	if (error && error != -EOPNOTSUPP)
		goto out_iput;

	error = simple_offset_add(shmem_get_offset_ctx(dir), dentry);
	if (error)
		goto out_iput;

	inode->i_size = len-1;
	if (len <= SHORT_SYMLINK_LEN) {
		inode->i_link = kmemdup(symname, len, GFP_KERNEL);
		if (!inode->i_link) {
			error = -ENOMEM;
			goto out_remove_offset;
		}
		inode->i_op = &shmem_short_symlink_operations;
	} else {
		inode_nohighmem(inode);
		error = shmem_get_folio(inode, 0, &folio, SGP_WRITE);
		if (error)
			goto out_remove_offset;
		inode->i_mapping->a_ops = &shmem_aops;
		inode->i_op = &shmem_symlink_inode_operations;
		memcpy(folio_address(folio), symname, len);
		folio_mark_uptodate(folio);
		folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
	}
	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_mtime = inode_set_ctime_current(dir);
	inode_inc_iversion(dir);
	d_instantiate(dentry, inode);
	dget(dentry);
	return 0;

out_remove_offset:
	simple_offset_remove(shmem_get_offset_ctx(dir), dentry);
out_iput:
	iput(inode);
	return error;
}

static void shmem_put_link(void *arg)
{
	folio_mark_accessed(arg);
	folio_put(arg);
}

static const char *shmem_get_link(struct dentry *dentry,
				  struct inode *inode,
				  struct delayed_call *done)
{
	struct folio *folio = NULL;
	int error;

	if (!dentry) {
		folio = filemap_get_folio(inode->i_mapping, 0);
		if (IS_ERR(folio))
			return ERR_PTR(-ECHILD);
		if (PageHWPoison(folio_page(folio, 0)) ||
		    !folio_test_uptodate(folio)) {
			folio_put(folio);
			return ERR_PTR(-ECHILD);
		}
	} else {
		error = shmem_get_folio(inode, 0, &folio, SGP_READ);
		if (error)
			return ERR_PTR(error);
		if (!folio)
			return ERR_PTR(-ECHILD);
		if (PageHWPoison(folio_page(folio, 0))) {
			folio_unlock(folio);
			folio_put(folio);
			return ERR_PTR(-ECHILD);
		}
		folio_unlock(folio);
	}
	set_delayed_call(done, shmem_put_link, folio);
	return folio_address(folio);
}

#ifdef CONFIG_TMPFS_XATTR

static int shmem_fileattr_get(struct dentry *dentry, struct fileattr *fa)
{
	struct shmem_inode_info *info = SHMEM_I(d_inode(dentry));

	fileattr_fill_flags(fa, info->fsflags & SHMEM_FL_USER_VISIBLE);

	return 0;
}

static int shmem_fileattr_set(struct mnt_idmap *idmap,
			      struct dentry *dentry, struct fileattr *fa)
{
	struct inode *inode = d_inode(dentry);
	struct shmem_inode_info *info = SHMEM_I(inode);

	if (fileattr_has_fsx(fa))
		return -EOPNOTSUPP;
	if (fa->flags & ~SHMEM_FL_USER_MODIFIABLE)
		return -EOPNOTSUPP;

	info->fsflags = (info->fsflags & ~SHMEM_FL_USER_MODIFIABLE) |
		(fa->flags & SHMEM_FL_USER_MODIFIABLE);

	shmem_set_inode_flags(inode, info->fsflags);
	inode_set_ctime_current(inode);
	inode_inc_iversion(inode);
	return 0;
}

/*
 * Superblocks without xattr inode operations may get some security.* xattr
 * support from the LSM "for free". As soon as we have any other xattrs
 * like ACLs, we also need to implement the security.* handlers at
 * filesystem level, though.
 */

/*
 * Callback for security_inode_init_security() for acquiring xattrs.
 */
static int shmem_initxattrs(struct inode *inode,
			    const struct xattr *xattr_array,
			    void *fs_info)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	const struct xattr *xattr;
	struct simple_xattr *new_xattr;
	size_t ispace = 0;
	size_t len;

	if (sbinfo->max_inodes) {
		for (xattr = xattr_array; xattr->name != NULL; xattr++) {
			ispace += simple_xattr_space(xattr->name,
				xattr->value_len + XATTR_SECURITY_PREFIX_LEN);
		}
		if (ispace) {
			raw_spin_lock(&sbinfo->stat_lock);
			if (sbinfo->free_ispace < ispace)
				ispace = 0;
			else
				sbinfo->free_ispace -= ispace;
			raw_spin_unlock(&sbinfo->stat_lock);
			if (!ispace)
				return -ENOSPC;
		}
	}

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		new_xattr = simple_xattr_alloc(xattr->value, xattr->value_len);
		if (!new_xattr)
			break;

		len = strlen(xattr->name) + 1;
		new_xattr->name = kmalloc(XATTR_SECURITY_PREFIX_LEN + len,
					  GFP_KERNEL_ACCOUNT);
		if (!new_xattr->name) {
			kvfree(new_xattr);
			break;
		}

		memcpy(new_xattr->name, XATTR_SECURITY_PREFIX,
		       XATTR_SECURITY_PREFIX_LEN);
		memcpy(new_xattr->name + XATTR_SECURITY_PREFIX_LEN,
		       xattr->name, len);

		simple_xattr_add(&info->xattrs, new_xattr);
	}

	if (xattr->name != NULL) {
		if (ispace) {
			raw_spin_lock(&sbinfo->stat_lock);
			sbinfo->free_ispace += ispace;
			raw_spin_unlock(&sbinfo->stat_lock);
		}
		simple_xattrs_free(&info->xattrs, NULL);
		return -ENOMEM;
	}

	return 0;
}

static int shmem_xattr_handler_get(const struct xattr_handler *handler,
				   struct dentry *unused, struct inode *inode,
				   const char *name, void *buffer, size_t size)
{
	struct shmem_inode_info *info = SHMEM_I(inode);

	name = xattr_full_name(handler, name);
	return simple_xattr_get(&info->xattrs, name, buffer, size);
}

static int shmem_xattr_handler_set(const struct xattr_handler *handler,
				   struct mnt_idmap *idmap,
				   struct dentry *unused, struct inode *inode,
				   const char *name, const void *value,
				   size_t size, int flags)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	struct simple_xattr *old_xattr;
	size_t ispace = 0;

	name = xattr_full_name(handler, name);
	if (value && sbinfo->max_inodes) {
		ispace = simple_xattr_space(name, size);
		raw_spin_lock(&sbinfo->stat_lock);
		if (sbinfo->free_ispace < ispace)
			ispace = 0;
		else
			sbinfo->free_ispace -= ispace;
		raw_spin_unlock(&sbinfo->stat_lock);
		if (!ispace)
			return -ENOSPC;
	}

	old_xattr = simple_xattr_set(&info->xattrs, name, value, size, flags);
	if (!IS_ERR(old_xattr)) {
		ispace = 0;
		if (old_xattr && sbinfo->max_inodes)
			ispace = simple_xattr_space(old_xattr->name,
						    old_xattr->size);
		simple_xattr_free(old_xattr);
		old_xattr = NULL;
		inode_set_ctime_current(inode);
		inode_inc_iversion(inode);
	}
	if (ispace) {
		raw_spin_lock(&sbinfo->stat_lock);
		sbinfo->free_ispace += ispace;
		raw_spin_unlock(&sbinfo->stat_lock);
	}
	return PTR_ERR(old_xattr);
}

static const struct xattr_handler shmem_security_xattr_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.get = shmem_xattr_handler_get,
	.set = shmem_xattr_handler_set,
};

static const struct xattr_handler shmem_trusted_xattr_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.get = shmem_xattr_handler_get,
	.set = shmem_xattr_handler_set,
};

static const struct xattr_handler shmem_user_xattr_handler = {
	.prefix = XATTR_USER_PREFIX,
	.get = shmem_xattr_handler_get,
	.set = shmem_xattr_handler_set,
};

static const struct xattr_handler *shmem_xattr_handlers[] = {
	&shmem_security_xattr_handler,
	&shmem_trusted_xattr_handler,
	&shmem_user_xattr_handler,
	NULL
};

static ssize_t shmem_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct shmem_inode_info *info = SHMEM_I(d_inode(dentry));
	return simple_xattr_list(d_inode(dentry), &info->xattrs, buffer, size);
}
#endif /* CONFIG_TMPFS_XATTR */

static const struct inode_operations shmem_short_symlink_operations = {
	.getattr	= shmem_getattr,
	.setattr	= shmem_setattr,
	.get_link	= simple_get_link,
#ifdef CONFIG_TMPFS_XATTR
	.listxattr	= shmem_listxattr,
#endif
};

static const struct inode_operations shmem_symlink_inode_operations = {
	.getattr	= shmem_getattr,
	.setattr	= shmem_setattr,
	.get_link	= shmem_get_link,
#ifdef CONFIG_TMPFS_XATTR
	.listxattr	= shmem_listxattr,
#endif
};

static struct dentry *shmem_get_parent(struct dentry *child)
{
	return ERR_PTR(-ESTALE);
}

static int shmem_match(struct inode *ino, void *vfh)
{
	__u32 *fh = vfh;
	__u64 inum = fh[2];
	inum = (inum << 32) | fh[1];
	return ino->i_ino == inum && fh[0] == ino->i_generation;
}

/* Find any alias of inode, but prefer a hashed alias */
static struct dentry *shmem_find_alias(struct inode *inode)
{
	struct dentry *alias = d_find_alias(inode);

	return alias ?: d_find_any_alias(inode);
}


static struct dentry *shmem_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct inode *inode;
	struct dentry *dentry = NULL;
	u64 inum;

	if (fh_len < 3)
		return NULL;

	inum = fid->raw[2];
	inum = (inum << 32) | fid->raw[1];

	inode = ilookup5(sb, (unsigned long)(inum + fid->raw[0]),
			shmem_match, fid->raw);
	if (inode) {
		dentry = shmem_find_alias(inode);
		iput(inode);
	}

	return dentry;
}

static int shmem_encode_fh(struct inode *inode, __u32 *fh, int *len,
				struct inode *parent)
{
	if (*len < 3) {
		*len = 3;
		return FILEID_INVALID;
	}

	if (inode_unhashed(inode)) {
		/* Unfortunately insert_inode_hash is not idempotent,
		 * so as we hash inodes here rather than at creation
		 * time, we need a lock to ensure we only try
		 * to do it once
		 */
		static DEFINE_SPINLOCK(lock);
		spin_lock(&lock);
		if (inode_unhashed(inode))
			__insert_inode_hash(inode,
					    inode->i_ino + inode->i_generation);
		spin_unlock(&lock);
	}

	fh[0] = inode->i_generation;
	fh[1] = inode->i_ino;
	fh[2] = ((__u64)inode->i_ino) >> 32;

	*len = 3;
	return 1;
}

static const struct export_operations shmem_export_ops = {
	.get_parent     = shmem_get_parent,
	.encode_fh      = shmem_encode_fh,
	.fh_to_dentry	= shmem_fh_to_dentry,
};

enum shmem_param {
	Opt_gid,
	Opt_huge,
	Opt_mode,
	Opt_mpol,
	Opt_nr_blocks,
	Opt_nr_inodes,
	Opt_size,
	Opt_uid,
	Opt_inode32,
	Opt_inode64,
	Opt_noswap,
	Opt_quota,
	Opt_usrquota,
	Opt_grpquota,
	Opt_usrquota_block_hardlimit,
	Opt_usrquota_inode_hardlimit,
	Opt_grpquota_block_hardlimit,
	Opt_grpquota_inode_hardlimit,
};

static const struct constant_table shmem_param_enums_huge[] = {
	{"never",	SHMEM_HUGE_NEVER },
	{"always",	SHMEM_HUGE_ALWAYS },
	{"within_size",	SHMEM_HUGE_WITHIN_SIZE },
	{"advise",	SHMEM_HUGE_ADVISE },
	{}
};

const struct fs_parameter_spec shmem_fs_parameters[] = {
	fsparam_u32   ("gid",		Opt_gid),
	fsparam_enum  ("huge",		Opt_huge,  shmem_param_enums_huge),
	fsparam_u32oct("mode",		Opt_mode),
	fsparam_string("mpol",		Opt_mpol),
	fsparam_string("nr_blocks",	Opt_nr_blocks),
	fsparam_string("nr_inodes",	Opt_nr_inodes),
	fsparam_string("size",		Opt_size),
	fsparam_u32   ("uid",		Opt_uid),
	fsparam_flag  ("inode32",	Opt_inode32),
	fsparam_flag  ("inode64",	Opt_inode64),
	fsparam_flag  ("noswap",	Opt_noswap),
#ifdef CONFIG_TMPFS_QUOTA
	fsparam_flag  ("quota",		Opt_quota),
	fsparam_flag  ("usrquota",	Opt_usrquota),
	fsparam_flag  ("grpquota",	Opt_grpquota),
	fsparam_string("usrquota_block_hardlimit", Opt_usrquota_block_hardlimit),
	fsparam_string("usrquota_inode_hardlimit", Opt_usrquota_inode_hardlimit),
	fsparam_string("grpquota_block_hardlimit", Opt_grpquota_block_hardlimit),
	fsparam_string("grpquota_inode_hardlimit", Opt_grpquota_inode_hardlimit),
#endif
	{}
};

static int shmem_parse_one(struct fs_context *fc, struct fs_parameter *param)
{
	struct shmem_options *ctx = fc->fs_private;
	struct fs_parse_result result;
	unsigned long long size;
	char *rest;
	int opt;
	kuid_t kuid;
	kgid_t kgid;

	opt = fs_parse(fc, shmem_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_size:
		size = memparse(param->string, &rest);
		if (*rest == '%') {
			size <<= PAGE_SHIFT;
			size *= totalram_pages();
			do_div(size, 100);
			rest++;
		}
		if (*rest)
			goto bad_value;
		ctx->blocks = DIV_ROUND_UP(size, PAGE_SIZE);
		ctx->seen |= SHMEM_SEEN_BLOCKS;
		break;
	case Opt_nr_blocks:
		ctx->blocks = memparse(param->string, &rest);
		if (*rest || ctx->blocks > LONG_MAX)
			goto bad_value;
		ctx->seen |= SHMEM_SEEN_BLOCKS;
		break;
	case Opt_nr_inodes:
		ctx->inodes = memparse(param->string, &rest);
		if (*rest || ctx->inodes > ULONG_MAX / BOGO_INODE_SIZE)
			goto bad_value;
		ctx->seen |= SHMEM_SEEN_INODES;
		break;
	case Opt_mode:
		ctx->mode = result.uint_32 & 07777;
		break;
	case Opt_uid:
		kuid = make_kuid(current_user_ns(), result.uint_32);
		if (!uid_valid(kuid))
			goto bad_value;

		/*
		 * The requested uid must be representable in the
		 * filesystem's idmapping.
		 */
		if (!kuid_has_mapping(fc->user_ns, kuid))
			goto bad_value;

		ctx->uid = kuid;
		break;
	case Opt_gid:
		kgid = make_kgid(current_user_ns(), result.uint_32);
		if (!gid_valid(kgid))
			goto bad_value;

		/*
		 * The requested gid must be representable in the
		 * filesystem's idmapping.
		 */
		if (!kgid_has_mapping(fc->user_ns, kgid))
			goto bad_value;

		ctx->gid = kgid;
		break;
	case Opt_huge:
		ctx->huge = result.uint_32;
		if (ctx->huge != SHMEM_HUGE_NEVER &&
		    !(IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) &&
		      has_transparent_hugepage()))
			goto unsupported_parameter;
		ctx->seen |= SHMEM_SEEN_HUGE;
		break;
	case Opt_mpol:
		if (IS_ENABLED(CONFIG_NUMA)) {
			mpol_put(ctx->mpol);
			ctx->mpol = NULL;
			if (mpol_parse_str(param->string, &ctx->mpol))
				goto bad_value;
			break;
		}
		goto unsupported_parameter;
	case Opt_inode32:
		ctx->full_inums = false;
		ctx->seen |= SHMEM_SEEN_INUMS;
		break;
	case Opt_inode64:
		if (sizeof(ino_t) < 8) {
			return invalfc(fc,
				       "Cannot use inode64 with <64bit inums in kernel\n");
		}
		ctx->full_inums = true;
		ctx->seen |= SHMEM_SEEN_INUMS;
		break;
	case Opt_noswap:
		if ((fc->user_ns != &init_user_ns) || !capable(CAP_SYS_ADMIN)) {
			return invalfc(fc,
				       "Turning off swap in unprivileged tmpfs mounts unsupported");
		}
		ctx->noswap = true;
		ctx->seen |= SHMEM_SEEN_NOSWAP;
		break;
	case Opt_quota:
		if (fc->user_ns != &init_user_ns)
			return invalfc(fc, "Quotas in unprivileged tmpfs mounts are unsupported");
		ctx->seen |= SHMEM_SEEN_QUOTA;
		ctx->quota_types |= (QTYPE_MASK_USR | QTYPE_MASK_GRP);
		break;
	case Opt_usrquota:
		if (fc->user_ns != &init_user_ns)
			return invalfc(fc, "Quotas in unprivileged tmpfs mounts are unsupported");
		ctx->seen |= SHMEM_SEEN_QUOTA;
		ctx->quota_types |= QTYPE_MASK_USR;
		break;
	case Opt_grpquota:
		if (fc->user_ns != &init_user_ns)
			return invalfc(fc, "Quotas in unprivileged tmpfs mounts are unsupported");
		ctx->seen |= SHMEM_SEEN_QUOTA;
		ctx->quota_types |= QTYPE_MASK_GRP;
		break;
	case Opt_usrquota_block_hardlimit:
		size = memparse(param->string, &rest);
		if (*rest || !size)
			goto bad_value;
		if (size > SHMEM_QUOTA_MAX_SPC_LIMIT)
			return invalfc(fc,
				       "User quota block hardlimit too large.");
		ctx->qlimits.usrquota_bhardlimit = size;
		break;
	case Opt_grpquota_block_hardlimit:
		size = memparse(param->string, &rest);
		if (*rest || !size)
			goto bad_value;
		if (size > SHMEM_QUOTA_MAX_SPC_LIMIT)
			return invalfc(fc,
				       "Group quota block hardlimit too large.");
		ctx->qlimits.grpquota_bhardlimit = size;
		break;
	case Opt_usrquota_inode_hardlimit:
		size = memparse(param->string, &rest);
		if (*rest || !size)
			goto bad_value;
		if (size > SHMEM_QUOTA_MAX_INO_LIMIT)
			return invalfc(fc,
				       "User quota inode hardlimit too large.");
		ctx->qlimits.usrquota_ihardlimit = size;
		break;
	case Opt_grpquota_inode_hardlimit:
		size = memparse(param->string, &rest);
		if (*rest || !size)
			goto bad_value;
		if (size > SHMEM_QUOTA_MAX_INO_LIMIT)
			return invalfc(fc,
				       "Group quota inode hardlimit too large.");
		ctx->qlimits.grpquota_ihardlimit = size;
		break;
	}
	return 0;

unsupported_parameter:
	return invalfc(fc, "Unsupported parameter '%s'", param->key);
bad_value:
	return invalfc(fc, "Bad value for '%s'", param->key);
}

static int shmem_parse_options(struct fs_context *fc, void *data)
{
	char *options = data;

	if (options) {
		int err = security_sb_eat_lsm_opts(options, &fc->security);
		if (err)
			return err;
	}

	while (options != NULL) {
		char *this_char = options;
		for (;;) {
			/*
			 * NUL-terminate this option: unfortunately,
			 * mount options form a comma-separated list,
			 * but mpol's nodelist may also contain commas.
			 */
			options = strchr(options, ',');
			if (options == NULL)
				break;
			options++;
			if (!isdigit(*options)) {
				options[-1] = '\0';
				break;
			}
		}
		if (*this_char) {
			char *value = strchr(this_char, '=');
			size_t len = 0;
			int err;

			if (value) {
				*value++ = '\0';
				len = strlen(value);
			}
			err = vfs_parse_fs_string(fc, this_char, value, len);
			if (err < 0)
				return err;
		}
	}
	return 0;
}

/*
 * Reconfigure a shmem filesystem.
 */
static int shmem_reconfigure(struct fs_context *fc)
{
	struct shmem_options *ctx = fc->fs_private;
	struct shmem_sb_info *sbinfo = SHMEM_SB(fc->root->d_sb);
	unsigned long used_isp;
	struct mempolicy *mpol = NULL;
	const char *err;

	raw_spin_lock(&sbinfo->stat_lock);
	used_isp = sbinfo->max_inodes * BOGO_INODE_SIZE - sbinfo->free_ispace;

	if ((ctx->seen & SHMEM_SEEN_BLOCKS) && ctx->blocks) {
		if (!sbinfo->max_blocks) {
			err = "Cannot retroactively limit size";
			goto out;
		}
		if (percpu_counter_compare(&sbinfo->used_blocks,
					   ctx->blocks) > 0) {
			err = "Too small a size for current use";
			goto out;
		}
	}
	if ((ctx->seen & SHMEM_SEEN_INODES) && ctx->inodes) {
		if (!sbinfo->max_inodes) {
			err = "Cannot retroactively limit inodes";
			goto out;
		}
		if (ctx->inodes * BOGO_INODE_SIZE < used_isp) {
			err = "Too few inodes for current use";
			goto out;
		}
	}

	if ((ctx->seen & SHMEM_SEEN_INUMS) && !ctx->full_inums &&
	    sbinfo->next_ino > UINT_MAX) {
		err = "Current inum too high to switch to 32-bit inums";
		goto out;
	}
	if ((ctx->seen & SHMEM_SEEN_NOSWAP) && ctx->noswap && !sbinfo->noswap) {
		err = "Cannot disable swap on remount";
		goto out;
	}
	if (!(ctx->seen & SHMEM_SEEN_NOSWAP) && !ctx->noswap && sbinfo->noswap) {
		err = "Cannot enable swap on remount if it was disabled on first mount";
		goto out;
	}

	if (ctx->seen & SHMEM_SEEN_QUOTA &&
	    !sb_any_quota_loaded(fc->root->d_sb)) {
		err = "Cannot enable quota on remount";
		goto out;
	}

#ifdef CONFIG_TMPFS_QUOTA
#define CHANGED_LIMIT(name)						\
	(ctx->qlimits.name## hardlimit &&				\
	(ctx->qlimits.name## hardlimit != sbinfo->qlimits.name## hardlimit))

	if (CHANGED_LIMIT(usrquota_b) || CHANGED_LIMIT(usrquota_i) ||
	    CHANGED_LIMIT(grpquota_b) || CHANGED_LIMIT(grpquota_i)) {
		err = "Cannot change global quota limit on remount";
		goto out;
	}
#endif /* CONFIG_TMPFS_QUOTA */

	if (ctx->seen & SHMEM_SEEN_HUGE)
		sbinfo->huge = ctx->huge;
	if (ctx->seen & SHMEM_SEEN_INUMS)
		sbinfo->full_inums = ctx->full_inums;
	if (ctx->seen & SHMEM_SEEN_BLOCKS)
		sbinfo->max_blocks  = ctx->blocks;
	if (ctx->seen & SHMEM_SEEN_INODES) {
		sbinfo->max_inodes  = ctx->inodes;
		sbinfo->free_ispace = ctx->inodes * BOGO_INODE_SIZE - used_isp;
	}

	/*
	 * Preserve previous mempolicy unless mpol remount option was specified.
	 */
	if (ctx->mpol) {
		mpol = sbinfo->mpol;
		sbinfo->mpol = ctx->mpol;	/* transfers initial ref */
		ctx->mpol = NULL;
	}

	if (ctx->noswap)
		sbinfo->noswap = true;

	raw_spin_unlock(&sbinfo->stat_lock);
	mpol_put(mpol);
	return 0;
out:
	raw_spin_unlock(&sbinfo->stat_lock);
	return invalfc(fc, "%s", err);
}

static int shmem_show_options(struct seq_file *seq, struct dentry *root)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(root->d_sb);
	struct mempolicy *mpol;

	if (sbinfo->max_blocks != shmem_default_max_blocks())
		seq_printf(seq, ",size=%luk", K(sbinfo->max_blocks));
	if (sbinfo->max_inodes != shmem_default_max_inodes())
		seq_printf(seq, ",nr_inodes=%lu", sbinfo->max_inodes);
	if (sbinfo->mode != (0777 | S_ISVTX))
		seq_printf(seq, ",mode=%03ho", sbinfo->mode);
	if (!uid_eq(sbinfo->uid, GLOBAL_ROOT_UID))
		seq_printf(seq, ",uid=%u",
				from_kuid_munged(&init_user_ns, sbinfo->uid));
	if (!gid_eq(sbinfo->gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u",
				from_kgid_munged(&init_user_ns, sbinfo->gid));

	/*
	 * Showing inode{64,32} might be useful even if it's the system default,
	 * since then people don't have to resort to checking both here and
	 * /proc/config.gz to confirm 64-bit inums were successfully applied
	 * (which may not even exist if IKCONFIG_PROC isn't enabled).
	 *
	 * We hide it when inode64 isn't the default and we are using 32-bit
	 * inodes, since that probably just means the feature isn't even under
	 * consideration.
	 *
	 * As such:
	 *
	 *                     +-----------------+-----------------+
	 *                     | TMPFS_INODE64=y | TMPFS_INODE64=n |
	 *  +------------------+-----------------+-----------------+
	 *  | full_inums=true  | show            | show            |
	 *  | full_inums=false | show            | hide            |
	 *  +------------------+-----------------+-----------------+
	 *
	 */
	if (IS_ENABLED(CONFIG_TMPFS_INODE64) || sbinfo->full_inums)
		seq_printf(seq, ",inode%d", (sbinfo->full_inums ? 64 : 32));
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	/* Rightly or wrongly, show huge mount option unmasked by shmem_huge */
	if (sbinfo->huge)
		seq_printf(seq, ",huge=%s", shmem_format_huge(sbinfo->huge));
#endif
	mpol = shmem_get_sbmpol(sbinfo);
	shmem_show_mpol(seq, mpol);
	mpol_put(mpol);
	if (sbinfo->noswap)
		seq_printf(seq, ",noswap");
	return 0;
}

#endif /* CONFIG_TMPFS */

static void shmem_put_super(struct super_block *sb)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);

#ifdef CONFIG_TMPFS_QUOTA
	shmem_disable_quotas(sb);
#endif
	free_percpu(sbinfo->ino_batch);
	percpu_counter_destroy(&sbinfo->used_blocks);
	mpol_put(sbinfo->mpol);
	kfree(sbinfo);
	sb->s_fs_info = NULL;
}

// 初始化shmem fs的sb
static int shmem_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct shmem_options *ctx = fc->fs_private;
	struct inode *inode;
	struct shmem_sb_info *sbinfo;
	int error = -ENOMEM;

	/* Round up to L1_CACHE_BYTES to resist false sharing */
	sbinfo = kzalloc(max((int)sizeof(struct shmem_sb_info),
				L1_CACHE_BYTES), GFP_KERNEL);
	if (!sbinfo)
		return error;

	sb->s_fs_info = sbinfo;

#ifdef CONFIG_TMPFS
	/*
	 * Per default we only allow half of the physical ram per
	 * tmpfs instance, limiting inodes to one per page of lowmem;
	 * but the internal instance is left unlimited.
	 */
	if (!(sb->s_flags & SB_KERNMOUNT)) {
		if (!(ctx->seen & SHMEM_SEEN_BLOCKS))
			ctx->blocks = shmem_default_max_blocks();
		if (!(ctx->seen & SHMEM_SEEN_INODES))
			ctx->inodes = shmem_default_max_inodes();
		if (!(ctx->seen & SHMEM_SEEN_INUMS))
			ctx->full_inums = IS_ENABLED(CONFIG_TMPFS_INODE64);
		sbinfo->noswap = ctx->noswap;
	} else {
		sb->s_flags |= SB_NOUSER;
	}
	sb->s_export_op = &shmem_export_ops;
	sb->s_flags |= SB_NOSEC | SB_I_VERSION;
#else
	sb->s_flags |= SB_NOUSER;
#endif
	sbinfo->max_blocks = ctx->blocks;
	sbinfo->max_inodes = ctx->inodes;
	sbinfo->free_ispace = sbinfo->max_inodes * BOGO_INODE_SIZE;
	if (sb->s_flags & SB_KERNMOUNT) {
		sbinfo->ino_batch = alloc_percpu(ino_t);
		if (!sbinfo->ino_batch)
			goto failed;
	}
	sbinfo->uid = ctx->uid;
	sbinfo->gid = ctx->gid;
	sbinfo->full_inums = ctx->full_inums;
	sbinfo->mode = ctx->mode;
	sbinfo->huge = ctx->huge;
	sbinfo->mpol = ctx->mpol;
	ctx->mpol = NULL;

	raw_spin_lock_init(&sbinfo->stat_lock);
	if (percpu_counter_init(&sbinfo->used_blocks, 0, GFP_KERNEL))
		goto failed;
	spin_lock_init(&sbinfo->shrinklist_lock);
	INIT_LIST_HEAD(&sbinfo->shrinklist);

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = TMPFS_MAGIC;
	sb->s_op = &shmem_ops;
	sb->s_time_gran = 1;
#ifdef CONFIG_TMPFS_XATTR
	sb->s_xattr = shmem_xattr_handlers;
#endif
#ifdef CONFIG_TMPFS_POSIX_ACL
	sb->s_flags |= SB_POSIXACL;
#endif
	uuid_gen(&sb->s_uuid);

#ifdef CONFIG_TMPFS_QUOTA
	if (ctx->seen & SHMEM_SEEN_QUOTA) {
		sb->dq_op = &shmem_quota_operations;
		sb->s_qcop = &dquot_quotactl_sysfile_ops;
		sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP;

		/* Copy the default limits from ctx into sbinfo */
		memcpy(&sbinfo->qlimits, &ctx->qlimits,
		       sizeof(struct shmem_quota_limits));

		if (shmem_enable_quotas(sb, ctx->quota_types))
			goto failed;
	}
#endif /* CONFIG_TMPFS_QUOTA */

	inode = shmem_get_inode(&nop_mnt_idmap, sb, NULL, S_IFDIR | sbinfo->mode, 0,
				VM_NORESERVE);
	if (IS_ERR(inode)) {
		error = PTR_ERR(inode);
		goto failed;
	}
	inode->i_uid = sbinfo->uid;
	inode->i_gid = sbinfo->gid;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto failed;
	return 0;

failed:
	shmem_put_super(sb);
	return error;
}

// fs的get_tree函数做什么用?
static int shmem_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, shmem_fill_super);
}

static void shmem_free_fc(struct fs_context *fc)
{
	struct shmem_options *ctx = fc->fs_private;

	if (ctx) {
		mpol_put(ctx->mpol);
		kfree(ctx);
	}
}

// shmem fc的ops. fc的ops是干什么的?
static const struct fs_context_operations shmem_fs_context_ops = {
	.free			= shmem_free_fc,
	.get_tree		= shmem_get_tree,
#ifdef CONFIG_TMPFS
	.parse_monolithic	= shmem_parse_options,
	.parse_param		= shmem_parse_one,
	.reconfigure		= shmem_reconfigure,
#endif
};

static struct kmem_cache *shmem_inode_cachep;

// shmem fs分配inode
static struct inode *shmem_alloc_inode(struct super_block *sb)
{
	struct shmem_inode_info *info;
	info = alloc_inode_sb(sb, shmem_inode_cachep, GFP_KERNEL);
	if (!info)
		return NULL;
	return &info->vfs_inode;
}

// 什么是incore inode?
static void shmem_free_in_core_inode(struct inode *inode)
{
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	kmem_cache_free(shmem_inode_cachep, SHMEM_I(inode));
}

// 这都是啥
static void shmem_destroy_inode(struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		mpol_free_shared_policy(&SHMEM_I(inode)->policy);
	if (S_ISDIR(inode->i_mode))
		simple_offset_destroy(shmem_get_offset_ctx(inode));
}

static void shmem_init_inode(void *foo)
{
	struct shmem_inode_info *info = foo;
	inode_init_once(&info->vfs_inode);
}

// 初始化shmem 的inode slab
static void shmem_init_inodecache(void)
{
	shmem_inode_cachep = kmem_cache_create("shmem_inode_cache",
				sizeof(struct shmem_inode_info),
				0, SLAB_PANIC|SLAB_ACCOUNT, shmem_init_inode);
}

static void shmem_destroy_inodecache(void)
{
	kmem_cache_destroy(shmem_inode_cachep);
}

/* Keep the page in page cache instead of truncating it */
static int shmem_error_remove_page(struct address_space *mapping,
				   struct page *page)
{
	return 0;
}
// shmem的mapping的ops
const struct address_space_operations shmem_aops = {
	/* 写入回调
	写入swap */
	.writepage	= shmem_writepage,
	/* 简单设置page的dirty flag即可 */
	.dirty_folio	= noop_dirty_folio,
#ifdef CONFIG_TMPFS
//写入内容到文件时会调用这俩

/* 其实一般也就是根据mapping和pos, 在xas里面找到对应index的folio,赋值到page
		status = a_ops->write_begin(file, mapping, pos, bytes,
						&page, &fsdata); */
	.write_begin	= shmem_write_begin,

	/* 等内核拷贝完数据后, 这里回写? */
	.write_end	= shmem_write_end,
#endif
#ifdef CONFIG_MIGRATION
	.migrate_folio	= migrate_folio,
#endif
	.error_remove_page = shmem_error_remove_page,
};
EXPORT_SYMBOL(shmem_aops);

// shmem文件的fops
static const struct file_operations shmem_file_operations = {
	// 执行mmap的回调
	// 这个回调是什么时候执行的?
	/* shmem文件也是支持mmap的, 应该是这个时候执行的 */
	.mmap		= shmem_mmap,
	/* 打开shmem 文件的回调
	没有做什么特别的工作 */
	.open		= shmem_file_open,
	/* 好像是mmap的时候获取可以mmap的空闲地址 */
	.get_unmapped_area = shmem_get_unmapped_area,
#ifdef CONFIG_TMPFS
	/* 以后 */
	.llseek		= shmem_file_llseek,
	/* 直接读取mapping的idx, 可能会换入, 再没有的话,
	也不会扩大文件 */
	.read_iter	= shmem_file_read_iter,
	/* 写入回调 */
	.write_iter	= shmem_file_write_iter,
	/*  */
	.fsync		= noop_fsync,
	/* 零拷贝读的回调 */
	.splice_read	= shmem_file_splice_read,
	/*  */
	.splice_write	= iter_file_splice_write,
	/*  */
	.fallocate	= shmem_fallocate,
#endif
};

/* shmem fs常规文件的inode ops */
static const struct inode_operations shmem_inode_operations = {
	.getattr	= shmem_getattr,
	.setattr	= shmem_setattr,
#ifdef CONFIG_TMPFS_XATTR
	.listxattr	= shmem_listxattr,
	.set_acl	= simple_set_acl,
	.fileattr_get	= shmem_fileattr_get,
	.fileattr_set	= shmem_fileattr_set,
#endif
};

// shmem的inode ops
static const struct inode_operations shmem_dir_inode_operations = {
#ifdef CONFIG_TMPFS
	.getattr	= shmem_getattr,
	// 创建什么?文件?
	.create		= shmem_create,
	//
	.lookup		= simple_lookup,
	//
	.link		= shmem_link,
	.unlink		= shmem_unlink,
	/* 建立符号链接? */
	.symlink	= shmem_symlink,
	// shmem创建文件夹
	.mkdir		= shmem_mkdir,
	.rmdir		= shmem_rmdir,
	// 创建inode的回调
	.mknod		= shmem_mknod,
	.rename		= shmem_rename2,
	// 为啥tmpfile还有回调
	.tmpfile	= shmem_tmpfile,
	.get_offset_ctx	= shmem_get_offset_ctx,
#endif
#ifdef CONFIG_TMPFS_XATTR
	.listxattr	= shmem_listxattr,
	.fileattr_get	= shmem_fileattr_get,
	.fileattr_set	= shmem_fileattr_set,
#endif
#ifdef CONFIG_TMPFS_POSIX_ACL
	.setattr	= shmem_setattr,
	.set_acl	= simple_set_acl,
#endif
};

static const struct inode_operations shmem_special_inode_operations = {
	.getattr	= shmem_getattr,
#ifdef CONFIG_TMPFS_XATTR
	.listxattr	= shmem_listxattr,
#endif
#ifdef CONFIG_TMPFS_POSIX_ACL
	.setattr	= shmem_setattr,
	.set_acl	= simple_set_acl,
#endif
};

// shmem fs的sb ops
static const struct super_operations shmem_ops = {
	// 分配新inode
	.alloc_inode	= shmem_alloc_inode,
	//
	.free_inode	= shmem_free_in_core_inode,
	//
	.destroy_inode	= shmem_destroy_inode,
#ifdef CONFIG_TMPFS
//
	.statfs		= shmem_statfs,
	.show_options	= shmem_show_options,
#endif
#ifdef CONFIG_TMPFS_QUOTA
	.get_dquots	= shmem_get_dquots,
#endif
	.evict_inode	= shmem_evict_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= shmem_put_super,
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	.nr_cached_objects	= shmem_unused_huge_count,
	.free_cached_objects	= shmem_unused_huge_scan,
#endif
};

/* 
如果一个进程的vma映射到了shmem 文件,
他的这个vma会被shmem fops mmap回调设置上这个ops,
规定缺页的时候, 映射的时候内核如何如何执行这些ops 回调来具体
获取shmem 文件的页面
*/
static const struct vm_operations_struct shmem_vm_ops = {
	// 缺页了就是调用get_folio, 函数内部自己会查找,换入or申请
	.fault		= shmem_fault,
	//
	.map_pages	= filemap_map_pages,
#ifdef CONFIG_NUMA
	.set_policy     = shmem_set_policy,
	.get_policy     = shmem_get_policy,
#endif
};

// 匿名的shmem file的mapping ops, 匿名的shmem file是什么?
//=====================
/* 
如果进程申请共享的匿名内存
底下是通过shmem实现的
会有一个shmem file
这个新建的vma使用这个vm_ops */
static const struct vm_operations_struct shmem_anon_vm_ops = {
	// 匿名的shmem缺页怎么处理? 和非匿名的一样的,所以区分这个
	// 的目的是什么呢?
	.fault		= shmem_fault,
	.map_pages	= filemap_map_pages,
#ifdef CONFIG_NUMA
	.set_policy     = shmem_set_policy,
	.get_policy     = shmem_get_policy,
#endif
};

// shmem初始化fc
int shmem_init_fs_context(struct fs_context *fc)
{
	struct shmem_options *ctx;

	ctx = kzalloc(sizeof(struct shmem_options), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->mode = 0777 | S_ISVTX;
	ctx->uid = current_fsuid();
	ctx->gid = current_fsgid();

	fc->fs_private = ctx;
	fc->ops = &shmem_fs_context_ops;
	return 0;
}
// shmem fs的定义
static struct file_system_type shmem_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tmpfs",
	.init_fs_context = shmem_init_fs_context,
#ifdef CONFIG_TMPFS
	.parameters	= shmem_fs_parameters,
#endif
	.kill_sb	= kill_litter_super,
#ifdef CONFIG_SHMEM
	.fs_flags	= FS_USERNS_MOUNT | FS_ALLOW_IDMAP,
#else
	.fs_flags	= FS_USERNS_MOUNT,
#endif
};

// shmem的初始化
void __init shmem_init(void)
{
	int error;
	// 初始化inode slab
	shmem_init_inodecache();

#ifdef CONFIG_TMPFS_QUOTA
	error = register_quota_format(&shmem_quota_format);
	if (error < 0) {
		pr_err("Could not register quota format\n");
		goto out3;
	}
#endif
	// 注册文件系统
	error = register_filesystem(&shmem_fs_type);
	if (error) {
		pr_err("Could not register tmpfs\n");
		goto out2;
	}
	// 这里挂载了一个shmem的fs?挂到哪?
	shm_mnt = kern_mount(&shmem_fs_type);
	if (IS_ERR(shm_mnt)) {
		error = PTR_ERR(shm_mnt);
		pr_err("Could not kern_mount tmpfs\n");
		goto out1;
	}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (has_transparent_hugepage() && shmem_huge > SHMEM_HUGE_DENY)
		SHMEM_SB(shm_mnt->mnt_sb)->huge = shmem_huge;
	else
		shmem_huge = SHMEM_HUGE_NEVER; /* just in case it was patched */
#endif
	return;

out1:
	unregister_filesystem(&shmem_fs_type);
out2:
#ifdef CONFIG_TMPFS_QUOTA
	unregister_quota_format(&shmem_quota_format);
out3:
#endif
	shmem_destroy_inodecache();
	shm_mnt = ERR_PTR(error);
}

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && defined(CONFIG_SYSFS)
static ssize_t shmem_enabled_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	static const int values[] = {
		SHMEM_HUGE_ALWAYS,
		SHMEM_HUGE_WITHIN_SIZE,
		SHMEM_HUGE_ADVISE,
		SHMEM_HUGE_NEVER,
		SHMEM_HUGE_DENY,
		SHMEM_HUGE_FORCE,
	};
	int len = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		len += sysfs_emit_at(buf, len,
				     shmem_huge == values[i] ? "%s[%s]" : "%s%s",
				     i ? " " : "",
				     shmem_format_huge(values[i]));
	}

	len += sysfs_emit_at(buf, len, "\n");

	return len;
}

static ssize_t shmem_enabled_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	char tmp[16];
	int huge;

	if (count + 1 > sizeof(tmp))
		return -EINVAL;
	memcpy(tmp, buf, count);
	tmp[count] = '\0';
	if (count && tmp[count - 1] == '\n')
		tmp[count - 1] = '\0';

	huge = shmem_parse_huge(tmp);
	if (huge == -EINVAL)
		return -EINVAL;
	if (!has_transparent_hugepage() &&
			huge != SHMEM_HUGE_NEVER && huge != SHMEM_HUGE_DENY)
		return -EINVAL;

	shmem_huge = huge;
	if (shmem_huge > SHMEM_HUGE_DENY)
		SHMEM_SB(shm_mnt->mnt_sb)->huge = shmem_huge;
	return count;
}

struct kobj_attribute shmem_enabled_attr = __ATTR_RW(shmem_enabled);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE && CONFIG_SYSFS */

#else /* !CONFIG_SHMEM */

/*
 * tiny-shmem: simple shmemfs and tmpfs using ramfs code
 *
 * This is intended for small system where the benefits of the full
 * shmem code (swap-backed and resource-limited) are outweighed by
 * their complexity. On systems without swap this code should be
 * effectively equivalent, but much lighter weight.
 */

static struct file_system_type shmem_fs_type = {
	.name		= "tmpfs",
	.init_fs_context = ramfs_init_fs_context,
	.parameters	= ramfs_fs_parameters,
	.kill_sb	= ramfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

void __init shmem_init(void)
{
	BUG_ON(register_filesystem(&shmem_fs_type) != 0);

	shm_mnt = kern_mount(&shmem_fs_type);
	BUG_ON(IS_ERR(shm_mnt));
}

int shmem_unuse(unsigned int type)
{
	return 0;
}

int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
{
	return 0;
}

void shmem_unlock_mapping(struct address_space *mapping)
{
}

#ifdef CONFIG_MMU
unsigned long shmem_get_unmapped_area(struct file *file,
				      unsigned long addr, unsigned long len,
				      unsigned long pgoff, unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}
#endif

void shmem_truncate_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	truncate_inode_pages_range(inode->i_mapping, lstart, lend);
}
EXPORT_SYMBOL_GPL(shmem_truncate_range);

#define shmem_vm_ops				generic_file_vm_ops
#define shmem_anon_vm_ops			generic_file_vm_ops
#define shmem_file_operations			ramfs_file_operations
#define shmem_acct_size(flags, size)		0
#define shmem_unacct_size(flags, size)		do {} while (0)

static inline struct inode *shmem_get_inode(struct mnt_idmap *idmap, struct super_block *sb, struct inode *dir,
					    umode_t mode, dev_t dev, unsigned long flags)
{
	struct inode *inode = ramfs_get_inode(sb, dir, mode, dev);
	return inode ? inode : ERR_PTR(-ENOSPC);
}

#endif /* CONFIG_SHMEM */

/* common code */

// 感觉就是新建一个文件,在内核内部使用的,或者其他机制使用的
// 就像get_random一样
static struct file *__shmem_file_setup(struct vfsmount *mnt, const char *name, loff_t size,
				       unsigned long flags, unsigned int i_flags)
{
	struct inode *inode;
	struct file *res;

	if (IS_ERR(mnt))
		return ERR_CAST(mnt);

	if (size < 0 || size > MAX_LFS_FILESIZE)
		return ERR_PTR(-EINVAL);

	if (shmem_acct_size(flags, size))
		return ERR_PTR(-ENOMEM);

	if (is_idmapped_mnt(mnt))
		return ERR_PTR(-EINVAL);
	// 获取这个新文件的inode
	inode = shmem_get_inode(&nop_mnt_idmap, mnt->mnt_sb, NULL,
				S_IFREG | S_IRWXUGO, 0, flags);

	if (IS_ERR(inode)) {
		shmem_unacct_size(flags, size);
		return ERR_CAST(inode);
	}
	inode->i_flags |= i_flags;
	inode->i_size = size;
	clear_nlink(inode);	/* It is unlinked */
	res = ERR_PTR(ramfs_nommu_expand_for_mapping(inode, size));
	if (!IS_ERR(res)) // 配上file
		res = alloc_file_pseudo(inode, mnt, name, O_RDWR, &shmem_file_operations);
	if (IS_ERR(res))
		iput(inode);
	return res;
}

/**
设置一个共享的匿名映射底下的shmem file. 感觉就是这里初始化一个“虚拟”“底层”
的文件供使用
 * shmem_kernel_file_setup - get an unlinked file living in tmpfs which must be
 * 	kernel internal.  
 获取一个在tmpfs中的未链接文件，该文件必须是内核内部的。
 There will be NO LSM permission checks against the
 * 	underlying inode.  So users of this interface must do LSM checks at a
 *	higher layer.  The users are the big_key and shm implementations.  LSM
 *	checks are provided at the key or shm level rather than the inode.
 * @name: name for dentry (to be seen in /proc/<pid>/maps
dentry（目录项）是Linux VFS（虚拟文件系统)层中的一个基本结构.
 * 它表示一个目录项,可以是文件/目录/符号链接等.
 * dentry结构用于管理目录项和inode之间的关系. 
 * @size: size to be set for the file
 * @flags: VM_NORESERVE suppresses pre-accounting of the entire object size
 */
struct file *shmem_kernel_file_setup(const char *name, loff_t size, unsigned long flags)
{
	return __shmem_file_setup(shm_mnt, name, size, flags, S_PRIVATE);
}

/**
 * shmem_file_setup - get an unlinked file living in tmpfs
  获取一个在tmpfs中的未链接文件
  ===========
  比如memfd是通过内核中文件实现的, 就是shmem的文件, 所以这里获取一个
 * @name: name for dentry (to be seen in /proc/<pid>/maps
 * @size: size to be set for the file
 * @flags: VM_NORESERVE suppresses pre-accounting of the entire object size
 */
struct file *shmem_file_setup(const char *name, loff_t size, unsigned long flags)
{
	return __shmem_file_setup(shm_mnt, name, size, flags, 0);
}
EXPORT_SYMBOL_GPL(shmem_file_setup);

/**
 * shmem_file_setup_with_mnt - get an unlinked file living in tmpfs
   这个接口和前俩是什么区别?
   这个
 * @mnt: the tmpfs mount where the file will be created
 * @name: name for dentry (to be seen in /proc/<pid>/maps
 * @size: size to be set for the file
 * @flags: VM_NORESERVE suppresses pre-accounting of the entire object size
 */
struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt, const char *name,
				       loff_t size, unsigned long flags)
{
	return __shmem_file_setup(mnt, name, size, flags, 0);
}
EXPORT_SYMBOL_GPL(shmem_file_setup_with_mnt);

/**
mmap的时候,如果是共享的vma, 会调用这个函数处理新建的vma
看来共享匿名内存是shmem这一套东西支撑的,需要给他们创建一个
共享的shmem file?
 * shmem_zero_setup - setup a shared anonymous mapping
   设置一个共享的匿名映射
 * @vma: the vma to be mmapped is prepared by do_mmap
 */
int shmem_zero_setup(struct vm_area_struct *vma)
{
	struct file *file;
	loff_t size = vma->vm_end - vma->vm_start;

	/*
	 * Cloning a new file under mmap_lock leads to a lock ordering conflict
	 * between XFS directory reading and selinux: since this file is only
	 * accessible to the user through its mapping, use S_PRIVATE flag to
	 * bypass file security, in the same way as shmem_kernel_file_setup().
	 */
	file = shmem_kernel_file_setup("dev/zero", size, vma->vm_flags);
	if (IS_ERR(file))
		return PTR_ERR(file);

	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = file;
	vma->vm_ops = &shmem_anon_vm_ops;

	return 0;
}

/**
 * shmem_read_folio_gfp - read into page cache, using specified page allocation flags.
   读入pagecache? 使用特定的gfp?
 * @mapping:	the folio's address_space
 * @index:	the folio index
 * @gfp:	the page allocator flags to use if allocating
 *
 * This behaves as a tmpfs "read_cache_page_gfp(mapping, index, gfp)",
 * with any new page allocations done using the specified allocation flags.
 * But read_cache_page_gfp() uses the ->read_folio() method: which does not
 * suit tmpfs, since it may have pages in swapcache, and needs to find those
 * for itself; although drivers/gpu/drm i915 and ttm rely upon this support.
 * 这个函数类似于tmpfs的read_cache_page_gfp(mapping, index, gfp),
 * 如果分配新的页面,则使用指定的分配标志。
 * 但是read_cache_page_gfp()使用->read_folio()方法: 这不适用于tmpfs，
 * 因为它可能在swapcache中有页面，并且需要自己找到这些页面;
 * 尽管drivers/gpu/drm i915和ttm依赖于此支持。
 * i915_gem_object_get_pages_gtt() mixes __GFP_NORETRY | __GFP_NOWARN in
 * with the mapping_gfp_mask(), to avoid OOMing the machine unnecessarily.
 */
struct folio *shmem_read_folio_gfp(struct address_space *mapping,
		pgoff_t index, gfp_t gfp)
{
#ifdef CONFIG_SHMEM
	struct inode *inode = mapping->host;
	struct folio *folio;
	int error;

	BUG_ON(!shmem_mapping(mapping));
	// 读取一个folio
	error = shmem_get_folio_gfp(inode, index, &folio, SGP_CACHE,
				  gfp, NULL, NULL, NULL);
	if (error)
		return ERR_PTR(error);

	folio_unlock(folio);
	return folio;
#else
	/*
	 * The tiny !SHMEM case uses ramfs without swap
	 */
	return mapping_read_folio_gfp(mapping, index, gfp);
#endif
}
EXPORT_SYMBOL_GPL(shmem_read_folio_gfp);

// 读取shmem的某一个index的页面
struct page *shmem_read_mapping_page_gfp(struct address_space *mapping,
					 pgoff_t index, gfp_t gfp)
{
	struct folio *folio = shmem_read_folio_gfp(mapping, index, gfp);
	struct page *page;

	if (IS_ERR(folio))
		return &folio->page;

	page = folio_file_page(folio, index);
	if (PageHWPoison(page)) {
		folio_put(folio);
		return ERR_PTR(-EIO);
	}

	return page;
}
EXPORT_SYMBOL_GPL(shmem_read_mapping_page_gfp);

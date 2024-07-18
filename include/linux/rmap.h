/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RMAP_H
#define _LINUX_RMAP_H
/*
 * Declarations for Reverse Mapping functions in mm/rmap.c
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/memcontrol.h>
#include <linux/highmem.h>

/*
 * The anon_vma heads a list of private "related" vmas, to scan if
 * an anonymous page pointing to this anon_vma needs to be unmapped:
 * the vmas on the list will be related by forking, or by splitting.
 *
 * Since vmas come and go as they are split and merged (particularly
 * in mprotect), the mapping field of an anonymous page cannot point
 * directly to a vma: instead it points to an anon_vma, on whose list
 * the related vmas can be easily linked or unlinked.
 *
 * After unlinking the last vma on the list, we must garbage collect
 * the anon_vma object itself: we're guaranteed no page can be
 * pointing to this anon_vma once its vma list is empty.
 2024年7月1日23:26:28
 struct anon_vma，简称AV;
AV结构用于管理匿名类型VMAs，当有匿名页需要unmap处理时，可以先找到AV，然后再通过AV进行查找处理
 */
struct anon_vma {
	struct anon_vma *root;		/* Root of this anon_vma tree ，指向此anon_vma所属的root */
	struct rw_semaphore rwsem;	/* W: modification, R: walking the list 读写信号量 */
	/*
	 * The refcount is taken on an anon_vma when there is no
	 * guarantee that the vma of page tables will exist for
	 * the duration of the operation. A caller that takes
	 * the reference is responsible for clearing up the
	 * anon_vma if they are the last user on release
	 红黑树中结点数量，初始化时为1，也就是只有本结点，当加入root的anon_vma的红黑树时，此值不变 
	 */
	atomic_t refcount;

	/*
	 * Count of child anon_vmas and VMAs which points to this anon_vma.
	 *
	 * This counter is used for making decision about reusing anon_vma
	 * instead of forking new one. See comments in function anon_vma_clone.
	 表示连接的av数量
	 */
	unsigned degree;

	struct anon_vma *parent;	/* Parent of this anon_vma */

	/*
	 * NOTE: the LSB of the rb_root.rb_node is set by
	 * mm_take_all_locks() _after_ taking the above lock. So the
	 * rb_root must only be read/written after taking the above lock
	 * to be sure to see a valid next pointer. The LSB bit itself
	 * is serialized by a system wide lock only visible to
	 * mm_take_all_locks() (mm_all_locks_mutex).
	 */

	/* Interval tree of private "related" vmas，
	rb红黑树节点，将anon_vma_chain添加到anon_vma->rb_root的红黑树中
	 */
	struct rb_root_cached rb_root;
};

/*
 * The copy-on-write semantics of fork mean that an anon_vma
 * can become associated with multiple processes. Furthermore,
 * each child process will have its own anon_vma, where new
 * pages for that process are instantiated.
 *
 * This structure allows us to find the anon_vmas associated
 * with a VMA, or the VMAs associated with an anon_vma.
 * The "same_vma" list contains the anon_vma_chains linking
 * all the anon_vmas associated with this VMA.
 * The "rb" field indexes on an interval tree the anon_vma_chains
 * which link all the VMAs associated with this anon_vma.
 2024年7月1日23:26:54

 简称AVC;
AVC是连接VMA和AV之间的桥梁
page找到VMA的路径一般如下：page->AV->AVC->VMA
 */
struct anon_vma_chain {
	/* anon_vma_chain 此结构所属的vma */
	struct vm_area_struct *vma;
	/* 此结构加入的红黑树所属的anon_vma */
	struct anon_vma *anon_vma;
	/* same_vma链表节点，将anon_vma_chain添加到vma->anon_vma_chain链表中 */
	struct list_head same_vma;   /* locked by mmap_sem & page_table_lock */
	struct rb_node rb;			/* locked by anon_vma->rwsem 用于加入到其他进程或者本进程vma的anon_vma的红黑树中 */
	unsigned long rb_subtree_last;
#ifdef CONFIG_DEBUG_VM_RB
	unsigned long cached_vma_start, cached_vma_last;
#endif
};

enum ttu_flags {
	TTU_MIGRATION		= 0x1,	/* migration mode */
	TTU_MUNLOCK		= 0x2,	/* munlock mode */

	TTU_SPLIT_HUGE_PMD	= 0x4,	/* split huge PMD if any */
	TTU_IGNORE_MLOCK	= 0x8,	/* ignore mlock */
	TTU_IGNORE_ACCESS	= 0x10,	/* don't age */
	TTU_IGNORE_HWPOISON	= 0x20,	/* corrupted page is recoverable */
	TTU_BATCH_FLUSH		= 0x40,	/* Batch TLB flushes where possible
					 * and caller guarantees they will
					 * do a final flush if necessary */
	TTU_RMAP_LOCKED		= 0x80,	/* do not grab rmap lock:
					 * caller holds it */
	TTU_SPLIT_FREEZE	= 0x100,		/* freeze pte under splitting thp */
};

#ifdef CONFIG_MMU
static inline void get_anon_vma(struct anon_vma *anon_vma)
{
	atomic_inc(&anon_vma->refcount);
}

void __put_anon_vma(struct anon_vma *anon_vma);
/* 2024年7月19日00:38:10 */
static inline void put_anon_vma(struct anon_vma *anon_vma)
{
	if (atomic_dec_and_test(&anon_vma->refcount))
		__put_anon_vma(anon_vma);
}

static inline void anon_vma_lock_write(struct anon_vma *anon_vma)
{
	down_write(&anon_vma->root->rwsem);
}
/* 2024年07月18日18:58:54 */
static inline void anon_vma_unlock_write(struct anon_vma *anon_vma)
{
	up_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
{
	down_read(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_read(struct anon_vma *anon_vma)
{
	up_read(&anon_vma->root->rwsem);
}


/*
 * anon_vma helper functions.
 */
void anon_vma_init(void);	/* create anon_vma_cachep */
int  __anon_vma_prepare(struct vm_area_struct *);
void unlink_anon_vmas(struct vm_area_struct *);
int anon_vma_clone(struct vm_area_struct *, struct vm_area_struct *);
int anon_vma_fork(struct vm_area_struct *, struct vm_area_struct *);
/* 2024年7月1日23:24:49
检查vma是否初始化了rmap
这个函数完成的工作就是为进程地址空间中的VMA准备struct anon_vma结构。
anon_vma_prepare中负责创建AVC和AV并建立彼此的关系;真正将创建的page与av关联在__page_set_anon_map中完成。
这样的话父进程新建的page在自己的反向映射中的关系就算完成了。
 */
static inline int anon_vma_prepare(struct vm_area_struct *vma)
{
	if (likely(vma->anon_vma))
		return 0;

	return __anon_vma_prepare(vma);
}

static inline void anon_vma_merge(struct vm_area_struct *vma,
				  struct vm_area_struct *next)
{
	VM_BUG_ON_VMA(vma->anon_vma != next->anon_vma, vma);
	unlink_anon_vmas(next);
}

struct anon_vma *page_get_anon_vma(struct page *page);

/* bitflags for do_page_add_anon_rmap() */
#define RMAP_EXCLUSIVE 0x01
#define RMAP_COMPOUND 0x02

/*
 * rmap interfaces called when adding or removing pte of page
 */
void page_move_anon_rmap(struct page *, struct vm_area_struct *);
void page_add_anon_rmap(struct page *, struct vm_area_struct *,
		unsigned long, bool);
void do_page_add_anon_rmap(struct page *, struct vm_area_struct *,
			   unsigned long, int);
void page_add_new_anon_rmap(struct page *, struct vm_area_struct *,
		unsigned long, bool);
void page_add_file_rmap(struct page *, bool);
void page_remove_rmap(struct page *, bool);

void hugepage_add_anon_rmap(struct page *, struct vm_area_struct *,
			    unsigned long);
void hugepage_add_new_anon_rmap(struct page *, struct vm_area_struct *,
				unsigned long);

static inline void page_dup_rmap(struct page *page, bool compound)
{
	atomic_inc(compound ? compound_mapcount_ptr(page) : &page->_mapcount);
}

/*
 * Called from mm/vmscan.c to handle paging out
 */
int page_referenced(struct page *, int is_locked,
			struct mem_cgroup *memcg, unsigned long *vm_flags);

bool try_to_unmap(struct page *, enum ttu_flags flags);

/* Avoid racy checks */
#define PVMW_SYNC		(1 << 0)
/* Look for migarion entries rather than present PTEs */
#define PVMW_MIGRATION		(1 << 1)
/* 
2024年7月2日23:55:21

 */
struct page_vma_mapped_walk {
	struct page *page;
	struct vm_area_struct *vma;
	unsigned long address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};
/* 2024年7月3日00:01:28

 */
static inline void page_vma_mapped_walk_done(struct page_vma_mapped_walk *pvmw)
{
	if (pvmw->pte)
		pte_unmap(pvmw->pte);
	if (pvmw->ptl)
		spin_unlock(pvmw->ptl);
}

bool page_vma_mapped_walk(struct page_vma_mapped_walk *pvmw);

/*
 * Used by swapoff to help locate where page is expected in vma.
 */
unsigned long page_address_in_vma(struct page *, struct vm_area_struct *);

/*
 * Cleans the PTEs of shared mappings.
 * (and since clean PTEs should also be readonly, write protects them too)
 *
 * returns the number of cleaned PTEs.
 */
int page_mkclean(struct page *);

/*
 * called in munlock()/munmap() path to check for other vmas holding
 * the page mlocked.
 */
void try_to_munlock(struct page *);

void remove_migration_ptes(struct page *old, struct page *new, bool locked);

/*
 * Called by memory-failure.c to kill processes.
 */
struct anon_vma *page_lock_anon_vma_read(struct page *page);
void page_unlock_anon_vma_read(struct anon_vma *anon_vma);
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma);

/*
2024年7月2日23:25:38

 * rmap_walk_control: To control rmap traversing for specific needs
 *
 * arg: passed to rmap_one() and invalid_vma()
 * rmap_one: executed on each vma where page is mapped
 * done: for checking traversing termination condition
 * anon_lock: for getting anon_lock by optimized way rather than default
 * invalid_vma: for skipping uninterested vma
 */
struct rmap_walk_control {
	void *arg;
	/*
	 * Return false if page table scanning in rmap_walk should be stopped.
	 * Otherwise, return true.
	 断开具体vma的pte
	 */
	bool (*rmap_one)(struct page *page, struct vm_area_struct *vma,
					unsigned long addr, void *arg);
	/* 判断一个页面是否已经断开 */
	int (*done)(struct page *page);
	/* 实现一个锁机制？ */
	struct anon_vma *(*anon_lock)(struct page *page);
	/* 跳过无效的vma */
	bool (*invalid_vma)(struct vm_area_struct *vma, void *arg);
};

void rmap_walk(struct page *page, struct rmap_walk_control *rwc);
void rmap_walk_locked(struct page *page, struct rmap_walk_control *rwc);

#else	/* !CONFIG_MMU */

#define anon_vma_init()		do {} while (0)
#define anon_vma_prepare(vma)	(0)
#define anon_vma_link(vma)	do {} while (0)

static inline int page_referenced(struct page *page, int is_locked,
				  struct mem_cgroup *memcg,
				  unsigned long *vm_flags)
{
	*vm_flags = 0;
	return 0;
}

#define try_to_unmap(page, refs) false

static inline int page_mkclean(struct page *page)
{
	return 0;
}


#endif	/* CONFIG_MMU */

#endif	/* _LINUX_RMAP_H */

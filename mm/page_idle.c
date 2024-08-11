// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/page_ext.h>
#include <linux/page_idle.h>
/* 一个位图chunk几个字节，8个 */
#define BITMAP_CHUNK_SIZE	sizeof(u64)
/* 一个位图chunk多少bit位，64位 */
#define BITMAP_CHUNK_BITS	(BITMAP_CHUNK_SIZE * BITS_PER_BYTE)

/*
通过pfn获得page结构体
 * Idle page tracking only considers user memory pages, for other types of
 * pages the idle flag is always unset and an attempt to set it is silently
 * ignored.
 *
 * We treat a page as a user memory page if it is on an LRU list, because it is
 * always safe to pass such a page to rmap_walk(), which is essential for idle
 * page tracking. With such an indicator of user pages we can skip isolated
 * pages, but since there are not usually many of them, it will hardly affect
 * the overall result.
 *
 * This function tries to get a user memory page by pfn as described above.
 */
static struct page *page_idle_get_page(unsigned long pfn)
{
	struct page *page;
	pg_data_t *pgdat;

	if (!pfn_valid(pfn))
		return NULL;
	/* 找到pfn的结构体 */
	page = pfn_to_page(pfn);
	if (!page || !PageLRU(page) ||
	    !get_page_unless_zero(page))
		return NULL;

	/* page存在，是lrupage，有引用 */
	pgdat = page_pgdat(page);

	spin_lock_irq(&pgdat->lru_lock);
	if (unlikely(!PageLRU(page))) {/* 这里加锁然后确认是不是lru页面，
	是什么作用？ */
		put_page(page);
		page = NULL;
	}
	spin_unlock_irq(&pgdat->lru_lock);
	return page;
}
/* page_idle_clear_pte_refs函数rmap是调用这个函数
对指向这个page的pte clear young，如果有映射的话
就对page清除PG_idle，设置PG_young */
static bool page_idle_clear_pte_refs_one(struct page *page,
					struct vm_area_struct *vma,
					unsigned long addr, void *arg)
{
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = addr,
	};
	bool referenced = false;

	while (page_vma_mapped_walk(&pvmw)) {/* 如果vma里面
	还有pte指向这个page，继续遍历 */
		addr = pvmw.address;
		if (pvmw.pte) {
			/*
			 * For PTE-mapped THP, one sub page is referenced,
			 * the whole THP is referenced.
			 */
			if (ptep_clear_young_notify(vma, addr, pvmw.pte))
				referenced = true;
		} else if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)) {
			if (pmdp_clear_young_notify(vma, addr, pvmw.pmd))
				referenced = true;
		} else {
			/* unexpected pmd-mapped page? */
			WARN_ON_ONCE(1);
		}
	}

	if (referenced) {/* 如果vma确实引用指向了这个page，
	清除PG_idle，设置PG_young */
		clear_page_idle(page);
		/*
		 * We cleared the referenced bit in a mapping to this page. To
		 * avoid interference with page reclaim, mark it young so that
		 * page_referenced() will return > 0.
		 */
		set_page_young(page);
	}
	return true;
}

/* 对这个页面进行rmap walk
对指向这个page的pte clear young，如果有映射的话
就对page清除PG_idle，设置PG_young */
static void page_idle_clear_pte_refs(struct page *page)
{
	/*
	 * Since rwc.arg is unused, rwc is effectively immutable, so we
	 * can make it static const to save some cycles and stack.
	 */
	static const struct rmap_walk_control rwc = {
		.rmap_one = page_idle_clear_pte_refs_one,
		.anon_lock = page_lock_anon_vma_read,
	};
	bool need_lock;

	if (!page_mapped(page) ||
	    !page_rmapping(page))
		return;

	need_lock = !PageAnon(page) || PageKsm(page);
	if (need_lock && !trylock_page(page))
		return;

	rmap_walk(page, (struct rmap_walk_control *)&rwc);

	if (need_lock)
		unlock_page(page);
}

/* read某pfn的idle位图的值 */
static ssize_t page_idle_bitmap_read(struct file *file, struct kobject *kobj,
				     struct bin_attribute *attr, char *buf,
				     loff_t pos, size_t count)
{
	u64 *out = (u64 *)buf;
	struct page *page;
	unsigned long pfn, end_pfn;
	int bit;

	if (pos % BITMAP_CHUNK_SIZE || count % BITMAP_CHUNK_SIZE)
		return -EINVAL;

	pfn = pos * BITS_PER_BYTE;
	if (pfn >= max_pfn)
		return 0;

	end_pfn = pfn + count * BITS_PER_BYTE;
	if (end_pfn > max_pfn)
		end_pfn = max_pfn;

	for (; pfn < end_pfn; pfn++) {
		bit = pfn % BITMAP_CHUNK_BITS;
		if (!bit)
			*out = 0ULL;
		page = page_idle_get_page(pfn);
		if (page) {
			if (page_is_idle(page)) {/* 如果page被设置了idle位  */
				/*
				 * The page might have been referenced via a
				 * pte, in which case it is not idle. Clear
				 * refs and recheck.
				 */
				page_idle_clear_pte_refs(page);
				if (page_is_idle(page))/* 是idle的话，
				把输出结果的相应位置位 */
					*out |= 1ULL << bit;
			}
			put_page(page);
		}
		if (bit == BITMAP_CHUNK_BITS - 1)
			out++;
		cond_resched();
	}
	return (char *)out - buf;
}
/* 写page_idle的bitmap，标记相应的页面的状态
@pos：目标pfn对应的bit位对应的字节位
@count：要操作的页面数量的bit位有多少字节


 */
static ssize_t page_idle_bitmap_write(struct file *file, struct kobject *kobj,
				      struct bin_attribute *attr, char *buf,
				      loff_t pos, size_t count)
{
	/* buf是一个long，也是位图的一个chunk？ */
	const u64 *in = (u64 *)buf;
	struct page *page;
	unsigned long pfn, end_pfn;
	int bit;

	if (pos % BITMAP_CHUNK_SIZE || count % BITMAP_CHUNK_SIZE)
		return -EINVAL;
	/*  */
	pfn = pos * BITS_PER_BYTE;
	if (pfn >= max_pfn)
		return -ENXIO;

	end_pfn = pfn + count * BITS_PER_BYTE;
	if (end_pfn > max_pfn)
		end_pfn = max_pfn;

	for (; pfn < end_pfn; pfn++) {/* 逐个操作pfn */
		/* 这个pfn在chunk里面的bit idx */
		bit = pfn % BITMAP_CHUNK_BITS;
		if ((*in >> bit) & 1) {/* 找到这个pfn在位图chunk：in的值，如果为1的话 */
			/* 获得page的结构体 */
			page = page_idle_get_page(pfn);
			
			if (page) {/*  */
			/* 这个函数作用是？ */
				page_idle_clear_pte_refs(page);
				/* 设置PG_idle位 */
				set_page_idle(page);
				put_page(page);
			}
		}
		if (bit == BITMAP_CHUNK_BITS - 1)
			in++;
		cond_resched();
	}
	return (char *)in - buf;
}
/* page_idle在fs接口文件的回调 */
static struct bin_attribute page_idle_bitmap_attr =
		__BIN_ATTR(bitmap, 0600,
			   page_idle_bitmap_read, page_idle_bitmap_write, 0);
/*  */
static struct bin_attribute *page_idle_bin_attrs[] = {
	&page_idle_bitmap_attr,
	NULL,
};
/* page_idle机制在fs接口的回调 */
static const struct attribute_group page_idle_attr_group = {
	.bin_attrs = page_idle_bin_attrs,
	.name = "page_idle",
};

#ifndef CONFIG_64BIT
static bool need_page_idle(void)
{
	return true;
}
struct page_ext_operations page_idle_ops = {
	.need = need_page_idle,
};
#endif
/* 初始化fs里面的接口文件 */
static int __init page_idle_init(void)
{
	int err;

	err = sysfs_create_group(mm_kobj, &page_idle_attr_group);
	if (err) {
		pr_err("page_idle: register sysfs failed\n");
		return err;
	}
	return 0;
}
subsys_initcall(page_idle_init);

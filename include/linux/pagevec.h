/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/pagevec.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagevec is a multipage container which is used for that.
 */

#ifndef _LINUX_PAGEVEC_H
#define _LINUX_PAGEVEC_H

#include <linux/xarray.h>

/* 15 pointers + header align the pagevec structure to a power of two */
#define PAGEVEC_SIZE	15

struct page;
struct address_space;
/* 2024年6月24日23:42:37
https://blog.csdn.net/dog250/article/details/6070075
以往要加入到lru链表的page都要加入到这个pagevec了，并不再直接往lru中加入了。
可是不加入lru的page就不会被内存管理机制所管理，因此仅仅这样是不行的，除非给
pagevec结构加上lru的功能，然而这又势必会使这个结构体复杂化，再一个，这个结构体
使用的最大范围就是“每cpu”，更多的它都是局部使用的，这样就使得锁的粒度细化了很多，
而lru则是全局的，设计pagevec的目的之一正是因为这个。
2024年06月25日14:39:09
每次对lru链表操作都可能涉及到加锁操作，这样就可能出现锁冲突严重的情况。为了解决这样的问题，
Linux增加了一个“中间层”，这就是pagevec，它其实是一个lru缓存。每个pagevec中最多可容纳
15个page，都是同一种操作的合集。
 */
struct pagevec {
	/* 现在的页面数量 */
	unsigned char nr;
	bool percpu_pvec_drained;
	/* 存储页面的数组 */
	struct page *pages[PAGEVEC_SIZE];
};

void __pagevec_release(struct pagevec *pvec);
void __pagevec_lru_add(struct pagevec *pvec);
unsigned pagevec_lookup_entries(struct pagevec *pvec,
				struct address_space *mapping,
				pgoff_t start, unsigned nr_entries,
				pgoff_t *indices);
void pagevec_remove_exceptionals(struct pagevec *pvec);
unsigned pagevec_lookup_range(struct pagevec *pvec,
			      struct address_space *mapping,
			      pgoff_t *start, pgoff_t end);
static inline unsigned pagevec_lookup(struct pagevec *pvec,
				      struct address_space *mapping,
				      pgoff_t *start)
{
	return pagevec_lookup_range(pvec, mapping, start, (pgoff_t)-1);
}

unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		xa_mark_t tag);
unsigned pagevec_lookup_range_nr_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		xa_mark_t tag, unsigned max_pages);
static inline unsigned pagevec_lookup_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, xa_mark_t tag)
{
	return pagevec_lookup_range_tag(pvec, mapping, index, (pgoff_t)-1, tag);
}

static inline void pagevec_init(struct pagevec *pvec)
{
	pvec->nr = 0;
	pvec->percpu_pvec_drained = false;
}
/* 2024年7月17日23:59:57 */
static inline void pagevec_reinit(struct pagevec *pvec)
{
	pvec->nr = 0;
}
/* 2024年06月25日14:49:02
2024年7月17日23:52:28
 */
static inline unsigned pagevec_count(struct pagevec *pvec)
{
	return pvec->nr;
}
/* 2024年6月24日23:47:19
剩余空间？
 */
static inline unsigned pagevec_space(struct pagevec *pvec)
{
	return PAGEVEC_SIZE - pvec->nr;
}

/*
2024年6月24日23:45:59
加入pagevec

 * Add a page to a pagevec.  Returns the number of slots still available.
 */
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
	pvec->pages[pvec->nr++] = page;
	return pagevec_space(pvec);
}
/* 2024年7月17日23:59:06 */
static inline void pagevec_release(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_release(pvec);
}

#endif /* _LINUX_PAGEVEC_H */

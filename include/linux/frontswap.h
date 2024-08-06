/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FRONTSWAP_H
#define _LINUX_FRONTSWAP_H

#include <linux/swap.h>
#include <linux/mm.h>
#include <linux/bitops.h>
#include <linux/jump_label.h>

/*
 * Return code to denote that requested number of
 * frontswap pages are unused(moved to page cache).
 * Used in in shmem_unuse and try_to_unuse.
 */
#define FRONTSWAP_PAGES_UNUSED	2
/* 2024年7月29日22:35:27
front swap是什么 */
struct frontswap_ops {
	void (*init)(unsigned); /* this swap type was just swapon'ed */
	int (*store)(unsigned, pgoff_t, struct page *); /* store a page */
	int (*load)(unsigned, pgoff_t, struct page *); /* load a page */
	void (*invalidate_page)(unsigned, pgoff_t); /* page no longer needed */
	void (*invalidate_area)(unsigned); /* swap type just swapoff'ed */
	struct frontswap_ops *next; /* private pointer to next ops */
};

extern void frontswap_register_ops(struct frontswap_ops *ops);
extern void frontswap_shrink(unsigned long);
extern unsigned long frontswap_curr_pages(void);
extern void frontswap_writethrough(bool);
#define FRONTSWAP_HAS_EXCLUSIVE_GETS
extern void frontswap_tmem_exclusive_gets(bool);

extern bool __frontswap_test(struct swap_info_struct *, pgoff_t);
extern void __frontswap_init(unsigned type, unsigned long *map);
extern int __frontswap_store(struct page *page);
extern int __frontswap_load(struct page *page);
extern void __frontswap_invalidate_page(unsigned, pgoff_t);
extern void __frontswap_invalidate_area(unsigned);

#ifdef CONFIG_FRONTSWAP
extern struct static_key_false frontswap_enabled_key;

static inline bool frontswap_enabled(void)
{
	return static_branch_unlikely(&frontswap_enabled_key);
}
/* 确定offset是否位于此si的frontswap里面？ */
static inline bool frontswap_test(struct swap_info_struct *sis, pgoff_t offset)
{
	return __frontswap_test(sis, offset);
}
/* 2024年08月01日19:55:02 */
static inline void frontswap_map_set(struct swap_info_struct *p,
				     unsigned long *map)
{
	p->frontswap_map = map;
}
/* 2024年08月01日19:54:35 */
static inline unsigned long *frontswap_map_get(struct swap_info_struct *p)
{
	return p->frontswap_map;
}
#else
/* all inline routines become no-ops and all externs are ignored */

static inline bool frontswap_enabled(void)
{
	return false;
}

static inline bool frontswap_test(struct swap_info_struct *sis, pgoff_t offset)
{
	return false;
}

static inline void frontswap_map_set(struct swap_info_struct *p,
				     unsigned long *map)
{
}

static inline unsigned long *frontswap_map_get(struct swap_info_struct *p)
{
	return NULL;
}
#endif
/* 2024年8月7日00:14:13
每当交换子系统准备将一个页面写入交换设备时（参见swap_writepage()），就会调用
frontswap_store。Frontswap与frontswap backend协商，如果backend说它没有空
间，frontswap_store返回-1，内核就会照常把页换到交换设备上。注意，来自frontswap
backend的响应对内核来说是不可预测的；它可能选择从不接受一个页面，可能接受每九个
页面，也可能接受每一个页面。但是如果backend确实接受了一个页面，那么这个页面的数
据已经被复制并与类型和偏移量相关联了，而且backend保证了数据的持久性。在这种情况
下，frontswap在交换设备的“frontswap_map” 中设置了一个位，对应于交换设备上的
页面偏移量，否则它就会将数据写入该设备。 */
static inline int frontswap_store(struct page *page)
{
	if (frontswap_enabled())
		return __frontswap_store(page);

	return -1;
}
/* 2024年07月03日14:54:12
尝试front swap机制读取页面 */
static inline int frontswap_load(struct page *page)
{
	if (frontswap_enabled())
		return __frontswap_load(page);

	return -1;
}
/* front swap机制invaliddatepage，
swap移除free 自己entry的时候调用 */
static inline void frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	if (frontswap_enabled())
		__frontswap_invalidate_page(type, offset);
}
/* 清空此type的si的front */
static inline void frontswap_invalidate_area(unsigned type)
{
	if (frontswap_enabled())
		__frontswap_invalidate_area(type);
}
/* 初始化type的si的frontmap */
static inline void frontswap_init(unsigned type, unsigned long *map)
{
#ifdef CONFIG_FRONTSWAP
	__frontswap_init(type, map);
#endif
}

#endif /* _LINUX_FRONTSWAP_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PAGE_IDLE_H
#define _LINUX_MM_PAGE_IDLE_H

#include <linux/bitops.h>
#include <linux/page-flags.h>
#include <linux/page_ext.h>

#ifdef CONFIG_IDLE_PAGE_TRACKING

#ifdef CONFIG_64BIT
static inline bool page_is_young(struct page *page)
{
	return PageYoung(page);
}
/* 设置的PG_young标记位 */
static inline void set_page_young(struct page *page)
{
	SetPageYoung(page);
}

static inline bool test_and_clear_page_young(struct page *page)
{
	return TestClearPageYoung(page);
}

static inline bool page_is_idle(struct page *page)
{
	return PageIdle(page);
}
/* 设置PG_idle位 */
static inline void set_page_idle(struct page *page)
{
	SetPageIdle(page);
}
/* 清除page的idle */
static inline void clear_page_idle(struct page *page)
{
	ClearPageIdle(page);
}
#else /* !CONFIG_64BIT */
/*
 * If there is not enough space to store Idle and Young bits in page flags, use
 * page ext flags instead.
 */
extern struct page_ext_operations page_idle_ops;

static inline bool page_is_young(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return false;

	return test_bit(PAGE_EXT_YOUNG, &page_ext->flags);
}

static inline void set_page_young(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return;

	set_bit(PAGE_EXT_YOUNG, &page_ext->flags);
}

static inline bool test_and_clear_page_young(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return false;

	return test_and_clear_bit(PAGE_EXT_YOUNG, &page_ext->flags);
}

static inline bool page_is_idle(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return false;

	return test_bit(PAGE_EXT_IDLE, &page_ext->flags);
}

static inline void set_page_idle(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return;

	set_bit(PAGE_EXT_IDLE, &page_ext->flags);
}

static inline void clear_page_idle(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return;

	clear_bit(PAGE_EXT_IDLE, &page_ext->flags);
}
#endif /* CONFIG_64BIT */

#else /* !CONFIG_IDLE_PAGE_TRACKING */

static inline bool page_is_young(struct page *page)
{
	return false;
}

static inline void set_page_young(struct page *page)
{
}

static inline bool test_and_clear_page_young(struct page *page)
{
	return false;
}

static inline bool page_is_idle(struct page *page)
{
	return false;
}

static inline void set_page_idle(struct page *page)
{
}

static inline void clear_page_idle(struct page *page)
{
}

#endif /* CONFIG_IDLE_PAGE_TRACKING */

#endif /* _LINUX_MM_PAGE_IDLE_H */

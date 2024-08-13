/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REF_H
#define _LINUX_PAGE_REF_H

#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/tracepoint-defs.h>

extern struct tracepoint __tracepoint_page_ref_set;
extern struct tracepoint __tracepoint_page_ref_mod;
extern struct tracepoint __tracepoint_page_ref_mod_and_test;
extern struct tracepoint __tracepoint_page_ref_mod_and_return;
extern struct tracepoint __tracepoint_page_ref_mod_unless;
extern struct tracepoint __tracepoint_page_ref_freeze;
extern struct tracepoint __tracepoint_page_ref_unfreeze;

#ifdef CONFIG_DEBUG_PAGE_REF

/*
 * Ideally we would want to use the trace_<tracepoint>_enabled() helper
 * functions. But due to include header file issues, that is not
 * feasible. Instead we have to open code the static key functions.
 *
 * See trace_##name##_enabled(void) in include/linux/tracepoint.h
 */
#define page_ref_tracepoint_active(t) static_key_false(&(t).key)

extern void __page_ref_set(struct page *page, int v);
extern void __page_ref_mod(struct page *page, int v);
extern void __page_ref_mod_and_test(struct page *page, int v, int ret);
extern void __page_ref_mod_and_return(struct page *page, int v, int ret);
extern void __page_ref_mod_unless(struct page *page, int v, int u);
extern void __page_ref_freeze(struct page *page, int v, int ret);
extern void __page_ref_unfreeze(struct page *page, int v);

#else
/* 2024年8月13日22:01:25 */
#define page_ref_tracepoint_active(t) false

static inline void __page_ref_set(struct page *page, int v)
{
}
static inline void __page_ref_mod(struct page *page, int v)
{
}
static inline void __page_ref_mod_and_test(struct page *page, int v, int ret)
{
}
static inline void __page_ref_mod_and_return(struct page *page, int v, int ret)
{
}
static inline void __page_ref_mod_unless(struct page *page, int v, int u)
{
}
static inline void __page_ref_freeze(struct page *page, int v, int ret)
{
}
static inline void __page_ref_unfreeze(struct page *page, int v)
{
}

#endif

static inline int page_ref_count(struct page *page)
{
	return atomic_read(&page->_refcount);
}
/* 2024年7月3日22:38:29
2024年7月14日14:50:04
 */
static inline int page_count(struct page *page)
{
	return atomic_read(&compound_head(page)->_refcount);
}
/* 2024年6月26日21:50:15 */
static inline void set_page_count(struct page *page, int v)
{
	atomic_set(&page->_refcount, v);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_set))
		__page_ref_set(page, v);
}

/*
2024年6月26日21:50:06

 * Setup the page count before being freed into the page allocator for
 * the first time (boot or memory hotplug)
 */
static inline void init_page_count(struct page *page)
{
	set_page_count(page, 1);
}
/*

 */
static inline void page_ref_add(struct page *page, int nr)
{
	atomic_add(nr, &page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))/* 不可能的if */
		__page_ref_mod(page, nr);
}

static inline void page_ref_sub(struct page *page, int nr)
{
	atomic_sub(nr, &page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, -nr);
}
/* 2024年6月24日23:45:29
 */
static inline void page_ref_inc(struct page *page)
{
	atomic_inc(&page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, 1);
}

static inline void page_ref_dec(struct page *page)
{
	atomic_dec(&page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, -1);
}

static inline int page_ref_sub_and_test(struct page *page, int nr)
{
	int ret = atomic_sub_and_test(nr, &page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_test))
		__page_ref_mod_and_test(page, -nr, ret);
	return ret;
}

static inline int page_ref_inc_return(struct page *page)
{
	int ret = atomic_inc_return(&page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_return))
		__page_ref_mod_and_return(page, 1, ret);
	return ret;
}
/* 2024年6月30日21:39:45 */
static inline int page_ref_dec_and_test(struct page *page)
{
	int ret = atomic_dec_and_test(&page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_test))
		__page_ref_mod_and_test(page, -1, ret);
	return ret;
}

static inline int page_ref_dec_return(struct page *page)
{
	int ret = atomic_dec_return(&page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_return))
		__page_ref_mod_and_return(page, -1, ret);
	return ret;
}
/* 2024年8月11日20:32:14 */
static inline int page_ref_add_unless(struct page *page, int nr, int u)
{
	int ret = atomic_add_unless(&page->_refcount, nr, u);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_unless))
		__page_ref_mod_unless(page, nr, ret);
	return ret;
}
/* 2024年07月03日11:51:39

 */
static inline int page_ref_freeze(struct page *page, int count)
{
	int ret = likely(atomic_cmpxchg(&page->_refcount, count, 0) == count);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_freeze))
		__page_ref_freeze(page, count, ret);
	
	return ret;
}
/* 2024年8月13日22:04:29
todo
 */
static inline void page_ref_unfreeze(struct page *page, int count)
{
	VM_BUG_ON_PAGE(page_count(page) != 0, page);
	VM_BUG_ON(count == 0);

	atomic_set_release(&page->_refcount, count);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_unfreeze))
		__page_ref_unfreeze(page, count);
}

#endif

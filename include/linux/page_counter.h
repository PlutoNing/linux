/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_COUNTER_H
#define _LINUX_PAGE_COUNTER_H

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <asm/page.h>
/* 

2024年06月21日15:30:51
每个 mem_cgroup 中又有一个名为 memory 的 page_counter 结构体，它跟踪了每个 mem_cgroup 
的内存使用情况，也就是每个控制组的内存使用情况。每当我们要为这个mem_cgroup 分配新的内存时，
便会调用 page_counter_try_charge 函数来尝试对这些新的内存进行 charge 操作，即将这些页
加入到该 page_counter 里。如果加上这些页之后，这个 page_counter 的值大于了我们给它设定
的最大值，则会导致这次 charge 失败，随后根据其他设置可能会进一步触发内存不足的操作 oom。
如果没有超过最大值的限制，则此次 charge 成功，新的页成功被加入 mem_cgroup 的计数器中。

 */
struct page_counter {
	/* 目前使用量 */
	atomic_long_t usage;
	/* todo 与min usage区别？ */
	unsigned long min;
	/*  */
	unsigned long low;
	/* 最大允许的使用量吗？ */
	unsigned long max;
	/* 父cg？ page counter也有层级结构*/
	struct page_counter *parent;

	/* effective memory.min and memory.min usage tracking */
	unsigned long emin;
	atomic_long_t min_usage;
	/* 子counter的min usage */
	atomic_long_t children_min_usage;

	/* effective memory.low and memory.low usage tracking */
	unsigned long elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;

	/* legacy */
	unsigned long watermark;
	/* 申请失败的情况，就是比如说超了max的情况 */
	unsigned long failcnt;
};

#if BITS_PER_LONG == 32
#define PAGE_COUNTER_MAX LONG_MAX
#else
#define PAGE_COUNTER_MAX (LONG_MAX / PAGE_SIZE)
#endif

static inline void page_counter_init(struct page_counter *counter,
				     struct page_counter *parent)
{
	atomic_long_set(&counter->usage, 0);
	counter->max = PAGE_COUNTER_MAX;
	counter->parent = parent;
}

static inline unsigned long page_counter_read(struct page_counter *counter)
{
	return atomic_long_read(&counter->usage);
}

void page_counter_cancel(struct page_counter *counter, unsigned long nr_pages);
void page_counter_charge(struct page_counter *counter, unsigned long nr_pages);
bool page_counter_try_charge(struct page_counter *counter,
			     unsigned long nr_pages,
			     struct page_counter **fail);
void page_counter_uncharge(struct page_counter *counter, unsigned long nr_pages);
void page_counter_set_min(struct page_counter *counter, unsigned long nr_pages);
void page_counter_set_low(struct page_counter *counter, unsigned long nr_pages);
int page_counter_set_max(struct page_counter *counter, unsigned long nr_pages);
int page_counter_memparse(const char *buf, const char *max,
			  unsigned long *nr_pages);

static inline void page_counter_reset_watermark(struct page_counter *counter)
{
	counter->watermark = page_counter_read(counter);
}

#endif /* _LINUX_PAGE_COUNTER_H */

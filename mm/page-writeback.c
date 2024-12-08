// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/page-writeback.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 * Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
 *
 * Contains functions related to writing back dirty pages at the
 * address_space level.
 *
 * 10Apr2002	Andrew Morton
 *		Initial version
 */

#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/init.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/mpage.h>
#include <linux/rmap.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/pagevec.h>
#include <linux/timer.h>
#include <linux/sched/rt.h>
#include <linux/sched/signal.h>
#include <linux/mm_inline.h>
#include <trace/events/writeback.h>

#include "internal.h"

/*
 * Sleep at most 200ms at a time in balance_dirty_pages().
 */
#define MAX_PAUSE		max(HZ/5, 1)

/*
 * Try to keep balance_dirty_pages() call intervals higher than this many pages
 * by raising pause time to max_pause when falls below it.
 */
#define DIRTY_POLL_THRESH	(128 >> (PAGE_SHIFT - 10))

/*
 * Estimate write bandwidth at 200ms intervals.
 */
#define BANDWIDTH_INTERVAL	max(HZ/5, 1)

#define RATELIMIT_CALC_SHIFT	10

/*
 * After a CPU has dirtied this many pages, balance_dirty_pages_ratelimited
 * will look to see if it needs to force writeback or throttling.
 */
static long ratelimit_pages = 32;

/* The following parameters are exported via /proc/sys/vm */

/*
 * Start background writeback (via writeback threads) at this percentage
 */
static int dirty_background_ratio = 10;

/*
 * dirty_background_bytes starts at 0 (disabled) so that it is a function of
 * dirty_background_ratio * the amount of dirtyable memory
 */
static unsigned long dirty_background_bytes;

/*
 * free highmem will not be subtracted from the total free memory
 * for calculating free ratios if vm_highmem_is_dirtyable is true
 */
static int vm_highmem_is_dirtyable;

/*
 * The generator of dirty data starts writeback at this percentage
 */
static int vm_dirty_ratio = 20;

/*
 * vm_dirty_bytes starts at 0 (disabled) so that it is a function of
 * vm_dirty_ratio * the amount of dirtyable memory
   表示? 2024年12月7日22:32:42
 */
static unsigned long vm_dirty_bytes;

/*
 * The interval between `kupdate'-style writebacks
 */
unsigned int dirty_writeback_interval = 5 * 100; /* centiseconds */

EXPORT_SYMBOL_GPL(dirty_writeback_interval);

/*
 * The longest time for which data is allowed to remain dirty
 */
unsigned int dirty_expire_interval = 30 * 100; /* centiseconds */

/*
 * Flag that puts the machine in "laptop mode". Doubles as a timeout in jiffies:
 * a full sync is triggered after this time elapses without any disk activity.
 */
int laptop_mode;

EXPORT_SYMBOL(laptop_mode);

/* End of sysctl-exported parameters */

struct wb_domain global_wb_domain;

/* consolidated parameters for balance_dirty_pages() and its subroutines */
struct dirty_throttle_control {
#ifdef CONFIG_CGROUP_WRITEBACK
	struct wb_domain	*dom;
	struct dirty_throttle_control *gdtc;	/* only set in memcg dtc's */
#endif
	struct bdi_writeback	*wb; 
	struct fprop_local_percpu *wb_completions;

	unsigned long		avail;		/* dirtyable */
	unsigned long		dirty;		/* file_dirty + write + nfs */
	unsigned long		thresh;		/* dirty threshold */
	unsigned long		bg_thresh;	/* dirty background threshold */

	unsigned long		wb_dirty;	/* per-wb counterparts */
	unsigned long		wb_thresh;
	unsigned long		wb_bg_thresh;

	unsigned long		pos_ratio;
};

/*
 * Length of period for aging writeout fractions of bdis. This is an
 * arbitrarily chosen number. The longer the period, the slower fractions will
 * reflect changes in current writeout rate.
 */
#define VM_COMPLETIONS_PERIOD_LEN (3*HZ)

#ifdef CONFIG_CGROUP_WRITEBACK

/*  */
#define GDTC_INIT(__wb)		.wb = (__wb),				\
				.dom = &global_wb_domain,		\
				.wb_completions = &(__wb)->completions

#define GDTC_INIT_NO_WB		.dom = &global_wb_domain

#define MDTC_INIT(__wb, __gdtc)	.wb = (__wb),				\
				.dom = mem_cgroup_wb_domain(__wb),	\
				.wb_completions = &(__wb)->memcg_completions, \
				.gdtc = __gdtc

static bool mdtc_valid(struct dirty_throttle_control *dtc)
{
	return dtc->dom;
}

static struct wb_domain *dtc_dom(struct dirty_throttle_control *dtc)
{
	return dtc->dom;
}

//返回mdtc对应的gdtc
static struct dirty_throttle_control *mdtc_gdtc(struct dirty_throttle_control *mdtc)
{
	return mdtc->gdtc;
}

static struct fprop_local_percpu *wb_memcg_completions(struct bdi_writeback *wb)
{
	return &wb->memcg_completions;
}

static void wb_min_max_ratio(struct bdi_writeback *wb,
			     unsigned long *minp, unsigned long *maxp)
{
	unsigned long this_bw = READ_ONCE(wb->avg_write_bandwidth);
	unsigned long tot_bw = atomic_long_read(&wb->bdi->tot_write_bandwidth);
	unsigned long long min = wb->bdi->min_ratio;
	unsigned long long max = wb->bdi->max_ratio;

	/*
	 * @wb may already be clean by the time control reaches here and
	 * the total may not include its bw.
	 */
	if (this_bw < tot_bw) {
		if (min) {
			min *= this_bw;
			min = div64_ul(min, tot_bw);
		}
		if (max < 100 * BDI_RATIO_SCALE) {
			max *= this_bw;
			max = div64_ul(max, tot_bw);
		}
	}

	*minp = min;
	*maxp = max;
}

#else	/* CONFIG_CGROUP_WRITEBACK */

#define GDTC_INIT(__wb)		.wb = (__wb),                           \
				.wb_completions = &(__wb)->completions
#define GDTC_INIT_NO_WB
#define MDTC_INIT(__wb, __gdtc)

static bool mdtc_valid(struct dirty_throttle_control *dtc)
{
	return false;
}

static struct wb_domain *dtc_dom(struct dirty_throttle_control *dtc)
{
	return &global_wb_domain;
}

static struct dirty_throttle_control *mdtc_gdtc(struct dirty_throttle_control *mdtc)
{
	return NULL;
}

static struct fprop_local_percpu *wb_memcg_completions(struct bdi_writeback *wb)
{
	return NULL;
}

static void wb_min_max_ratio(struct bdi_writeback *wb,
			     unsigned long *minp, unsigned long *maxp)
{
	*minp = wb->bdi->min_ratio;
	*maxp = wb->bdi->max_ratio;
}

#endif	/* CONFIG_CGROUP_WRITEBACK */

/*
 * In a memory zone, there is a certain amount of pages we consider
 * available for the page cache, which is essentially the number of
 * free and reclaimable pages, minus some zone reserves to protect
 * lowmem and the ability to uphold the zone's watermarks without
 * requiring writeback.
 *
 * This number of dirtyable pages is the base value of which the
 * user-configurable dirty ratio is the effective number of pages that
 * are allowed to be actually dirtied.  Per individual zone, or
 * globally by using the sum of dirtyable pages over all zones.
 *
 * Because the user is allowed to specify the dirty limit globally as
 * absolute number of bytes, calculating the per-zone dirty limit can
 * require translating the configured limit into a percentage of
 * global dirtyable memory first.
 */

/**
 * node_dirtyable_memory - number of dirtyable pages in a node
 * @pgdat: the node
 *
 * Return: the node's number of pages potentially available for dirty
 * page cache.  This is the base value for the per-node dirty limits.
 */
static unsigned long node_dirtyable_memory(struct pglist_data *pgdat)
{
	unsigned long nr_pages = 0;
	int z;

	for (z = 0; z < MAX_NR_ZONES; z++) {
		struct zone *zone = pgdat->node_zones + z;

		if (!populated_zone(zone))
			continue;

		nr_pages += zone_page_state(zone, NR_FREE_PAGES);
	}

	/*
	 * Pages reserved for the kernel should not be considered
	 * dirtyable, to prevent a situation where reclaim has to
	 * clean pages in order to balance the zones.
	 */
	nr_pages -= min(nr_pages, pgdat->totalreserve_pages);

	nr_pages += node_page_state(pgdat, NR_INACTIVE_FILE);
	nr_pages += node_page_state(pgdat, NR_ACTIVE_FILE);

	return nr_pages;
}

static unsigned long highmem_dirtyable_memory(unsigned long total)
{
#ifdef CONFIG_HIGHMEM
	int node;
	unsigned long x = 0;
	int i;

	for_each_node_state(node, N_HIGH_MEMORY) {
		for (i = ZONE_NORMAL + 1; i < MAX_NR_ZONES; i++) {
			struct zone *z;
			unsigned long nr_pages;

			if (!is_highmem_idx(i))
				continue;

			z = &NODE_DATA(node)->node_zones[i];
			if (!populated_zone(z))
				continue;

			nr_pages = zone_page_state(z, NR_FREE_PAGES);
			/* watch for underflows */
			nr_pages -= min(nr_pages, high_wmark_pages(z));
			nr_pages += zone_page_state(z, NR_ZONE_INACTIVE_FILE);
			nr_pages += zone_page_state(z, NR_ZONE_ACTIVE_FILE);
			x += nr_pages;
		}
	}

	/*
	 * Make sure that the number of highmem pages is never larger
	 * than the number of the total dirtyable memory. This can only
	 * occur in very strange VM situations but we want to make sure
	 * that this does not occur.
	 */
	return min(x, total);
#else
	return 0;
#endif
}

/**
 * global_dirtyable_memory - number of globally dirtyable pages
 * 可以脏的页?是什么页? 好像差不多就是free+文件页
 * Return: the global number of pages potentially available for dirty
 * page cache.  This is the base value for the global dirty limits.
 */
static unsigned long global_dirtyable_memory(void)
{
	unsigned long x;

	x = global_zone_page_state(NR_FREE_PAGES);

	/*
	 * Pages reserved for the kernel should not be considered
	 * dirtyable, to prevent a situation where reclaim has to
	 * clean pages in order to balance the zones.
	 */
	x -= min(x, totalreserve_pages);

	x += global_node_page_state(NR_INACTIVE_FILE);
	x += global_node_page_state(NR_ACTIVE_FILE);

	if (!vm_highmem_is_dirtyable)
		x -= highmem_dirtyable_memory(x);

	return x + 1;	/* Ensure that we never return 0 */
}

/**
   计算一个dtc的门限?
 * domain_dirty_limits - calculate thresh and bg_thresh for a wb_domain
 * @dtc: dirty_throttle_control of interest
 *
 * Calculate @dtc->thresh and ->bg_thresh considering
 * vm_dirty_{bytes|ratio} and dirty_background_{bytes|ratio}.  The caller
 * must ensure that @dtc->avail is set before calling this function.  The
 * dirty limits will be lifted by 1/4 for real-time tasks.
   计算dtc的thresh和bg_thresh, 考虑vm_dirty_{bytes|ratio}和dirty_background_{bytes|ratio}
  调用者必须确保dtc->avail在调用这个函数之前被设置
  脏页限制将被实时任务提高1/4
 */
static void domain_dirty_limits(struct dirty_throttle_control *dtc)
{
	const unsigned long available_memory = dtc->avail; //获得可用内存
	struct dirty_throttle_control *gdtc = mdtc_gdtc(dtc); //获得gdtc
	unsigned long bytes = vm_dirty_bytes;
	unsigned long bg_bytes = dirty_background_bytes;
	/* convert ratios to per-PAGE_SIZE for higher precision */
	unsigned long ratio = (vm_dirty_ratio * PAGE_SIZE) / 100;
	unsigned long bg_ratio = (dirty_background_ratio * PAGE_SIZE) / 100;
	unsigned long thresh;
	unsigned long bg_thresh;
	struct task_struct *tsk;

	/* gdtc is !NULL iff @dtc is for memcg domain */
	if (gdtc) {
		unsigned long global_avail = gdtc->avail;

		/*
		 * The byte settings can't be applied directly to memcg
		 * domains.  Convert them to ratios by scaling against
		 * globally available memory.  As the ratios are in
		 * per-PAGE_SIZE, they can be obtained by dividing bytes by
		 * number of pages.
		 */
		if (bytes)
			ratio = min(DIV_ROUND_UP(bytes, global_avail),
				    PAGE_SIZE);
		if (bg_bytes)
			bg_ratio = min(DIV_ROUND_UP(bg_bytes, global_avail),
				       PAGE_SIZE);
		bytes = bg_bytes = 0;
	}

	if (bytes)
		thresh = DIV_ROUND_UP(bytes, PAGE_SIZE);
	else
		thresh = (ratio * available_memory) / PAGE_SIZE;

	if (bg_bytes)
		bg_thresh = DIV_ROUND_UP(bg_bytes, PAGE_SIZE);
	else
		bg_thresh = (bg_ratio * available_memory) / PAGE_SIZE;

	if (bg_thresh >= thresh)
		bg_thresh = thresh / 2;
	tsk = current;
	if (rt_task(tsk)) {
		bg_thresh += bg_thresh / 4 + global_wb_domain.dirty_limit / 32;
		thresh += thresh / 4 + global_wb_domain.dirty_limit / 32;
	}


	dtc->thresh = thresh;
	dtc->bg_thresh = bg_thresh;

	/* we should eventually report the domain in the TP */
	if (!gdtc)
		trace_global_dirty_state(bg_thresh, thresh);
}

/**
 * global_dirty_limits - background-writeback and dirty-throttling thresholds
  后台写回和脏页限制阈值?
 * @pbackground: out parameter for bg_thresh
 * @pdirty: out parameter for thresh
 *
 * Calculate bg_thresh and thresh for global_wb_domain.  See
 * domain_dirty_limits() for details.
 */
void global_dirty_limits(unsigned long *pbackground, unsigned long *pdirty)
{
	struct dirty_throttle_control gdtc = { GDTC_INIT_NO_WB };

	gdtc.avail = global_dirtyable_memory();
	domain_dirty_limits(&gdtc);

	*pbackground = gdtc.bg_thresh;
	*pdirty = gdtc.thresh;
}

/**
 * node_dirty_limit - maximum number of dirty pages allowed in a node
   计算一个node的脏页限制?
 * @pgdat: the node
 *
 * Return: the maximum number of dirty pages allowed in a node, based
 * on the node's dirtyable memory.
   返回: 基于节点的脏页内存，节点允许的最大脏页数
 */
static unsigned long node_dirty_limit(struct pglist_data *pgdat)
{
	unsigned long node_memory = node_dirtyable_memory(pgdat);
	struct task_struct *tsk = current;
	unsigned long dirty;

	if (vm_dirty_bytes)
		dirty = DIV_ROUND_UP(vm_dirty_bytes, PAGE_SIZE) *
			node_memory / global_dirtyable_memory();
	else
		dirty = vm_dirty_ratio * node_memory / 100;

	if (rt_task(tsk))
		dirty += dirty / 4;

	return dirty;
}

/**
 * node_dirty_ok - tells whether a node is within its dirty limits
 * @pgdat: the node to check
 *
 * Return: %true when the dirty pages in @pgdat are within the node's
 * dirty limit, %false if the limit is exceeded.
 */
bool node_dirty_ok(struct pglist_data *pgdat)
{
	unsigned long limit = node_dirty_limit(pgdat);
	unsigned long nr_pages = 0;

	nr_pages += node_page_state(pgdat, NR_FILE_DIRTY);
	nr_pages += node_page_state(pgdat, NR_WRITEBACK);

	return nr_pages <= limit;
}

#ifdef CONFIG_SYSCTL
static int dirty_background_ratio_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		dirty_background_bytes = 0;
	return ret;
}

static int dirty_background_bytes_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		dirty_background_ratio = 0;
	return ret;
}

static int dirty_ratio_handler(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	int old_ratio = vm_dirty_ratio;
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write && vm_dirty_ratio != old_ratio) {
		writeback_set_ratelimit();
		vm_dirty_bytes = 0;
	}
	return ret;
}

static int dirty_bytes_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned long old_bytes = vm_dirty_bytes;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write && vm_dirty_bytes != old_bytes) {
		writeback_set_ratelimit();
		vm_dirty_ratio = 0;
	}
	return ret;
}
#endif

static unsigned long wp_next_time(unsigned long cur_time)
{
	cur_time += VM_COMPLETIONS_PERIOD_LEN;
	/* 0 has a special meaning... */
	if (!cur_time)
		return 1;
	return cur_time;
}

static void wb_domain_writeout_add(struct wb_domain *dom,
				   struct fprop_local_percpu *completions,
				   unsigned int max_prop_frac, long nr)
{
	__fprop_add_percpu_max(&dom->completions, completions,
			       max_prop_frac, nr);
	/* First event after period switching was turned off? */
	if (unlikely(!dom->period_time)) {
		/*
		 * We can race with other __bdi_writeout_inc calls here but
		 * it does not cause any harm since the resulting time when
		 * timer will fire and what is in writeout_period_time will be
		 * roughly the same.
		 */
		dom->period_time = wp_next_time(jiffies);
		mod_timer(&dom->period_timer, dom->period_time);
	}
}

/*
 * Increment @wb's writeout completion count and the global writeout
 * completion count. Called from __folio_end_writeback().
   增加这个wb的写回完成计数和全局写回完成计数。从__folio_end_writeback()调用。
 */
static inline void __wb_writeout_add(struct bdi_writeback *wb, long nr)
{
	struct wb_domain *cgdom;

	wb_stat_mod(wb, WB_WRITTEN, nr);
	wb_domain_writeout_add(&global_wb_domain, &wb->completions,
			       wb->bdi->max_prop_frac, nr);

	cgdom = mem_cgroup_wb_domain(wb);
	if (cgdom)
		wb_domain_writeout_add(cgdom, wb_memcg_completions(wb),
				       wb->bdi->max_prop_frac, nr);
}

void wb_writeout_inc(struct bdi_writeback *wb)
{
	unsigned long flags;

	local_irq_save(flags);
	__wb_writeout_add(wb, 1);
	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(wb_writeout_inc);

/*
 * On idle system, we can be called long after we scheduled because we use
 * deferred timers so count with missed periods.
 */
static void writeout_period(struct timer_list *t)
{
	struct wb_domain *dom = from_timer(dom, t, period_timer);
	int miss_periods = (jiffies - dom->period_time) /
						 VM_COMPLETIONS_PERIOD_LEN;

	if (fprop_new_period(&dom->completions, miss_periods + 1)) {
		dom->period_time = wp_next_time(dom->period_time +
				miss_periods * VM_COMPLETIONS_PERIOD_LEN);
		mod_timer(&dom->period_timer, dom->period_time);
	} else {
		/*
		 * Aging has zeroed all fractions. Stop wasting CPU on period
		 * updates.
		 */
		dom->period_time = 0;
	}
}

// 
int wb_domain_init(struct wb_domain *dom, gfp_t gfp)
{
	memset(dom, 0, sizeof(*dom));

	spin_lock_init(&dom->lock);

	timer_setup(&dom->period_timer, writeout_period, TIMER_DEFERRABLE);

	dom->dirty_limit_tstamp = jiffies;

	return fprop_global_init(&dom->completions, gfp);
}

#ifdef CONFIG_CGROUP_WRITEBACK
void wb_domain_exit(struct wb_domain *dom)
{
	del_timer_sync(&dom->period_timer);
	fprop_global_destroy(&dom->completions);
}
#endif

/*
 * bdi_min_ratio keeps the sum of the minimum dirty shares of all
 * registered backing devices, which, for obvious reasons, can not
 * exceed 100%.
 */
static unsigned int bdi_min_ratio;

static int bdi_check_pages_limit(unsigned long pages)
{
	unsigned long max_dirty_pages = global_dirtyable_memory();

	if (pages > max_dirty_pages)
		return -EINVAL;

	return 0;
}

static unsigned long bdi_ratio_from_pages(unsigned long pages)
{
	unsigned long background_thresh;
	unsigned long dirty_thresh;
	unsigned long ratio;

	global_dirty_limits(&background_thresh, &dirty_thresh);
	ratio = div64_u64(pages * 100ULL * BDI_RATIO_SCALE, dirty_thresh);

	return ratio;
}

static u64 bdi_get_bytes(unsigned int ratio)
{
	unsigned long background_thresh;
	unsigned long dirty_thresh;
	u64 bytes;

	global_dirty_limits(&background_thresh, &dirty_thresh);
	bytes = (dirty_thresh * PAGE_SIZE * ratio) / BDI_RATIO_SCALE / 100;

	return bytes;
}

static int __bdi_set_min_ratio(struct backing_dev_info *bdi, unsigned int min_ratio)
{
	unsigned int delta;
	int ret = 0;

	if (min_ratio > 100 * BDI_RATIO_SCALE)
		return -EINVAL;
	min_ratio *= BDI_RATIO_SCALE;

	spin_lock_bh(&bdi_lock);
	if (min_ratio > bdi->max_ratio) {
		ret = -EINVAL;
	} else {
		if (min_ratio < bdi->min_ratio) {
			delta = bdi->min_ratio - min_ratio;
			bdi_min_ratio -= delta;
			bdi->min_ratio = min_ratio;
		} else {
			delta = min_ratio - bdi->min_ratio;
			if (bdi_min_ratio + delta < 100 * BDI_RATIO_SCALE) {
				bdi_min_ratio += delta;
				bdi->min_ratio = min_ratio;
			} else {
				ret = -EINVAL;
			}
		}
	}
	spin_unlock_bh(&bdi_lock);

	return ret;
}

static int __bdi_set_max_ratio(struct backing_dev_info *bdi, unsigned int max_ratio)
{
	int ret = 0;

	if (max_ratio > 100 * BDI_RATIO_SCALE)
		return -EINVAL;

	spin_lock_bh(&bdi_lock);
	if (bdi->min_ratio > max_ratio) {
		ret = -EINVAL;
	} else {
		bdi->max_ratio = max_ratio;
		bdi->max_prop_frac = (FPROP_FRAC_BASE * max_ratio) / 100;
	}
	spin_unlock_bh(&bdi_lock);

	return ret;
}

int bdi_set_min_ratio_no_scale(struct backing_dev_info *bdi, unsigned int min_ratio)
{
	return __bdi_set_min_ratio(bdi, min_ratio);
}

int bdi_set_max_ratio_no_scale(struct backing_dev_info *bdi, unsigned int max_ratio)
{
	return __bdi_set_max_ratio(bdi, max_ratio);
}

int bdi_set_min_ratio(struct backing_dev_info *bdi, unsigned int min_ratio)
{
	return __bdi_set_min_ratio(bdi, min_ratio * BDI_RATIO_SCALE);
}

int bdi_set_max_ratio(struct backing_dev_info *bdi, unsigned int max_ratio)
{
	return __bdi_set_max_ratio(bdi, max_ratio * BDI_RATIO_SCALE);
}
EXPORT_SYMBOL(bdi_set_max_ratio);

u64 bdi_get_min_bytes(struct backing_dev_info *bdi)
{
	return bdi_get_bytes(bdi->min_ratio);
}

int bdi_set_min_bytes(struct backing_dev_info *bdi, u64 min_bytes)
{
	int ret;
	unsigned long pages = min_bytes >> PAGE_SHIFT;
	unsigned long min_ratio;

	ret = bdi_check_pages_limit(pages);
	if (ret)
		return ret;

	min_ratio = bdi_ratio_from_pages(pages);
	return __bdi_set_min_ratio(bdi, min_ratio);
}

u64 bdi_get_max_bytes(struct backing_dev_info *bdi)
{
	return bdi_get_bytes(bdi->max_ratio);
}

int bdi_set_max_bytes(struct backing_dev_info *bdi, u64 max_bytes)
{
	int ret;
	unsigned long pages = max_bytes >> PAGE_SHIFT;
	unsigned long max_ratio;

	ret = bdi_check_pages_limit(pages);
	if (ret)
		return ret;

	max_ratio = bdi_ratio_from_pages(pages);
	return __bdi_set_max_ratio(bdi, max_ratio);
}

int bdi_set_strict_limit(struct backing_dev_info *bdi, unsigned int strict_limit)
{
	if (strict_limit > 1)
		return -EINVAL;

	spin_lock_bh(&bdi_lock);
	if (strict_limit)
		bdi->capabilities |= BDI_CAP_STRICTLIMIT;
	else
		bdi->capabilities &= ~BDI_CAP_STRICTLIMIT;
	spin_unlock_bh(&bdi_lock);

	return 0;
}

static unsigned long dirty_freerun_ceiling(unsigned long thresh,
					   unsigned long bg_thresh)
{
	return (thresh + bg_thresh) / 2;
}

static unsigned long hard_dirty_limit(struct wb_domain *dom,
				      unsigned long thresh)
{
	return max(thresh, dom->dirty_limit);
}

/*
 * Memory which can be further allocated to a memcg domain is capped by
 * system-wide clean memory excluding the amount being used in the domain.
 */
static void mdtc_calc_avail(struct dirty_throttle_control *mdtc,
			    unsigned long filepages, unsigned long headroom)
{
	struct dirty_throttle_control *gdtc = mdtc_gdtc(mdtc);
	unsigned long clean = filepages - min(filepages, mdtc->dirty);
	unsigned long global_clean = gdtc->avail - min(gdtc->avail, gdtc->dirty);
	unsigned long other_clean = global_clean - min(global_clean, clean);

	mdtc->avail = filepages + min(headroom, other_clean);
}

/**
 * __wb_calc_thresh - @wb's share of dirty throttling threshold
 * @dtc: dirty_throttle_context of interest
 *
 * Note that balance_dirty_pages() will only seriously take it as a hard limit
 * when sleeping max_pause per page is not enough to keep the dirty pages under
 * control. For example, when the device is completely stalled due to some error
 * conditions, or when there are 1000 dd tasks writing to a slow 10MB/s USB key.
 * In the other normal situations, it acts more gently by throttling the tasks
 * more (rather than completely block them) when the wb dirty pages go high.
 *
 * It allocates high/low dirty limits to fast/slow devices, in order to prevent
 * - starving fast devices
 * - piling up dirty pages (that will take long time to sync) on slow devices
 *
 * The wb's share of dirty limit will be adapting to its throughput and
 * bounded by the bdi->min_ratio and/or bdi->max_ratio parameters, if set.
 *
 * Return: @wb's dirty limit in pages. The term "dirty" in the context of
 * dirty balancing includes all PG_dirty and PG_writeback pages.
 */
static unsigned long __wb_calc_thresh(struct dirty_throttle_control *dtc)
{
	struct wb_domain *dom = dtc_dom(dtc);
	unsigned long thresh = dtc->thresh;
	u64 wb_thresh;
	unsigned long numerator, denominator;
	unsigned long wb_min_ratio, wb_max_ratio;

	/*
	 * Calculate this BDI's share of the thresh ratio.
	 */
	fprop_fraction_percpu(&dom->completions, dtc->wb_completions,
			      &numerator, &denominator);

	wb_thresh = (thresh * (100 * BDI_RATIO_SCALE - bdi_min_ratio)) / (100 * BDI_RATIO_SCALE);
	wb_thresh *= numerator;
	wb_thresh = div64_ul(wb_thresh, denominator);

	wb_min_max_ratio(dtc->wb, &wb_min_ratio, &wb_max_ratio);

	wb_thresh += (thresh * wb_min_ratio) / (100 * BDI_RATIO_SCALE);
	if (wb_thresh > (thresh * wb_max_ratio) / (100 * BDI_RATIO_SCALE))
		wb_thresh = thresh * wb_max_ratio / (100 * BDI_RATIO_SCALE);

	return wb_thresh;
}

unsigned long wb_calc_thresh(struct bdi_writeback *wb, unsigned long thresh)
{
	struct dirty_throttle_control gdtc = { GDTC_INIT(wb),
					       .thresh = thresh };
	return __wb_calc_thresh(&gdtc);
}

/*
 *                           setpoint - dirty 3
 *        f(dirty) := 1.0 + (----------------)
 *                           limit - setpoint
 *
 * it's a 3rd order polynomial that subjects to
 *
 * (1) f(freerun)  = 2.0 => rampup dirty_ratelimit reasonably fast
 * (2) f(setpoint) = 1.0 => the balance point
 * (3) f(limit)    = 0   => the hard limit
 * (4) df/dx      <= 0	 => negative feedback control
 * (5) the closer to setpoint, the smaller |df/dx| (and the reverse)
 *     => fast response on large errors; small oscillation near setpoint
 */
static long long pos_ratio_polynom(unsigned long setpoint,
					  unsigned long dirty,
					  unsigned long limit)
{
	long long pos_ratio;
	long x;

	x = div64_s64(((s64)setpoint - (s64)dirty) << RATELIMIT_CALC_SHIFT,
		      (limit - setpoint) | 1);
	pos_ratio = x;
	pos_ratio = pos_ratio * x >> RATELIMIT_CALC_SHIFT;
	pos_ratio = pos_ratio * x >> RATELIMIT_CALC_SHIFT;
	pos_ratio += 1 << RATELIMIT_CALC_SHIFT;

	return clamp(pos_ratio, 0LL, 2LL << RATELIMIT_CALC_SHIFT);
}

/*
 * Dirty position control.
 *
 * (o) global/bdi setpoints
 *
 * We want the dirty pages be balanced around the global/wb setpoints.
 * When the number of dirty pages is higher/lower than the setpoint, the
 * dirty position control ratio (and hence task dirty ratelimit) will be
 * decreased/increased to bring the dirty pages back to the setpoint.
 *
 *     pos_ratio = 1 << RATELIMIT_CALC_SHIFT
 *
 *     if (dirty < setpoint) scale up   pos_ratio
 *     if (dirty > setpoint) scale down pos_ratio
 *
 *     if (wb_dirty < wb_setpoint) scale up   pos_ratio
 *     if (wb_dirty > wb_setpoint) scale down pos_ratio
 *
 *     task_ratelimit = dirty_ratelimit * pos_ratio >> RATELIMIT_CALC_SHIFT
 *
 * (o) global control line
 *
 *     ^ pos_ratio
 *     |
 *     |            |<===== global dirty control scope ======>|
 * 2.0  * * * * * * *
 *     |            .*
 *     |            . *
 *     |            .   *
 *     |            .     *
 *     |            .        *
 *     |            .            *
 * 1.0 ................................*
 *     |            .                  .     *
 *     |            .                  .          *
 *     |            .                  .              *
 *     |            .                  .                 *
 *     |            .                  .                    *
 *   0 +------------.------------------.----------------------*------------->
 *           freerun^          setpoint^                 limit^   dirty pages
 *
 * (o) wb control line
 *
 *     ^ pos_ratio
 *     |
 *     |            *
 *     |              *
 *     |                *
 *     |                  *
 *     |                    * |<=========== span ============>|
 * 1.0 .......................*
 *     |                      . *
 *     |                      .   *
 *     |                      .     *
 *     |                      .       *
 *     |                      .         *
 *     |                      .           *
 *     |                      .             *
 *     |                      .               *
 *     |                      .                 *
 *     |                      .                   *
 *     |                      .                     *
 * 1/4 ...............................................* * * * * * * * * * * *
 *     |                      .                         .
 *     |                      .                           .
 *     |                      .                             .
 *   0 +----------------------.-------------------------------.------------->
 *                wb_setpoint^                    x_intercept^
 *
 * The wb control line won't drop below pos_ratio=1/4, so that wb_dirty can
 * be smoothly throttled down to normal if it starts high in situations like
 * - start writing to a slow SD card and a fast disk at the same time. The SD
 *   card's wb_dirty may rush to many times higher than wb_setpoint.
 * - the wb dirty thresh drops quickly due to change of JBOD workload
 */
static void wb_position_ratio(struct dirty_throttle_control *dtc)
{
	struct bdi_writeback *wb = dtc->wb;
	unsigned long write_bw = READ_ONCE(wb->avg_write_bandwidth);
	unsigned long freerun = dirty_freerun_ceiling(dtc->thresh, dtc->bg_thresh);
	unsigned long limit = hard_dirty_limit(dtc_dom(dtc), dtc->thresh);
	unsigned long wb_thresh = dtc->wb_thresh;
	unsigned long x_intercept;
	unsigned long setpoint;		/* dirty pages' target balance point */
	unsigned long wb_setpoint;
	unsigned long span;
	long long pos_ratio;		/* for scaling up/down the rate limit */
	long x;

	dtc->pos_ratio = 0;

	if (unlikely(dtc->dirty >= limit))
		return;

	/*
	 * global setpoint
	 *
	 * See comment for pos_ratio_polynom().
	 */
	setpoint = (freerun + limit) / 2;
	pos_ratio = pos_ratio_polynom(setpoint, dtc->dirty, limit);

	/*
	 * The strictlimit feature is a tool preventing mistrusted filesystems
	 * from growing a large number of dirty pages before throttling. For
	 * such filesystems balance_dirty_pages always checks wb counters
	 * against wb limits. Even if global "nr_dirty" is under "freerun".
	 * This is especially important for fuse which sets bdi->max_ratio to
	 * 1% by default. Without strictlimit feature, fuse writeback may
	 * consume arbitrary amount of RAM because it is accounted in
	 * NR_WRITEBACK_TEMP which is not involved in calculating "nr_dirty".
	 *
	 * Here, in wb_position_ratio(), we calculate pos_ratio based on
	 * two values: wb_dirty and wb_thresh. Let's consider an example:
	 * total amount of RAM is 16GB, bdi->max_ratio is equal to 1%, global
	 * limits are set by default to 10% and 20% (background and throttle).
	 * Then wb_thresh is 1% of 20% of 16GB. This amounts to ~8K pages.
	 * wb_calc_thresh(wb, bg_thresh) is about ~4K pages. wb_setpoint is
	 * about ~6K pages (as the average of background and throttle wb
	 * limits). The 3rd order polynomial will provide positive feedback if
	 * wb_dirty is under wb_setpoint and vice versa.
	 *
	 * Note, that we cannot use global counters in these calculations
	 * because we want to throttle process writing to a strictlimit wb
	 * much earlier than global "freerun" is reached (~23MB vs. ~2.3GB
	 * in the example above).
	 */
	if (unlikely(wb->bdi->capabilities & BDI_CAP_STRICTLIMIT)) {
		long long wb_pos_ratio;

		if (dtc->wb_dirty < 8) {
			dtc->pos_ratio = min_t(long long, pos_ratio * 2,
					   2 << RATELIMIT_CALC_SHIFT);
			return;
		}

		if (dtc->wb_dirty >= wb_thresh)
			return;

		wb_setpoint = dirty_freerun_ceiling(wb_thresh,
						    dtc->wb_bg_thresh);

		if (wb_setpoint == 0 || wb_setpoint == wb_thresh)
			return;

		wb_pos_ratio = pos_ratio_polynom(wb_setpoint, dtc->wb_dirty,
						 wb_thresh);

		/*
		 * Typically, for strictlimit case, wb_setpoint << setpoint
		 * and pos_ratio >> wb_pos_ratio. In the other words global
		 * state ("dirty") is not limiting factor and we have to
		 * make decision based on wb counters. But there is an
		 * important case when global pos_ratio should get precedence:
		 * global limits are exceeded (e.g. due to activities on other
		 * wb's) while given strictlimit wb is below limit.
		 *
		 * "pos_ratio * wb_pos_ratio" would work for the case above,
		 * but it would look too non-natural for the case of all
		 * activity in the system coming from a single strictlimit wb
		 * with bdi->max_ratio == 100%.
		 *
		 * Note that min() below somewhat changes the dynamics of the
		 * control system. Normally, pos_ratio value can be well over 3
		 * (when globally we are at freerun and wb is well below wb
		 * setpoint). Now the maximum pos_ratio in the same situation
		 * is 2. We might want to tweak this if we observe the control
		 * system is too slow to adapt.
		 */
		dtc->pos_ratio = min(pos_ratio, wb_pos_ratio);
		return;
	}

	/*
	 * We have computed basic pos_ratio above based on global situation. If
	 * the wb is over/under its share of dirty pages, we want to scale
	 * pos_ratio further down/up. That is done by the following mechanism.
	 */

	/*
	 * wb setpoint
	 *
	 *        f(wb_dirty) := 1.0 + k * (wb_dirty - wb_setpoint)
	 *
	 *                        x_intercept - wb_dirty
	 *                     := --------------------------
	 *                        x_intercept - wb_setpoint
	 *
	 * The main wb control line is a linear function that subjects to
	 *
	 * (1) f(wb_setpoint) = 1.0
	 * (2) k = - 1 / (8 * write_bw)  (in single wb case)
	 *     or equally: x_intercept = wb_setpoint + 8 * write_bw
	 *
	 * For single wb case, the dirty pages are observed to fluctuate
	 * regularly within range
	 *        [wb_setpoint - write_bw/2, wb_setpoint + write_bw/2]
	 * for various filesystems, where (2) can yield in a reasonable 12.5%
	 * fluctuation range for pos_ratio.
	 *
	 * For JBOD case, wb_thresh (not wb_dirty!) could fluctuate up to its
	 * own size, so move the slope over accordingly and choose a slope that
	 * yields 100% pos_ratio fluctuation on suddenly doubled wb_thresh.
	 */
	if (unlikely(wb_thresh > dtc->thresh))
		wb_thresh = dtc->thresh;
	/*
	 * It's very possible that wb_thresh is close to 0 not because the
	 * device is slow, but that it has remained inactive for long time.
	 * Honour such devices a reasonable good (hopefully IO efficient)
	 * threshold, so that the occasional writes won't be blocked and active
	 * writes can rampup the threshold quickly.
	 */
	wb_thresh = max(wb_thresh, (limit - dtc->dirty) / 8);
	/*
	 * scale global setpoint to wb's:
	 *	wb_setpoint = setpoint * wb_thresh / thresh
	 */
	x = div_u64((u64)wb_thresh << 16, dtc->thresh | 1);
	wb_setpoint = setpoint * (u64)x >> 16;
	/*
	 * Use span=(8*write_bw) in single wb case as indicated by
	 * (thresh - wb_thresh ~= 0) and transit to wb_thresh in JBOD case.
	 *
	 *        wb_thresh                    thresh - wb_thresh
	 * span = --------- * (8 * write_bw) + ------------------ * wb_thresh
	 *         thresh                           thresh
	 */
	span = (dtc->thresh - wb_thresh + 8 * write_bw) * (u64)x >> 16;
	x_intercept = wb_setpoint + span;

	if (dtc->wb_dirty < x_intercept - span / 4) {
		pos_ratio = div64_u64(pos_ratio * (x_intercept - dtc->wb_dirty),
				      (x_intercept - wb_setpoint) | 1);
	} else
		pos_ratio /= 4;

	/*
	 * wb reserve area, safeguard against dirty pool underrun and disk idle
	 * It may push the desired control point of global dirty pages higher
	 * than setpoint.
	 */
	x_intercept = wb_thresh / 2;
	if (dtc->wb_dirty < x_intercept) {
		if (dtc->wb_dirty > x_intercept / 8)
			pos_ratio = div_u64(pos_ratio * x_intercept,
					    dtc->wb_dirty);
		else
			pos_ratio *= 8;
	}

	dtc->pos_ratio = pos_ratio;
}

static void wb_update_write_bandwidth(struct bdi_writeback *wb,
				      unsigned long elapsed,
				      unsigned long written)
{
	const unsigned long period = roundup_pow_of_two(3 * HZ);
	unsigned long avg = wb->avg_write_bandwidth;
	unsigned long old = wb->write_bandwidth;
	u64 bw;

	/*
	 * bw = written * HZ / elapsed
	 *
	 *                   bw * elapsed + write_bandwidth * (period - elapsed)
	 * write_bandwidth = ---------------------------------------------------
	 *                                          period
	 *
	 * @written may have decreased due to folio_redirty_for_writepage().
	 * Avoid underflowing @bw calculation.
	 */
	bw = written - min(written, wb->written_stamp);
	bw *= HZ;
	if (unlikely(elapsed > period)) {
		bw = div64_ul(bw, elapsed);
		avg = bw;
		goto out;
	}
	bw += (u64)wb->write_bandwidth * (period - elapsed);
	bw >>= ilog2(period);

	/*
	 * one more level of smoothing, for filtering out sudden spikes
	 */
	if (avg > old && old >= (unsigned long)bw)
		avg -= (avg - old) >> 3;

	if (avg < old && old <= (unsigned long)bw)
		avg += (old - avg) >> 3;

out:
	/* keep avg > 0 to guarantee that tot > 0 if there are dirty wbs */
	avg = max(avg, 1LU);
	if (wb_has_dirty_io(wb)) {
		long delta = avg - wb->avg_write_bandwidth;
		WARN_ON_ONCE(atomic_long_add_return(delta,
					&wb->bdi->tot_write_bandwidth) <= 0);
	}
	wb->write_bandwidth = bw;
	WRITE_ONCE(wb->avg_write_bandwidth, avg);
}

static void update_dirty_limit(struct dirty_throttle_control *dtc)
{
	struct wb_domain *dom = dtc_dom(dtc);
	unsigned long thresh = dtc->thresh;
	unsigned long limit = dom->dirty_limit;

	/*
	 * Follow up in one step.
	 */
	if (limit < thresh) {
		limit = thresh;
		goto update;
	}

	/*
	 * Follow down slowly. Use the higher one as the target, because thresh
	 * may drop below dirty. This is exactly the reason to introduce
	 * dom->dirty_limit which is guaranteed to lie above the dirty pages.
	 */
	thresh = max(thresh, dtc->dirty);
	if (limit > thresh) {
		limit -= (limit - thresh) >> 5;
		goto update;
	}
	return;
update:
	dom->dirty_limit = limit;
}

static void domain_update_dirty_limit(struct dirty_throttle_control *dtc,
				      unsigned long now)
{
	struct wb_domain *dom = dtc_dom(dtc);

	/*
	 * check locklessly first to optimize away locking for the most time
	 */
	if (time_before(now, dom->dirty_limit_tstamp + BANDWIDTH_INTERVAL))
		return;

	spin_lock(&dom->lock);
	if (time_after_eq(now, dom->dirty_limit_tstamp + BANDWIDTH_INTERVAL)) {
		update_dirty_limit(dtc);
		dom->dirty_limit_tstamp = now;
	}
	spin_unlock(&dom->lock);
}

/*
 * Maintain wb->dirty_ratelimit, the base dirty throttle rate.
 *
 * Normal wb tasks will be curbed at or below it in long term.
 * Obviously it should be around (write_bw / N) when there are N dd tasks.
 */
static void wb_update_dirty_ratelimit(struct dirty_throttle_control *dtc,
				      unsigned long dirtied,
				      unsigned long elapsed)
{
	struct bdi_writeback *wb = dtc->wb;
	unsigned long dirty = dtc->dirty;
	unsigned long freerun = dirty_freerun_ceiling(dtc->thresh, dtc->bg_thresh);
	unsigned long limit = hard_dirty_limit(dtc_dom(dtc), dtc->thresh);
	unsigned long setpoint = (freerun + limit) / 2;
	unsigned long write_bw = wb->avg_write_bandwidth;
	unsigned long dirty_ratelimit = wb->dirty_ratelimit;
	unsigned long dirty_rate;
	unsigned long task_ratelimit;
	unsigned long balanced_dirty_ratelimit;
	unsigned long step;
	unsigned long x;
	unsigned long shift;

	/*
	 * The dirty rate will match the writeout rate in long term, except
	 * when dirty pages are truncated by userspace or re-dirtied by FS.
	 */
	dirty_rate = (dirtied - wb->dirtied_stamp) * HZ / elapsed;

	/*
	 * task_ratelimit reflects each dd's dirty rate for the past 200ms.
	 */
	task_ratelimit = (u64)dirty_ratelimit *
					dtc->pos_ratio >> RATELIMIT_CALC_SHIFT;
	task_ratelimit++; /* it helps rampup dirty_ratelimit from tiny values */

	/*
	 * A linear estimation of the "balanced" throttle rate. The theory is,
	 * if there are N dd tasks, each throttled at task_ratelimit, the wb's
	 * dirty_rate will be measured to be (N * task_ratelimit). So the below
	 * formula will yield the balanced rate limit (write_bw / N).
	 *
	 * Note that the expanded form is not a pure rate feedback:
	 *	rate_(i+1) = rate_(i) * (write_bw / dirty_rate)		     (1)
	 * but also takes pos_ratio into account:
	 *	rate_(i+1) = rate_(i) * (write_bw / dirty_rate) * pos_ratio  (2)
	 *
	 * (1) is not realistic because pos_ratio also takes part in balancing
	 * the dirty rate.  Consider the state
	 *	pos_ratio = 0.5						     (3)
	 *	rate = 2 * (write_bw / N)				     (4)
	 * If (1) is used, it will stuck in that state! Because each dd will
	 * be throttled at
	 *	task_ratelimit = pos_ratio * rate = (write_bw / N)	     (5)
	 * yielding
	 *	dirty_rate = N * task_ratelimit = write_bw		     (6)
	 * put (6) into (1) we get
	 *	rate_(i+1) = rate_(i)					     (7)
	 *
	 * So we end up using (2) to always keep
	 *	rate_(i+1) ~= (write_bw / N)				     (8)
	 * regardless of the value of pos_ratio. As long as (8) is satisfied,
	 * pos_ratio is able to drive itself to 1.0, which is not only where
	 * the dirty count meet the setpoint, but also where the slope of
	 * pos_ratio is most flat and hence task_ratelimit is least fluctuated.
	 */
	balanced_dirty_ratelimit = div_u64((u64)task_ratelimit * write_bw,
					   dirty_rate | 1);
	/*
	 * balanced_dirty_ratelimit ~= (write_bw / N) <= write_bw
	 */
	if (unlikely(balanced_dirty_ratelimit > write_bw))
		balanced_dirty_ratelimit = write_bw;

	/*
	 * We could safely do this and return immediately:
	 *
	 *	wb->dirty_ratelimit = balanced_dirty_ratelimit;
	 *
	 * However to get a more stable dirty_ratelimit, the below elaborated
	 * code makes use of task_ratelimit to filter out singular points and
	 * limit the step size.
	 *
	 * The below code essentially only uses the relative value of
	 *
	 *	task_ratelimit - dirty_ratelimit
	 *	= (pos_ratio - 1) * dirty_ratelimit
	 *
	 * which reflects the direction and size of dirty position error.
	 */

	/*
	 * dirty_ratelimit will follow balanced_dirty_ratelimit iff
	 * task_ratelimit is on the same side of dirty_ratelimit, too.
	 * For example, when
	 * - dirty_ratelimit > balanced_dirty_ratelimit
	 * - dirty_ratelimit > task_ratelimit (dirty pages are above setpoint)
	 * lowering dirty_ratelimit will help meet both the position and rate
	 * control targets. Otherwise, don't update dirty_ratelimit if it will
	 * only help meet the rate target. After all, what the users ultimately
	 * feel and care are stable dirty rate and small position error.
	 *
	 * |task_ratelimit - dirty_ratelimit| is used to limit the step size
	 * and filter out the singular points of balanced_dirty_ratelimit. Which
	 * keeps jumping around randomly and can even leap far away at times
	 * due to the small 200ms estimation period of dirty_rate (we want to
	 * keep that period small to reduce time lags).
	 */
	step = 0;

	/*
	 * For strictlimit case, calculations above were based on wb counters
	 * and limits (starting from pos_ratio = wb_position_ratio() and up to
	 * balanced_dirty_ratelimit = task_ratelimit * write_bw / dirty_rate).
	 * Hence, to calculate "step" properly, we have to use wb_dirty as
	 * "dirty" and wb_setpoint as "setpoint".
	 *
	 * We rampup dirty_ratelimit forcibly if wb_dirty is low because
	 * it's possible that wb_thresh is close to zero due to inactivity
	 * of backing device.
	 */
	if (unlikely(wb->bdi->capabilities & BDI_CAP_STRICTLIMIT)) {
		dirty = dtc->wb_dirty;
		if (dtc->wb_dirty < 8)
			setpoint = dtc->wb_dirty + 1;
		else
			setpoint = (dtc->wb_thresh + dtc->wb_bg_thresh) / 2;
	}

	if (dirty < setpoint) {
		x = min3(wb->balanced_dirty_ratelimit,
			 balanced_dirty_ratelimit, task_ratelimit);
		if (dirty_ratelimit < x)
			step = x - dirty_ratelimit;
	} else {
		x = max3(wb->balanced_dirty_ratelimit,
			 balanced_dirty_ratelimit, task_ratelimit);
		if (dirty_ratelimit > x)
			step = dirty_ratelimit - x;
	}

	/*
	 * Don't pursue 100% rate matching. It's impossible since the balanced
	 * rate itself is constantly fluctuating. So decrease the track speed
	 * when it gets close to the target. Helps eliminate pointless tremors.
	 */
	shift = dirty_ratelimit / (2 * step + 1);
	if (shift < BITS_PER_LONG)
		step = DIV_ROUND_UP(step >> shift, 8);
	else
		step = 0;

	if (dirty_ratelimit < balanced_dirty_ratelimit)
		dirty_ratelimit += step;
	else
		dirty_ratelimit -= step;

	WRITE_ONCE(wb->dirty_ratelimit, max(dirty_ratelimit, 1UL));
	wb->balanced_dirty_ratelimit = balanced_dirty_ratelimit;

	trace_bdi_dirty_ratelimit(wb, dirty_rate, task_ratelimit);
}

static void __wb_update_bandwidth(struct dirty_throttle_control *gdtc,
				  struct dirty_throttle_control *mdtc,
				  bool update_ratelimit)
{
	struct bdi_writeback *wb = gdtc->wb;
	unsigned long now = jiffies;
	unsigned long elapsed;
	unsigned long dirtied;
	unsigned long written;

	spin_lock(&wb->list_lock);

	/*
	 * Lockless checks for elapsed time are racy and delayed update after
	 * IO completion doesn't do it at all (to make sure written pages are
	 * accounted reasonably quickly). Make sure elapsed >= 1 to avoid
	 * division errors.
	 */
	elapsed = max(now - wb->bw_time_stamp, 1UL);
	dirtied = percpu_counter_read(&wb->stat[WB_DIRTIED]);
	written = percpu_counter_read(&wb->stat[WB_WRITTEN]);

	if (update_ratelimit) {
		domain_update_dirty_limit(gdtc, now);
		wb_update_dirty_ratelimit(gdtc, dirtied, elapsed);

		/*
		 * @mdtc is always NULL if !CGROUP_WRITEBACK but the
		 * compiler has no way to figure that out.  Help it.
		 */
		if (IS_ENABLED(CONFIG_CGROUP_WRITEBACK) && mdtc) {
			domain_update_dirty_limit(mdtc, now);
			wb_update_dirty_ratelimit(mdtc, dirtied, elapsed);
		}
	}
	wb_update_write_bandwidth(wb, elapsed, written);

	wb->dirtied_stamp = dirtied;
	wb->written_stamp = written;
	WRITE_ONCE(wb->bw_time_stamp, now);
	spin_unlock(&wb->list_lock);
}

//更新wb的带宽
void wb_update_bandwidth(struct bdi_writeback *wb)
{
	struct dirty_throttle_control gdtc = { GDTC_INIT(wb) };

	__wb_update_bandwidth(&gdtc, NULL, false);
}

/* Interval after which we consider wb idle and don't estimate bandwidth */
#define WB_BANDWIDTH_IDLE_JIF (HZ)

static void wb_bandwidth_estimate_start(struct bdi_writeback *wb)
{
	unsigned long now = jiffies;
	unsigned long elapsed = now - READ_ONCE(wb->bw_time_stamp);

	if (elapsed > WB_BANDWIDTH_IDLE_JIF &&
	    !atomic_read(&wb->writeback_inodes)) {
		spin_lock(&wb->list_lock);
		wb->dirtied_stamp = wb_stat(wb, WB_DIRTIED);
		wb->written_stamp = wb_stat(wb, WB_WRITTEN);
		WRITE_ONCE(wb->bw_time_stamp, now);
		spin_unlock(&wb->list_lock);
	}
}

/*
 * After a task dirtied this many pages, balance_dirty_pages_ratelimited()
 * will look to see if it needs to start dirty throttling.
 * 在一个任务脏了这么多页之后，balance_dirty_pages_ratelimited()将查看是否需要开始脏限制。
 
 * If dirty_poll_interval is too low, big NUMA machines will call the expensive
 * global_zone_page_state() too often. So scale it near-sqrt to the safety margin
 * (the number of pages we may dirty without exceeding the dirty limits).
 如果dirty_poll_interval太低，大型NUMA机器将频繁调用昂贵的global_zone_page_state()。
 因此，将其缩放到接近sqrt以确保安全边际（我们可以脏的页面数不超过脏限制）。
 */
static unsigned long dirty_poll_interval(unsigned long dirty,
					 unsigned long thresh)
{
	if (thresh > dirty)
		return 1UL << (ilog2(thresh - dirty) >> 1);

	return 1;
}

static unsigned long wb_max_pause(struct bdi_writeback *wb,
				  unsigned long wb_dirty)
{
	unsigned long bw = READ_ONCE(wb->avg_write_bandwidth);
	unsigned long t;

	/*
	 * Limit pause time for small memory systems. If sleeping for too long
	 * time, a small pool of dirty/writeback pages may go empty and disk go
	 * idle.
	 *
	 * 8 serves as the safety ratio.
	 */
	t = wb_dirty / (1 + bw / roundup_pow_of_two(1 + HZ / 8));
	t++;

	return min_t(unsigned long, t, MAX_PAUSE);
}

static long wb_min_pause(struct bdi_writeback *wb,
			 long max_pause,
			 unsigned long task_ratelimit,
			 unsigned long dirty_ratelimit,
			 int *nr_dirtied_pause)
{
	long hi = ilog2(READ_ONCE(wb->avg_write_bandwidth));
	long lo = ilog2(READ_ONCE(wb->dirty_ratelimit));
	long t;		/* target pause */
	long pause;	/* estimated next pause */
	int pages;	/* target nr_dirtied_pause */

	/* target for 10ms pause on 1-dd case */
	t = max(1, HZ / 100);

	/*
	 * Scale up pause time for concurrent dirtiers in order to reduce CPU
	 * overheads.
	 *
	 * (N * 10ms) on 2^N concurrent tasks.
	 */
	if (hi > lo)
		t += (hi - lo) * (10 * HZ) / 1024;

	/*
	 * This is a bit convoluted. We try to base the next nr_dirtied_pause
	 * on the much more stable dirty_ratelimit. However the next pause time
	 * will be computed based on task_ratelimit and the two rate limits may
	 * depart considerably at some time. Especially if task_ratelimit goes
	 * below dirty_ratelimit/2 and the target pause is max_pause, the next
	 * pause time will be max_pause*2 _trimmed down_ to max_pause.  As a
	 * result task_ratelimit won't be executed faithfully, which could
	 * eventually bring down dirty_ratelimit.
	 *
	 * We apply two rules to fix it up:
	 * 1) try to estimate the next pause time and if necessary, use a lower
	 *    nr_dirtied_pause so as not to exceed max_pause. When this happens,
	 *    nr_dirtied_pause will be "dancing" with task_ratelimit.
	 * 2) limit the target pause time to max_pause/2, so that the normal
	 *    small fluctuations of task_ratelimit won't trigger rule (1) and
	 *    nr_dirtied_pause will remain as stable as dirty_ratelimit.
	 */
	t = min(t, 1 + max_pause / 2);
	pages = dirty_ratelimit * t / roundup_pow_of_two(HZ);

	/*
	 * Tiny nr_dirtied_pause is found to hurt I/O performance in the test
	 * case fio-mmap-randwrite-64k, which does 16*{sync read, async write}.
	 * When the 16 consecutive reads are often interrupted by some dirty
	 * throttling pause during the async writes, cfq will go into idles
	 * (deadline is fine). So push nr_dirtied_pause as high as possible
	 * until reaches DIRTY_POLL_THRESH=32 pages.
	 */
	if (pages < DIRTY_POLL_THRESH) {
		t = max_pause;
		pages = dirty_ratelimit * t / roundup_pow_of_two(HZ);
		if (pages > DIRTY_POLL_THRESH) {
			pages = DIRTY_POLL_THRESH;
			t = HZ * DIRTY_POLL_THRESH / dirty_ratelimit;
		}
	}

	pause = HZ * pages / (task_ratelimit + 1);
	if (pause > max_pause) {
		t = max_pause;
		pages = task_ratelimit * t / roundup_pow_of_two(HZ);
	}

	*nr_dirtied_pause = pages;
	/*
	 * The minimal pause time will normally be half the target pause time.
	 */
	return pages >= DIRTY_POLL_THRESH ? 1 + t / 2 : t;
}

static inline void wb_dirty_limits(struct dirty_throttle_control *dtc)
{
	struct bdi_writeback *wb = dtc->wb;
	unsigned long wb_reclaimable;

	/*
	 * wb_thresh is not treated as some limiting factor as
	 * dirty_thresh, due to reasons
	 * - in JBOD setup, wb_thresh can fluctuate a lot
	 * - in a system with HDD and USB key, the USB key may somehow
	 *   go into state (wb_dirty >> wb_thresh) either because
	 *   wb_dirty starts high, or because wb_thresh drops low.
	 *   In this case we don't want to hard throttle the USB key
	 *   dirtiers for 100 seconds until wb_dirty drops under
	 *   wb_thresh. Instead the auxiliary wb control line in
	 *   wb_position_ratio() will let the dirtier task progress
	 *   at some rate <= (write_bw / 2) for bringing down wb_dirty.
	 */
	dtc->wb_thresh = __wb_calc_thresh(dtc);
	dtc->wb_bg_thresh = dtc->thresh ?
		div_u64((u64)dtc->wb_thresh * dtc->bg_thresh, dtc->thresh) : 0;

	/*
	 * In order to avoid the stacked BDI deadlock we need
	 * to ensure we accurately count the 'dirty' pages when
	 * the threshold is low.
	 *
	 * Otherwise it would be possible to get thresh+n pages
	 * reported dirty, even though there are thresh-m pages
	 * actually dirty; with m+n sitting in the percpu
	 * deltas.
	 */
	if (dtc->wb_thresh < 2 * wb_stat_error()) {
		wb_reclaimable = wb_stat_sum(wb, WB_RECLAIMABLE);
		dtc->wb_dirty = wb_reclaimable + wb_stat_sum(wb, WB_WRITEBACK);
	} else {
		wb_reclaimable = wb_stat(wb, WB_RECLAIMABLE);
		dtc->wb_dirty = wb_reclaimable + wb_stat(wb, WB_WRITEBACK);
	}
}

/*
   总体来说, 是一个限制脏页生成的函数
 * balance_dirty_pages() must be called by processes which are generating dirty
 * data.  It looks at the number of dirty pages in the machine and will force
 * the caller to wait once crossing the (background_thresh + dirty_thresh) / 2.
 * If we're over `background_thresh' then the writeback threads are woken to
 * perform some writeout.
   函数balance_dirty_pages()必须由正在生成脏数据的进程调用。它查看机器中的脏页数，
   并在越过(background_thresh + dirty_thresh) / 2时强制调用者等待。如果我们超过
   了`background_thresh'，那么唤醒写回线程执行一些写出。
 */
static int balance_dirty_pages(struct bdi_writeback *wb,
			       unsigned long pages_dirtied, unsigned int flags)
{
	struct dirty_throttle_control gdtc_stor = { GDTC_INIT(wb) };
	struct dirty_throttle_control mdtc_stor = { MDTC_INIT(wb, &gdtc_stor) };
	struct dirty_throttle_control * const gdtc = &gdtc_stor;
	struct dirty_throttle_control * const mdtc = mdtc_valid(&mdtc_stor) ?
						     &mdtc_stor : NULL;
	struct dirty_throttle_control *sdtc;
	unsigned long nr_reclaimable;	/* = file_dirty */
	long period;
	long pause;
	long max_pause;
	long min_pause;
	int nr_dirtied_pause;
	bool dirty_exceeded = false;
	unsigned long task_ratelimit;
	unsigned long dirty_ratelimit;
	struct backing_dev_info *bdi = wb->bdi;
	bool strictlimit = bdi->capabilities & BDI_CAP_STRICTLIMIT;
	unsigned long start_time = jiffies;
	int ret = 0;

	for (;;) {
		unsigned long now = jiffies;
		unsigned long dirty, thresh, bg_thresh;
		unsigned long m_dirty = 0;	/* stop bogus uninit warnings */
		unsigned long m_thresh = 0;
		unsigned long m_bg_thresh = 0;

		nr_reclaimable = global_node_page_state(NR_FILE_DIRTY);
		gdtc->avail = global_dirtyable_memory();
		gdtc->dirty = nr_reclaimable + global_node_page_state(NR_WRITEBACK);

		//计算gdtc的thresh和bg_thresh
		domain_dirty_limits(gdtc);

		if (unlikely(strictlimit)) {
			wb_dirty_limits(gdtc);

			dirty = gdtc->wb_dirty;
			thresh = gdtc->wb_thresh;
			bg_thresh = gdtc->wb_bg_thresh;
		} else {
			dirty = gdtc->dirty;
			thresh = gdtc->thresh;
			bg_thresh = gdtc->bg_thresh;
		}
		//上面为了计算出 dirty, thresh, bg_thresh
		if (mdtc) {
			unsigned long filepages, headroom, writeback;

			/*
			 * If @wb belongs to !root memcg, repeat the same
			 * basic calculations for the memcg domain.
			 */
			mem_cgroup_wb_stats(wb, &filepages, &headroom,
					    &mdtc->dirty, &writeback);
			mdtc->dirty += writeback;
			mdtc_calc_avail(mdtc, filepages, headroom);

			domain_dirty_limits(mdtc);

			if (unlikely(strictlimit)) {
				wb_dirty_limits(mdtc);
				m_dirty = mdtc->wb_dirty;
				m_thresh = mdtc->wb_thresh;
				m_bg_thresh = mdtc->wb_bg_thresh;
			} else {
				m_dirty = mdtc->dirty;
				m_thresh = mdtc->thresh;
				m_bg_thresh = mdtc->bg_thresh;
			}
		}

		// 计算出m_dirty, m_thresh, m_bg_thresh

		/*
		 * In laptop mode, we wait until hitting the higher threshold
		 * before starting background writeout, and then write out all
		 * the way down to the lower threshold.  So slow writers cause
		 * minimal disk activity.
		 * 处于笔记本模式时，我们等到达到较高的阈值后才开始后台写出，
		 * 然后一直写到较低的阈值。因此，慢速写入者会导致最小的磁盘活动。
		 
		 * In normal mode, we start background writeout at the lower
		 * background_thresh, to keep the amount of dirty memory low.
		 * 在正常模式下，我们从较低的background_thresh开始后台写出，
		 * 以保持脏内存的数量较低。
		 */
		if (!laptop_mode && nr_reclaimable > gdtc->bg_thresh &&
		    !writeback_in_progress(wb))
			wb_start_background_writeback(wb);

		/*
		 * Throttle it only when the background writeback cannot
		 * catch-up. This avoids (excessively) small writeouts
		 * when the wb limits are ramping up in case of !strictlimit.
		 *
		 * In strictlimit case make decision based on the wb counters
		 * and limits. Small writeouts when the wb limits are ramping
		 * up are the price we consciously pay for strictlimit-ing.
		 *
		 * If memcg domain is in effect, @dirty should be under
		 * both global and memcg freerun ceilings.
		   限流仅在后台写回无法追赶时才进行。这样可以避免在wb限制在!strictlimit情况下
		   上升时出现(过度)小的写出。在strictlimit情况下，根据wb计数器和限制做出决定。
		   当wb限制上升时，小的写出是我们有意为之的strictlimit-ing的代价。
		   如果memcg域生效，则@dirty应该在全局和memcg自由运行上限之下。

		 */
		if (dirty <= dirty_freerun_ceiling(thresh, bg_thresh) &&
		    (!mdtc ||
		     m_dirty <= dirty_freerun_ceiling(m_thresh, m_bg_thresh))) {
				//考虑这两个阈值, 说明可以退出了?
			unsigned long intv;
			unsigned long m_intv;

free_running:
			intv = dirty_poll_interval(dirty, thresh);
			m_intv = ULONG_MAX;

			current->dirty_paused_when = now;
			current->nr_dirtied = 0;
			if (mdtc)
				m_intv = dirty_poll_interval(m_dirty, m_thresh);
			current->nr_dirtied_pause = min(intv, m_intv);
			break;
		}

		/* Start writeback even when in laptop mode */
		if (unlikely(!writeback_in_progress(wb)))
			wb_start_background_writeback(wb);

		mem_cgroup_flush_foreign(wb);

		/*
		 * Calculate global domain's pos_ratio and select the
		 * global dtc by default.
		 */
		if (!strictlimit) {
			wb_dirty_limits(gdtc);

			if ((current->flags & PF_LOCAL_THROTTLE) &&
			    gdtc->wb_dirty <
			    dirty_freerun_ceiling(gdtc->wb_thresh,
						  gdtc->wb_bg_thresh))
				/*
				 * LOCAL_THROTTLE tasks must not be throttled
				 * when below the per-wb freerun ceiling.
				 */
				goto free_running;
		}

		//严格限制的情况下

		dirty_exceeded = (gdtc->wb_dirty > gdtc->wb_thresh) &&
			((gdtc->dirty > gdtc->thresh) || strictlimit);

		wb_position_ratio(gdtc);
		sdtc = gdtc;

		if (mdtc) {
			/*
			 * If memcg domain is in effect, calculate its
			 * pos_ratio.  @wb should satisfy constraints from
			 * both global and memcg domains.  Choose the one
			 * w/ lower pos_ratio.
			 */
			if (!strictlimit) {
				wb_dirty_limits(mdtc);

				if ((current->flags & PF_LOCAL_THROTTLE) &&
				    mdtc->wb_dirty <
				    dirty_freerun_ceiling(mdtc->wb_thresh,
							  mdtc->wb_bg_thresh))
					/*
					 * LOCAL_THROTTLE tasks must not be
					 * throttled when below the per-wb
					 * freerun ceiling.
					 */
					goto free_running;
			}
			//继续考虑memcg是不是超过了阈值
			dirty_exceeded |= (mdtc->wb_dirty > mdtc->wb_thresh) &&
				((mdtc->dirty > mdtc->thresh) || strictlimit);

			wb_position_ratio(mdtc);
			if (mdtc->pos_ratio < gdtc->pos_ratio)
				sdtc = mdtc;
		}

		if (dirty_exceeded != wb->dirty_exceeded)
			wb->dirty_exceeded = dirty_exceeded;

		if (time_is_before_jiffies(READ_ONCE(wb->bw_time_stamp) +
					   BANDWIDTH_INTERVAL))  //计算wb带宽
			__wb_update_bandwidth(gdtc, mdtc, true);

		/* throttle according to the chosen dtc */
		dirty_ratelimit = READ_ONCE(wb->dirty_ratelimit);
		task_ratelimit = ((u64)dirty_ratelimit * sdtc->pos_ratio) >>
							RATELIMIT_CALC_SHIFT;
		max_pause = wb_max_pause(wb, sdtc->wb_dirty);
		min_pause = wb_min_pause(wb, max_pause,
					 task_ratelimit, dirty_ratelimit,
					 &nr_dirtied_pause);

		if (unlikely(task_ratelimit == 0)) {
			period = max_pause;
			pause = max_pause;
			goto pause;
		}
		period = HZ * pages_dirtied / task_ratelimit;
		pause = period;
		if (current->dirty_paused_when)
			pause -= now - current->dirty_paused_when;
		/*
		 * For less than 1s think time (ext3/4 may block the dirtier
		 * for up to 800ms from time to time on 1-HDD; so does xfs,
		 * however at much less frequency), try to compensate it in
		 * future periods by updating the virtual time; otherwise just
		 * do a reset, as it may be a light dirtier.
		 */
		if (pause < min_pause) {
			trace_balance_dirty_pages(wb,sdtc->thresh,sdtc->bg_thresh,sdtc->dirty,
						  sdtc->wb_thresh,sdtc->wb_dirty, dirty_ratelimit,task_ratelimit,
						  pages_dirtied, period, min(pause, 0L),start_time);
			if (pause < -HZ) {
				current->dirty_paused_when = now;
				current->nr_dirtied = 0;
			} else if (period) {
				current->dirty_paused_when += period;
				current->nr_dirtied = 0;
			} else if (current->nr_dirtied_pause <= pages_dirtied)
				current->nr_dirtied_pause += pages_dirtied;
			break;
		}

		if (unlikely(pause > max_pause)) {
			/* for occasional dropped task_ratelimit */
			now += min(pause - max_pause, max_pause);
			pause = max_pause;
		}

pause:
		trace_balance_dirty_pages(wb,sdtc->thresh,sdtc->bg_thresh,sdtc->dirty,
					  sdtc->wb_thresh,sdtc->wb_dirty,dirty_ratelimit,task_ratelimit,
					  pages_dirtied, period, pause,start_time);
		if (flags & BDP_ASYNC) {
			ret = -EAGAIN;
			break;
		}
		__set_current_state(TASK_KILLABLE);
		wb->dirty_sleep = now;
		io_schedule_timeout(pause);

		current->dirty_paused_when = now + pause;
		current->nr_dirtied = 0;
		current->nr_dirtied_pause = nr_dirtied_pause;

		/*
		 * This is typically equal to (dirty < thresh) and can also
		 * keep "1000+ dd on a slow USB stick" under control.
		 */
		if (task_ratelimit)
			break;

		/*
		 * In the case of an unresponsive NFS server and the NFS dirty
		 * pages exceeds dirty_thresh, give the other good wb's a pipe
		 * to go through, so that tasks on them still remain responsive.
		 *
		 * In theory 1 page is enough to keep the consumer-producer
		 * pipe going: the flusher cleans 1 page => the task dirties 1
		 * more page. However wb_dirty has accounting errors.  So use
		 * the larger and more IO friendly wb_stat_error.
		 */
		if (sdtc->wb_dirty <= wb_stat_error())
			break;

		if (fatal_signal_pending(current))
			break;
	}

	return ret;
}

static DEFINE_PER_CPU(int, bdp_ratelimits);

/*
 * Normal tasks are throttled by
 *	loop {
 *		dirty tsk->nr_dirtied_pause pages;
 *		take a snap in balance_dirty_pages();
 *	}
 * However there is a worst case. If every task exit immediately when dirtied
 * (tsk->nr_dirtied_pause - 1) pages, balance_dirty_pages() will never be
 * called to throttle the page dirties. The solution is to save the not yet
 * throttled page dirties in dirty_throttle_leaks on task exit and charge them
 * randomly into the running tasks. This works well for the above worst case,
 * as the new task will pick up and accumulate the old task's leaked dirty
 * count and eventually get throttled.
 */
DEFINE_PER_CPU(int, dirty_throttle_leaks) = 0;

/**
   产生脏页的进程调用这个函数, 如果超限了, 起到一个限制的作用
 * balance_dirty_pages_ratelimited_flags - Balance dirty memory state.
   平衡脏内存状态。
 * @mapping: address_space which was dirtied.
 * @flags: BDP flags.
 *
 * Processes which are dirtying memory should call in here once for each page
 * which was newly dirtied.  The function will periodically check the system's
 * dirty state and will initiate writeback if needed.
 * 正在脏化内存的进程应该为每个新脏化的页面调用这里。该函数将定期检查系统的脏状态，
 * 并在需要时启动写回。
   
 * See balance_dirty_pages_ratelimited() for details.
 * 有关详细信息，请参见balance_dirty_pages_ratelimited()。
 * Return: If @flags contains BDP_ASYNC, it may return -EAGAIN to
 * indicate that memory is out of balance and the caller must wait
 * for I/O to complete.  Otherwise, it will return 0 to indicate
 * that either memory was already in balance, or it was able to sleep
 * until the amount of dirty memory returned to balance.
 */
int balance_dirty_pages_ratelimited_flags(struct address_space *mapping,
					unsigned int flags)
{
	struct inode *inode = mapping->host;
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	struct bdi_writeback *wb = NULL;
	int ratelimit;
	int ret = 0;
	int *p;

	if (!(bdi->capabilities & BDI_CAP_WRITEBACK))
		return ret;

	if (inode_cgwb_enabled(inode))
		wb = wb_get_create_current(bdi, GFP_KERNEL);
	if (!wb)
		wb = &bdi->wb;

	ratelimit = current->nr_dirtied_pause;
	if (wb->dirty_exceeded)
		ratelimit = min(ratelimit, 32 >> (PAGE_SHIFT - 10));

	preempt_disable();
	/*
	 * This prevents one CPU to accumulate too many dirtied pages without
	 * calling into balance_dirty_pages(), which can happen when there are
	 * 1000+ tasks, all of them start dirtying pages at exactly the same
	 * time, hence all honoured too large initial task->nr_dirtied_pause.
	 */
	p =  this_cpu_ptr(&bdp_ratelimits);
	if (unlikely(current->nr_dirtied >= ratelimit))
		*p = 0;
	else if (unlikely(*p >= ratelimit_pages)) {
		*p = 0;
		ratelimit = 0;
	}
	/*
	 * Pick up the dirtied pages by the exited tasks. This avoids lots of
	 * short-lived tasks (eg. gcc invocations in a kernel build) escaping
	 * the dirty throttling and livelock other long-run dirtiers.
	 */
	p = this_cpu_ptr(&dirty_throttle_leaks);
	if (*p > 0 && current->nr_dirtied < ratelimit) {
		unsigned long nr_pages_dirtied;
		nr_pages_dirtied = min(*p, ratelimit - current->nr_dirtied);
		*p -= nr_pages_dirtied;
		current->nr_dirtied += nr_pages_dirtied;
	}
	preempt_enable();

	if (unlikely(current->nr_dirtied >= ratelimit))
		ret = balance_dirty_pages(wb, current->nr_dirtied, flags);

	wb_put(wb);
	return ret;
}

EXPORT_SYMBOL_GPL(balance_dirty_pages_ratelimited_flags);

/**
   限制脏页
   do mm fault时会调用
 * balance_dirty_pages_ratelimited - balance dirty memory state.
   
 * @mapping: address_space which was dirtied.
 *
 * Processes which are dirtying memory should call in here once for each page
 * which was newly dirtied.  The function will periodically check the system's
 * dirty state and will initiate writeback if needed.
 * 那些正在脏化内存的进程应该为每个新脏化的页面调用这里。该函数将定期检查系统的脏状态，
 * 并在需要时启动写回。
   
 * Once we're over the dirty memory limit we decrease the ratelimiting
 * by a lot, to prevent individual processes from overshooting the limit
 * by (ratelimit_pages) each.
 * 一旦我们超过了脏内存限制，我们会大幅降低速率限制，以防止单个进程每次超过(ratelimit_pages)限制。
   
 */
void balance_dirty_pages_ratelimited(struct address_space *mapping)
{
	balance_dirty_pages_ratelimited_flags(mapping, 0);
}
EXPORT_SYMBOL(balance_dirty_pages_ratelimited);

/**
 * wb_over_bg_thresh - does @wb need to be written back?
 * @wb: bdi_writeback of interest
 *
 * Determines whether background writeback should keep writing @wb or it's
 * clean enough.
 *
 * Return: %true if writeback should continue.
 */
bool wb_over_bg_thresh(struct bdi_writeback *wb)
{
	struct dirty_throttle_control gdtc_stor = { GDTC_INIT(wb) };
	struct dirty_throttle_control mdtc_stor = { MDTC_INIT(wb, &gdtc_stor) };
	struct dirty_throttle_control * const gdtc = &gdtc_stor;
	struct dirty_throttle_control * const mdtc = mdtc_valid(&mdtc_stor) ?
						     &mdtc_stor : NULL;
	unsigned long reclaimable;
	unsigned long thresh;

	/*
	 * Similar to balance_dirty_pages() but ignores pages being written
	 * as we're trying to decide whether to put more under writeback.
	 */
	gdtc->avail = global_dirtyable_memory();
	gdtc->dirty = global_node_page_state(NR_FILE_DIRTY);
	domain_dirty_limits(gdtc);

	if (gdtc->dirty > gdtc->bg_thresh)
		return true;

	thresh = wb_calc_thresh(gdtc->wb, gdtc->bg_thresh);
	if (thresh < 2 * wb_stat_error())
		reclaimable = wb_stat_sum(wb, WB_RECLAIMABLE);
	else
		reclaimable = wb_stat(wb, WB_RECLAIMABLE);

	if (reclaimable > thresh)
		return true;

	if (mdtc) {
		unsigned long filepages, headroom, writeback;

		mem_cgroup_wb_stats(wb, &filepages, &headroom, &mdtc->dirty,
				    &writeback);
		mdtc_calc_avail(mdtc, filepages, headroom);
		domain_dirty_limits(mdtc);	/* ditto, ignore writeback */

		if (mdtc->dirty > mdtc->bg_thresh)
			return true;

		thresh = wb_calc_thresh(mdtc->wb, mdtc->bg_thresh);
		if (thresh < 2 * wb_stat_error())
			reclaimable = wb_stat_sum(wb, WB_RECLAIMABLE);
		else
			reclaimable = wb_stat(wb, WB_RECLAIMABLE);

		if (reclaimable > thresh)
			return true;
	}

	return false;
}

#ifdef CONFIG_SYSCTL
/*
 * sysctl handler for /proc/sys/vm/dirty_writeback_centisecs
 */
static int dirty_writeback_centisecs_handler(struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	unsigned int old_interval = dirty_writeback_interval;
	int ret;

	ret = proc_dointvec(table, write, buffer, length, ppos);

	/*
	 * Writing 0 to dirty_writeback_interval will disable periodic writeback
	 * and a different non-zero value will wakeup the writeback threads.
	 * wb_wakeup_delayed() would be more appropriate, but it's a pain to
	 * iterate over all bdis and wbs.
	 * The reason we do this is to make the change take effect immediately.
	 */
	if (!ret && write && dirty_writeback_interval &&
		dirty_writeback_interval != old_interval)
		wakeup_flusher_threads(WB_REASON_PERIODIC);

	return ret;
}
#endif

void laptop_mode_timer_fn(struct timer_list *t)
{
	struct backing_dev_info *backing_dev_info =
		from_timer(backing_dev_info, t, laptop_mode_wb_timer);

	wakeup_flusher_threads_bdi(backing_dev_info, WB_REASON_LAPTOP_TIMER);
}

/*
 * We've spun up the disk and we're in laptop mode: schedule writeback
 * of all dirty data a few seconds from now.  If the flush is already scheduled
 * then push it back - the user is still using the disk.
 */
void laptop_io_completion(struct backing_dev_info *info)
{
	mod_timer(&info->laptop_mode_wb_timer, jiffies + laptop_mode);
}

/*
 * We're in laptop mode and we've just synced. The sync's writes will have
 * caused another writeback to be scheduled by laptop_io_completion.
 * Nothing needs to be written back anymore, so we unschedule the writeback.
 */
void laptop_sync_completion(void)
{
	struct backing_dev_info *bdi;

	rcu_read_lock();

	list_for_each_entry_rcu(bdi, &bdi_list, bdi_list)
		del_timer(&bdi->laptop_mode_wb_timer);

	rcu_read_unlock();
}

/*
 * If ratelimit_pages is too high then we can get into dirty-data overload
 * if a large number of processes all perform writes at the same time.
 *
 * Here we set ratelimit_pages to a level which ensures that when all CPUs are
 * dirtying in parallel, we cannot go more than 3% (1/32) over the dirty memory
 * thresholds.
 */

void writeback_set_ratelimit(void)
{
	struct wb_domain *dom = &global_wb_domain;
	unsigned long background_thresh;
	unsigned long dirty_thresh;

	global_dirty_limits(&background_thresh, &dirty_thresh);
	dom->dirty_limit = dirty_thresh;
	ratelimit_pages = dirty_thresh / (num_online_cpus() * 32);
	if (ratelimit_pages < 16)
		ratelimit_pages = 16;
}

//负责回写的wb内核线程?
static int page_writeback_cpu_online(unsigned int cpu)
{
	writeback_set_ratelimit();
	return 0;
}

#ifdef CONFIG_SYSCTL

/* this is needed for the proc_doulongvec_minmax of vm_dirty_bytes */
static const unsigned long dirty_bytes_min = 2 * PAGE_SIZE;

static struct ctl_table vm_page_writeback_sysctls[] = {
	{
		.procname   = "dirty_background_ratio",
		.data       = &dirty_background_ratio,
		.maxlen     = sizeof(dirty_background_ratio),
		.mode       = 0644,
		.proc_handler   = dirty_background_ratio_handler,
		.extra1     = SYSCTL_ZERO,
		.extra2     = SYSCTL_ONE_HUNDRED,
	},
	{
		.procname   = "dirty_background_bytes",
		.data       = &dirty_background_bytes,
		.maxlen     = sizeof(dirty_background_bytes),
		.mode       = 0644,
		.proc_handler   = dirty_background_bytes_handler,
		.extra1     = SYSCTL_LONG_ONE,
	},
	{
		.procname   = "dirty_ratio",
		.data       = &vm_dirty_ratio,
		.maxlen     = sizeof(vm_dirty_ratio),
		.mode       = 0644,
		.proc_handler   = dirty_ratio_handler,
		.extra1     = SYSCTL_ZERO,
		.extra2     = SYSCTL_ONE_HUNDRED,
	},
	{
		.procname   = "dirty_bytes",
		.data       = &vm_dirty_bytes,
		.maxlen     = sizeof(vm_dirty_bytes),
		.mode       = 0644,
		.proc_handler   = dirty_bytes_handler,
		.extra1     = (void *)&dirty_bytes_min,
	},
	{
		.procname   = "dirty_writeback_centisecs",
		.data       = &dirty_writeback_interval,
		.maxlen     = sizeof(dirty_writeback_interval),
		.mode       = 0644,
		.proc_handler   = dirty_writeback_centisecs_handler,
	},
	{
		.procname   = "dirty_expire_centisecs",
		.data       = &dirty_expire_interval,
		.maxlen     = sizeof(dirty_expire_interval),
		.mode       = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1     = SYSCTL_ZERO,
	},
#ifdef CONFIG_HIGHMEM
	{
		.procname	= "highmem_is_dirtyable",
		.data		= &vm_highmem_is_dirtyable,
		.maxlen		= sizeof(vm_highmem_is_dirtyable),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "laptop_mode",
		.data		= &laptop_mode,
		.maxlen		= sizeof(laptop_mode),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{}
};
#endif

/*
 * Called early on to tune the page writeback dirty limits.
 *  * 在早期调用以调整页面写回脏限制。
 * We used to scale dirty pages according to how total memory
 * related to pages that could be allocated for buffers.
 * * 我们过去根据总内存与可用于缓冲区的页面相关的页面来缩放脏页。
 * However, that was when we used "dirty_ratio" to scale with
 * all memory, and we don't do that any more. "dirty_ratio"
 * is now applied to total non-HIGHPAGE memory, and as such we can't
 * get into the old insane situation any more where we had
 * large amounts of dirty pages compared to a small amount of
 * non-HIGHMEM memory.
 * * 但是，那是当我们使用“dirty_ratio”与所有内存一起缩放时，我们不再这样做。
 * “dirty_ratio”现在应用于总非HIGHPAGE内存，因此我们不再会陷入旧的疯狂情况，
 * 在那种情况下，我们有大量脏页与少量非HIGHMEM内存相比。
   
 * But we might still want to scale the dirty_ratio by how
 * much memory the box has..
 * * 但我们可能仍然希望根据盒子的内存量来缩放dirty_ratio。
   
 */
void __init page_writeback_init(void)
{
	BUG_ON(wb_domain_init(&global_wb_domain, GFP_KERNEL));

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/writeback:online",
			  page_writeback_cpu_online, NULL);


	cpuhp_setup_state(CPUHP_MM_WRITEBACK_DEAD, "mm/writeback:dead", NULL,
			  page_writeback_cpu_online);
#ifdef CONFIG_SYSCTL
	register_sysctl_init("vm", vm_page_writeback_sysctls);
#endif
}

/**
 * tag_pages_for_writeback - tag pages to be written by write_cache_pages
 * @mapping: address space structure to write
 * @start: starting page index
 * @end: ending page index (inclusive)
 *
 * This function scans the page range from @start to @end (inclusive) and tags
 * all pages that have DIRTY tag set with a special TOWRITE tag. The idea is
 * that write_cache_pages (or whoever calls this function) will then use
 * TOWRITE tag to identify pages eligible for writeback.  This mechanism is
 * used to avoid livelocking of writeback by a process steadily creating new
 * dirty pages in the file (thus it is important for this function to be quick
 * so that it can tag pages faster than a dirtying process can create them).
 */
void tag_pages_for_writeback(struct address_space *mapping,
			     pgoff_t start, pgoff_t end)
{
	XA_STATE(xas, &mapping->i_pages, start);
	unsigned int tagged = 0;
	void *page;

	xas_lock_irq(&xas);
	xas_for_each_marked(&xas, page, end, PAGECACHE_TAG_DIRTY) {
		xas_set_mark(&xas, PAGECACHE_TAG_TOWRITE);
		if (++tagged % XA_CHECK_SCHED)
			continue;

		xas_pause(&xas);
		xas_unlock_irq(&xas);
		cond_resched();
		xas_lock_irq(&xas);
	}
	xas_unlock_irq(&xas);
}
EXPORT_SYMBOL(tag_pages_for_writeback);

/**
使用wbc作为控制,写回这个mapping的所有脏页
 * write_cache_pages - walk the list of dirty pages of the given address space and write all of them.
   遍历给定地址空间的脏页列表并写回所有脏页
 * @mapping: address space structure to write, 用于写入的地址空间结构
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write, 
 * @writepage: function called for each page, 负责写回遍历到的每个页的函数
 * @data: data passed to writepage function, 传递给writepage函数的数据参数
 *
 * If a page is already under I/O, write_cache_pages() skips it, even
 * if it's dirty.  This is desirable behaviour for memory-cleaning writeback,
 * but it is INCORRECT for data-integrity system calls such as fsync().  fsync()
 * and msync() need to guarantee that all the data which was dirty at the time
 * the call was made get new I/O started against them.  If wbc->sync_mode is
 * WB_SYNC_ALL then we were called for data integrity and we must wait for
 * existing IO to complete.
 * 如果一个页已经在I/O下,write_cache_pages()会跳过它,即使它是脏的.这是内存清理写回的理想行为,
 * 但对于数据完整性系统调用(如fsync())是不正确的.fsync()和msync()需要保证在调用时脏的所有数据都
 * 开始新的I/O.如果wbc->sync_mode是WB_SYNC_ALL,那么我们是为了数据完整性而调用的,我们必须等待现有的IO完成.

 * To avoid livelocks (when other process dirties new pages), we first tag
 * pages which should be written back with TOWRITE tag and only then start
 * writing them. For data-integrity sync we have to be careful so that we do
 * not miss some pages (e.g., because some other process has cleared TOWRITE
 * tag we set). The rule we follow is that TOWRITE tag can be cleared only
 * by the process clearing the DIRTY tag (and submitting the page for IO).
 * 为了避免活锁(当其他进程使新页变脏时),我们首先使用TOWRITE标记应该写回的页,然后才开始写回它们.
 * 对于数据完整性同步,我们必须小心,以免错过一些页(例如,因为其他进程已经清除了我们设置的TOWRITE标记).
 * 我们遵循的规则是TOWRITE标记只能由清除DIRTY标记(并将页提交给IO)的进程清除.
 * To avoid deadlocks between range_cyclic writeback and callers that hold
 * pages in PageWriteback to aggregate IO until write_cache_pages() returns,
 * we do not loop back to the start of the file. Doing so causes a page
 * lock/page writeback access order inversion - we should only ever lock
 * multiple pages in ascending page->index order, and looping back to the start
 * of the file violates that rule and causes deadlocks.
 * 为了避免range_cyclic写回和持有PageWriteback页以聚合IO直到write_cache_pages()返回的调用者之间的死锁,
   我们不会回到文件的开头.这样做会导致页面锁/页面写回访问顺序倒置-我们应该只按升序锁定多个页面->索引顺序的页面,
   并且回到文件的开头违反了该规则并导致死锁.
 * Return: %0 on success, negative error code otherwise
 */
int write_cache_pages(struct address_space *mapping,
		      struct writeback_control *wbc, writepage_t writepage,
		      void *data)
{
	int ret = 0;
	int done = 0;
	int error;
	struct folio_batch fbatch;
	int nr_folios;
	pgoff_t index;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index;
	int range_whole = 0;
	xa_mark_t tag;

	folio_batch_init(&fbatch);
	if (wbc->range_cyclic) {//这里是啥意思
		index = mapping->writeback_index; /* prev offset */
		end = -1;
	} else {//一般情况下, range_start和range_end是指定的范围
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
	}
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) { //WB_SYNC_ALL表示数据完整性同步
		tag_pages_for_writeback(mapping, index, end); //标记这个mapping的这个范围的脏页为TOWRITE
		tag = PAGECACHE_TAG_TOWRITE;
	} else { //如果是一般性的写回,则标记脏页为DIRTY
		tag = PAGECACHE_TAG_DIRTY;
	}
	done_index = index;
	while (!done && (index <= end)) {//遍历这个范围的脏页
		int i;

		nr_folios = filemap_get_folios_tag(mapping, &index, end,
				tag, &fbatch);//获取这个范围的tag标记的脏页到fbatch中

		if (nr_folios == 0)
			break;
		//此时fbatch中有nr_folios个脏页
		for (i = 0; i < nr_folios; i++) {//逐个处理这些脏页
			struct folio *folio = fbatch.folios[i];
			unsigned long nr;

			done_index = folio->index;

			folio_lock(folio);

			/*
			 * Page truncated or invalidated. We can freely skip it
			 * then, even for data integrity operations: the page
			 * has disappeared concurrently, so there could be no
			 * real expectation of this data integrity operation
			 * even if there is now a new, dirty page at the same
			 * pagecache address.
			   说明这个页已经被截断或者失效了,我们可以跳过它,
			   即使是数据完整性操作:这个页已经被并发地删除了,
			   所以即使现在在相同的页缓存地址上有一个新的脏页,
			   也不要再想继续进行数据完整性操作了.
			 */
			if (unlikely(folio->mapping != mapping)) {
continue_unlock:
				folio_unlock(folio);
				continue;
			}

			if (!folio_test_dirty(folio)) {//这个页不是脏页了
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (folio_test_writeback(folio)) {//这个页已经在I/O了
				if (wbc->sync_mode != WB_SYNC_NONE)
					folio_wait_writeback(folio); //如果我们这次是数据完整性同步,则等待这个页的I/O完成
				else
					goto continue_unlock; //否则跳过这个页,可以去处理下一个了
			}

			BUG_ON(folio_test_writeback(folio));
			//正常情况下走到这里,说明这个页是脏页,并且不在I/O中
			if (!folio_clear_dirty_for_io(folio))
				goto continue_unlock; //这个页面本来不是脏的?
			

			trace_wbc_writepage(wbc, inode_to_bdi(mapping->host));
			//调用指定的写回函数
			error = writepage(folio, wbc, data);
			nr = folio_nr_pages(folio);
			if (unlikely(error)) { //写回出错
				/*
				 * Handle errors according to the type of
				 * writeback. There's no need to continue for
				 * background writeback. Just push done_index
				 * past this page so media errors won't choke
				 * writeout for the entire file. For integrity
				 * writeback, we must process the entire dirty
				 * set regardless of errors because the fs may
				 * still have state to clear for each page. In
				 * that case we continue processing and return
				 * the first error.
				   根据写回的类型处理错误.对于后台写回,没有必要继续.
				   只需将done_index推到这个页的后面,这样媒介错误就不会使整个文件的写出中断.
				   对于完整性写回,我们必须处理整个脏页集合,而不管错误,因为文件系统可能仍然有每个页要清除的状态.
				   在这种情况下,我们继续处理并返回第一个错误.
				 */
				if (error == AOP_WRITEPAGE_ACTIVATE) {
					folio_unlock(folio);
					error = 0;
				} else if (wbc->sync_mode != WB_SYNC_ALL) {//后台写回
					ret = error;
					done_index = folio->index + nr;
					done = 1;
					break;
				}
				if (!ret)
					ret = error;
			}

			/*
			 * We stop writing back only if we are not doing
			 * integrity sync. In case of integrity sync we have to
			 * keep going until we have written all the pages
			 * we tagged for writeback prior to entering this loop.
			   我们只在不进行完整性同步时停止写回.在进行完整性同步的情况下,
			   我们必须继续进行,直到我们写回了进入这个循环之前标记为写回的所有页.
			 */
			wbc->nr_to_write -= nr;
			if (wbc->nr_to_write <= 0 &&
			    wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}
		}
		folio_batch_release(&fbatch);
		cond_resched();
	}

	/*
	 * If we hit the last page and there is more work to be done: wrap
	 * back the index back to the start of the file for the next
	 * time we are called.
	 如果我们到达了最后一页,还有更多的工作要做:为下一次调用将索引回到文件的开头.
	 */
	if (wbc->range_cyclic && !done)
		done_index = 0;
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

	return ret;
}
EXPORT_SYMBOL(write_cache_pages);

static int writepage_cb(struct folio *folio, struct writeback_control *wbc,
		void *data)
{
	struct address_space *mapping = data;
	int ret = mapping->a_ops->writepage(&folio->page, wbc);
	mapping_set_error(mapping, ret);
	return ret;
}

//写回函数
//其中wbc控制这个inode的这个@mapping的写回行为
//调用mapping的写回方法, 或者通用的写回方法

/* 写回inode或者mapping的一部分 */
int do_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	int ret;
	struct bdi_writeback *wb;

	if (wbc->nr_to_write <= 0)
		return 0;

	// 获取inode对应的wb
	wb = inode_to_wb_wbc(mapping->host, wbc);
	wb_bandwidth_estimate_start(wb);
	while (1) {
		if (mapping->a_ops->writepages) { //如果mapping有writepages方法
			ret = mapping->a_ops->writepages(mapping, wbc); //调用writepages方法

		} else if (mapping->a_ops->writepage) {//没有writepages方法，有writepage方法也行
			struct blk_plug plug;
			//但是这里为什么没有调用write_page呢？

			blk_start_plug(&plug);   
			//按照wbc写回mapping的脏页, 遍历脏页,调用writepage_cb回写
			ret = write_cache_pages(mapping, wbc, writepage_cb,
						mapping);
			blk_finish_plug(&plug);
		} else {
			/* deal with chardevs and other special files */
			ret = 0;
		}

		if (ret != -ENOMEM || wbc->sync_mode != WB_SYNC_ALL)
			break;
		
		//到这里说明写回出错了,并且是WB_SYNC_ALL模式

		/*
		 * Lacking an allocation context or the locality or writeback
		 * state of any of the inode's pages, throttle based on
		 * writeback activity on the local node. It's as good a
		 * guess as any.
		 	缺少分配上下文或任何inode页面的局部性或写回状态，
			基于本地节点上的写回活动进行限流。这是任何猜测的好方法。
		 */
		 /* 限流一会儿 */
		reclaim_throttle(NODE_DATA(numa_node_id()),
			VMSCAN_THROTTLE_WRITEBACK);
	} //
	/*
	 * Usually few pages are written by now from those we've just submitted
	 * but if there's constant writeback being submitted, this makes sure
	 * writeback bandwidth is updated once in a while.
	   通常我们刚刚提交的页面中现在已经写入了一些页面,但是如果不断提交写回,这会确保写回带宽不时更新一次.
	 */
	if (time_is_before_jiffies(READ_ONCE(wb->bw_time_stamp) +
				   BANDWIDTH_INTERVAL))
		wb_update_bandwidth(wb); //更新一下这个wb的写回速度, 可能用于计算配额吧什么的
	return ret;
}

/*
 * For address_spaces which do not use buffers nor write back.
 */
bool noop_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	if (!folio_test_dirty(folio))
		return !folio_test_set_dirty(folio);
	return false;
}
EXPORT_SYMBOL(noop_dirty_folio);

/*
   标记mapping的某个folio为脏页时会调用这个函数
   更新统计信息, 并在inode上附加wb
 * Helper function for set_page_dirty family.
 *
 * Caller must hold folio_memcg_lock().
 *
 * NOTE: This relies on being atomic wrt interrupts.
 */
static void folio_account_dirtied(struct folio *folio,
		struct address_space *mapping)
{
	struct inode *inode = mapping->host;

	trace_writeback_dirty_folio(folio, mapping);

	if (mapping_can_writeback(mapping)) { //mapping可以写回
		struct bdi_writeback *wb;
		long nr = folio_nr_pages(folio);

		inode_attach_wb(inode, folio); //为什么这里需要更新inode的wb呢?
		wb = inode_to_wb(inode);

		__lruvec_stat_mod_folio(folio, NR_FILE_DIRTY, nr);
		__zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, nr);
		__node_stat_mod_folio(folio, NR_DIRTIED, nr);
		
		wb_stat_mod(wb, WB_RECLAIMABLE, nr);
		wb_stat_mod(wb, WB_DIRTIED, nr);
		task_io_account_write(nr * PAGE_SIZE);
		current->nr_dirtied += nr;
		__this_cpu_add(bdp_ratelimits, nr);

		mem_cgroup_track_foreign_dirty(folio, wb);
	}
}

/*
 * Helper function for deaccounting dirty page without writeback.
 *
 * Caller must hold folio_memcg_lock().
 */
void folio_account_cleaned(struct folio *folio, struct bdi_writeback *wb)
{
	long nr = folio_nr_pages(folio);

	lruvec_stat_mod_folio(folio, NR_FILE_DIRTY, -nr);
	zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
	wb_stat_mod(wb, WB_RECLAIMABLE, -nr);
	task_io_account_cancelled_write(nr * PAGE_SIZE);
}

/*
   标记mapping的这个folio为脏页
   标记folio, mapping, inode为脏
   --------------
   2024年12月7日21:28:40 在page, mapping, inode上标记这个folio为脏页
 * Mark the folio dirty, and set it dirty in the page cache, and mark
 * the inode dirty.
 * 标记这个folio为脏页,并在页缓存中设置为脏页,并标记inode为脏.
 * If warn is true, then emit a warning if the folio is not uptodate and has
 * not been truncated.
 *
 * The caller must hold folio_memcg_lock().  Most callers have the folio
 * locked.  A few have the folio blocked from truncation through other
 * means (eg zap_vma_pages() has it mapped and is holding the page table
 * lock).  This can also be called from mark_buffer_dirty(), which I
 * cannot prove is always protected against truncate.
 */
void __folio_mark_dirty(struct folio *folio, struct address_space *mapping,
			     int warn)
{
	unsigned long flags;

	xa_lock_irqsave(&mapping->i_pages, flags);
	if (folio->mapping) {	/* Race with truncate? */
		WARN_ON_ONCE(warn && !folio_test_uptodate(folio));
		folio_account_dirtied(folio, mapping); //更新wb, inode的统计信息
		__xa_set_mark(&mapping->i_pages, folio_index(folio),
				PAGECACHE_TAG_DIRTY); //在mapping的页缓存中设置这个页为脏页
	}
	xa_unlock_irqrestore(&mapping->i_pages, flags);
}

/**
 * filemap_dirty_folio - Mark a folio dirty for filesystems which do not use buffer_heads.
   让一个folio变脏,适用于不使用buffer_heads的文件系统.
   -------------------------
   标记page, mapping, inode为脏
 * @mapping: Address space this folio belongs to.
 * @folio: Folio to be marked as dirty.
 *
 * Filesystems which do not use buffer heads should call this function
 * from their set_page_dirty address space operation.  It ignores the
 * contents of folio_get_private(), so if the filesystem marks individual
 * blocks as dirty, the filesystem should handle that itself.
 * 不使用buffer_heads的文件系统应该从他们的set_page_dirty地址空间操作中调用这个函数.
 * 它忽略folio_get_private()的内容,所以如果文件系统标记单个块为脏,文件系统应该自己处理.

 * This is also sometimes used by filesystems which use buffer_heads when
 * a single buffer is being dirtied: we want to set the folio dirty in
 * that case, but not all the buffers.  This is a "bottom-up" dirtying,
 * whereas block_dirty_folio() is a "top-down" dirtying.
 * 有时,当单个缓冲区被标记为脏时,使用buffer_heads的文件系统也会使用它:在这种情况下,
   我们希望设置folio为脏,但是不是所有的缓冲区.
   这是一种"自下而上"的脏化,而block_dirty_folio()是一种"自上而下"的脏化.
 * The caller must ensure this doesn't race with truncation.  Most will
 * simply hold the folio lock, but e.g. zap_pte_range() calls with the
 * folio mapped and the pte lock held, which also locks out truncation.
 * 调用者必须确保这不会与截断竞争.大多数情况下,只需持有folio锁,但是例如,zap_pte_range()调用时,
   folio被映射并且持有pte锁,这也会锁定截断.
 */
bool filemap_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	folio_memcg_lock(folio);
	if (folio_test_set_dirty(folio)) { //如果folio是脏的,本来就是脏的,则返回false
		folio_memcg_unlock(folio);
		return false;
	}

	__folio_mark_dirty(folio, mapping, !folio_test_private(folio));
	// 在mapping的页缓存中设置这个页为脏页,更新wb, inode的统计信息
	folio_memcg_unlock(folio);

	if (mapping->host) {
		/* !PageAnon && !swapper_space */
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	}
	return true;
}
EXPORT_SYMBOL(filemap_dirty_folio);

/**
 * folio_redirty_for_writepage - Decline to write a dirty folio.
   先不写这个脏页.
 * @wbc: The writeback control.
 * @folio: The folio.
 * 
 * When a writepage implementation decides that it doesn't want to write
 * @folio for some reason, it should call this function, unlock @folio and
 * return 0.
 * 如果写页实现决定出于某种原因不想写@folio,则应调用此函数,解锁@folio并返回0.
 * Return: True if we redirtied the folio.  False if someone else dirtied
 * it first.
   返回真,如果我们重新标记了这个folio.如果其他人先标记了它,则返回假.
 */
bool folio_redirty_for_writepage(struct writeback_control *wbc,
		struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	long nr = folio_nr_pages(folio);
	bool ret;

	wbc->pages_skipped += nr;
	ret = filemap_dirty_folio(mapping, folio); //标记文件映射的folio为脏

	if (mapping && mapping_can_writeback(mapping)) { //处理mapping相关的工作
		struct inode *inode = mapping->host;
		struct bdi_writeback *wb;
		struct wb_lock_cookie cookie = {};

		wb = unlocked_inode_to_wb_begin(inode, &cookie);
		current->nr_dirtied -= nr;
		node_stat_mod_folio(folio, NR_DIRTIED, -nr);
		wb_stat_mod(wb, WB_DIRTIED, -nr);
		unlocked_inode_to_wb_end(inode, &cookie);
	}
	return ret;
}
EXPORT_SYMBOL(folio_redirty_for_writepage);

/**
   调用mapping的dirty回调
 * folio_mark_dirty - Mark a folio as being modified.
   标记一个folio为被修改.
 * @folio: The folio.
 * 
 * The folio may not be truncated while this function is running.
 * Holding the folio lock is sufficient to prevent truncation, but some
 * callers cannot acquire a sleeping lock.  These callers instead hold
 * the page table lock for a page table which contains at least one page
 * in this folio.  Truncation will block on the page table lock as it
 * unmaps pages before removing the folio from its mapping.
   当此函数运行时，不能截断（truncate）该 folio。
 * 持有 folio 的锁足以防止截断，但某些调用者无法获取会引起休眠的锁。
 * 这些调用者会持有页表锁（page table lock），该锁用于保护至少包含该 folio 中一个页面的页表。
 * 在截断操作期间，页表锁会在解除页面映射（unmap pages）之前阻止截断操作，从而确保 folio 未被移出其映射。
 *
   
 * Return: True if the folio was newly dirtied, false if it was already dirty.
 */
bool folio_mark_dirty(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);

	if (likely(mapping)) {
		/*
		 * readahead/folio_deactivate could remain
		 * PG_readahead/PG_reclaim due to race with folio_end_writeback
		 * About readahead, if the folio is written, the flags would be
		 * reset. So no problem.
		 * About folio_deactivate, if the folio is redirtied,
		 * the flag will be reset. So no problem. but if the
		 * folio is used by readahead it will confuse readahead
		 * and make it restart the size rampup process. But it's
		 * a trivial problem.
		   预读或者folio_deactivate可能由于与folio_end_writeback的竞争而保持PG_readahead/PG_reclaim.
		   对于预读,如果folio被写入,标志将被重置.所以没有问题.
		   对于folio_deactivate,如果folio被重新标记为脏,标志将被重置.所以没有问题.但是如果
		   folio被预读使用,它将混淆预读并使其重新启动大小逐步增加的过程.但这是一个微不足道的问题.
		   这都是在说啥....
		 */
		if (folio_test_reclaim(folio))
			folio_clear_reclaim(folio);
		return mapping->a_ops->dirty_folio(mapping, folio);
	}

	return noop_dirty_folio(mapping, folio);
}
EXPORT_SYMBOL(folio_mark_dirty);

/*
 * set_page_dirty() is racy if the caller has no reference against
 * page->mapping->host, and if the page is unlocked.  This is because another
 * CPU could truncate the page off the mapping and then free the mapping.
 *
 * Usually, the page _is_ locked, or the caller is a user-space process which
 * holds a reference on the inode by having an open file.
 *
 * In other cases, the page should be locked before running set_page_dirty().
 */
int set_page_dirty_lock(struct page *page)
{
	int ret;

	lock_page(page);
	ret = set_page_dirty(page);
	unlock_page(page);
	return ret;
}
EXPORT_SYMBOL(set_page_dirty_lock);

/*
 * This cancels just the dirty bit on the kernel page itself, it does NOT
 * actually remove dirty bits on any mmap's that may be around. It also
 * leaves the page tagged dirty, so any sync activity will still find it on
 * the dirty lists, and in particular, clear_page_dirty_for_io() will still
 * look at the dirty bits in the VM.
 *
 * Doing this should *normally* only ever be done when a page is truncated,
 * and is not actually mapped anywhere at all. However, fs/buffer.c does
 * this when it notices that somebody has cleaned out all the buffers on a
 * page without actually doing it through the VM. Can you say "ext3 is
 * horribly ugly"? Thought you could.
 */
void __folio_cancel_dirty(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);

	if (mapping_can_writeback(mapping)) {
		struct inode *inode = mapping->host;
		struct bdi_writeback *wb;
		struct wb_lock_cookie cookie = {};

		folio_memcg_lock(folio);
		wb = unlocked_inode_to_wb_begin(inode, &cookie);

		if (folio_test_clear_dirty(folio))
			folio_account_cleaned(folio, wb);

		unlocked_inode_to_wb_end(inode, &cookie);
		folio_memcg_unlock(folio);
	} else {
		folio_clear_dirty(folio);
	}
}
EXPORT_SYMBOL(__folio_cancel_dirty);

/*
清除页表的脏位, 但是调用ops的dirty回调,清除page flag的脏位
 * Clear a folio's dirty flag, while caring for dirty memory accounting.
 * Returns true if the folio was previously dirty.
 * 清除一个folio的脏标志,同时关心脏内存计数.如果这个folio之前是脏的,则返回true.
 * This is for preparing to put the folio under writeout.  We leave
 * the folio tagged as dirty in the xarray so that a concurrent
 * write-for-sync can discover it via a PAGECACHE_TAG_DIRTY walk.
 * The ->writepage implementation will run either folio_start_writeback()
 * or folio_mark_dirty(), at which stage we bring the folio's dirty flag
 * and xarray dirty tag back into sync.
 * 这是为了准备将folio放入写出.
 我们在xarray中将这个folio标记为脏,
 以便并发的写入同步可以通过PAGECACHE_TAG_DIRTY遍历发现它.
 ->writepage实现将运行folio_start_writeback()或folio_mark_dirty(),
 在这个阶段,我们将folio的脏标志和xarray脏标记重新同步.

 * This incoherency between the folio's dirty flag and xarray tag is
 * unfortunate, but it only exists while the folio is locked.
 * 这个folio的脏标志和xarray标记之间的不一致是不幸的,
 但只存在于folio被锁定时.
 */
bool folio_clear_dirty_for_io(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);
	bool ret = false;

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	if (mapping && mapping_can_writeback(mapping)) {//如果这个folio有mapping,并且这个mapping可以写回
		struct inode *inode = mapping->host;
		struct bdi_writeback *wb;
		struct wb_lock_cookie cookie = {};

		/*
		 * Yes, Virginia, this is indeed insane.
		 * 这是一个疯狂的操作.
		 * We use this sequence to make sure that
		 *  (a) we account for dirty stats properly
		 *  (b) we tell the low-level filesystem to
		 *      mark the whole folio dirty if it was
		 *      dirty in a pagetable. Only to then
		 *  (c) clean the folio again and return 1 to
		 *      cause the writeback.
		 * 我们使用这个序列来确保:
		 *  (a)我们正确地统计脏数据
		 *  (b)我们告诉底层文件系统,如果在页表中脏了整个folio,则标记整个folio为脏.然后
		 *  (c)再次清理folio并返回1以引起写回.
		 * This way we avoid all nasty races with the
		 * dirty bit in multiple places and clearing
		 * them concurrently from different threads.
		 * 这可能会避免在多个地方的脏位中发生的所有恶性竞争,并且可以同时从不同的线程中清除它们.
		 * Note! Normally the "folio_mark_dirty(folio)"
		 * has no effect on the actual dirty bit - since
		 * that will already usually be set. But we
		 * need the side effects, and it can help us
		 * avoid races.
		 * 注意, 通常"folio_mark_dirty(folio)"对实际的脏位没有影响-因为通常已经设置了.
		 * 但我们需要副作用,它可以帮助我们避免竞争.
		 
		 * We basically use the folio "master dirty bit"
		 * as a serialization point for all the different
		 * threads doing their things.
		 * 我们基本上使用folio的"主脏位"作为所有不同线程执行操作的序列化点.

		 */
		if (folio_mkclean(folio)) //让指向这个folio的所有页表项的脏位都清除
			folio_mark_dirty(folio); //为什么又让page变dirty了, 这里是调用ops的dirty回调
		/*
		 * We carefully synchronise fault handlers against
		 * installing a dirty pte and marking the folio dirty
		 * at this point.  We do this by having them hold the
		 * page lock while dirtying the folio, and folios are
		 * always locked coming in here, so we get the desired
		 * exclusion.
		   仔细的与故障处理程序同步,故障处理程序防止在这时候安装一个脏的pte并标记folio为脏出现的fault.
		   我们通过dirty的时候持有页锁来实现这一点,而在这里进来的folio总是被锁定的,所以我们得到了期望的排除.
		 */
		wb = unlocked_inode_to_wb_begin(inode, &cookie);
		if (folio_test_clear_dirty(folio)) {//这里是清除标记位的dirty
			long nr = folio_nr_pages(folio);
			lruvec_stat_mod_folio(folio, NR_FILE_DIRTY, -nr);
			zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
			wb_stat_mod(wb, WB_RECLAIMABLE, -nr);
			ret = true;
		}
		unlocked_inode_to_wb_end(inode, &cookie);
		return ret;
	}
	return folio_test_clear_dirty(folio);
}
EXPORT_SYMBOL(folio_clear_dirty_for_io);

//其实就是增加需要回写的inode数量
static void wb_inode_writeback_start(struct bdi_writeback *wb)
{
	atomic_inc(&wb->writeback_inodes);
}

//表示wb控制的这个inode写回完成了
//wb对inode写回完成的end
static void wb_inode_writeback_end(struct bdi_writeback *wb)
{
	unsigned long flags;
	atomic_dec(&wb->writeback_inodes);
	/*
	 * Make sure estimate of writeback throughput gets updated after
	 * writeback completed. We delay the update by BANDWIDTH_INTERVAL
	 * (which is the interval other bandwidth updates use for batching) so
	 * that if multiple inodes end writeback at a similar time, they get
	 * batched into one bandwidth update.
	   保证写回吞吐量的估计在写回完成后得到更新.
	   我们将更新延迟BANDWIDTH_INTERVAL(这是其他带宽更新用于批处理的间隔),
	   以便如果多个inode在类似的时间结束写回,它们将被批处理到一个带宽更新中.

	 */
	spin_lock_irqsave(&wb->work_lock, flags);
	if (test_bit(WB_registered, &wb->state)) //更新带宽
		queue_delayed_work(bdi_wq, &wb->bw_dwork, BANDWIDTH_INTERVAL);
	spin_unlock_irqrestore(&wb->work_lock, flags);
}

//folio回写完成的清理工作,涉及mapping, wb, inode, sb等
bool __folio_end_writeback(struct folio *folio)
{
	long nr = folio_nr_pages(folio);
	struct address_space *mapping = folio_mapping(folio);
	bool ret;

	folio_memcg_lock(folio);
	if (mapping && mapping_use_writeback_tags(mapping)) {
		struct inode *inode = mapping->host;
		struct backing_dev_info *bdi = inode_to_bdi(inode);
		unsigned long flags;

		xa_lock_irqsave(&mapping->i_pages, flags);
		ret = folio_test_clear_writeback(folio);//最主要的end: 清除这个folio的写回标记
		if (ret) {//如果这个folio之前有写回标记
			__xa_clear_mark(&mapping->i_pages, folio_index(folio),
						PAGECACHE_TAG_WRITEBACK);//mapping相关的end: 清除这个folio的在mapping的写回标记

			if (bdi->capabilities & BDI_CAP_WRITEBACK_ACCT) {//这里是wb相关的end
				struct bdi_writeback *wb = inode_to_wb(inode);

				wb_stat_mod(wb, WB_WRITEBACK, -nr);
				__wb_writeout_add(wb, nr);

				if (!mapping_tagged(mapping,
						    PAGECACHE_TAG_WRITEBACK)) //如果mapping没有任何页面有写回标记
							//可能是因为写回完成了
					wb_inode_writeback_end(wb);
			}
		}

		if (mapping->host && !mapping_tagged(mapping,
						     PAGECACHE_TAG_WRITEBACK))
			sb_clear_inode_writeback(mapping->host); //sb对这个inode的end

		xa_unlock_irqrestore(&mapping->i_pages, flags);
	} else { //如果不存在mapping, 或者mapping不支持tag
		ret = folio_test_clear_writeback(folio);
	}


	if (ret) { //如果之前有写回标记
		lruvec_stat_mod_folio(folio, NR_WRITEBACK, -nr);
		zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
		node_stat_mod_folio(folio, NR_WRITTEN, nr);
	}

	folio_memcg_unlock(folio);
	return ret;
}


//写回folio?
//感觉好像就是登记这个要回写了?
bool __folio_start_writeback(struct folio *folio, bool keep_write)
{
	long nr = folio_nr_pages(folio);
	struct address_space *mapping = folio_mapping(folio);
	bool ret;
	int access_ret;

	folio_memcg_lock(folio);

	if (mapping && mapping_use_writeback_tags(mapping)) { //mapping支持wb tag
		XA_STATE(xas, &mapping->i_pages, folio_index(folio));
		struct inode *inode = mapping->host;
		struct backing_dev_info *bdi = inode_to_bdi(inode);
		unsigned long flags;

		xas_lock_irqsave(&xas, flags);
		xas_load(&xas);
		ret = folio_test_set_writeback(folio); //标记为开始回写
		if (!ret) {//说明folio本来没在回写
			bool on_wblist;

			on_wblist = mapping_tagged(mapping,
						   PAGECACHE_TAG_WRITEBACK);

			xas_set_mark(&xas, PAGECACHE_TAG_WRITEBACK);
			if (bdi->capabilities & BDI_CAP_WRITEBACK_ACCT) {
				struct bdi_writeback *wb = inode_to_wb(inode);

				wb_stat_mod(wb, WB_WRITEBACK, nr); //登记这个wb又写了这些东西
				if (!on_wblist) //这整个mapping都是刚开始回写?
					wb_inode_writeback_start(wb);
			}

			/*
			 * We can come through here when swapping
			 * anonymous folios, so we don't necessarily
			 * have an inode to track for sync.
			 */
			if (mapping->host && !on_wblist)
				sb_mark_inode_writeback(mapping->host);
		}

		if (!folio_test_dirty(folio))
			xas_clear_mark(&xas, PAGECACHE_TAG_DIRTY);
		if (!keep_write)
			xas_clear_mark(&xas, PAGECACHE_TAG_TOWRITE);
		xas_unlock_irqrestore(&xas, flags);
	} else {
		ret = folio_test_set_writeback(folio);
	}
	if (!ret) { //本来没在回写
		lruvec_stat_mod_folio(folio, NR_WRITEBACK, nr);
		zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, nr);
	}
	folio_memcg_unlock(folio);
	access_ret = arch_make_folio_accessible(folio);
	/*
	 * If writeback has been triggered on a page that cannot be made
	 * accessible, it is too late to recover here.
	 */
	VM_BUG_ON_FOLIO(access_ret != 0, folio);

	return ret;
}
EXPORT_SYMBOL(__folio_start_writeback);

/**
 * folio_wait_writeback - Wait for a folio to finish writeback.
   等待一个folio完成写回,此时这个folio应该是脏的并且正在写回
 * @folio: The folio to wait for.
 *
 * If the folio is currently being written back to storage, wait for the
 * I/O to complete.
 * 如果这个folio当前正在写回到存储,等待I/O完成.
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
   上下文:睡眠.必须在进程上下文中调用,并且没有自旋锁被持有.调用者应该持有folio的引用.
   如果这个folio没有被锁住,写回可能在写回完成后重新开始.
 */
void folio_wait_writeback(struct folio *folio)
{
	while (folio_test_writeback(folio)) {//如果这个folio还在处于写回状态
		trace_folio_wait_writeback(folio, folio_mapping(folio));
		folio_wait_bit(folio, PG_writeback);
	}
}
EXPORT_SYMBOL_GPL(folio_wait_writeback);

/**
 * folio_wait_writeback_killable - Wait for a folio to finish writeback.
 * @folio: The folio to wait for.
 *
 * If the folio is currently being written back to storage, wait for the
 * I/O to complete or a fatal signal to arrive.
 *
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
 * Return: 0 on success, -EINTR if we get a fatal signal while waiting.
 */
int folio_wait_writeback_killable(struct folio *folio)
{
	while (folio_test_writeback(folio)) {
		trace_folio_wait_writeback(folio, folio_mapping(folio));
		if (folio_wait_bit_killable(folio, PG_writeback))
			return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(folio_wait_writeback_killable);

/**
 * folio_wait_stable() - wait for writeback to finish, if necessary.
 * @folio: The folio to wait on.
 *
 * This function determines if the given folio is related to a backing
 * device that requires folio contents to be held stable during writeback.
 * If so, then it will wait for any pending writeback to complete.
 *
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
 */
void folio_wait_stable(struct folio *folio)
{
	if (folio_inode(folio)->i_sb->s_iflags & SB_I_STABLE_WRITES)
		folio_wait_writeback(folio);
}
EXPORT_SYMBOL_GPL(folio_wait_stable);

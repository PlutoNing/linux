// SPDX-License-Identifier: GPL-2.0
/*
 * Manage cache of swap slots to be used for and returned from
 * swap.
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * Author: Tim Chen <tim.c.chen@linux.intel.com>
 *
 * We allocate the swap slots from the global pool and put
 * it into local per cpu caches.  This has the advantage
 * of no needing to acquire the swap_info lock every time
 * we need a new slot.
 *
 * There is also opportunity to simply return the slot
 * to local caches without needing to acquire swap_info
 * lock.  We do not reuse the returned slots directly but
 * move them back to the global pool in a batch.  This
 * allows the slots to coalesce and reduce fragmentation.
 *
 * The swap entry allocated is marked with SWAP_HAS_CACHE
 * flag in map_count that prevents it from being allocated
 * again from the global pool.
 *
 * The swap slots cache is protected by a mutex instead of
 * a spin lock as when we search for slots with scan_swap_map,
 * we can possibly sleep.
 */

#include <linux/swap_slots.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/mm.h>

// 好像是申请swap slot的cache?
static DEFINE_PER_CPU(struct swap_slots_cache, swp_slots);
static bool	swap_slot_cache_active;
bool	swap_slot_cache_enabled;
static bool	swap_slot_cache_initialized;
static DEFINE_MUTEX(swap_slots_cache_mutex);
/* Serialize swap slots cache enable/disable operations */
static DEFINE_MUTEX(swap_slots_cache_enable_mutex);

static void __drain_swap_slots_cache(unsigned int type);

#define use_swap_slot_cache (swap_slot_cache_active && swap_slot_cache_enabled)
#define SLOTS_CACHE 0x1
#define SLOTS_CACHE_RET 0x2

// 失效swap slot缓存
static void deactivate_swap_slots_cache(void)
{
	mutex_lock(&swap_slots_cache_mutex);
	swap_slot_cache_active = false;
	// 排空缓存项
	__drain_swap_slots_cache(SLOTS_CACHE|SLOTS_CACHE_RET);
	mutex_unlock(&swap_slots_cache_mutex);
}

// 重新激活swap slot缓存
static void reactivate_swap_slots_cache(void)
{
	mutex_lock(&swap_slots_cache_mutex);
	swap_slot_cache_active = true;
	mutex_unlock(&swap_slots_cache_mutex);
}

/* Must not be called with cpu hot plug lock
swapoff调用这个函数
*/
void disable_swap_slots_cache_lock(void)
{
	mutex_lock(&swap_slots_cache_enable_mutex);
	swap_slot_cache_enabled = false;
	if (swap_slot_cache_initialized) {
		/* serialize with cpu hotplug operations */
		cpus_read_lock();
		// 排空swap slot的cache
		__drain_swap_slots_cache(SLOTS_CACHE|SLOTS_CACHE_RET);
		cpus_read_unlock();
	}
}

// 重启缓存
static void __reenable_swap_slots_cache(void)
{
	swap_slot_cache_enabled = has_usable_swap();
}

// 重启缓存
void reenable_swap_slots_cache_unlock(void)
{
	__reenable_swap_slots_cache();
	mutex_unlock(&swap_slots_cache_enable_mutex);
}

// 检查缓存是否激活
static bool check_cache_active(void)
{
	long pages;

	if (!swap_slot_cache_enabled)
		return false; // swap slot缓存没打开

	pages = get_nr_swap_pages();
	if (!swap_slot_cache_active) {
		if (pages > num_online_cpus() *
		    THRESHOLD_ACTIVATE_SWAP_SLOTS_CACHE) // 交换页多于一定量才启用缓存
			reactivate_swap_slots_cache();
		goto out;
	}

	/* if global pool of slot caches too low, deactivate cache */
	if (pages < num_online_cpus() * THRESHOLD_DEACTIVATE_SWAP_SLOTS_CACHE)
		deactivate_swap_slots_cache(); // 使失效
out:
	return swap_slot_cache_active;
}

// 分配swap slot的缓存的结构体
static int alloc_swap_slot_cache(unsigned int cpu)
{
	struct swap_slots_cache *cache;
	swp_entry_t *slots, *slots_ret;

	/*
	 * Do allocation outside swap_slots_cache_mutex
	 * as kvzalloc could trigger reclaim and folio_alloc_swap,
	 * which can lock swap_slots_cache_mutex.
	 */
	 /* 先分配缓存cache用于存储slot的slots数组 */
	slots = kvcalloc(SWAP_SLOTS_CACHE_SIZE, sizeof(swp_entry_t),
			 GFP_KERNEL);
	if (!slots)
		return -ENOMEM;

	slots_ret = kvcalloc(SWAP_SLOTS_CACHE_SIZE, sizeof(swp_entry_t),
			     GFP_KERNEL);
	if (!slots_ret) {
		kvfree(slots);
		return -ENOMEM;
	}

	mutex_lock(&swap_slots_cache_mutex);
	// 获取这个cpu的pcp cache指针
	cache = &per_cpu(swp_slots, cpu);
	if (cache->slots || cache->slots_ret) { // 这个cpu已经有cache了
		/* cache already allocated */
		mutex_unlock(&swap_slots_cache_mutex);

		kvfree(slots);
		kvfree(slots_ret);

		return 0;
	}

	if (!cache->lock_initialized) {
		mutex_init(&cache->alloc_lock);
		spin_lock_init(&cache->free_lock);
		cache->lock_initialized = true;
	}
	cache->nr = 0;
	cache->cur = 0;
	cache->n_ret = 0;
	/*
	 * We initialized alloc_lock and free_lock earlier.  We use
	 * !cache->slots or !cache->slots_ret to know if it is safe to acquire
	 * the corresponding lock and use the cache.  Memory barrier below
	 * ensures the assumption.
	 */
	mb();
	cache->slots = slots;
	cache->slots_ret = slots_ret;
	mutex_unlock(&swap_slots_cache_mutex);
	return 0;
}

// 排空这个cpu在这swap file的swap slot cache
static void drain_slots_cache_cpu(unsigned int cpu, unsigned int type,
				  bool free_slots)
{
	struct swap_slots_cache *cache;
	swp_entry_t *slots = NULL;
	// 获得这个cache
	cache = &per_cpu(swp_slots, cpu);
	if ((type & SLOTS_CACHE) && cache->slots) {// cache有容量
		mutex_lock(&cache->alloc_lock);
		// 释放这些entries
		swapcache_free_entries(cache->slots + cache->cur, cache->nr);
		cache->cur = 0;
		cache->nr = 0;
		if (free_slots && cache->slots) {
			kvfree(cache->slots);
			cache->slots = NULL;
		}
		mutex_unlock(&cache->alloc_lock);
	}

	if ((type & SLOTS_CACHE_RET) && cache->slots_ret) {
		spin_lock_irq(&cache->free_lock);
		swapcache_free_entries(cache->slots_ret, cache->n_ret);
		cache->n_ret = 0;
		if (free_slots && cache->slots_ret) {
			slots = cache->slots_ret;
			cache->slots_ret = NULL;
		}
		spin_unlock_irq(&cache->free_lock);
		kvfree(slots);
	}
}

// 排空swap slot的cache?
static void __drain_swap_slots_cache(unsigned int type)
{
	unsigned int cpu;

	/*
	 * This function is called during
	 *	1) swapoff, when we have to make sure no
	 *	   left over slots are in cache when we remove
	 *	   a swap device;
	 *      2) disabling of swap slot cache, when we run low
	 *	   on swap slots when allocating memory and need
	 *	   to return swap slots to global pool.
	 *
	 * We cannot acquire cpu hot plug lock here as
	 * this function can be invoked in the cpu
	 * hot plug path:
	 * cpu_up -> lock cpu_hotplug -> cpu hotplug state callback
	 *   -> memory allocation -> direct reclaim -> folio_alloc_swap
	 *   -> drain_swap_slots_cache
	 *
	 * Hence the loop over current online cpu below could miss cpu that
	 * is being brought online but not yet marked as online.
	 * That is okay as we do not schedule and run anything on a
	 * cpu before it has been marked online. Hence, we will not
	 * fill any swap slots in slots cache of such cpu.
	 * There are no slots on such cpu that need to be drained.
	 */
	for_each_online_cpu(cpu) // 排空每个cpu在这个swap file的slot cache
		drain_slots_cache_cpu(cpu, type, false);
}

// 释放swap slot的分配缓存
static int free_slot_cache(unsigned int cpu)
{
	mutex_lock(&swap_slots_cache_mutex);
	drain_slots_cache_cpu(cpu, SLOTS_CACHE | SLOTS_CACHE_RET, true);
	mutex_unlock(&swap_slots_cache_mutex);
	return 0;
}

// swapon的时候启用swap slot的缓存
void enable_swap_slots_cache(void)
{
	mutex_lock(&swap_slots_cache_enable_mutex);
	if (!swap_slot_cache_initialized) {
		int ret;

		ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "swap_slots_cache",
					alloc_swap_slot_cache, free_slot_cache);
		if (WARN_ONCE(ret < 0, "Cache allocation failed (%s), operating "
				       "without swap slots cache.\n", __func__))
			goto out_unlock;

		swap_slot_cache_initialized = true;
	}

	__reenable_swap_slots_cache();
out_unlock:
	mutex_unlock(&swap_slots_cache_enable_mutex);
}

/* called with swap slot cache's alloc lock held
重新填充swap slot的缓存
*/
static int refill_swap_slots_cache(struct swap_slots_cache *cache)
{
	if (!use_swap_slot_cache)
		return 0;

	cache->cur = 0;
	if (swap_slot_cache_active)
	// 这里申请新的, 直接放到cache的slots数组里面
		cache->nr = get_swap_pages(SWAP_SLOTS_CACHE_SIZE,
					   cache->slots, 1);

	return cache->nr;
}

// 释放swap的slot, 好像是释放swap mapping的slot
void free_swap_slot(swp_entry_t entry)
{
	struct swap_slots_cache *cache;

	cache = raw_cpu_ptr(&swp_slots);
	if (likely(use_swap_slot_cache && cache->slots_ret)) {
		spin_lock_irq(&cache->free_lock);
		/* Swap slots cache may be deactivated before acquiring lock */
		if (!use_swap_slot_cache || !cache->slots_ret) {
			spin_unlock_irq(&cache->free_lock);
			goto direct_free;
		}
		if (cache->n_ret >= SWAP_SLOTS_CACHE_SIZE) {
			/*
			 * Return slots to global pool.
			 * The current swap_map value is SWAP_HAS_CACHE.
			 * Set it to 0 to indicate it is available for
			 * allocation in global pool
			 */
			swapcache_free_entries(cache->slots_ret, cache->n_ret);
			cache->n_ret = 0;
		}
		cache->slots_ret[cache->n_ret++] = entry;
		spin_unlock_irq(&cache->free_lock);
	} else {




direct_free:
		swapcache_free_entries(&entry, 1);
	}
}

// 给folio分配swap slot, 好像就是在swap file分配slot, 和swap map有关
// 这时候应该和mapping还没有关系
swp_entry_t folio_alloc_swap(struct folio *folio)
{
	swp_entry_t entry;
	struct swap_slots_cache *cache;

	entry.val = 0;

	if (folio_test_large(folio)) { // 大页的情况
		if (IS_ENABLED(CONFIG_THP_SWAP) && arch_thp_swp_supported())
		// 分配swap的slot存储在entry里面
			get_swap_pages(1, &entry, folio_nr_pages(folio));
		goto out;
	}

	/*
	 * Preemption is allowed here, because we may sleep
	 * in refill_swap_slots_cache().  But it is safe, because
	 * accesses to the per-CPU data structure are protected by the
	 * mutex cache->alloc_lock.
	 * 这里允许抢占，因为我们可能在refill_swap_slots_cache()中睡眠。
	 * 但是这是安全的，因为对每个CPU数据结构的访问受到互斥锁cache->alloc_lock的保护。
	 * The alloc path here does not touch cache->slots_ret
	 * so cache->free_lock is not taken.
	 这个分配路径不会触及cache->slots_ret，所以不会使用cache->free_lock。
	 */
	 // 找到申请slots的cache
	cache = raw_cpu_ptr(&swp_slots);

	if (likely(check_cache_active() && cache->slots)) {// 如果cache里面还有可用的slot
		mutex_lock(&cache->alloc_lock);
		if (cache->slots) {
repeat:
			if (cache->nr) { // cache还有东西
				entry = cache->slots[cache->cur];
				cache->slots[cache->cur++].val = 0;
				cache->nr--;
			} else if (refill_swap_slots_cache(cache)) { // cache里面没有了, 重新填充
				goto repeat;
			}
		}
		mutex_unlock(&cache->alloc_lock);
		if (entry.val)
			goto out;
	}
	// 无法利用缓存获取,. 这里直接自己申请
	get_swap_pages(1, &entry, 1);
out:
// 现在entry里面存储的是分配的新的slot
/* 这里charge这个memcg使用的swap file的空间 */
	if (mem_cgroup_try_charge_swap(folio, entry)) {
		put_swap_folio(folio, entry);
		entry.val = 0;
	}
	return entry;
}

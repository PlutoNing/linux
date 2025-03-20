// SPDX-License-Identifier: GPL-2.0-only
/*
 * zbud.c
 *
 * Copyright (C) 2013, Seth Jennings, IBM
 *
 * Concepts based on zcache internal zbud allocator by Dan Magenheimer.
 * 基于zcache内部zbud分配器的概念
 * zbud is an special purpose allocator for storing compressed pages.  Contrary
 * to what its name may suggest, zbud is not a buddy allocator, but rather an
 * allocator that "buddies" two compressed pages together in a single memory
 * page.
 * zbud是一个专门用于存储压缩页面的分配器。与其名称所暗示的相反，zbud不是一个伙伴分配器，
 而是一个将两个压缩页面“伙伴”在一起的分配器。
 * While this design limits storage density, it has simple and deterministic
 * reclaim properties that make it preferable to a higher density approach when
 * reclaim will be used.
 * 然而，这种设计限制了存储密度，但它具有简单和确定的回收属性，使其在回收时优于更高密度的方法。
 * zbud works by storing compressed pages, or "zpages", together in pairs in a
 * single memory page called a "zbud page".  The first buddy is "left
 * justified" at the beginning of the zbud page, and the last buddy is "right
 * justified" at the end of the zbud page.  The benefit is that if either
 * buddy is freed, the freed buddy space, coalesced with whatever slack space
 * that existed between the buddies, results in the largest possible free region
 * within the zbud page.
 * zbud通过将压缩页面或“zpages”一起存储在一对中，存储在称为“zbud页面”的单个内存页面中。
 第一个伙伴“左对齐”在zbud页面的开头，最后一个伙伴“右对齐”在zbud页面的末尾。
 好处是，如果任何一个伙伴被释放，那么释放的伙伴空间，与伙伴之间存在的任何松弛空间合并，
 将导致zbud页面中可能的最大空闲区域。
 * zbud also provides an attractive lower bound on density. The ratio of zpages
 * to zbud pages can not be less than 1.  This ensures that zbud can never "do
 * harm" by using more pages to store zpages than the uncompressed zpages would
 * have used on their own.
 * zbud也提供了一个有吸引力的密度下限。 zpages与zbud页面的比率不能小于1。
 这确保zbud永远不会“造成伤害”，因为使用更多页面来存储zpages，而不是未压缩的zpages本身将使用的页面。
 * zbud pages are divided into "chunks".  The size of the chunks is fixed at
 * compile time and determined by NCHUNKS_ORDER below.  Dividing zbud pages
 * into chunks allows organizing unbuddied zbud pages into a manageable number
 * of unbuddied lists according to the number of free chunks available in the
 * zbud page.
 * zbud的页面被划分为“块”。 块的大小在编译时固定，并由下面的NCHUNKS_ORDER确定。
 将zbud页面划分为块允许根据zbud页面中可用的空闲块的数量将未伙伴的zbud页面组织到可管理的未伙伴列表中。

 * The zbud API differs from that of conventional allocators in that the
 * allocation function, zbud_alloc(), returns an opaque handle to the user,
 * not a dereferenceable pointer.  The user must map the handle using
 * zbud_map() in order to get a usable pointer by which to access the
 * allocation data and unmap the handle with zbud_unmap() when operations
 * on the allocation data are complete.
 zbud的api与传统分配器的api不同，分配函数zbud_alloc()返回一个不透明的句柄给用户，而不是可解引用的指针。
 用户必须使用zbud_map()映射句柄，以便通过该指针访问分配数据，并在完成对分配数据的操作时取消映射句柄。
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/zpool.h>

/*****************
 * Structures
*****************/
/*
 * NCHUNKS_ORDER determines the internal allocation granularity, effectively
 * adjusting internal fragmentation.  It also determines the number of
 * freelists maintained in each pool. NCHUNKS_ORDER of 6 means that the
 * allocation granularity will be in chunks of size PAGE_SIZE/64. As one chunk
 * in allocated page is occupied by zbud header, NCHUNKS will be calculated to
 * 63 which shows the max number of free chunks in zbud page, also there will be
 * 63 freelists per pool.
 */
#define NCHUNKS_ORDER	6
/* 12 - 6 = 6 */
#define CHUNK_SHIFT	(PAGE_SHIFT - NCHUNKS_ORDER)
/* 64 */
#define CHUNK_SIZE	(1 << CHUNK_SHIFT)
/* 64 */
#define ZHDR_SIZE_ALIGNED CHUNK_SIZE
/*
(4096 - 64 ) >> 6 = 63?
*/
#define NCHUNKS		((PAGE_SIZE - ZHDR_SIZE_ALIGNED) >> CHUNK_SHIFT)

struct zbud_pool;

/**
 * struct zbud_pool - stores metadata for each zbud pool
 * @lock:	protects all pool fields and first|last_chunk fields of any
 *		zbud page in the pool
 * @unbuddied:	array of lists tracking zbud pages that only contain one buddy;
 *		the lists each zbud page is added to depends on the size of
 *		its free region.
 * @buddied:	list tracking the zbud pages that contain two buddies;
 *		these zbud pages are full
 * @pages_nr:	number of zbud pages in the pool.
 *
 * This structure is allocated at pool creation time and maintains metadata
 * pertaining to a particular zbud pool.
 */
struct zbud_pool {
	spinlock_t lock;
	union {
		/*
		 * Reuse unbuddied[0] as buddied on the ground that
		 * unbuddied[0] is unused.
		 */
		struct list_head buddied; /* 已经buddied的页面
		 */
		struct list_head unbuddied[NCHUNKS];/*
		记录单独buddy的链表
		*/
	};
	u64 pages_nr; // pool里面的页面数量
};

/*
 * struct zbud_header - zbud page metadata occupying the first chunk of each
 *			zbud page.
 * @buddy:	links the zbud page into the unbuddied/buddied lists in the pool
 * @first_chunks:	the size of the first buddy in chunks, 0 if free
 * @last_chunks:	the size of the last buddy in chunks, 0 if free
 */
struct zbud_header {
	struct list_head buddy;
	unsigned int first_chunks;
	unsigned int last_chunks;
};

/*****************
 * Helpers
*****************/
/* Just to make the code easier to read */
enum buddy {
	FIRST,
	LAST
};

/* Converts an allocation size in bytes to size in zbud chunks */
static int size_to_chunks(size_t size)
{
	return (size + CHUNK_SIZE - 1) >> CHUNK_SHIFT;
}

#define for_each_unbuddied_list(_iter, _begin) \
	for ((_iter) = (_begin); (_iter) < NCHUNKS; (_iter)++)

/* Initializes the zbud header of a newly allocated zbud page */
static struct zbud_header *init_zbud_page(struct page *page)
{
	struct zbud_header *zhdr = page_address(page);
	zhdr->first_chunks = 0;
	zhdr->last_chunks = 0;
	INIT_LIST_HEAD(&zhdr->buddy);
	return zhdr;
}

/* Resets the struct page fields and frees the page */
static void free_zbud_page(struct zbud_header *zhdr)
{
	__free_page(virt_to_page(zhdr));
}

/*
 * Encodes the handle of a particular buddy within a zbud page
 * Pool lock should be held as this function accesses first|last_chunks
 */
static unsigned long encode_handle(struct zbud_header *zhdr, enum buddy bud)
{
	unsigned long handle;

	/*
	 * For now, the encoded handle is actually just the pointer to the data
	 * but this might not always be the case.  A little information hiding.
	 * Add CHUNK_SIZE to the handle if it is the first allocation to jump
	 * over the zbud header in the first chunk.
	 */
	handle = (unsigned long)zhdr;
	if (bud == FIRST)
		/* skip over zbud header */
		handle += ZHDR_SIZE_ALIGNED;
	else /* bud == LAST */
		handle += PAGE_SIZE - (zhdr->last_chunks  << CHUNK_SHIFT);
	return handle;
}

/* Returns the zbud page where a given handle is stored */
static struct zbud_header *handle_to_zbud_header(unsigned long handle)
{
	return (struct zbud_header *)(handle & PAGE_MASK);
}

/* Returns the number of free chunks in a zbud page */
static int num_free_chunks(struct zbud_header *zhdr)
{
	/*
	 * Rather than branch for different situations, just use the fact that
	 * free buddies have a length of zero to simplify everything.
	 */
	return NCHUNKS - zhdr->first_chunks - zhdr->last_chunks;
}

/*****************
 * API Functions
*****************/
/*
创建zbud pool
初始化结构体成员
 * zbud_create_pool() - create a new zbud pool
 * @gfp:	gfp flags when allocating the zbud pool structure
 *
 * Return: pointer to the new zbud pool or NULL if the metadata allocation
 * failed.
 */
static struct zbud_pool *zbud_create_pool(gfp_t gfp)
{
	struct zbud_pool *pool;
	int i;
	// 分配结构体内存
	pool = kzalloc(sizeof(struct zbud_pool), gfp);
	if (!pool)
		return NULL;
	spin_lock_init(&pool->lock);
	for_each_unbuddied_list(i, 0)
		INIT_LIST_HEAD(&pool->unbuddied[i]);
	INIT_LIST_HEAD(&pool->buddied);
	pool->pages_nr = 0;
	return pool;
}

/*
释放zbud pool的内存
 * zbud_destroy_pool() - destroys an existing zbud pool
 * @pool:	the zbud pool to be destroyed
 *
 * The pool should be emptied before this function is called.
 */
static void zbud_destroy_pool(struct zbud_pool *pool)
{
	kfree(pool);
}

/**
 * zbud_alloc() - allocates a region of a given size
 * @pool:	zbud pool from which to allocate
 * @size:	size in bytes of the desired allocation
 * @gfp:	gfp flags used if the pool needs to grow
 * @handle:	handle of the new allocation
 *
 * This function will attempt to find a free region in the pool large enough to
 * satisfy the allocation request.  A search of the unbuddied lists is
 * performed first. If no suitable free region is found, then a new page is
 * allocated and added to the pool to satisfy the request.
 * 翻译: 函数会
 * gfp should not set __GFP_HIGHMEM as highmem pages cannot be used
 * as zbud pool pages.
 *
 * Return: 0 if success and handle is set, otherwise -EINVAL if the size or
 * gfp arguments are invalid or -ENOMEM if the pool was unable to allocate
 * a new page.
 */
static int zbud_alloc(struct zbud_pool *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	int chunks, i, freechunks;
	struct zbud_header *zhdr = NULL;
	enum buddy bud;
	struct page *page;

	if (!size || (gfp & __GFP_HIGHMEM))
		return -EINVAL;
	if (size > PAGE_SIZE - ZHDR_SIZE_ALIGNED - CHUNK_SIZE)
		return -ENOSPC;
	chunks = size_to_chunks(size);
	spin_lock(&pool->lock);

	/* First, try to find an unbuddied zbud page. */
	for_each_unbuddied_list(i, chunks) {
		if (!list_empty(&pool->unbuddied[i])) {
			zhdr = list_first_entry(&pool->unbuddied[i],
					struct zbud_header, buddy);
			list_del(&zhdr->buddy);
			if (zhdr->first_chunks == 0)
				bud = FIRST;
			else
				bud = LAST;
			goto found;
		}
	}

	/* Couldn't find unbuddied zbud page, create new one */
	spin_unlock(&pool->lock);
	page = alloc_page(gfp);
	if (!page)
		return -ENOMEM;
	spin_lock(&pool->lock);
	pool->pages_nr++;
	zhdr = init_zbud_page(page);
	bud = FIRST;

found:
	if (bud == FIRST)
		zhdr->first_chunks = chunks;
	else
		zhdr->last_chunks = chunks;

	if (zhdr->first_chunks == 0 || zhdr->last_chunks == 0) {
		/* Add to unbuddied list */
		freechunks = num_free_chunks(zhdr);
		list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
	} else {
		/* Add to buddied list */
		list_add(&zhdr->buddy, &pool->buddied);
	}

	*handle = encode_handle(zhdr, bud);
	spin_unlock(&pool->lock);

	return 0;
}

/**
 * zbud_free() - frees the allocation associated with the given handle
 * @pool:	pool in which the allocation resided
 * @handle:	handle associated with the allocation returned by zbud_alloc()
 */
static void zbud_free(struct zbud_pool *pool, unsigned long handle)
{
	struct zbud_header *zhdr;
	int freechunks;

	spin_lock(&pool->lock);
	zhdr = handle_to_zbud_header(handle);

	/* If first buddy, handle will be page aligned */
	if ((handle - ZHDR_SIZE_ALIGNED) & ~PAGE_MASK)
		zhdr->last_chunks = 0;
	else
		zhdr->first_chunks = 0;

	/* Remove from existing buddy list */
	list_del(&zhdr->buddy);

	if (zhdr->first_chunks == 0 && zhdr->last_chunks == 0) {
		/* zbud page is empty, free */
		free_zbud_page(zhdr);
		pool->pages_nr--;
	} else {
		/* Add to unbuddied list */
		freechunks = num_free_chunks(zhdr);
		list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
	}

	spin_unlock(&pool->lock);
}

/**
 * zbud_map() - maps the allocation associated with the given handle
 * @pool:	pool in which the allocation resides
 * @handle:	handle associated with the allocation to be mapped
 *
 * While trivial for zbud, the mapping functions for others allocators
 * implementing this allocation API could have more complex information encoded
 * in the handle and could create temporary mappings to make the data
 * accessible to the user.
 *
 * Returns: a pointer to the mapped allocation
 */
static void *zbud_map(struct zbud_pool *pool, unsigned long handle)
{
	return (void *)(handle);
}

/**
 * zbud_unmap() - maps the allocation associated with the given handle
 * @pool:	pool in which the allocation resides
 * @handle:	handle associated with the allocation to be unmapped
 */
static void zbud_unmap(struct zbud_pool *pool, unsigned long handle)
{
}

/**
获取zbud的pool的页面数量
 * zbud_get_pool_size() - gets the zbud pool size in pages
 * @pool:	pool whose size is being queried
 *
 * Returns: size in pages of the given pool.  The pool lock need not be
 * taken to access pages_nr.
 */
static u64 zbud_get_pool_size(struct zbud_pool *pool)
{
	return pool->pages_nr;
}

/*****************
 * zpool
 ****************/

static void *zbud_zpool_create(const char *name, gfp_t gfp)
{
	return zbud_create_pool(gfp);
}

// 释放zbud pool
static void zbud_zpool_destroy(void *pool)
{
	zbud_destroy_pool(pool);
}

static int zbud_zpool_malloc(void *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	return zbud_alloc(pool, size, gfp, handle);
}
static void zbud_zpool_free(void *pool, unsigned long handle)
{
	zbud_free(pool, handle);
}

static void *zbud_zpool_map(void *pool, unsigned long handle,
			enum zpool_mapmode mm)
{
	return zbud_map(pool, handle);
}
static void zbud_zpool_unmap(void *pool, unsigned long handle)
{
	zbud_unmap(pool, handle);
}

// 获取页面数量, 存储在结构体成员中
static u64 zbud_zpool_total_size(void *pool)
{
	return zbud_get_pool_size(pool) * PAGE_SIZE;
}

static struct zpool_driver zbud_zpool_driver = {
	.type =		"zbud",
	.sleep_mapped = true,
	.owner =	THIS_MODULE,
	.create =	zbud_zpool_create, // 创建zbud pool,初始化
	.destroy =	zbud_zpool_destroy,
	.malloc =	zbud_zpool_malloc,
	.free =		zbud_zpool_free,
	.map =		zbud_zpool_map,
	.unmap =	zbud_zpool_unmap,
	.total_size =	zbud_zpool_total_size, // 获取zbud的pool size
};

MODULE_ALIAS("zpool-zbud");
// 初始化模块
static int __init init_zbud(void)
{
	/* Make sure the zbud header will fit in one chunk */
	BUILD_BUG_ON(sizeof(struct zbud_header) > ZHDR_SIZE_ALIGNED);
	pr_info("loaded\n");

	zpool_register_driver(&zbud_zpool_driver);

	return 0;
}

// 卸载模块
static void __exit exit_zbud(void)
{
	zpool_unregister_driver(&zbud_zpool_driver);
	pr_info("unloaded\n");
}

module_init(init_zbud);
module_exit(exit_zbud);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seth Jennings <sjennings@variantweb.net>");
MODULE_DESCRIPTION("Buddy Allocator for Compressed Pages");

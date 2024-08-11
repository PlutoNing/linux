/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_PERCPU_INTERNAL_H
#define _MM_PERCPU_INTERNAL_H

#include <linux/types.h>
#include <linux/percpu.h>

/*
 * pcpu_block_md is the metadata block struct.
 * Each chunk's bitmap is split into a number of full blocks.
 * All units are in terms of bits.
 *
 * The scan hint is the largest known contiguous area before the contig hint.
 * It is not necessarily the actual largest contig hint though.  There is an
 * invariant that the scan_hint_start > contig_hint_start iff
 * scan_hint == contig_hint.  This is necessary because when scanning forward,
 * we don't know if a new contig hint would be better than the current one.
 */
struct pcpu_block_md {
	int			scan_hint;	/* scan hint for block */
	int			scan_hint_start; /* block relative starting
						    position of the scan hint */
	int                     contig_hint;    /* 
	当前chunk中记录的最大连续内存contig_hint
	contig hint for block */
	int                     contig_hint_start; /* 
	当前的最大连续空闲区域的起始地址
	block relative starting position of the contig hint */
	int                     left_free;      /* 
	左边的free数量
	size of free space along the left side of the block */
	int                     right_free;     /* 
	右侧free的数量
	size of free space along the right side of the block */

	int                     first_free;     /* 
	第一个可用的free分配单元所在的bit索引
	block position of first free */
	int			nr_bits;	/* 
	管理的bit数量
	total bits responsible for */
};
/* 2024年8月10日15:17:46 
per-cpu 内存被使用struct pcpu_chunk来描述， 不同大小的chunk被放在不同的链表中，
在动态分配per-cpu data时， 从合适的chunk中分配所需的空间*/
struct pcpu_chunk {
#ifdef CONFIG_PERCPU_STATS
	int			nr_alloc;	/* # of allocations */
	size_t			max_alloc_size; /* largest allocation size */
#endif

	struct list_head	list;		/* 
	用来把chunk链接起来形成链表pcpu_slot[slot]， 
	chunk中空闲空间的大小链表又被放到pcpu_slot数组中
	linked to pcpu_slot lists */
	int			free_bytes;	/* 
	chunk中的空闲大小
	free bytes in the chunk */
	struct pcpu_block_md	chunk_md;
	void			*base_addr;	/* 
	percpu chunk内存开始基地值
	base address of this chunk */

	unsigned long		*alloc_map;	/* 
	管理哦region的位图
	allocation map */
	unsigned long		*bound_map;	/* 
	保存每个“已使用区域”【bit_off，bit_off+alloc_bits】的边界。
	boundary map */
	struct pcpu_block_md	*md_blocks;	/* 
	一个chunk的block占用这里数组的一个元素
	metadata blocks */

	void			*data;		/* chunk data */
	bool			immutable;	/* no [de]population allowed */
	int			start_offset;	/*
	这个是在base_addr所在页的页内偏移，这个偏移地址后的内存才属于chunk 
	---------------------
	就是说base_addr虽然指向一个页面，但是这个页面不一定全是chunk的
	the overlap with the previous region to have a page aligned
						   base_addr */
	int			end_offset;	/* 
	chunk的pages中最右侧page的右边这一部分不属于chunk？
	additional area required to
						   have the region end page
						   aligned */

	int			nr_pages;	/* # of pages served by this chunk */
	int			nr_populated;	/* # of populated pages */
	int                     nr_empty_pop_pages; /* # of empty populated pages */
	unsigned long		populated[];	/* 
	标记pages有没有初始化的bitmap
	populated bitmap */
};

extern spinlock_t pcpu_lock;

extern struct list_head *pcpu_slot;
extern int pcpu_nr_slots;
extern int pcpu_nr_empty_pop_pages;

extern struct pcpu_chunk *pcpu_first_chunk;
extern struct pcpu_chunk *pcpu_reserved_chunk;

/**
？
也是计算管理chunk里面的这么多页面需要多少个block？
 * pcpu_chunk_nr_blocks - converts nr_pages to # of md_blocks
 * @chunk: chunk of interest
 *
 * This conversion is 
 from the number of physical pages that the chunkserves 
 to the number of bitmap blocks used.
 */
static inline int pcpu_chunk_nr_blocks(struct pcpu_chunk *chunk)
{
	return chunk->nr_pages * PAGE_SIZE / PCPU_BITMAP_BLOCK_SIZE;
}

/**
计算在pcp方式下用位图管理pages个页面分配需要多少空间。
这个需要考虑最小的分配细度，这里是PCPU_MIN_ALLOC_SIZE=4字节.
pages个页面一共有pages*page_size字节
那么一共需要pages*page_size/4个bit才能表示每个细度的大小有没有被分配
 * pcpu_nr_pages_to_map_bits - converts the pages to size of bitmap
 * @pages: number of physical pages
 *
 * This conversion is from physical pages to the number of bits
 * required in the bitmap.
 */
static inline int pcpu_nr_pages_to_map_bits(int pages)
{
	return pages * PAGE_SIZE / PCPU_MIN_ALLOC_SIZE;
}

/**
2024年8月10日15:43:57
计算在pcp方式下用位图管理pages个页面分配需要多少空间
 * pcpu_chunk_map_bits - helper to convert nr_pages to size of bitmap
 * @chunk: chunk of interest
 *
 * This conversion is from the number of physical pages that the chunk
 * serves to the number of bits in the bitmap.
 */
static inline int pcpu_chunk_map_bits(struct pcpu_chunk *chunk)
{
	return pcpu_nr_pages_to_map_bits(chunk->nr_pages);
}

#ifdef CONFIG_PERCPU_STATS

#include <linux/spinlock.h>

struct percpu_stats {
	u64 nr_alloc;		/* lifetime # of allocations */
	u64 nr_dealloc;		/* lifetime # of deallocations */
	u64 nr_cur_alloc;	/* current # of allocations */
	u64 nr_max_alloc;	/* max # of live allocations */
	u32 nr_chunks;		/* current # of live chunks */
	u32 nr_max_chunks;	/* max # of live chunks */
	size_t min_alloc_size;	/* min allocaiton size */
	size_t max_alloc_size;	/* max allocation size */
};

extern struct percpu_stats pcpu_stats;
extern struct pcpu_alloc_info pcpu_stats_ai;

/*
 * For debug purposes. We don't care about the flexible array.
 */
static inline void pcpu_stats_save_ai(const struct pcpu_alloc_info *ai)
{
	memcpy(&pcpu_stats_ai, ai, sizeof(struct pcpu_alloc_info));

	/* initialize min_alloc_size to unit_size */
	pcpu_stats.min_alloc_size = pcpu_stats_ai.unit_size;
}

/*
 * pcpu_stats_area_alloc - increment area allocation stats
 * @chunk: the location of the area being allocated
 * @size: size of area to allocate in bytes
 *
 * CONTEXT:
 * pcpu_lock.
 */
static inline void pcpu_stats_area_alloc(struct pcpu_chunk *chunk, size_t size)
{
	lockdep_assert_held(&pcpu_lock);

	pcpu_stats.nr_alloc++;
	pcpu_stats.nr_cur_alloc++;
	pcpu_stats.nr_max_alloc =
		max(pcpu_stats.nr_max_alloc, pcpu_stats.nr_cur_alloc);
	pcpu_stats.min_alloc_size =
		min(pcpu_stats.min_alloc_size, size);
	pcpu_stats.max_alloc_size =
		max(pcpu_stats.max_alloc_size, size);

	chunk->nr_alloc++;
	chunk->max_alloc_size = max(chunk->max_alloc_size, size);
}

/*
 * pcpu_stats_area_dealloc - decrement allocation stats
 * @chunk: the location of the area being deallocated
 *
 * CONTEXT:
 * pcpu_lock.
 */
static inline void pcpu_stats_area_dealloc(struct pcpu_chunk *chunk)
{
	lockdep_assert_held(&pcpu_lock);

	pcpu_stats.nr_dealloc++;
	pcpu_stats.nr_cur_alloc--;

	chunk->nr_alloc--;
}

/*
 * pcpu_stats_chunk_alloc - increment chunk stats
 */
static inline void pcpu_stats_chunk_alloc(void)
{
	unsigned long flags;
	spin_lock_irqsave(&pcpu_lock, flags);

	pcpu_stats.nr_chunks++;
	pcpu_stats.nr_max_chunks =
		max(pcpu_stats.nr_max_chunks, pcpu_stats.nr_chunks);

	spin_unlock_irqrestore(&pcpu_lock, flags);
}

/*
 * pcpu_stats_chunk_dealloc - decrement chunk stats
 */
static inline void pcpu_stats_chunk_dealloc(void)
{
	unsigned long flags;
	spin_lock_irqsave(&pcpu_lock, flags);

	pcpu_stats.nr_chunks--;

	spin_unlock_irqrestore(&pcpu_lock, flags);
}

#else

static inline void pcpu_stats_save_ai(const struct pcpu_alloc_info *ai)
{
}

static inline void pcpu_stats_area_alloc(struct pcpu_chunk *chunk, size_t size)
{
}

static inline void pcpu_stats_area_dealloc(struct pcpu_chunk *chunk)
{
}

static inline void pcpu_stats_chunk_alloc(void)
{
}

static inline void pcpu_stats_chunk_dealloc(void)
{
}

#endif /* !CONFIG_PERCPU_STATS */

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>

/*
 * pfn_t: encapsulates a page-frame number that is optionally backed
 * by memmap (struct page).  Whether a pfn_t has a 'struct page'
 * backing is indicated by flags in the high bits of the value.
 */
typedef struct {
	u64 val;
} pfn_t;
#endif

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
/* 物理页帧号（PFN）和物理地址之间存在一种简单的对应关系。物理页帧号可以被视为物理地址的索引或偏移量，通过一些计算可以将物理页帧号转换为对应的物理地址。

物理页帧号是一个无符号整数，用于标识物理内存页。它代表了物理页在系统中的位置或索引。每个物理页都有一个唯一的物理页帧号。

物理地址是实际的硬件地址，用于访问系统的物理内存。它表示内存中特定位置的物理存储单元。
————————————————

 */

#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
#define PHYS_PFN(x)	((unsigned long)((x) >> PAGE_SHIFT))

#endif

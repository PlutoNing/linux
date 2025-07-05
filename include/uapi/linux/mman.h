/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_MMAN_H
#define _UAPI_LINUX_MMAN_H

#include <asm/mman.h>
#include <asm-generic/hugetlb_encode.h>
#include <linux/types.h>

/* 允许内核在无法​​原地扩展内存映射区域​​时，将其移动到新的虚拟地址。 */
#define MREMAP_MAYMOVE		1
/* 强制将内存映射移动到用户指定的新地址 new_address？ */
#define MREMAP_FIXED		2
/* 调整内存映射后，​​保留原地址的映射​​，避免自动解除？ */
#define MREMAP_DONTUNMAP	4

#define OVERCOMMIT_GUESS		0
#define OVERCOMMIT_ALWAYS		1
#define OVERCOMMIT_NEVER		2

/* 当进程调用 mmap(MAP_SHARED) 映射匿名内存时，内核会隐式使用 shmem 机制分配内存。 */
#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_SHARED_VALIDATE 0x03	/* share + validate extension flags */

/*
 * Huge page size encoding when MAP_HUGETLB is specified, and a huge page
 * size other than the default is desired.  See hugetlb_encode.h.
 * All known huge page size encodings are provided here.  It is the
 * responsibility of the application to know which sizes are supported on
 * the running system.  See mmap(2) man page for details.
 */
#define MAP_HUGE_SHIFT	HUGETLB_FLAG_ENCODE_SHIFT
#define MAP_HUGE_MASK	HUGETLB_FLAG_ENCODE_MASK

#define MAP_HUGE_16KB	HUGETLB_FLAG_ENCODE_16KB
#define MAP_HUGE_64KB	HUGETLB_FLAG_ENCODE_64KB
#define MAP_HUGE_512KB	HUGETLB_FLAG_ENCODE_512KB
#define MAP_HUGE_1MB	HUGETLB_FLAG_ENCODE_1MB
#define MAP_HUGE_2MB	HUGETLB_FLAG_ENCODE_2MB
#define MAP_HUGE_8MB	HUGETLB_FLAG_ENCODE_8MB
#define MAP_HUGE_16MB	HUGETLB_FLAG_ENCODE_16MB
#define MAP_HUGE_32MB	HUGETLB_FLAG_ENCODE_32MB
#define MAP_HUGE_256MB	HUGETLB_FLAG_ENCODE_256MB
#define MAP_HUGE_512MB	HUGETLB_FLAG_ENCODE_512MB
#define MAP_HUGE_1GB	HUGETLB_FLAG_ENCODE_1GB
#define MAP_HUGE_2GB	HUGETLB_FLAG_ENCODE_2GB
#define MAP_HUGE_16GB	HUGETLB_FLAG_ENCODE_16GB

struct cachestat_range {
	__u64 off;
	__u64 len;
};

struct cachestat {
	__u64 nr_cache;
	__u64 nr_dirty;
	__u64 nr_writeback;
	__u64 nr_evicted;
	__u64 nr_recently_evicted;
};

#endif /* _UAPI_LINUX_MMAN_H */

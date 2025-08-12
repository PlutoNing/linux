// SPDX-License-Identifier: GPL-2.0
/*
 * mm/fadvise.c
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 11Jan2003	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/fadvise.h>
#include <linux/writeback.h>
#include <linux/syscalls.h>
#include <linux/swap.h>

#include <asm/unistd.h>
/* 
`advise`（file advise）系统调用允许应用程序告诉内核它对文件的访问意图，这样内核可以优化页面缓存和预读策略：

1. __POSIX_FADV_NORMAL__ - 正常访问模式，使用默认预读
2. __POSIX_FADV_RANDOM__ - 随机访问，禁用预读
3. __POSIX_FADV_SEQUENTIAL__ - 顺序访问，增加预读窗口
4. __POSIX_FADV_WILLNEED__ - 将要访问，提前读入页面缓存
5. __POSIX_FADV_DONTNEED__ - 不再需要，从缓存中移除
6. __POSIX_FADV_NOREUSE__ - 不重复使用，暂时无特殊处理

## madvise的作用

`madvise`（memory advise）与`fadvise`类似，但它作用于内存映射区域而不是文件描述符。它允许进程告诉内核对特定内存区域的使用意图：

- __MADV_NORMAL__ - 正常访问模式
- __MADV_RANDOM__ - 随机访问，减少预读
- __MADV_SEQUENTIAL__ - 顺序访问，增加预读
- __MADV_WILLNEED__ - 将要访问，提前加载页面
- __MADV_DONTNEED__ - 不再需要，可以释放页面
- __MADV_FREE__ - 可以释放页面，延迟回收
- __MADV_REMOVE__ - 移除映射
- __MADV_MERGEABLE__ - 允许KSM合并相同页面
- __MADV_UNMERGEABLE__ - 禁止KSM合并

主要区别：

- `fadvise`作用于文件描述符，影响文件缓存
- `madvise`作用于内存映射区域，影响进程地址空间

 */

/* 在io链路上相当于是个hook
根据系统调用的参数advice
设置是预读,还是不预读,还是大力预读,或者清除这段范围 */
int generic_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct inode *inode;
	struct address_space *mapping;
	struct backing_dev_info *bdi;
	loff_t endbyte;			/* inclusive */
	pgoff_t start_index;
	pgoff_t end_index;
	unsigned long nrpages;

	inode = file_inode(file);
	if (S_ISFIFO(inode->i_mode))
		return -ESPIPE;

	mapping = file->f_mapping;
	if (!mapping || len < 0)
		return -EINVAL;

	bdi = inode_to_bdi(mapping->host);

	if (IS_DAX(inode) || (bdi == &noop_backing_dev_info)) {
		/* 如果是直接IO */
		switch (advice) {
		case POSIX_FADV_NORMAL:
		case POSIX_FADV_RANDOM:
		case POSIX_FADV_SEQUENTIAL:
		case POSIX_FADV_WILLNEED:
		case POSIX_FADV_NOREUSE:
		case POSIX_FADV_DONTNEED:
			/* no bad return value, but ignore advice */
			break;
		default:
			return -EINVAL;
		}
		return 0;
	}

	/*
	 * Careful about overflows. Len == 0 means "as much as possible".  Use
	 * unsigned math because signed overflows are undefined and UBSan
	 * complains.
	 */
	endbyte = (u64)offset + (u64)len;
	if (!len || endbyte < len)
		endbyte = -1;
	else
		endbyte--;		/* inclusive */

	switch (advice) {
	case POSIX_FADV_NORMAL:
	/* 正常访问模式, 开启预读 */
		file->f_ra.ra_pages = bdi->ra_pages;
		spin_lock(&file->f_lock);
		file->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_RANDOM:
	/* 随机访问, 不要预读 */
		spin_lock(&file->f_lock);
		file->f_mode |= FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_SEQUENTIAL:
	/* 顺序访问, 大力预读（*2） */
		file->f_ra.ra_pages = bdi->ra_pages * 2;
		spin_lock(&file->f_lock);
		file->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_WILLNEED:
	/* 马上就需要,现在预读 */
		/* First and last PARTIAL page! */
		start_index = offset >> PAGE_SHIFT;
		end_index = endbyte >> PAGE_SHIFT;

		/* Careful about overflow on the "+1" */
		nrpages = end_index - start_index + 1;
		if (!nrpages)
			nrpages = ~0UL;

		/*
		 * Ignore return value because fadvise() shall return
		 * success even if filesystem can't retrieve a hint,
		 加载进pagecache
		 */
		force_page_cache_readahead(mapping, file, start_index, nrpages);
		break;
	case POSIX_FADV_NOREUSE:
		break;
	case POSIX_FADV_DONTNEED:
	/* 清理范围 */
		if (!inode_write_congested(mapping->host))
			__filemap_fdatawrite_range(mapping, offset, endbyte,
						   WB_SYNC_NONE);/* 启动回写 */

		/*
		 * First and last FULL page! Partial pages are deliberately
		 * preserved on the expectation that it is better to preserve
		 * needed memory than to discard unneeded memory.
		 */
		start_index = (offset+(PAGE_SIZE-1)) >> PAGE_SHIFT;
		end_index = (endbyte >> PAGE_SHIFT);
		/*
		 * The page at end_index will be inclusively discarded according
		 * by invalidate_mapping_pages(), so subtracting 1 from
		 * end_index means we will skip the last page.  But if endbyte
		 * is page aligned or is at the end of file, we should not skip
		 * that page - discarding the last page is safe enough.
		 */
		if ((endbyte & ~PAGE_MASK) != ~PAGE_MASK &&
				endbyte != inode->i_size - 1) {
			/* First page is tricky as 0 - 1 = -1, but pgoff_t
			 * is unsigned, so the end_index >= start_index
			 * check below would be true and we'll discard the whole
			 * file cache which is not what was asked.
			 */
			if (end_index == 0)
				break;

			end_index--;
		}

		if (end_index >= start_index) {
			unsigned long count;

			/*
			 * It's common to FADV_DONTNEED right after
			 * the read or write that instantiates the
			 * pages, in which case there will be some
			 * sitting on the local LRU cache. Try to
			 * avoid the expensive remote drain and the
			 * second cache tree walk below by flushing
			 * them out right away.
			 */
			lru_add_drain();

			count = invalidate_mapping_pages(mapping,
						start_index, end_index);

			/*
			 * If fewer pages were invalidated than expected then
			 * it is possible that some of the pages were on
			 * a per-cpu pagevec for a remote CPU. Drain all
			 * pagevecs and try again.
			 */
			if (count < (end_index - start_index + 1)) {
				lru_add_drain_all();
				invalidate_mapping_pages(mapping, start_index,
						end_index);
			}
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(generic_fadvise);
/* 2024年07月18日18:30:17
这个被mmap的file的offset对应的vma被willneed了
这里调用file的fops来执行完成这个willneed (基本就是把文件读入pagecache)
======================================
系统调用直接调用
madvise willneed调用
预读调用
 */
int vfs_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	/* 只有overlayfs
	overlayfs的fadvise实现是一个代理模式，将用户的fadvise请求正确地路由到实际存储文件上 */
	if (file->f_op->fadvise)
		return file->f_op->fadvise(file, offset, len, advice);

	return generic_fadvise(file, offset, len, advice);
}
EXPORT_SYMBOL(vfs_fadvise);

#ifdef CONFIG_ADVISE_SYSCALLS
/* 2024年07月18日18:30:13
系统调用 */
int ksys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice)
{
	struct fd f = fdget(fd);
	int ret;

	if (!f.file)
		return -EBADF;

	ret = vfs_fadvise(f.file, offset, len, advice);

	fdput(f);
	return ret;
}

SYSCALL_DEFINE4(fadvise64_64, int, fd, loff_t, offset, loff_t, len, int, advice)
{
	return ksys_fadvise64_64(fd, offset, len, advice);
}

#ifdef __ARCH_WANT_SYS_FADVISE64

SYSCALL_DEFINE4(fadvise64, int, fd, loff_t, offset, size_t, len, int, advice)
{
	return ksys_fadvise64_64(fd, offset, len, advice);
}

#endif
#endif

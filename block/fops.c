// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 1991, 1992  Linus Torvalds
 * Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 * Copyright (C) 2016 - 2020 Christoph Hellwig
 */
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/falloc.h>
#include <linux/suspend.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/module.h>
#include "blk.h"

//获取块设备filp的vfs inode
static inline struct inode *bdev_file_inode(struct file *file)
{
	return file->f_mapping->host;
}

static blk_opf_t dio_bio_write_op(struct kiocb *iocb)
{
	blk_opf_t opf = REQ_OP_WRITE | REQ_SYNC | REQ_IDLE;

	/* avoid the need for a I/O completion work item */
	if (iocb_is_dsync(iocb))
		opf |= REQ_FUA;
	return opf;
}

static bool blkdev_dio_unaligned(struct block_device *bdev, loff_t pos,
			      struct iov_iter *iter)
{
	return pos & (bdev_logical_block_size(bdev) - 1) ||
		!bdev_iter_is_aligned(bdev, iter);
}

#define DIO_INLINE_BIO_VECS 4

/* 块设备的direct IO实现中的一种
 */
static ssize_t __blkdev_direct_IO_simple(struct kiocb *iocb,
		struct iov_iter *iter, unsigned int nr_pages)
{
	/* 要读写的磁盘 */
	struct block_device *bdev = I_BDEV(iocb->ki_filp->f_mapping->host);
	struct bio_vec inline_vecs[DIO_INLINE_BIO_VECS], *vecs;
	loff_t pos = iocb->ki_pos;
	bool should_dirty = false;
	struct bio bio;
	ssize_t ret;

	if (blkdev_dio_unaligned(bdev, pos, iter))
		return -EINVAL;

	if (nr_pages <= DIO_INLINE_BIO_VECS)
		vecs = inline_vecs;
	else {
		vecs = kmalloc_array(nr_pages, sizeof(struct bio_vec),
				     GFP_KERNEL);
		if (!vecs)
			return -ENOMEM;
	}

	/* 这里初始化bio */
	if (iov_iter_rw(iter) == READ) {
		bio_init(&bio, bdev, vecs, nr_pages, REQ_OP_READ);
		if (user_backed_iter(iter))
			should_dirty = true;
	} else {
		bio_init(&bio, bdev, vecs, nr_pages, dio_bio_write_op(iocb));
	}
	bio.bi_iter.bi_sector = pos >> SECTOR_SHIFT;
	bio.bi_ioprio = iocb->ki_ioprio;

	/* 这里把iter的内容页面给bio */
	ret = bio_iov_iter_get_pages(&bio, iter);
	if (unlikely(ret))
		goto out;
	ret = bio.bi_iter.bi_size;

	if (iov_iter_rw(iter) == WRITE)
		task_io_account_write(ret);

	if (iocb->ki_flags & IOCB_NOWAIT)
		bio.bi_opf |= REQ_NOWAIT;

	/* 提交bio, 等待完成 */
	submit_bio_wait(&bio);

	/* 释放内存 */
	bio_release_pages(&bio, should_dirty);
	if (unlikely(bio.bi_status))
		ret = blk_status_to_errno(bio.bi_status);

out:
	if (vecs != inline_vecs)
		kfree(vecs);

	bio_uninit(&bio);

	return ret;
}

enum {
	DIO_SHOULD_DIRTY	= 1,
	DIO_IS_SYNC		= 2,
};

struct blkdev_dio {
	union {
		struct kiocb		*iocb;
		struct task_struct	*waiter;
	};
	size_t			size;
	atomic_t		ref;
	unsigned int		flags;
	struct bio		bio ____cacheline_aligned_in_smp;
};

static struct bio_set blkdev_dio_pool;

static void blkdev_bio_end_io(struct bio *bio)
{
	struct blkdev_dio *dio = bio->bi_private;
	bool should_dirty = dio->flags & DIO_SHOULD_DIRTY;

	if (bio->bi_status && !dio->bio.bi_status)
		dio->bio.bi_status = bio->bi_status;

	if (atomic_dec_and_test(&dio->ref)) {
		if (!(dio->flags & DIO_IS_SYNC)) {
			struct kiocb *iocb = dio->iocb;
			ssize_t ret;

			WRITE_ONCE(iocb->private, NULL);

			if (likely(!dio->bio.bi_status)) {
				ret = dio->size;
				iocb->ki_pos += ret;
			} else {
				ret = blk_status_to_errno(dio->bio.bi_status);
			}

			dio->iocb->ki_complete(iocb, ret);
			bio_put(&dio->bio);
		} else {
			struct task_struct *waiter = dio->waiter;

			WRITE_ONCE(dio->waiter, NULL);
			blk_wake_io_task(waiter);
		}
	}

	if (should_dirty) {
		bio_check_pages_dirty(bio);
	} else {
		bio_release_pages(bio, false);
		bio_put(bio);
	}
}

/* blk直接io的实现 (用于nr_pages比较大的情况) */
static ssize_t __blkdev_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
		unsigned int nr_pages)
{
	struct block_device *bdev = I_BDEV(iocb->ki_filp->f_mapping->host);
	struct blk_plug plug;
	struct blkdev_dio *dio;
	struct bio *bio;
	bool is_read = (iov_iter_rw(iter) == READ), is_sync;
	blk_opf_t opf = is_read ? REQ_OP_READ : dio_bio_write_op(iocb);
	loff_t pos = iocb->ki_pos;
	int ret = 0;

	if (blkdev_dio_unaligned(bdev, pos, iter))
		return -EINVAL;

	if (iocb->ki_flags & IOCB_ALLOC_CACHE)
		opf |= REQ_ALLOC_CACHE;
	bio = bio_alloc_bioset(bdev, nr_pages, opf, GFP_KERNEL,
			       &blkdev_dio_pool);
	dio = container_of(bio, struct blkdev_dio, bio);
	atomic_set(&dio->ref, 1);
	/*
	 * Grab an extra reference to ensure the dio structure which is embedded
	 * into the first bio stays around.
	 */
	bio_get(bio);

	is_sync = is_sync_kiocb(iocb);
	if (is_sync) {
		dio->flags = DIO_IS_SYNC;
		dio->waiter = current;
	} else {
		dio->flags = 0;
		dio->iocb = iocb;
	}

	dio->size = 0;
	if (is_read && user_backed_iter(iter))
		dio->flags |= DIO_SHOULD_DIRTY;

	blk_start_plug(&plug);

	for (;;) {
		bio->bi_iter.bi_sector = pos >> SECTOR_SHIFT;
		bio->bi_private = dio;
		bio->bi_end_io = blkdev_bio_end_io;
		bio->bi_ioprio = iocb->ki_ioprio;

		ret = bio_iov_iter_get_pages(bio, iter);
		if (unlikely(ret)) {
			bio->bi_status = BLK_STS_IOERR;
			bio_endio(bio);
			break;
		}
		if (iocb->ki_flags & IOCB_NOWAIT) {
			/*
			 * This is nonblocking IO, and we need to allocate
			 * another bio if we have data left to map. As we
			 * cannot guarantee that one of the sub bios will not
			 * fail getting issued FOR NOWAIT and as error results
			 * are coalesced across all of them, be safe and ask for
			 * a retry of this from blocking context.
			 */
			if (unlikely(iov_iter_count(iter))) {
				bio_release_pages(bio, false);
				bio_clear_flag(bio, BIO_REFFED);
				bio_put(bio);
				blk_finish_plug(&plug);
				return -EAGAIN;
			}
			bio->bi_opf |= REQ_NOWAIT;
		}

		if (is_read) {
			if (dio->flags & DIO_SHOULD_DIRTY)
				bio_set_pages_dirty(bio);
		} else {
			task_io_account_write(bio->bi_iter.bi_size);
		}
		dio->size += bio->bi_iter.bi_size;
		pos += bio->bi_iter.bi_size;

		nr_pages = bio_iov_vecs_to_alloc(iter, BIO_MAX_VECS);
		if (!nr_pages) {
			submit_bio(bio);
			break;
		}
		atomic_inc(&dio->ref);
		submit_bio(bio);
		bio = bio_alloc(bdev, nr_pages, opf, GFP_KERNEL);
	}

	blk_finish_plug(&plug);

	if (!is_sync)
		return -EIOCBQUEUED;

	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!READ_ONCE(dio->waiter))
			break;
		blk_io_schedule();
	}
	__set_current_state(TASK_RUNNING);

	if (!ret)
		ret = blk_status_to_errno(dio->bio.bi_status);
	if (likely(!ret))
		ret = dio->size;

	bio_put(&dio->bio);
	return ret;
}

static void blkdev_bio_end_io_async(struct bio *bio)
{
	struct blkdev_dio *dio = container_of(bio, struct blkdev_dio, bio);
	struct kiocb *iocb = dio->iocb;
	ssize_t ret;

	WRITE_ONCE(iocb->private, NULL);

	if (likely(!bio->bi_status)) {
		ret = dio->size;
		iocb->ki_pos += ret;
	} else {
		ret = blk_status_to_errno(bio->bi_status);
	}

	iocb->ki_complete(iocb, ret);

	if (dio->flags & DIO_SHOULD_DIRTY) {
		bio_check_pages_dirty(bio);
	} else {
		bio_release_pages(bio, false);
		bio_put(bio);
	}
}

/* 把iter写入iocb
这函数是异步的bio提交 */
static ssize_t __blkdev_direct_IO_async(struct kiocb *iocb,
					struct iov_iter *iter,
					unsigned int nr_pages)
{
	struct block_device *bdev = I_BDEV(iocb->ki_filp->f_mapping->host);
	bool is_read = iov_iter_rw(iter) == READ;
	blk_opf_t opf = is_read ? REQ_OP_READ : dio_bio_write_op(iocb);
	struct blkdev_dio *dio;
	struct bio *bio;
	loff_t pos = iocb->ki_pos;
	int ret = 0;

	if (blkdev_dio_unaligned(bdev, pos, iter))
		return -EINVAL;

	if (iocb->ki_flags & IOCB_ALLOC_CACHE)
		opf |= REQ_ALLOC_CACHE;
	bio = bio_alloc_bioset(bdev, nr_pages, opf, GFP_KERNEL,
			       &blkdev_dio_pool);
	dio = container_of(bio, struct blkdev_dio, bio);
	dio->flags = 0;
	dio->iocb = iocb;
	bio->bi_iter.bi_sector = pos >> SECTOR_SHIFT;
	bio->bi_end_io = blkdev_bio_end_io_async;
	bio->bi_ioprio = iocb->ki_ioprio;

	if (iov_iter_is_bvec(iter)) {
		/*
		 * Users don't rely on the iterator being in any particular
		 * state for async I/O returning -EIOCBQUEUED, hence we can
		 * avoid expensive iov_iter_advance(). Bypass
		 * bio_iov_iter_get_pages() and set the bvec directly.
		 */
		bio_iov_bvec_set(bio, iter);
	} else {
		ret = bio_iov_iter_get_pages(bio, iter);
		if (unlikely(ret)) {
			bio_put(bio);
			return ret;
		}
	}
	dio->size = bio->bi_iter.bi_size;

	if (is_read) {
		if (user_backed_iter(iter)) {
			dio->flags |= DIO_SHOULD_DIRTY;
			bio_set_pages_dirty(bio);
		}
	} else {
		task_io_account_write(bio->bi_iter.bi_size);
	}

	if (iocb->ki_flags & IOCB_NOWAIT)
		bio->bi_opf |= REQ_NOWAIT;

	if (iocb->ki_flags & IOCB_HIPRI) {
		bio->bi_opf |= REQ_POLLED;
		submit_bio(bio);
		WRITE_ONCE(iocb->private, bio);
	} else {
		submit_bio(bio);
	}
	return -EIOCBQUEUED;
}
/* 块设备的direct IO实现
================
返回成功读取或者写入的数量 */
static ssize_t blkdev_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	unsigned int nr_pages;

	if (!iov_iter_count(iter))
		return 0;

	/*  */
	nr_pages = bio_iov_vecs_to_alloc(iter, BIO_MAX_VECS + 1);
	/* 如果要读写的内容不是很多 */
	if (likely(nr_pages <= BIO_MAX_VECS)) {/* 
	 */
	
	 /* 如果kiocb要求同步读写, __blkdev_direct_IO_simple就把iter的内容页面抽取
	 到一个bio, 然后提交, 等待完成 */
	 if (is_sync_kiocb(iocb))
			return __blkdev_direct_IO_simple(iocb, iter, nr_pages);

		/* 这里是可以异步提交bio */
		return __blkdev_direct_IO_async(iocb, iter, nr_pages);
	}
	return __blkdev_direct_IO(iocb, iter, bio_max_segs(nr_pages));
}

static int blkdev_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	struct block_device *bdev = I_BDEV(inode);
	loff_t isize = i_size_read(inode);

	iomap->bdev = bdev;
	iomap->offset = ALIGN_DOWN(offset, bdev_logical_block_size(bdev));
	if (iomap->offset >= isize)
		return -EIO;
	iomap->type = IOMAP_MAPPED;
	iomap->addr = iomap->offset;
	iomap->length = isize - iomap->offset;
	iomap->flags |= IOMAP_F_BUFFER_HEAD; /* noop for !CONFIG_BUFFER_HEAD */
	return 0;
}

/*  */
static const struct iomap_ops blkdev_iomap_ops = {
	.iomap_begin		= blkdev_iomap_begin,
};

#ifdef CONFIG_BUFFER_HEAD
/*
dev在io过程中的get ref操作
表示dev的某个block与bh建立了映射关联? */
static int blkdev_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh, int create)
{
	bh->b_bdev = I_BDEV(inode);
	bh->b_blocknr = iblock;
	set_buffer_mapped(bh);
	return 0;
}
// bdev的inode mapping的write_page回调
static int blkdev_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, blkdev_get_block, wbc);
}
/* bdev fs的inode的mapping的read folio回调 */
static int blkdev_read_folio(struct file *file, struct folio *folio)
{
	return block_read_full_folio(folio, blkdev_get_block);
}

/* bdev fs的mapping的预读回调 */
static void blkdev_readahead(struct readahead_control *rac)
{
	mpage_readahead(rac, blkdev_get_block);
}

/* bdev fs的write_begin回调 */
static int blkdev_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, struct page **pagep, void **fsdata)
{
	return block_write_begin(mapping, pos, len, pagep, blkdev_get_block);
}

/* bdev fs的write_end的fops回调 */
static int blkdev_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied, struct page *page,
		void *fsdata)
{
	int ret;
	/* 这里把page的相关buffer置脏 */
	ret = block_write_end(file, mapping, pos, len, copied, page, fsdata);

	unlock_page(page);
	put_page(page);

	return ret;
}
//块设备的inode的mapping的ops
/* 块设备的inode的mapping是什么? */
const struct address_space_operations def_blk_aops = {
	/* bdevfs的dirty aops
	在mapping级别设置folio为dirty? */
	.dirty_folio	= block_dirty_folio,
	/*  */
	.invalidate_folio = block_invalidate_folio,
	//读取设备到folio里面
	.read_folio	= blkdev_read_folio,
	/* 预读的fops */
	.readahead	= blkdev_readahead,
	/*  */
	.writepage	= blkdev_writepage,
	/* 写回指定页面 */
	.write_begin	= blkdev_write_begin,
	/*  */
	.write_end	= blkdev_write_end,
	.migrate_folio	= buffer_migrate_folio_norefs,
	.is_dirty_writeback = buffer_check_dirty_writeback,
};
#else /* CONFIG_BUFFER_HEAD */
static int blkdev_read_folio(struct file *file, struct folio *folio)
{
	return iomap_read_folio(folio, &blkdev_iomap_ops);
}

static void blkdev_readahead(struct readahead_control *rac)
{
	iomap_readahead(rac, &blkdev_iomap_ops);
}

static int blkdev_map_blocks(struct iomap_writepage_ctx *wpc,
		struct inode *inode, loff_t offset)
{
	loff_t isize = i_size_read(inode);

	if (WARN_ON_ONCE(offset >= isize))
		return -EIO;
	if (offset >= wpc->iomap.offset &&
	    offset < wpc->iomap.offset + wpc->iomap.length)
		return 0;
	return blkdev_iomap_begin(inode, offset, isize - offset,
				  IOMAP_WRITE, &wpc->iomap, NULL);
}

static const struct iomap_writeback_ops blkdev_writeback_ops = {
	.map_blocks		= blkdev_map_blocks,
};

static int blkdev_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct iomap_writepage_ctx wpc = { };

	return iomap_writepages(mapping, wbc, &wpc, &blkdev_writeback_ops);
}

const struct address_space_operations def_blk_aops = {
	.dirty_folio	= filemap_dirty_folio,
	.release_folio		= iomap_release_folio,
	.invalidate_folio	= iomap_invalidate_folio,
	.read_folio		= blkdev_read_folio,
	.readahead		= blkdev_readahead,
	.writepages		= blkdev_writepages,
	.is_partially_uptodate  = iomap_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
	.migrate_folio		= filemap_migrate_folio,
};
#endif /* CONFIG_BUFFER_HEAD */

/*
块设备的fops的seek回调
 * for a block special file file_inode(file)->i_size is zero
 * so we compute the size by hand (just as in block_read/write above)
 对于块特殊文件file_inode(file)->i_size为零，因此我们手动计算大小（就像上面的block_read/write一样）

 */
static loff_t blkdev_llseek(struct file *file, loff_t offset, int whence)
{
	// 获取vfs file结构体对应的bd_inode
	struct inode *bd_inode = bdev_file_inode(file);
	loff_t retval;

	inode_lock(bd_inode);
	retval = fixed_size_llseek(file, offset, whence, i_size_read(bd_inode));
	inode_unlock(bd_inode);
	return retval;
}
/*  */
static int blkdev_fsync(struct file *filp, loff_t start, loff_t end,
		int datasync)
{
	// 获取vfs file结构体对应的bdev
	struct block_device *bdev = I_BDEV(filp->f_mapping->host);
	int error;

	// 写入并等待范围内的数据
	error = file_write_and_wait_range(filp, start, end);
	if (error)
		return error;

	/*
	 * There is no need to serialise calls to blkdev_issue_flush with
	 * i_mutex and doing so causes performance issues with concurrent
	 * O_SYNC writers to a block device.
	  没有必要使用i_mutex对blkdev_issue_flush的调用进行串行化，这样做会导致
	  对块设备的并发O_SYNC写入的性能问题。
	 */
	error = blkdev_issue_flush(bdev);
	if (error == -EOPNOTSUPP)
		error = 0;

	return error;
}

blk_mode_t file_to_blk_mode(struct file *file)
{
	blk_mode_t mode = 0;

	if (file->f_mode & FMODE_READ)
		mode |= BLK_OPEN_READ;
	if (file->f_mode & FMODE_WRITE)
		mode |= BLK_OPEN_WRITE;
	if (file->private_data)
		mode |= BLK_OPEN_EXCL;
	if (file->f_flags & O_NDELAY)
		mode |= BLK_OPEN_NDELAY;

	/*
	 * If all bits in O_ACCMODE set (aka O_RDWR | O_WRONLY), the floppy
	 * driver has historically allowed ioctls as if the file was opened for
	 * writing, but does not allow and actual reads or writes.
	 */
	if ((file->f_flags & O_ACCMODE) == (O_RDWR | O_WRONLY))
		mode |= BLK_OPEN_WRITE_IOCTL;

	return mode;
}
/* 块设备fops的open回调
------------
打开的过程似乎就是获取设备号(通过inode获得, 这个inode就是/dev/sda的inode?)对应的bdev,然后filp
与设备inode共享mapping */
static int blkdev_open(struct inode *inode, struct file *filp)
{
	struct block_device *bdev;

	/*
	 * Preserve backwards compatibility and allow large file access
	 * even if userspace doesn't ask for it explicitly. Some mkfs
	 * binary needs it. We might want to drop this workaround
	 * during an unstable branch.
	   保持向后兼容性，即使用户空间没有明确要求，也允许大文件访问。
	   一些mkfs二进制文件需要它。我们可能会在不稳定的分支中放弃这个解决方案。
	   ---------------
	   看来确实是/dev/sda之类的文件
	 */
	filp->f_flags |= O_LARGEFILE;
	filp->f_mode |= FMODE_BUF_RASYNC | FMODE_CAN_ODIRECT;

	/*
	 * Use the file private data to store the holder for exclusive openes.
	 * file_to_blk_mode relies on it being present to set BLK_OPEN_EXCL.
	  使用文件私有数据存储独占打开的持有者。
	  file_to_blk_mode依赖于它的存在来设置BLK_OPEN_EXCL。
	 */
	if (filp->f_flags & O_EXCL)
		filp->private_data = filp;
	
	// 通过设备号获取bdev结构体
	bdev = blkdev_get_by_dev(inode->i_rdev, file_to_blk_mode(filp),
				 filp->private_data, NULL);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	if (bdev_nowait(bdev))
		filp->f_mode |= FMODE_NOWAIT;

	filp->f_mapping = bdev->bd_inode->i_mapping;
	filp->f_wb_err = filemap_sample_wb_err(filp->f_mapping);
	return 0;
}
/* 
块设备的fops的release回调
似乎是 */
static int blkdev_release(struct inode *inode, struct file *filp)
{
	/* 
	open的时候filp的mapping指向了bdev的inode的mapping
	这里获得此bdev fs inode对应的bdev
	
	 */
	blkdev_put(I_BDEV(filp->f_mapping->host), filp->private_data);
	return 0;
}

/* 
进程bdevfs的直接IO
=====================
返回的是io成功的数据量
*/
static ssize_t blkdev_direct_write(struct kiocb *iocb, struct iov_iter *from)
{
	size_t count = iov_iter_count(from);
	ssize_t written;

	/* 这里处理范围内mapping的page ,(回写什么的) */
	written = kiocb_invalidate_pages(iocb, count);
	if (written) {
		if (written == -EBUSY)
			return 0;
		return written;
	}

	written = blkdev_direct_IO(iocb, from);
	if (written > 0) {
		/* 如果成功io了一部分 , 这里进行后处理 */
		kiocb_invalidate_post_direct_write(iocb, count);
		iocb->ki_pos += written;
		count -= written;
	}
	if (written != -EIOCBQUEUED)
		iov_iter_revert(from, count - iov_iter_count(from));
	return written;
}

/* bdevfs的write_iter函数的buffer方式(对应于
直接IO)写入数据(用户的from写入到内核的kiocb) */
static ssize_t blkdev_buffered_write(struct kiocb *iocb, struct iov_iter *from)
{
	return iomap_file_buffered_write(iocb, from, &blkdev_iomap_ops);
}

/*
bdevfs的write_iter回调实现

 * Write data to the block device.  Only intended for the block device itself
 * and the raw driver which basically is a fake block device.
 *
 * Does not take i_mutex for the write and thus is not for general purpose
 * use.
 返回非0出错
 */
static ssize_t blkdev_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct block_device *bdev = I_BDEV(file->f_mapping->host);
	struct inode *bd_inode = bdev->bd_inode;
	loff_t size = bdev_nr_bytes(bdev);
	size_t shorted = 0;
	ssize_t ret;

	if (bdev_read_only(bdev))
		return -EPERM;

	if (IS_SWAPFILE(bd_inode) && !is_hibernate_resume_dev(bd_inode->i_rdev))
		return -ETXTBSY;

	if (!iov_iter_count(from))
		return 0;

	if (iocb->ki_pos >= size)
		return -ENOSPC;

	if ((iocb->ki_flags & (IOCB_NOWAIT | IOCB_DIRECT)) == IOCB_NOWAIT)
		return -EOPNOTSUPP;

	size -= iocb->ki_pos;
	if (iov_iter_count(from) > size) {
		shorted = iov_iter_count(from) - size;
		iov_iter_truncate(from, size);
	}

	/* 更新修改时间? */
	ret = file_update_time(file);
	if (ret)
		return ret;

	/*  */
	if (iocb->ki_flags & IOCB_DIRECT) {
		/* 如果要求直接写入, 这里直接写入 */
		ret = blkdev_direct_write(iocb, from);
		if (ret >= 0 && iov_iter_count(from)) /* 直接写入有点问题, 这里fallback */
			ret = direct_write_fallback(iocb, from, ret,
					blkdev_buffered_write(iocb, from));
	} else {
		/* buffer方式写入 (底下调用的是iomap机制 (这样做的fs有多少比例)) */
		ret = blkdev_buffered_write(iocb, from);
	}

	/* ret大于零表示成功写入了一些数据 */
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	iov_iter_reexpand(from, iov_iter_count(from) + shorted);
	return ret;
}
// 块设备fops的read_iter回调
static ssize_t blkdev_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	/* 获取file对应的bdev
	大概过程就是:
	iocb存储了读写的file结构体, file的mapping就是bd_inode的mapping
	然后bd_inode与bdev是一一对应的
	 */
	struct block_device *bdev = I_BDEV(iocb->ki_filp->f_mapping->host);
	loff_t size = bdev_nr_bytes(bdev); // 获取bdev的大小
	loff_t pos = iocb->ki_pos;
	size_t shorted = 0;
	ssize_t ret = 0;
	size_t count;

	// 表示读取的位置超过了bdev的大小?
	if (unlikely(pos + iov_iter_count(to) > size)) {
		if (pos >= size)
			return 0;
		size -= pos;
		shorted = iov_iter_count(to) - size;
		iov_iter_truncate(to, size);
	}

	count = iov_iter_count(to);
	if (!count)
		goto reexpand; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) { // 直接io的读取
		ret = kiocb_write_and_wait(iocb, count);
		if (ret < 0)
			goto reexpand;
		file_accessed(iocb->ki_filp);

		ret = blkdev_direct_IO(iocb, to);
		if (ret >= 0) {
			iocb->ki_pos += ret;
			count -= ret;
		}
		iov_iter_revert(to, count - iov_iter_count(to));
		if (ret < 0 || !count)
			goto reexpand;
	}
	// 从page cache中读取数据page, 拷贝到to
	ret = filemap_read(iocb, to, ret);

reexpand:
	if (unlikely(shorted))
		iov_iter_reexpand(to, iov_iter_count(to) + shorted);
	return ret;
}

#define	BLKDEV_FALLOC_FL_SUPPORTED					\
		(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |		\
		 FALLOC_FL_ZERO_RANGE | FALLOC_FL_NO_HIDE_STALE)

// 看看块设备如何实现fallocate
static long blkdev_fallocate(struct file *file, int mode, loff_t start,
			     loff_t len)
{
	// 获取vfs inode
	struct inode *inode = bdev_file_inode(file);
	// 获取bdev
	struct block_device *bdev = I_BDEV(inode);
	loff_t end = start + len - 1;
	loff_t isize;
	int error;

	/* Fail if we don't recognize the flags. */
	if (mode & ~BLKDEV_FALLOC_FL_SUPPORTED)
		return -EOPNOTSUPP;

	/* Don't go off the end of the device. */
	isize = bdev_nr_bytes(bdev);
	if (start >= isize)
		return -EINVAL;
	if (end >= isize) {
		if (mode & FALLOC_FL_KEEP_SIZE) {
			len = isize - start;
			end = start + len - 1;
		} else
			return -EINVAL;
	}

	/*
	 * Don't allow IO that isn't aligned to logical block size.
	 */
	if ((start | len) & (bdev_logical_block_size(bdev) - 1))
		return -EINVAL;

	filemap_invalidate_lock(inode->i_mapping);

	/*
	 * Invalidate the page cache, including dirty pages, for valid
	 * de-allocate mode calls to fallocate().
	 无效化页面缓存，包括脏页，以便对fallocate()的有效释放模式调用。
	 */
	switch (mode) {
	case FALLOC_FL_ZERO_RANGE:
	case FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE: // 保持文件大小,仅仅分配空间
		error = truncate_bdev_range(bdev, file_to_blk_mode(file), start, end);
		if (error)
			goto fail;

		error = blkdev_issue_zeroout(bdev, start >> SECTOR_SHIFT,
					     len >> SECTOR_SHIFT, GFP_KERNEL,
					     BLKDEV_ZERO_NOUNMAP);
		break;
	case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:
		error = truncate_bdev_range(bdev, file_to_blk_mode(file), start, end);
		if (error)
			goto fail;

		error = blkdev_issue_zeroout(bdev, start >> SECTOR_SHIFT,
					     len >> SECTOR_SHIFT, GFP_KERNEL,
					     BLKDEV_ZERO_NOFALLBACK);
		break;
	case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE | FALLOC_FL_NO_HIDE_STALE:
		error = truncate_bdev_range(bdev, file_to_blk_mode(file), start, end);
		if (error)
			goto fail;

		error = blkdev_issue_discard(bdev, start >> SECTOR_SHIFT,
					     len >> SECTOR_SHIFT, GFP_KERNEL);
		break;
	default:
		error = -EOPNOTSUPP;
	}

 fail:
	filemap_invalidate_unlock(inode->i_mapping);
	return error;
}

//块设备文件的mmap?
static int blkdev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *bd_inode = bdev_file_inode(file);

	if (bdev_read_only(I_BDEV(bd_inode)))
		return generic_file_readonly_mmap(file, vma);
		// 一般的通用的mmap实现
	return generic_file_mmap(file, vma);
}

// 块设备的fops?
/* 这个是/dev/sda的fops回调吗? */
const struct file_operations def_blk_fops = {
	/* 话说也需要看看fops的这些回调是怎么被调用的 */
	.open		= blkdev_open,
	/* 就是put bdev */
	.release	= blkdev_release,
/* 就是一个包装的通用seek实现 */
	.llseek		= blkdev_llseek,
	/* 如果不是直接IO的情况, 就是filemap_read()
	通过pagecache把内容读到iter */
	.read_iter	= blkdev_read_iter,
	/* 分为直接io 或者buffer io(利用iomap机制) */
	.write_iter	= blkdev_write_iter,
	.iopoll		= iocb_bio_iopoll,
	/* 也是一般的mmap实现 */
	.mmap		= blkdev_mmap,
	/* sync块设备 */
	.fsync		= blkdev_fsync,
	// 这个是什么回调
	.unlocked_ioctl	= blkdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_blkdev_ioctl,
#endif
	/* 块设备文件的零拷贝读 */
	.splice_read	= filemap_splice_read,
	.splice_write	= iter_file_splice_write,
	// 块设备的fallocate回调
	.fallocate	= blkdev_fallocate,
};

static __init int blkdev_init(void)
{
	return bioset_init(&blkdev_dio_pool, 4,
				offsetof(struct blkdev_dio, bio),
				BIOSET_NEED_BVECS|BIOSET_PERCPU_CACHE);
}
module_init(blkdev_init);

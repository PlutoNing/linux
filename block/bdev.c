// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright (C) 2016 - 2020 Christoph Hellwig
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/device_cgroup.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/backing-dev.h>
#include <linux/module.h>
#include <linux/blkpg.h>
#include <linux/magic.h>
#include <linux/buffer_head.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/part_stat.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include "../fs/internal.h"
#include "blk.h"
/* bdev fs的inode */
struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
	return container_of(inode, struct bdev_inode, vfs_inode);
}

struct block_device *I_BDEV(struct inode *inode)
{
	return &BDEV_I(inode)->bdev;
}
EXPORT_SYMBOL(I_BDEV);

static void bdev_write_inode(struct block_device *bdev)
{
	struct inode *inode = bdev->bd_inode;
	int ret;

	spin_lock(&inode->i_lock);
	while (inode->i_state & I_DIRTY) {
		spin_unlock(&inode->i_lock);
		ret = write_inode_now(inode, true);
		if (ret)
			pr_warn_ratelimited(
	"VFS: Dirty inode writeback failed for block device %pg (err=%d).\n",
				bdev, ret);
		spin_lock(&inode->i_lock);
	}
	spin_unlock(&inode->i_lock);
}

/* Kill _all_ buffers and pagecache , dirty or not.. */
static void kill_bdev(struct block_device *bdev)
{
	struct address_space *mapping = bdev->bd_inode->i_mapping;

	if (mapping_empty(mapping))
		return;

	invalidate_bh_lrus();
	truncate_inode_pages(mapping, 0);
}

/* Invalidate clean unused buffers and pagecache.
驱逐bdev之前无效化干净的未使用的buffer和pagecache 
 */
void invalidate_bdev(struct block_device *bdev)
{
	struct address_space *mapping = bdev->bd_inode->i_mapping;

	if (mapping->nrpages) {// dev还有pagecache
		invalidate_bh_lrus();
		lru_add_drain_all();	/* make sure all lru add caches are flushed */
		invalidate_mapping_pages(mapping, 0, -1); // 移除全部可以移除的pagecache页面
	}
}
EXPORT_SYMBOL(invalidate_bdev);

/*
难道bdev的mapping也是pagecache吗?里面存储的是什么呢,不会与自己上面fs的文件的pagecache重复吗?
 * Drop all buffers & page cache for given bdev range. This function bails
 * with error if bdev has other exclusive owner (such as filesystem).
   驱逐bdev的范围内的所有buffer和pagecache, 如果bdev有其他独占所有者(例如文件系统), 则返回错误
 */
int truncate_bdev_range(struct block_device *bdev, blk_mode_t mode,
			loff_t lstart, loff_t lend)
{
	/*
	 * If we don't hold exclusive handle for the device, upgrade to it
	 * while we discard the buffer cache to avoid discarding buffers
	 * under live filesystem.
	 如果我们没有独占设备的句柄, 则在丢弃缓冲区缓存时升级它, 以避免在活动文件系统下丢弃缓冲区
	 */
	if (!(mode & BLK_OPEN_EXCL)) {//没有独占
		// 这里等待独占
		int err = bd_prepare_to_claim(bdev, truncate_bdev_range, NULL);
		if (err) // 等待独占失败
			goto invalidate;
	// 好,现在是自己独占了
	}

	// 从pagecache中移除
	truncate_inode_pages_range(bdev->bd_inode->i_mapping, lstart, lend);
	if (!(mode & BLK_OPEN_EXCL))
		bd_abort_claiming(bdev, truncate_bdev_range);
	return 0;

invalidate:
	/*
	 * Someone else has handle exclusively open. Try invalidating instead.
	 * The 'end' argument is inclusive so the rounding is safe.
	   说明有其他人独占打开句柄, 尝试无效化, end参数是包含的, 因此舍入是安全的
	 */
	return invalidate_inode_pages2_range(bdev->bd_inode->i_mapping,
					     lstart >> PAGE_SHIFT,
					     lend >> PAGE_SHIFT);
}

static void set_init_blocksize(struct block_device *bdev)
{
	unsigned int bsize = bdev_logical_block_size(bdev);
	loff_t size = i_size_read(bdev->bd_inode);

	while (bsize < PAGE_SIZE) {
		if (size & bsize)
			break;
		bsize <<= 1;
	}
	bdev->bd_inode->i_blkbits = blksize_bits(bsize);
}

int set_blocksize(struct block_device *bdev, int size)
{
	/* Size must be a power of two, and between 512 and PAGE_SIZE */
	if (size > PAGE_SIZE || size < 512 || !is_power_of_2(size))
		return -EINVAL;

	/* Size cannot be smaller than the size supported by the device */
	if (size < bdev_logical_block_size(bdev))
		return -EINVAL;

	/* Don't change the size if it is same as current */
	if (bdev->bd_inode->i_blkbits != blksize_bits(size)) {
		sync_blockdev(bdev);
		bdev->bd_inode->i_blkbits = blksize_bits(size);
		kill_bdev(bdev);
	}
	return 0;
}

EXPORT_SYMBOL(set_blocksize);

int sb_set_blocksize(struct super_block *sb, int size)
{
	if (set_blocksize(sb->s_bdev, size))
		return 0;
	/* If we get here, we know size is power of two
	 * and it's value is between 512 and PAGE_SIZE */
	sb->s_blocksize = size;
	sb->s_blocksize_bits = blksize_bits(size);
	return sb->s_blocksize;
}

EXPORT_SYMBOL(sb_set_blocksize);

int sb_min_blocksize(struct super_block *sb, int size)
{
	int minsize = bdev_logical_block_size(sb->s_bdev);
	if (size < minsize)
		size = minsize;
	return sb_set_blocksize(sb, size);
}

EXPORT_SYMBOL(sb_min_blocksize);
/* 刷盘 */
int sync_blockdev_nowait(struct block_device *bdev)
{
	if (!bdev)
		return 0;
	return filemap_flush(bdev->bd_inode->i_mapping);
}

EXPORT_SYMBOL_GPL(sync_blockdev_nowait);

/*
	刷新落盘, 设备的脏数据
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
	if (!bdev)
		return 0;
	return filemap_write_and_wait(bdev->bd_inode->i_mapping);
}

EXPORT_SYMBOL(sync_blockdev);

int sync_blockdev_range(struct block_device *bdev, loff_t lstart, loff_t lend)
{
	return filemap_write_and_wait_range(bdev->bd_inode->i_mapping,
			lstart, lend);
}
EXPORT_SYMBOL(sync_blockdev_range);

/**
 * freeze_bdev - lock a filesystem and force it into a consistent state
 * @bdev:	blockdevice to lock
 *
 * If a superblock is found on this device, we take the s_umount semaphore
 * on it to make sure nobody unmounts until the snapshot creation is done.
 * The reference counter (bd_fsfreeze_count) guarantees that only the last
 * unfreeze process can unfreeze the frozen filesystem actually when multiple
 * freeze requests arrive simultaneously. It counts up in freeze_bdev() and
 * count down in thaw_bdev(). When it becomes 0, thaw_bdev() will unfreeze
 * actually.
 */
int freeze_bdev(struct block_device *bdev)
{
	struct super_block *sb;
	int error = 0;

	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (++bdev->bd_fsfreeze_count > 1)
		goto done;

	sb = get_active_super(bdev);
	if (!sb)
		goto sync;
	if (sb->s_op->freeze_super)
		error = sb->s_op->freeze_super(sb, FREEZE_HOLDER_USERSPACE);
	else
		error = freeze_super(sb, FREEZE_HOLDER_USERSPACE);
	deactivate_super(sb);

	if (error) {
		bdev->bd_fsfreeze_count--;
		goto done;
	}
	bdev->bd_fsfreeze_sb = sb;

sync:
	sync_blockdev(bdev);
done:
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	return error;
}
EXPORT_SYMBOL(freeze_bdev);

/**
 * thaw_bdev - unlock filesystem
 * @bdev:	blockdevice to unlock
 *
 * Unlocks the filesystem and marks it writeable again after freeze_bdev().
 */
int thaw_bdev(struct block_device *bdev)
{
	struct super_block *sb;
	int error = -EINVAL;

	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (!bdev->bd_fsfreeze_count)
		goto out;

	error = 0;
	if (--bdev->bd_fsfreeze_count > 0)
		goto out;

	sb = bdev->bd_fsfreeze_sb;
	if (!sb)
		goto out;

	if (sb->s_op->thaw_super)
		error = sb->s_op->thaw_super(sb, FREEZE_HOLDER_USERSPACE);
	else
		error = thaw_super(sb, FREEZE_HOLDER_USERSPACE);
	if (error)
		bdev->bd_fsfreeze_count++;
	else
		bdev->bd_fsfreeze_sb = NULL;
out:
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	return error;
}
EXPORT_SYMBOL(thaw_bdev);

/*
 * pseudo-fs
 */

static  __cacheline_aligned_in_smp DEFINE_MUTEX(bdev_lock);
static struct kmem_cache * bdev_cachep __read_mostly;
/* bdev fs的sb分配inode */
static struct inode *bdev_alloc_inode(struct super_block *sb)
{
	struct bdev_inode *ei = alloc_inode_sb(sb, bdev_cachep, GFP_KERNEL);

	if (!ei)
		return NULL;
	memset(&ei->bdev, 0, sizeof(ei->bdev));
	return &ei->vfs_inode;
}

static void bdev_free_inode(struct inode *inode)
{
	struct block_device *bdev = I_BDEV(inode);

	free_percpu(bdev->bd_stats);
	kfree(bdev->bd_meta_info);

	if (!bdev_is_partition(bdev)) {
		if (bdev->bd_disk && bdev->bd_disk->bdi)
			bdi_put(bdev->bd_disk->bdi);
		kfree(bdev->bd_disk);
	}

	if (MAJOR(bdev->bd_dev) == BLOCK_EXT_MAJOR)
		blk_free_ext_minor(MINOR(bdev->bd_dev));

	kmem_cache_free(bdev_cachep, BDEV_I(inode));
}

static void init_once(void *data)
{
	struct bdev_inode *ei = data;

	inode_init_once(&ei->vfs_inode);
}
// bdev和inode各是什么?
static void bdev_evict_inode(struct inode *inode)
{
	// 释放inode的pagecache
	truncate_inode_pages_final(&inode->i_data);
	// 清理inode的buffer
	invalidate_inode_buffers(inode); /* is it needed here? */
	clear_inode(inode);
}
/*  */
static const struct super_operations bdev_sops = {
	.statfs = simple_statfs,
	/* 从slab取一个 */
	/* 似乎bdevfs 的inode就是借助vfs inode的框架加上了bdev成员 */
	.alloc_inode = bdev_alloc_inode,
	.free_inode = bdev_free_inode,
	.drop_inode = generic_delete_inode,
	// bdev fs删除inode
	.evict_inode = bdev_evict_inode,
};
/* 初始化bdev fs */
static int bd_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, BDEVFS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	fc->s_iflags |= SB_I_CGROUPWB;
	ctx->ops = &bdev_sops;
	return 0;
}
/* bdev的文件系统 */
static struct file_system_type bd_type = {
	.name		= "bdev",
	.init_fs_context = bd_init_fs_context,
	.kill_sb	= kill_anon_super,
};
/* 20250704010312 */
struct super_block *blockdev_superblock __read_mostly;
EXPORT_SYMBOL_GPL(blockdev_superblock);

void __init bdev_cache_init(void)
{
	int err;
	static struct vfsmount *bd_mnt;

	bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
			0, (SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|
				SLAB_MEM_SPREAD|SLAB_ACCOUNT|SLAB_PANIC),
			init_once);

	err = register_filesystem(&bd_type);
	if (err)
		panic("Cannot register bdev pseudo-fs");
	bd_mnt = kern_mount(&bd_type);
	if (IS_ERR(bd_mnt))
		panic("Cannot create bdev pseudo-fs");
	// 保存下这个伪文件系统的sb
	blockdev_superblock = bd_mnt->mnt_sb;   /* For writeback */
}
/* 分配bdev结构体 */
struct block_device *bdev_alloc(struct gendisk *disk, u8 partno)
{
	struct block_device *bdev;
	struct inode *inode;
	//在bdev的伪文件系统上分配一个inode
	inode = new_inode(blockdev_superblock);
	if (!inode)
		return NULL;
	inode->i_mode = S_IFBLK;
	inode->i_rdev = 0;
	//设置块设备inode的mapping的ops
	inode->i_data.a_ops = &def_blk_aops;
	mapping_set_gfp_mask(&inode->i_data, GFP_USER);
	//这个时候的inode实际上是bdev的inode, 所以这里是取出bdev fs inode特有的字段
	bdev = I_BDEV(inode);
	//下面是初始化inode中bdev成员相关的字段
	//初始化对应的bdev的锁
	mutex_init(&bdev->bd_fsfreeze_mutex);
	spin_lock_init(&bdev->bd_size_lock);
	mutex_init(&bdev->bd_holder_lock);
	bdev->bd_partno = partno;
	bdev->bd_inode = inode;
	bdev->bd_queue = disk->queue;
	if (partno)
		bdev->bd_has_submit_bio = disk->part0->bd_has_submit_bio;
	else
		bdev->bd_has_submit_bio = false;
	bdev->bd_stats = alloc_percpu(struct disk_stats);
	if (!bdev->bd_stats) {
		iput(inode);
		return NULL;
	}
	bdev->bd_disk = disk;
	return bdev;
}

void bdev_set_nr_sectors(struct block_device *bdev, sector_t sectors)
{
	spin_lock(&bdev->bd_size_lock);
	i_size_write(bdev->bd_inode, (loff_t)sectors << SECTOR_SHIFT);
	bdev->bd_nr_sectors = sectors;
	spin_unlock(&bdev->bd_size_lock);
}

void bdev_add(struct block_device *bdev, dev_t dev)
{
	bdev->bd_dev = dev;
	bdev->bd_inode->i_rdev = dev;
	bdev->bd_inode->i_ino = dev;
	insert_inode_hash(bdev->bd_inode);
}

/* 这个统计的是什么?
看起来像是bdev fs的全部inode的mapping数量之和 */
long nr_blockdev_pages(void)
{
	struct inode *inode;
	long ret = 0;

	spin_lock(&blockdev_superblock->s_inode_list_lock);
	list_for_each_entry(inode, &blockdev_superblock->s_inodes, i_sb_list)
		ret += inode->i_mapping->nrpages;
	spin_unlock(&blockdev_superblock->s_inode_list_lock);

	return ret;
}

/**
 * bd_may_claim - test whether a block device can be claimed
 测试一个块设备是否可以被claim
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 * @hops: holder ops
 *
 * Test whether @bdev can be claimed by @holder.
 *
 * RETURNS:
 * %true if @bdev can be claimed, %false otherwise.
 */
static bool bd_may_claim(struct block_device *bdev, void *holder,
		const struct blk_holder_ops *hops)
{
	struct block_device *whole = bdev_whole(bdev);

	lockdep_assert_held(&bdev_lock);

	if (bdev->bd_holder) {// 如果已经有holder了
		/*
		 * The same holder can always re-claim.
		 */
		if (bdev->bd_holder == holder) { // 如果是同一个holder
			if (WARN_ON_ONCE(bdev->bd_holder_ops != hops))
				return false;
			return true; // 可以claim
		}
		return false;
	}
	//如果没有holder
	/*
	 * If the whole devices holder is set to bd_may_claim, a partition on
	 * the device is claimed, but not the whole device.
	 */
	if (whole != bdev &&
	    whole->bd_holder && whole->bd_holder != bd_may_claim)
		return false;
	return true;
}

/**
 * bd_prepare_to_claim - claim a block device
 准备claim一个块设备
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 * @hops: holder ops.
 *
 * Claim @bdev.  This function fails if @bdev is already claimed by another
 * holder and waits if another claiming is in progress. return, the caller
 * has ownership of bd_claiming and bd_holder[s].
 * claim @bdev。如果@bdev已经被另一个持有者claim，则此函数将失败，并等待另一个claim完成。
 * RETURNS:
 * 0 if @bdev can be claimed, -EBUSY otherwise.
 */
int bd_prepare_to_claim(struct block_device *bdev, void *holder,
		const struct blk_holder_ops *hops)
{
	struct block_device *whole = bdev_whole(bdev);

	if (WARN_ON_ONCE(!holder))
		return -EINVAL;
retry:
	mutex_lock(&bdev_lock);
	/* if someone else claimed, fail
	已经有其他人claim了,失败
	 
	*/
	if (!bd_may_claim(bdev, holder, hops)) {
		mutex_unlock(&bdev_lock);
		return -EBUSY;
	}

	/* if claiming is already in progress, wait for it to finish
	已经在claiming了,等待claiming完成
	 */
	if (whole->bd_claiming) {
		wait_queue_head_t *wq = bit_waitqueue(&whole->bd_claiming, 0);
		DEFINE_WAIT(wait);

		prepare_to_wait(wq, &wait, TASK_UNINTERRUPTIBLE);
		mutex_unlock(&bdev_lock);
		schedule();
		finish_wait(wq, &wait);
		goto retry;
	}

	/* yay, all mine
	自己可以独占了
	*/
	whole->bd_claiming = holder;
	mutex_unlock(&bdev_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(bd_prepare_to_claim); /* only for the loop driver */
// 清除claiming
static void bd_clear_claiming(struct block_device *whole, void *holder)
{
	lockdep_assert_held(&bdev_lock);
	/* tell others that we're done */
	BUG_ON(whole->bd_claiming != holder);
	whole->bd_claiming = NULL;
	// 唤醒等待claiming的
	wake_up_bit(&whole->bd_claiming, 0);
}

/**
 * bd_finish_claiming - finish claiming of a block device
 * 完成对块设备的claiming
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 * @hops: block device holder operations
 *
 * Finish exclusive open of a block device. Mark the device as exlusively
 * open by the holder and wake up all waiters for exclusive open to finish.
 完成对块设备的独占打开。将设备标记为由持有者独占打开，并唤醒所有等待独占打开完成的线程。
 */
static void bd_finish_claiming(struct block_device *bdev, void *holder,
		const struct blk_holder_ops *hops)
{
	struct block_device *whole = bdev_whole(bdev);

	mutex_lock(&bdev_lock);
	BUG_ON(!bd_may_claim(bdev, holder, hops));
	/*
	 * Note that for a whole device bd_holders will be incremented twice,
	 * and bd_holder will be set to bd_may_claim before being set to holder
	 注意，对于整个设备，bd_holders将增加两次，并且在设置为持有者之前将bd_holder设置为bd_may_claim。
	 */
	whole->bd_holders++;
	whole->bd_holder = bd_may_claim;
	bdev->bd_holders++;
	mutex_lock(&bdev->bd_holder_lock);
	bdev->bd_holder = holder;
	bdev->bd_holder_ops = hops;
	mutex_unlock(&bdev->bd_holder_lock);
	bd_clear_claiming(whole, holder);
	mutex_unlock(&bdev_lock);
}

/**
 * bd_abort_claiming - abort claiming of a block device

 * 中止对块设备的claiming
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 *
 * Abort claiming of a block device when the exclusive open failed. This can be
 * also used when exclusive open is not actually desired and we just needed
 * to block other exclusive openers for a while.
 */
void bd_abort_claiming(struct block_device *bdev, void *holder)
{
	mutex_lock(&bdev_lock);
	bd_clear_claiming(bdev_whole(bdev), holder);
	mutex_unlock(&bdev_lock);
}
EXPORT_SYMBOL(bd_abort_claiming);
// 结束claim
static void bd_end_claim(struct block_device *bdev, void *holder)
{
	struct block_device *whole = bdev_whole(bdev);
	bool unblock = false;

	/*
	 * Release a claim on the device.  The holder fields are protected with
	 * bdev_lock.  open_mutex is used to synchronize disk_holder unlinking.
	 */
	mutex_lock(&bdev_lock);
	WARN_ON_ONCE(bdev->bd_holder != holder);
	WARN_ON_ONCE(--bdev->bd_holders < 0);
	WARN_ON_ONCE(--whole->bd_holders < 0);
	if (!bdev->bd_holders) {
		mutex_lock(&bdev->bd_holder_lock);
		bdev->bd_holder = NULL;
		bdev->bd_holder_ops = NULL;
		mutex_unlock(&bdev->bd_holder_lock);
		if (bdev->bd_write_holder)
			unblock = true;
	}
	if (!whole->bd_holders)
		whole->bd_holder = NULL;
	mutex_unlock(&bdev_lock);

	/*
	 * If this was the last claim, remove holder link and unblock evpoll if
	 * it was a write holder.
	 如果这是最后一个reclaim,则删除持有者链接并解除写持有者的阻塞。
	 */
	if (unblock) {
		disk_unblock_events(bdev->bd_disk);
		bdev->bd_write_holder = false;
	}
}
// 刷新bdev的mapping
static void blkdev_flush_mapping(struct block_device *bdev)
{
	WARN_ON_ONCE(bdev->bd_holders);
	sync_blockdev(bdev);
	kill_bdev(bdev);
	bdev_write_inode(bdev);
}
// 
static int blkdev_get_whole(struct block_device *bdev, blk_mode_t mode)
{
	struct gendisk *disk = bdev->bd_disk;
	int ret;

	if (disk->fops->open) {
		ret = disk->fops->open(disk, mode);
		if (ret) {
			/* avoid ghost partitions on a removed medium */
			if (ret == -ENOMEDIUM &&
			     test_bit(GD_NEED_PART_SCAN, &disk->state))
				bdev_disk_changed(disk, true);
			return ret;
		}
	}

	if (!atomic_read(&bdev->bd_openers))
		set_init_blocksize(bdev);
	if (test_bit(GD_NEED_PART_SCAN, &disk->state))
		bdev_disk_changed(disk, false);
	atomic_inc(&bdev->bd_openers);
	return 0;
}
// 如果是bdev是disk的时候, put的实现
static void blkdev_put_whole(struct block_device *bdev)
{
	if (atomic_dec_and_test(&bdev->bd_openers))
		blkdev_flush_mapping(bdev);
	if (bdev->bd_disk->fops->release)
		bdev->bd_disk->fops->release(bdev->bd_disk);
}
//
static int blkdev_get_part(struct block_device *part, blk_mode_t mode)
{
	struct gendisk *disk = part->bd_disk;
	int ret;

	ret = blkdev_get_whole(bdev_whole(part), mode);
	if (ret)
		return ret;

	ret = -ENXIO;
	if (!bdev_nr_sectors(part))
		goto out_blkdev_put;

	if (!atomic_read(&part->bd_openers)) {
		disk->open_partitions++;
		set_init_blocksize(part);
	}
	atomic_inc(&part->bd_openers);
	return 0;

out_blkdev_put:
	blkdev_put_whole(bdev_whole(part));
	return ret;
}
// 如果是bdev是part的时候, put的实现
static void blkdev_put_part(struct block_device *part)
{
	struct block_device *whole = bdev_whole(part);

	if (atomic_dec_and_test(&part->bd_openers)) {// 说明自己put之后还有人在用
		blkdev_flush_mapping(part);
		whole->bd_disk->open_partitions--;
	}
	blkdev_put_whole(whole);
}

struct block_device *blkdev_get_no_open(dev_t dev)
{
	struct block_device *bdev;
	struct inode *inode;

	inode = ilookup(blockdev_superblock, dev);
	if (!inode && IS_ENABLED(CONFIG_BLOCK_LEGACY_AUTOLOAD)) {
		blk_request_module(dev);
		inode = ilookup(blockdev_superblock, dev);
		if (inode)
			pr_warn_ratelimited(
"block device autoloading is deprecated and will be removed.\n");
	}
	if (!inode)
		return NULL;
		// 如果找到了inode
	/* switch from the inode reference to a device mode one: */
	bdev = &BDEV_I(inode)->bdev;
	if (!kobject_get_unless_zero(&bdev->bd_device.kobj))
		bdev = NULL;
	iput(inode);
	return bdev;
}

void blkdev_put_no_open(struct block_device *bdev)
{
	put_device(&bdev->bd_device);
}
	
/**
 * blkdev_get_by_dev - open a block device by device number
 通过设备号打开一个块设备
 --------------
 块设备的fops的open回调可能会这么调用.
 * @dev: device number of block device to open
 * @mode: open mode (BLK_OPEN_*)
 * @holder: exclusive holder identifier
 holder可能是个file结构体
 * @hops: holder operations
 *
 * Open the block device described by device number @dev. If @holder is not
 * %NULL, the block device is opened with exclusive access.  Exclusive opens may
 * nest for the same @holder.
 *
 * Use this interface ONLY if you really do not have anything better - i.e. when
 * you are behind a truly sucky interface and all you are given is a device
 * number.  Everything else should use blkdev_get_by_path().
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Reference to the block_device on success, ERR_PTR(-errno) on failure.
 */
struct block_device *blkdev_get_by_dev(dev_t dev, blk_mode_t mode, void *holder,
		const struct blk_holder_ops *hops)
{
	bool unblock_events = true;
	struct block_device *bdev;
	struct gendisk *disk;
	int ret;

	ret = devcgroup_check_permission(DEVCG_DEV_BLOCK,
			MAJOR(dev), MINOR(dev),
			((mode & BLK_OPEN_READ) ? DEVCG_ACC_READ : 0) |
			((mode & BLK_OPEN_WRITE) ? DEVCG_ACC_WRITE : 0));
	if (ret)
		return ERR_PTR(ret);

	bdev = blkdev_get_no_open(dev);
	if (!bdev)
		return ERR_PTR(-ENXIO);
	disk = bdev->bd_disk;

	if (holder) {
		mode |= BLK_OPEN_EXCL;
		ret = bd_prepare_to_claim(bdev, holder, hops);
		if (ret)
			goto put_blkdev;
	} else {
		if (WARN_ON_ONCE(mode & BLK_OPEN_EXCL)) {
			ret = -EIO;
			goto put_blkdev;
		}
	}

	disk_block_events(disk);

	mutex_lock(&disk->open_mutex);
	ret = -ENXIO;
	if (!disk_live(disk))
		goto abort_claiming;
	if (!try_module_get(disk->fops->owner))
		goto abort_claiming;
	if (bdev_is_partition(bdev))
		ret = blkdev_get_part(bdev, mode);
	else
		ret = blkdev_get_whole(bdev, mode);
	if (ret)
		goto put_module;
	if (holder) {
		bd_finish_claiming(bdev, holder, hops);

		/*
		 * Block event polling for write claims if requested.  Any write
		 * holder makes the write_holder state stick until all are
		 * released.  This is good enough and tracking individual
		 * writeable reference is too fragile given the way @mode is
		 * used in blkdev_get/put().
		 */
		if ((mode & BLK_OPEN_WRITE) && !bdev->bd_write_holder &&
		    (disk->event_flags & DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE)) {
			bdev->bd_write_holder = true;
			unblock_events = false;
		}
	}
	mutex_unlock(&disk->open_mutex);

	if (unblock_events)
		disk_unblock_events(disk);
	return bdev;
put_module:
	module_put(disk->fops->owner);
abort_claiming:
	if (holder)
		bd_abort_claiming(bdev, holder);
	mutex_unlock(&disk->open_mutex);
	disk_unblock_events(disk);
put_blkdev:
	blkdev_put_no_open(bdev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(blkdev_get_by_dev);

/**
 * blkdev_get_by_path - open a block device by name
 通过名字打开一个块设备
 * @path: path to the block device to open
 * @mode: open mode (BLK_OPEN_*)
 * @holder: exclusive holder identifier
 * @hops: holder operations
 *
 * Open the block device described by the device file at @path.  If @holder is
 * not %NULL, the block device is opened with exclusive access.  Exclusive opens
 * may nest for the same @holder.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Reference to the block_device on success, ERR_PTR(-errno) on failure.
 */
struct block_device *blkdev_get_by_path(const char *path, blk_mode_t mode,
		void *holder, const struct blk_holder_ops *hops)
{
	struct block_device *bdev;
	dev_t dev;
	int error;

	error = lookup_bdev(path, &dev);
	if (error)
		return ERR_PTR(error);

	bdev = blkdev_get_by_dev(dev, mode, holder, hops);
	if (!IS_ERR(bdev) && (mode & BLK_OPEN_WRITE) && bdev_read_only(bdev)) {
		blkdev_put(bdev, holder);
		return ERR_PTR(-EACCES);
	}

	return bdev;
}
EXPORT_SYMBOL(blkdev_get_by_path);
/* put bdev的函数 */
void blkdev_put(struct block_device *bdev, void *holder)
{
	struct gendisk *disk = bdev->bd_disk;

	/*
	 * Sync early if it looks like we're the last one.  If someone else
	 * opens the block device between now and the decrement of bd_openers
	 * then we did a sync that we didn't need to, but that's not the end
	 * of the world and we want to avoid long (could be several minute)
	 * syncs while holding the mutex.
	  早期同步，如果看起来我们是最后一个。如果现在和bd_openers的递减之间有其他人打开了块设备，
	  那么我们做了一个我们不需要的同步，但这并不是世界末日，我们想避免在持有互斥锁时进行长时间（可能是几分钟）的同步。
	 */
	if (atomic_read(&bdev->bd_openers) == 1)
		sync_blockdev(bdev);

	mutex_lock(&disk->open_mutex);
	if (holder)
		bd_end_claim(bdev, holder);

	/*
	 * Trigger event checking and tell drivers to flush MEDIA_CHANGE
	 * event.  This is to ensure detection of media removal commanded
	 * from userland - e.g. eject(1).
	  触发事件检查并告诉驱动程序刷新MEDIA_CHANGE事件。这是为了确保检测到从用户空间命令的介质移除-例如eject(1)。
	 */
	disk_flush_events(disk, DISK_EVENT_MEDIA_CHANGE);

	if (bdev_is_partition(bdev))
		blkdev_put_part(bdev);
	else
		blkdev_put_whole(bdev);
	mutex_unlock(&disk->open_mutex);

	module_put(disk->fops->owner);
	blkdev_put_no_open(bdev);
}
EXPORT_SYMBOL(blkdev_put);

/**
 * lookup_bdev() - Look up a struct block_device by name.
 查找一个块设备
 * @pathname: Name of the block device in the filesystem.
 * @dev: Pointer to the block device's dev_t, if found.
 *
 * Lookup the block device's dev_t at @pathname in the current
 * namespace if possible and return it in @dev.
 * 查找当前命名空间中@pathname处的块设备的dev_t，并将其存储在@dev中。
 * Context: May sleep.
 * Return: 0 if succeeded, negative errno otherwise.
 */
int lookup_bdev(const char *pathname, dev_t *dev)
{
	struct inode *inode;
	struct path path;
	int error;

	if (!pathname || !*pathname)
		return -EINVAL;

	error = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (error)
		return error;
		// 获取inode
	inode = d_backing_inode(path.dentry);
	error = -ENOTBLK;
	if (!S_ISBLK(inode->i_mode))
		goto out_path_put;
	error = -EACCES;
	if (!may_open_dev(&path))
		goto out_path_put;

	*dev = inode->i_rdev;
	error = 0;
out_path_put:
	path_put(&path);
	return error;
}
EXPORT_SYMBOL(lookup_bdev);

/**
 * bdev_mark_dead - mark a block device as dead
 标记块设备为死亡
 * @bdev: block device to operate on
 * @surprise: indicate a surprise removal
 *
 * Tell the file system that this devices or media is dead.  If @surprise is set
 * to %true the device or media is already gone, if not we are preparing for an
 * orderly removal.
 * 告诉文件系统这个设备或介质已经死亡。如果@surprise设置为%true，则设备或介质已经消失，
 * 如果没有，我们正在为有序移除做准备。
 * This calls into the file system, which then typicall syncs out all dirty data
 * and writes back inodes and then invalidates any cached data in the inodes on
 * the file system.  In addition we also invalidate the block device mapping.
 * 这将调用文件系统，然后通常同步所有脏数据并写回inode，然后使文件系统上的inode中的任何缓存数据无效。
 * 此外，我们还使块设备映射无效。
2025年2月14日01:27:18
 */
void bdev_mark_dead(struct block_device *bdev, bool surprise)
{
	mutex_lock(&bdev->bd_holder_lock);
	if (bdev->bd_holder_ops && bdev->bd_holder_ops->mark_dead)
		bdev->bd_holder_ops->mark_dead(bdev, surprise);
	else
		sync_blockdev(bdev); //1. 发起同步
	mutex_unlock(&bdev->bd_holder_lock);

	invalidate_bdev(bdev); //2.无效相关的块设备映射
}
#ifdef CONFIG_DASD_MODULE
/*
 * Drivers should not use this directly, but the DASD driver has historically
 * had a shutdown to offline mode that doesn't actually remove the gendisk
 * that otherwise looks a lot like a safe device removal.
 */
EXPORT_SYMBOL_GPL(bdev_mark_dead);
#endif
/* 执行sync系统调用时，会调用sync_blockdevs函数 */
void sync_bdevs(bool wait)
{
	struct inode *inode, *old_inode = NULL;

	// 遍历块设备的inode链表
	spin_lock(&blockdev_superblock->s_inode_list_lock);
	list_for_each_entry(inode, &blockdev_superblock->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;
		struct block_device *bdev;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW) ||
		    mapping->nrpages == 0) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode); // 获取inode引用计数
		// 获取了inode引用计数后，释放inode锁
		spin_unlock(&inode->i_lock);
		spin_unlock(&blockdev_superblock->s_inode_list_lock);
		/*
		 * We hold a reference to 'inode' so it couldn't have been
		 * removed from s_inodes list while we dropped the
		 * s_inode_list_lock  We cannot iput the inode now as we can
		 * be holding the last reference and we cannot iput it under
		 * s_inode_list_lock. So we keep the reference and iput it
		 * later.
		 我们持有对“inode”的引用，因此在我们释放s_inode_list_lock时，它不能从s_inodes列表中删除
		 我们不能现在释放inode，因为我们可能持有最后一个引用，我们不能在s_inode_list_lock下释放它。
		 因此，我们保留引用并稍后释放它。
		 */
		iput(old_inode);
		old_inode = inode;
		// 获取块设备
		bdev = I_BDEV(inode);

		mutex_lock(&bdev->bd_disk->open_mutex);
		if (!atomic_read(&bdev->bd_openers)) {
			; /* skip */
		} else if (wait) {
			/*
			 * We keep the error status of individual mapping so
			 * that applications can catch the writeback error using
			 * fsync(2). See filemap_fdatawait_keep_errors() for
			 * details.
			 块设备的inode的mapping是什么?
			 */
			filemap_fdatawait_keep_errors(inode->i_mapping);
		} else {
			filemap_fdatawrite(inode->i_mapping);
		}
		mutex_unlock(&bdev->bd_disk->open_mutex);

		spin_lock(&blockdev_superblock->s_inode_list_lock);
	}
	spin_unlock(&blockdev_superblock->s_inode_list_lock);
	iput(old_inode);
}

/*
 * Handle STATX_DIOALIGN for block devices.
 * 解决块设备的DIO对齐问题
 * Note that the inode passed to this is the inode of a block device node file,
 * not the block device's internal inode.  Therefore it is *not* valid to use
 * I_BDEV() here; the block device has to be looked up by i_rdev instead.
 注意传递给此函数的inode是块设备节点文件的inode，而不是块设备的内部inode。因此，
 在这里使用I_BDEV()是*无效的；必须通过i_rdev查找块设备。
 */
void bdev_statx_dioalign(struct inode *inode, struct kstat *stat)
{
	struct block_device *bdev;

	bdev = blkdev_get_no_open(inode->i_rdev);
	if (!bdev)
		return;

	stat->dio_mem_align = bdev_dma_alignment(bdev) + 1;
	stat->dio_offset_align = bdev_logical_block_size(bdev);
	stat->result_mask |= STATX_DIOALIGN;

	blkdev_put_no_open(bdev);
}

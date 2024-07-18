// SPDX-License-Identifier: GPL-2.0-only

#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/backing-dev.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>
#include <trace/events/writeback.h>

struct backing_dev_info noop_backing_dev_info = {
	.name		= "noop",
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK,
};
EXPORT_SYMBOL_GPL(noop_backing_dev_info);

static struct class *bdi_class;

/*
 * bdi_lock protects bdi_tree and updates to bdi_list. bdi_list has RCU
 * reader side locking.
 */
DEFINE_SPINLOCK(bdi_lock);
static u64 bdi_id_cursor;
static struct rb_root bdi_tree = RB_ROOT;
LIST_HEAD(bdi_list);

/* bdi_wq serves all asynchronous writeback tasks */
struct workqueue_struct *bdi_wq;

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/seq_file.h>

static struct dentry *bdi_debug_root;

static void bdi_debug_init(void)
{
	bdi_debug_root = debugfs_create_dir("bdi", NULL);
}

static int bdi_debug_stats_show(struct seq_file *m, void *v)
{
	struct backing_dev_info *bdi = m->private;
	struct bdi_writeback *wb = &bdi->wb;
	unsigned long background_thresh;
	unsigned long dirty_thresh;
	unsigned long wb_thresh;
	unsigned long nr_dirty, nr_io, nr_more_io, nr_dirty_time;
	struct inode *inode;

	nr_dirty = nr_io = nr_more_io = nr_dirty_time = 0;
	spin_lock(&wb->list_lock);
	list_for_each_entry(inode, &wb->b_dirty, i_io_list)
		nr_dirty++;
	list_for_each_entry(inode, &wb->b_io, i_io_list)
		nr_io++;
	list_for_each_entry(inode, &wb->b_more_io, i_io_list)
		nr_more_io++;
	list_for_each_entry(inode, &wb->b_dirty_time, i_io_list)
		if (inode->i_state & I_DIRTY_TIME)
			nr_dirty_time++;
	spin_unlock(&wb->list_lock);

	global_dirty_limits(&background_thresh, &dirty_thresh);
	wb_thresh = wb_calc_thresh(wb, dirty_thresh);

#define K(x) ((x) << (PAGE_SHIFT - 10))
	seq_printf(m,
		   "BdiWriteback:       %10lu kB\n"
		   "BdiReclaimable:     %10lu kB\n"
		   "BdiDirtyThresh:     %10lu kB\n"
		   "DirtyThresh:        %10lu kB\n"
		   "BackgroundThresh:   %10lu kB\n"
		   "BdiDirtied:         %10lu kB\n"
		   "BdiWritten:         %10lu kB\n"
		   "BdiWriteBandwidth:  %10lu kBps\n"
		   "b_dirty:            %10lu\n"
		   "b_io:               %10lu\n"
		   "b_more_io:          %10lu\n"
		   "b_dirty_time:       %10lu\n"
		   "bdi_list:           %10u\n"
		   "state:              %10lx\n",
		   (unsigned long) K(wb_stat(wb, WB_WRITEBACK)),
		   (unsigned long) K(wb_stat(wb, WB_RECLAIMABLE)),
		   K(wb_thresh),
		   K(dirty_thresh),
		   K(background_thresh),
		   (unsigned long) K(wb_stat(wb, WB_DIRTIED)),
		   (unsigned long) K(wb_stat(wb, WB_WRITTEN)),
		   (unsigned long) K(wb->write_bandwidth),
		   nr_dirty,
		   nr_io,
		   nr_more_io,
		   nr_dirty_time,
		   !list_empty(&bdi->bdi_list), bdi->wb.state);
#undef K

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(bdi_debug_stats);

static void bdi_debug_register(struct backing_dev_info *bdi, const char *name)
{
	bdi->debug_dir = debugfs_create_dir(name, bdi_debug_root);

	debugfs_create_file("stats", 0444, bdi->debug_dir, bdi,
			    &bdi_debug_stats_fops);
}

static void bdi_debug_unregister(struct backing_dev_info *bdi)
{
	debugfs_remove_recursive(bdi->debug_dir);
}
#else
static inline void bdi_debug_init(void)
{
}
static inline void bdi_debug_register(struct backing_dev_info *bdi,
				      const char *name)
{
}
static inline void bdi_debug_unregister(struct backing_dev_info *bdi)
{
}
#endif
/*  */
static ssize_t read_ahead_kb_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned long read_ahead_kb;
	ssize_t ret;

	ret = kstrtoul(buf, 10, &read_ahead_kb);
	if (ret < 0)
		return ret;

	bdi->ra_pages = read_ahead_kb >> (PAGE_SHIFT - 10);

	return count;
}

#define K(pages) ((pages) << (PAGE_SHIFT - 10))

#define BDI_SHOW(name, expr)						\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr, char *page)	\
{									\
	struct backing_dev_info *bdi = dev_get_drvdata(dev);		\
									\
	return snprintf(page, PAGE_SIZE-1, "%lld\n", (long long)expr);	\
}									\
static DEVICE_ATTR_RW(name);

BDI_SHOW(read_ahead_kb, K(bdi->ra_pages))
/* 2024年07月18日17:41:06 */
static ssize_t min_ratio_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned int ratio;
	ssize_t ret;

	ret = kstrtouint(buf, 10, &ratio);
	if (ret < 0)
		return ret;

	ret = bdi_set_min_ratio(bdi, ratio);
	if (!ret)
		ret = count;

	return ret;
}
BDI_SHOW(min_ratio, bdi->min_ratio)
/* 2024年07月18日17:40:36

 */
static ssize_t max_ratio_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned int ratio;
	ssize_t ret;

	ret = kstrtouint(buf, 10, &ratio);
	if (ret < 0)
		return ret;

	ret = bdi_set_max_ratio(bdi, ratio);
	if (!ret)
		ret = count;

	return ret;
}
BDI_SHOW(max_ratio, bdi->max_ratio)
/* 2024年07月18日17:28:20 */
static ssize_t stable_pages_required_show(struct device *dev,
					  struct device_attribute *attr,
					  char *page)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);

	return snprintf(page, PAGE_SIZE-1, "%d\n",
			bdi_cap_stable_pages_required(bdi) ? 1 : 0);
}
static DEVICE_ATTR_RO(stable_pages_required);

static struct attribute *bdi_dev_attrs[] = {
	&dev_attr_read_ahead_kb.attr,
	&dev_attr_min_ratio.attr,
	&dev_attr_max_ratio.attr,
	&dev_attr_stable_pages_required.attr,
	NULL,
};
ATTRIBUTE_GROUPS(bdi_dev);
/* 2024年07月18日17:27:49
驱动层面的obj，class那些 */
static __init int bdi_class_init(void)
{
	bdi_class = class_create(THIS_MODULE, "bdi");
	if (IS_ERR(bdi_class))
		return PTR_ERR(bdi_class);

	bdi_class->dev_groups = bdi_dev_groups;
	bdi_debug_init();

	return 0;
}
postcore_initcall(bdi_class_init);

static int bdi_init(struct backing_dev_info *bdi);
/* 2024年07月18日17:27:21
初始化bdi线程 */
static int __init default_bdi_init(void)
{
	int err;

	bdi_wq = alloc_workqueue("writeback", WQ_MEM_RECLAIM | WQ_UNBOUND |
				 WQ_SYSFS, 0);
	if (!bdi_wq)
		return -ENOMEM;

	err = bdi_init(&noop_backing_dev_info);

	return err;
}
subsys_initcall(default_bdi_init);

/*
2024年07月18日17:26:39
这个dwork是什么，todo。
 * This function is used when the first inode for this wb is marked dirty. It
 * wakes-up the corresponding bdi thread which should then take care of the
 * periodic background write-out of dirty inodes. Since the write-out would
 * starts only 'dirty_writeback_interval' centisecs from now anyway, we just
 * set up a timer which wakes the bdi thread up later.
 *
 * Note, we wouldn't bother setting up the timer, but this function is on the
 * fast-path (used by '__mark_inode_dirty()'), so we save few context switches
 * by delaying the wake-up.
 *
 * We have to be careful not to postpone flush work if it is scheduled for
 * earlier. Thus we use queue_delayed_work().
 */
void wb_wakeup_delayed(struct bdi_writeback *wb)
{
	unsigned long timeout;

	timeout = msecs_to_jiffies(dirty_writeback_interval * 10);

	spin_lock_bh(&wb->work_lock);
	if (test_bit(WB_registered, &wb->state))
		queue_delayed_work(bdi_wq, &wb->dwork, timeout);
	spin_unlock_bh(&wb->work_lock);
}

/*
 * Initial write bandwidth: 100 MB/s
 */
#define INIT_BW		(100 << (20 - PAGE_SHIFT))
/* 2024年7月17日23:11:21
2024年07月18日16:36:22
初始化wb */
static int wb_init(struct bdi_writeback *wb, struct backing_dev_info *bdi,
		   int blkcg_id, gfp_t gfp)
{
	int i, err;

	memset(wb, 0, sizeof(*wb));

	if (wb != &bdi->wb)
		bdi_get(bdi);
	wb->bdi = bdi;
	wb->last_old_flush = jiffies;
	INIT_LIST_HEAD(&wb->b_dirty);
	INIT_LIST_HEAD(&wb->b_io);
	INIT_LIST_HEAD(&wb->b_more_io);
	INIT_LIST_HEAD(&wb->b_dirty_time);

	/*  */
	spin_lock_init(&wb->list_lock);

	wb->bw_time_stamp = jiffies;
	wb->balanced_dirty_ratelimit = INIT_BW;
	wb->dirty_ratelimit = INIT_BW;
	wb->write_bandwidth = INIT_BW;
	wb->avg_write_bandwidth = INIT_BW;

	spin_lock_init(&wb->work_lock);
	INIT_LIST_HEAD(&wb->work_list);
	INIT_DELAYED_WORK(&wb->dwork, wb_workfn);
	wb->dirty_sleep = jiffies;
	/*  */
	wb->congested = wb_congested_get_create(bdi, blkcg_id, gfp);
	if (!wb->congested) {
		err = -ENOMEM;
		goto out_put_bdi;
	}

	err = fprop_local_init_percpu(&wb->completions, gfp);
	if (err)
		goto out_put_cong;

	for (i = 0; i < NR_WB_STAT_ITEMS; i++) {
		err = percpu_counter_init(&wb->stat[i], 0, gfp);
		if (err)
			goto out_destroy_stat;
	}

	return 0;

out_destroy_stat:
	while (i--)
		percpu_counter_destroy(&wb->stat[i]);
	fprop_local_destroy_percpu(&wb->completions);
out_put_cong:
	wb_congested_put(wb->congested);
out_put_bdi:
	if (wb != &bdi->wb)
		bdi_put(bdi);
	return err;
}

static void cgwb_remove_from_bdi_list(struct bdi_writeback *wb);

/*
2024年07月18日15:17:53
关闭wb的线程
2024年07月18日16:57:22
移除bdinode，然后刷新dwork。
 * Remove bdi from the global list and shutdown any threads we have running
 */
static void wb_shutdown(struct bdi_writeback *wb)
{
	/* Make sure nobody queues further work */
	spin_lock_bh(&wb->work_lock);
	if (!test_and_clear_bit(WB_registered, &wb->state)) {
		spin_unlock_bh(&wb->work_lock);
		return;
	}
	spin_unlock_bh(&wb->work_lock);

	/* 移除自己连接到bdi的bdi-node */
	cgwb_remove_from_bdi_list(wb);
	/*
	 * Drain work list and shutdown the delayed_work.  !WB_registered
	 * tells wb_workfn() that @wb is dying and its work_list needs to
	 * be drained no matter what.
	 */
	mod_delayed_work(bdi_wq, &wb->dwork, 0);
	/* 还不清楚机制，可否理解为执行最后一次？ */
	flush_delayed_work(&wb->dwork);
	WARN_ON(!list_empty(&wb->work_list));
}
/* 2024年07月18日17:00:48
清除counter，put bdi。
 */
static void wb_exit(struct bdi_writeback *wb)
{
	int i;

	WARN_ON(delayed_work_pending(&wb->dwork));

	for (i = 0; i < NR_WB_STAT_ITEMS; i++)
		percpu_counter_destroy(&wb->stat[i]);

	fprop_local_destroy_percpu(&wb->completions);
	
	wb_congested_put(wb->congested);
	
	if (wb != &wb->bdi->wb)
	/* 如果不是bdi的wb，就说明是关联bdi的wb，自己退出了，页put一下bdi */
		bdi_put(wb->bdi);
}

#ifdef CONFIG_CGROUP_WRITEBACK

#include <linux/memcontrol.h>

/*
 * cgwb_lock protects bdi->cgwb_tree, bdi->cgwb_congested_tree,
 * blkcg->cgwb_list, and memcg->cgwb_list.  bdi->cgwb_tree is also RCU
 * protected.
 */
static DEFINE_SPINLOCK(cgwb_lock);
static struct workqueue_struct *cgwb_release_wq;

/**
2024年7月17日23:13:24
2024年07月18日17:10:33
创建一些cgwb共享的congested stat。
 * wb_congested_get_create - get or create a wb_congested
 * @bdi: associated bdi
 * @blkcg_id: ID of the associated blkcg
 * @gfp: allocation mask
 *
 * Look up the wb_congested for @blkcg_id on @bdi.  If missing, create one.
 * The returned wb_congested has its reference count incremented.  Returns
 * NULL on failure.
 */
struct bdi_writeback_congested *
wb_congested_get_create(struct backing_dev_info *bdi, int blkcg_id, gfp_t gfp)
{
	struct bdi_writeback_congested *new_congested = NULL, *congested;
	struct rb_node **node, *parent;
	unsigned long flags;
retry:
	spin_lock_irqsave(&cgwb_lock, flags);

	node = &bdi->cgwb_congested_tree.rb_node;
	parent = NULL;
	/* 在tree上面查找congested stat */
	while (*node != NULL) {
		parent = *node;
		congested = rb_entry(parent, struct bdi_writeback_congested,
				     rb_node);
		if (congested->blkcg_id < blkcg_id)
			node = &parent->rb_left;
		else if (congested->blkcg_id > blkcg_id)
			node = &parent->rb_right;
		else
			goto found;
	}

	/* 在树上没找到就来到这？ */
	if (new_congested) {
		/* 如果新建了congested stat */
		/* !found and storage for new one already allocated, insert */
		congested = new_congested;
		rb_link_node(&congested->rb_node, parent, node);
		rb_insert_color(&congested->rb_node, &bdi->cgwb_congested_tree);
		spin_unlock_irqrestore(&cgwb_lock, flags);
		return congested;
	}

	spin_unlock_irqrestore(&cgwb_lock, flags);

	/* allocate storage for new one and retry 
	创建新的congested stat*/
	new_congested = kzalloc(sizeof(*new_congested), gfp);
	if (!new_congested)
		return NULL;
	/* 设置相关属性 */
	refcount_set(&new_congested->refcnt, 1);
	new_congested->__bdi = bdi;
	new_congested->blkcg_id = blkcg_id;
	/* 去retry，应该就可以找到了，然后去found */
	goto retry;

found:
/* 如果在tree找到了现成的stat */
	refcount_inc(&congested->refcnt);
	spin_unlock_irqrestore(&cgwb_lock, flags);
/* 这里为什么释放，需要释放吗 */
	kfree(new_congested);
	return congested;
}

/**
2024年07月18日17:08:14
wb来put congested，为0则清理
 * wb_congested_put - put a wb_congested
 * @congested: wb_congested to put
 *
 * Put @congested and destroy it if the refcnt reaches zero.
 */
void wb_congested_put(struct bdi_writeback_congested *congested)
{
	unsigned long flags;

	if (!refcount_dec_and_lock_irqsave(&congested->refcnt, &cgwb_lock, &flags))
		return;

	/* bdi might already have been destroyed leaving @congested unlinked */
	if (congested->__bdi) {
		/*  */
		rb_erase(&congested->rb_node,
			 &congested->__bdi->cgwb_congested_tree);
		congested->__bdi = NULL;
	}

	spin_unlock_irqrestore(&cgwb_lock, flags);
	kfree(congested);
}
/* 2024年07月18日16:53:01 */
static void cgwb_release_workfn(struct work_struct *work)
{
	/* 获得要操作的wb */
	struct bdi_writeback *wb = container_of(work, struct bdi_writeback,
						release_work);
	/* 通过自己的blkcg css获得blkcg（就是containerof获取的），但是自己的blkcg node不是也连了一个blkcg吗 */
	struct blkcg *blkcg = css_to_blkcg(wb->blkcg_css);

	mutex_lock(&wb->bdi->cgwb_release_mutex);
	/* 断联bdi，刷新dwork */
	wb_shutdown(wb);
	css_put(wb->memcg_css);
	css_put(wb->blkcg_css);
	mutex_unlock(&wb->bdi->cgwb_release_mutex);

	/* triggers blkg destruction if cgwb_refcnt becomes zero
	put关联的blkcg， */
	blkcg_cgwb_put(blkcg);

	fprop_local_destroy_percpu(&wb->memcg_completions);
	
	percpu_ref_exit(&wb->refcnt);
	
	wb_exit(wb);
	kfree_rcu(wb, rcu);
}
/* 2024年07月18日16:52:05
好像这种工作，都是异步的。想想也正常，万一谁还在用呢。 */
static void cgwb_release(struct percpu_ref *refcnt)
{
	struct bdi_writeback *wb = container_of(refcnt, struct bdi_writeback,
						refcnt);
	queue_work(cgwb_release_wq, &wb->release_work);
}
/* 2024年07月18日16:03:09
处理bdi的cgwb tree里面的cg wb
清理与memcg，blkcg的连接，还有ref */
static void cgwb_kill(struct bdi_writeback *wb)
{
	lockdep_assert_held(&cgwb_lock);

	WARN_ON(!radix_tree_delete(&wb->bdi->cgwb_tree, wb->memcg_css->id));
	list_del(&wb->memcg_node);
	list_del(&wb->blkcg_node);
	percpu_ref_kill(&wb->refcnt);
}
/* 2024年07月18日15:18:38
2024年07月18日16:51:52
为啥这个简单的功能也要函数 */
static void cgwb_remove_from_bdi_list(struct bdi_writeback *wb)
{
	spin_lock_irq(&cgwb_lock);
	/* 移除 */
	list_del_rcu(&wb->bdi_node);
	spin_unlock_irq(&cgwb_lock);
}

/* 2024年7月17日23:06:50
2024年07月18日16:47:25
创建cgwb，并进行相应的初始化和连接 */
static int cgwb_create(struct backing_dev_info *bdi,
		       struct cgroup_subsys_state *memcg_css, gfp_t gfp)
{
	struct mem_cgroup *memcg;
	struct cgroup_subsys_state *blkcg_css;
	struct blkcg *blkcg;
	struct list_head *memcg_cgwb_list, *blkcg_cgwb_list;
	struct bdi_writeback *wb;
	unsigned long flags;
	int ret = 0;

	memcg = mem_cgroup_from_css(memcg_css);
	blkcg_css = cgroup_get_e_css(memcg_css->cgroup, &io_cgrp_subsys);
	/* 怎么保证一定有blkcg呢 */
	blkcg = css_to_blkcg(blkcg_css);
	memcg_cgwb_list = &memcg->cgwb_list;
	blkcg_cgwb_list = &blkcg->cgwb_list;


	/* look up again under lock and discard on blkcg mismatch */
	spin_lock_irqsave(&cgwb_lock, flags);
	/* 2024年7月17日23:09:59为什么又查一遍，不是wb_get_create刚才没查到来到这的吗 */
	wb = radix_tree_lookup(&bdi->cgwb_tree, memcg_css->id);
	if (wb && wb->blkcg_css != blkcg_css) {
		/* 查到了，但是不匹配，清理？
		就是断开此wb的cg链接和ref */
		cgwb_kill(wb);
		wb = NULL;
	}
	spin_unlock_irqrestore(&cgwb_lock, flags);



	if (wb)
	/* 还是查到了匹配得了，可能是race情况下创建的吧 */
		goto out_put;

	/* need to create a new one
	开始自己创建 */
	wb = kmalloc(sizeof(*wb), gfp);
	if (!wb) {
		ret = -ENOMEM;
		goto out_put;
	}
	/* 艰难的初始化，todo，2024年7月17日23:14:26 */
	ret = wb_init(wb, bdi, blkcg_css->id, gfp);
	if (ret)
		goto err_free;

	ret = percpu_ref_init(&wb->refcnt, cgwb_release, 0, gfp);
	if (ret)
		goto err_wb_exit;

	ret = fprop_local_init_percpu(&wb->memcg_completions, gfp);
	if (ret)
		goto err_ref_exit;
	/* 关联cg */
	wb->memcg_css = memcg_css;
	wb->blkcg_css = blkcg_css;
	INIT_WORK(&wb->release_work, cgwb_release_workfn);
	set_bit(WB_registered, &wb->state);

	/*
	 * The root wb determines the registered state of the whole bdi and
	 * memcg_cgwb_list and blkcg_cgwb_list's next pointers indicate
	 * whether they're still online.  Don't link @wb if any is dead.
	 * See wb_memcg_offline() and wb_blkcg_offline().
	 */
	ret = -ENODEV;


	/* 下面这一块是吧新建的wb与全局的设施进行链接吗，
	bdi的cgwb树，bdi，全局cg链表。 */
	spin_lock_irqsave(&cgwb_lock, flags);
	if (test_bit(WB_registered, &bdi->wb.state) &&
	    blkcg_cgwb_list->next && memcg_cgwb_list->next) {
		/* we might have raced another instance of this function
		race情况 */
		ret = radix_tree_insert(&bdi->cgwb_tree, memcg_css->id, wb);
		if (!ret) {
			list_add_tail_rcu(&wb->bdi_node, &bdi->wb_list);
			list_add(&wb->memcg_node, memcg_cgwb_list);
			list_add(&wb->blkcg_node, blkcg_cgwb_list);
			blkcg_cgwb_get(blkcg);
			css_get(memcg_css);
			css_get(blkcg_css);
		}
	}
	spin_unlock_irqrestore(&cgwb_lock, flags);


	if (ret) {
		if (ret == -EEXIST)
			ret = 0;
		goto err_fprop_exit;
	}
	goto out_put;

err_fprop_exit:
	fprop_local_destroy_percpu(&wb->memcg_completions);
err_ref_exit:
	percpu_ref_exit(&wb->refcnt);
err_wb_exit:
	wb_exit(wb);
err_free:
	kfree(wb);
out_put:
	css_put(blkcg_css);
	return ret;
}

/**
2024年7月17日00:38:10
2024年7月17日23:03:07
查找bdi上面的属于此css的wb
 * wb_get_lookup - get wb for a given memcg
 * @bdi: target bdi
 * @memcg_css: cgroup_subsys_state of the target memcg (must have positive ref)
 *
 * Try to get the wb for @memcg_css on @bdi.  The returned wb has its
 * refcount incremented.
 *
 * This function uses css_get() on @memcg_css and thus expects its refcnt
 * to be positive on invocation.  IOW, rcu_read_lock() protection on
 * @memcg_css isn't enough.  try_get it before calling this function.
 *
 * A wb is keyed by its associated memcg.  As blkcg implicitly enables
 * memcg on the default hierarchy, memcg association is guaranteed to be
 * more specific (equal or descendant to the associated blkcg) and thus can
 * identify both the memcg and blkcg associations.
 *
 * Because the blkcg associated with a memcg may change as blkcg is enabled
 * and disabled closer to root in the hierarchy, each wb keeps track of
 * both the memcg and blkcg associated with it and verifies the blkcg on
 * each lookup.  On mismatch, the existing wb is discarded and a new one is
 * created.
 */
struct bdi_writeback *wb_get_lookup(struct backing_dev_info *bdi,
				    struct cgroup_subsys_state *memcg_css)
{
	struct bdi_writeback *wb;

	if (!memcg_css->parent)
		return &bdi->wb;

	rcu_read_lock();

	wb = radix_tree_lookup(&bdi->cgwb_tree, memcg_css->id);
	if (wb) {
		/* 如果查到了这个memcg的wb已经存在 */
		struct cgroup_subsys_state *blkcg_css;

		/* see whether the blkcg association has changed
		2024年7月17日23:04:15
		哦哦还是通过memcg css获取blkcg css */
		blkcg_css = cgroup_get_e_css(memcg_css->cgroup, &io_cgrp_subsys);
		if (unlikely(wb->blkcg_css != blkcg_css || !wb_tryget(wb)))
			wb = NULL;

		/* 获取之后立即put？
		2024年7月17日23:04:35
		为什么立即put呢 */
		css_put(blkcg_css);
	}

	rcu_read_unlock();

	return wb;
}

/**
2024年7月17日23:00:53
查找现成的，或者创建
2024年07月18日16:46:31
在bdi上面获取属于此memcg css的wb
 * wb_get_create - get wb for a given memcg, create if necessary
 * @bdi: target bdi
 * @memcg_css: cgroup_subsys_state of the target memcg (must have positive ref)
 * @gfp: allocation mask to use
 *
 * Try to get the wb for @memcg_css on @bdi.  If it doesn't exist, try to
 * create one.  See wb_get_lookup() for more details.
 */
struct bdi_writeback *wb_get_create(struct backing_dev_info *bdi,
				    struct cgroup_subsys_state *memcg_css,
				    gfp_t gfp)
{
	struct bdi_writeback *wb;

	might_sleep_if(gfpflags_allow_blocking(gfp));

	if (!memcg_css->parent)
	/* root？ 就使用全局的，也就是设备自己的wb*/
		return &bdi->wb;
	/* 不是root的话，好像每个memcg有自己对应的wb？2024年7月17日23:02:13
	 */
	do {
		/* 看来是每个css和bdi都有特定的wb，存储在bdi的cgwb tree里面2024年07月18日16:41:18 */
		wb = wb_get_lookup(bdi, memcg_css);
		/* 这个while循环看起来只是为了重试？不涉及层次关系？ */
	} while (!wb && 
	/* 没有查到现成的wb，创建这个memcg css对应的wb？ */
	!cgwb_create(bdi, memcg_css, gfp));

	return wb;
}
/* 
2024年07月18日16:35:09
初始化bdi的cgwb */
static int cgwb_bdi_init(struct backing_dev_info *bdi)
{
	int ret;

	INIT_RADIX_TREE(&bdi->cgwb_tree, GFP_ATOMIC);
	bdi->cgwb_congested_tree = RB_ROOT;
	mutex_init(&bdi->cgwb_release_mutex);
	init_rwsem(&bdi->wb_switch_rwsem);
	/* 初始化bdi的wb，话说这个wb到底是什么，特殊在哪，此时wb应该就是一块内存空间2024年07月18日16:36:08 */
	ret = wb_init(&bdi->wb, bdi, 1, GFP_KERNEL);
	
	if (!ret) {
		/* 初始化wb成功。链接memcg和blkcg */
		bdi->wb.memcg_css = &root_mem_cgroup->css;
		bdi->wb.blkcg_css = blkcg_root_css;
	}
	return ret;
}
/* 2024年07月18日15:36:02
好像就是清除tree和list的wb */
static void cgwb_bdi_unregister(struct backing_dev_info *bdi)
{
	struct radix_tree_iter iter;
	void **slot;
	struct bdi_writeback *wb;

	WARN_ON(test_bit(WB_registered, &bdi->wb.state));

	spin_lock_irq(&cgwb_lock);
	/* tree里面是cgroup wb们。 */
	radix_tree_for_each_slot(slot, &bdi->cgwb_tree, &iter, 0)
		/* 断开memcg，blkcg连接 */
		cgwb_kill(*slot);

	spin_unlock_irq(&cgwb_lock);

	mutex_lock(&bdi->cgwb_release_mutex);
	spin_lock_irq(&cgwb_lock);
	while (!list_empty(&bdi->wb_list)) {
		wb = list_first_entry(&bdi->wb_list, struct bdi_writeback,
				      bdi_node);
		spin_unlock_irq(&cgwb_lock);
		wb_shutdown(wb);
		spin_lock_irq(&cgwb_lock);
	}
	spin_unlock_irq(&cgwb_lock);
	mutex_unlock(&bdi->cgwb_release_mutex);
}

/**
2024年7月13日15:04:09

 * wb_memcg_offline - kill all wb's associated with a memcg being offlined
 * @memcg: memcg being offlined
 *
 * Also prevents creation of any new wb's associated with @memcg.
 */
void wb_memcg_offline(struct mem_cgroup *memcg)
{
	struct list_head *memcg_cgwb_list = &memcg->cgwb_list;
	struct bdi_writeback *wb, *next;

	spin_lock_irq(&cgwb_lock);
	list_for_each_entry_safe(wb, next, memcg_cgwb_list, memcg_node)
		cgwb_kill(wb);
	memcg_cgwb_list->next = NULL;	/* prevent new wb's */
	spin_unlock_irq(&cgwb_lock);
}

/**
 * wb_blkcg_offline - kill all wb's associated with a blkcg being offlined
 * @blkcg: blkcg being offlined
 *
 * Also prevents creation of any new wb's associated with @blkcg.
 */
void wb_blkcg_offline(struct blkcg *blkcg)
{
	struct bdi_writeback *wb, *next;

	spin_lock_irq(&cgwb_lock);
	list_for_each_entry_safe(wb, next, &blkcg->cgwb_list, blkcg_node)
		cgwb_kill(wb);
	blkcg->cgwb_list.next = NULL;	/* prevent new wb's */
	spin_unlock_irq(&cgwb_lock);
}

static void cgwb_bdi_exit(struct backing_dev_info *bdi)
{
	struct rb_node *rbn;

	spin_lock_irq(&cgwb_lock);
	while ((rbn = rb_first(&bdi->cgwb_congested_tree))) {
		struct bdi_writeback_congested *congested =
			rb_entry(rbn, struct bdi_writeback_congested, rb_node);

		rb_erase(rbn, &bdi->cgwb_congested_tree);
		congested->__bdi = NULL;	/* mark @congested unlinked */
	}
	spin_unlock_irq(&cgwb_lock);
}
/* 2024年07月18日16:26:41
链接上自己的wb
 */
static void cgwb_bdi_register(struct backing_dev_info *bdi)
{
	spin_lock_irq(&cgwb_lock);
	list_add_tail_rcu(&bdi->wb.bdi_node, &bdi->wb_list);
	spin_unlock_irq(&cgwb_lock);
}

static int __init cgwb_init(void)
{
	/*
	 * There can be many concurrent release work items overwhelming
	 * system_wq.  Put them in a separate wq and limit concurrency.
	 * There's no point in executing many of these in parallel.
	 */
	cgwb_release_wq = alloc_workqueue("cgwb_release", 0, 1);
	if (!cgwb_release_wq)
		return -ENOMEM;

	return 0;
}
subsys_initcall(cgwb_init);

#else	/* CONFIG_CGROUP_WRITEBACK */

static int cgwb_bdi_init(struct backing_dev_info *bdi)
{
	int err;

	bdi->wb_congested = kzalloc(sizeof(*bdi->wb_congested), GFP_KERNEL);
	if (!bdi->wb_congested)
		return -ENOMEM;

	refcount_set(&bdi->wb_congested->refcnt, 1);

	err = wb_init(&bdi->wb, bdi, 1, GFP_KERNEL);
	if (err) {
		wb_congested_put(bdi->wb_congested);
		return err;
	}
	return 0;
}

static void cgwb_bdi_unregister(struct backing_dev_info *bdi) { }

static void cgwb_bdi_exit(struct backing_dev_info *bdi)
{
	wb_congested_put(bdi->wb_congested);
}

static void cgwb_bdi_register(struct backing_dev_info *bdi)
{
	list_add_tail_rcu(&bdi->wb.bdi_node, &bdi->wb_list);
}

static void cgwb_remove_from_bdi_list(struct bdi_writeback *wb)
{
	list_del_rcu(&wb->bdi_node);
}

#endif	/* CONFIG_CGROUP_WRITEBACK */
/* 2024年07月18日16:33:59
初始化bdi */
static int bdi_init(struct backing_dev_info *bdi)
{
	int ret;

	bdi->dev = NULL;

	kref_init(&bdi->refcnt);
	bdi->min_ratio = 0;
	bdi->max_ratio = 100;
	bdi->max_prop_frac = FPROP_FRAC_BASE;
	INIT_LIST_HEAD(&bdi->bdi_list);
	INIT_LIST_HEAD(&bdi->wb_list);
	init_waitqueue_head(&bdi->wb_waitq);

	ret = cgwb_bdi_init(bdi);

	return ret;
}
/* 2024年07月18日16:33:40
分配bdi
 */
struct backing_dev_info *bdi_alloc_node(gfp_t gfp_mask, int node_id)
{
	struct backing_dev_info *bdi;

	bdi = kmalloc_node(sizeof(struct backing_dev_info),
			   gfp_mask | __GFP_ZERO, node_id);
	if (!bdi)
		return NULL;

	if (bdi_init(bdi)) {
		kfree(bdi);
		return NULL;
	}
	return bdi;
}
EXPORT_SYMBOL(bdi_alloc_node);
/* 2024年07月18日16:28:33 */
static struct rb_node **bdi_lookup_rb_node(u64 id, struct rb_node **parentp)
{
	struct rb_node **p = &bdi_tree.rb_node;
	struct rb_node *parent = NULL;
	struct backing_dev_info *bdi;

	lockdep_assert_held(&bdi_lock);

	while (*p) {
		parent = *p;
		bdi = rb_entry(parent, struct backing_dev_info, rb_node);

		if (bdi->id > id)
			p = &(*p)->rb_left;
		else if (bdi->id < id)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (parentp)
		*parentp = parent;
	return p;
}

/**
2024年7月13日15:20:27
通过id在红黑树查找来get设备
 * bdi_get_by_id - lookup and get bdi from its id
 * @id: bdi id to lookup
 *
 * Find bdi matching @id and get it.  Returns NULL if the matching bdi
 * doesn't exist or is already unregistered.
 */
struct backing_dev_info *bdi_get_by_id(u64 id)
{
	struct backing_dev_info *bdi = NULL;
	struct rb_node **p;

	spin_lock_bh(&bdi_lock);
	p = bdi_lookup_rb_node(id, NULL);
	if (*p) {
		bdi = rb_entry(*p, struct backing_dev_info, rb_node);
		bdi_get(bdi);
	}
	spin_unlock_bh(&bdi_lock);

	return bdi;
}
/* 2024年07月18日16:26:07
创建设备，注册设备
 */
int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
{
	struct device *dev;
	struct rb_node *parent, **p;

	if (bdi->dev)	/* The driver needs to use separate queues per device */
		return 0;

	dev = device_create_vargs(bdi_class, NULL, MKDEV(0, 0), bdi, fmt, args);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	cgwb_bdi_register(bdi);
	bdi->dev = dev;

	bdi_debug_register(bdi, dev_name(dev));
	set_bit(WB_registered, &bdi->wb.state);

	spin_lock_bh(&bdi_lock);

	bdi->id = ++bdi_id_cursor;

	p = bdi_lookup_rb_node(bdi->id, &parent);
	rb_link_node(&bdi->rb_node, parent, p);
	rb_insert_color(&bdi->rb_node, &bdi_tree);

	list_add_tail_rcu(&bdi->bdi_list, &bdi_list);

	spin_unlock_bh(&bdi_lock);

	trace_writeback_bdi_register(bdi);
	return 0;
}
EXPORT_SYMBOL(bdi_register_va);
/* 2024年07月18日16:25:36
注册设备 */
int bdi_register(struct backing_dev_info *bdi, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = bdi_register_va(bdi, fmt, args);
	va_end(args);
	return ret;
}
EXPORT_SYMBOL(bdi_register);
/* 2024年07月18日16:25:13
owner是什么

 */
int bdi_register_owner(struct backing_dev_info *bdi, struct device *owner)
{
	int rc;

	rc = bdi_register(bdi, "%u:%u", MAJOR(owner->devt), MINOR(owner->devt));
	if (rc)
		return rc;
	/* Leaking owner reference... */
	WARN_ON(bdi->owner);
	bdi->owner = owner;
	get_device(owner);
	return 0;
}
EXPORT_SYMBOL(bdi_register_owner);

/*
2024年07月18日15:16:44
从bdi list移出
 * Remove bdi from bdi_list, and ensure that it is no longer visible
 */
static void bdi_remove_from_list(struct backing_dev_info *bdi)
{
	spin_lock_bh(&bdi_lock);
	rb_erase(&bdi->rb_node, &bdi_tree);
	list_del_rcu(&bdi->bdi_list);
	spin_unlock_bh(&bdi_lock);

	synchronize_rcu_expedited();
}
/* 2024年07月18日15:16:32 */
void bdi_unregister(struct backing_dev_info *bdi)
{
	/* make sure nobody finds us on the bdi_list anymore */
	bdi_remove_from_list(bdi);
	/* 移除bdi-node，刷新dwork */
	wb_shutdown(&bdi->wb);
	/* 清除tree和list的wb */
	cgwb_bdi_unregister(bdi);

	if (bdi->dev) {
		/* 有dev的话 */
		bdi_debug_unregister(bdi);
		device_unregister(bdi->dev);
		bdi->dev = NULL;
	}

	if (bdi->owner) {
		/*  */
		put_device(bdi->owner);
		bdi->owner = NULL;
	}
}
/* 2024年07月18日15:15:22 
释放bdi的回调函数
*/
static void release_bdi(struct kref *ref)
{
	struct backing_dev_info *bdi =
			container_of(ref, struct backing_dev_info, refcnt);

	if (test_bit(WB_registered, &bdi->wb.state))
		bdi_unregister(bdi);

	WARN_ON_ONCE(bdi->dev);
	wb_exit(&bdi->wb);
	cgwb_bdi_exit(bdi);
	kfree(bdi);
}
/* 2024年07月18日15:14:11 */
void bdi_put(struct backing_dev_info *bdi)
{
	/* 减一 */
	kref_put(&bdi->refcnt, release_bdi);
}
EXPORT_SYMBOL(bdi_put);
/* 2024年07月18日14:48:01 */
static wait_queue_head_t congestion_wqh[2] = {
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[0]),
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[1])
	};
/* 2024年07月18日14:49:20
==0说明没有congestion？
2024年07月18日15:09:10
bit = sync ? WB_sync_congested : WB_async_congested;
	if (!test_and_set_bit(bit, &congested->state))
		atomic_inc(&nr_wb_congested[sync]);
值表示发生congestion的wb数量
		 */
static atomic_t nr_wb_congested[2];
/* 2024年07月18日15:12:51
有个wb不阻塞了，唤醒相应队列
 */
void clear_wb_congested(struct bdi_writeback_congested *congested, int sync)
{
	wait_queue_head_t *wqh = &congestion_wqh[sync];
	enum wb_congested_state bit;

	bit = sync ? WB_sync_congested : WB_async_congested;
	if (test_and_clear_bit(bit, &congested->state))
		atomic_dec(&nr_wb_congested[sync]);

	smp_mb__after_atomic();
	if (waitqueue_active(wqh))
		wake_up(wqh);
}


EXPORT_SYMBOL(clear_wb_congested);
/* 2024年07月18日15:06:42
报告wb的阻塞情况，统计到全局数组nr-wb-congestion数组
 */
void set_wb_congested(struct bdi_writeback_congested *congested, int sync)
{
	enum wb_congested_state bit;

	bit = sync ? WB_sync_congested : WB_async_congested;
	if (!test_and_set_bit(bit, &congested->state))
		atomic_inc(&nr_wb_congested[sync]);
}
EXPORT_SYMBOL(set_wb_congested);

/**
2024年07月18日14:57:22
wait一直到bdi不congested
与wait_iff_congested区别？
 * congestion_wait - wait for a backing_dev to become uncongested
 * @sync: SYNC or ASYNC IO
 * @timeout: timeout in jiffies
 *
 * Waits for up to @timeout jiffies for a backing_dev (any backing_dev) to exit
 * write congestion.  If no backing_devs are congested then just wait for the
 * next write to be completed.
 */
long congestion_wait(int sync, long timeout)
{
	long ret;
	unsigned long start = jiffies;
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = &congestion_wqh[sync];

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = io_schedule_timeout(timeout);
	finish_wait(wqh, &wait);

	trace_writeback_congestion_wait(jiffies_to_usecs(timeout),
					jiffies_to_usecs(jiffies - start));

	return ret;
}
EXPORT_SYMBOL(congestion_wait);

/**
2024年07月18日14:47:31
等待一直到拥塞（很多脏页)
 * wait_iff_congested - Conditionally wait for a backing_dev to become uncongested or a 
 pgdat to complete writes
 * @sync: SYNC or ASYNC IO
 * @timeout: timeout in jiffies
 *
 * In the event of a congested backing_dev (any backing_dev) this waits
 * for up to @timeout jiffies for either a BDI to exit congestion of the
 * given @sync queue or a write to complete.
 *
 * The return value is 0 if the sleep is for the full timeout. Otherwise,
 * it is the number of jiffies that were still remaining when the function
 * returned. return_value == timeout implies the function did not sleep.
 */
long wait_iff_congested(int sync, long timeout)
{
	long ret;
	unsigned long start = jiffies;
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = &congestion_wqh[sync];

	/*
	 * If there is no congestion, yield if necessary instead
	 * of sleeping on the congestion queue
	 */
	if (atomic_read(&nr_wb_congested[sync]) == 0) {
		cond_resched();

		/* In case we scheduled, work out time remaining */
		ret = timeout - (jiffies - start);
		if (ret < 0)
		/* 说明超时了 */
			ret = 0;

		goto out;
	}

	/* Sleep until uncongested or a write happens */
	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	/* 是io wait */
	ret = io_schedule_timeout(timeout);
	finish_wait(wqh, &wait);

out:
	trace_writeback_wait_iff_congested(jiffies_to_usecs(timeout),
					jiffies_to_usecs(jiffies - start));

	return ret;
}
EXPORT_SYMBOL(wait_iff_congested);

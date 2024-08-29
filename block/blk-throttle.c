// SPDX-License-Identifier: GPL-2.0
/*
 * Interface for controlling IO bandwidth on a request queue
 *
 * Copyright (C) 2010 Vivek Goyal <vgoyal@redhat.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/blktrace_api.h>
#include <linux/blk-cgroup.h>
#include "blk.h"

/* Max dispatch from a group in 1 round */
static int throtl_grp_quantum = 8;

/* Total max dispatch from all groups in one round */
static int throtl_quantum = 32;

/* Throttling is performed over a slice and after that slice is renewed */
#define DFL_THROTL_SLICE_HD (HZ / 10)
#define DFL_THROTL_SLICE_SSD (HZ / 50)
#define MAX_THROTL_SLICE (HZ)
#define MAX_IDLE_TIME (5L * 1000 * 1000) /* 5 s */
#define MIN_THROTL_BPS (320 * 1024)
#define MIN_THROTL_IOPS (10)
#define DFL_LATENCY_TARGET (-1L)
#define DFL_IDLE_THRESHOLD (0)
#define DFL_HD_BASELINE_LATENCY (4000L) /* 4ms */
#define LATENCY_FILTERED_SSD (0)
/*
 * For HD, very small latency comes from sequential IO. Such IO is helpless to
 * help determine if its IO is impacted by others, hence we ignore the IO
 */
#define LATENCY_FILTERED_HD (1000L) /* 1ms */

static struct blkcg_policy blkcg_policy_throtl;

/* A workqueue to queue throttle related work
blkio throttle的后台线程. */
static struct workqueue_struct *kthrotld_workqueue;

/*
是tg的queued的节点，包含了一些bio
 * To implement hierarchical throttling, throtl_grps form a tree and bios
 * are dispatched upwards level by level until they reach the top and get
 * issued.  When dispatching bios from the children and local group at each
 * level, if the bios are dispatched into a single bio_list, there's a risk
 * of a local or child group which can queue many bios at once filling up
 * the list starving others.
 *
 * To avoid such starvation, dispatched bios are queued separately
 * according to where they came from.  When they are again dispatched to
 * the parent, they're popped in round-robin order so that no single source
 * hogs the dispatch window.
 *
 * throtl_qnode is used to keep the queued bios separated by their sources.
 * Bios are queued to throtl_qnode which in turn is queued to
 * throtl_service_queue and then dispatched in round-robin order.
 *
 * It's also used to track the reference counts on blkg's.  A qnode always
 * belongs to a throtl_grp and gets queued on itself or the parent, so
 * incrementing the reference of the associated throtl_grp when a qnode is
 * queued and decrementing when dequeued is enough to keep the whole blkg
 * tree pinned while bios are in flight.
 */
struct throtl_qnode {
	struct list_head	node;		/* service_queue->queued[] 
	挂载到sq*/
	struct bio_list		bios;		/* queued bios
	包含的bio */
	struct throtl_grp	*tg;		/* 
	指向包含自己的tg   tg this qnode belongs to */
};
/* cgroup io限速的io服务队列？ */
struct throtl_service_queue {
	struct throtl_service_queue *parent_sq;	/* the parent service_queue */

	/*
	 * Bios queued directly to this service_queue or dispatched from
	 * children throtl_grp's.
	 */
	struct list_head	queued[2];	/* throtl_qnode [READ/WRITE]，
	读和写的bio分别挂上去？ */
	unsigned int		nr_queued[2];	/* number of queued bios，
	描述读和写队列的bio的数量 */

	/*
	 * RB tree of active children throtl_grp's, which are sorted by
	 * their ->disptime.
	
	 */
	struct rb_root_cached	pending_tree;	/* RB tree of active tgs
	红黑树的元素是tg
	红黑树的key是时间,__tg->disptime
	有个left元素，可以快取。 */
	unsigned int		nr_pending;	/* # queued in the tree */
	unsigned long		first_pending_disptime;	/* disptime of the first tg */
	struct timer_list	pending_timer;	/* fires on first_pending_disptime
	计时器 */
};

enum tg_state_flags {
	THROTL_TG_PENDING	= 1 << 0,	/* on parent's pending tree */
	THROTL_TG_WAS_EMPTY	= 1 << 1,	/* bio_lists[] became non-empty */
};
/* 通过rbn获取所属的tg。 */
#define rb_entry_tg(node)	rb_entry((node), struct throtl_grp, rb_node)
/*struct throtl_grp里的读写的限速种类 */
enum {
	LIMIT_LOW,
	LIMIT_MAX,
	LIMIT_CNT,
};
/* 
每个限速的group都有一个struct throtl_grp结构，
所有的throtl_grp根据其group的“层级”，组织成一个树状结构(红黑树) */
struct throtl_grp {
	/* must be the first member */
	struct blkg_policy_data pd;

	/* active throtl group service_queue member
	挂载到父sq的pending tree上 */
	struct rb_node rb_node;

	/* throtl_data this group belongs to
	此tg的td */
	struct throtl_data *td;

	/* this group's service queue */
	struct throtl_service_queue service_queue;

	/*
	bio直接给本tg处理的话,会用到qnode_on_self,为了自己的bio和来自孩子的bio
	完全公平.
	qnode_on_parent:如果自己的bio交给父tg处理的话,会用到qnode_on_parent,
	为了保证自己孩子的qnode_on_parent,与父tg的qnode_on_self之间的bio的公平性

	 * qnode_on_self is used when bios are directly queued to this
	 * throtl_grp so that local bios compete fairly with bios
	 * dispatched from children.  qnode_on_parent is used when bios are
	 * dispatched from this throtl_grp into its parent and will compete
	 * with the sibling qnode_on_parents and the parent's
	 * qnode_on_self.
	 todo
	 */
	struct throtl_qnode qnode_on_self[2];
	struct throtl_qnode qnode_on_parent[2];

	/*
	 * Dispatch time in jiffies. This is the estimated time when group
	 * will unthrottle and is ready to dispatch more bio. It is used as
	 * key to sort active groups in service tree.
	 何时处理因限速而没有分发的bio
	 */
	unsigned long disptime;

	unsigned int flags;

	/* are there any throtl rules between this group and td? */
	bool has_rules[2];

	/* internally used bytes per second rate limits
	 一维读、写带宽限制，单位是字节/秒，-1表示没有限制
	  二维表示对读or写的什么东西的限制，比如
	  */
	uint64_t bps[2][LIMIT_CNT];
	/* user configured bps limits */
	uint64_t bps_conf[2][LIMIT_CNT];

	/* internally used IOPS limits
	读、写IOPS限制，-1表示没有限制 */
	unsigned int iops[2][LIMIT_CNT];
	/* user configured IOPS limits */
	unsigned int iops_conf[2][LIMIT_CNT];
	/* 限速是以时间片为单位的，每个时间片的长度是100ms（即HZ/100，存放在全局变量
	throtl_slice中。时间片的起始时间是slice_start，结束时间是slice_end，
	bytes_disp是当前时间片内已经分发的字节数，
	io_disp存放当前时间片内已经分外的IO个数  */
	/* Number of bytes disptached in current slice
	当前slice处理的数据量? */
	uint64_t bytes_disp[2];
	/* Number of bio's dispatched in current slice
	当前slice处理的bio数量? */
	unsigned int io_disp[2];

	unsigned long last_low_overflow_time[2];

	uint64_t last_bytes_disp[2];
	unsigned int last_io_disp[2];

	unsigned long last_check_time;

	unsigned long latency_target; /* us */
	unsigned long latency_target_conf; /* us */
	/* When did we start a new slice
	限速时间片起始和结束值 */
	unsigned long slice_start[2];
	unsigned long slice_end[2];

	unsigned long last_finish_time; /* ns / 1024 */
	unsigned long checked_last_finish_time; /* ns / 1024 */
	unsigned long avg_idletime; /* ns / 1024 */
	unsigned long idletime_threshold; /* us */
	unsigned long idletime_threshold_conf; /* us */

	unsigned int bio_cnt; /* total bios */
	unsigned int bad_bio_cnt; /* bios exceeding latency threshold */
	unsigned long bio_cnt_reset_time;
};

/* We measure latency for request size from <= 4k to >= 1M */
#define LATENCY_BUCKET_SIZE 9
/* td的latency_buckets[2] */
struct latency_bucket {
	unsigned long total_latency; /* ns / 1024 */
	int samples;
};

struct avg_latency_bucket {
	unsigned long latency; /* ns / 1024 */
	bool valid;
};
/* 每个 blkdev 对应一个 throttle data，
保存该 blkdev 的 blk-throttle policy 相关的信息 */
struct throtl_data
{
	/* service tree for active throtl groups
	此dev的sq */
	struct throtl_service_queue service_queue;
	/* 这个是指向rq */
	struct request_queue *queue;

	/* Total Number of queued bios on READ and WRITE lists
	是指还在排队的bio数量? */
	unsigned int nr_queued[2];

	unsigned int throtl_slice;/* 时间片slice长度 */

	/* Work for dispatching throttled bios
	好像是dispatch的后台线程. */
	struct work_struct dispatch_work;
	
	unsigned int limit_index;/* 可能是low max什么的 */
	bool limit_valid[LIMIT_CNT];

	unsigned long low_upgrade_time;
	unsigned long low_downgrade_time;

	unsigned int scale;

	struct latency_bucket tmp_buckets[2][LATENCY_BUCKET_SIZE];
	struct avg_latency_bucket avg_buckets[2][LATENCY_BUCKET_SIZE];

	struct latency_bucket __percpu *latency_buckets[2];
	unsigned long last_calculate_time;
	unsigned long filtered_latency;

	bool track_bio_latency;
};

static void throtl_pending_timer_fn(struct timer_list *t);
/* 获取pd的tg */
static inline struct throtl_grp *pd_to_tg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct throtl_grp, pd) : NULL;
}
/* 获取blkgq关联的tg。
blkgq有个pd数组，不同的pol对应不同的pd，进而查到不同的tg。 */
static inline struct throtl_grp *blkg_to_tg(struct blkcg_gq *blkg)
{
	return pd_to_tg(blkg_to_pd(blkg, &blkcg_policy_throtl));
}
/* 获取tg的blkg */
static inline struct blkcg_gq *tg_to_blkg(struct throtl_grp *tg)
{
	return pd_to_blkg(&tg->pd);
}

/**
获取sq的tg
 * sq_to_tg - return the throl_grp the specified service queue belongs to
 * @sq: the throtl_service_queue of interest
 *
 * Return the throtl_grp @sq belongs to.  If @sq is the top-level one
 * embedded in throtl_data, %NULL is returned.
 */
static struct throtl_grp *sq_to_tg(struct throtl_service_queue *sq)
{
	if (sq && sq->parent_sq)
		return container_of(sq, struct throtl_grp, service_queue);
	else
		return NULL;
}

/**
获取sq的td
 * sq_to_td - return throtl_data the specified service queue belongs to
 * @sq: the throtl_service_queue of interest
 *
 * A service_queue can be embedded in either a throtl_grp or throtl_data.
 * Determine the associated throtl_data accordingly and return it.
 */
static struct throtl_data *sq_to_td(struct throtl_service_queue *sq)
{
	struct throtl_grp *tg = sq_to_tg(sq);

	if (tg)
		return tg->td;
	else
		return container_of(sq, struct throtl_data, service_queue);
}

/*
 * cgroup's limit in LIMIT_MAX is scaled if low limit is set. This scale is to
 * make the IO dispatch more smooth.
 * Scale up: linearly scale up according to lapsed time since upgrade. For
 *           every throtl_slice, the limit scales up 1/2 .low limit till the
 *           limit hits .max limit
 * Scale down: exponentially scale down if a cgroup doesn't hit its .low limit
 */
static uint64_t throtl_adjusted_limit(uint64_t low, struct throtl_data *td)
{
	/* arbitrary value to avoid too big scale */
	if (td->scale < 4096 && time_after_eq(jiffies,
	    td->low_upgrade_time + td->scale * td->throtl_slice))
		td->scale = (jiffies - td->low_upgrade_time) / td->throtl_slice;

	return low + (low >> 1) * td->scale;
}
/* todo
好像是bps,乘时间就是数据量 */
static uint64_t tg_bps_limit(struct throtl_grp *tg, int rw)
{
	struct blkcg_gq *blkg = tg_to_blkg(tg);
	struct throtl_data *td;
	uint64_t ret;

	if (cgroup_subsys_on_dfl(io_cgrp_subsys) && !blkg->parent)
		return U64_MAX;

	td = tg->td;
	ret = tg->bps[rw][td->limit_index];
	if (ret == 0 && td->limit_index == LIMIT_LOW) {/* 低限速=0?
	这个应该是少见的情况 */
		/* intermediate node or iops isn't 0 */
		if (!list_empty(&blkg->blkcg->css.children) ||
		    tg->iops[rw][td->limit_index])
			return U64_MAX;
		else
			return MIN_THROTL_BPS;
	}

	if (td->limit_index == LIMIT_MAX && tg->bps[rw][LIMIT_LOW] &&
	    tg->bps[rw][LIMIT_LOW] != tg->bps[rw][LIMIT_MAX]) {/* 如果这是个限制最大速度,
		并且也有最低速度的限制.
		就返回限制的速度,但是可能要调整一下，返回较小值.
		 */
		uint64_t adjusted;

		adjusted = throtl_adjusted_limit(tg->bps[rw][LIMIT_LOW], td);
		ret = min(tg->bps[rw][LIMIT_MAX], adjusted);
	}

	return ret;
}
/* todo
iops的限制,是个速率变量 */
static unsigned int tg_iops_limit(struct throtl_grp *tg, int rw)
{
	struct blkcg_gq *blkg = tg_to_blkg(tg);
	struct throtl_data *td;
	unsigned int ret;

	if (cgroup_subsys_on_dfl(io_cgrp_subsys) && !blkg->parent)
		return UINT_MAX;

	td = tg->td;
	ret = tg->iops[rw][td->limit_index];
	if (ret == 0 && tg->td->limit_index == LIMIT_LOW) {
		/* intermediate node or bps isn't 0 */
		if (!list_empty(&blkg->blkcg->css.children) ||
		    tg->bps[rw][td->limit_index])
			return UINT_MAX;
		else
			return MIN_THROTL_IOPS;
	}

	if (td->limit_index == LIMIT_MAX && tg->iops[rw][LIMIT_LOW] &&
	    tg->iops[rw][LIMIT_LOW] != tg->iops[rw][LIMIT_MAX]) {
		uint64_t adjusted;

		adjusted = throtl_adjusted_limit(tg->iops[rw][LIMIT_LOW], td);
		if (adjusted > UINT_MAX)
			adjusted = UINT_MAX;
		ret = min_t(unsigned int, tg->iops[rw][LIMIT_MAX], adjusted);
	}
	return ret;
}

#define request_bucket_index(sectors) \
	clamp_t(int, order_base_2(sectors) - 3, 0, LATENCY_BUCKET_SIZE - 1)

/**
 * throtl_log - log debug message via blktrace
 * @sq: the service_queue being reported
 * @fmt: printf format string
 * @args: printf args
 *
 * The messages are prefixed with "throtl BLKG_NAME" if @sq belongs to a
 * throtl_grp; otherwise, just "throtl".
 */
#define throtl_log(sq, fmt, args...)	do {				\
	struct throtl_grp *__tg = sq_to_tg((sq));			\
	struct throtl_data *__td = sq_to_td((sq));			\
									\
	(void)__td;							\
	if (likely(!blk_trace_note_message_enabled(__td->queue)))	\
		break;							\
	if ((__tg)) {							\
		blk_add_cgroup_trace_msg(__td->queue,			\
			tg_to_blkg(__tg)->blkcg, "throtl " fmt, ##args);\
	} else {							\
		blk_add_trace_msg(__td->queue, "throtl " fmt, ##args);	\
	}								\
} while (0)
/* 获取bio的size */
static inline unsigned int throtl_bio_data_size(struct bio *bio)
{
	/* assume it's one sector */
	if (unlikely(bio_op(bio) == REQ_OP_DISCARD))
		return 512;
	return bio->bi_iter.bi_size;
}
/*  */
static void throtl_qnode_init(struct throtl_qnode *qn, struct throtl_grp *tg)
{
	INIT_LIST_HEAD(&qn->node);
	bio_list_init(&qn->bios);
	qn->tg = tg;
}

/**
把bio添加到qn.如果qn是孤儿的话,会把qn挂到queued
 * throtl_qnode_add_bio - add a bio to a throtl_qnode and activate it
 * @bio: bio being added
 * @qn: qnode to add bio to
 * @queued: the service_queue->queued[] list @qn belongs to
 *
 * Add @bio to @qn and put @qn on @queued if it's not already on.
 * @qn->tg's reference count is bumped when @qn is activated.  See the
 * comment on top of throtl_qnode definition for details.
 */
static void throtl_qnode_add_bio(struct bio *bio, struct throtl_qnode *qn,
				 struct list_head *queued)
{
	bio_list_add(&qn->bios, bio);
	if (list_empty(&qn->node)) {/* 把qn挂载到sq */
		list_add_tail(&qn->node, queued);
		blkg_get(tg_to_blkg(qn->tg));
	}
}

/**
从tg里面queued的bio，取下一个。
 * throtl_peek_queued - peek the first bio on a qnode list
 * @queued: the qnode list to peek
 */
static struct bio *throtl_peek_queued(struct list_head *queued)
{
	struct throtl_qnode *qn = list_first_entry(queued, struct throtl_qnode, node);
	struct bio *bio;

	if (list_empty(queued))
		return NULL;
	/* 从tg的queue  */
	bio = bio_list_peek(&qn->bios);
	WARN_ON_ONCE(!bio);
	return bio;
}

/**
从queued(sq->queued[rw])里面取下一个bio,如果所在的qnode取完就空了,
就把qnode的tg赋值到@tg_to_put.
 * throtl_pop_queued - pop the first bio form a qnode list
 * @queued: the qnode list to pop a bio from
 * @tg_to_put: optional out argument for throtl_grp to put
 *
 * Pop the first bio from the qnode list @queued.  After popping, the first
 * qnode is removed from @queued if empty or moved to the end of @queued so
 * that the popping order is round-robin.
 *
 * When the first qnode is removed, its associated throtl_grp should be put
 * too.  If @tg_to_put is NULL, this function automatically puts it;
 * otherwise, *@tg_to_put is set to the throtl_grp to put and the caller is
 * responsible for putting it.
 */
static struct bio *throtl_pop_queued(struct list_head *queued,
				     struct throtl_grp **tg_to_put)
{
	/* 获取第一个qnode */
	struct throtl_qnode *qn = list_first_entry(queued, struct throtl_qnode, node);
	struct bio *bio;

	if (list_empty(queued))
		return NULL;
	/* 从qnode里面取下一个bio */
	bio = bio_list_pop(&qn->bios);
	WARN_ON_ONCE(!bio);

	if (bio_list_empty(&qn->bios)) {/* 说明取下之后sq的这个queue就空了? */
	/* 把这个qnode从sq的queue[]移除 */
		list_del_init(&qn->node);
		if (tg_to_put)
			*tg_to_put = qn->tg;
		else
			blkg_put(tg_to_blkg(qn->tg));
	} else {/* 这个qn里面还有bio,就把qn移到后面去,估计可能是为了公平吧.不过这里
	保证的是谁之间的公平,毕竟好像这都是一种bio?只是在不同的qnode而已?todo. */
		list_move_tail(&qn->node, queued);
	}

	return bio;
}

/* 
初始化tg的sq
init a service_queue, assumes the caller zeroed it */
static void throtl_service_queue_init(struct throtl_service_queue *sq)
{
	INIT_LIST_HEAD(&sq->queued[0]);
	INIT_LIST_HEAD(&sq->queued[1]);
	sq->pending_tree = RB_ROOT_CACHED;
	/* 初始化计时器 */
	timer_setup(&sq->pending_timer, throtl_pending_timer_fn, 0);
}
/* 
rq激活某个policy时,给关联的blkgq的pd数组对应槽位分配pd,
pd其实就是tg的一种表示和连接?
这个是分配pd的函数,pd可以理解为tg */
static struct blkg_policy_data *throtl_pd_alloc(gfp_t gfp,
						struct request_queue *q,
						struct blkcg *blkcg)
{
	struct throtl_grp *tg;
	int rw;
	/* 分配一个tg */
	tg = kzalloc_node(sizeof(*tg), gfp, q->node);
	if (!tg)
		return NULL;

	throtl_service_queue_init(&tg->service_queue);

	for (rw = READ; rw <= WRITE; rw++) {/* 分别初始化读写 */
		throtl_qnode_init(&tg->qnode_on_self[rw], tg);
		throtl_qnode_init(&tg->qnode_on_parent[rw], tg);
	}

	RB_CLEAR_NODE(&tg->rb_node);
	tg->bps[READ][LIMIT_MAX] = U64_MAX;
	tg->bps[WRITE][LIMIT_MAX] = U64_MAX;
	tg->iops[READ][LIMIT_MAX] = UINT_MAX;
	tg->iops[WRITE][LIMIT_MAX] = UINT_MAX;
	tg->bps_conf[READ][LIMIT_MAX] = U64_MAX;
	tg->bps_conf[WRITE][LIMIT_MAX] = U64_MAX;
	tg->iops_conf[READ][LIMIT_MAX] = UINT_MAX;
	tg->iops_conf[WRITE][LIMIT_MAX] = UINT_MAX;
	/* LIMIT_LOW will have default value 0 */

	tg->latency_target = DFL_LATENCY_TARGET;
	tg->latency_target_conf = DFL_LATENCY_TARGET;
	tg->idletime_threshold = DFL_IDLE_THRESHOLD;
	tg->idletime_threshold_conf = DFL_IDLE_THRESHOLD;

	return &tg->pd;
}

/* 2024年08月27日19:45:33
 blkcg_policy_throtl这个policy初始化自己pd的方法
pd是对应blkgq里面对应某种policy的东西，
pd自己是tg,算是tg的代表,
sq与td的sq建立联系
tg与rq的td建立关系
 */
static void throtl_pd_init(struct blkg_policy_data *pd)
{
	struct throtl_grp *tg = pd_to_tg(pd);
	/* tg还指向blkgq&q? */
	struct blkcg_gq *blkg = tg_to_blkg(tg);
	struct throtl_data *td = blkg->q->td;
	struct throtl_service_queue *sq = &tg->service_queue;

	/*
	 * If on the default hierarchy, we switch to properly hierarchical
	 * behavior where limits on a given throtl_grp are applied to the
	 * whole subtree rather than just the group itself.  e.g. If 16M
	 * read_bps limit is set on the root group, the whole system can't
	 * exceed 16M for the device.
	 *
	 * If not on the default hierarchy, the broken flat hierarchy
	 * behavior is retained where all throtl_grps are treated as if
	 * they're all separate root groups right below throtl_data.
	 * Limits of a group don't interact with limits of other groups
	 * regardless of the position of the group in the hierarchy.
	 */
	sq->parent_sq = &td->service_queue;
	if (cgroup_subsys_on_dfl(io_cgrp_subsys) && blkg->parent)
		sq->parent_sq = &blkg_to_tg(blkg->parent)->service_queue;
	/* 把tg的td指向tg关联的blkgq的q的td */
	tg->td = td;
}

/*
如果tg或者tg的父级被设置了，就设置has_rules[]。
tg和父tg是通过，所包含的sq父子关系建立联系的。
 * Set has_rules[] if @tg or any of its parents have limits configured.
 * This doesn't require walking up to the top of the hierarchy as the
 * parent's has_rules[] is guaranteed to be correct.
 */
static void tg_update_has_rules(struct throtl_grp *tg)
{
	struct throtl_grp *parent_tg = sq_to_tg(tg->service_queue.parent_sq);
	struct throtl_data *td = tg->td;
	int rw;

	for (rw = READ; rw <= WRITE; rw++)
		tg->has_rules[rw] = (parent_tg && parent_tg->has_rules[rw]) ||
			(    td->limit_valid[td->limit_index] &&
			    (tg_bps_limit(tg, rw) != U64_MAX || tg_iops_limit(tg, rw) != UINT_MAX)
			);
}
/* pd怎么online？
主要操作的是pd的tg。是以pd为句柄的 */
static void throtl_pd_online(struct blkg_policy_data *pd)
{
	struct throtl_grp *tg = pd_to_tg(pd);
	/*
	 * We don't want new groups to escape the limits of its ancestors.
	 * Update has_rules[] after a new group is brought online.
	 */
	tg_update_has_rules(tg);
}
/* 虽然缕了一下过程，但是意义不明，todo2024年8月27日23:25:50 */
static void blk_throtl_update_limit_valid(struct throtl_data *td)
{
	struct cgroup_subsys_state *pos_css;
	struct blkcg_gq *blkg;
	bool low_valid = false;

	rcu_read_lock();
	/* 遍历这个td的rq&blkgq的关联的blkgq&rq。 */
	blkg_for_each_descendant_post(blkg, pos_css, td->queue->root_blkg) {
		/* 获取tg */
		struct throtl_grp *tg = blkg_to_tg(blkg);

		if (tg->bps[READ][LIMIT_LOW] || tg->bps[WRITE][LIMIT_LOW] ||
		    tg->iops[READ][LIMIT_LOW] || tg->iops[WRITE][LIMIT_LOW]) {/* 只要层级上
			还有tg是有效的 */

			low_valid = true;
			break;
		}
	}
	rcu_read_unlock();

	td->limit_valid[LIMIT_LOW] = low_valid;
}

static void throtl_upgrade_state(struct throtl_data *td);
/* 2024年8月27日22:52:27 */
static void throtl_pd_offline(struct blkg_policy_data *pd)
{
	struct throtl_grp *tg = pd_to_tg(pd);

	tg->bps[READ][LIMIT_LOW] = 0;
	tg->bps[WRITE][LIMIT_LOW] = 0;
	tg->iops[READ][LIMIT_LOW] = 0;
	tg->iops[WRITE][LIMIT_LOW] = 0;

	/* 似乎是更新tg的td的有效值，是通过查询层级上还有没有有效值决定的 */
	blk_throtl_update_limit_valid(tg->td);

	if (!tg->td->limit_valid[tg->td->limit_index])
		throtl_upgrade_state(tg->td);
}
/* free此pd
pd链接blkgq和tg,作为tg的代表.
free前的release就是把sq的timer移除? */
static void throtl_pd_free(struct blkg_policy_data *pd)
{
	struct throtl_grp *tg = pd_to_tg(pd);

	del_timer_sync(&tg->service_queue.pending_timer);
	kfree(tg);
}
/* rb_first?
找到sq的rb上面第一个node的tg。
 */
static struct throtl_grp *
throtl_rb_first(struct throtl_service_queue *parent_sq)
{
	struct rb_node *n;
	/* Service tree is empty */
	if (!parent_sq->nr_pending)
		return NULL;

	n = rb_first_cached(&parent_sq->pending_tree);
	WARN_ON_ONCE(!n);

	if (!n)
		return NULL;
	/* 查到rbn，找所属的tg */
	return rb_entry_tg(n);
}
/* 从sq的pending tree移除这个node。*/
static void throtl_rb_erase(struct rb_node *n,
			    struct throtl_service_queue *parent_sq)
{
	rb_erase_cached(n, &parent_sq->pending_tree);

	RB_CLEAR_NODE(n);
	--parent_sq->nr_pending;

}
/* 找到sq的pending tree里面的.最早的tg,把触发时间
赋值到first_pending_disptime */
static void update_min_dispatch_time(struct throtl_service_queue *parent_sq)
{
	struct throtl_grp *tg;

	tg = throtl_rb_first(parent_sq);
	if (!tg)
		return;

	parent_sq->first_pending_disptime = tg->disptime;
}
/* 就是把这个tg,按照自己的disptime,挂载到父sq的pending tree上面. */
static void tg_service_queue_add(struct throtl_grp *tg)
{
	/* tg的父sq */
	struct throtl_service_queue *parent_sq = tg->service_queue.parent_sq;
	struct rb_node **node = &parent_sq->pending_tree.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct throtl_grp *__tg;
	unsigned long key = tg->disptime;
	bool leftmost = true;

	while (*node != NULL) {
		parent = *node;
		__tg = rb_entry_tg(parent);

		if (time_before(key, __tg->disptime))
			node = &parent->rb_left;
		else {
			node = &parent->rb_right;
			leftmost = false;
		}
	}
	/* 挂载到父sq的pending tree上面 */
	rb_link_node(&tg->rb_node, parent, node);
	rb_insert_color_cached(&tg->rb_node, &parent_sq->pending_tree,
			       leftmost);
}
/* 把tg挂到父sq的. 应该是为了触发做准备*/
static void __throtl_enqueue_tg(struct throtl_grp *tg)
{
	tg_service_queue_add(tg);
	tg->flags |= THROTL_TG_PENDING;
	tg->service_queue.parent_sq->nr_pending++;
}

/* 把tg加到父sq的pending tree */
static void throtl_enqueue_tg(struct throtl_grp *tg)
{
	if (!(tg->flags & THROTL_TG_PENDING))
		__throtl_enqueue_tg(tg);
}
/* 
deque tg。
把tg从父sq的pending tree移除。 */
static void __throtl_dequeue_tg(struct throtl_grp *tg)
{
	throtl_rb_erase(&tg->rb_node, tg->service_queue.parent_sq);
	tg->flags &= ~THROTL_TG_PENDING;
}
/* 把tg从父sq的pending移除。 */
static void throtl_dequeue_tg(struct throtl_grp *tg)
{
	if (tg->flags & THROTL_TG_PENDING)
		__throtl_dequeue_tg(tg);
}

/* Call with queue lock held
2024年8月28日23:46:11
这是让出dispatch之前,更新计时器?
把计时器的触发时间设置为expires,但是不会晚于max_expire.
 */
static void throtl_schedule_pending_timer(struct throtl_service_queue *sq,
					  unsigned long expires)
{
	unsigned long max_expire = jiffies + 8 * sq_to_td(sq)->throtl_slice;

	/*
	 * Since we are adjusting the throttle limit dynamically, the sleep
	 * time calculated according to previous limit might be invalid. It's
	 * possible the cgroup sleep time is very long and no other cgroups
	 * have IO running so notify the limit changes. Make sure the cgroup
	 * doesn't sleep too long to avoid the missed notification.
	 */
	if (time_after(expires, max_expire))
		expires = max_expire;
	mod_timer(&sq->pending_timer, expires);
	throtl_log(sq, "schedule timer. delay=%lu jiffies=%lu",
		   expires - jiffies, jiffies);
}

/**
2024年8月28日23:40:40
判断是不是该结束这次dispatch了.
就是找到自己的第一个disptime,如果超时了,就返回false,不然就是true.
反正没超时,可以让出.
 * throtl_schedule_next_dispatch - schedule the next dispatch cycle
 * @sq: the service_queue to schedule dispatch for
 * @force: force scheduling
 *
 * Arm @sq->pending_timer so that the next dispatch cycle starts on the
 * dispatch time of the first pending child.  Returns %true if either timer
 * is armed or there's no pending child left.  %false if the current
 * dispatch window is still open and the caller should continue
 * dispatching.
 *
 * If @force is %true, the dispatch timer is always scheduled and this
 * function is guaranteed to return %true.  This is to be used when the
 * caller can't dispatch itself and needs to invoke pending_timer
 * unconditionally.  Note that forced scheduling is likely to induce short
 * delay before dispatch starts even if @sq->first_pending_disptime is not
 * in the future and thus shouldn't be used in hot paths.
 */
static bool throtl_schedule_next_dispatch(struct throtl_service_queue *sq,
					  bool force)
{
	/* any pending children left? */
	if (!sq->nr_pending)
		return true;
	/* 更新自己的pending tree里面的first disptime. */
	update_min_dispatch_time(sq);

	/* is the next dispatch time in the future? */
	if (force || time_after(sq->first_pending_disptime, jiffies)) {/* 如果第一个触发
	的tg的触发时间是未来的时间,就返回真 */
		/* 这是让出dispatch之前,更新sq的计时器触发时间为first_pending_disptime? */
		throtl_schedule_pending_timer(sq, sq->first_pending_disptime);
		return true;
	}

	/* tell the caller to continue dispatching */
	return false;
}
/* 把tg的新slice设置为[start,jiffies + throtl_slice] */
static inline void throtl_start_new_slice_with_credit(struct throtl_grp *tg,
		bool rw, unsigned long start)
{
	tg->bytes_disp[rw] = 0;
	tg->io_disp[rw] = 0;

	/*
	 * Previous slice has expired. We must have trimmed it after last
	 * bio dispatch. That means since start of last slice, we never used
	 * that bandwidth. Do try to make use of that bandwidth while giving
	 * credit.
	 */
	if (time_after_eq(start, tg->slice_start[rw]))
		tg->slice_start[rw] = start;

	tg->slice_end[rw] = jiffies + tg->td->throtl_slice;
	throtl_log(&tg->service_queue,
		   "[%c] new slice with credit start=%lu end=%lu jiffies=%lu",
		   rw == READ ? 'R' : 'W', tg->slice_start[rw],
		   tg->slice_end[rw], jiffies);
}
/* 如果slice过去了,并且没有未处理的请求了,新开一个slice */
static inline void throtl_start_new_slice(struct throtl_grp *tg, bool rw)
{
	tg->bytes_disp[rw] = 0;
	tg->io_disp[rw] = 0;

	tg->slice_start[rw] = jiffies;
	tg->slice_end[rw] = jiffies + tg->td->throtl_slice;
	throtl_log(&tg->service_queue,
		   "[%c] new slice start=%lu end=%lu jiffies=%lu",
		   rw == READ ? 'R' : 'W', tg->slice_start[rw],
		   tg->slice_end[rw], jiffies);
}
/*  */
static inline void throtl_set_slice_end(struct throtl_grp *tg, bool rw,
					unsigned long jiffy_end)
{
	tg->slice_end[rw] = roundup(jiffy_end, tg->td->throtl_slice);
}
/* 延长当前的slice到@jiffy_end */
static inline void throtl_extend_slice(struct throtl_grp *tg, bool rw,
				       unsigned long jiffy_end)
{
	tg->slice_end[rw] = roundup(jiffy_end, tg->td->throtl_slice);
	throtl_log(&tg->service_queue,
		   "[%c] extend slice start=%lu end=%lu jiffies=%lu",
		   rw == READ ? 'R' : 'W', tg->slice_start[rw],
		   tg->slice_end[rw], jiffies);
}

/* 
判断slice是不是完成了
Determine if previously allocated or extended slice is complete or not */
static bool throtl_slice_used(struct throtl_grp *tg, bool rw)
{
	if (time_in_range(jiffies, tg->slice_start[rw], tg->slice_end[rw]))
		return false;

	return true;
}

/* Trim the used slices and adjust slice start accordingly
tg处理一个bio之后,trim自己的slice
todo,不知道意义何在 */
static inline void throtl_trim_slice(struct throtl_grp *tg, bool rw)
{
	unsigned long nr_slices, time_elapsed, io_trim;
	u64 bytes_trim, tmp;

	BUG_ON(time_before(tg->slice_end[rw], tg->slice_start[rw]));

	/*
	 * If bps are unlimited (-1), then time slice don't get
	 * renewed. Don't try to trim the slice if slice is used. A new
	 * slice will start when appropriate.
	 */
	if (throtl_slice_used(tg, rw))
		return;

	/*
	 * A bio has been dispatched. Also adjust slice_end. It might happen
	 * that initially cgroup limit was very low resulting in high
	 * slice_end, but later limit was bumped up and bio was dispached
	 * sooner, then we need to reduce slice_end. A high bogus slice_end
	 * is bad because it does not allow new slice to start.
	 */

	throtl_set_slice_end(tg, rw, jiffies + tg->td->throtl_slice);

	time_elapsed = jiffies - tg->slice_start[rw];

	nr_slices = time_elapsed / tg->td->throtl_slice;

	if (!nr_slices)
		return;

	tmp = tg_bps_limit(tg, rw) * tg->td->throtl_slice * nr_slices;
	do_div(tmp, HZ);
	bytes_trim = tmp;

	io_trim = (tg_iops_limit(tg, rw) * tg->td->throtl_slice * nr_slices) /
		HZ;

	if (!bytes_trim && !io_trim)
		return;

	if (tg->bytes_disp[rw] >= bytes_trim)
		tg->bytes_disp[rw] -= bytes_trim;
	else
		tg->bytes_disp[rw] = 0;

	if (tg->io_disp[rw] >= io_trim)
		tg->io_disp[rw] -= io_trim;
	else
		tg->io_disp[rw] = 0;

	tg->slice_start[rw] += nr_slices * tg->td->throtl_slice;

	throtl_log(&tg->service_queue,
		   "[%c] trim slice nr=%lu bytes=%llu io=%lu start=%lu end=%lu jiffies=%lu",
		   rw == READ ? 'R' : 'W', nr_slices, bytes_trim, io_trim,
		   tg->slice_start[rw], tg->slice_end[rw], jiffies);
}
/* 计算如果处理这个bio的话,iops会不会超量 */
static bool tg_with_in_iops_limit(struct throtl_grp *tg, struct bio *bio,
				  unsigned long *wait)
{
	bool rw = bio_data_dir(bio);
	unsigned int io_allowed;
	unsigned long jiffy_elapsed, jiffy_wait, jiffy_elapsed_rnd;
	u64 tmp;

	jiffy_elapsed = jiffies - tg->slice_start[rw];

	/* Round up to the next throttle slice, wait time must be nonzero */
	jiffy_elapsed_rnd = roundup(jiffy_elapsed + 1, tg->td->throtl_slice);

	/*
	 * jiffy_elapsed_rnd should not be a big value as minimum iops can be
	 * 1 then at max jiffy elapsed should be equivalent of 1 second as we
	 * will allow dispatch after 1 second and after that slice should
	 * have been trimmed.
	 */

	tmp = (u64)tg_iops_limit(tg, rw) * jiffy_elapsed_rnd;
	do_div(tmp, HZ);

	if (tmp > UINT_MAX)
		io_allowed = UINT_MAX;
	else
		io_allowed = tmp;
	/* 刚刚得出当前允许的iops */

	if (tg->io_disp[rw] + 1 <= io_allowed) {/* 没超当前允许的iops */
		if (wait)
			*wait = 0;
		return true;
	}

	/* Calc approx time to dispatch */
	jiffy_wait = jiffy_elapsed_rnd - jiffy_elapsed;

	if (wait)
		*wait = jiffy_wait;
	return false;
}
/*  判断tg能不能dispatch这个bio*/
static bool tg_with_in_bps_limit(struct throtl_grp *tg, struct bio *bio,
				 unsigned long *wait)
{
	bool rw = bio_data_dir(bio);
	u64 bytes_allowed, extra_bytes, tmp;
	unsigned long jiffy_elapsed, jiffy_wait, jiffy_elapsed_rnd;
	unsigned int bio_size = throtl_bio_data_size(bio);
	/* slice已经过去的时间 */
	jiffy_elapsed = jiffy_elapsed_rnd = jiffies - tg->slice_start[rw];

	/* Slice has just started. Consider one slice interval */
	if (!jiffy_elapsed )
		jiffy_elapsed_rnd = tg->td->throtl_slice;
	/* 向上对齐到throtl_slice整倍数 */
	jiffy_elapsed_rnd = roundup(jiffy_elapsed_rnd, tg->td->throtl_slice);

	tmp = tg_bps_limit(tg, rw) * jiffy_elapsed_rnd;
	do_div(tmp, HZ);
	bytes_allowed = tmp;/* bytes_allowed好像就是按照bps和时间比例计算的此时刻应该
	派发数据量? */

	if (tg->bytes_disp[rw] + bio_size <= bytes_allowed) {/* 说明没超 */
		if (wait)
			*wait = 0;
		return true;
	}

	/* Calc approx time to dispatch 
	下面是计算处理超量的数据的等待时间?*/
	extra_bytes = tg->bytes_disp[rw] + bio_size - bytes_allowed;
	/* 这是超量数据的处理时间,差不多也是数量除以bps的一个逻辑,不过细节
	还是不清楚. */
	jiffy_wait = div64_u64(extra_bytes * HZ, tg_bps_limit(tg, rw));

	if (!jiffy_wait)
		jiffy_wait = 1;

	/*
	 * This wait time is without taking into consideration the rounding
	 * up we did. Add that time also.
	 */
	jiffy_wait = jiffy_wait + (jiffy_elapsed_rnd - jiffy_elapsed);
	if (wait)
		*wait = jiffy_wait;
	return false;
}

/*
2024年8月28日00:41:42
判断tg能不能派发这个刚刚从queued里面取下的bio
 * Returns whether one can dispatch a bio or not. Also returns approx number
 * of jiffies to wait before this bio is with-in IO rate and can be dispatched
 */
static bool tg_may_dispatch(struct throtl_grp *tg, struct bio *bio,
			    unsigned long *wait)
{
	bool rw = bio_data_dir(bio);

	unsigned long bps_wait = 0, iops_wait = 0, max_wait = 0;

	/*
 	 * Currently whole state machine of group depends on first bio
	 * queued in the group bio list. So one should not be calling
	 * this function with a different bio if there are other bios
	 * queued.
	 */
	BUG_ON(tg->service_queue.nr_queued[rw] &&
	       bio != throtl_peek_queued(&tg->service_queue.queued[rw]));

	/* If tg->bps = -1, then BW is unlimited */
	if (tg_bps_limit(tg, rw) == U64_MAX &&
	    tg_iops_limit(tg, rw) == UINT_MAX) {/* 这里好像是说明没有限速 */
		if (wait)
			*wait = 0;
		return true;
	}

	/*
	 * If previous slice expired, start a new one otherwise renew/extend
	 * existing slice to make sure it is at least throtl_slice interval
	 * long since now. New slice is started only for empty throttle group.
	 * If there is queued bio, that means there should be an active
	 * slice and it should be extended instead.
	 */
	if (throtl_slice_used(tg, rw) && !(tg->service_queue.nr_queued[rw]))/* 如果
	slice过去了,并且没有未处理的请求了,新开一个slice */
		throtl_start_new_slice(tg, rw);
	else {/* 这是说明还在旧的slice? */
		if (time_before(tg->slice_end[rw],
		    jiffies + tg->td->throtl_slice))/* 如果已经超时了,就extend? */
			throtl_extend_slice(tg, rw,
				jiffies + tg->td->throtl_slice);
	}

	if (tg_with_in_bps_limit(tg, bio, &bps_wait) &&
	    tg_with_in_iops_limit(tg, bio, &iops_wait)) {/* 如果bps和iops都没超量 */
		if (wait)
			*wait = 0;
		return true;
	}
	/* 得出较大的等待时间.这俩时间是刚才如果会超量的话,需要等待的时间.过了这个时间再处理,才不会超量. */
	max_wait = max(bps_wait, iops_wait);

	if (wait)/* 同样返回需要等待的时间 */
		*wait = max_wait;

	if (time_before(tg->slice_end[rw], jiffies + max_wait))/* 扩展当前的slice,但是为什么可以拓展? */
		throtl_extend_slice(tg, rw, jiffies + max_wait);

	return false;
}
/* blkio的charge相关? 
只是统计而已,不涉及cgroup.*/
static void throtl_charge_bio(struct throtl_grp *tg, struct bio *bio)
{
	bool rw = bio_data_dir(bio);
	unsigned int bio_size = throtl_bio_data_size(bio);

	/* Charge the bio to the group */
	tg->bytes_disp[rw] += bio_size;
	tg->io_disp[rw]++;
	tg->last_bytes_disp[rw] += bio_size;
	tg->last_io_disp[rw]++;

	/*
	 * BIO_THROTTLED is used to prevent the same bio to be throttled
	 * more than once as a throttled bio will go through blk-throtl the
	 * second time when it eventually gets issued.  Set it when a bio
	 * is being charged to a tg.
	 */
	if (!bio_flagged(bio, BIO_THROTTLED))/* 如果没有BIO_THROTTLED,就BIO_THROTTLED */
		bio_set_flag(bio, BIO_THROTTLED);
}

/**
可以用于子tg向父tg传递bio.
把bio加到qn,有可能也把qn加到tg的sq
 * throtl_add_bio_tg - add a bio to the specified throtl_grp
 * @bio: bio to add,
 * @qn: qnode to use,有可能是子tg的qnode_on_parent
 * @tg: the target throtl_grp,有可能是父tg
 *
 * Add @bio to @tg's service_queue using @qn.  If @qn is not specified,
 * tg->qnode_on_self[] is used.
 */
static void throtl_add_bio_tg(struct bio *bio, struct throtl_qnode *qn,
			      struct throtl_grp *tg)
{
	/* 目标sq */
	struct throtl_service_queue *sq = &tg->service_queue;
	/*  */
	bool rw = bio_data_dir(bio);

	if (!qn)
		qn = &tg->qnode_on_self[rw];

	/*
	 * If @tg doesn't currently have any bios queued in the same
	 * direction, queueing @bio can change when @tg should be
	 * dispatched.  Mark that @tg was empty.  This is automatically
	 * cleaered on the next tg_update_disptime().
	 */
	if (!sq->nr_queued[rw])
		tg->flags |= THROTL_TG_WAS_EMPTY;
	/* 把bio加到qn,有可能也把qn加到sq */
	throtl_qnode_add_bio(bio, qn, &sq->queued[rw]);

	sq->nr_queued[rw]++;
	/* enqueue这个tg */
	throtl_enqueue_tg(tg);
}
/* 父sq刚刚从pending tree选择了这个tg进行了触发
现在更新他的disptime,就是下一个bio的触发时间
再pending tree里面找个新位置 */
static void tg_update_disptime(struct throtl_grp *tg)
{
	struct throtl_service_queue *sq = &tg->service_queue;
	unsigned long read_wait = -1, write_wait = -1, min_wait = -1, disptime;
	struct bio *bio;

	bio = throtl_peek_queued(&sq->queued[READ]);
	if (bio)
		tg_may_dispatch(tg, bio, &read_wait);

	bio = throtl_peek_queued(&sq->queued[WRITE]);
	if (bio)
		tg_may_dispatch(tg, bio, &write_wait);
	/* 刚刚两个判断能不能派发这个bio的函数如果判断为不能派发,会把可以派发的
	时间,存储到两个指针参数上*/
	min_wait = min(read_wait, write_wait);
	/* 得出下次派发的事件 */
	disptime = jiffies + min_wait;

	/* Update dispatch time */
	/* 这里是先deque,再更新时间,再enqueue,tg会去到新的位置. */
	throtl_dequeue_tg(tg);
	tg->disptime = disptime;
	throtl_enqueue_tg(tg);

	/* see throtl_add_bio_tg() */
	tg->flags &= ~THROTL_TG_WAS_EMPTY;
}
/* 开始parent_tg的新时间片,以child_tg->slice_start[rw]作为start */
static void start_parent_slice_with_credit(struct throtl_grp *child_tg,
					struct throtl_grp *parent_tg, bool rw)
{
	if (throtl_slice_used(parent_tg, rw)) {/* 如果parent的slice用完了 */
		throtl_start_new_slice_with_credit(parent_tg, rw,
				child_tg->slice_start[rw]);
	}

}
/* tg处理一个bio的执行函数
好像就是交给父sq，然后trim slice */
static void tg_dispatch_one_bio(struct throtl_grp *tg, bool rw)
{
	/* 获取tg的sq */
	struct throtl_service_queue *sq = &tg->service_queue;
	/* 还有父sq */
	struct throtl_service_queue *parent_sq = sq->parent_sq;
	/* tg的父子关系好像是通过sq维护的 */
	struct throtl_grp *parent_tg = sq_to_tg(parent_sq);
	/*  */
	struct throtl_grp *tg_to_put = NULL;
	struct bio *bio;

	/*
	 * @bio is being transferred from @tg to @parent_sq.  Popping a bio
	 * from @tg may put its reference and @parent_sq might end up
	 * getting released prematurely.  Remember the tg to put and put it
	 * after @bio is transferred to @parent_sq.
	 */

	/* 取下一个bio */
	bio = throtl_pop_queued(&sq->queued[rw], &tg_to_put);
	/*  */
	sq->nr_queued[rw]--;
	/* 统计信息 */
	throtl_charge_bio(tg, bio);

	/*
	 * If our parent is another tg, we just need to transfer @bio to
	 * the parent using throtl_add_bio_tg().  If our parent is
	 * @td->service_queue, @bio is ready to be issued.  Put it on its
	 * bio_lists[] and decrease total number queued.  The caller is
	 * responsible for issuing these bios.
	 */
	if (parent_tg) {/*  */
		/* 把bio加到tg->qnode_on_parent[rw],有可能也把tg->qnode_on_parent[rw]
		加到parent_tg的sq .
		再把parent_tg进行enqueue*/
		throtl_add_bio_tg(bio, &tg->qnode_on_parent[rw], parent_tg);
		/* 开启父tg的新slice */
		start_parent_slice_with_credit(tg, parent_tg, rw);
	} else {/* 没有父tg是什么情况 */
		/* 把bio交出去 */
		throtl_qnode_add_bio(bio, &tg->qnode_on_parent[rw],
				     &parent_sq->queued[rw]);
		BUG_ON(tg->td->nr_queued[rw] <= 0);
		tg->td->nr_queued[rw]--;
	}

	/*  */
	throtl_trim_slice(tg, rw);

	if (tg_to_put)
		blkg_put(tg_to_blkg(tg_to_put));
}
/* 处理派发tg的两个queue的一定量的bio */
static int throtl_dispatch_tg(struct throtl_grp *tg)
{
	/* 获取sq */
	struct throtl_service_queue *sq = &tg->service_queue;
	unsigned int nr_reads = 0, nr_writes = 0;
	unsigned int max_nr_reads = throtl_grp_quantum*3/4;
	unsigned int max_nr_writes = throtl_grp_quantum - max_nr_reads;
	struct bio *bio;

	/* Try to dispatch 75% READS and 25% WRITES */

	/* 先处理读的，逐个取下bio */
	while ((bio = throtl_peek_queued(&sq->queued[READ])) &&
	       tg_may_dispatch(tg, bio, NULL)) {/* 如果取下bio了,并且可以派发当前bio
		   就处理 */

		tg_dispatch_one_bio(tg, bio_data_dir(bio));
		nr_reads++;

		if (nr_reads >= max_nr_reads)
			break;
	}

	/* 在处理写的 */
	while ((bio = throtl_peek_queued(&sq->queued[WRITE])) &&
	       tg_may_dispatch(tg, bio, NULL)) {

		tg_dispatch_one_bio(tg, bio_data_dir(bio));
		nr_writes++;

		if (nr_writes >= max_nr_writes)
			break;
	}

	return nr_reads + nr_writes;
}
/* 派发这个sq，通过红黑树找到disptime最优先的tg,进行处理一定量的bio
返回处理的bio数量 */
static int throtl_select_dispatch(struct throtl_service_queue *parent_sq)
{
	unsigned int nr_disp = 0;

	while (1) {
		struct throtl_grp *tg = throtl_rb_first(parent_sq);
		struct throtl_service_queue *sq;

		if (!tg)
			break;

		if (time_before(jiffies, tg->disptime))/* 还没到时间 */
			break;
		/* 这个tg到时间了。把tg从父sq的pending 移除 */
		throtl_dequeue_tg(tg);
		/* 这里开始dispatch */
		nr_disp += throtl_dispatch_tg(tg);

		/* 如果这个tg还有数据,就更新它在pending tree
		的位置,便于继续触发,也保证公平性. */
		sq = &tg->service_queue;
		if (sq->nr_queued[0] || sq->nr_queued[1])
			tg_update_disptime(tg);

		if (nr_disp >= throtl_quantum)/* 达到数量了就
		结束循环 */
			break;
	}

	return nr_disp;
}

static bool throtl_can_upgrade(struct throtl_data *td,
	struct throtl_grp *this_tg);
/**
blkio限速计时器超时的回调函数。
大体逻辑就是顺着sq的父子层级,向上触发每一个sq.

 * throtl_pending_timer_fn - timer function for service_queue->pending_timer
 * @t: the pending_timer member of the throtl_service_queue being serviced
 *
 * This timer is armed when a child throtl_grp with active bio's become
 * pending and queued on the service_queue's pending_tree and expires when
 * the first child throtl_grp should be dispatched.  This function
 * dispatches bio's from the children throtl_grps to the parent
 * service_queue.
 *
 * If the parent's parent is another throtl_grp, dispatching is propagated
 * by either arming its pending_timer or repeating dispatch directly.  If
 * the top-level service_tree is reached, throtl_data->dispatch_work is
 * kicked so that the ready bio's are issued.
 */
static void throtl_pending_timer_fn(struct timer_list *t)
{
	/* 获取timer所属的sq */
	struct throtl_service_queue *sq = from_timer(sq, t, pending_timer);
	/* 获取sq的tg */
	/* container_of */
	struct throtl_grp *tg = sq_to_tg(sq);
	/*  */
	struct throtl_data *td = sq_to_td(sq);

	struct request_queue *q = td->queue;
	struct throtl_service_queue *parent_sq;
	bool dispatched;
	int ret;

	spin_lock_irq(&q->queue_lock);
	if (throtl_can_upgrade(td, NULL))
		throtl_upgrade_state(td);

again:
	parent_sq = sq->parent_sq;
	dispatched = false;

	while (true) {
		throtl_log(sq, "dispatch nr_queued=%u read=%u write=%u",
			   sq->nr_queued[READ] + sq->nr_queued[WRITE],
			   sq->nr_queued[READ], sq->nr_queued[WRITE]);

		ret = throtl_select_dispatch(sq);
		if (ret) {/* 成功处理了一部分数据 */
			throtl_log(sq, "bios disp=%u", ret);
			dispatched = true;
		}

		if (throtl_schedule_next_dispatch(sq, false))/* 如果
		可以结束这次dispatch了,就让出 */
			break;

		/* this dispatch windows is still open, relax and repeat */
		spin_unlock_irq(&q->queue_lock);
		cpu_relax();
		spin_lock_irq(&q->queue_lock);
	}
	/* 结束了一次dispatch */
	if (!dispatched)
		goto out_unlock;

	if (parent_sq) {
		/* @parent_sq is another throl_grp, propagate dispatch
		这里尝试也dispatch 父sq */
		if (tg->flags & THROTL_TG_WAS_EMPTY) {
			/* 首先计算此子tg的disptime,更新在父sq的pending tree
			的位置 */
			tg_update_disptime(tg);
			if (!throtl_schedule_next_dispatch(parent_sq, false)) {/* 然后
			判断父sq是不是也需要触发,需要的话进入if */
				/* window is already open, repeat dispatching */
				sq = parent_sq;
				tg = sq_to_tg(sq);
				goto again;
			}
		}
	} else {
		/* reached the top-level, queue issueing */
		queue_work(kthrotld_workqueue, &td->dispatch_work);
	}

out_unlock:
	spin_unlock_irq(&q->queue_lock);
}

/**
td的dispatch线程的函数.
取下td的sq的bio.进行派发.
 * blk_throtl_dispatch_work_fn - work function for throtl_data->dispatch_work
 * @work: work item being executed
 *
 * This function is queued for execution when bio's reach the bio_lists[]
 * of throtl_data->service_queue.  Those bio's are ready and issued by this
 * function.
 */
static void blk_throtl_dispatch_work_fn(struct work_struct *work)
{
	/* 获取td */
	struct throtl_data *td = container_of(work, struct throtl_data,
					      dispatch_work);
	/* 获取td的sq */
	struct throtl_service_queue *td_sq = &td->service_queue;
	struct request_queue *q = td->queue;
	struct bio_list bio_list_on_stack;
	struct bio *bio;
	struct blk_plug plug;
	int rw;

	bio_list_init(&bio_list_on_stack);

	spin_lock_irq(&q->queue_lock);
	for (rw = READ; rw <= WRITE; rw++)
		while ((bio = throtl_pop_queued(&td_sq->queued[rw], NULL)))/* 成功取下了
	一个bio. */
			bio_list_add(&bio_list_on_stack, bio);
	spin_unlock_irq(&q->queue_lock);

	/*  */
	if (!bio_list_empty(&bio_list_on_stack)) {
		blk_start_plug(&plug);
		while((bio = bio_list_pop(&bio_list_on_stack)))
			generic_make_request(bio);
		blk_finish_plug(&plug);
	}
}

static u64 tg_prfill_conf_u64(struct seq_file *sf, struct blkg_policy_data *pd,
			      int off)
{
	struct throtl_grp *tg = pd_to_tg(pd);
	u64 v = *(u64 *)((void *)tg + off);

	if (v == U64_MAX)
		return 0;
	return __blkg_prfill_u64(sf, pd, v);
}

static u64 tg_prfill_conf_uint(struct seq_file *sf, struct blkg_policy_data *pd,
			       int off)
{
	struct throtl_grp *tg = pd_to_tg(pd);
	unsigned int v = *(unsigned int *)((void *)tg + off);

	if (v == UINT_MAX)
		return 0;
	return __blkg_prfill_u64(sf, pd, v);
}

static int tg_print_conf_u64(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), tg_prfill_conf_u64,
			  &blkcg_policy_throtl, seq_cft(sf)->private, false);
	return 0;
}

static int tg_print_conf_uint(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), tg_prfill_conf_uint,
			  &blkcg_policy_throtl, seq_cft(sf)->private, false);
	return 0;
}

static void tg_conf_updated(struct throtl_grp *tg, bool global)
{
	struct throtl_service_queue *sq = &tg->service_queue;
	struct cgroup_subsys_state *pos_css;
	struct blkcg_gq *blkg;

	throtl_log(&tg->service_queue,
		   "limit change rbps=%llu wbps=%llu riops=%u wiops=%u",
		   tg_bps_limit(tg, READ), tg_bps_limit(tg, WRITE),
		   tg_iops_limit(tg, READ), tg_iops_limit(tg, WRITE));

	/*
	 * Update has_rules[] flags for the updated tg's subtree.  A tg is
	 * considered to have rules if either the tg itself or any of its
	 * ancestors has rules.  This identifies groups without any
	 * restrictions in the whole hierarchy and allows them to bypass
	 * blk-throttle.
	 */
	blkg_for_each_descendant_pre(blkg, pos_css,
			global ? tg->td->queue->root_blkg : tg_to_blkg(tg)) {
		struct throtl_grp *this_tg = blkg_to_tg(blkg);
		struct throtl_grp *parent_tg;

		tg_update_has_rules(this_tg);
		/* ignore root/second level */
		if (!cgroup_subsys_on_dfl(io_cgrp_subsys) || !blkg->parent ||
		    !blkg->parent->parent)
			continue;
		parent_tg = blkg_to_tg(blkg->parent);
		/*
		 * make sure all children has lower idle time threshold and
		 * higher latency target
		 */
		this_tg->idletime_threshold = min(this_tg->idletime_threshold,
				parent_tg->idletime_threshold);
		this_tg->latency_target = max(this_tg->latency_target,
				parent_tg->latency_target);
	}

	/*
	 * We're already holding queue_lock and know @tg is valid.  Let's
	 * apply the new config directly.
	 *
	 * Restart the slices for both READ and WRITES. It might happen
	 * that a group's limit are dropped suddenly and we don't want to
	 * account recently dispatched IO with new low rate.
	 */
	throtl_start_new_slice(tg, 0);
	throtl_start_new_slice(tg, 1);

	if (tg->flags & THROTL_TG_PENDING) {
		tg_update_disptime(tg);
		throtl_schedule_next_dispatch(sq->parent_sq, true);
	}
}
/* fs设置最大bps的回调函数. */
static ssize_t tg_set_conf(struct kernfs_open_file *of,
			   char *buf, size_t nbytes, loff_t off, bool is_u64)
{
	/* 先获得对应的blkcg */
	struct blkcg *blkcg = css_to_blkcg(of_css(of));
	struct blkg_conf_ctx ctx;
	struct throtl_grp *tg;
	int ret;
	u64 v;

	ret = blkg_conf_prep(blkcg, &blkcg_policy_throtl, buf, &ctx);
	if (ret)
		return ret;

	ret = -EINVAL;
	if (sscanf(ctx.body, "%llu", &v) != 1)
		goto out_finish;
	if (!v)
		v = U64_MAX;

	tg = blkg_to_tg(ctx.blkg);

	if (is_u64)
		*(u64 *)((void *)tg + of_cft(of)->private) = v;
	else
		*(unsigned int *)((void *)tg + of_cft(of)->private) = v;

	tg_conf_updated(tg, false);
	ret = 0;
out_finish:
	blkg_conf_finish(&ctx);
	return ret ?: nbytes;
}
/* 设置blkio的读写限速最大值 */
static ssize_t tg_set_conf_u64(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	return tg_set_conf(of, buf, nbytes, off, true);
}

static ssize_t tg_set_conf_uint(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	return tg_set_conf(of, buf, nbytes, off, false);
}
/* cgroup v1的blkio限制的fs接口 */
static struct cftype throtl_legacy_files[] = {
	{
		.name = "throttle.read_bps_device",
		.private = offsetof(struct throtl_grp, bps[READ][LIMIT_MAX]),
		.seq_show = tg_print_conf_u64,
		.write = tg_set_conf_u64,
	},
	{
		.name = "throttle.write_bps_device",
		.private = offsetof(struct throtl_grp, bps[WRITE][LIMIT_MAX]),
		.seq_show = tg_print_conf_u64,
		.write = tg_set_conf_u64,
	},
	{
		.name = "throttle.read_iops_device",
		.private = offsetof(struct throtl_grp, iops[READ][LIMIT_MAX]),
		.seq_show = tg_print_conf_uint,
		.write = tg_set_conf_uint,
	},
	{
		.name = "throttle.write_iops_device",
		.private = offsetof(struct throtl_grp, iops[WRITE][LIMIT_MAX]),
		.seq_show = tg_print_conf_uint,
		.write = tg_set_conf_uint,
	},
	{
		.name = "throttle.io_service_bytes",
		.private = (unsigned long)&blkcg_policy_throtl,
		.seq_show = blkg_print_stat_bytes,
	},
	{
		.name = "throttle.io_service_bytes_recursive",
		.private = (unsigned long)&blkcg_policy_throtl,
		.seq_show = blkg_print_stat_bytes_recursive,
	},
	{
		.name = "throttle.io_serviced",
		.private = (unsigned long)&blkcg_policy_throtl,
		.seq_show = blkg_print_stat_ios,
	},
	{
		.name = "throttle.io_serviced_recursive",
		.private = (unsigned long)&blkcg_policy_throtl,
		.seq_show = blkg_print_stat_ios_recursive,
	},
	{ }	/* terminate */
};

static u64 tg_prfill_limit(struct seq_file *sf, struct blkg_policy_data *pd,
			 int off)
{
	struct throtl_grp *tg = pd_to_tg(pd);
	const char *dname = blkg_dev_name(pd->blkg);
	char bufs[4][21] = { "max", "max", "max", "max" };
	u64 bps_dft;
	unsigned int iops_dft;
	char idle_time[26] = "";
	char latency_time[26] = "";

	if (!dname)
		return 0;

	if (off == LIMIT_LOW) {
		bps_dft = 0;
		iops_dft = 0;
	} else {
		bps_dft = U64_MAX;
		iops_dft = UINT_MAX;
	}

	if (tg->bps_conf[READ][off] == bps_dft &&
	    tg->bps_conf[WRITE][off] == bps_dft &&
	    tg->iops_conf[READ][off] == iops_dft &&
	    tg->iops_conf[WRITE][off] == iops_dft &&
	    (off != LIMIT_LOW ||
	     (tg->idletime_threshold_conf == DFL_IDLE_THRESHOLD &&
	      tg->latency_target_conf == DFL_LATENCY_TARGET)))
		return 0;

	if (tg->bps_conf[READ][off] != U64_MAX)
		snprintf(bufs[0], sizeof(bufs[0]), "%llu",
			tg->bps_conf[READ][off]);
	if (tg->bps_conf[WRITE][off] != U64_MAX)
		snprintf(bufs[1], sizeof(bufs[1]), "%llu",
			tg->bps_conf[WRITE][off]);
	if (tg->iops_conf[READ][off] != UINT_MAX)
		snprintf(bufs[2], sizeof(bufs[2]), "%u",
			tg->iops_conf[READ][off]);
	if (tg->iops_conf[WRITE][off] != UINT_MAX)
		snprintf(bufs[3], sizeof(bufs[3]), "%u",
			tg->iops_conf[WRITE][off]);
	if (off == LIMIT_LOW) {
		if (tg->idletime_threshold_conf == ULONG_MAX)
			strcpy(idle_time, " idle=max");
		else
			snprintf(idle_time, sizeof(idle_time), " idle=%lu",
				tg->idletime_threshold_conf);

		if (tg->latency_target_conf == ULONG_MAX)
			strcpy(latency_time, " latency=max");
		else
			snprintf(latency_time, sizeof(latency_time),
				" latency=%lu", tg->latency_target_conf);
	}

	seq_printf(sf, "%s rbps=%s wbps=%s riops=%s wiops=%s%s%s\n",
		   dname, bufs[0], bufs[1], bufs[2], bufs[3], idle_time,
		   latency_time);
	return 0;
}

static int tg_print_limit(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), tg_prfill_limit,
			  &blkcg_policy_throtl, seq_cft(sf)->private, false);
	return 0;
}

static ssize_t tg_set_limit(struct kernfs_open_file *of,
			  char *buf, size_t nbytes, loff_t off)
{
	struct blkcg *blkcg = css_to_blkcg(of_css(of));
	struct blkg_conf_ctx ctx;
	struct throtl_grp *tg;
	u64 v[4];
	unsigned long idle_time;
	unsigned long latency_time;
	int ret;
	int index = of_cft(of)->private;

	ret = blkg_conf_prep(blkcg, &blkcg_policy_throtl, buf, &ctx);
	if (ret)
		return ret;

	tg = blkg_to_tg(ctx.blkg);

	v[0] = tg->bps_conf[READ][index];
	v[1] = tg->bps_conf[WRITE][index];
	v[2] = tg->iops_conf[READ][index];
	v[3] = tg->iops_conf[WRITE][index];

	idle_time = tg->idletime_threshold_conf;
	latency_time = tg->latency_target_conf;
	while (true) {
		char tok[27];	/* wiops=18446744073709551616 */
		char *p;
		u64 val = U64_MAX;
		int len;

		if (sscanf(ctx.body, "%26s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		ctx.body += len;

		ret = -EINVAL;
		p = tok;
		strsep(&p, "=");
		if (!p || (sscanf(p, "%llu", &val) != 1 && strcmp(p, "max")))
			goto out_finish;

		ret = -ERANGE;
		if (!val)
			goto out_finish;

		ret = -EINVAL;
		if (!strcmp(tok, "rbps"))
			v[0] = val;
		else if (!strcmp(tok, "wbps"))
			v[1] = val;
		else if (!strcmp(tok, "riops"))
			v[2] = min_t(u64, val, UINT_MAX);
		else if (!strcmp(tok, "wiops"))
			v[3] = min_t(u64, val, UINT_MAX);
		else if (off == LIMIT_LOW && !strcmp(tok, "idle"))
			idle_time = val;
		else if (off == LIMIT_LOW && !strcmp(tok, "latency"))
			latency_time = val;
		else
			goto out_finish;
	}

	tg->bps_conf[READ][index] = v[0];
	tg->bps_conf[WRITE][index] = v[1];
	tg->iops_conf[READ][index] = v[2];
	tg->iops_conf[WRITE][index] = v[3];

	if (index == LIMIT_MAX) {
		tg->bps[READ][index] = v[0];
		tg->bps[WRITE][index] = v[1];
		tg->iops[READ][index] = v[2];
		tg->iops[WRITE][index] = v[3];
	}
	tg->bps[READ][LIMIT_LOW] = min(tg->bps_conf[READ][LIMIT_LOW],
		tg->bps_conf[READ][LIMIT_MAX]);
	tg->bps[WRITE][LIMIT_LOW] = min(tg->bps_conf[WRITE][LIMIT_LOW],
		tg->bps_conf[WRITE][LIMIT_MAX]);
	tg->iops[READ][LIMIT_LOW] = min(tg->iops_conf[READ][LIMIT_LOW],
		tg->iops_conf[READ][LIMIT_MAX]);
	tg->iops[WRITE][LIMIT_LOW] = min(tg->iops_conf[WRITE][LIMIT_LOW],
		tg->iops_conf[WRITE][LIMIT_MAX]);
	tg->idletime_threshold_conf = idle_time;
	tg->latency_target_conf = latency_time;

	/* force user to configure all settings for low limit  */
	if (!(tg->bps[READ][LIMIT_LOW] || tg->iops[READ][LIMIT_LOW] ||
	      tg->bps[WRITE][LIMIT_LOW] || tg->iops[WRITE][LIMIT_LOW]) ||
	    tg->idletime_threshold_conf == DFL_IDLE_THRESHOLD ||
	    tg->latency_target_conf == DFL_LATENCY_TARGET) {
		tg->bps[READ][LIMIT_LOW] = 0;
		tg->bps[WRITE][LIMIT_LOW] = 0;
		tg->iops[READ][LIMIT_LOW] = 0;
		tg->iops[WRITE][LIMIT_LOW] = 0;
		tg->idletime_threshold = DFL_IDLE_THRESHOLD;
		tg->latency_target = DFL_LATENCY_TARGET;
	} else if (index == LIMIT_LOW) {
		tg->idletime_threshold = tg->idletime_threshold_conf;
		tg->latency_target = tg->latency_target_conf;
	}

	blk_throtl_update_limit_valid(tg->td);
	if (tg->td->limit_valid[LIMIT_LOW]) {
		if (index == LIMIT_LOW)
			tg->td->limit_index = LIMIT_LOW;
	} else
		tg->td->limit_index = LIMIT_MAX;
	tg_conf_updated(tg, index == LIMIT_LOW &&
		tg->td->limit_valid[LIMIT_LOW]);
	ret = 0;
out_finish:
	blkg_conf_finish(&ctx);
	return ret ?: nbytes;
}

static struct cftype throtl_files[] = {
#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
	{
		.name = "low",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = tg_print_limit,
		.write = tg_set_limit,
		.private = LIMIT_LOW,
	},
#endif
	{
		.name = "max",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = tg_print_limit,
		.write = tg_set_limit,
		.private = LIMIT_MAX,
	},
	{ }	/* terminate */
};
/* rq关闭throttle前,取消dispatch线程. */
static void throtl_shutdown_wq(struct request_queue *q)
{
	struct throtl_data *td = q->td;

	cancel_work_sync(&td->dispatch_work);
}
/* 描述定义一种速度的限制,一组policy */
static struct blkcg_policy blkcg_policy_throtl = {
	.dfl_cftypes		= throtl_files,/*  */
	.legacy_cftypes		= throtl_legacy_files,/* blkio的读写限速的fs定义接口 */
	/* 分配pd */
	.pd_alloc_fn		= throtl_pd_alloc,
	/* blkcg_policy_throtl这个policy初始化自己pd的方法 */
	.pd_init_fn		= throtl_pd_init,
	/* 怎么online？ */
	.pd_online_fn		= throtl_pd_online,
	/* offline */
	.pd_offline_fn		= throtl_pd_offline,
	/* free此pd */
	.pd_free_fn		= throtl_pd_free,
};

static unsigned long __tg_last_low_overflow_time(struct throtl_grp *tg)
{
	unsigned long rtime = jiffies, wtime = jiffies;

	if (tg->bps[READ][LIMIT_LOW] || tg->iops[READ][LIMIT_LOW])
		rtime = tg->last_low_overflow_time[READ];
	if (tg->bps[WRITE][LIMIT_LOW] || tg->iops[WRITE][LIMIT_LOW])
		wtime = tg->last_low_overflow_time[WRITE];
	return min(rtime, wtime);
}

/* tg should not be an intermediate node */
static unsigned long tg_last_low_overflow_time(struct throtl_grp *tg)
{
	struct throtl_service_queue *parent_sq;
	struct throtl_grp *parent = tg;
	unsigned long ret = __tg_last_low_overflow_time(tg);

	while (true) {
		parent_sq = parent->service_queue.parent_sq;
		parent = sq_to_tg(parent_sq);
		if (!parent)
			break;

		/*
		 * The parent doesn't have low limit, it always reaches low
		 * limit. Its overflow time is useless for children
		 */
		if (!parent->bps[READ][LIMIT_LOW] &&
		    !parent->iops[READ][LIMIT_LOW] &&
		    !parent->bps[WRITE][LIMIT_LOW] &&
		    !parent->iops[WRITE][LIMIT_LOW])
			continue;
		if (time_after(__tg_last_low_overflow_time(parent), ret))
			ret = __tg_last_low_overflow_time(parent);
	}
	return ret;
}

static bool throtl_tg_is_idle(struct throtl_grp *tg)
{
	/*
	 * cgroup is idle if:
	 * - single idle is too long, longer than a fixed value (in case user
	 *   configure a too big threshold) or 4 times of idletime threshold
	 * - average think time is more than threshold
	 * - IO latency is largely below threshold
	 */
	unsigned long time;
	bool ret;

	time = min_t(unsigned long, MAX_IDLE_TIME, 4 * tg->idletime_threshold);
	ret = tg->latency_target == DFL_LATENCY_TARGET ||
	      tg->idletime_threshold == DFL_IDLE_THRESHOLD ||
	      (ktime_get_ns() >> 10) - tg->last_finish_time > time ||
	      tg->avg_idletime > tg->idletime_threshold ||
	      (tg->latency_target && tg->bio_cnt &&
		tg->bad_bio_cnt * 5 < tg->bio_cnt);
	throtl_log(&tg->service_queue,
		"avg_idle=%ld, idle_threshold=%ld, bad_bio=%d, total_bio=%d, is_idle=%d, scale=%d",
		tg->avg_idletime, tg->idletime_threshold, tg->bad_bio_cnt,
		tg->bio_cnt, ret, tg->td->scale);
	return ret;
}

static bool throtl_tg_can_upgrade(struct throtl_grp *tg)
{
	struct throtl_service_queue *sq = &tg->service_queue;
	bool read_limit, write_limit;

	/*
	 * if cgroup reaches low limit (if low limit is 0, the cgroup always
	 * reaches), it's ok to upgrade to next limit
	 */
	read_limit = tg->bps[READ][LIMIT_LOW] || tg->iops[READ][LIMIT_LOW];
	write_limit = tg->bps[WRITE][LIMIT_LOW] || tg->iops[WRITE][LIMIT_LOW];
	if (!read_limit && !write_limit)
		return true;
	if (read_limit && sq->nr_queued[READ] &&
	    (!write_limit || sq->nr_queued[WRITE]))
		return true;
	if (write_limit && sq->nr_queued[WRITE] &&
	    (!read_limit || sq->nr_queued[READ]))
		return true;

	if (time_after_eq(jiffies,
		tg_last_low_overflow_time(tg) + tg->td->throtl_slice) &&
	    throtl_tg_is_idle(tg))
		return true;
	return false;
}

static bool throtl_hierarchy_can_upgrade(struct throtl_grp *tg)
{
	while (true) {
		if (throtl_tg_can_upgrade(tg))
			return true;
		tg = sq_to_tg(tg->service_queue.parent_sq);
		if (!tg || !tg_to_blkg(tg)->parent)
			return false;
	}
	return false;
}

static bool throtl_can_upgrade(struct throtl_data *td,
	struct throtl_grp *this_tg)
{
	struct cgroup_subsys_state *pos_css;
	struct blkcg_gq *blkg;

	if (td->limit_index != LIMIT_LOW)
		return false;

	if (time_before(jiffies, td->low_downgrade_time + td->throtl_slice))
		return false;

	rcu_read_lock();
	blkg_for_each_descendant_post(blkg, pos_css, td->queue->root_blkg) {
		struct throtl_grp *tg = blkg_to_tg(blkg);

		if (tg == this_tg)
			continue;
		if (!list_empty(&tg_to_blkg(tg)->blkcg->css.children))
			continue;
		if (!throtl_hierarchy_can_upgrade(tg)) {
			rcu_read_unlock();
			return false;
		}
	}
	rcu_read_unlock();
	return true;
}

static void throtl_upgrade_check(struct throtl_grp *tg)
{
	unsigned long now = jiffies;

	if (tg->td->limit_index != LIMIT_LOW)
		return;

	if (time_after(tg->last_check_time + tg->td->throtl_slice, now))
		return;

	tg->last_check_time = now;

	if (!time_after_eq(now,
	     __tg_last_low_overflow_time(tg) + tg->td->throtl_slice))
		return;

	if (throtl_can_upgrade(tg->td, NULL))
		throtl_upgrade_state(tg->td);
}
/* 更新什么state */
static void throtl_upgrade_state(struct throtl_data *td)
{
	struct cgroup_subsys_state *pos_css;
	struct blkcg_gq *blkg;

	throtl_log(&td->service_queue, "upgrade to max");
	
	td->limit_index = LIMIT_MAX;
	td->low_upgrade_time = jiffies;
	td->scale = 0;


	rcu_read_lock();
	/* 遍历td->queue->root_blkg有关系的blkgq */
	blkg_for_each_descendant_post(blkg, pos_css, td->queue->root_blkg) {
		struct throtl_grp *tg = blkg_to_tg(blkg);
		struct throtl_service_queue *sq = &tg->service_queue;

		tg->disptime = jiffies - 1;
		throtl_select_dispatch(sq);
		throtl_schedule_next_dispatch(sq, true);
	}
	rcu_read_unlock();


	throtl_select_dispatch(&td->service_queue);
	throtl_schedule_next_dispatch(&td->service_queue, true);
	queue_work(kthrotld_workqueue, &td->dispatch_work);
}

static void throtl_downgrade_state(struct throtl_data *td, int new)
{
	td->scale /= 2;

	throtl_log(&td->service_queue, "downgrade, scale %d", td->scale);
	if (td->scale) {
		td->low_upgrade_time = jiffies - td->scale * td->throtl_slice;
		return;
	}

	td->limit_index = new;
	td->low_downgrade_time = jiffies;
}

static bool throtl_tg_can_downgrade(struct throtl_grp *tg)
{
	struct throtl_data *td = tg->td;
	unsigned long now = jiffies;

	/*
	 * If cgroup is below low limit, consider downgrade and throttle other
	 * cgroups
	 */
	if (time_after_eq(now, td->low_upgrade_time + td->throtl_slice) &&
	    time_after_eq(now, tg_last_low_overflow_time(tg) +
					td->throtl_slice) &&
	    (!throtl_tg_is_idle(tg) ||
	     !list_empty(&tg_to_blkg(tg)->blkcg->css.children)))
		return true;
	return false;
}

static bool throtl_hierarchy_can_downgrade(struct throtl_grp *tg)
{
	while (true) {
		if (!throtl_tg_can_downgrade(tg))
			return false;
		tg = sq_to_tg(tg->service_queue.parent_sq);
		if (!tg || !tg_to_blkg(tg)->parent)
			break;
	}
	return true;
}

static void throtl_downgrade_check(struct throtl_grp *tg)
{
	uint64_t bps;
	unsigned int iops;
	unsigned long elapsed_time;
	unsigned long now = jiffies;

	if (tg->td->limit_index != LIMIT_MAX ||
	    !tg->td->limit_valid[LIMIT_LOW])
		return;
	if (!list_empty(&tg_to_blkg(tg)->blkcg->css.children))
		return;
	if (time_after(tg->last_check_time + tg->td->throtl_slice, now))
		return;

	elapsed_time = now - tg->last_check_time;
	tg->last_check_time = now;

	if (time_before(now, tg_last_low_overflow_time(tg) +
			tg->td->throtl_slice))
		return;

	if (tg->bps[READ][LIMIT_LOW]) {
		bps = tg->last_bytes_disp[READ] * HZ;
		do_div(bps, elapsed_time);
		if (bps >= tg->bps[READ][LIMIT_LOW])
			tg->last_low_overflow_time[READ] = now;
	}

	if (tg->bps[WRITE][LIMIT_LOW]) {
		bps = tg->last_bytes_disp[WRITE] * HZ;
		do_div(bps, elapsed_time);
		if (bps >= tg->bps[WRITE][LIMIT_LOW])
			tg->last_low_overflow_time[WRITE] = now;
	}

	if (tg->iops[READ][LIMIT_LOW]) {
		iops = tg->last_io_disp[READ] * HZ / elapsed_time;
		if (iops >= tg->iops[READ][LIMIT_LOW])
			tg->last_low_overflow_time[READ] = now;
	}

	if (tg->iops[WRITE][LIMIT_LOW]) {
		iops = tg->last_io_disp[WRITE] * HZ / elapsed_time;
		if (iops >= tg->iops[WRITE][LIMIT_LOW])
			tg->last_low_overflow_time[WRITE] = now;
	}

	/*
	 * If cgroup is below low limit, consider downgrade and throttle other
	 * cgroups
	 */
	if (throtl_hierarchy_can_downgrade(tg))
		throtl_downgrade_state(tg->td, LIMIT_LOW);

	tg->last_bytes_disp[READ] = 0;
	tg->last_bytes_disp[WRITE] = 0;
	tg->last_io_disp[READ] = 0;
	tg->last_io_disp[WRITE] = 0;
}

static void blk_throtl_update_idletime(struct throtl_grp *tg)
{
	unsigned long now = ktime_get_ns() >> 10;
	unsigned long last_finish_time = tg->last_finish_time;

	if (now <= last_finish_time || last_finish_time == 0 ||
	    last_finish_time == tg->checked_last_finish_time)
		return;

	tg->avg_idletime = (tg->avg_idletime * 7 + now - last_finish_time) >> 3;
	tg->checked_last_finish_time = last_finish_time;
}

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
static void throtl_update_latency_buckets(struct throtl_data *td)
{
	struct avg_latency_bucket avg_latency[2][LATENCY_BUCKET_SIZE];
	int i, cpu, rw;
	unsigned long last_latency[2] = { 0 };
	unsigned long latency[2];

	if (!blk_queue_nonrot(td->queue))
		return;
	if (time_before(jiffies, td->last_calculate_time + HZ))
		return;
	td->last_calculate_time = jiffies;

	memset(avg_latency, 0, sizeof(avg_latency));
	for (rw = READ; rw <= WRITE; rw++) {
		for (i = 0; i < LATENCY_BUCKET_SIZE; i++) {
			struct latency_bucket *tmp = &td->tmp_buckets[rw][i];

			for_each_possible_cpu(cpu) {
				struct latency_bucket *bucket;

				/* this isn't race free, but ok in practice */
				bucket = per_cpu_ptr(td->latency_buckets[rw],
					cpu);
				tmp->total_latency += bucket[i].total_latency;
				tmp->samples += bucket[i].samples;
				bucket[i].total_latency = 0;
				bucket[i].samples = 0;
			}

			if (tmp->samples >= 32) {
				int samples = tmp->samples;

				latency[rw] = tmp->total_latency;

				tmp->total_latency = 0;
				tmp->samples = 0;
				latency[rw] /= samples;
				if (latency[rw] == 0)
					continue;
				avg_latency[rw][i].latency = latency[rw];
			}
		}
	}

	for (rw = READ; rw <= WRITE; rw++) {
		for (i = 0; i < LATENCY_BUCKET_SIZE; i++) {
			if (!avg_latency[rw][i].latency) {
				if (td->avg_buckets[rw][i].latency < last_latency[rw])
					td->avg_buckets[rw][i].latency =
						last_latency[rw];
				continue;
			}

			if (!td->avg_buckets[rw][i].valid)
				latency[rw] = avg_latency[rw][i].latency;
			else
				latency[rw] = (td->avg_buckets[rw][i].latency * 7 +
					avg_latency[rw][i].latency) >> 3;

			td->avg_buckets[rw][i].latency = max(latency[rw],
				last_latency[rw]);
			td->avg_buckets[rw][i].valid = true;
			last_latency[rw] = td->avg_buckets[rw][i].latency;
		}
	}

	for (i = 0; i < LATENCY_BUCKET_SIZE; i++)
		throtl_log(&td->service_queue,
			"Latency bucket %d: read latency=%ld, read valid=%d, "
			"write latency=%ld, write valid=%d", i,
			td->avg_buckets[READ][i].latency,
			td->avg_buckets[READ][i].valid,
			td->avg_buckets[WRITE][i].latency,
			td->avg_buckets[WRITE][i].valid);
}
#else
static inline void throtl_update_latency_buckets(struct throtl_data *td)
{
}
#endif
/* IO限速的核心函数是blk_throtl_bio()，它在__generic_make_request()中被调用。
__generic_make_request()根据blk_throtl_bio()的返回值来决定如何处理一个bio，

如果blk_throtl_bio()返回0，表明无需限速或者当前读写速度未达到设定的上限，
__generic_make_request()继续处理
如果blk_throtl_bio()返回非0，则说明该bio因为限速而不能立即分发，throttle模块
会来处理这个bio，__generic_make_request()直接跳到end_bio 


*/
bool blk_throtl_bio(struct request_queue *q, struct blkcg_gq *blkg,
		    struct bio *bio)
{
	struct throtl_qnode *qn = NULL;
	struct throtl_grp *tg = blkg_to_tg(blkg ?: q->root_blkg);
	struct throtl_service_queue *sq;
	bool rw = bio_data_dir(bio);
	bool throttled = false;
	struct throtl_data *td = tg->td;

	WARN_ON_ONCE(!rcu_read_lock_held());

	/* see throtl_charge_bio() */
	if (bio_flagged(bio, BIO_THROTTLED) || !tg->has_rules[rw])
		goto out;

	spin_lock_irq(&q->queue_lock);

	throtl_update_latency_buckets(td);

	blk_throtl_update_idletime(tg);

	sq = &tg->service_queue;

again:
	while (true) {
		if (tg->last_low_overflow_time[rw] == 0)
			tg->last_low_overflow_time[rw] = jiffies;
		throtl_downgrade_check(tg);
		throtl_upgrade_check(tg);
		/* throtl is FIFO - if bios are already queued, should queue */
		if (sq->nr_queued[rw])
			break;

		/* if above limits, break to queue */
		if (!tg_may_dispatch(tg, bio, NULL)) {
			tg->last_low_overflow_time[rw] = jiffies;
			if (throtl_can_upgrade(td, tg)) {
				throtl_upgrade_state(td);
				goto again;
			}
			break;
		}

		/* within limits, let's charge and dispatch directly */
		throtl_charge_bio(tg, bio);

		/*
		 * We need to trim slice even when bios are not being queued
		 * otherwise it might happen that a bio is not queued for
		 * a long time and slice keeps on extending and trim is not
		 * called for a long time. Now if limits are reduced suddenly
		 * we take into account all the IO dispatched so far at new
		 * low rate and * newly queued IO gets a really long dispatch
		 * time.
		 *
		 * So keep on trimming slice even if bio is not queued.
		 */
		throtl_trim_slice(tg, rw);

		/*
		 * @bio passed through this layer without being throttled.
		 * Climb up the ladder.  If we''re already at the top, it
		 * can be executed directly.
		 */
		qn = &tg->qnode_on_parent[rw];
		sq = sq->parent_sq;
		tg = sq_to_tg(sq);
		if (!tg)
			goto out_unlock;
	}

	/* out-of-limit, queue to @tg */
	throtl_log(sq, "[%c] bio. bdisp=%llu sz=%u bps=%llu iodisp=%u iops=%u queued=%d/%d",
		   rw == READ ? 'R' : 'W',
		   tg->bytes_disp[rw], bio->bi_iter.bi_size,
		   tg_bps_limit(tg, rw),
		   tg->io_disp[rw], tg_iops_limit(tg, rw),
		   sq->nr_queued[READ], sq->nr_queued[WRITE]);

	tg->last_low_overflow_time[rw] = jiffies;

	td->nr_queued[rw]++;
	throtl_add_bio_tg(bio, qn, tg);
	throttled = true;

	/*
	 * Update @tg's dispatch time and force schedule dispatch if @tg
	 * was empty before @bio.  The forced scheduling isn't likely to
	 * cause undue delay as @bio is likely to be dispatched directly if
	 * its @tg's disptime is not in the future.
	 */
	if (tg->flags & THROTL_TG_WAS_EMPTY) {
		tg_update_disptime(tg);
		throtl_schedule_next_dispatch(tg->service_queue.parent_sq, true);
	}

out_unlock:
	spin_unlock_irq(&q->queue_lock);
out:
	bio_set_flag(bio, BIO_THROTTLED);

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
	if (throttled || !td->track_bio_latency)
		bio->bi_issue.value |= BIO_ISSUE_THROTL_SKIP_LATENCY;
#endif
	return throttled;
}

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
static void throtl_track_latency(struct throtl_data *td, sector_t size,
	int op, unsigned long time)
{
	struct latency_bucket *latency;
	int index;

	if (!td || td->limit_index != LIMIT_LOW ||
	    !(op == REQ_OP_READ || op == REQ_OP_WRITE) ||
	    !blk_queue_nonrot(td->queue))
		return;

	index = request_bucket_index(size);

	latency = get_cpu_ptr(td->latency_buckets[op]);
	latency[index].total_latency += time;
	latency[index].samples++;
	put_cpu_ptr(td->latency_buckets[op]);
}

void blk_throtl_stat_add(struct request *rq, u64 time_ns)
{
	struct request_queue *q = rq->q;
	struct throtl_data *td = q->td;

	throtl_track_latency(td, blk_rq_stats_sectors(rq), req_op(rq),
			     time_ns >> 10);
}

void blk_throtl_bio_endio(struct bio *bio)
{
	struct blkcg_gq *blkg;
	struct throtl_grp *tg;
	u64 finish_time_ns;
	unsigned long finish_time;
	unsigned long start_time;
	unsigned long lat;
	int rw = bio_data_dir(bio);

	blkg = bio->bi_blkg;
	if (!blkg)
		return;
	tg = blkg_to_tg(blkg);

	finish_time_ns = ktime_get_ns();
	tg->last_finish_time = finish_time_ns >> 10;

	start_time = bio_issue_time(&bio->bi_issue) >> 10;
	finish_time = __bio_issue_time(finish_time_ns) >> 10;
	if (!start_time || finish_time <= start_time)
		return;

	lat = finish_time - start_time;
	/* this is only for bio based driver */
	if (!(bio->bi_issue.value & BIO_ISSUE_THROTL_SKIP_LATENCY))
		throtl_track_latency(tg->td, bio_issue_size(&bio->bi_issue),
				     bio_op(bio), lat);

	if (tg->latency_target && lat >= tg->td->filtered_latency) {
		int bucket;
		unsigned int threshold;

		bucket = request_bucket_index(bio_issue_size(&bio->bi_issue));
		threshold = tg->td->avg_buckets[rw][bucket].latency +
			tg->latency_target;
		if (lat > threshold)
			tg->bad_bio_cnt++;
		/*
		 * Not race free, could get wrong count, which means cgroups
		 * will be throttled
		 */
		tg->bio_cnt++;
	}

	if (time_after(jiffies, tg->bio_cnt_reset_time) || tg->bio_cnt > 1024) {
		tg->bio_cnt_reset_time = tg->td->throtl_slice + jiffies;
		tg->bio_cnt /= 2;
		tg->bad_bio_cnt /= 2;
	}
}
#endif

/*
 * Dispatch all bios from all children tg's queued on @parent_sq.  On
 * return, @parent_sq is guaranteed to not have any active children tg's
 * and all bios from previously active tg's are on @parent_sq->bio_lists[].
 */
static void tg_drain_bios(struct throtl_service_queue *parent_sq)
{
	struct throtl_grp *tg;

	while ((tg = throtl_rb_first(parent_sq))) {
		struct throtl_service_queue *sq = &tg->service_queue;
		struct bio *bio;

		throtl_dequeue_tg(tg);

		while ((bio = throtl_peek_queued(&sq->queued[READ])))
			tg_dispatch_one_bio(tg, bio_data_dir(bio));
		while ((bio = throtl_peek_queued(&sq->queued[WRITE])))
			tg_dispatch_one_bio(tg, bio_data_dir(bio));
	}
}

/**
 * blk_throtl_drain - drain throttled bios
 * @q: request_queue to drain throttled bios for
 *
 * Dispatch all currently throttled bios on @q through ->make_request_fn().
 */
void blk_throtl_drain(struct request_queue *q)
	__releases(&q->queue_lock) __acquires(&q->queue_lock)
{
	struct throtl_data *td = q->td;
	struct blkcg_gq *blkg;
	struct cgroup_subsys_state *pos_css;
	struct bio *bio;
	int rw;

	rcu_read_lock();

	/*
	 * Drain each tg while doing post-order walk on the blkg tree, so
	 * that all bios are propagated to td->service_queue.  It'd be
	 * better to walk service_queue tree directly but blkg walk is
	 * easier.
	 */
	blkg_for_each_descendant_post(blkg, pos_css, td->queue->root_blkg)
		tg_drain_bios(&blkg_to_tg(blkg)->service_queue);

	/* finally, transfer bios from top-level tg's into the td */
	tg_drain_bios(&td->service_queue);

	rcu_read_unlock();
	spin_unlock_irq(&q->queue_lock);

	/* all bios now should be in td->service_queue, issue them */
	for (rw = READ; rw <= WRITE; rw++)
		while ((bio = throtl_pop_queued(&td->service_queue.queued[rw],
						NULL)))
			generic_make_request(bio);

	spin_lock_irq(&q->queue_lock);
}
/* 初始化一个td?
td是关联到rq的*/
int blk_throtl_init(struct request_queue *q)
{
	struct throtl_data *td;
	int ret;

	td = kzalloc_node(sizeof(*td), GFP_KERNEL, q->node);
	if (!td)
		return -ENOMEM;
	/* 初始化pcp的latency_buckets */
	td->latency_buckets[READ] = __alloc_percpu(sizeof(struct latency_bucket) *
		LATENCY_BUCKET_SIZE, __alignof__(u64));
	if (!td->latency_buckets[READ]) {
		kfree(td);
		return -ENOMEM;
	}
	td->latency_buckets[WRITE] = __alloc_percpu(sizeof(struct latency_bucket) *
		LATENCY_BUCKET_SIZE, __alignof__(u64));
	if (!td->latency_buckets[WRITE]) {
		free_percpu(td->latency_buckets[READ]);
		kfree(td);
		return -ENOMEM;
	}

	/* 赋值td的后台dispatch work的执行函数 */
	INIT_WORK(&td->dispatch_work, blk_throtl_dispatch_work_fn);
	/* 初始化td的sq */
	throtl_service_queue_init(&td->service_queue);

	q->td = td;
	td->queue = q;

	td->limit_valid[LIMIT_MAX] = true;
	td->limit_index = LIMIT_MAX;
	td->low_upgrade_time = jiffies;
	td->low_downgrade_time = jiffies;

	/* activate policy */
	ret = blkcg_activate_policy(q, &blkcg_policy_throtl);
	if (ret) {/* activate失败了 */
		free_percpu(td->latency_buckets[READ]);
		free_percpu(td->latency_buckets[WRITE]);
		kfree(td);
	}
	return ret;
}
/* 
2024年08月29日16:10:05
这是rq关闭throttle? */
void blk_throtl_exit(struct request_queue *q)
{
	BUG_ON(!q->td);
	/* 停止td的dispatch线程 */
	throtl_shutdown_wq(q);
	/* 关闭这个policy */
	blkcg_deactivate_policy(q, &blkcg_policy_throtl);

	free_percpu(q->td->latency_buckets[READ]);
	free_percpu(q->td->latency_buckets[WRITE]);

	kfree(q->td);
}

void blk_throtl_register_queue(struct request_queue *q)
{
	struct throtl_data *td;
	int i;

	td = q->td;
	BUG_ON(!td);

	if (blk_queue_nonrot(q)) {
		td->throtl_slice = DFL_THROTL_SLICE_SSD;
		td->filtered_latency = LATENCY_FILTERED_SSD;
	} else {
		td->throtl_slice = DFL_THROTL_SLICE_HD;
		td->filtered_latency = LATENCY_FILTERED_HD;
		for (i = 0; i < LATENCY_BUCKET_SIZE; i++) {
			td->avg_buckets[READ][i].latency = DFL_HD_BASELINE_LATENCY;
			td->avg_buckets[WRITE][i].latency = DFL_HD_BASELINE_LATENCY;
		}
	}
#ifndef CONFIG_BLK_DEV_THROTTLING_LOW
	/* if no low limit, use previous default */
	td->throtl_slice = DFL_THROTL_SLICE_HD;
#endif

	td->track_bio_latency = !queue_is_mq(q);
	if (!td->track_bio_latency)
		blk_stat_enable_accounting(q);
}

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
ssize_t blk_throtl_sample_time_show(struct request_queue *q, char *page)
{
	if (!q->td)
		return -EINVAL;
	return sprintf(page, "%u\n", jiffies_to_msecs(q->td->throtl_slice));
}

ssize_t blk_throtl_sample_time_store(struct request_queue *q,
	const char *page, size_t count)
{
	unsigned long v;
	unsigned long t;

	if (!q->td)
		return -EINVAL;
	if (kstrtoul(page, 10, &v))
		return -EINVAL;
	t = msecs_to_jiffies(v);
	if (t == 0 || t > MAX_THROTL_SLICE)
		return -EINVAL;
	q->td->throtl_slice = t;
	return count;
}
#endif

static int __init throtl_init(void)
{
	kthrotld_workqueue = alloc_workqueue("kthrotld", WQ_MEM_RECLAIM, 0);
	if (!kthrotld_workqueue)
		panic("Failed to create kthrotld\n");

	return blkcg_policy_register(&blkcg_policy_throtl);
}

module_init(throtl_init);

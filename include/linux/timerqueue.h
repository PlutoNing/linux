/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMERQUEUE_H
#define _LINUX_TIMERQUEUE_H

#include <linux/rbtree.h>
#include <linux/ktime.h>

/*
进程的pct的posix_cputimers的
一个代表不同时间统计方式的posix_cputimer_base的
tqhead红黑树上的节点
*/
struct timerqueue_node {
	struct rb_node node;
	/* 到期时间 */
	ktime_t expires; // 如果值为0的话, 表示不再被触发了?
};

/*
包含一个红黑树
似乎是挂着一些timer
*/
struct timerqueue_head {
	struct rb_root_cached rb_root;
};


extern bool timerqueue_add(struct timerqueue_head *head,
			   struct timerqueue_node *node);
extern bool timerqueue_del(struct timerqueue_head *head,
			   struct timerqueue_node *node);
extern struct timerqueue_node *timerqueue_iterate_next(
						struct timerqueue_node *node);

/**
head是pcb的posix_cputimers的一个posix_cputimer_base的tqhead
 * timerqueue_getnext - Returns the timer with the earliest expiration time
 * 返回具有最早到期时间的计时器的指针
 * @head: head of timerqueue
 *
 * Returns a pointer to the timer node that has the earliest expiration time.
 */
static inline
struct timerqueue_node *timerqueue_getnext(struct timerqueue_head *head)
{
	struct rb_node *leftmost = rb_first_cached(&head->rb_root);

	return rb_entry_safe(leftmost, struct timerqueue_node, node);
}

static inline void timerqueue_init(struct timerqueue_node *node)
{
	RB_CLEAR_NODE(&node->node);
}

static inline bool timerqueue_node_queued(struct timerqueue_node *node)
{
	return !RB_EMPTY_NODE(&node->node);
}

static inline bool timerqueue_node_expires(struct timerqueue_node *node)
{
	return node->expires;
}
/* 
初始化clock_base的tqhead
*/
static inline void timerqueue_init_head(struct timerqueue_head *head)
{
	head->rb_root = RB_ROOT_CACHED;
}
#endif /* _LINUX_TIMERQUEUE_H */

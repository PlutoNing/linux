/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _linux_POSIX_TIMERS_H
#define _linux_POSIX_TIMERS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/alarmtimer.h>
#include <linux/timerqueue.h>

struct kernel_siginfo;
struct task_struct;

/*
 * Bit fields within a clockid:
 * clockid的位域:
 * The most significant 29 bits hold either a pid or a file descriptor.
 * 最高的29位存储着一个pid或者一个文件描述符
 * Bit 2 indicates whether a cpu clock refers to a thread or a process.
 * 第二位表示一个cpu clock是指向一个线程还是一个进程
 * Bits 1 and 0 give the type: PROF=0, VIRT=1, SCHED=2, or FD=3.
 * 第一位和第0位给出了类型: PROF=0, VIRT=1, SCHED=2, or FD=3.
 * A clockid is invalid if bits 2, 1, and 0 are all set.
 */
#define CPUCLOCK_PID(clock)		((pid_t) ~((clock) >> 3))
// 检查这个clock是否是PERTHREAD的, 第三个bit是标记这个clock是PERTHREAD的
#define CPUCLOCK_PERTHREAD(clock) \
	(((clock) & (clockid_t) CPUCLOCK_PERTHREAD_MASK) != 0)

#define CPUCLOCK_PERTHREAD_MASK	4
#define CPUCLOCK_WHICH(clock)	((clock) & (clockid_t) CPUCLOCK_CLOCK_MASK)
#define CPUCLOCK_CLOCK_MASK	3
#define CPUCLOCK_PROF		0
#define CPUCLOCK_VIRT		1
#define CPUCLOCK_SCHED		2
/* 3个, prof, virt, sched */
#define CPUCLOCK_MAX		3
/*
011
*/
#define CLOCKFD			CPUCLOCK_MAX
/* 4|3 = 111, 三个1 bit */
#define CLOCKFD_MASK		(CPUCLOCK_PERTHREAD_MASK|CPUCLOCK_CLOCK_MASK)

static inline clockid_t make_process_cpuclock(const unsigned int pid,
		const clockid_t clock)
{
	return ((~pid) << 3) | clock;
}
static inline clockid_t make_thread_cpuclock(const unsigned int tid,
		const clockid_t clock)
{
	return make_process_cpuclock(tid, clock | CPUCLOCK_PERTHREAD_MASK);
}

static inline clockid_t fd_to_clockid(const int fd)
{
	return make_process_cpuclock((unsigned int) fd, CLOCKFD);
}
/*
把clockid转换为fd
*/
static inline int clockid_to_fd(const clockid_t clk)
{
	return ~(clk >> 3);
}

#ifdef CONFIG_POSIX_TIMERS

/**
 * cpu_timer - Posix CPU timer representation for k_itimer
 代表一个posix CPU计时器
 * @node:	timerqueue node to queue in the task/sig
 * @head:	timerqueue head on which this timer is queued
 * @pid:	Pointer to target task PID
 * @elist:	List head for the expiry list
 * @firing:	Timer is currently firing
 * @handling:	Pointer to the task which handles expiry
 */
struct cpu_timer {
	// 通过这个东西挂到进程的posix_cputimers的一个posix_cputimer_base的tqhead红黑树上
	struct timerqueue_node		node;
	// 指向posix_cputimers的一个posix_cputimer_base的tqhead
	// 也就是node所在的红黑树的那个东西
	struct timerqueue_head		*head;
	struct pid			*pid; // cputimer对应的pid
	struct list_head		elist; // 加入到了一个firing列表中
	int				firing; // 表示timer是否到时了, 等于1说明正在触发ing
	struct task_struct __rcu	*handling; // 指向一个task, 
	// 似乎是如果这个进程发现了到期, 就是这个进程被指向
};

/*
把cputimer挂到一个posix_cputimers的一个posix_cputimer_base的tqhead红黑树上
*/
static inline bool cpu_timer_enqueue(struct timerqueue_head *head,
				     struct cpu_timer *ctmr)
{
	ctmr->head = head;
	return timerqueue_add(head, &ctmr->node);
}
/*
看看这个cpu_timer是否已经挂到了pct的一个posix_cputimer_base的tqhead红黑树上
因为如果这个cpu_timer因为超时被从红黑树上摘下来了,会把head置为NULL
*/
static inline bool cpu_timer_queued(struct cpu_timer *ctmr)
{
	return !!ctmr->head;
}
/*
把cpu_timer从posix_cputimers的一个posix_cputimer_base的tqhead红黑树上摘下来
置空head
*/
static inline bool cpu_timer_dequeue(struct cpu_timer *ctmr)
{
	if (cpu_timer_queued(ctmr)) {
		timerqueue_del(ctmr->head, &ctmr->node);
		ctmr->head = NULL;
		return true;
	}
	return false;
}
/*
获取一个cpu_timer的expires
是存储在红黑树node连接件的expires里面的
因为这样还能顺便作为红黑树的key
*/
static inline u64 cpu_timer_getexpires(struct cpu_timer *ctmr)
{
	return ctmr->node.expires;
}

/*
简简单单给一个cpu_timer的expires赋值
*/
static inline void cpu_timer_setexpires(struct cpu_timer *ctmr, u64 exp)
{
	ctmr->node.expires = exp;
}

/**
表示进程的posix CPU计时器的一个posix CPU clock计时方式
比如sched, virt, prof时间什么的
其实是个红黑树,挂着各种timer
 * posix_cputimer_base - Container per posix CPU clock
 * @nextevt:		Earliest-expiration cache
 * @tqhead:		timerqueue head for cpu_timers
 */
struct posix_cputimer_base {
	/*
	如果值为u64_max,表示有一个timer到期了
	如果值不为u64_max,表示这个posix_cputimer_base的tqhead红黑树上的timer都还没到期
	值是最左边的那个timer的expires
	*/
	u64			nextevt;
	// 挂着全部的cpu_timer的红黑树
	struct timerqueue_head	tqhead;
};

/**
 * posix_cputimers - Container for posix CPU timer related data
 * @bases:		Base container for posix CPU clocks
   表示进程的posix CPU计时器的各种posix CPU clock计时方式
 * @timers_active:	Timers are queued.
   表示有timer被挂到了posix_cputimers的一个posix_cputimer_base的tqhead红黑树上?
 * @expiry_active:	Timer expiry is active. Used for
 *			process wide timers to avoid multiple
 *			task trying to handle expiry concurrently
 *
 * Used in task_struct and signal_struct
 */
struct posix_cputimers {
	struct posix_cputimer_base	bases[CPUCLOCK_MAX];
	/*
	如果上面几个posix_cputimer_base的nextevt都是u64_max,这个值就是false
	也就是说都有超时的timer
	*/
	unsigned int			timers_active;
	unsigned int			expiry_active;
};

/**
 * posix_cputimers_work - Container for task work based posix CPU timer expiry
 表示
 * @work:	The task work to be scheduled
 * @mutex:	Mutex held around expiry in context of this task work
 * @scheduled:  @work has been scheduled already, no further processing
 */
struct posix_cputimers_work {
	struct callback_head	work;
	struct mutex		mutex;
	unsigned int		scheduled;
};

static inline void posix_cputimers_init(struct posix_cputimers *pct)
{
	memset(pct, 0, sizeof(*pct));
	pct->bases[0].nextevt = U64_MAX;
	pct->bases[1].nextevt = U64_MAX;
	pct->bases[2].nextevt = U64_MAX;
}

void posix_cputimers_group_init(struct posix_cputimers *pct, u64 cpu_limit);

static inline void posix_cputimers_rt_watchdog(struct posix_cputimers *pct,
					       u64 runtime)
{
	pct->bases[CPUCLOCK_SCHED].nextevt = runtime;
}

/* Init task static initializer */
#define INIT_CPU_TIMERBASE(b) {						\
	.nextevt	= U64_MAX,					\
}

#define INIT_CPU_TIMERBASES(b) {					\
	INIT_CPU_TIMERBASE(b[0]),					\
	INIT_CPU_TIMERBASE(b[1]),					\
	INIT_CPU_TIMERBASE(b[2]),					\
}

#define INIT_CPU_TIMERS(s)						\
	.posix_cputimers = {						\
		.bases = INIT_CPU_TIMERBASES(s.posix_cputimers.bases),	\
	},
#else
struct posix_cputimers { };
struct cpu_timer { };
#define INIT_CPU_TIMERS(s)
static inline void posix_cputimers_init(struct posix_cputimers *pct) { }
static inline void posix_cputimers_group_init(struct posix_cputimers *pct,
					      u64 cpu_limit) { }
#endif

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
void clear_posix_cputimers_work(struct task_struct *p);
void posix_cputimers_init_work(void);
#else
static inline void clear_posix_cputimers_work(struct task_struct *p) { }
static inline void posix_cputimers_init_work(void) { }
#endif

#define REQUEUE_PENDING 1

/**
 * struct k_itimer - POSIX.1b interval timer structure.
 * @list:		List head for binding the timer to signals->posix_timers
 * @t_hash:		Entry in the posix timer hash table
 * @it_lock:		Lock protecting the timer
 * @kclock:		Pointer to the k_clock struct handling this timer
 * @it_clock:		The posix timer clock id
 * @it_id:		The posix timer id for identifying the timer
 * @it_active:		Marker that timer is active
 * @it_overrun:		The overrun counter for pending signals
 * @it_overrun_last:	The overrun at the time of the last delivered signal
 * @it_requeue_pending:	Indicator that timer waits for being requeued on
 *			signal delivery
 * @it_sigev_notify:	The notify word of sigevent struct for signal delivery
 * @it_interval:	The interval for periodic timers
 * @it_signal:		Pointer to the creators signal struct
 * @it_pid:		The pid of the process/task targeted by the signal
 * @it_process:		The task to wakeup on clock_nanosleep (CPU timers)
 * @sigq:		Pointer to preallocated sigqueue
 * @it:			Union representing the various posix timer type
 *			internals.
 * @rcu:		RCU head for freeing the timer.
 */
struct k_itimer {
	struct list_head	list;
	struct hlist_node	t_hash;
	spinlock_t		it_lock;
	const struct k_clock	*kclock; // 对应的posix clock类型
	clockid_t		it_clock;
	timer_t			it_id;
	int			it_active;
	s64			it_overrun;
	s64			it_overrun_last;
	int			it_requeue_pending;
	int			it_sigev_notify;
	ktime_t			it_interval; // 触发间隔?为0的话是单次触发的?
	struct signal_struct	*it_signal;
	union {
		struct pid		*it_pid;
		struct task_struct	*it_process;
	};
	struct sigqueue		*sigq;
	union {
		struct {
			struct hrtimer	timer;
		} real;
		//// 比如可能是挂载到posix_cputimers的一个posix_cputimer_base的tqhead红黑树上的cpu_timer
		struct cpu_timer	cpu; 
		struct {
			struct alarm	alarmtimer;
		} alarm;
	} it;
	struct rcu_head		rcu;
};

void run_posix_cpu_timers(void);
void posix_cpu_timers_exit(struct task_struct *task);
void posix_cpu_timers_exit_group(struct task_struct *task);
void set_process_cpu_timer(struct task_struct *task, unsigned int clock_idx,
			   u64 *newval, u64 *oldval);

int update_rlimit_cpu(struct task_struct *task, unsigned long rlim_new);

void posixtimer_rearm(struct kernel_siginfo *info);
#endif

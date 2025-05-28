/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TICK_SCHED_H
#define _TICK_SCHED_H

#include <linux/hrtimer.h>

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC,
	TICKDEV_MODE_ONESHOT,
};
/* 
表示pcp的tick设备
*/
struct tick_device {
	/*  */
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_nohz_mode {
	NOHZ_MODE_INACTIVE,
	NOHZ_MODE_LOWRES,
	NOHZ_MODE_HIGHRES,
};

/**
一旦切换到高精度模式后，原来的Tick层就失去作用了，高分辨率定时器层将“接管”
对底层定时事件设备的控制。这时，也就意味着，系统中原有的Tick将不复存在了。
但是，这个Tick其实是非常重要的，系统jiffies要靠它更新，用户看到的墙上时间
也需要在Tick到来的时候定期更新，进程的调度也需要用它来计算时间片。

Tick模拟层的主要目的就是当原来的Tick层不再工作了之后，用一些特殊的方式来模拟
出一个系统Tick，保证系统许多原有的功能还能够正常的运行。同时，它还要处理所谓
动态时钟的情况，也就是当系统中某个CPU空闲的时候，停掉该CPU上的Tick，从而达
到省电的目的。
 * struct tick_sched - sched tick emulation and no idle tick control/stats
 * 表示: sched tick模拟和无空闲tick控制/统计
 * @inidle:		Indicator that the CPU is in the tick idle mode
 * @tick_stopped:	Indicator that the idle tick has been stopped
 * @idle_active:	Indicator that the CPU is actively in the tick idle mode;
 *			it is reset during irq handling phases.
 * @do_timer_last:	CPU was the last one doing do_timer before going idle
 * @got_idle_tick:	Tick timer function has run with @inidle set
 * @stalled_jiffies:	Number of stalled jiffies detected across ticks
 * @last_tick_jiffies:	Value of jiffies seen on last tick
 * @sched_timer:	hrtimer to schedule the periodic tick in high
 *			resolution mode
 * @last_tick:		Store the last tick expiry time when the tick
 *			timer is modified for nohz sleeps. This is necessary
 *			to resume the tick timer operation in the timeline
 *			when the CPU returns from nohz sleep.
 * @next_tick:		Next tick to be fired when in dynticks mode.
 * @idle_jiffies:	jiffies at the entry to idle for idle time accounting
 * @idle_waketime:	Time when the idle was interrupted
 * @idle_entrytime:	Time when the idle call was entered
 * @nohz_mode:		Mode - one state of tick_nohz_mode
 * @last_jiffies:	Base jiffies snapshot when next event was last computed
 * @timer_expires_base:	Base time clock monotonic for @timer_expires
 * @timer_expires:	Anticipated timer expiration time (in case sched tick is stopped)
 * @next_timer:		Expiry time of next expiring timer for debugging purpose only
 * @idle_expires:	Next tick in idle, for debugging purpose only
 * @idle_calls:		Total number of idle calls
 * @idle_sleeps:	Number of idle calls, where the sched tick was stopped
 * @idle_exittime:	Time when the idle state was left
 * @idle_sleeptime:	Sum of the time slept in idle with sched tick stopped
 * @iowait_sleeptime:	Sum of the time slept in idle with sched tick stopped, with IO outstanding
 * @tick_dep_mask:	Tick dependency mask - is set, if someone needs the tick
 * @check_clocks:	Notification mechanism about clocksource changes
 */
struct tick_sched {
	/* Common flags */
	unsigned int			inidle		: 1; /* 表示当前CPU处于空闲状态。*/
	/* 表示当前CPU上的Tick已经被停止了。 */
	unsigned int			tick_stopped	: 1;
	/* 表示当前CPU确实是处于空闲状态。一般情况下inidle的值和idle_active的值应该是一样的，
	但有可能在CPU处于空闲状态时，收到一个中断处理请求，这时候当前CPU就会临时退出空闲状态，
	将idle_active置0，但inidle任然是1。 */
	unsigned int			idle_active	: 1;
	/* 表示在停止Tick之前，该CPU是否是负责更新系统jiffies的。 */
	unsigned int			do_timer_last	: 1;
	/* 表示是否在空闲状态下仍收到了Tick。 */
	unsigned int			got_idle_tick	: 1;

	/* Tick handling: jiffies stall check */
	/*  */
	unsigned int			stalled_jiffies;
	/*  */
	unsigned long			last_tick_jiffies;

	/* Tick handling */
/* 
在高精度模式下，用来模拟系统Tick的一个高分辨率定时器。
*/
	struct hrtimer			sched_timer;
	/* 记录上一次Tick到来的时间。 */
	ktime_t				last_tick;
	/* 记录下一次Tick到来的时间。 */
	ktime_t				next_tick;
	/* 在进入空闲状态时，系统jiffies的值。 */
	unsigned long			idle_jiffies;
	/* 
	上次idle被中断的时间
	记录了在空闲状态下收到并处理中断的时间。 */
	ktime_t				idle_waketime;

	/* Idle entry */
	/*  */
	seqcount_t			idle_sleeptime_seq;
	/* 记录了进入空闲状态的时间。 */
	ktime_t				idle_entrytime;

	/* Tick stop */
	/* 
	表明当前动态时钟的工作模式，目前共有三种模式：
	NOHZ_MODE_INACTIVE表示还没有激活;
	NOHZ_MODE_LOWRES表示当前处于低精度动态时钟模式;
	NOHZ_MODE_HIGHRES表示当前处于高精度动态时钟模式。
	*/
	enum tick_nohz_mode		nohz_mode;
	/* 记录了在停止Tick前，系统jiffies的值。 */
	unsigned long			last_jiffies;
	/* 记录了在停止Tick的情况下，定时器到期的基准时间，其实就是记录了在停止Tick的时候，
	上一次Tick到来的时间，也就是上一次更新系统jiffies的时间。 */
	u64				timer_expires_base;
	/* 下一个预期的定时器到期时间 */
	u64				timer_expires;
	/* 系统中所有定时器中最近要到期的到期时间 */
	u64				next_timer;
	/* 记录了在空闲且Tick停止后，下一个到期定时器的到期时间。 */
	ktime_t				idle_expires;
	/* 记录一共进入了多少次空闲状态。 */
	unsigned long			idle_calls;
	/* 记录了进入空闲状态后，一共停了多少次Tick。 */
	unsigned long			idle_sleeps;

	/* Idle exit */
	/* 记录上一次退出空闲状态的时间。 */
	ktime_t				idle_exittime;
	/* 记录了在空闲且Tick停止状态下，并且没有任何IO请求在等待的情况下，一共持续了多长时间。 */
	ktime_t				idle_sleeptime;
	/* 记录了在空闲且Tick停止状态下，同时还有IO请求在等待的情况下，一共持续了多长时间。 */
	ktime_t				iowait_sleeptime;

	/* Full dynticks handling */
	/* 记录了系统中还有哪些功能需要Tick，主要用于将CONFIG_NO_HZ_FULL编译选项打开的情况下 */
	atomic_t			tick_dep_mask;

	/* Clocksource changes
	该字段用来实现定时事件层和时钟源层向Tick模拟层
	的通知上报机制。当该字段的第0位被置位是，意味着有
	一个新的定时事件设备或者一个新的时钟源设备被添加到系统中了。
	*/
	unsigned long			check_clocks;
};

extern struct tick_sched *tick_get_tick_sched(int cpu);

extern void tick_setup_sched_timer(void);
#if defined CONFIG_NO_HZ_COMMON || defined CONFIG_HIGH_RES_TIMERS
extern void tick_cancel_sched_timer(int cpu);
#else
static inline void tick_cancel_sched_timer(int cpu) { }
#endif

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
extern int __tick_broadcast_oneshot_control(enum tick_broadcast_state state);
#else
static inline int
__tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	return -EBUSY;
}
#endif

#endif

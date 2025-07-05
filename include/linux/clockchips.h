/* SPDX-License-Identifier: GPL-2.0 */
/*  linux/include/linux/clockchips.h
 *
 *  This file contains the structure definitions for clockchips.
 *
 *  If you are not a clockchip, or the time of day code, you should
 *  not be including this file!
 */
#ifndef _LINUX_CLOCKCHIPS_H
#define _LINUX_CLOCKCHIPS_H

#ifdef CONFIG_GENERIC_CLOCKEVENTS

# include <linux/clocksource.h>
# include <linux/cpumask.h>
# include <linux/ktime.h>
# include <linux/notifier.h>

struct clock_event_device;
struct module;

/*
表示当前定时事件设备所处的状态，是一个枚举变量，一共有五种。
CLOCK_EVT_STATE_DETACHED,表示这个设备目前没有被内核事件子系统使用，也是设备的初始状态；
CLOCK_EVT_STATE_SHUTDOWN,表示该设备已经被关闭了；
CLOCK_EVT_STATE_PERIODIC ，表示这个设备一旦设置完成后就可以产生周期性事件，一般都是低精度的设备；
CLOCK_EVT_STATE_ONESHOT，表示该设备只能产生单次触发的时钟事件，一般都是高精度设备；
CLOCK_EVT_STATE_ONESHOT_STOPPED，表示该设备是单次触发设备，但是已经被停止了
 * Possible states of a clock event device.
 *
 * DETACHED:	Device is not used by clockevents core. Initial state or can be
 *		reached from SHUTDOWN.
 * SHUTDOWN:	Device is powered-off. Can be reached from PERIODIC or ONESHOT.
 * PERIODIC:	Device is programmed to generate events periodically. Can be
 *		reached from DETACHED or SHUTDOWN.
 * ONESHOT:	Device is programmed to generate event only once. Can be reached
 *		from DETACHED or SHUTDOWN.
 * ONESHOT_STOPPED: Device was programmed in ONESHOT mode and is temporarily
 *		    stopped.
 */
enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED, // 被释放了
	CLOCK_EVT_STATE_SHUTDOWN, // 被关闭了
	CLOCK_EVT_STATE_PERIODIC,
	CLOCK_EVT_STATE_ONESHOT,
	CLOCK_EVT_STATE_ONESHOT_STOPPED,
};

/*
 * Clock event features
 */
# define CLOCK_EVT_FEAT_PERIODIC	0x000001
# define CLOCK_EVT_FEAT_ONESHOT		0x000002
# define CLOCK_EVT_FEAT_KTIME		0x000004

/*
 * x86(64) specific (mis)features:
 *
 * - Clockevent source stops in C3 State and needs broadcast support.
     时钟事件源在C3状态下停止并且需要广播支持。
 * - Local APIC timer is used as a dummy device.
     本地APIC计时器用作虚拟设备。
 */
# define CLOCK_EVT_FEAT_C3STOP		0x000008
# define CLOCK_EVT_FEAT_DUMMY		0x000010

/*
 * Core shall set the interrupt affinity dynamically in broadcast mode
 */
# define CLOCK_EVT_FEAT_DYNIRQ		0x000020
# define CLOCK_EVT_FEAT_PERCPU		0x000040

/*
 * Clockevent device is based on a hrtimer for broadcast
 */
# define CLOCK_EVT_FEAT_HRTIMER		0x000080

/**
 * struct clock_event_device - clock event device descriptor
 * @event_handler:	Assigned by the framework to be called by the low
 *			level handler of the event source
 * @set_next_event:	set next event function using a clocksource delta
 * @set_next_ktime:	set next event function using a direct ktime value
 * @next_event:		local storage for the next event in oneshot mode
 * @max_delta_ns:	maximum delta value in ns
 * @min_delta_ns:	minimum delta value in ns
 * @mult:		nanosecond to cycles multiplier
 * @shift:		nanoseconds to cycles divisor (power of two)
 * @state_use_accessors:current state of the device, assigned by the core code
 * @features:		features
 * @retries:		number of forced programming retries
 * @set_state_periodic:	switch state to periodic
 * @set_state_oneshot:	switch state to oneshot
 * @set_state_oneshot_stopped: switch state to oneshot_stopped
 * @set_state_shutdown:	switch state to shutdown
 * @tick_resume:	resume clkevt device
 * @broadcast:		function to broadcast events
 * @min_delta_ticks:	minimum delta value in ticks stored for reconfiguration
 * @max_delta_ticks:	maximum delta value in ticks stored for reconfiguration
 * @name:		ptr to clock event name
 * @rating:		variable to rate clock event devices
 * @irq:		IRQ number (only for non CPU local devices)
 * @bound_on:		Bound on CPU
 * @cpumask:		cpumask to indicate for which CPUs this device works
 * @list:		list head for the management code
 * @owner:		module reference
 */
struct clock_event_device {
	/* 
	event_handler顾名思义就是产生了clock event的时候调用的handler。一般而言，
	底层的clock event chip driver会注册中断处理函数，在硬件timer中断到来的时候
	调用该timer中断handler，而在这个中断handler中再调用event_handler。
	*/
	void			(*event_handler)(struct clock_event_device *);
	/* 
	既然是产生clock event的device，那么总是要控制下一次event产生的时间点，
	我们有两个成员函数完成这个功能：set_next_event和set_next_ktime。set_next_ktime
	函数可以直接接收ktime作为参数，而set_next_event设定的counter的cycle数值。
		*/
	int			(*set_next_event)(unsigned long evt, struct clock_event_device *);
	int			(*set_next_ktime)(ktime_t expires, struct clock_event_device *);
	// 该定时事件设备的下一次到期绝对时间，用ktime表示。
	ktime_t			next_event;
	/* 
	表示当前定时事件设备能分辨的最大定时时间间隔，以纳秒数表示。系统中的时钟源计数器一般都有一个最大计数值，
	超过这个值后就会回滚了，这也就是单次定时能设定的最大时间间隔。假如系统时钟源计数超过10分钟就会越界回滚，
	如果定时在10分钟内，那没关系，即使会越界系统回滚后也可以正确定时。而如果定时超过10分钟，
	那系统就无法区分到底是越界之前的值是对了还是越界之后的值是对的。
	所以，超过这个定时间隔系统一定会出错。这个值可以和max_delta_ticks通过mult和shift互相转换。
	*/
	u64			max_delta_ns;
	/* 
	表示当前定时事件设备能分辨的最小定时时间间隔，以纳秒数表示。系统中的时钟源一般都有一个最小分辨率，
	如果时钟源以10MHz运行，那么其最小的定时时间间隔肯定要大于100纳秒，
	小于这个定时间隔在这个系统上是无法实现的。这个值可以和min_delta_ticks通过mult和shift互相转换。
	*/
	u64			min_delta_ns;
	/* 
	系统中都会有一个时钟源（Clock Source），有的系统会将其称作计数器，它会按照一个固定的频率周期工作，
	不停的累加。注意区分时钟源和本文说的定时器，时钟源只是自顾自的累加，频率很高，让系统“感知”时间的流逝，
	它不会触发中断，计数器的值是CPU自己主动读取的；而定时器是会触发中断的，而且其定时间隔肯定比时钟源
	的周期间隔要大。内核可以通过不同渠道知道时钟源的频率（Frequency），也可以通过比较现在的时钟计数器
	数值和上一次时钟计数器数值获得已经过去了多少个周期（Cycle），有了这两个参数就可以知道过去了多少秒了
	（Cycle / Frequency）。但是，内核是没有浮点运算单元的，因此，只能通过整数运算进行模拟。mult表示乘数，
	shift表示位移多少位。这样，拿到了计数器的值后，先用shift左移位，然后再整数除以mult之后，就可以算出过了
	多少纳秒（(Cycle << shift) / mult）。这两个值是需要精心计算了，如果太大了会造成溢出，
	如果太小了，会造成精度不够。
	*/
	u32			mult;
	u32			shift;
	/* 
	表示当前定时事件设备所处的状态，是一个枚举变量，一共有五种。
	CLOCK_EVT_STATE_DETACHED，表示这个设备目前没有被内核事件子系统使用，也是设备的初始状态；
	CLOCK_EVT_STATE_SHUTDOWN，表示该设备已经被关闭了；
	CLOCK_EVT_STATE_PERIODIC，表示这个设备一旦设置完成后就可以产生周期性事件，一般都是低精度的设备；
	CLOCK_EVT_STATE_ONESHOT，表示该设备只能产生单次触发的时钟事件，一般都是高精度设备；
	CLOCK_EVT_STATE_ONESHOT_STOPPED，表示该设备是单次触发设备，但是已经被停止了
	*/
	enum clock_event_state	state_use_accessors;
	/*
	features成员是描述底层硬件的功能feature的，包括：
#define CLOCK_EVT_FEAT_PERIODIC        0x000001－－具备产生周期性event的能力
#define CLOCK_EVT_FEAT_ONESHOT        0x000002－－具备产生oneshot类型event的能力
#define CLOCK_EVT_FEAT_KTIME        0x000004－－－－上面已经描述了

#define CLOCK_EVT_FEAT_C3STOP        0x000008
#define CLOCK_EVT_FEAT_DUMMY        0x000010
	*/
	unsigned int		features;
	unsigned long		retries;

	int			(*set_state_periodic)(struct clock_event_device *);
	int			(*set_state_oneshot)(struct clock_event_device *);
	int			(*set_state_oneshot_stopped)(struct clock_event_device *);
	int			(*set_state_shutdown)(struct clock_event_device *);
	/* 恢复设备的tick */
	int			(*tick_resume)(struct clock_event_device *);
/* 
内核中有一个模块叫做cpuidle framework，当没有任务做的时候，cpu会进入idle状态。
这种CPU的sleep state叫做C-states，有C1/C2…Cn种states（具体多少种和CPU设计相关），
当然不同的状态是在功耗和唤醒时间上进行平衡，CPU睡的越浅，功耗越大，但是能够很快的唤醒。
一般而言，在sleep state的CPU可以被local timer唤醒，但是，当CPU进入某个深度睡眠状态的时候，
停止了local timer的运作，这时候，local timer将无法唤醒CPU了。

kernel的注释说这是一个x86（64）的功能设计失误（misfeature），不过，在嵌入式平台上，
这也可以认为是对功耗的极致追求（ARM 的generic timer也有这个misfeature）。
为了让系统可以继续运作，传说中tick broadcast framework粉墨登场了。
struct clock_event_device中的broadcast这个callback函数是和clock event广播有关。
在per CPU 的local timer硬件无法正常运作的时候，需要一个独立于各个CPU的timer硬件
来作为broadcast clock event device。
在这种情况下，它可以将clock event广播到所有的CPU core，以此推动各个CPU core上的
tick device的运作。
*/
	void			(*broadcast)(const struct cpumask *mask);
	// 当要暂停定时事件设备时，会调用对应设备的该函数。
	void			(*suspend)(struct clock_event_device *);
	// 当要恢复定时事件设备时，会调用对应设备的该函数。
	void			(*resume)(struct clock_event_device *);
	// 表示当前定时事件设备能分辨的最小定时时间间隔，以时钟源设备的周期数表示，肯定是一个大于1的值。
	unsigned long		min_delta_ticks;
	// 表示当前定时事件设备能分辨的最大定时时间间隔，以时钟源设备的周期数表示，肯定不能大于时钟源设备的最大计数器值。
	unsigned long		max_delta_ticks;
	// 是给这个定时事件设备起的一个名字，一般比较直观，在/proc/timer_list中或者dmesg中都会出现。
	const char		*name;
	// 代表这个定时事件设备的精度值，其取值范围从1到499，数字越大代表设备的精度越高。当系统中同时有多个定时事件设备存在的时候，内核可以根据这个值选一个最佳的设备。
	int			rating;
	// 指定了该定时事件设备使用的中断号。
	int			irq;
	// 绑定的CPU，主要在Tick广播层使用。
	int			bound_on;
	const struct cpumask	*cpumask;
	struct list_head	list; // 链接到哪里?
	struct module		*owner;
} ____cacheline_aligned;

/* Helpers to verify state of a clockevent device
检查clock event设备是否处于DETACHED状态
是不是被释放了, 解绑了
*/
static inline bool clockevent_state_detached(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_DETACHED;
}
/* 
设备是否处于SHUTDOWN状态
*/
static inline bool clockevent_state_shutdown(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_SHUTDOWN;
}
/* 
检查ce设备是不是周期性的
*/
static inline bool clockevent_state_periodic(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_PERIODIC;
}
/* 
检查是不是单次触发的定时事件设备
*/
static inline bool clockevent_state_oneshot(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_ONESHOT;
}

static inline bool clockevent_state_oneshot_stopped(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_ONESHOT_STOPPED;
}

/*
 * Calculate a multiplication factor for scaled math, which is used to convert
 * nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 *
 * div_sc is the rearranged equation to calculate a factor from a given clock
 * ticks / nanoseconds ratio:
 *
 * factor = (clock_ticks << shift) / nanoseconds
 */
static inline unsigned long
div_sc(unsigned long ticks, unsigned long nsec, int shift)
{
	u64 tmp = ((u64)ticks) << shift;

	do_div(tmp, nsec);

	return (unsigned long) tmp;
}

/* Clock event layer functions */
extern u64 clockevent_delta2ns(unsigned long latch, struct clock_event_device *evt);
extern void clockevents_register_device(struct clock_event_device *dev);
extern int clockevents_unbind_device(struct clock_event_device *ced, int cpu);

extern void clockevents_config_and_register(struct clock_event_device *dev,
					    u32 freq, unsigned long min_delta,
					    unsigned long max_delta);

extern int clockevents_update_freq(struct clock_event_device *ce, u32 freq);

static inline void
clockevents_calc_mult_shift(struct clock_event_device *ce, u32 freq, u32 maxsec)
{
	return clocks_calc_mult_shift(&ce->mult, &ce->shift, NSEC_PER_SEC, freq, maxsec);
}

extern void clockevents_suspend(void);
extern void clockevents_resume(void);

# ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
#  ifdef CONFIG_ARCH_HAS_TICK_BROADCAST
extern void tick_broadcast(const struct cpumask *mask);
#  else
#   define tick_broadcast	NULL
#  endif
extern int tick_receive_broadcast(void);
# endif

# if defined(CONFIG_GENERIC_CLOCKEVENTS_BROADCAST) && defined(CONFIG_TICK_ONESHOT)
extern void tick_setup_hrtimer_broadcast(void);
extern int tick_check_broadcast_expired(void);
# else
static __always_inline int tick_check_broadcast_expired(void) { return 0; }
static inline void tick_setup_hrtimer_broadcast(void) { }
# endif

#else /* !CONFIG_GENERIC_CLOCKEVENTS: */

static inline void clockevents_suspend(void) { }
static inline void clockevents_resume(void) { }
static __always_inline int tick_check_broadcast_expired(void) { return 0; }
static inline void tick_setup_hrtimer_broadcast(void) { }

#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

#endif /* _LINUX_CLOCKCHIPS_H */

===================================================================
delays - Information on the various kernel delay / sleep mechanisms
关于各种内核延迟/睡眠机制的信息
===================================================================

This document seeks to answer the common question: "What is the
RightWay (TM) to insert a delay?"
文档力求回答一个常见问题:'插入延迟的正确方式是什么?'
This question is most often faced by driver writers who have to
deal with hardware delays and who may not be the most intimately
familiar with the inner workings of the Linux Kernel.
这个问题通常是由驱动程序编写者面对的,他们必须处理硬件延迟,而且可能对
Linux内核的内部工作机制不太熟悉。

Inserting Delays
----------------

The first, and most important, question you need to ask is "Is my
code in an atomic context?"  This should be followed closely by "Does
it really need to delay in atomic context?" If so...
最开始,也是最重要的问题是你需要问的是"我的代码是否在原子上下文中?"紧随其后的是
"它是否真的需要在原子上下文中延迟?"如果是...
ATOMIC CONTEXT:
	You must use the `*delay` family of functions. These
	functions use the jiffie estimation of clock speed
	and will busy wait for enough loop cycles to achieve
	the desired delay:
	你必须使用`*delay`函数族。这些函数使用时钟速度的jiffie估计值,
	并将忙等待足够的循环周期以实现所需的延迟:
	ndelay(unsigned long nsecs)
	udelay(unsigned long usecs)
	mdelay(unsigned long msecs)

	udelay is the generally preferred API; ndelay-level
	precision may not actually exist on many non-PC devices.
	udelay是通常首选的API;ndelay级别的精度在许多非PC设备上可能实际上并不存在。
	mdelay is macro wrapper around udelay, to account for
	possible overflow when passing large arguments to udelay.
	In general, use of mdelay is discouraged and code should
	be refactored to allow for the use of msleep.
	mdelay是udelay的宏包装器,用于处理将大参数传递给udelay时可能发生的溢出。
	一般来说,不鼓励使用mdelay,代码应该重构以允许使用msleep。
NON-ATOMIC CONTEXT:
	You should use the `*sleep[_range]` family of functions.
	There are a few more options here, while any of them may
	work correctly, using the "right" sleep function will
	help the scheduler, power management, and just make your
	driver better :)
	你应该使用`*sleep[_range]`函数族。这里有一些更多的选项,虽然它们中的任何一个可能
	工作正确,但使用"正确"的睡眠函数将有助于调度器、电源管理,并使你的驱动程序更好:)
	-- Backed by busy-wait loop:
		以下函数由忙等待循环支持:
		udelay(unsigned long usecs)

	-- Backed by hrtimers:
		以下函数由高精度定时器支持:
		usleep_range(unsigned long min, unsigned long max)

	-- Backed by jiffies / legacy_timers
		以下函数由jiffies/legacy_timers支持:
		msleep(unsigned long msecs)
		msleep_interruptible(unsigned long msecs)

	Unlike the `*delay` family, the underlying mechanism
	driving each of these calls varies, thus there are
	quirks you should be aware of.
	不像`*delay`函数族,驱动每个调用的底层机制是不同的,因此你应该注意到一些特殊情况。

	SLEEPING FOR "A FEW" USECS ( < ~10us? ):
		* Use udelay

		- Why not usleep?
			On slower systems, (embedded, OR perhaps a speed-
			stepped PC!) the overhead of setting up the hrtimers
			for usleep *may* not be worth it. Such an evaluation
			will obviously depend on your specific situation, but
			it is something to be aware of.

	SLEEPING FOR ~USECS OR SMALL MSECS ( 10us - 20ms):
		* Use usleep_range

		- Why not msleep for (1ms - 20ms)?
			Explained originally here:
				https://lore.kernel.org/r/15327.1186166232@lwn.net

			msleep(1~20) may not do what the caller intends, and
			will often sleep longer (~20 ms actual sleep for any
			value given in the 1~20ms range). In many cases this
			is not the desired behavior.

		- Why is there no "usleep" / What is a good range?
			Since usleep_range is built on top of hrtimers, the
			wakeup will be very precise (ish), thus a simple
			usleep function would likely introduce a large number
			of undesired interrupts.

			With the introduction of a range, the scheduler is
			free to coalesce your wakeup with any other wakeup
			that may have happened for other reasons, or at the
			worst case, fire an interrupt for your upper bound.

			The larger a range you supply, the greater a chance
			that you will not trigger an interrupt; this should
			be balanced with what is an acceptable upper bound on
			delay / performance for your specific code path. Exact
			tolerances here are very situation specific, thus it
			is left to the caller to determine a reasonable range.

	SLEEPING FOR LARGER MSECS ( 10ms+ )
		* Use msleep or possibly msleep_interruptible

		- What's the difference?
			msleep sets the current task to TASK_UNINTERRUPTIBLE
			whereas msleep_interruptible sets the current task to
			TASK_INTERRUPTIBLE before scheduling the sleep. In
			short, the difference is whether the sleep can be ended
			early by a signal. In general, just use msleep unless
			you know you have a need for the interruptible variant.

	FLEXIBLE SLEEPING (any delay, uninterruptible)
		* Use fsleep

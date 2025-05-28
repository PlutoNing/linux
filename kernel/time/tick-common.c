// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains the base functions to manage periodic tick
 * related events.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <trace/events/power.h>

#include <asm/irq_regs.h>

#include "tick-internal.h"

/*
 * Tick devices
 pcp的tick设备
 */
DEFINE_PER_CPU(struct tick_device, tick_cpu_device);
/*
tick_next_period是在Tick层定义的，表示下一次Tick的到期时间。
 * Tick next event: keeps track of the tick time. It's updated by the
 * CPU which handles the tick and protected by jiffies_lock. There is
 * no requirement to write hold the jiffies seqcount for it.
 */
ktime_t tick_next_period;

/*
 * tick_do_timer_cpu is a timer core internal variable which holds the CPU NR
 * which is responsible for calling do_timer(), i.e. the timekeeping stuff. This
 * variable has two functions:
 *
 * 1) Prevent a thundering herd issue of a gazillion of CPUs trying to grab the
 *    timekeeping lock all at once. Only the CPU which is assigned to do the
 *    update is handling it.
 *
 * 2) Hand off the duty in the NOHZ idle case by setting the value to
 *    TICK_DO_TIMER_NONE, i.e. a non existing CPU. So the next cpu which looks
 *    at it will take over and keep the time keeping alive.  The handover
 *    procedure also covers cpu hotplug.
 tick_do_timer_cpu是一个定时器核心内部变量，保存着负责调用do_timer()的CPU编号
 * (也就是负责时间保持的CPU编号)。这个变量有两个作用：
 * 1) 防止一大堆CPU同时获取时间保持锁的问题。只有被分配来更新的CPU会处理它。
 * 2) 在NOHZ空闲的情况下，设置值为TICK_DO_TIMER_NONE，也就是一个不存在的CPU。
 * 这样下一个查看它的CPU就会接管它，保持时间保持。这个交接过程也覆盖了CPU热插拔。
 */
int tick_do_timer_cpu __read_mostly = TICK_DO_TIMER_BOOT;
#ifdef CONFIG_NO_HZ_FULL
/*
 * tick_do_timer_boot_cpu indicates the boot CPU temporarily owns
 * tick_do_timer_cpu and it should be taken over by an eligible secondary
 * when one comes online.
 */
static int tick_do_timer_boot_cpu __read_mostly = -1;
#endif

/*
 * Debugging: see timer_list.c
 */
struct tick_device *tick_get_device(int cpu)
{
	return &per_cpu(tick_cpu_device, cpu);
}

/**
在低精度模式下的周期处理函数hrtimer_run_queues中，每次都会调用tick_check_oneshot_change
函数，判断目前是否可以切换到高精度模式。而在这个函数中，还会调用tick_is_oneshot_available
函数判断Tick层是否已经准备好切换了：
 * tick_is_oneshot_available - check for a oneshot capable event device
 */
int tick_is_oneshot_available(void)
{
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);

	if (!dev || !(dev->features & CLOCK_EVT_FEAT_ONESHOT))
		return 0;
	if (!(dev->features & CLOCK_EVT_FEAT_C3STOP))
		return 1;
	//调用tick_broadcast_oneshot_available函数，看看Tick广播层是否已经准备好了
	return tick_broadcast_oneshot_available();
}

/*
 * Periodic tick
 设置jiffies_64、计算负载、更新墙上时间
 =================================================================
 系统中每个CPU都会有一个系统定时器，本质上是一个可编程中断时钟。
 通过配置可以让其每秒生成固定HZ个中断(类似于心跳)。在其中断处理程序
 中要做的事情会涉及到体系架构部分和非体系架构部分。体系架构无关的部分
 位于tick_periodic(cpu)函数中。tick_periodic(cpu)会做很多事情
 其中周期性调度器的部分：tick_periodic->update_process_times->scheduler_tick()计算负载?
 */
static void tick_periodic(int cpu)
{
	if (tick_do_timer_cpu == cpu) {
		raw_spin_lock(&jiffies_lock);
		write_seqcount_begin(&jiffies_seq);

		/* Keep track of the next tick event */
		tick_next_period = ktime_add_ns(tick_next_period, TICK_NSEC);
		// 更新jiffies_64, 计算负载
		do_timer(1);
		write_seqcount_end(&jiffies_seq);
		raw_spin_unlock(&jiffies_lock);
		// 更新墙钟
		update_wall_time();
	}

	update_process_times(user_mode(get_irq_regs()));
	profile_tick(CPU_PROFILING);
}

/*
 * Event handler for periodic ticks
 广播关闭情况下周期性ce设备的event handler
 ========================================================
 此函数主要是更新jiffies_64、计算负载、更新墙上时间也就是系统时间，
 由于是工作在periodic模式，所以每次执行完毕，没必要reprogram下一次的event
 2025年3月29日00:04:38
 */
void tick_handle_periodic(struct clock_event_device *dev)
{
	int cpu = smp_processor_id();
	ktime_t next = dev->next_event;
	// 主要的工作
	tick_periodic(cpu);

#if defined(CONFIG_HIGH_RES_TIMERS) || defined(CONFIG_NO_HZ_COMMON)
	/*
	 * The cpu might have transitioned to HIGHRES or NOHZ mode via
	 * update_process_times() -> run_local_timers() ->
	 * hrtimer_run_queues().
	 */
	if (dev->event_handler != tick_handle_periodic)
		return;
#endif

	if (!clockevent_state_oneshot(dev))
		return;
	// one-shot模式下，设置下一个到期时间
	for (;;) {
		/*
		 * Setup the next period for devices, which do not have
		 * periodic mode:
		 */
		next = ktime_add_ns(next, TICK_NSEC);

		if (!clockevents_program_event(dev, next, false))
			return;
		/*
		 * Have to be careful here. If we're in oneshot mode,
		 * before we call tick_periodic() in a loop, we need
		 * to be sure we're using a real hardware clocksource.
		 * Otherwise we could get trapped in an infinite
		 * loop, as the tick_periodic() increments jiffies,
		 * which then will increment time, possibly causing
		 * the loop to trigger again and again.
		 */
		if (timekeeping_valid_for_hres())
			tick_periodic(cpu);
	}
}

/*
 * Setup the device for a periodic tick
 设置ce设备为周期性或者one-shot
 */
void tick_setup_periodic(struct clock_event_device *dev, int broadcast)
{
	// 这里根据广播开启情况设置event_handler
	tick_set_periodic_handler(dev, broadcast);

	/* Broadcast setup ? */
	if (!tick_device_is_functional(dev))
		return;

	if ((dev->features & CLOCK_EVT_FEAT_PERIODIC) &&
	    !tick_broadcast_oneshot_active()) {
		// 切换ce设备为周期性
		clockevents_switch_state(dev, CLOCK_EVT_STATE_PERIODIC);
	} else {/* 
		1 dev不是周期性的
		2 广播设备处于one-shot模式
		*/
		unsigned int seq;
		ktime_t next;

		do {
			seq = read_seqcount_begin(&jiffies_seq);
			next = tick_next_period; //获取下一个周期性tick触发的时间
		} while (read_seqcount_retry(&jiffies_seq, seq));
		// 切换ce设备为one-shot
		clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);

		for (;;) {
			// 设置ce设备下一次到期时间
			if (!clockevents_program_event(dev, next, false))
				return; // clockevents_program_event设置好了就返回
			next = ktime_add_ns(next, TICK_NSEC);
		}
	}
}

#ifdef CONFIG_NO_HZ_FULL
static void giveup_do_timer(void *info)
{
	int cpu = *(unsigned int *)info;

	WARN_ON(tick_do_timer_cpu != smp_processor_id());

	tick_do_timer_cpu = cpu;
}

static void tick_take_do_timer_from_boot(void)
{
	int cpu = smp_processor_id();
	int from = tick_do_timer_boot_cpu;

	if (from >= 0 && from != cpu)
		smp_call_function_single(from, giveup_do_timer, &cpu, 1);
}
#endif

/*
 * Setup the tick device
 设置某个cpu的pcp的tick设备
 */
static void tick_setup_device(struct tick_device *td,
			      struct clock_event_device *newdev, int cpu,
			      const struct cpumask *cpumask)
{
	void (*handler)(struct clock_event_device *) = NULL;
	ktime_t next_event = 0;

	/*
	 * First device setup ?
	 如果是初始化tick设备
	 */
	if (!td->evtdev) {
		/*
		 * If no cpu took the do_timer update, assign it to
		 * this cpu:
		 */
		if (tick_do_timer_cpu == TICK_DO_TIMER_BOOT) {
			tick_do_timer_cpu = cpu;
			tick_next_period = ktime_get();
#ifdef CONFIG_NO_HZ_FULL
			/*
			 * The boot CPU may be nohz_full, in which case set
			 * tick_do_timer_boot_cpu so the first housekeeping
			 * secondary that comes up will take do_timer from
			 * us.
			 */
			if (tick_nohz_full_cpu(cpu))
				tick_do_timer_boot_cpu = cpu;

		} else if (tick_do_timer_boot_cpu != -1 &&
						!tick_nohz_full_cpu(cpu)) {
			tick_take_do_timer_from_boot();
			tick_do_timer_boot_cpu = -1;
			WARN_ON(tick_do_timer_cpu != cpu);
#endif
		}

		/*
		 * Startup in periodic mode first.
		 */
		td->mode = TICKDEV_MODE_PERIODIC;
	} else {// 如果是拿newdev替换旧的tick设备的clock event设备
		// 获取tick设备之前的clock event设备的event_handler
		handler = td->evtdev->event_handler;
		// 获取tick设备之前的clock event设备的next_event触发时间
		next_event = td->evtdev->next_event;
		// 关闭旧设备的ce设备
		td->evtdev->event_handler = clockevents_handle_noop;
	}
	// 设置新的clock event设备
	td->evtdev = newdev;

	/*
	 * When the device is not per cpu, pin the interrupt to the
	 * current cpu:
	 */
	if (!cpumask_equal(newdev->cpumask, cpumask))
		irq_set_affinity(newdev->irq, cpumask);

	/*
	 * When global broadcasting is active, check if the current
	 * device is registered as a placeholder for broadcast mode.
	 * This allows us to handle this x86 misfeature in a generic
	 * way. This function also returns !=0 when we keep the
	 * current active broadcast state for this CPU.
	 如果是全局广播模式, 则检查当前设备是否注册为广播模式的占位符
	 这允许我们以通用方式处理这个x86错误特性。 当我们保持当前活动的广播状态时，此函数还返回！= 0
	 */
	if (tick_device_uses_broadcast(newdev, cpu))
		return;

	if (td->mode == TICKDEV_MODE_PERIODIC)
		tick_setup_periodic(newdev, 0); // 设置ce设备为周期性,也可能是one-shot
	else
		tick_setup_oneshot(newdev, handler, next_event);
}
/* 
安装新设备用于替换旧设备
新设备更合适
=======================
可以用来删除解绑旧设备
*/
void tick_install_replacement(struct clock_event_device *newdev)
{
	// 获取当前cpu的tick设备
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	int cpu = smp_processor_id();
	// 进行相关设备的put和get
	clockevents_exchange_device(td->evtdev, newdev);
	// 设置td的新ce
	tick_setup_device(td, newdev, cpu, cpumask_of(cpu));
	if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_oneshot_notify();
}
// 检查newdev是否比curdev更适合
static bool tick_check_percpu(struct clock_event_device *curdev,
			      struct clock_event_device *newdev, int cpu)
{
	if (!cpumask_test_cpu(cpu, newdev->cpumask))
		return false;
	if (cpumask_equal(newdev->cpumask, cpumask_of(cpu)))
		return true;
	/* Check if irq affinity can be set */
	if (newdev->irq >= 0 && !irq_can_set_affinity(newdev->irq))
		return false;
	/* Prefer an existing cpu local device */
	if (curdev && cpumask_equal(curdev->cpumask, cpumask_of(cpu)))
		return false;
	return true;
}
/* 
检查newdev是否比curdev更适合
*/
static bool tick_check_preferred(struct clock_event_device *curdev,
				 struct clock_event_device *newdev)
{
	/* Prefer oneshot capable device */
	if (!(newdev->features & CLOCK_EVT_FEAT_ONESHOT)) {
		if (curdev && (curdev->features & CLOCK_EVT_FEAT_ONESHOT))
			return false;
		if (tick_oneshot_mode_active())
			return false;
	}

	/*
	 * Use the higher rated one, but prefer a CPU local device with a lower
	 * rating than a non-CPU local device
	 */
	return !curdev ||
		newdev->rating > curdev->rating ||
	       !cpumask_equal(curdev->cpumask, newdev->cpumask);
}

/*
 * Check whether the new device is a better fit than curdev. curdev
 * can be NULL !
 检查新设备是否比curdev更适合。curdev可以为NULL！
 ==============================================
 卸载解绑curdev的时候可能会调用这个函数
 */
bool tick_check_replacement(struct clock_event_device *curdev,
			    struct clock_event_device *newdev)
{
	if (!tick_check_percpu(curdev, newdev, smp_processor_id()))
		return false;

	return tick_check_preferred(curdev, newdev);
}

/*
当注册上来一个新的定时事件设备的时候，会调用Tick层的
tick_check_new_device函数尝试使用新的定时事件设备替换老的定时事件设备，
作为当前CPU上的Tick设备。
 * Check, if the new registered device should be used. Called with
 * clockevents_lock held and interrupts disabled.
 检查新注册的设备是否应该使用。在持有clockevents_lock并禁用中断时调用。
 */
void tick_check_new_device(struct clock_event_device *newdev)
{
	struct clock_event_device *curdev;
	struct tick_device *td;
	int cpu;

	cpu = smp_processor_id();
	td = &per_cpu(tick_cpu_device, cpu);
	curdev = td->evtdev;
	// 刚刚是获取cpu现在的td和ce


	// 如果新设备更适合
	if (!tick_check_replacement(curdev, newdev))
		goto out_bc;

	if (!try_module_get(newdev->owner))
		return;

	/*
	 * Replace the eventually existing device by the new
	 * device. If the current device is the broadcast device, do
	 * not give it back to the clockevents layer !
	 */
	if (tick_is_broadcast_device(curdev)) {
		clockevents_shutdown(curdev);
		curdev = NULL;
	}
	// 进行相关的put和get
	clockevents_exchange_device(curdev, newdev);
	// 设置新的ce
	tick_setup_device(td, newdev, cpu, cpumask_of(cpu));
	if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_oneshot_notify();
	return;

out_bc:
	/*
	 * Can the new device be used as a broadcast device ?
	 但是，如果新的设备某些条件不满足或者还不如老的设备的时候，
	 会接着尝试调用tick_install_broadcast_device函数，
	 看看这个设备能不能作为Tick广播层的设备
	 */
	tick_install_broadcast_device(newdev, cpu);
}

/**
 * tick_broadcast_oneshot_control - Enter/exit broadcast oneshot mode
 * @state:	The target state (enter/exit)
 *
 * The system enters/leaves a state, where affected devices might stop
 * Returns 0 on success, -EBUSY if the cpu is used to broadcast wakeups.
 *
 * Called with interrupts disabled, so clockevents_lock is not
 * required here because the local clock event device cannot go away
 * under us.
 */
int tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);

	if (!(td->evtdev->features & CLOCK_EVT_FEAT_C3STOP))
		return 0;

	return __tick_broadcast_oneshot_control(state);
}
EXPORT_SYMBOL_GPL(tick_broadcast_oneshot_control);

#ifdef CONFIG_HOTPLUG_CPU
/*
 * Transfer the do_timer job away from a dying cpu.
 *
 * Called with interrupts disabled. No locking required. If
 * tick_do_timer_cpu is owned by this cpu, nothing can change it.
 */
void tick_handover_do_timer(void)
{
	if (tick_do_timer_cpu == smp_processor_id())
		tick_do_timer_cpu = cpumask_first(cpu_online_mask);
}

/*
下线cpu的时候调用
关闭td和ce
 * Shutdown an event device on a given cpu:
 *
 * This is called on a life CPU, when a CPU is dead. So we cannot
 * access the hardware device itself.
 * We just set the mode and remove it from the lists.
 当一个cpu下线的时候，调用这个函数
 所以我们不能访问硬件设备本身
 我们只是设置模式并将其从列表中删除
 */
void tick_shutdown(unsigned int cpu)
{
	// 获取td设备
	struct tick_device *td = &per_cpu(tick_cpu_device, cpu);
	// 获取ce设备
	struct clock_event_device *dev = td->evtdev;

	td->mode = TICKDEV_MODE_PERIODIC;
	if (dev) {
		/*
		 * Prevent that the clock events layer tries to call
		 * the set mode function!
		 阻止时钟事件层尝试调用设置模式函数！
		 */
		clockevent_set_state(dev, CLOCK_EVT_STATE_DETACHED);
		clockevents_exchange_device(dev, NULL);
		dev->event_handler = clockevents_handle_noop;
		td->evtdev = NULL;
	}
}
#endif

/**
停止local设备的tick
* tick_suspend_local - Suspend the local tick device
 *
 * Called from the local cpu for freeze with interrupts disabled.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_suspend_local(void)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);

	clockevents_shutdown(td->evtdev);
}

/**
恢复local 设备的tick
 * tick_resume_local - Resume the local tick device
 *
 * Called from the local CPU for unfreeze or XEN resume magic.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_resume_local(void)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	bool broadcast = tick_resume_check_broadcast();

	/* 恢复td的设备的tick */
	clockevents_tick_resume(td->evtdev);
	if (!broadcast) {
		if (td->mode == TICKDEV_MODE_PERIODIC)
			tick_setup_periodic(td->evtdev, 0);
		else
		/* 切换为one-shot状态,设置下次到期时间 */
			tick_resume_oneshot();
	}

	/*
	 * Ensure that hrtimers are up to date and the clockevents device
	 * is reprogrammed correctly when high resolution timers are
	 * enabled.
	   保证hrtimers是最新的，并且当启用高分辨率定时器时，clockevents设备被正确重新编程。
	 */
	hrtimers_resume_local();
}

/**
挂起tk的时候停止tick
 * tick_suspend - Suspend the tick and the broadcast device
 *
 * Called from syscore_suspend() via timekeeping_suspend with only one
 * CPU online and interrupts disabled or from tick_unfreeze() under
 * tick_freeze_lock.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_suspend(void)
{
	/* 就是把next时间设置为LONGMAX */
	tick_suspend_local();
	tick_suspend_broadcast();
}

/**
恢复ce设备和hrtimer的tick
 * tick_resume - Resume the tick and the broadcast device
 *
 * Called from syscore_resume() via timekeeping_resume with only one
 * CPU online and interrupts disabled.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_resume(void)
{
	/* 恢复广播设备的tick */
	tick_resume_broadcast();
	/* 这里进行当前cpu的hrtimer_bases的更新, 检查和设置到期时间什么的 */
	tick_resume_local();
}

#ifdef CONFIG_SUSPEND
static DEFINE_RAW_SPINLOCK(tick_freeze_lock);
static unsigned int tick_freeze_depth;

/**
 * tick_freeze - Suspend the local tick and (possibly) timekeeping.
 *
 * Check if this is the last online CPU executing the function and if so,
 * suspend timekeeping.  Otherwise suspend the local tick.
 *
 * Call with interrupts disabled.  Must be balanced with %tick_unfreeze().
 * Interrupts must not be enabled before the subsequent %tick_unfreeze().
 */
void tick_freeze(void)
{
	raw_spin_lock(&tick_freeze_lock);

	tick_freeze_depth++;
	if (tick_freeze_depth == num_online_cpus()) {
		trace_suspend_resume(TPS("timekeeping_freeze"),
				     smp_processor_id(), true);
		system_state = SYSTEM_SUSPEND;
		sched_clock_suspend();
		timekeeping_suspend();
	} else {
		tick_suspend_local();
	}

	raw_spin_unlock(&tick_freeze_lock);
}

/**
 * tick_unfreeze - Resume the local tick and (possibly) timekeeping.
 *
 * Check if this is the first CPU executing the function and if so, resume
 * timekeeping.  Otherwise resume the local tick.
 *
 * Call with interrupts disabled.  Must be balanced with %tick_freeze().
 * Interrupts must not be enabled after the preceding %tick_freeze().
 */
void tick_unfreeze(void)
{
	raw_spin_lock(&tick_freeze_lock);

	if (tick_freeze_depth == num_online_cpus()) {
		timekeeping_resume();
		sched_clock_resume();
		system_state = SYSTEM_RUNNING;
		trace_suspend_resume(TPS("timekeeping_freeze"),
				     smp_processor_id(), false);
	} else {
		touch_softlockup_watchdog();
		tick_resume_local();
	}

	tick_freeze_depth--;

	raw_spin_unlock(&tick_freeze_lock);
}
#endif /* CONFIG_SUSPEND */

/**
 * tick_init - initialize the tick control
 */
void __init tick_init(void)
{
	tick_broadcast_init();
	tick_nohz_init();
}

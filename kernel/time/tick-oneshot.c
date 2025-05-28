// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains functions which manage high resolution tick
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
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/sched.h>

#include "tick-internal.h"

/**
program是指?
 * tick_program_event - program the CPU local timer device for the next event

 * @description: 如果cpubase的到期时间发生了变化,调用这个函数
 * @param {ktime_t} expires. 最新计算的某个到期时间发生变化了的cpubase的新到期时间
 * @param {int} force
 * @return {*}
 */
int tick_program_event(ktime_t expires, int force)
{
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);

	/* 以后 */
	if (unlikely(expires == KTIME_MAX)) {
		/*
		 * We don't need the clock event device any more, stop it.
		 */
		clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT_STOPPED);
		dev->next_event = KTIME_MAX;
		return 0;
	}

	/* 以后 */
	if (unlikely(clockevent_state_oneshot_stopped(dev))) {
		/*
		 * We need the clock event again, configure it in ONESHOT mode
		 * before using it.
		 */
		clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);
	}

	return clockevents_program_event(dev, expires, force);
}

/**
恢复当前cpu的td设备的one-shot
 * tick_resume_oneshot - resume oneshot mode
 */
void tick_resume_oneshot(void)
{
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);

	/* 设置设备的状态 */
	clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);
	/* 编程设备. 设置到期时间什么的 */
	clockevents_program_event(dev, ktime_get(), true);
}

/**
替换td设备的ce设备的时候设置ce设备为one-shot模式
handler是旧ce设备的event_handler
next_event是旧ce设备的next_event到期时间
 * tick_setup_oneshot - setup the event device for oneshot mode (hres or nohz)
 */
void tick_setup_oneshot(struct clock_event_device *newdev,
			void (*handler)(struct clock_event_device *),
			ktime_t next_event)
{
	// 设置event_handler回调函数
	newdev->event_handler = handler;
	// 切换为one-shot模式
	clockevents_switch_state(newdev, CLOCK_EVT_STATE_ONESHOT);
	// 设置下一次到期时间
	clockevents_program_event(newdev, next_event, true);
}

/**
开启使用hrtimer的函数
==================================
通过了测试正式准备切换到单次触发模式了，最终会调用tick_switch_to_oneshot函数。
如果切换成功，函数的最后会调用tick_broadcast_switch_to_oneshot函数，将Tick广播层
也切换到单次触发模式
 * tick_switch_to_oneshot - switch to oneshot mode
 */
int tick_switch_to_oneshot(void (*handler)(struct clock_event_device *))
{
	/* 获取tick设备 */
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	struct clock_event_device *dev = td->evtdev;

	if (!dev || !(dev->features & CLOCK_EVT_FEAT_ONESHOT) ||
		    !tick_device_is_functional(dev)) {
	/* 如果设备不可用 */
		pr_info("Clockevents: could not switch to one-shot mode:");
		if (!dev) {
			pr_cont(" no tick device\n");
		} else {
			if (!tick_device_is_functional(dev))
				pr_cont(" %s is not functional.\n", dev->name);
			else
				pr_cont(" %s does not support one-shot mode.\n",
					dev->name);
		}
		return -EINVAL;
	}
	/* 设置设备 */
	td->mode = TICKDEV_MODE_ONESHOT;
	/* 设置处理handler */
	dev->event_handler = handler;
	clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);
	/* 传播这次变动 */
	tick_broadcast_switch_to_oneshot();
	return 0;
}

/**
 * tick_oneshot_mode_active - check whether the system is in oneshot mode
 *
 * returns 1 when either nohz or highres are enabled. otherwise 0.
 */
int tick_oneshot_mode_active(void)
{
	unsigned long flags;
	int ret;

	local_irq_save(flags);
	ret = __this_cpu_read(tick_cpu_device.mode) == TICKDEV_MODE_ONESHOT;
	local_irq_restore(flags);

	return ret;
}

#ifdef CONFIG_HIGH_RES_TIMERS
/**
开启高精度计时
 * tick_init_highres - switch to high resolution mode
 *
 * Called with interrupts disabled.
 */
int tick_init_highres(void)
{
	return tick_switch_to_oneshot(hrtimer_interrupt);
}
#endif

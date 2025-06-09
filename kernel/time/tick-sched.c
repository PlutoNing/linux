// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 *  Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 *  Copyright(C) 2006-2007  Timesys Corp., Thomas Gleixner
 *
 *  No idle tick implementation for low and high resolution timers
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/percpu.h>
#include <linux/nmi.h>
#include <linux/profile.h>
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#include <linux/sched/stat.h>
#include <linux/sched/nohz.h>
#include <linux/sched/loadavg.h>
#include <linux/module.h>
#include <linux/irq_work.h>
#include <linux/posix-timers.h>
#include <linux/context_tracking.h>
#include <linux/mm.h>

#include <asm/irq_regs.h>

#include "tick-internal.h"

#include <trace/events/timer.h>

/*
 * Per-CPU nohz control structure
 好像是表示那个什么模拟的tick层
 */
static DEFINE_PER_CPU(struct tick_sched, tick_cpu_sched);
/* 获取tick_cpu_sched设备 */
struct tick_sched *tick_get_tick_sched(int cpu)
{
	return &per_cpu(tick_cpu_sched, cpu);
}

#if defined(CONFIG_NO_HZ_COMMON) || defined(CONFIG_HIGH_RES_TIMERS)
/*
last_jiffies_update是一个全局变量，用来记录上一次jiffy更新时的时间：
 * The time, when the last jiffy update happened. Write access must hold
 * jiffies_lock and jiffies_seq. tick_nohz_next_event() needs to get a
 * consistent view of jiffies and last_jiffies_update.
   上一次jiffy更新发生的时间。写访问必须持有jiffies_lock和jiffies_seq。
   tick_nohz_next_event()需要获得jiffies和last_jiffies_update的一致视图。
 */
static ktime_t last_jiffies_update;

/*
内核内部的全局变量jiffies，用于记录自系统启动以来经过了多少个TICK。
jiffies由tick_do_update_jiffies64函数来更新
 * Must be called with interrupts disabled !
 */
static void tick_do_update_jiffies64(ktime_t now)
{
	unsigned long ticks = 1;
	ktime_t delta, nextp;

	/*
	 * 64bit can do a quick check without holding jiffies lock and
	 * without looking at the sequence count. The smp_load_acquire()
	 * pairs with the update done later in this function.
	 *
	 * 32bit cannot do that because the store of tick_next_period
	 * consists of two 32bit stores and the first store could move it
	 * to a random point in the future.
	 */
	if (IS_ENABLED(CONFIG_64BIT)) {
		if (ktime_before(now, smp_load_acquire(&tick_next_period)))
			return;
	} else {
		unsigned int seq;
		/*
		 * Avoid contention on jiffies_lock and protect the quick
		 * check with the sequence count.
		 */
		do {
			seq = read_seqcount_begin(&jiffies_seq);
			nextp = tick_next_period;
		} while (read_seqcount_retry(&jiffies_seq, seq));

		if (ktime_before(now, nextp))
			return;
	}

	/* Quick check failed, i.e. update is required. */
	raw_spin_lock(&jiffies_lock);
	/*
	 * Reevaluate with the lock held. Another CPU might have done the
	 * update already.
	 */
	if (ktime_before(now, tick_next_period)) {
		raw_spin_unlock(&jiffies_lock);
		return;
	}

	write_seqcount_begin(&jiffies_seq);

	delta = ktime_sub(now, tick_next_period);
	if (unlikely(delta >= TICK_NSEC)) {
		/* Slow path for long idle sleep times */
		s64 incr = TICK_NSEC;

		ticks += ktime_divns(delta, incr);

		last_jiffies_update = ktime_add_ns(last_jiffies_update,
						   incr * ticks);
	} else {
		last_jiffies_update = ktime_add_ns(last_jiffies_update,
						   TICK_NSEC);
	}

	/* Advance jiffies to complete the jiffies_seq protected job */
	jiffies_64 += ticks;

	/*
	 * Keep the tick_next_period variable up to date.
	 */
	nextp = ktime_add_ns(last_jiffies_update, TICK_NSEC);

	if (IS_ENABLED(CONFIG_64BIT)) {
		/*
		 * Pairs with smp_load_acquire() in the lockless quick
		 * check above and ensures that the update to jiffies_64 is
		 * not reordered vs. the store to tick_next_period, neither
		 * by the compiler nor by the CPU.
		 */
		smp_store_release(&tick_next_period, nextp);
	} else {
		/*
		 * A plain store is good enough on 32bit as the quick check
		 * above is protected by the sequence count.
		 */
		tick_next_period = nextp;
	}

	/*
	 * Release the sequence count. calc_global_load() below is not
	 * protected by it, but jiffies_lock needs to be held to prevent
	 * concurrent invocations.
	 */
	write_seqcount_end(&jiffies_seq);
	// 计算负载
	calc_global_load();

	raw_spin_unlock(&jiffies_lock);
	// 更新墙钟
	update_wall_time();
}

/*
tick_init_jiffy_update函数用来获得上一次jiffy更新的时间：
 * Initialize and return retrieve the jiffies update.
 */
static ktime_t tick_init_jiffy_update(void)
{
	ktime_t period;

	raw_spin_lock(&jiffies_lock);
	write_seqcount_begin(&jiffies_seq);
	/* Did we start the jiffies update yet ? */
	if (last_jiffies_update == 0) {
		u32 rem;

		/*
		 * Ensure that the tick is aligned to a multiple of
		 * TICK_NSEC.
		 */
		div_u64_rem(tick_next_period, TICK_NSEC, &rem);
		if (rem)
			tick_next_period += TICK_NSEC - rem;

		last_jiffies_update = tick_next_period;
	}
	period = last_jiffies_update;
	write_seqcount_end(&jiffies_seq);
	raw_spin_unlock(&jiffies_lock);
	return period;
}

#define MAX_STALLED_JIFFIES 5
/* 
根据当前时间来更新系统jiffies
也是一个驱动的作用
===========================================================
内核内部的全局变量jiffies，用于记录自系统启动以来经过了多少个TICK。
jiffies由tick_do_update_jiffies64函数来更新
jiffies变量更新时调用的相关函数：
timer timeout
	-> tick_nohz_handler
		-> tick_sched_do_timer
			-> tick_do_update_jiffies64
=============================================
			|-->tick_sched_do_timer(ts, now);
    |-->tick_do_update_jiffies64(now);
      |-->  jiffies_64 += ticks;     //更新jiffies变量
    |-->  calc_global_load();    //每10 jiffies计算1次全局负载
    |-->  update_wall_time();   //更新墙上时间(系统时间)
*/
static void tick_sched_do_timer(struct tick_sched *ts, ktime_t now)
{
	int cpu = smp_processor_id();

#ifdef CONFIG_NO_HZ_COMMON
	/*
	 * Check if the do_timer duty was dropped. We don't care about
	 * concurrency: This happens only when the CPU in charge went
	 * into a long sleep. If two CPUs happen to assign themselves to
	 * this duty, then the jiffies update is still serialized by
	 * jiffies_lock.
	 *
	 * If nohz_full is enabled, this should not happen because the
	 * tick_do_timer_cpu never relinquishes.
	 如果还没有选中由哪个CPU来更新系统jiffies
	 */
	if (unlikely(tick_do_timer_cpu == TICK_DO_TIMER_NONE)) {
#ifdef CONFIG_NO_HZ_FULL
		WARN_ON_ONCE(tick_nohz_full_running);
#endif
// 就选择当前CPU来更新系统jiffies
		tick_do_timer_cpu = cpu;
	}
#endif

	/* Check, if the jiffies need an update
	调用tick_do_update_jiffies64函数，负责更新系统jiffies
	*/
	if (tick_do_timer_cpu == cpu)
		tick_do_update_jiffies64(now);

	/*
	 * If jiffies update stalled for too long (timekeeper in stop_machine()
	 * or VMEXIT'ed for several msecs), force an update.
	 */
	if (ts->last_tick_jiffies != jiffies) {
		ts->stalled_jiffies = 0;
		ts->last_tick_jiffies = READ_ONCE(jiffies);
	} else {
		if (++ts->stalled_jiffies == MAX_STALLED_JIFFIES) {
			tick_do_update_jiffies64(now);
			ts->stalled_jiffies = 0;
			ts->last_tick_jiffies = READ_ONCE(jiffies);
		}
	}

	if (ts->inidle)
		ts->got_idle_tick = 1;
}
/* 
tick_sched_handle函数主要的功能是通知（低分辨率）定时器层Tick已经到来了，
可以开始处理定时器了。一旦切换到高精度模式，（低分辨率）定时器层实际是由Tick模拟层来触发的。
===================================================================
sched_timer定时器中断处理程序内容如下，sched_timer此时就是系统节拍定时器，
不仅给调度程序提供心跳，更新jiffies，还充当了一个管理者，以jiffies时间精度给内核其他程序提供定时服务。
原有的timer的功能接口，如timer_setup()、add_timer()以及其经典的time wheel方式被保留，
继续给内核中其他程序提供定时服务。
|-->tick_sched_handle(ts, regs);
  |-->  update_process_times(user_mode(regs)); //更新当前进程时间
  |-->  account_process_tick(p, user_tick); //计算进程运行tick
  |-->  run_local_timers(); //运行自己管理的低精度定时任务
  |-->  rraise_softirq(TIMER_SOFTIRQ); //通过TIMER_SOFTIRQ处理本地定时任务
  |-->  rcu_sched_clock_irq(user_tick);
  |-->  scheduler_tick(); //调度程序tick处理
  |-->  run_posix_cpu_timers(); //处理posix timer与  cpu  运行时间相关的事务
*/
static void tick_sched_handle(struct tick_sched *ts, struct pt_regs *regs)
{
#ifdef CONFIG_NO_HZ_COMMON
	/*
	 * When we are idle and the tick is stopped, we have to touch
	 * the watchdog as we might not schedule for a really long
	 * time. This happens on complete idle SMP systems while
	 * waiting on the login prompt. We also increment the "start of
	 * idle" jiffy stamp so the idle accounting adjustment we do
	 * when we go busy again does not account too much ticks.
	 */
	if (ts->tick_stopped) {
		touch_softlockup_watchdog_sched();
		if (is_idle_task(current))
			ts->idle_jiffies++;
		/*
		 * In case the current tick fired too early past its expected
		 * expiration, make sure we don't bypass the next clock reprogramming
		 * to the same deadline.
		 */
		ts->next_tick = 0;
	}
#endif
/*  */
	update_process_times(user_mode(regs));
	profile_tick(CPU_PROFILING);
}
#endif

#ifdef CONFIG_NO_HZ_FULL
cpumask_var_t tick_nohz_full_mask;
EXPORT_SYMBOL_GPL(tick_nohz_full_mask);
bool tick_nohz_full_running;
EXPORT_SYMBOL_GPL(tick_nohz_full_running);
static atomic_t tick_dep_mask;

static bool check_tick_dependency(atomic_t *dep)
{
	int val = atomic_read(dep);

	if (val & TICK_DEP_MASK_POSIX_TIMER) {
		trace_tick_stop(0, TICK_DEP_MASK_POSIX_TIMER);
		return true;
	}

	if (val & TICK_DEP_MASK_PERF_EVENTS) {
		trace_tick_stop(0, TICK_DEP_MASK_PERF_EVENTS);
		return true;
	}

	if (val & TICK_DEP_MASK_SCHED) {
		trace_tick_stop(0, TICK_DEP_MASK_SCHED);
		return true;
	}

	if (val & TICK_DEP_MASK_CLOCK_UNSTABLE) {
		trace_tick_stop(0, TICK_DEP_MASK_CLOCK_UNSTABLE);
		return true;
	}

	if (val & TICK_DEP_MASK_RCU) {
		trace_tick_stop(0, TICK_DEP_MASK_RCU);
		return true;
	}

	if (val & TICK_DEP_MASK_RCU_EXP) {
		trace_tick_stop(0, TICK_DEP_MASK_RCU_EXP);
		return true;
	}

	return false;
}

static bool can_stop_full_tick(int cpu, struct tick_sched *ts)
{
	lockdep_assert_irqs_disabled();

	if (unlikely(!cpu_online(cpu)))
		return false;

	if (check_tick_dependency(&tick_dep_mask))
		return false;

	if (check_tick_dependency(&ts->tick_dep_mask))
		return false;

	if (check_tick_dependency(&current->tick_dep_mask))
		return false;

	if (check_tick_dependency(&current->signal->tick_dep_mask))
		return false;

	return true;
}

static void nohz_full_kick_func(struct irq_work *work)
{
	/* Empty, the tick restart happens on tick_nohz_irq_exit() */
}

static DEFINE_PER_CPU(struct irq_work, nohz_full_kick_work) =
	IRQ_WORK_INIT_HARD(nohz_full_kick_func);

/*
 * Kick this CPU if it's full dynticks in order to force it to
 * re-evaluate its dependency on the tick and restart it if necessary.
 * This kick, unlike tick_nohz_full_kick_cpu() and tick_nohz_full_kick_all(),
 * is NMI safe.
 */
static void tick_nohz_full_kick(void)
{
	if (!tick_nohz_full_cpu(smp_processor_id()))
		return;

	irq_work_queue(this_cpu_ptr(&nohz_full_kick_work));
}

/*
 * Kick the CPU if it's full dynticks in order to force it to
 * re-evaluate its dependency on the tick and restart it if necessary.
 */
void tick_nohz_full_kick_cpu(int cpu)
{
	if (!tick_nohz_full_cpu(cpu))
		return;

	irq_work_queue_on(&per_cpu(nohz_full_kick_work, cpu), cpu);
}

static void tick_nohz_kick_task(struct task_struct *tsk)
{
	int cpu;

	/*
	 * If the task is not running, run_posix_cpu_timers()
	 * has nothing to elapse, IPI can then be spared.
	 *
	 * activate_task()                      STORE p->tick_dep_mask
	 *   STORE p->on_rq
	 * __schedule() (switch to task 'p')    smp_mb() (atomic_fetch_or())
	 *   LOCK rq->lock                      LOAD p->on_rq
	 *   smp_mb__after_spin_lock()
	 *   tick_nohz_task_switch()
	 *     LOAD p->tick_dep_mask
	 */
	if (!sched_task_on_rq(tsk))
		return;

	/*
	 * If the task concurrently migrates to another CPU,
	 * we guarantee it sees the new tick dependency upon
	 * schedule.
	 *
	 * set_task_cpu(p, cpu);
	 *   STORE p->cpu = @cpu
	 * __schedule() (switch to task 'p')
	 *   LOCK rq->lock
	 *   smp_mb__after_spin_lock()          STORE p->tick_dep_mask
	 *   tick_nohz_task_switch()            smp_mb() (atomic_fetch_or())
	 *      LOAD p->tick_dep_mask           LOAD p->cpu
	 */
	cpu = task_cpu(tsk);

	preempt_disable();
	if (cpu_online(cpu))
		tick_nohz_full_kick_cpu(cpu);
	preempt_enable();
}

/*
 * Kick all full dynticks CPUs in order to force these to re-evaluate
 * their dependency on the tick and restart it if necessary.
 */
static void tick_nohz_full_kick_all(void)
{
	int cpu;

	if (!tick_nohz_full_running)
		return;

	preempt_disable();
	for_each_cpu_and(cpu, tick_nohz_full_mask, cpu_online_mask)
		tick_nohz_full_kick_cpu(cpu);
	preempt_enable();
}

static void tick_nohz_dep_set_all(atomic_t *dep,
				  enum tick_dep_bits bit)
{
	int prev;

	prev = atomic_fetch_or(BIT(bit), dep);
	if (!prev)
		tick_nohz_full_kick_all();
}

/*
 * Set a global tick dependency. Used by perf events that rely on freq and
 * by unstable clock.
 */
void tick_nohz_dep_set(enum tick_dep_bits bit)
{
	tick_nohz_dep_set_all(&tick_dep_mask, bit);
}

void tick_nohz_dep_clear(enum tick_dep_bits bit)
{
	atomic_andnot(BIT(bit), &tick_dep_mask);
}

/*
 * Set per-CPU tick dependency. Used by scheduler and perf events in order to
 * manage events throttling.
 */
void tick_nohz_dep_set_cpu(int cpu, enum tick_dep_bits bit)
{
	int prev;
	struct tick_sched *ts;

	ts = per_cpu_ptr(&tick_cpu_sched, cpu);

	prev = atomic_fetch_or(BIT(bit), &ts->tick_dep_mask);
	if (!prev) {
		preempt_disable();
		/* Perf needs local kick that is NMI safe */
		if (cpu == smp_processor_id()) {
			tick_nohz_full_kick();
		} else {
			/* Remote irq work not NMI-safe */
			if (!WARN_ON_ONCE(in_nmi()))
				tick_nohz_full_kick_cpu(cpu);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(tick_nohz_dep_set_cpu);

void tick_nohz_dep_clear_cpu(int cpu, enum tick_dep_bits bit)
{
	struct tick_sched *ts = per_cpu_ptr(&tick_cpu_sched, cpu);

	atomic_andnot(BIT(bit), &ts->tick_dep_mask);
}
EXPORT_SYMBOL_GPL(tick_nohz_dep_clear_cpu);

/*
 * Set a per-task tick dependency. RCU need this. Also posix CPU timers
 * in order to elapse per task timers.
 */
void tick_nohz_dep_set_task(struct task_struct *tsk, enum tick_dep_bits bit)
{
	if (!atomic_fetch_or(BIT(bit), &tsk->tick_dep_mask))
		tick_nohz_kick_task(tsk);
}
EXPORT_SYMBOL_GPL(tick_nohz_dep_set_task);

void tick_nohz_dep_clear_task(struct task_struct *tsk, enum tick_dep_bits bit)
{
	atomic_andnot(BIT(bit), &tsk->tick_dep_mask);
}
EXPORT_SYMBOL_GPL(tick_nohz_dep_clear_task);

/*
 * Set a per-taskgroup tick dependency. Posix CPU timers need this in order to elapse
 * per process timers.
 */
void tick_nohz_dep_set_signal(struct task_struct *tsk,
			      enum tick_dep_bits bit)
{
	int prev;
	struct signal_struct *sig = tsk->signal;

	prev = atomic_fetch_or(BIT(bit), &sig->tick_dep_mask);
	if (!prev) {
		struct task_struct *t;

		lockdep_assert_held(&tsk->sighand->siglock);
		__for_each_thread(sig, t)
			tick_nohz_kick_task(t);
	}
}

void tick_nohz_dep_clear_signal(struct signal_struct *sig, enum tick_dep_bits bit)
{
	atomic_andnot(BIT(bit), &sig->tick_dep_mask);
}

/*
 * Re-evaluate the need for the tick as we switch the current task.
 * It might need the tick due to per task/process properties:
 * perf events, posix CPU timers, ...
 */
void __tick_nohz_task_switch(void)
{
	struct tick_sched *ts;

	if (!tick_nohz_full_cpu(smp_processor_id()))
		return;

	ts = this_cpu_ptr(&tick_cpu_sched);

	if (ts->tick_stopped) {
		if (atomic_read(&current->tick_dep_mask) ||
		    atomic_read(&current->signal->tick_dep_mask))
			tick_nohz_full_kick();
	}
}

/* Get the boot-time nohz CPU list from the kernel parameters. */
void __init tick_nohz_full_setup(cpumask_var_t cpumask)
{
	alloc_bootmem_cpumask_var(&tick_nohz_full_mask);
	cpumask_copy(tick_nohz_full_mask, cpumask);
	tick_nohz_full_running = true;
}

bool tick_nohz_cpu_hotpluggable(unsigned int cpu)
{
	/*
	 * The tick_do_timer_cpu CPU handles housekeeping duty (unbound
	 * timers, workqueues, timekeeping, ...) on behalf of full dynticks
	 * CPUs. It must remain online when nohz full is enabled.
	 */
	if (tick_nohz_full_running && tick_do_timer_cpu == cpu)
		return false;
	return true;
}

static int tick_nohz_cpu_down(unsigned int cpu)
{
	return tick_nohz_cpu_hotpluggable(cpu) ? 0 : -EBUSY;
}

void __init tick_nohz_init(void)
{
	int cpu, ret;

	if (!tick_nohz_full_running)
		return;

	/*
	 * Full dynticks uses irq work to drive the tick rescheduling on safe
	 * locking contexts. But then we need irq work to raise its own
	 * interrupts to avoid circular dependency on the tick
	 */
	if (!arch_irq_work_has_interrupt()) {
		pr_warn("NO_HZ: Can't run full dynticks because arch doesn't support irq work self-IPIs\n");
		cpumask_clear(tick_nohz_full_mask);
		tick_nohz_full_running = false;
		return;
	}

	if (IS_ENABLED(CONFIG_PM_SLEEP_SMP) &&
			!IS_ENABLED(CONFIG_PM_SLEEP_SMP_NONZERO_CPU)) {
		cpu = smp_processor_id();

		if (cpumask_test_cpu(cpu, tick_nohz_full_mask)) {
			pr_warn("NO_HZ: Clearing %d from nohz_full range "
				"for timekeeping\n", cpu);
			cpumask_clear_cpu(cpu, tick_nohz_full_mask);
		}
	}

	for_each_cpu(cpu, tick_nohz_full_mask)
		ct_cpu_track_user(cpu);

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"kernel/nohz:predown", NULL,
					tick_nohz_cpu_down);
	WARN_ON(ret < 0);
	pr_info("NO_HZ: Full dynticks CPUs: %*pbl.\n",
		cpumask_pr_args(tick_nohz_full_mask));
}
#endif

/*
 * NOHZ - aka dynamic tick functionality
 */
#ifdef CONFIG_NO_HZ_COMMON
/*
 * NO HZ enabled ?
 */
bool tick_nohz_enabled __read_mostly  = true;
unsigned long tick_nohz_active  __read_mostly;
/*
 * Enable / Disable tickless mode
 */
static int __init setup_tick_nohz(char *str)
{
	return (kstrtobool(str, &tick_nohz_enabled) == 0);
}

__setup("nohz=", setup_tick_nohz);
/* 检查tick_cpu_sched是不是停止了 */
bool tick_nohz_tick_stopped(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	return ts->tick_stopped;
}
/* 检查此cpu的tick_cpu_sched是不是停止了 */
bool tick_nohz_tick_stopped_cpu(int cpu)
{
	struct tick_sched *ts = per_cpu_ptr(&tick_cpu_sched, cpu);

	return ts->tick_stopped;
}

/**
当CPU处于空闲状态时，tick_nohz_update_jiffies函数会被调用?
更新jiffies
 * tick_nohz_update_jiffies - update jiffies when idle was interrupted
 *
 * Called from interrupt entry when the CPU was idle
 *
 * In case the sched_tick was stopped on this CPU, we have to check if jiffies
 * must be updated. Otherwise an interrupt handler could use a stale jiffy
 * value. We do this unconditionally on any CPU, as we don't know whether the
 * CPU, which has the update task assigned is in a long sleep.
 */
static void tick_nohz_update_jiffies(ktime_t now)
{
	unsigned long flags;
	/* 记录idle_waketime */
	__this_cpu_write(tick_cpu_sched.idle_waketime, now);

	local_irq_save(flags);
	/* 更新jiffies */
	tick_do_update_jiffies64(now);
	local_irq_restore(flags);

	touch_softlockup_watchdog_sched();
}
/* 
处于空闲状态，则调用tick_nohz_stop_idle函数退出
*/
static void tick_nohz_stop_idle(struct tick_sched *ts, ktime_t now)
{
	ktime_t delta;

	if (WARN_ON_ONCE(!ts->idle_active))
		return;

	delta = ktime_sub(now, ts->idle_entrytime);

	write_seqcount_begin(&ts->idle_sleeptime_seq);
	if (nr_iowait_cpu(smp_processor_id()) > 0)
		ts->iowait_sleeptime = ktime_add(ts->iowait_sleeptime, delta);
	else
		ts->idle_sleeptime = ktime_add(ts->idle_sleeptime, delta);

	ts->idle_entrytime = now;
	ts->idle_active = 0;
	write_seqcount_end(&ts->idle_sleeptime_seq);

	sched_clock_idle_wakeup_event();
}
/* 
设置进入idle的时间, 设置处于idle的flag
===========================
该函数也主要是完成一些字段设置的工作，先将表示进入空闲状态时间的idle_entrytime
字段设置为当前时间，然后将表示当前CPU确实是处于空闲状态的字段idle_active也置1。
到此，准备工作就完成了，接着会调用tick_nohz_idle_stop_tick函数开始停Tick
*/
static void tick_nohz_start_idle(struct tick_sched *ts)
{
	write_seqcount_begin(&ts->idle_sleeptime_seq);
	ts->idle_entrytime = ktime_get();
	ts->idle_active = 1;
	write_seqcount_end(&ts->idle_sleeptime_seq);

	sched_clock_idle_sleep_event();
}

static u64 get_cpu_sleep_time_us(struct tick_sched *ts, ktime_t *sleeptime,
				 bool compute_delta, u64 *last_update_time)
{
	ktime_t now, idle;
	unsigned int seq;

	if (!tick_nohz_active)
		return -1;

	now = ktime_get();
	if (last_update_time)
		*last_update_time = ktime_to_us(now);

	do {
		seq = read_seqcount_begin(&ts->idle_sleeptime_seq);

		if (ts->idle_active && compute_delta) {
			ktime_t delta = ktime_sub(now, ts->idle_entrytime);

			idle = ktime_add(*sleeptime, delta);
		} else {
			idle = *sleeptime;
		}
	} while (read_seqcount_retry(&ts->idle_sleeptime_seq, seq));

	return ktime_to_us(idle);

}

/**
获取一个cpu的总的idle time
 * get_cpu_idle_time_us - get the total idle time of a CPU
 * @cpu: CPU number to query
 * @last_update_time: variable to store update time in. Do not update
 * counters if NULL.
 *
 * Return the cumulative idle time (since boot) for a given
 * CPU, in microseconds. Note this is partially broken due to
 * the counter of iowait tasks that can be remotely updated without
 * any synchronization. Therefore it is possible to observe backward
 * values within two consecutive reads.
 *
 * This time is measured via accounting rather than sampling,
 * and is as accurate as ktime_get() is.
 *
 * This function returns -1 if NOHZ is not enabled.
 */
u64 get_cpu_idle_time_us(int cpu, u64 *last_update_time)
{
	struct tick_sched *ts = &per_cpu(tick_cpu_sched, cpu);

	return get_cpu_sleep_time_us(ts, &ts->idle_sleeptime,
				     !nr_iowait_cpu(cpu), last_update_time);
}
EXPORT_SYMBOL_GPL(get_cpu_idle_time_us);

/**
获取一个cpu的总的iowait time
 * get_cpu_iowait_time_us - get the total iowait time of a CPU
 * @cpu: CPU number to query
 * @last_update_time: variable to store update time in. Do not update
 * counters if NULL.
 *
 * Return the cumulative iowait time (since boot) for a given
 * CPU, in microseconds. Note this is partially broken due to
 * the counter of iowait tasks that can be remotely updated without
 * any synchronization. Therefore it is possible to observe backward
 * values within two consecutive reads.
 *
 * This time is measured via accounting rather than sampling,
 * and is as accurate as ktime_get() is.
 *
 * This function returns -1 if NOHZ is not enabled.
 */
u64 get_cpu_iowait_time_us(int cpu, u64 *last_update_time)
{
	struct tick_sched *ts = &per_cpu(tick_cpu_sched, cpu);

	return get_cpu_sleep_time_us(ts, &ts->iowait_sleeptime,
				     nr_iowait_cpu(cpu), last_update_time);
}
EXPORT_SYMBOL_GPL(get_cpu_iowait_time_us);
/*
恢复Tick
*/
static void tick_nohz_restart(struct tick_sched *ts, ktime_t now)
{
	hrtimer_cancel(&ts->sched_timer);
	hrtimer_set_expires(&ts->sched_timer, ts->last_tick);

	/* Forward the time to expire in the future */
	hrtimer_forward(&ts->sched_timer, now, TICK_NSEC);

	if (ts->nohz_mode == NOHZ_MODE_HIGHRES) {
		hrtimer_start_expires(&ts->sched_timer,
				      HRTIMER_MODE_ABS_PINNED_HARD);
	} else {
		tick_program_event(hrtimer_get_expires(&ts->sched_timer), 1);
	}

	/*
	 * Reset to make sure next tick stop doesn't get fooled by past
	 * cached clock deadline.
	 */
	ts->next_tick = 0;
}
/* local是否有TIMER_SOFTIRQ */
static inline bool local_timer_softirq_pending(void)
{
	return local_softirq_pending() & BIT(TIMER_SOFTIRQ);
}
/* 
虽然关掉了当前CPU的Tick，但是并不能停止当前CPU上的（低分辨率）定时器和高分辨率定时器，
如果这都停了，那所有定时器都将会超时，这个是不能接受的。所以，很自然的想到，马上需要
获得系统中所有定时器的最近到期的时间。不过，需要注意的是，目前系统中其实有两种类型的
定时器，所以必须要分别从（低分辨率）定时器层和高分辨率定时器层获得它们各自的最近要到期
的定时器的时间，然后再比较两者哪个更早。这些是在tick_nohz_next_event函数中实现的：
=======================================
如果tick_nohz_next_event函数返回0，则表示任然需要保留当前CPU上的Tick；
而如果返回值大于0，则表示可以停止Tick了，但必须在这个返回值指定的时间后
触发事件处理。不是所有情况下都需要停止Tick的，如果真的需要保留，那么就将
下一次Tick的到来时间设置成本来Tick到来的时间。如果确实不需要保留Tick了，
则先要获得系统中所有定时器中最近要到期的到期时间，如果这个到期时间还小于
下一个Tick到来的时间，并且当前Tick还没停止的话，那还是选择保留Tick。最后，
如果当前的CPU负责更新系统jiffies的话，那么对睡眠时间还有一个限制，否则想
停多长时间的Tick都可以。在分析时钟源层代码的时候，曾经提到过有一个max_idle_ns
值，表示最大允许的空闲间隔时间，如果停止Tick的时间超过了这个最大时间，那么
在读取时钟源设备周期数并将其转换成纳秒数的时候有可能会产生溢出。
*/
static ktime_t tick_nohz_next_event(struct tick_sched *ts, int cpu)
{
	u64 basemono, next_tick, delta, expires;
	unsigned long basejiff;
	unsigned int seq;

	/* Read jiffies and the time when jiffies were updated last */
	do {
		seq = read_seqcount_begin(&jiffies_seq);
		basemono = last_jiffies_update;
		basejiff = jiffies;
	} while (read_seqcount_retry(&jiffies_seq, seq));
	ts->last_jiffies = basejiff;
	ts->timer_expires_base = basemono;

	/*
	 * Keep the periodic tick, when RCU, architecture or irq_work
	 * requests it.
	 * Aside of that check whether the local timer softirq is
	 * pending. If so its a bad idea to call get_next_timer_interrupt()
	 * because there is an already expired timer, so it will request
	 * immediate expiry, which rearms the hardware timer with a
	 * minimal delta which brings us back to this place
	 * immediately. Lather, rinse and repeat...
	 */
	if (rcu_needs_cpu() || arch_needs_cpu() ||
	    irq_work_needs_cpu() || local_timer_softirq_pending()) {
		next_tick = basemono + TICK_NSEC;
	} else {
		/*
		 * Get the next pending timer. If high resolution
		 * timers are enabled this only takes the timer wheel
		 * timers into account. If high resolution timers are
		 * disabled this also looks at the next expiring
		 * hrtimer.
		 */
		next_tick = get_next_timer_interrupt(basejiff, basemono);
		ts->next_timer = next_tick;
	}

	/*
	 * If the tick is due in the next period, keep it ticking or
	 * force prod the timer.
	 */
	delta = next_tick - basemono;
	if (delta <= (u64)TICK_NSEC) {
		/*
		 * Tell the timer code that the base is not idle, i.e. undo
		 * the effect of get_next_timer_interrupt():
		 */
		timer_clear_idle();
		/*
		 * We've not stopped the tick yet, and there's a timer in the
		 * next period, so no point in stopping it either, bail.
		 */
		if (!ts->tick_stopped) {
			ts->timer_expires = 0;
			goto out;
		}
	}

	/*
	 * If this CPU is the one which had the do_timer() duty last, we limit
	 * the sleep time to the timekeeping max_deferment value.
	 * Otherwise we can sleep as long as we want.
	 */
	delta = timekeeping_max_deferment();
	if (cpu != tick_do_timer_cpu &&
	    (tick_do_timer_cpu != TICK_DO_TIMER_NONE || !ts->do_timer_last))
		delta = KTIME_MAX;

	/* Calculate the next expiry time */
	if (delta < (KTIME_MAX - basemono))
		expires = basemono + delta;
	else
		expires = KTIME_MAX;

	ts->timer_expires = min_t(u64, expires, next_tick);

out:
	return ts->timer_expires;
}
/* 
cpu下线的时候调用来关掉什么东西
*/
static void tick_nohz_stop_tick(struct tick_sched *ts, int cpu)
{
	/* 取出tick设备 */
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);
	u64 basemono = ts->timer_expires_base;
	/*  */
	u64 expires = ts->timer_expires;
	ktime_t tick = expires;

	/* Make sure we won't be trying to stop it twice in a row. */
	ts->timer_expires_base = 0;

	/*
	 * If this CPU is the one which updates jiffies, then give up
	 * the assignment and let it be taken by the CPU which runs
	 * the tick timer next, which might be this CPU as well. If we
	 * don't drop this here the jiffies might be stale and
	 * do_timer() never invoked. Keep track of the fact that it
	 * was the one which had the do_timer() duty last.
	 */
	if (cpu == tick_do_timer_cpu) {
		/* 如果这个cpu的do_timer的cpu */
		tick_do_timer_cpu = TICK_DO_TIMER_NONE;
		ts->do_timer_last = 1;
	} else if (tick_do_timer_cpu != TICK_DO_TIMER_NONE) {
		ts->do_timer_last = 0;
	}

	/* Skip reprogram of event if its not changed */
	if (ts->tick_stopped && (expires == ts->next_tick)) {
		/* Sanity check: make sure clockevent is actually programmed */
		if (tick == KTIME_MAX || ts->next_tick == hrtimer_get_expires(&ts->sched_timer))
			return;

		WARN_ON_ONCE(1);
		printk_once("basemono: %llu ts->next_tick: %llu dev->next_event: %llu timer->active: %d timer->expires: %llu\n",
			    basemono, ts->next_tick, dev->next_event,
			    hrtimer_active(&ts->sched_timer), hrtimer_get_expires(&ts->sched_timer));
	}

	/*
	 * nohz_stop_sched_tick can be called several times before
	 * the nohz_restart_sched_tick is called. This happens when
	 * interrupts arrive which do not cause a reschedule. In the
	 * first call we save the current tick time, so we can restart
	 * the scheduler tick in nohz_restart_sched_tick.
	 */
	if (!ts->tick_stopped) {/* 如果ts还在运行 */
		calc_load_nohz_start();
		quiet_vmstat();

		ts->last_tick = hrtimer_get_expires(&ts->sched_timer);
		ts->tick_stopped = 1;
		/* trace此次关闭 */
		trace_tick_stop(1, TICK_DEP_MASK_NONE);
	}

	ts->next_tick = tick;

	/*
	 * If the expiration time == KTIME_MAX, then we simply stop
	 * the tick timer.
	 如果ts的timer没有到期时间
	 */
	if (unlikely(expires == KTIME_MAX)) {
		if (ts->nohz_mode == NOHZ_MODE_HIGHRES)
			hrtimer_cancel(&ts->sched_timer);/* 取消timer */
		else
			tick_program_event(KTIME_MAX, 1);
		return;
	}
	/* 看来这里是更一般的情况 */

	if (ts->nohz_mode == NOHZ_MODE_HIGHRES) {
		hrtimer_start(&ts->sched_timer, tick,
			      HRTIMER_MODE_ABS_PINNED_HARD);
	} else {
		hrtimer_set_expires(&ts->sched_timer, tick);
		tick_program_event(tick, 1);
	}
}

static void tick_nohz_retain_tick(struct tick_sched *ts)
{
	ts->timer_expires_base = 0;
}

#ifdef CONFIG_NO_HZ_FULL
static void tick_nohz_stop_sched_tick(struct tick_sched *ts, int cpu)
{
	if (tick_nohz_next_event(ts, cpu))
		tick_nohz_stop_tick(ts, cpu);
	else
		tick_nohz_retain_tick(ts);
}
#endif /* CONFIG_NO_HZ_FULL */
/* 
调用了tick_nohz_restart_sched_tick函数恢复Tick
*/
static void tick_nohz_restart_sched_tick(struct tick_sched *ts, ktime_t now)
{
	/* Update jiffies first */
	tick_do_update_jiffies64(now);

	/*
	 * Clear the timer idle flag, so we avoid IPIs on remote queueing and
	 * the clock forward checks in the enqueue path:
	 */
	timer_clear_idle();

	calc_load_nohz_stop();
	touch_softlockup_watchdog_sched();
	/*
	 * Cancel the scheduled timer and restore the tick
	 */
	ts->tick_stopped  = 0;
	/* 在更新了系统jiffies和一些状态字段后，直接调用了tick_nohz_restart函数 */
	tick_nohz_restart(ts, now);
}

static void __tick_nohz_full_update_tick(struct tick_sched *ts,
					 ktime_t now)
{
#ifdef CONFIG_NO_HZ_FULL
	int cpu = smp_processor_id();

	if (can_stop_full_tick(cpu, ts))
		tick_nohz_stop_sched_tick(ts, cpu);
	else if (ts->tick_stopped)
		tick_nohz_restart_sched_tick(ts, now);
#endif
}
/* 以后 */
static void tick_nohz_full_update_tick(struct tick_sched *ts)
{
	if (!tick_nohz_full_cpu(smp_processor_id()))
		return;

	if (!ts->tick_stopped && ts->nohz_mode == NOHZ_MODE_INACTIVE)
		return;

	__tick_nohz_full_update_tick(ts, ktime_get());
}

/*
 * A pending softirq outside an IRQ (or softirq disabled section) context
 * should be waiting for ksoftirqd to handle it. Therefore we shouldn't
 * reach here due to the need_resched() early check in can_stop_idle_tick().
 *
 * However if we are between CPUHP_AP_SMPBOOT_THREADS and CPU_TEARDOWN_CPU on the
 * cpu_down() process, softirqs can still be raised while ksoftirqd is parked,
 * triggering the below since wakep_softirqd() is ignored.
 *
 */
static bool report_idle_softirq(void)
{
	static int ratelimit;
	unsigned int pending = local_softirq_pending();

	if (likely(!pending))
		return false;

	/* Some softirqs claim to be safe against hotplug and ksoftirqd parking */
	if (!cpu_active(smp_processor_id())) {
		pending &= ~SOFTIRQ_HOTPLUG_SAFE_MASK;
		if (!pending)
			return false;
	}

	if (ratelimit >= 10)
		return false;

	/* On RT, softirqs handling may be waiting on some lock */
	if (local_bh_blocked())
		return false;

	pr_warn("NOHZ tick-stop error: local softirq work is pending, handler #%02x!!!\n",
		pending);
	ratelimit++;

	return true;
}

static bool can_stop_idle_tick(int cpu, struct tick_sched *ts)
{
	/*
	 * If this CPU is offline and it is the one which updates
	 * jiffies, then give up the assignment and let it be taken by
	 * the CPU which runs the tick timer next. If we don't drop
	 * this here the jiffies might be stale and do_timer() never
	 * invoked.
	 */
	if (unlikely(!cpu_online(cpu))) {
		if (cpu == tick_do_timer_cpu)
			tick_do_timer_cpu = TICK_DO_TIMER_NONE;
		/*
		 * Make sure the CPU doesn't get fooled by obsolete tick
		 * deadline if it comes back online later.
		 */
		ts->next_tick = 0;
		return false;
	}

	if (unlikely(ts->nohz_mode == NOHZ_MODE_INACTIVE))
		return false;

	if (need_resched())
		return false;

	if (unlikely(report_idle_softirq()))
		return false;

	if (tick_nohz_full_enabled()) {
		/*
		 * Keep the tick alive to guarantee timekeeping progression
		 * if there are full dynticks CPUs around
		 */
		if (tick_do_timer_cpu == cpu)
			return false;

		/* Should not happen for nohz-full */
		if (WARN_ON_ONCE(tick_do_timer_cpu == TICK_DO_TIMER_NONE))
			return false;
	}

	return true;
}

/**
cpu下线了会调用这个函数
调用tick_nohz_idle_stop_tick函数开始停Tick
 * tick_nohz_idle_stop_tick - stop the idle tick from the idle task
 *
 * When the next event is more than a tick into the future, stop the idle tick
 */
void tick_nohz_idle_stop_tick(void)
{
	/* 取出ts */
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	int cpu = smp_processor_id();
	ktime_t expires;

	/*
	 * If tick_nohz_get_sleep_length() ran tick_nohz_next_event(), the
	 * tick timer expiration time is known already.
	 */
	if (ts->timer_expires_base)
		expires = ts->timer_expires;
	// 调用can_stop_idle_tick函数判断现在是否可以真的停掉Tick
	else if (can_stop_idle_tick(cpu, ts))
		expires = tick_nohz_next_event(ts, cpu);
	else
		return;

	ts->idle_calls++;

	if (expires > 0LL) {
		int was_stopped = ts->tick_stopped;

		tick_nohz_stop_tick(ts, cpu);

		ts->idle_sleeps++;
		ts->idle_expires = expires;

		if (!was_stopped && ts->tick_stopped) {
			/* 如果确实是这次操作刚刚关闭的 */
			ts->idle_jiffies = ts->last_jiffies;
			nohz_balance_enter_idle(cpu);
		}
	} else {
		tick_nohz_retain_tick(ts);
	}
}

void tick_nohz_idle_retain_tick(void)
{
	tick_nohz_retain_tick(this_cpu_ptr(&tick_cpu_sched));
	/*
	 * Undo the effect of get_next_timer_interrupt() called from
	 * tick_nohz_next_event().
	 */
	timer_clear_idle();
}

/**
cpu进入idle后设置ts为idle
====================
为什么进入空闲状态
就是cpu执行do_idle函数时，cpu会进入空闲状态
============================
如果当前CPU进入空闲状态，Linux系统先会调用tick_nohz_idle_enter函数，
通知Tick模拟层进入空闲状态，接着会调用tick_nohz_idle_stop_tick函数，
正式停掉当前CPU上的Tick。
 * tick_nohz_idle_enter - prepare for entering idle on the current CPU
 *
 * Called when we start the idle loop.
 */
void tick_nohz_idle_enter(void)
{
	struct tick_sched *ts;

	lockdep_assert_irqs_enabled();

	local_irq_disable();
	/* 
	找到当前CPU的tick_sched结构体，将表示当前处于空闲状态的inidle字段
	置1，然后调用了tick_nohz_start_idle函数
	*/
	ts = this_cpu_ptr(&tick_cpu_sched);

	WARN_ON_ONCE(ts->timer_expires_base);
	/* 设置这个cpu的ts为inidle */
	ts->inidle = 1;
	/* 设置处于idle */
	tick_nohz_start_idle(ts);

	local_irq_enable();
}

/**
中断结束的时候, 更新下次tick event
 * tick_nohz_irq_exit - update next tick event from interrupt exit
 *
 * When an interrupt fires while we are idle and it doesn't cause
 * a reschedule, it may still add, modify or delete a timer, enqueue
 * an RCU callback, etc...
 * So we need to re-calculate and reprogram the next tick event.
 如果在空闲状态下发生了中断，而且它没有导致重新调度，那么它可能仍然会添加、修改或删除一个定时器，
 * 入队一个RCU回调等等...
 所以我们需要重新计算并重新编程下一个tick事件。
 */
void tick_nohz_irq_exit(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	if (ts->inidle)
		tick_nohz_start_idle(ts);
	else
		tick_nohz_full_update_tick(ts);
}

/**
 * tick_nohz_idle_got_tick - Check whether or not the tick handler has run
 */
bool tick_nohz_idle_got_tick(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	if (ts->got_idle_tick) {
		ts->got_idle_tick = 0;
		return true;
	}
	return false;
}

/**
 * tick_nohz_get_next_hrtimer - return the next expiration time for the hrtimer
 * or the tick, whatever that expires first. Note that, if the tick has been
 * stopped, it returns the next hrtimer.
 *
 * Called from power state control code with interrupts disabled
 */
ktime_t tick_nohz_get_next_hrtimer(void)
{
	return __this_cpu_read(tick_cpu_device.evtdev)->next_event;
}

/**
 * tick_nohz_get_sleep_length - return the expected length of the current sleep
 * @delta_next: duration until the next event if the tick cannot be stopped
 *
 * Called from power state control code with interrupts disabled.
 *
 * The return value of this function and/or the value returned by it through the
 * @delta_next pointer can be negative which must be taken into account by its
 * callers.
 */
ktime_t tick_nohz_get_sleep_length(ktime_t *delta_next)
{
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	int cpu = smp_processor_id();
	/*
	 * The idle entry time is expected to be a sufficient approximation of
	 * the current time at this point.
	 */
	ktime_t now = ts->idle_entrytime;
	ktime_t next_event;

	WARN_ON_ONCE(!ts->inidle);

	*delta_next = ktime_sub(dev->next_event, now);

	if (!can_stop_idle_tick(cpu, ts))
		return *delta_next;

	next_event = tick_nohz_next_event(ts, cpu);
	if (!next_event)
		return *delta_next;

	/*
	 * If the next highres timer to expire is earlier than next_event, the
	 * idle governor needs to know that.
	 */
	next_event = min_t(u64, next_event,
			   hrtimer_next_event_without(&ts->sched_timer));

	return ktime_sub(next_event, now);
}

/**
 * tick_nohz_get_idle_calls_cpu - return the current idle calls counter value
 * for a particular CPU.
 *
 * Called from the schedutil frequency scaling governor in scheduler context.
 */
unsigned long tick_nohz_get_idle_calls_cpu(int cpu)
{
	struct tick_sched *ts = tick_get_tick_sched(cpu);

	return ts->idle_calls;
}

/**
 * tick_nohz_get_idle_calls - return the current idle calls counter value
 *
 * Called from the schedutil frequency scaling governor in scheduler context.
 */
unsigned long tick_nohz_get_idle_calls(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	return ts->idle_calls;
}

static void tick_nohz_account_idle_time(struct tick_sched *ts,
					ktime_t now)
{
	unsigned long ticks;

	ts->idle_exittime = now;

	if (vtime_accounting_enabled_this_cpu())
		return;
	/*
	 * We stopped the tick in idle. Update process times would miss the
	 * time we slept as update_process_times does only a 1 tick
	 * accounting. Enforce that this is accounted to idle !
	 */
	ticks = jiffies - ts->idle_jiffies;
	/*
	 * We might be one off. Do not randomly account a huge number of ticks!
	 */
	if (ticks && ticks < LONG_MAX)
		account_idle_ticks(ticks);
}
/* 
如果当前的Tick确实是被停止了，则调用__tick_nohz_idle_restart_tick函数恢复
*/
void tick_nohz_idle_restart_tick(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	if (ts->tick_stopped) {
		ktime_t now = ktime_get();
		tick_nohz_restart_sched_tick(ts, now);
		tick_nohz_account_idle_time(ts, now);
	}
}

static void tick_nohz_idle_update_tick(struct tick_sched *ts, ktime_t now)
{
	if (tick_nohz_full_cpu(smp_processor_id()))
		__tick_nohz_full_update_tick(ts, now);
	else
		tick_nohz_restart_sched_tick(ts, now);

	tick_nohz_account_idle_time(ts, now);
}

/**
如果想恢复Tick，Linux系统是通过调用tick_nohz_idle_exit函数实现的
 * tick_nohz_idle_exit - restart the idle tick from the idle task
 *
 * Restart the idle tick when the CPU is woken up from idle
 * This also exit the RCU extended quiescent state. The CPU
 * can use RCU again after this function is called.
 */
void tick_nohz_idle_exit(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	bool idle_active, tick_stopped;
	ktime_t now;

	local_irq_disable();

	WARN_ON_ONCE(!ts->inidle);
	WARN_ON_ONCE(ts->timer_expires_base);

	ts->inidle = 0;
	idle_active = ts->idle_active;
	tick_stopped = ts->tick_stopped;

	if (idle_active || tick_stopped)
		now = ktime_get();

	if (idle_active)
		tick_nohz_stop_idle(ts, now);

	if (tick_stopped)
		tick_nohz_idle_update_tick(ts, now);

	local_irq_enable();
}

/*
在切换到低精度动态时钟模式下，定时事件设备的到期处理函数被设置成了tick_nohz_handler
 * The nohz low res interrupt handler
 */
static void tick_nohz_handler(struct clock_event_device *dev)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	struct pt_regs *regs = get_irq_regs();
	ktime_t now = ktime_get();

	dev->next_event = KTIME_MAX;

	tick_sched_do_timer(ts, now);
	tick_sched_handle(ts, regs);

	if (unlikely(ts->tick_stopped)) {
		/*
		 * The clockevent device is not reprogrammed, so change the
		 * clock event device to ONESHOT_STOPPED to avoid spurious
		 * interrupts on devices which might not be truly one shot.
		 */
		tick_program_event(KTIME_MAX, 1);
		return;
	}

	hrtimer_forward(&ts->sched_timer, now, TICK_NSEC);
	tick_program_event(hrtimer_get_expires(&ts->sched_timer), 1);
}
/* 
调用tick_nohz_activate函数，试着将Tick模拟层切换到NOHZ_MODE_HIGHRES模式
*/
static inline void tick_nohz_activate(struct tick_sched *ts, int mode)
{
	if (!tick_nohz_enabled) // 如果没有启用NO_HZ模式则直接退出
		return;
	ts->nohz_mode = mode;
	/* One update is enough */
	if (!test_and_set_bit(0, &tick_nohz_active))
		timers_update_nohz(); // 通知（低分辨率）定时器层切换到NO_HZ模式
}

/**
调用tick_nohz_switch_to_nohz函数，将Tick模拟层设置成低精度动态时钟模式
 * tick_nohz_switch_to_nohz - switch to nohz mode
 */
static void tick_nohz_switch_to_nohz(void)
{
	// 获得当前CPU对应的tick_sched结构体
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	ktime_t next;
	// 如果不支持NO_HZ模式则直接退出
	if (!tick_nohz_enabled)
		return;
	// 切换到单次触发模式
	if (tick_switch_to_oneshot(tick_nohz_handler))
		return;

	/*
	 * Recycle the hrtimer in ts, so we can share the
	 * hrtimer_forward with the highres code.
	 */
	hrtimer_init(&ts->sched_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_HARD);
	/* Get the next period */
	next = tick_init_jiffy_update();

	hrtimer_set_expires(&ts->sched_timer, next);
	hrtimer_forward_now(&ts->sched_timer, TICK_NSEC);
	tick_program_event(hrtimer_get_expires(&ts->sched_timer), 1);
	tick_nohz_activate(ts, NOHZ_MODE_LOWRES);
}

static inline void tick_nohz_irq_enter(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	ktime_t now;

	if (!ts->idle_active && !ts->tick_stopped)
		return;
	now = ktime_get();
	if (ts->idle_active)
		tick_nohz_stop_idle(ts, now);
	/*
	 * If all CPUs are idle. We may need to update a stale jiffies value.
	 * Note nohz_full is a special case: a timekeeper is guaranteed to stay
	 * alive but it might be busy looping with interrupts disabled in some
	 * rare case (typically stop machine). So we must make sure we have a
	 * last resort.
	 */
	if (ts->tick_stopped)
		tick_nohz_update_jiffies(now);
}

#else

static inline void tick_nohz_switch_to_nohz(void) { }
static inline void tick_nohz_irq_enter(void) { }
static inline void tick_nohz_activate(struct tick_sched *ts, int mode) { }

#endif /* CONFIG_NO_HZ_COMMON */

/*
 * Called from irq_enter to notify about the possible interruption of idle()
 */
void tick_irq_enter(void)
{
	tick_check_oneshot_broadcast_this_cpu();
	tick_nohz_irq_enter();
}

/*
 * High resolution timer specific code
 */
#ifdef CONFIG_HIGH_RES_TIMERS
/*
早期linux使用低精度定时器timer，代码位于kernel/time/timer.c中，
虽然精度比较低，但是很多内核定时触发代码都是在这个基础上搭建的，
例如调度、时间更新、各种低精度定时任务。在高精度时钟模式下，
内核仍然需要周期性的tick中断，以便刷新内核的一些任务，所以仍然保留
了低精度timer的角色和运作模式，通过hrtimer模拟出原本的timer，
称之为sched_timer，将其超时时间设置为一个tick时长，在超时回来后，
完成对应的工作，然后再次设置下一个tick的超时时间，以此达到周期性tick中断的需求。

sched_timer触发频率为CONFIG_HZ，在CONFIG_HZ=250的系统中，每4ms触发一次，
也就是一个jiffies时间间隔。虽然触发时间粒度比较大，但是精度仍然是纳秒级，
属于高精度定时器。
设置sched_timer定时器处理函数
 * We rearm the timer until we get disabled by the idle code.
 * Called with interrupts disabled.
 sched_timer定时器中断处理程序内容如下，sched_timer此时就是系统节拍定时器，
 不仅给调度程序提供心跳，更新jiffies，还充当了一个管理者，以jiffies时间精度给内核其他程序提供定时服务。
 原有的timer的功能接口，如timer_setup()、add_timer()以及其经典的time wheel方式被保留，
 继续给内核中其他程序提供定时服务。
 */
static enum hrtimer_restart tick_sched_timer(struct hrtimer *timer)
{
	// 获得tick_sched
	struct tick_sched *ts =
		container_of(timer, struct tick_sched, sched_timer);
	struct pt_regs *regs = get_irq_regs();
	ktime_t now = ktime_get();
/* 
tick_sched_do_timer主要的职责是根据当前时间来更新系统jiffies
|-->tick_sched_do_timer(ts, now);
    |-->tick_do_update_jiffies64(now);
      |-->  jiffies_64 += ticks;     //更新jiffies变量
    |-->  calc_global_load();    //每10 jiffies计算1次全局负载
    |-->  update_wall_time();   //更新墙上时间(系统时间)
*/
	tick_sched_do_timer(ts, now);

	/*
	 * Do not call, when we are not in irq context and have
	 * no valid regs pointer
	 */
	if (regs)
		tick_sched_handle(ts, regs);
	else
		ts->next_tick = 0;

	/* No need to reprogram if we are in idle or full dynticks mode */
	if (unlikely(ts->tick_stopped))
		return HRTIMER_NORESTART;

	hrtimer_forward(timer, now, TICK_NSEC);

	return HRTIMER_RESTART;
}

static int sched_skew_tick;

static int __init skew_tick(char *str)
{
	get_option(&str, &sched_skew_tick);

	return 0;
}
early_param("skew_tick", skew_tick);

/**
开启高精度计时后会调用这个函数
设置sched_timer
==============
由于已经没有Tick了，而这时候高分辨率定时器层是处在高精度模式的，
那么想制造一个Tick其实很简单，只需要向高分辨率定时器层添加一个
定时间隔是一个Tick的高分辨率定时器模拟一下以前的系统Tick就好了。
函数首先初始化了在本CPU结构体变量tick_sched中的sched_timer
高分辨率定时器。可以看到，它是用的单调时间，到期时间是绝对值，
并且是一个“硬”定时器，
定时器的到期函数被设置成了tick_sched_timer。

 * tick_setup_sched_timer - setup the tick emulation timer
 */
void tick_setup_sched_timer(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);
	ktime_t now = ktime_get();

	/*
	 * Emulate tick processing via per-CPU hrtimers:
	 */
	hrtimer_init(&ts->sched_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_HARD);
	ts->sched_timer.function = tick_sched_timer; //设置sched_timer定时器处理函数

	/* Get the next period (per-CPU) */
	hrtimer_set_expires(&ts->sched_timer, tick_init_jiffy_update());

	/* Offset the tick to avert jiffies_lock contention. */
	if (sched_skew_tick) {
		u64 offset = TICK_NSEC >> 1;
		do_div(offset, num_possible_cpus());
		offset *= smp_processor_id();
		hrtimer_add_expires_ns(&ts->sched_timer, offset);
	}

	hrtimer_forward(&ts->sched_timer, now, TICK_NSEC);
	hrtimer_start_expires(&ts->sched_timer, HRTIMER_MODE_ABS_PINNED_HARD);
	// 最后调用tick_nohz_activate函数，试着将Tick模拟层切换到NOHZ_MODE_HIGHRES模式
	tick_nohz_activate(ts, NOHZ_MODE_HIGHRES);
}
#endif /* HIGH_RES_TIMERS */

#if defined CONFIG_NO_HZ_COMMON || defined CONFIG_HIGH_RES_TIMERS
void tick_cancel_sched_timer(int cpu)
{
	struct tick_sched *ts = &per_cpu(tick_cpu_sched, cpu);

# ifdef CONFIG_HIGH_RES_TIMERS
	if (ts->sched_timer.base)
		hrtimer_cancel(&ts->sched_timer);
# endif

	memset(ts, 0, sizeof(*ts));
}
#endif

/*
 * Async notification about clocksource changes
 */
void tick_clock_notify(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		set_bit(0, &per_cpu(tick_cpu_sched, cpu).check_clocks);
}

/*
好像是变更one-shot的ce设备之后调用这个函数来提醒触发?
 * Async notification about clock event changes
 关于时钟事件的变化的异步通知
 */
void tick_oneshot_notify(void)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	set_bit(0, &ts->check_clocks);
}

/*
在低精度模式下的周期处理函数hrtimer_run_queues中，每次都会调用tick_check_oneshot_change
函数，判断目前是否可以切换到高精度模式。而在这个函数中，还会调用tick_is_oneshot_available
函数判断Tick层是否已经准备好切换了
 * Check, if a change happened, which makes oneshot possible.
 *
 * Called cyclic from the hrtimer softirq (driven by the timer
 * softirq) allow_nohz signals, that we can switch into low-res nohz
 * mode, because high resolution timers are disabled (either compile
 * or runtime). Called with interrupts disabled.
 */
int tick_check_oneshot_change(int allow_nohz)
{
	struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

	if (!test_and_clear_bit(0, &ts->check_clocks))
		return 0;

	if (ts->nohz_mode != NOHZ_MODE_INACTIVE)
		return 0;

	if (!timekeeping_valid_for_hres() || !tick_is_oneshot_available())
		return 0;

	if (!allow_nohz)
		return 1;

	tick_nohz_switch_to_nohz();
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Implement CPU time clocks for the POSIX clock interface.
 */

#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/posix-timers.h>
#include <linux/errno.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/kernel_stat.h>
#include <trace/events/timer.h>
#include <linux/tick.h>
#include <linux/workqueue.h>
#include <linux/compat.h>
#include <linux/sched/deadline.h>
#include <linux/task_work.h>

#include "posix-timers.h"

static void posix_cpu_timer_rearm(struct k_itimer *timer);

void posix_cputimers_group_init(struct posix_cputimers *pct, u64 cpu_limit)
{
	posix_cputimers_init(pct);
	if (cpu_limit != RLIM_INFINITY) {
		pct->bases[CPUCLOCK_PROF].nextevt = cpu_limit * NSEC_PER_SEC;
		pct->timers_active = true;
	}
}

/*
 * Called after updating RLIMIT_CPU to run cpu timer and update
 * tsk->signal->posix_cputimers.bases[clock].nextevt expiration cache if
 * necessary. Needs siglock protection since other code may update the
 * expiration cache as well.
 *
 * Returns 0 on success, -ESRCH on failure.  Can fail if the task is exiting and
 * we cannot lock_task_sighand.  Cannot fail if task is current.
 */
int update_rlimit_cpu(struct task_struct *task, unsigned long rlim_new)
{
	u64 nsecs = rlim_new * NSEC_PER_SEC;
	unsigned long irq_fl;

	if (!lock_task_sighand(task, &irq_fl))
		return -ESRCH;
	set_process_cpu_timer(task, CPUCLOCK_PROF, &nsecs, NULL);
	unlock_task_sighand(task, &irq_fl);
	return 0;
}

/*
获取clock的pid
 * Functions for validating access to tasks.
 */
static struct pid *pid_for_clock(const clockid_t clock, bool gettime)
{
	const bool thread = !!CPUCLOCK_PERTHREAD(clock);
	const pid_t upid = CPUCLOCK_PID(clock);
	struct pid *pid;

	if (CPUCLOCK_WHICH(clock) >= CPUCLOCK_MAX)
		return NULL;

	/*
	 * If the encoded PID is 0, then the timer is targeted at current
	 * or the process to which current belongs.
	 如果upid是0,表示这个timer是针对当前进程的
	 */
	if (upid == 0)
		return thread ? task_pid(current) : task_tgid(current);

	pid = find_vpid(upid);
	if (!pid)
		return NULL;

	if (thread) {
		struct task_struct *tsk = pid_task(pid, PIDTYPE_PID);
		return (tsk && same_thread_group(tsk, current)) ? pid : NULL;
	}

	/*
	 * For clock_gettime(PROCESS) allow finding the process by
	 * with the pid of the current task.  The code needs the tgid
	 * of the process so that pid_task(pid, PIDTYPE_TGID) can be
	 * used to find the process.
	 */
	if (gettime && (pid == task_pid(current)))
		return task_tgid(current);

	/*
	 * For processes require that pid identifies a process.
	 */
	return pid_has_task(pid, PIDTYPE_TGID) ? pid : NULL;
}

static inline int validate_clock_permissions(const clockid_t clock)
{
	int ret;

	rcu_read_lock();
	ret = pid_for_clock(clock, false) ? 0 : -EINVAL;
	rcu_read_unlock();

	return ret;
}

/*
获取这个clock的类型, 是PERTHREAD还是PROCESS?
*/
static inline enum pid_type clock_pid_type(const clockid_t clock)
{
	return CPUCLOCK_PERTHREAD(clock) ? PIDTYPE_PID : PIDTYPE_TGID;
}

/*
获取ktimer绑定的pid对应的task
*/
static inline struct task_struct *cpu_timer_task_rcu(struct k_itimer *timer)
{
	return pid_task(timer->it.cpu.pid, clock_pid_type(timer->it_clock));
}

/*
 * Update expiry time from increment, and increase overrun count,
 * given the current clock sample.
 * 从增量更新到期时间，并增加超时计数，给定当前时钟样本。
 */
static u64 bump_cpu_timer(struct k_itimer *timer, u64 now)
{
	u64 delta, incr, expires = timer->it.cpu.node.expires;
	int i;

	if (!timer->it_interval)
		return expires;

	if (now < expires)
		return expires;

	incr = timer->it_interval;
	delta = now + incr - expires;

	/* Don't use (incr*2 < delta), incr*2 might overflow. */
	for (i = 0; incr < delta - incr; i++)
		incr = incr << 1;

	for (; i >= 0; incr >>= 1, i--) {
		if (delta < incr)
			continue;

		timer->it.cpu.node.expires += incr;
		timer->it_overrun += 1LL << i;
		delta -= incr;
	}
	return timer->it.cpu.node.expires;
}

/* Check whether all cache entries contain U64_MAX, i.e. eternal expiry time
检查所有的缓存项是否都包含U64_MAX
意思就是这三种时间的计时器都有过期的
*/
static inline bool expiry_cache_is_inactive(const struct posix_cputimers *pct)
{
	return !(~pct->bases[CPUCLOCK_PROF].nextevt |
		 ~pct->bases[CPUCLOCK_VIRT].nextevt |
		 ~pct->bases[CPUCLOCK_SCHED].nextevt);
}

/*
posix cpu clock是什么?
*/
static int
posix_cpu_clock_getres(const clockid_t which_clock, struct timespec64 *tp)
{
	int error = validate_clock_permissions(which_clock);

	if (!error) {
		tp->tv_sec = 0;
		tp->tv_nsec = ((NSEC_PER_SEC + HZ - 1) / HZ);
		if (CPUCLOCK_WHICH(which_clock) == CPUCLOCK_SCHED) {
			/*
			 * If sched_clock is using a cycle counter, we
			 * don't have any idea of its true resolution
			 * exported, but it is much more than 1s/HZ.
			 */
			tp->tv_nsec = 1;
		}
	}
	return error;
}

/*
空函数
*/
static int
posix_cpu_clock_set(const clockid_t clock, const struct timespec64 *tp)
{
	int error = validate_clock_permissions(clock);

	/*
	 * You can never reset a CPU clock, but we check for other errors
	 * in the call before failing with EPERM.
	 */
	return error ? : -EPERM;
}

/*
获取进程的clkid时钟类型的时间
 * Sample a per-thread clock for the given task. clkid is validated.
 作用: 为给定的task采样一个per-thread clock?
 */
static u64 cpu_clock_sample(const clockid_t clkid, struct task_struct *p)
{
	u64 utime, stime;

	if (clkid == CPUCLOCK_SCHED) // 如果是sched时间
		return task_sched_runtime(p);

	task_cputime(p, &utime, &stime);

	switch (clkid) {
	case CPUCLOCK_PROF:
		return utime + stime;
	case CPUCLOCK_VIRT:
		return utime;
	default:
		WARN_ON_ONCE(1);
	}
	return 0;
}
/*
统计一些不同定义方式下的时间
*/
static inline void store_samples(u64 *samples, u64 stime, u64 utime, u64 rtime)
{
	samples[CPUCLOCK_PROF] = stime + utime;
	samples[CPUCLOCK_VIRT] = utime;
	samples[CPUCLOCK_SCHED] = rtime;
}

/*
samples是一个空数组
计算进程的一些时间存储到samples中
比如什么sched时间, virt时间, prof时间
*/
static void task_sample_cputime(struct task_struct *p, u64 *samples)
{
	u64 stime, utime;

	task_cputime(p, &utime, &stime);
	store_samples(samples, stime, utime, p->se.sum_exec_runtime);
}

/*
at是进程的sig->cputimer.cputime_atomic
samples是一个空数组
读取at中的时间存储到samples中
*/
static void proc_sample_cputime_atomic(struct task_cputime_atomic *at,
				       u64 *samples)
{
	u64 stime, utime, rtime;

	utime = atomic64_read(&at->utime);
	stime = atomic64_read(&at->stime);
	rtime = atomic64_read(&at->sum_exec_runtime);
	store_samples(samples, stime, utime, rtime);
}

/*
 * Set cputime to sum_cputime if sum_cputime > cputime. Use cmpxchg
 * to avoid race conditions with concurrent updates to cputime.
 */
static inline void __update_gt_cputime(atomic64_t *cputime, u64 sum_cputime)
{
	u64 curr_cputime = atomic64_read(cputime);

	do {
		if (sum_cputime <= curr_cputime)
			return;
	} while (!atomic64_try_cmpxchg(cputime, &curr_cputime, sum_cputime));
}

/*
把sum中的时间更新到cputime_atomic中
*/
static void update_gt_cputime(struct task_cputime_atomic *cputime_atomic,
			      struct task_cputime *sum)
{
	__update_gt_cputime(&cputime_atomic->utime, sum->utime);
	__update_gt_cputime(&cputime_atomic->stime, sum->stime);
	__update_gt_cputime(&cputime_atomic->sum_exec_runtime, sum->sum_exec_runtime);
}

/**
 * thread_group_sample_cputime - Sample cputime for a given task
 * @tsk:	Task for which cputime needs to be started
 * @samples:	Storage for time samples
 *
 * Called from sys_getitimer() to calculate the expiry time of an active
 * timer. That means group cputime accounting is already active. Called
 * with task sighand lock held.
 *
 * Updates @times with an uptodate sample of the thread group cputimes.
 */
void thread_group_sample_cputime(struct task_struct *tsk, u64 *samples)
{
	struct thread_group_cputimer *cputimer = &tsk->signal->cputimer;
	struct posix_cputimers *pct = &tsk->signal->posix_cputimers;

	WARN_ON_ONCE(!pct->timers_active);

	proc_sample_cputime_atomic(&cputimer->cputime_atomic, samples);
}

/**
作用也是采样tsk的时间到samples中
不过应用于还没有开启计时的情况, 这个函数会先开启cputimer
 * thread_group_start_cputime - Start cputime and return a sample
   开启cpu时间并返回一个sample
 * @tsk:	Task for which cputime needs to be started
 * @samples:	Storage for time samples
 *
 * The thread group cputime accounting is avoided when there are no posix
 * CPU timers armed. Before starting a timer it's required to check whether
 * the time accounting is active. If not, a full update of the atomic
 * accounting store needs to be done and the accounting enabled.
 * 一开始没有posix CPU timers被使用,就避免了线程组cputime accounting
 * 在启动timer之前,需要检查time accounting是否激活
 * 如果没有,则需要对原子计数存储进行完全更新,并启用accounting
 * Updates @times with an uptodate sample of the thread group cputimes.
 */
static void thread_group_start_cputime(struct task_struct *tsk, u64 *samples)
{
	struct thread_group_cputimer *cputimer = &tsk->signal->cputimer;
	struct posix_cputimers *pct = &tsk->signal->posix_cputimers;

	lockdep_assert_task_sighand_held(tsk);

	/* Check if cputimer isn't running. This is accessed without locking. */
	if (!READ_ONCE(pct->timers_active)) {// 如果timers_active是false
		struct task_cputime sum;

		/*
		 * The POSIX timer interface allows for absolute time expiry
		 * values through the TIMER_ABSTIME flag, therefore we have
		 * to synchronize the timer to the clock every time we start it.
		 因为POSIX timer接口允许通过TIMER_ABSTIME标志设置绝对时间到期值
		 所以我们每次启动timer时都必须将timer与时钟同步
		 */
		thread_group_cputime(tsk, &sum);
		// 把sum中的时间更新到cputime_atomic中
		update_gt_cputime(&cputimer->cputime_atomic, &sum);

		/*
		 * We're setting timers_active without a lock. Ensure this
		 * only gets written to in one operation. We set it after
		 * update_gt_cputime() as a small optimization, but
		 * barriers are not required because update_gt_cputime()
		 * can handle concurrent updates.
		 */
		WRITE_ONCE(pct->timers_active, true);
	}
	proc_sample_cputime_atomic(&cputimer->cputime_atomic, samples);
}
/*
收集一个task的cputime存储到samples中
*/
static void __thread_group_cputime(struct task_struct *tsk, u64 *samples)
{
	struct task_cputime ct;

	thread_group_cputime(tsk, &ct);
	store_samples(samples, ct.stime, ct.utime, ct.sum_exec_runtime);
}

/*
获取进程的clkid时钟类型的时间
先采样,后取值
 * Sample a process (thread group) clock for the given task clkid. If the
 * group's cputime accounting is already enabled, read the atomic
 * store. Otherwise a full update is required.  clkid is already validated.
   为指定的task采样一个进程的clock
   如果group的cputime accounting已经启用,则读取原子存储
   否则需要完全更新
 */
static u64 cpu_clock_sample_group(const clockid_t clkid, struct task_struct *p,
				  bool start)
{
	struct thread_group_cputimer *cputimer = &p->signal->cputimer;
	struct posix_cputimers *pct = &p->signal->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];

	/*
	下面三个路径,看参数都是采样, 不过算法和来源不一样
	*/
	if (!READ_ONCE(pct->timers_active)) {
		if (start) // 需要先开启active开关,手动计算时间,再proc_sample_cputime_atomic
			thread_group_start_cputime(p, samples);
		else // 直接手动计算时间, 不开启active开关?
			__thread_group_cputime(p, samples);
	} else {
		// 可以直接proc_sample_cputime_atomic
		proc_sample_cputime_atomic(&cputimer->cputime_atomic, samples);
	}

	return samples[clkid];
}
/*
posix cpu clock这个kclock的get函数
=================================
似乎是每个clock对应一个pid
获取的是pid的sched时间什么的
*/
static int posix_cpu_clock_get(const clockid_t clock, struct timespec64 *tp)
{
	const clockid_t clkid = CPUCLOCK_WHICH(clock);
	struct task_struct *tsk;
	u64 t;

	rcu_read_lock();
	tsk = pid_task(pid_for_clock(clock, true), clock_pid_type(clock));
	if (!tsk) {
		rcu_read_unlock();
		return -EINVAL;
	}

	if (CPUCLOCK_PERTHREAD(clock)) // 如果是PERTHREAD
		t = cpu_clock_sample(clkid, tsk);
	else
		t = cpu_clock_sample_group(clkid, tsk, false);
	rcu_read_unlock();

	*tp = ns_to_timespec64(t);
	return 0;
}

/*
posix cpu kclcock的创建timer函数
do_timer_create()就是获取kc之后调用回调
 * Validate the clockid_t for a new CPU-clock timer, and initialize the timer.
 * This is called from sys_timer_create() and do_cpu_nanosleep() with the
 * new timer already all-zeros initialized.
   校验一个新的CPU-clock timer的clockid_t,并初始化timer
 */
static int posix_cpu_timer_create(struct k_itimer *new_timer)
{
	static struct lock_class_key posix_cpu_timers_key;
	struct pid *pid;

	rcu_read_lock();
	pid = pid_for_clock(new_timer->it_clock, false);
	if (!pid) {
		rcu_read_unlock();
		return -EINVAL;
	}

	/*
	 * If posix timer expiry is handled in task work context then
	 * timer::it_lock can be taken without disabling interrupts as all
	 * other locking happens in task context. This requires a separate
	 * lock class key otherwise regular posix timer expiry would record
	 * the lock class being taken in interrupt context and generate a
	 * false positive warning.
	 */
	if (IS_ENABLED(CONFIG_POSIX_CPU_TIMERS_TASK_WORK))
		lockdep_set_class(&new_timer->it_lock, &posix_cpu_timers_key);

	new_timer->kclock = &clock_posix_cpu;
	// 初始化其cpu timer的红黑树连接件
	timerqueue_init(&new_timer->it.cpu.node);
	new_timer->it.cpu.pid = get_pid(pid);
	rcu_read_unlock();
	return 0;
}
/*
确定这个ktimer应该被插到进程的那个posix_cpu_timer_base的红黑树上
可以是task的pct, 也可以是task的signal的pct
可以是sched时间,也可以是virt时间,也可以是prof时间
这个函数来确定
*/
static struct posix_cputimer_base *timer_base(struct k_itimer *timer,
					      struct task_struct *tsk)
{
	int clkidx = CPUCLOCK_WHICH(timer->it_clock);

	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		return tsk->posix_cputimers.bases + clkidx;
	else
		return tsk->signal->posix_cputimers.bases + clkidx;
}

/*
重置base的nextevt
 * Force recalculating the base earliest expiration on the next tick.
 * This will also re-evaluate the need to keep around the process wide
 * cputime counter and tick dependency and eventually shut these down
 * if necessary.
 */
static void trigger_base_recalc_expires(struct k_itimer *timer,
					struct task_struct *tsk)
{
	struct posix_cputimer_base *base = timer_base(timer, tsk);

	base->nextevt = 0;
}

/*
 * Dequeue the timer and reset the base if it was its earliest expiration.
 * It makes sure the next tick recalculates the base next expiration so we
 * don't keep the costly process wide cputime counter around for a random
 * amount of time, along with the tick dependency.
 * 移除timer并重置base,如果它是最早到期的
  它确保下一个tick重新计算base的下一个到期时间，以便我们不会在随机时间内保留昂贵的
  进程范围cputime计数器，以及tick依赖性
 * If another timer gets queued between this and the next tick, its
 * expiration will update the base next event if necessary on the next
 * tick.
  如果在这个和下一个tick之间排队了另一个timer，如果必要，它的到期时间将在下一个
  tick上更新base的下一个事件
 */
static void disarm_timer(struct k_itimer *timer, struct task_struct *p)
{
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct posix_cputimer_base *base;

	if (!cpu_timer_dequeue(ctmr))
		return;
	// 说明本来不在红黑树上面
	base = timer_base(timer, p);
	if (cpu_timer_getexpires(ctmr) == base->nextevt)
		trigger_base_recalc_expires(timer, p);
}


/*
从posix_cpu_timer_base的红黑树上删除一个ktimer
 * Clean up a CPU-clock timer that is about to be destroyed.
 * This is called from timer deletion with the timer already locked.
 * If we return TIMER_RETRY, it's necessary to release the timer's lock
 * and try again.  (This happens when the timer is in the middle of firing.)
 清理即将被销毁的CPU-clock timer
 这是在timer删除时调用的,定时器已经被锁定
 如果返回TIMER_RETRY,则需要释放定时器的锁并重试
 （当定时器正在触发时会发生这种情况）
 */
static int posix_cpu_timer_del(struct k_itimer *timer)
{
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct sighand_struct *sighand;
	struct task_struct *p;
	unsigned long flags;
	int ret = 0;

	rcu_read_lock();
	// 获取这个timer绑定的pid对应的task
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;

	/*
	 * Protect against sighand release/switch in exit/exec and process/
	 * thread timer list entry concurrent read/writes.
	 保护免受退出/执行和进程/线程计时器列表条目并发读/写的影响
	 加锁sighand
	 */
	sighand = lock_task_sighand(p, &flags);
	if (unlikely(sighand == NULL)) {// 加锁失败?
		/*
		 * This raced with the reaping of the task. The exit cleanup
		 * should have removed this timer from the timer queue.
		 */
		WARN_ON_ONCE(ctmr->head || timerqueue_node_queued(&ctmr->node));
	} else { // 加锁成功了,开始操作
		if (timer->it.cpu.firing)
			ret = TIMER_RETRY; // 已经在触发中了, 返回重试
		else // 这里开始删除
			disarm_timer(timer, p);

		unlock_task_sighand(p, &flags);
	}

out:
	rcu_read_unlock();
	if (!ret)
		put_pid(ctmr->pid);

	return ret;
}

static void cleanup_timerqueue(struct timerqueue_head *head)
{
	struct timerqueue_node *node;
	struct cpu_timer *ctmr;

	while ((node = timerqueue_getnext(head))) {
		timerqueue_del(head, node);
		ctmr = container_of(node, struct cpu_timer, node);
		ctmr->head = NULL;
	}
}

/*
 * Clean out CPU timers which are still armed when a thread exits. The
 * timers are only removed from the list. No other updates are done. The
 * corresponding posix timers are still accessible, but cannot be rearmed.
 *
 * This must be called with the siglock held.
 */
static void cleanup_timers(struct posix_cputimers *pct)
{
	cleanup_timerqueue(&pct->bases[CPUCLOCK_PROF].tqhead);
	cleanup_timerqueue(&pct->bases[CPUCLOCK_VIRT].tqhead);
	cleanup_timerqueue(&pct->bases[CPUCLOCK_SCHED].tqhead);
}

/*
 * These are both called with the siglock held, when the current thread
 * is being reaped.  When the final (leader) thread in the group is reaped,
 * posix_cpu_timers_exit_group will be called after posix_cpu_timers_exit.
 */
void posix_cpu_timers_exit(struct task_struct *tsk)
{
	cleanup_timers(&tsk->posix_cputimers);
}
void posix_cpu_timers_exit_group(struct task_struct *tsk)
{
	cleanup_timers(&tsk->signal->posix_cputimers);
}

/*
把ktimer插入到进程的posix_cpu_timer_base的红黑树上
 * Insert the timer on the appropriate list before any timers that
 * expire later.  This must be called with the sighand lock held.
   把这个timer插入到适当的列表中,在任何稍后到期的timer之前
   这必须在sighand锁被持有的情况下调用
 */
static void arm_timer(struct k_itimer *timer, struct task_struct *p)
{	
	// 找到应该插入的posix_cpu_timer_base
	struct posix_cputimer_base *base = timer_base(timer, p);
	// 获取准备插入pct base红黑树的cpu_timer(也算是个连接件)
	struct cpu_timer *ctmr = &timer->it.cpu;
	u64 newexp = cpu_timer_getexpires(ctmr);

	// 插入到红黑树上
	if (!cpu_timer_enqueue(&base->tqhead, ctmr))
		return;

	/*
	 * We are the new earliest-expiring POSIX 1.b timer, hence
	 * need to update expiration cache. Take into account that
	 * for process timers we share expiration cache with itimers
	 * and RLIMIT_CPU and for thread timers with RLIMIT_RTTIME.
	 */
	if (newexp < base->nextevt)
		base->nextevt = newexp;

	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		tick_dep_set_task(p, TICK_DEP_BIT_POSIX_TIMER);
	else
		tick_dep_set_signal(p, TICK_DEP_BIT_POSIX_TIMER);
}

/*
这个k_itimer到时间了, 触发他
k_itimer的cpu_timer是posix_cpu_timer的posix_cputimer_base的tqhead红黑树上的一个cpu_timer
 * The timer is locked, fire it and arrange for its reload.
 */
static void cpu_timer_fire(struct k_itimer *timer)
{
	// 取下这个cpu_timer
	// 这个cpu_timer是挂在posix_cpu_timer的posix_cputimer_base的tqhead红黑树上的一个cpu_timer
	struct cpu_timer *ctmr = &timer->it.cpu;

	if ((timer->it_sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_NONE) {
		/*
		 * User don't want any signal.
		 */
		cpu_timer_setexpires(ctmr, 0);
	} else if (unlikely(timer->sigq == NULL)) {
		/*
		 * This a special case for clock_nanosleep,
		 * not a normal timer from sys_timer_create.
		 */
		wake_up_process(timer->it_process);
		cpu_timer_setexpires(ctmr, 0);
	} else if (!timer->it_interval) {
		/*
		只触发一次的timer?
		 * One-shot timer.  Clear it as soon as it's fired.
		 */
		// 发送timer的sigq信号
		posix_timer_event(timer, 0);
		cpu_timer_setexpires(ctmr, 0);
	} else if (posix_timer_event(timer, ++timer->it_requeue_pending)) {
		/*
		 * The signal did not get queued because the signal
		 * was ignored, so we won't get any callback to
		 * reload the timer.  But we need to keep it
		 * ticking in case the signal is deliverable next time.
		 */
		posix_cpu_timer_rearm(timer);
		++timer->it_requeue_pending;
	}
}

/*
posix cpu这个kclock的timer_set回调函数
总体来说算是把timer插入到进程的posix_cpu_timer_base的红黑树上
 * Guts of sys_timer_settime for CPU timers.
 * This is called with the timer locked and interrupts disabled.
 * If we return TIMER_RETRY, it's necessary to release the timer's lock
 * and try again.  (This happens when the timer is in the middle of firing.)
 */
static int posix_cpu_timer_set(struct k_itimer *timer, int timer_flags,
			       struct itimerspec64 *new, struct itimerspec64 *old)
{
	clockid_t clkid = CPUCLOCK_WHICH(timer->it_clock);
	u64 old_expires, new_expires, old_incr, val;
	// 获取k_itimer的cpu_timer
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct sighand_struct *sighand;
	struct task_struct *p;
	unsigned long flags;
	int ret = 0;

	rcu_read_lock();
	// 获取ktimer对应的task
	p = cpu_timer_task_rcu(timer);
	if (!p) {
		/*
		 * If p has just been reaped, we can no
		 * longer get any information about it at all.
		 */
		rcu_read_unlock();
		return -ESRCH;
	}

	/*
	 * Use the to_ktime conversion because that clamps the maximum
	 * value to KTIME_MAX and avoid multiplication overflows.
	 */
	new_expires = ktime_to_ns(timespec64_to_ktime(new->it_value));

	/*
	 * Protect against sighand release/switch in exit/exec and p->cpu_timers
	 * and p->signal->cpu_timers read/write in arm_timer()
	 加锁
	 */
	sighand = lock_task_sighand(p, &flags);
	/*
	 * If p has just been reaped, we can no
	 * longer get any information about it at all.
	 */
	if (unlikely(sighand == NULL)) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/*
	 * Disarm any old timer after extracting its expiry time.
	 */
	old_incr = timer->it_interval;
	// 获取cpu_timer的expires时间
	old_expires = cpu_timer_getexpires(ctmr);

	if (unlikely(timer->it.cpu.firing)) {// 如果这个timer正在firing
		timer->it.cpu.firing = -1;
		ret = TIMER_RETRY;
	} else {
		// 把cpu_timer从红黑树上取下来
		cpu_timer_dequeue(ctmr);
	}

	/*
	 * We need to sample the current value to convert the new
	 * value from to relative and absolute, and to convert the
	 * old value from absolute to relative.  To set a process
	 * timer, we need a sample to balance the thread expiry
	 * times (in arm_timer).  With an absolute time, we must
	 * check if it's already passed.  In short, we need a sample.
	 我们需要采样当前值,以将新值从相对值转换为绝对值,并将旧值从绝对值转换为相对值。
	 要设置进程timer，我们需要一个sample来平衡线程到期时间(在arm_timer中)。
	 对于绝对时间，我们必须检查它是否已经过去。简而言之，我们需要一个sample。
	 */
	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		val = cpu_clock_sample(clkid, p); // 获取进程的clkid时钟类型的时间
	else
		val = cpu_clock_sample_group(clkid, p, true);

	if (old) {
		if (old_expires == 0) {
			old->it_value.tv_sec = 0;
			old->it_value.tv_nsec = 0;
		} else {
			/*
			如果cpu_timer本来有expires时间
			 * Update the timer in case it has overrun already.
			 * If it has, we'll report it as having overrun and
			 * with the next reloaded timer already ticking,
			 * though we are swallowing that pending
			 * notification here to install the new setting.
			 更新计时器以防它已经超时。
			 如果是这样，我们将报告它已经超时，并且下一个重新加载的计时器已经在滴答，
			 尽管我们在这里吞下了挂起的通知以安装新设置。
			 */
			u64 exp = bump_cpu_timer(timer, val);

			if (val < exp) {
				old_expires = exp - val;
				old->it_value = ns_to_timespec64(old_expires);
			} else {
				old->it_value.tv_nsec = 1;
				old->it_value.tv_sec = 0;
			}
		}
	}

	if (unlikely(ret)) {
		/*
		 * We are colliding with the timer actually firing.
		 * Punt after filling in the timer's old value, and
		 * disable this firing since we are already reporting
		 * it as an overrun (thanks to bump_cpu_timer above).
		 */
		unlock_task_sighand(p, &flags);
		goto out;
	}

	if (new_expires != 0 && !(timer_flags & TIMER_ABSTIME)) {
		new_expires += val;
	}

	/*
	 * Install the new expiry time (or zero).
	 * For a timer with no notification action, we don't actually
	 * arm the timer (we'll just fake it for timer_gettime).
	 */
	cpu_timer_setexpires(ctmr, new_expires);
	if (new_expires != 0 && val < new_expires) {
		arm_timer(timer, p); // 把cpu_timer插入到红黑树上
	}

	unlock_task_sighand(p, &flags);
	/*
	 * Install the new reload setting, and
	 * set up the signal and overrun bookkeeping.
	 */
	timer->it_interval = timespec64_to_ktime(new->it_interval);

	/*
	 * This acts as a modification timestamp for the timer,
	 * so any automatic reload attempt will punt on seeing
	 * that we have reset the timer manually.
	 */
	timer->it_requeue_pending = (timer->it_requeue_pending + 2) &
		~REQUEUE_PENDING;
	timer->it_overrun_last = 0;
	timer->it_overrun = -1;

	if (val >= new_expires) {// 已经超时了
		if (new_expires != 0) {
			/*
			 * The designated time already passed, so we notify
			 * immediately, even if the thread never runs to
			 * accumulate more time on this clock.
			 指定的时间已经过去，因此我们立即通知，即使线程从未运行以
			 在此时钟上累积更多时间。
			 */
			cpu_timer_fire(timer);
		}

		/*
		 * Make sure we don't keep around the process wide cputime
		 * counter or the tick dependency if they are not necessary.
		 */
		sighand = lock_task_sighand(p, &flags);
		if (!sighand)
			goto out;

		if (!cpu_timer_queued(ctmr))
			trigger_base_recalc_expires(timer, p);

		unlock_task_sighand(p, &flags);
	}
 out:
	rcu_read_unlock();
	if (old)
		old->it_interval = ns_to_timespec64(old_incr);

	return ret;
}
/*
posix cpu这个kclock的timer_get回调函数
获取的是什么东西?
*/
static void posix_cpu_timer_get(struct k_itimer *timer, struct itimerspec64 *itp)
{
	clockid_t clkid = CPUCLOCK_WHICH(timer->it_clock);
	struct cpu_timer *ctmr = &timer->it.cpu;
	u64 now, expires = cpu_timer_getexpires(ctmr);
	struct task_struct *p;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;

	/*
	 * Easy part: convert the reload time.
	 */
	itp->it_interval = ktime_to_timespec64(timer->it_interval);

	if (!expires)
		goto out;

	/*
	 * Sample the clock to take the difference with the expiry time.
	 */
	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		now = cpu_clock_sample(clkid, p);
	else
		now = cpu_clock_sample_group(clkid, p, false);

	if (now < expires) {
		itp->it_value = ns_to_timespec64(expires - now);
	} else {
		/*
		 * The timer should have expired already, but the firing
		 * hasn't taken place yet.  Say it's just about to expire.
		 */
		itp->it_value.tv_nsec = 1;
		itp->it_value.tv_sec = 0;
	}
out:
	rcu_read_unlock();
}

#define MAX_COLLECTED	20

/*
head是进程的posix_cputimers的一个posix_cputimer_base的tqhead
now是进程的采样的时间,比如sched时间, virt时间, prof时间啥啥的
==================
tqhead是这个posix_cputimer_base的红黑树,上面挂着各种timer
函数从上面取下超时的,挂入fireing列表中
=================
返回u64_max表示找到了超时的, 现在在fireing列表中的timer
如果返回小于u64_max的,表示还没找到超时的,返回的是下一个超时的时间
也就是当前红黑树的最左边timer的超时时间
*/
static u64 collect_timerqueue(struct timerqueue_head *head,
			      struct list_head *firing, u64 now)
{
	struct timerqueue_node *next;
	int i = 0;

	while ((next = timerqueue_getnext(head))) {
		struct cpu_timer *ctmr;
		u64 expires;
		// 取出这个next连接件所属的真正的cpu_timer
		ctmr = container_of(next, struct cpu_timer, node);
		expires = cpu_timer_getexpires(ctmr);
		/* Limit the number of timers to expire at once
		如果还没过期?
		*/
		if (++i == MAX_COLLECTED || now < expires)
			return expires; // 这里直接返回是因为最左边的都没过期, 其他的也不可能
		/* 过期了 */
		ctmr->firing = 1;
		/* See posix_cpu_timer_wait_running() */
		rcu_assign_pointer(ctmr->handling, current);
		cpu_timer_dequeue(ctmr); // 从pct_timer_base的tqhead中删除这个cpu_timer
		list_add_tail(&ctmr->elist, firing); // 加入到firing列表中
	}

	return U64_MAX;
}
/*
pct是进程的posix_cputimers
samples是从这个进程中采样的一些时间,比如sched时间, virt时间, prof时间啥啥的
================================
函数从pct的各种计时下的pct_cputimer_base中取出超时的timer,加入到firing列表中
*/
static void collect_posix_cputimers(struct posix_cputimers *pct, u64 *samples,
				    struct list_head *firing)
{
	struct posix_cputimer_base *base = pct->bases;
	int i;
	// 这个循环是遍历pct的每一个posix_cputimer_base
	// 从里面取出超时的timer,加入到firing列表中
	for (i = 0; i < CPUCLOCK_MAX; i++, base++) { // 遍历pct的每一个posix_cputimer_base
		base->nextevt = collect_timerqueue(&base->tqhead, firing,
						    samples[i]);
	}
}

/*
重置deadline任务的dl_overrun标志，并发送SIGXCPU信号
*/
static inline void check_dl_overrun(struct task_struct *tsk)
{
	if (tsk->dl.dl_overrun) {
		tsk->dl.dl_overrun = 0;
		// 发送cpu时间超时信号
		send_signal_locked(SIGXCPU, SEND_SIG_PRIV, tsk, PIDTYPE_TGID);
	}
}

static bool check_rlimit(u64 time, u64 limit, int signo, bool rt, bool hard)
{
	if (time < limit)
		return false;

	if (print_fatal_signals) {
		pr_info("%s Watchdog Timeout (%s): %s[%d]\n",
			rt ? "RT" : "CPU", hard ? "hard" : "soft",
			current->comm, task_pid_nr(current));
	}
	send_signal_locked(signo, SEND_SIG_PRIV, current, PIDTYPE_TGID);
	return true;
}

/*
检查进程的posix_cputimers的各种计时下的posix_cputimer_base是否有超时的timer
如果有,加入到firing列表中
 * Check for any per-thread CPU timers that have fired and move them off
 * the tsk->cpu_timers[N] list onto the firing list.  Here we update the
 * tsk->it_*_expires values to reflect the remaining thread CPU timers.
 检查任何已触发的线程CPU定时器，并将其从tsk->cpu_timers[N]列表移动到firing列表中。
 在这里，我们更新tsk->it_*_expires值以反映剩余的线程CPU定时器。
 */
static void check_thread_timers(struct task_struct *tsk,
				struct list_head *firing)
{
	struct posix_cputimers *pct = &tsk->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];
	unsigned long soft;

	if (dl_task(tsk)) // 如果是deadline任务
		check_dl_overrun(tsk); // 重置deadline任务的dl_overrun标志，并发送SIGXCPU信号

	if (expiry_cache_is_inactive(pct))
		return;
	// 采样线程的一些时间存储到samples中
	task_sample_cputime(tsk, samples);
	// 从pct的各种计时下的pct_cputimer_base(比如sched时间,virt时间)中取出超时的timer,
	// 加入到firing列表中
	collect_posix_cputimers(pct, samples, firing);

	/*
	 * Check for the special case thread timers.
	 */
	// 获取进程的RTTIME的软限制
	soft = task_rlimit(tsk, RLIMIT_RTTIME);
	if (soft != RLIM_INFINITY) { // 如果不是无限制
		/* Task RT timeout is accounted in jiffies. RTTIME is usec */
		unsigned long rttime = tsk->rt.timeout * (USEC_PER_SEC / HZ);
		unsigned long hard = task_rlimit_max(tsk, RLIMIT_RTTIME);

		/* At the hard limit, send SIGKILL. No further action. */
		if (hard != RLIM_INFINITY &&
		    check_rlimit(rttime, hard, SIGKILL, true, true))
			return;

		/* At the soft limit, send a SIGXCPU every second */
		if (check_rlimit(rttime, soft, SIGXCPU, true, false)) {
			soft += USEC_PER_SEC;
			tsk->signal->rlim[RLIMIT_RTTIME].rlim_cur = soft;
		}
	}

	if (expiry_cache_is_inactive(pct)) // 如果这几个pct_cputimer_base都有超时的timer
		tick_dep_clear_task(tsk, TICK_DEP_BIT_POSIX_TIMER);
}

// 如果sig的posix_cputimers的各种计时下的posix_cputimer_base都有超时的timer
// 就把pct的timers_active设置为false
static inline void stop_process_timers(struct signal_struct *sig)
{
	struct posix_cputimers *pct = &sig->posix_cputimers;

	/* Turn off the active flag. This is done without locking. */
	WRITE_ONCE(pct->timers_active, false);
	tick_dep_clear_signal(sig, TICK_DEP_BIT_POSIX_TIMER);
}

/*
it的tsk的sig的prof和virt的it之一
expires是sig的posix_cputimers的prof和virt的base的nextevt, 表示红黑树上最早的到期时间什么的
cur_time是tsk的采样的时间,比如sched时间, virt时间, prof时间啥啥的
signo是SIGPROF或者SIGVTALRM
检查itimer是否到期,如果到期,发送信号
*/
static void check_cpu_itimer(struct task_struct *tsk, struct cpu_itimer *it,
			     u64 *expires, u64 cur_time, int signo)
{
	if (!it->expires)
		return;

	if (cur_time >= it->expires) {
		if (it->incr)
			it->expires += it->incr;
		else
			it->expires = 0;
		// tp点
		trace_itimer_expire(signo == SIGPROF ?
				    ITIMER_PROF : ITIMER_VIRTUAL,
				    task_tgid(tsk), cur_time);
		// 发送信号
		send_signal_locked(signo, SEND_SIG_PRIV, tsk, PIDTYPE_TGID);
	}

	if (it->expires && it->expires < *expires)
		*expires = it->expires;
}

/*
类似check_thread_timers,但是这个是检查进程的?
 * Check for any per-thread CPU timers that have fired and move them
 * off the tsk->*_timers list onto the firing list.  Per-thread timers
 * have already been taken off.
 检查已触发的任何线程CPU定时器，并将其从tsk->*_timers列表移动到firing列表中。
 线程定时器已经被移除。
 */
static void check_process_timers(struct task_struct *tsk,
				 struct list_head *firing)
{
	// 进程的signal_struct也有posix_cputimers?
	struct signal_struct *const sig = tsk->signal;
	struct posix_cputimers *pct = &sig->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];
	unsigned long soft;

	/*
	 * If there are no active process wide timers (POSIX 1.b, itimers,
	 * RLIMIT_CPU) nothing to check. Also skip the process wide timer
	 * processing when there is already another task handling them.
	 */
	if (!READ_ONCE(pct->timers_active) || pct->expiry_active)
		return;
	// 必须是timers_active,并且expiry_不active
	/*
	 * Signify that a thread is checking for process timers.
	 * Write access to this field is protected by the sighand lock.
	 */
	pct->expiry_active = true;

	/*
	 * Collect the current process totals. Group accounting is active
	 * so the sample can be taken directly.
	 
	 */
	// 统计sig的cputimer的cputime_atomic到samples中
	proc_sample_cputime_atomic(&sig->cputimer.cputime_atomic, samples);
	collect_posix_cputimers(pct, samples, firing);

	/*
	 * Check for the special case process timers.
	 这里进行prof和virt的时间检查,
	 */
	check_cpu_itimer(tsk, &sig->it[CPUCLOCK_PROF],
			 &pct->bases[CPUCLOCK_PROF].nextevt,
			 samples[CPUCLOCK_PROF], SIGPROF);
	check_cpu_itimer(tsk, &sig->it[CPUCLOCK_VIRT],
			 &pct->bases[CPUCLOCK_VIRT].nextevt,
			 samples[CPUCLOCK_VIRT], SIGVTALRM);


	// 检查进程的RLIMIT_CPU的时间
	soft = task_rlimit(tsk, RLIMIT_CPU);
	if (soft != RLIM_INFINITY) { // 如果不是无限制
		/* RLIMIT_CPU is in seconds. Samples are nanoseconds */
		unsigned long hard = task_rlimit_max(tsk, RLIMIT_CPU);
		u64 ptime = samples[CPUCLOCK_PROF];
		u64 softns = (u64)soft * NSEC_PER_SEC;
		u64 hardns = (u64)hard * NSEC_PER_SEC;

		/* At the hard limit, send SIGKILL. No further action. */
		if (hard != RLIM_INFINITY &&
		    check_rlimit(ptime, hardns, SIGKILL, false, true))
			return;

		/* At the soft limit, send a SIGXCPU every second */
		if (check_rlimit(ptime, softns, SIGXCPU, false, false)) {
			sig->rlim[RLIMIT_CPU].rlim_cur = soft + 1;
			softns += NSEC_PER_SEC;
		}

		/* Update the expiry cache */
		if (softns < pct->bases[CPUCLOCK_PROF].nextevt)
			pct->bases[CPUCLOCK_PROF].nextevt = softns;
	}

	if (expiry_cache_is_inactive(pct)) // 如果这几个pct_cputimer_base都有超时的timer
		stop_process_timers(sig);// 把pct的timers_active设置为false

	pct->expiry_active = false;
}

/*
 * This is called from the signal code (via posixtimer_rearm)
 * when the last timer signal was delivered and we have to reload the timer.
   这是从signal code（通过posixtimer_rearm）调用的
   当最后一个计时器信号被传递并且我们必须重新加载计时器时。
 */
static void posix_cpu_timer_rearm(struct k_itimer *timer)
{
	clockid_t clkid = CPUCLOCK_WHICH(timer->it_clock);
	struct task_struct *p;
	struct sighand_struct *sighand;
	unsigned long flags;
	u64 now;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;

	/* Protect timer list r/w in arm_timer()
	加锁
	*/
	sighand = lock_task_sighand(p, &flags);
	if (unlikely(sighand == NULL))
		goto out;

	/*
	 * Fetch the current sample and update the timer's expiry time.
	 */
	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		now = cpu_clock_sample(clkid, p);
	else
		now = cpu_clock_sample_group(clkid, p, true);

	bump_cpu_timer(timer, now);

	/*
	 * Now re-arm for the new expiry time.
	 */
	// 插入红黑树
	arm_timer(timer, p);
	unlock_task_sighand(p, &flags);
out:
	rcu_read_unlock();
}

/**
 * task_cputimers_expired - Check whether posix CPU timers are expired
 *
 * @samples:	Array of current samples for the CPUCLOCK clocks
 * @pct:	Pointer to a posix_cputimers container
 *
 * Returns true if any member of @samples is greater than the corresponding
 * member of @pct->bases[CLK].nextevt. False otherwise
 */
static inline bool
task_cputimers_expired(const u64 *samples, struct posix_cputimers *pct)
{
	int i;

	for (i = 0; i < CPUCLOCK_MAX; i++) {
		if (samples[i] >= pct->bases[i].nextevt)
			return true;
	}
	return false;
}

/**
 * fastpath_timer_check - POSIX CPU timers fast path.
 *
 * @tsk:	The task (thread) being checked.
 *
 * Check the task and thread group timers.  If both are zero (there are no
 * timers set) return false.  Otherwise snapshot the task and thread group
 * timers and compare them with the corresponding expiration times.  Return
 * true if a timer has expired, else return false.
 */
static inline bool fastpath_timer_check(struct task_struct *tsk)
{
	struct posix_cputimers *pct = &tsk->posix_cputimers;
	struct signal_struct *sig;

	if (!expiry_cache_is_inactive(pct)) {
		u64 samples[CPUCLOCK_MAX];

		task_sample_cputime(tsk, samples);
		if (task_cputimers_expired(samples, pct))
			return true;
	}

	sig = tsk->signal;
	pct = &sig->posix_cputimers;
	/*
	 * Check if thread group timers expired when timers are active and
	 * no other thread in the group is already handling expiry for
	 * thread group cputimers. These fields are read without the
	 * sighand lock. However, this is fine because this is meant to be
	 * a fastpath heuristic to determine whether we should try to
	 * acquire the sighand lock to handle timer expiry.
	 *
	 * In the worst case scenario, if concurrently timers_active is set
	 * or expiry_active is cleared, but the current thread doesn't see
	 * the change yet, the timer checks are delayed until the next
	 * thread in the group gets a scheduler interrupt to handle the
	 * timer. This isn't an issue in practice because these types of
	 * delays with signals actually getting sent are expected.
	 */
	if (READ_ONCE(pct->timers_active) && !READ_ONCE(pct->expiry_active)) {
		u64 samples[CPUCLOCK_MAX];

		proc_sample_cputime_atomic(&sig->cputimer.cputime_atomic,
					   samples);

		if (task_cputimers_expired(samples, pct))
			return true;
	}

	if (dl_task(tsk) && tsk->dl.dl_overrun)
		return true;

	return false;
}

static void handle_posix_cpu_timers(struct task_struct *tsk);

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
/*
p->posix_cputimers_work.work的回调函数
*/
static void posix_cpu_timers_work(struct callback_head *work)
{
	// 获取对应的posix_cputimers_work结构体
	// 是一个进程的p->posix_cputimers_work成员
	struct posix_cputimers_work *cw = container_of(work, typeof(*cw), work);

	mutex_lock(&cw->mutex);
	handle_posix_cpu_timers(current);
	mutex_unlock(&cw->mutex);
}

/*
没看懂是什么逻辑
 * Invoked from the posix-timer core when a cancel operation failed because
 * the timer is marked firing. The caller holds rcu_read_lock(), which
 * protects the timer and the task which is expiring it from being freed.
   从posix-timer核心调用，当取消操作失败时，因为计时器标记为firing。
   调用者持有rcu_read_lock()，它保护计时器和正在过期的任务不被释放。
 */
static void posix_cpu_timer_wait_running(struct k_itimer *timr)
{
	// 获取负责这个cpu_timer触发的task
	struct task_struct *tsk = rcu_dereference(timr->it.cpu.handling);

	/* Has the handling task completed expiry already? */
	if (!tsk)
		return;

	/* Ensure that the task cannot go away */
	get_task_struct(tsk);
	/* Now drop the RCU protection so the mutex can be locked */
	rcu_read_unlock();
	/* Wait on the expiry mutex */
	mutex_lock(&tsk->posix_cputimers_work.mutex);
	/* Release it immediately again. */
	mutex_unlock(&tsk->posix_cputimers_work.mutex);
	/* Drop the task reference. */
	put_task_struct(tsk);
	/* Relock RCU so the callsite is balanced */
	rcu_read_lock();
}

static void posix_cpu_timer_wait_running_nsleep(struct k_itimer *timr)
{
	/* Ensure that timr->it.cpu.handling task cannot go away */
	rcu_read_lock();
	spin_unlock_irq(&timr->it_lock);
	posix_cpu_timer_wait_running(timr);
	rcu_read_unlock();
	/* @timr is on stack and is valid */
	spin_lock_irq(&timr->it_lock);
}

/*

 * Clear existing posix CPU timers task work.
 */
void clear_posix_cputimers_work(struct task_struct *p)
{
	/*
	 * A copied work entry from the old task is not meaningful, clear it.
	 * N.B. init_task_work will not do this.
	 */
	memset(&p->posix_cputimers_work.work, 0,
	       sizeof(p->posix_cputimers_work.work));
	init_task_work(&p->posix_cputimers_work.work,
		       posix_cpu_timers_work);
	mutex_init(&p->posix_cputimers_work.mutex);
	p->posix_cputimers_work.scheduled = false;
}

/*
 * Initialize posix CPU timers task work in init task. Out of line to
 * keep the callback static and to avoid header recursion hell.
   初始化init task中的posix CPU计时器任务工作。为了保持回调静态并避免头递归地狱，需要离线。
 */
void __init posix_cputimers_init_work(void)
{
	clear_posix_cputimers_work(current);
}

/*
 * Note: All operations on tsk->posix_cputimer_work.scheduled happen either
 * in hard interrupt context or in task context with interrupts
 * disabled. Aside of that the writer/reader interaction is always in the
 * context of the current task, which means they are strict per CPU.
 注意：对tsk->posix_cputimer_work.scheduled的所有操作都发生在硬中断上下文中，
 * 或者在禁用中断的任务上下文中。除此之外，读/写器交互总是在当前任务的上下文中，
 * 这意味着它们是严格的每个CPU。
 */
static inline bool posix_cpu_timers_work_scheduled(struct task_struct *tsk)
{
	return tsk->posix_cputimers_work.scheduled;
}

static inline void __run_posix_cpu_timers(struct task_struct *tsk)
{
	if (WARN_ON_ONCE(tsk->posix_cputimers_work.scheduled))
		return;

	/* Schedule task work to actually expire the timers */
	tsk->posix_cputimers_work.scheduled = true;
	task_work_add(tsk, &tsk->posix_cputimers_work.work, TWA_RESUME);
}

static inline bool posix_cpu_timers_enable_work(struct task_struct *tsk,
						unsigned long start)
{
	bool ret = true;

	/*
	 * On !RT kernels interrupts are disabled while collecting expired
	 * timers, so no tick can happen and the fast path check can be
	 * reenabled without further checks.
	 在非RT的内核中，当收集过期的计时器时，中断被禁用，因此不会发生tick，
	 并且可以在不进行进一步检查的情况下重新启用快速路径检查。
	 */
	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
		tsk->posix_cputimers_work.scheduled = false;
		return true;
	}

	/*
	 * On RT enabled kernels ticks can happen while the expired timers
	 * are collected under sighand lock. But any tick which observes
	 * the CPUTIMERS_WORK_SCHEDULED bit set, does not run the fastpath
	 * checks. So reenabling the tick work has do be done carefully:
	 *
	 * Disable interrupts and run the fast path check if jiffies have
	 * advanced since the collecting of expired timers started. If
	 * jiffies have not advanced or the fast path check did not find
	 * newly expired timers, reenable the fast path check in the timer
	 * interrupt. If there are newly expired timers, return false and
	 * let the collection loop repeat.
	 */
	local_irq_disable();
	if (start != jiffies && fastpath_timer_check(tsk))
		ret = false;
	else
		tsk->posix_cputimers_work.scheduled = false;
	local_irq_enable();

	return ret;
}
#else /* CONFIG_POSIX_CPU_TIMERS_TASK_WORK */
static inline void __run_posix_cpu_timers(struct task_struct *tsk)
{
	lockdep_posixtimer_enter();
	handle_posix_cpu_timers(tsk);
	lockdep_posixtimer_exit();
}

static void posix_cpu_timer_wait_running(struct k_itimer *timr)
{
	cpu_relax();
}

static void posix_cpu_timer_wait_running_nsleep(struct k_itimer *timr)
{
	spin_unlock_irq(&timr->it_lock);
	cpu_relax();
	spin_lock_irq(&timr->it_lock);
}

static inline bool posix_cpu_timers_work_scheduled(struct task_struct *tsk)
{
	return false;
}

static inline bool posix_cpu_timers_enable_work(struct task_struct *tsk,
						unsigned long start)
{
	return true;
}
#endif /* CONFIG_POSIX_CPU_TIMERS_TASK_WORK */

/*
触发进程的到期的posix_cputimers
*/
static void handle_posix_cpu_timers(struct task_struct *tsk)
{
	struct k_itimer *timer, *next;
	unsigned long flags, start;
	LIST_HEAD(firing);

	// 获取tsk的sighand锁
	if (!lock_task_sighand(tsk, &flags))
		return;

	do {
		/*
		 * On RT locking sighand lock does not disable interrupts,
		 * so this needs to be careful vs. ticks. Store the current
		 * jiffies value.
		 */
		start = READ_ONCE(jiffies);
		barrier();

		/*
		 * Here we take off tsk->signal->cpu_timers[N] and
		 * tsk->cpu_timers[N] all the timers that are firing, and
		 * put them on the firing list.
		 这里我们将tsk->signal->cpu_timers[N]和tsk->cpu_timers[N]上的所有正在触发的定时器取下来，
		 并将它们放在firing列表上。
		 */
		// 这里是检查线程的posix_cputimers的各种计时下的posix_cputimer_base是否有超时的timer
		// 如果有,加入到firing列表中
		check_thread_timers(tsk, &firing);
		// 这里是进程级别的,好像操作的是task的sig的posix_cputimers的各种计时下的posix_cputimer_base
		check_process_timers(tsk, &firing);

		/*
		 * The above timer checks have updated the expiry cache and
		 * because nothing can have queued or modified timers after
		 * sighand lock was taken above it is guaranteed to be
		 * consistent. So the next timer interrupt fastpath check
		 * will find valid data.
		 *
		 * If timer expiry runs in the timer interrupt context then
		 * the loop is not relevant as timers will be directly
		 * expired in interrupt context. The stub function below
		 * returns always true which allows the compiler to
		 * optimize the loop out.
		 *
		 * If timer expiry is deferred to task work context then
		 * the following rules apply:
		 *
		 * - On !RT kernels no tick can have happened on this CPU
		 *   after sighand lock was acquired because interrupts are
		 *   disabled. So reenabling task work before dropping
		 *   sighand lock and reenabling interrupts is race free.
		 *
		 * - On RT kernels ticks might have happened but the tick
		 *   work ignored posix CPU timer handling because the
		 *   CPUTIMERS_WORK_SCHEDULED bit is set. Reenabling work
		 *   must be done very carefully including a check whether
		 *   ticks have happened since the start of the timer
		 *   expiry checks. posix_cpu_timers_enable_work() takes
		 *   care of that and eventually lets the expiry checks
		 *   run again.
		 */
	} while (!posix_cpu_timers_enable_work(tsk, start));

	/*
	 * We must release sighand lock before taking any timer's lock.
	 * There is a potential race with timer deletion here, as the
	 * siglock now protects our private firing list.  We have set
	 * the firing flag in each timer, so that a deletion attempt
	 * that gets the timer lock before we do will give it up and
	 * spin until we've taken care of that timer below.
	 */
	 // 这里对应函数开始时的lock_task_sighand
	unlock_task_sighand(tsk, &flags);

	/*
	 * Now that all the timers on our list have the firing flag,
	 * no one will touch their list entries but us.  We'll take
	 * each timer's lock before clearing its firing flag, so no
	 * timer call will interfere.
	 现在我们列表上的所有定时器都有firing标志，除了我们，没有人会触摸它们的列表条目。
	 我们将在清除其firing标志之前获取每个定时器的锁，因此没有定时器调用会干扰。
	 */
	// 刚才往fireing列表中加入的是cpu_timer,
	// 现在取下的是k_itimer, 可能cpu_timer也是k_itimer的一个成员
	// k_itimer是内核的表示?
	list_for_each_entry_safe(timer, next, &firing, it.cpu.elist) {
		int cpu_firing;

		/*
		 * spin_lock() is sufficient here even independent of the
		 * expiry context. If expiry happens in hard interrupt
		 * context it's obvious. For task work context it's safe
		 * because all other operations on timer::it_lock happen in
		 * task context (syscall or exit).
		 */
		spin_lock(&timer->it_lock);
		// 从fireing列表中取下这个timer
		list_del_init(&timer->it.cpu.elist);
		// 看看这个cpu_timer是否是firing的
		cpu_firing = timer->it.cpu.firing;
		timer->it.cpu.firing = 0;
		/*
		 * The firing flag is -1 if we collided with a reset
		 * of the timer, which already reported this
		 * almost-firing as an overrun.  So don't generate an event.
		 */
		if (likely(cpu_firing >= 0)) // 大于0就是firing的
			cpu_timer_fire(timer); // 触发?
		/* See posix_cpu_timer_wait_running() */
		rcu_assign_pointer(timer->it.cpu.handling, NULL);
		spin_unlock(&timer->it_lock);
	}
}

/*
 * This is called from the timer interrupt handler.  The irq handler has
 * already updated our counts.  We need to check if any timers fire now.
 * Interrupts are disabled.
 这是从定时器中断处理程序调用的。irq处理程序已经更新了我们的计数。
 我们需要检查是否有任何计时器现在触发。中断被禁用。
 */
void run_posix_cpu_timers(void)
{
	struct task_struct *tsk = current;

	lockdep_assert_irqs_disabled();

	/*
	 * If the actual expiry is deferred to task work context and the
	 * work is already scheduled there is no point to do anything here.
	 如果实际的到期被推迟到任务工作上下文，并且工作已经安排在那里，
	 * 这里没有任何意义。
	 */
	if (posix_cpu_timers_work_scheduled(tsk))
		return;

	/*
	 * The fast path checks that there are no expired thread or thread
	 * group timers.  If that's so, just return.
	 fastpath检查没有过期的线程或线程组定时器。
	 如果是这样，就返回。
	 */
	if (!fastpath_timer_check(tsk))
		return;

	__run_posix_cpu_timers(tsk);
}

/*
 * Set one of the process-wide special case CPU timers or RLIMIT_CPU.
 * The tsk->sighand->siglock must be held by the caller.
 */
void set_process_cpu_timer(struct task_struct *tsk, unsigned int clkid,
			   u64 *newval, u64 *oldval)
{
	u64 now, *nextevt;

	if (WARN_ON_ONCE(clkid >= CPUCLOCK_SCHED))
		return;

	nextevt = &tsk->signal->posix_cputimers.bases[clkid].nextevt;
	now = cpu_clock_sample_group(clkid, tsk, true);

	if (oldval) {
		/*
		 * We are setting itimer. The *oldval is absolute and we update
		 * it to be relative, *newval argument is relative and we update
		 * it to be absolute.
		 */
		if (*oldval) {
			if (*oldval <= now) {
				/* Just about to fire. */
				*oldval = TICK_NSEC;
			} else {
				*oldval -= now;
			}
		}

		if (*newval)
			*newval += now;
	}

	/*
	 * Update expiration cache if this is the earliest timer. CPUCLOCK_PROF
	 * expiry cache is also used by RLIMIT_CPU!.
	 */
	if (*newval < *nextevt)
		*nextevt = *newval;

	tick_dep_set_signal(tsk, TICK_DEP_BIT_POSIX_TIMER);
}

static int do_cpu_nanosleep(const clockid_t which_clock, int flags,
			    const struct timespec64 *rqtp)
{
	struct itimerspec64 it;
	struct k_itimer timer;
	u64 expires;
	int error;

	/*
	 * Set up a temporary timer and then wait for it to go off.
	 */
	memset(&timer, 0, sizeof timer);
	spin_lock_init(&timer.it_lock);
	timer.it_clock = which_clock;
	timer.it_overrun = -1;
	error = posix_cpu_timer_create(&timer);
	timer.it_process = current;

	if (!error) {
		static struct itimerspec64 zero_it;
		struct restart_block *restart;

		memset(&it, 0, sizeof(it));
		it.it_value = *rqtp;

		spin_lock_irq(&timer.it_lock);
		error = posix_cpu_timer_set(&timer, flags, &it, NULL);
		if (error) {
			spin_unlock_irq(&timer.it_lock);
			return error;
		}

		while (!signal_pending(current)) {
			if (!cpu_timer_getexpires(&timer.it.cpu)) {
				/*
				 * Our timer fired and was reset, below
				 * deletion can not fail.
				 */
				posix_cpu_timer_del(&timer);
				spin_unlock_irq(&timer.it_lock);
				return 0;
			}

			/*
			 * Block until cpu_timer_fire (or a signal) wakes us.
			 */
			__set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(&timer.it_lock);
			schedule();
			spin_lock_irq(&timer.it_lock);
		}

		/*
		 * We were interrupted by a signal.
		 */
		expires = cpu_timer_getexpires(&timer.it.cpu);
		error = posix_cpu_timer_set(&timer, 0, &zero_it, &it);
		if (!error) {
			/* Timer is now unarmed, deletion can not fail. */
			posix_cpu_timer_del(&timer);
		} else {
			while (error == TIMER_RETRY) {
				posix_cpu_timer_wait_running_nsleep(&timer);
				error = posix_cpu_timer_del(&timer);
			}
		}

		spin_unlock_irq(&timer.it_lock);

		if ((it.it_value.tv_sec | it.it_value.tv_nsec) == 0) {
			/*
			 * It actually did fire already.
			 */
			return 0;
		}

		error = -ERESTART_RESTARTBLOCK;
		/*
		 * Report back to the user the time still remaining.
		 */
		restart = &current->restart_block;
		restart->nanosleep.expires = expires;
		if (restart->nanosleep.type != TT_NONE)
			error = nanosleep_copyout(restart, &it.it_value);
	}

	return error;
}

static long posix_cpu_nsleep_restart(struct restart_block *restart_block);

static int posix_cpu_nsleep(const clockid_t which_clock, int flags,
			    const struct timespec64 *rqtp)
{
	struct restart_block *restart_block = &current->restart_block;
	int error;

	/*
	 * Diagnose required errors first.
	 */
	if (CPUCLOCK_PERTHREAD(which_clock) &&
	    (CPUCLOCK_PID(which_clock) == 0 ||
	     CPUCLOCK_PID(which_clock) == task_pid_vnr(current)))
		return -EINVAL;

	error = do_cpu_nanosleep(which_clock, flags, rqtp);

	if (error == -ERESTART_RESTARTBLOCK) {

		if (flags & TIMER_ABSTIME)
			return -ERESTARTNOHAND;

		restart_block->nanosleep.clockid = which_clock;
		set_restart_fn(restart_block, posix_cpu_nsleep_restart);
	}
	return error;
}

static long posix_cpu_nsleep_restart(struct restart_block *restart_block)
{
	clockid_t which_clock = restart_block->nanosleep.clockid;
	struct timespec64 t;

	t = ns_to_timespec64(restart_block->nanosleep.expires);

	return do_cpu_nanosleep(which_clock, TIMER_ABSTIME, &t);
}

#define PROCESS_CLOCK	make_process_cpuclock(0, CPUCLOCK_SCHED)
#define THREAD_CLOCK	make_thread_cpuclock(0, CPUCLOCK_SCHED)

static int process_cpu_clock_getres(const clockid_t which_clock,
				    struct timespec64 *tp)
{
	return posix_cpu_clock_getres(PROCESS_CLOCK, tp);
}
static int process_cpu_clock_get(const clockid_t which_clock,
				 struct timespec64 *tp)
{
	return posix_cpu_clock_get(PROCESS_CLOCK, tp);
}
static int process_cpu_timer_create(struct k_itimer *timer)
{
	timer->it_clock = PROCESS_CLOCK;
	return posix_cpu_timer_create(timer);
}
static int process_cpu_nsleep(const clockid_t which_clock, int flags,
			      const struct timespec64 *rqtp)
{
	return posix_cpu_nsleep(PROCESS_CLOCK, flags, rqtp);
}
static int thread_cpu_clock_getres(const clockid_t which_clock,
				   struct timespec64 *tp)
{
	return posix_cpu_clock_getres(THREAD_CLOCK, tp);
}
/*

*/
static int thread_cpu_clock_get(const clockid_t which_clock,
				struct timespec64 *tp)
{
	return posix_cpu_clock_get(THREAD_CLOCK, tp);
}
static int thread_cpu_timer_create(struct k_itimer *timer)
{
	timer->it_clock = THREAD_CLOCK;
	return posix_cpu_timer_create(timer);
}
/*
这个又是posix的什么时钟?
似乎是获取进程的时间,比如sched什么的
*/
const struct k_clock clock_posix_cpu = {
	.clock_getres		= posix_cpu_clock_getres,
	.clock_set		= posix_cpu_clock_set, // 这是个只读的时钟
	.clock_get_timespec	= posix_cpu_clock_get, // 获取进程的时间,比如sched什么的
	.timer_create		= posix_cpu_timer_create, // 
	.nsleep			= posix_cpu_nsleep,
	.timer_set		= posix_cpu_timer_set, // 插入timer到红黑树
	.timer_del		= posix_cpu_timer_del, // 从红黑树中删除timer
	.timer_get		= posix_cpu_timer_get,
	.timer_rearm		= posix_cpu_timer_rearm, // 好像也是插入
	.timer_wait_running	= posix_cpu_timer_wait_running, // 没看懂
};

const struct k_clock clock_process = {
	.clock_getres		= process_cpu_clock_getres,
	.clock_get_timespec	= process_cpu_clock_get,
	.timer_create		= process_cpu_timer_create,
	.nsleep			= process_cpu_nsleep,
};

const struct k_clock clock_thread = {
	.clock_getres		= thread_cpu_clock_getres,
	.clock_get_timespec	= thread_cpu_clock_get,
	.timer_create		= thread_cpu_timer_create,
};

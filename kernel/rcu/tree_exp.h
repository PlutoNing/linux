/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * RCU expedited grace periods
 *
 * Copyright IBM Corporation, 2016
 *
 * Authors: Paul E. McKenney <paulmck@linux.ibm.com>
 */

#include <linux/lockdep.h>

static void rcu_exp_handler(void *unused);
static int rcu_print_task_exp_stall(struct rcu_node *rnp);
static void rcu_exp_print_detail_task_stall_rnp(struct rcu_node *rnp);

/*
增加expedited seq的值
用于开始一个expedited gp
 * Record the start of an expedited grace period.
 */
static void rcu_exp_gp_seq_start(void)
{
	rcu_seq_start(&rcu_state.expedited_sequence);
	rcu_poll_gp_seq_start_unlocked(&rcu_state.gp_seq_polled_exp_snap);
}

/*
 * Return the value that the expedited-grace-period counter will have
 * at the end of the current grace period.
 */
static __maybe_unused unsigned long rcu_exp_gp_seq_endval(void)
{
	return rcu_seq_endval(&rcu_state.expedited_sequence);
}

/*
 * Record the end of an expedited grace period.
 */
static void rcu_exp_gp_seq_end(void)
{
	rcu_poll_gp_seq_end_unlocked(&rcu_state.gp_seq_polled_exp_snap);
	rcu_seq_end(&rcu_state.expedited_sequence);
	smp_mb(); /* Ensure that consecutive grace periods serialize. */
}

/*
保存rcu_state.expedited_sequence的seq版本号
 * Take a snapshot of the expedited-grace-period counter, which is the
 * earliest value that will indicate that a full grace period has
 * elapsed since the current time.
 */
static unsigned long rcu_exp_gp_seq_snap(void)
{
	unsigned long s;

	smp_mb(); /* Caller's modifications seen first by other CPUs. */
	s = rcu_seq_snap(&rcu_state.expedited_sequence);
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("snap"));
	return s;
}

/*
s是一个expedited版本号
这里检查在获取这个版本号之后是否完成了一个gp
就是检查这个s是不是落后了源值
 * Given a counter snapshot from rcu_exp_gp_seq_snap(), return true
 * if a full expedited grace period has elapsed since that snapshot
 * was taken.
 */
static bool rcu_exp_gp_seq_done(unsigned long s)
{
	return rcu_seq_done(&rcu_state.expedited_sequence, s);
}

/*
以后
重置rcu_node树中的->expmaskinit值用于反应cpu的上线活动
 * Reset the ->expmaskinit values in the rcu_node tree to reflect any
 * recent CPU-online activity.  Note that these masks are not cleared
 * when CPUs go offline, so they reflect the union of all CPUs that have
 * ever been online.  This means that this function normally takes its
 * no-work-to-do fastpath.
 */
static void sync_exp_reset_tree_hotplug(void)
{
	bool done;
	unsigned long flags;
	unsigned long mask;
	unsigned long oldmask;
	int ncpus = smp_load_acquire(&rcu_state.ncpus); /* Order vs. locking. */
	struct rcu_node *rnp;
	struct rcu_node *rnp_up;

	/* If no new CPUs onlined since last time, nothing to do. */
	if (likely(ncpus == rcu_state.ncpus_snap))
		return;
	/* 更新ncpus快照 */
	rcu_state.ncpus_snap = ncpus;

	/*
	 * Each pass through the following loop propagates newly onlined
	 * CPUs for the current rcu_node structure up the rcu_node tree.
	 这里遍历rcu_state的什么叶节点
	 */
	rcu_for_each_leaf_node(rnp) {
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		if (rnp->expmaskinit == rnp->expmaskinitnext) {
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			continue;  /* No new CPUs, nothing to do. */
		}

		/* Update this node's mask, track old value for propagation. */
		oldmask = rnp->expmaskinit;
		rnp->expmaskinit = rnp->expmaskinitnext;
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

		/* If was already nonzero, nothing to propagate. */
		if (oldmask)
			continue;

		/* Propagate the new CPU up the tree. */
		mask = rnp->grpmask;
		rnp_up = rnp->parent;
		done = false;
		while (rnp_up) {
			raw_spin_lock_irqsave_rcu_node(rnp_up, flags);
			if (rnp_up->expmaskinit)
				done = true;
			rnp_up->expmaskinit |= mask;
			raw_spin_unlock_irqrestore_rcu_node(rnp_up, flags);
			if (done)
				break;
			mask = rnp_up->grpmask;
			rnp_up = rnp_up->parent;
		}
	}
}

/*
为了准备一个新的expedited gp
这里重置rcu_node树中的->expmask值
 * Reset the ->expmask values in the rcu_node tree in preparation for
 * a new expedited grace period.
 */
static void __maybe_unused sync_exp_reset_tree(void)
{
	unsigned long flags;
	struct rcu_node *rnp;

	sync_exp_reset_tree_hotplug();
	rcu_for_each_node_breadth_first(rnp) {
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		WARN_ON_ONCE(rnp->expmask);
		WRITE_ONCE(rnp->expmask, rnp->expmaskinit);
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	}
}

/*
 * Return non-zero if there is no RCU expedited grace period in progress
 * for the specified rcu_node structure, in other words, if all CPUs and
 * tasks covered by the specified rcu_node structure have done their bit
 * for the current expedited grace period.
 */
static bool sync_rcu_exp_done(struct rcu_node *rnp)
{
	raw_lockdep_assert_held_rcu_node(rnp);
	return READ_ONCE(rnp->exp_tasks) == NULL &&
	       READ_ONCE(rnp->expmask) == 0;
}

/*
 * Like sync_rcu_exp_done(), but where the caller does not hold the
 * rcu_node's ->lock.
 */
static bool sync_rcu_exp_done_unlocked(struct rcu_node *rnp)
{
	unsigned long flags;
	bool ret;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	ret = sync_rcu_exp_done(rnp);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

	return ret;
}


/*
 * Report the exit from RCU read-side critical section for the last task
 * that queued itself during or before the current expedited preemptible-RCU
 * grace period.  This event is reported either to the rcu_node structure on
 * which the task was queued or to one of that rcu_node structure's ancestors,
 * recursively up the tree.  (Calm down, calm down, we do the recursion
 * iteratively!)
 */
static void __rcu_report_exp_rnp(struct rcu_node *rnp,
				 bool wake, unsigned long flags)
	__releases(rnp->lock)
{
	unsigned long mask;

	raw_lockdep_assert_held_rcu_node(rnp);
	for (;;) {
		if (!sync_rcu_exp_done(rnp)) {
			if (!rnp->expmask)
				rcu_initiate_boost(rnp, flags);
			else
				raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			break;
		}
		if (rnp->parent == NULL) {
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			if (wake) {
				smp_mb(); /* EGP done before wake_up(). */
				swake_up_one(&rcu_state.expedited_wq);
			}
			break;
		}
		mask = rnp->grpmask;
		raw_spin_unlock_rcu_node(rnp); /* irqs remain disabled */
		rnp = rnp->parent;
		raw_spin_lock_rcu_node(rnp); /* irqs already disabled */
		WARN_ON_ONCE(!(rnp->expmask & mask));
		WRITE_ONCE(rnp->expmask, rnp->expmask & ~mask);
	}
}

/*
 * Report expedited quiescent state for specified node.  This is a
 * lock-acquisition wrapper function for __rcu_report_exp_rnp().
 */
static void __maybe_unused rcu_report_exp_rnp(struct rcu_node *rnp, bool wake)
{
	unsigned long flags;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	__rcu_report_exp_rnp(rnp, wake, flags);
}

/*
 * Report expedited quiescent state for multiple CPUs, all covered by the
 * specified leaf rcu_node structure.
 */
static void rcu_report_exp_cpu_mult(struct rcu_node *rnp,
				    unsigned long mask, bool wake)
{
	int cpu;
	unsigned long flags;
	struct rcu_data *rdp;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	if (!(rnp->expmask & mask)) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}
	WRITE_ONCE(rnp->expmask, rnp->expmask & ~mask);
	for_each_leaf_node_cpu_mask(rnp, cpu, mask) {
		rdp = per_cpu_ptr(&rcu_data, cpu);
		if (!IS_ENABLED(CONFIG_NO_HZ_FULL) || !rdp->rcu_forced_tick_exp)
			continue;
		rdp->rcu_forced_tick_exp = false;
		tick_dep_clear_cpu(cpu, TICK_DEP_BIT_RCU_EXP);
	}
	__rcu_report_exp_rnp(rnp, wake, flags); /* Releases rnp->lock. */
}

/*
 * Report expedited quiescent state for specified rcu_data (CPU).
 */
static void rcu_report_exp_rdp(struct rcu_data *rdp)
{
	WRITE_ONCE(rdp->cpu_no_qs.b.exp, false);
	rcu_report_exp_cpu_mult(rdp->mynode, rdp->grpmask, true);
}

/* Common code for work-done checking.
检查s是不是落后了源值, 说明过了一个gp? */
static bool sync_exp_work_done(unsigned long s)
{
	if (rcu_exp_gp_seq_done(s)) {
		trace_rcu_exp_grace_period(rcu_state.name, s, TPS("done"));
		smp_mb(); /* Ensure test happens before caller kfree(). */
		return true;
	}
	return false;
}

/*
 * Funnel-lock acquisition for expedited grace periods.  Returns true
 * if some other task completed an expedited grace period that this task
 * can piggy-back on, and with no mutex held.  Otherwise, returns false
 * with the mutex held, indicating that the caller must actually do the
 * expedited grace period.
 返回真表示有其他进程完成了一个加速的gp, 这样我们可以搭便车.
 否则返回false, 表示我们必须自己完成这个gp
 */
static bool exp_funnel_lock(unsigned long s)
{
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, raw_smp_processor_id());
	struct rcu_node *rnp = rdp->mynode;
	struct rcu_node *rnp_root = rcu_get_root();

	/* Low-contention fastpath. */
	if (ULONG_CMP_LT(READ_ONCE(rnp->exp_seq_rq), s) &&
	    (rnp == rnp_root ||
	     ULONG_CMP_LT(READ_ONCE(rnp_root->exp_seq_rq), s)) &&
	    mutex_trylock(&rcu_state.exp_mutex))
		goto fastpath;

	/*
	这个循环每一遍都会检查这个rcu_node tree?返回有没有其他人完成了这个工作?
	 * Each pass through the following loop works its way up
	 * the rcu_node tree, returning if others have done the work or
	 * otherwise falls through to acquire ->exp_mutex.  The mapping
	 * from CPU to rcu_node structure can be inexact, as it is just
	 * promoting locality and is not strictly needed for correctness.
	 */
	/* 检查rdp->mynode所在的树 */
	for (; rnp != NULL; rnp = rnp->parent) {
		if (sync_exp_work_done(s))/* 如果这个s的源值自从获取之后变大了
		说明有人完成了gp? */
			return true;

		/* 现在说明没有其他人完成gp, 现在是检查是不是有人正在完成gp
		或者去检查rdp->mynode父层级 */
		/* Work not done, either wait here or go up. */
		spin_lock(&rnp->exp_lock);
		if (ULONG_CMP_GE(rnp->exp_seq_rq, s)) {
			/* 说明有其他人正在gp */

			/* Someone else doing GP, so wait for them. */
			spin_unlock(&rnp->exp_lock);
			trace_rcu_exp_funnel_lock(rcu_state.name, rnp->level,
						  rnp->grplo, rnp->grphi,
						  TPS("wait"));
			/* 在这里等待别人完成gp */
			wait_event(rnp->exp_wq[rcu_seq_ctr(s) & 0x3],
				   sync_exp_work_done(s));
			return true;
		}
		/* 自己做gp? */
		WRITE_ONCE(rnp->exp_seq_rq, s); /* Followers can wait on us. */
		spin_unlock(&rnp->exp_lock);
		trace_rcu_exp_funnel_lock(rcu_state.name, rnp->level,
					  rnp->grplo, rnp->grphi, TPS("nxtlvl"));
	}
	mutex_lock(&rcu_state.exp_mutex);
fastpath:
/* 可以直接检查 */
	if (sync_exp_work_done(s)) {
		mutex_unlock(&rcu_state.exp_mutex);
		return true;
	}
	/* 到这里说明需要自己完成expedited gp?
	增加expedited seq的值, 开始写侧更新 */
	rcu_exp_gp_seq_start();
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("start"));
	return false;
}

/*
选择expedited gp需要等待的指定的rcu_node树中的CPU?
 * Select the CPUs within the specified rcu_node that the upcoming
 * expedited grace period needs to wait for.
 rewp是一个rnp的work
 */
static void __sync_rcu_exp_select_node_cpus(struct rcu_exp_work *rewp)
{
	int cpu;
	unsigned long flags;
	unsigned long mask_ofl_test;
	unsigned long mask_ofl_ipi;
	int ret;
	struct rcu_node *rnp = container_of(rewp, struct rcu_node, rew);

	raw_spin_lock_irqsave_rcu_node(rnp, flags);

	/* Each pass checks a CPU for identity, offline, and idle.
	每一遍循环检查一个cpu */
	mask_ofl_test = 0;
	for_each_leaf_node_cpu_mask(rnp, cpu, rnp->expmask) {
		struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
		unsigned long mask = rdp->grpmask;
		int snap;

		if (raw_smp_processor_id() == cpu ||
		    !(rnp->qsmaskinitnext & mask)) {
			mask_ofl_test |= mask;
		} else {
			snap = rcu_dynticks_snap(cpu);
			if (rcu_dynticks_in_eqs(snap))
				mask_ofl_test |= mask;
			else
				rdp->exp_dynticks_snap = snap;
		}
	}
	mask_ofl_ipi = rnp->expmask & ~mask_ofl_test;

	/*
	 * Need to wait for any blocked tasks as well.	Note that
	 * additional blocking tasks will also block the expedited GP
	 * until such time as the ->expmask bits are cleared.
	 */
	if (rcu_preempt_has_tasks(rnp))
		WRITE_ONCE(rnp->exp_tasks, rnp->blkd_tasks.next);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

	/* IPI the remaining CPUs for expedited quiescent state. */
	for_each_leaf_node_cpu_mask(rnp, cpu, mask_ofl_ipi) {
		struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
		unsigned long mask = rdp->grpmask;

retry_ipi:
		if (rcu_dynticks_in_eqs_since(rdp, rdp->exp_dynticks_snap)) {
			mask_ofl_test |= mask;
			continue;
		}
		if (get_cpu() == cpu) {
			mask_ofl_test |= mask;
			put_cpu();
			continue;
		}
		ret = smp_call_function_single(cpu, rcu_exp_handler, NULL, 0);
		put_cpu();
		/* The CPU will report the QS in response to the IPI. */
		if (!ret)
			continue;

		/* Failed, raced with CPU hotplug operation. */
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		if ((rnp->qsmaskinitnext & mask) &&
		    (rnp->expmask & mask)) {
			/* Online, so delay for a bit and try again. */
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("selectofl"));
			schedule_timeout_idle(1);
			goto retry_ipi;
		}
		/* CPU really is offline, so we must report its QS. */
		if (rnp->expmask & mask)
			mask_ofl_test |= mask;
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	}
	/* Report quiescent states for those that went offline. */
	if (mask_ofl_test)
		rcu_report_exp_cpu_mult(rnp, mask_ofl_test, false);
}

static void rcu_exp_sel_wait_wake(unsigned long s);

#ifdef CONFIG_RCU_EXP_KTHREAD
static void sync_rcu_exp_select_node_cpus(struct kthread_work *wp)
{
	struct rcu_exp_work *rewp =
		container_of(wp, struct rcu_exp_work, rew_work);

	__sync_rcu_exp_select_node_cpus(rewp);
}

static inline bool rcu_gp_par_worker_started(void)
{
	return !!READ_ONCE(rcu_exp_par_gp_kworker);
}

static inline void sync_rcu_exp_select_cpus_queue_work(struct rcu_node *rnp)
{
	kthread_init_work(&rnp->rew.rew_work, sync_rcu_exp_select_node_cpus);
	/*
	 * Use rcu_exp_par_gp_kworker, because flushing a work item from
	 * another work item on the same kthread worker can result in
	 * deadlock.
	 */
	kthread_queue_work(rcu_exp_par_gp_kworker, &rnp->rew.rew_work);
}

static inline void sync_rcu_exp_select_cpus_flush_work(struct rcu_node *rnp)
{
	kthread_flush_work(&rnp->rew.rew_work);
}

/*
 * Work-queue handler to drive an expedited grace period forward.
 */
static void wait_rcu_exp_gp(struct kthread_work *wp)
{
	struct rcu_exp_work *rewp;

	rewp = container_of(wp, struct rcu_exp_work, rew_work);
	rcu_exp_sel_wait_wake(rewp->rew_s);
}

static inline void synchronize_rcu_expedited_queue_work(struct rcu_exp_work *rew)
{
	kthread_init_work(&rew->rew_work, wait_rcu_exp_gp);
	kthread_queue_work(rcu_exp_gp_kworker, &rew->rew_work);
}

static inline void synchronize_rcu_expedited_destroy_work(struct rcu_exp_work *rew)
{
}
#else /* !CONFIG_RCU_EXP_KTHREAD */
/* 这里好像是在最后一个叶节点或者没有其他race的情况下
直接调用一个什么work */
static void sync_rcu_exp_select_node_cpus(struct work_struct *wp)
{
	struct rcu_exp_work *rewp =
		container_of(wp, struct rcu_exp_work, rew_work);

	__sync_rcu_exp_select_node_cpus(rewp);
}

static inline bool rcu_gp_par_worker_started(void)
{
	return !!READ_ONCE(rcu_par_gp_wq);
}

static inline void sync_rcu_exp_select_cpus_queue_work(struct rcu_node *rnp)
{
	int cpu = find_next_bit(&rnp->ffmask, BITS_PER_LONG, -1);

	INIT_WORK(&rnp->rew.rew_work, sync_rcu_exp_select_node_cpus);
	/* If all offline, queue the work on an unbound CPU. */
	if (unlikely(cpu > rnp->grphi - rnp->grplo))
		cpu = WORK_CPU_UNBOUND;
	else
		cpu += rnp->grplo;
	queue_work_on(cpu, rcu_par_gp_wq, &rnp->rew.rew_work);
}

static inline void sync_rcu_exp_select_cpus_flush_work(struct rcu_node *rnp)
{
	flush_work(&rnp->rew.rew_work);
}

/*
用于完成expedited gp的synchronize_rcu_expedited_queue_work的work的func函数
 * Work-queue handler to drive an expedited grace period forward.
 */
static void wait_rcu_exp_gp(struct work_struct *wp)
{
	struct rcu_exp_work *rewp;

	/* 获取到所属的rew */
	rewp = container_of(wp, struct rcu_exp_work, rew_work);
	rcu_exp_sel_wait_wake(rewp->rew_s);
}

/* 这个函数用于完成一个expedited gp */
static inline void synchronize_rcu_expedited_queue_work(struct rcu_exp_work *rew)
{
	INIT_WORK_ONSTACK(&rew->rew_work, wait_rcu_exp_gp);
	queue_work(rcu_gp_wq, &rew->rew_work);
}

static inline void synchronize_rcu_expedited_destroy_work(struct rcu_exp_work *rew)
{
	destroy_work_on_stack(&rew->rew_work);
}
#endif /* CONFIG_RCU_EXP_KTHREAD */

/*
用于完成expedited gp的人物入队后, 被唤醒时先执行这个prep的逻辑
后续其他函数进行wait和wake,clean
这个函数打下基础
 * Select the nodes that the upcoming expedited grace period needs
 * to wait for.
 */
static void sync_rcu_exp_select_cpus(void)
{
	struct rcu_node *rnp;

	trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("reset"));
	/* 重置rcu_node树中的->expmask值 */
	sync_exp_reset_tree();
	trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("select"));

	/* Schedule work for each leaf rcu_node structure.
	调度每个rcu_node叶节点的什么work */
	rcu_for_each_leaf_node(rnp) {
		rnp->exp_need_flush = false;
		if (!READ_ONCE(rnp->expmask))
			continue; /* Avoid early boot non-existent wq. */
		if (!rcu_gp_par_worker_started() ||
		    rcu_scheduler_active != RCU_SCHEDULER_RUNNING ||
		    rcu_is_last_leaf_node(rnp)) {
			/* No worker started yet or last leaf, do direct call. */
			sync_rcu_exp_select_node_cpus(&rnp->rew.rew_work);
			continue;
		}
		sync_rcu_exp_select_cpus_queue_work(rnp);
		rnp->exp_need_flush = true;
	}

	/* Wait for jobs (if any) to complete. */
	rcu_for_each_leaf_node(rnp)
		if (rnp->exp_need_flush)
			sync_rcu_exp_select_cpus_flush_work(rnp);
}

/*
 * Wait for the expedited grace period to elapse, within time limit.
 * If the time limit is exceeded without the grace period elapsing,
 * return false, otherwise return true.
 */
static bool synchronize_rcu_expedited_wait_once(long tlimit)
{
	int t;
	struct rcu_node *rnp_root = rcu_get_root();

	t = swait_event_timeout_exclusive(rcu_state.expedited_wq,
					  sync_rcu_exp_done_unlocked(rnp_root),
					  tlimit);
	// Workqueues should not be signaled.
	if (t > 0 || sync_rcu_exp_done_unlocked(rnp_root))
		return true;
	WARN_ON(t < 0);  /* workqueues should not be signaled. */
	return false;
}

/*
 * Wait for the expedited grace period to elapse, issuing any needed
 * RCU CPU stall warnings along the way.
 */
static void synchronize_rcu_expedited_wait(void)
{
	int cpu;
	unsigned long j;
	unsigned long jiffies_stall;
	unsigned long jiffies_start;
	unsigned long mask;
	int ndetected;
	struct rcu_data *rdp;
	struct rcu_node *rnp;
	struct rcu_node *rnp_root = rcu_get_root();
	unsigned long flags;

	trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("startwait"));
	jiffies_stall = rcu_exp_jiffies_till_stall_check();
	jiffies_start = jiffies;
	if (tick_nohz_full_enabled() && rcu_inkernel_boot_has_ended()) {
		if (synchronize_rcu_expedited_wait_once(1))
			return;
		rcu_for_each_leaf_node(rnp) {
			raw_spin_lock_irqsave_rcu_node(rnp, flags);
			mask = READ_ONCE(rnp->expmask);
			for_each_leaf_node_cpu_mask(rnp, cpu, mask) {
				rdp = per_cpu_ptr(&rcu_data, cpu);
				if (rdp->rcu_forced_tick_exp)
					continue;
				rdp->rcu_forced_tick_exp = true;
				if (cpu_online(cpu))
					tick_dep_set_cpu(cpu, TICK_DEP_BIT_RCU_EXP);
			}
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		}
		j = READ_ONCE(jiffies_till_first_fqs);
		if (synchronize_rcu_expedited_wait_once(j + HZ))
			return;
	}

	for (;;) {
		if (synchronize_rcu_expedited_wait_once(jiffies_stall))
			return;
		if (rcu_stall_is_suppressed())
			continue;
		trace_rcu_stall_warning(rcu_state.name, TPS("ExpeditedStall"));
		pr_err("INFO: %s detected expedited stalls on CPUs/tasks: {",
		       rcu_state.name);
		ndetected = 0;
		rcu_for_each_leaf_node(rnp) {
			ndetected += rcu_print_task_exp_stall(rnp);
			for_each_leaf_node_possible_cpu(rnp, cpu) {
				struct rcu_data *rdp;

				mask = leaf_node_cpu_bit(rnp, cpu);
				if (!(READ_ONCE(rnp->expmask) & mask))
					continue;
				ndetected++;
				rdp = per_cpu_ptr(&rcu_data, cpu);
				pr_cont(" %d-%c%c%c%c", cpu,
					"O."[!!cpu_online(cpu)],
					"o."[!!(rdp->grpmask & rnp->expmaskinit)],
					"N."[!!(rdp->grpmask & rnp->expmaskinitnext)],
					"D."[!!data_race(rdp->cpu_no_qs.b.exp)]);
			}
		}
		pr_cont(" } %lu jiffies s: %lu root: %#lx/%c\n",
			jiffies - jiffies_start, rcu_state.expedited_sequence,
			data_race(rnp_root->expmask),
			".T"[!!data_race(rnp_root->exp_tasks)]);
		if (ndetected) {
			pr_err("blocking rcu_node structures (internal RCU debug):");
			rcu_for_each_node_breadth_first(rnp) {
				if (rnp == rnp_root)
					continue; /* printed unconditionally */
				if (sync_rcu_exp_done_unlocked(rnp))
					continue;
				pr_cont(" l=%u:%d-%d:%#lx/%c",
					rnp->level, rnp->grplo, rnp->grphi,
					data_race(rnp->expmask),
					".T"[!!data_race(rnp->exp_tasks)]);
			}
			pr_cont("\n");
		}
		rcu_for_each_leaf_node(rnp) {
			for_each_leaf_node_possible_cpu(rnp, cpu) {
				mask = leaf_node_cpu_bit(rnp, cpu);
				if (!(READ_ONCE(rnp->expmask) & mask))
					continue;
				preempt_disable(); // For smp_processor_id() in dump_cpu_task().
				dump_cpu_task(cpu);
				preempt_enable();
			}
			rcu_exp_print_detail_task_stall_rnp(rnp);
		}
		jiffies_stall = 3 * rcu_exp_jiffies_till_stall_check() + 3;
		panic_on_rcu_stall();
	}
}

/*
 * Wait for the current expedited grace period to complete, and then
 * wake up everyone who piggybacked on the just-completed expedited
 * grace period.  Also update all the ->exp_seq_rq counters as needed
 * in order to avoid counter-wrap problems.
 */
static void rcu_exp_wait_wake(unsigned long s)
{
	struct rcu_node *rnp;

	synchronize_rcu_expedited_wait();

	// Switch over to wakeup mode, allowing the next GP to proceed.
	// End the previous grace period only after acquiring the mutex
	// to ensure that only one GP runs concurrently with wakeups.
	mutex_lock(&rcu_state.exp_wake_mutex);
	rcu_exp_gp_seq_end();
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("end"));

	rcu_for_each_node_breadth_first(rnp) {
		if (ULONG_CMP_LT(READ_ONCE(rnp->exp_seq_rq), s)) {
			spin_lock(&rnp->exp_lock);
			/* Recheck, avoid hang in case someone just arrived. */
			if (ULONG_CMP_LT(rnp->exp_seq_rq, s))
				WRITE_ONCE(rnp->exp_seq_rq, s);
			spin_unlock(&rnp->exp_lock);
		}
		smp_mb(); /* All above changes before wakeup. */
		wake_up_all(&rnp->exp_wq[rcu_seq_ctr(s) & 0x3]);
	}
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("endwake"));
	mutex_unlock(&rcu_state.exp_wake_mutex);
}

/*用于完成expedited gp的synchronize_rcu_expedited_queue_work的work的func
函数的核心函数
在队列中被唤醒后执行这个函数来完成expedited gp.
参数是rew的rew_s
 * Common code to drive an expedited grace period forward, used by
 * workqueues and mid-boot-time tasks.
 */
static void rcu_exp_sel_wait_wake(unsigned long s)
{
	/* Initialize the rcu_node tree in preparation for the wait. */
	sync_rcu_exp_select_cpus();

	/* Wait and clean up, including waking everyone. */
	rcu_exp_wait_wake(s);
}

#ifdef CONFIG_PREEMPT_RCU

/*
 * Remote handler for smp_call_function_single().  If there is an
 * RCU read-side critical section in effect, request that the
 * next rcu_read_unlock() record the quiescent state up the
 * ->expmask fields in the rcu_node tree.  Otherwise, immediately
 * report the quiescent state.
 */
static void rcu_exp_handler(void *unused)
{
	int depth = rcu_preempt_depth();
	unsigned long flags;
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
	struct rcu_node *rnp = rdp->mynode;
	struct task_struct *t = current;

	/*
	 * First, the common case of not being in an RCU read-side
	 * critical section.  If also enabled or idle, immediately
	 * report the quiescent state, otherwise defer.
	 */
	if (!depth) {
		if (!(preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK)) ||
		    rcu_is_cpu_rrupt_from_idle()) {
			rcu_report_exp_rdp(rdp);
		} else {
			WRITE_ONCE(rdp->cpu_no_qs.b.exp, true);
			set_tsk_need_resched(t);
			set_preempt_need_resched();
		}
		return;
	}

	/*
	 * Second, the less-common case of being in an RCU read-side
	 * critical section.  In this case we can count on a future
	 * rcu_read_unlock().  However, this rcu_read_unlock() might
	 * execute on some other CPU, but in that case there will be
	 * a future context switch.  Either way, if the expedited
	 * grace period is still waiting on this CPU, set ->deferred_qs
	 * so that the eventual quiescent state will be reported.
	 * Note that there is a large group of race conditions that
	 * can have caused this quiescent state to already have been
	 * reported, so we really do need to check ->expmask.
	 */
	if (depth > 0) {
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		if (rnp->expmask & rdp->grpmask) {
			WRITE_ONCE(rdp->cpu_no_qs.b.exp, true);
			t->rcu_read_unlock_special.b.exp_hint = true;
		}
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}

	// Finally, negative nesting depth should not happen.
	WARN_ON_ONCE(1);
}

/* PREEMPTION=y, so no PREEMPTION=n expedited grace period to clean up after. */
static void sync_sched_exp_online_cleanup(int cpu)
{
}

/*
 * Scan the current list of tasks blocked within RCU read-side critical
 * sections, printing out the tid of each that is blocking the current
 * expedited grace period.
 */
static int rcu_print_task_exp_stall(struct rcu_node *rnp)
{
	unsigned long flags;
	int ndetected = 0;
	struct task_struct *t;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	if (!rnp->exp_tasks) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return 0;
	}
	t = list_entry(rnp->exp_tasks->prev,
		       struct task_struct, rcu_node_entry);
	list_for_each_entry_continue(t, &rnp->blkd_tasks, rcu_node_entry) {
		pr_cont(" P%d", t->pid);
		ndetected++;
	}
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	return ndetected;
}

/*
 * Scan the current list of tasks blocked within RCU read-side critical
 * sections, dumping the stack of each that is blocking the current
 * expedited grace period.
 */
static void rcu_exp_print_detail_task_stall_rnp(struct rcu_node *rnp)
{
	unsigned long flags;
	struct task_struct *t;

	if (!rcu_exp_stall_task_details)
		return;
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	if (!READ_ONCE(rnp->exp_tasks)) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}
	t = list_entry(rnp->exp_tasks->prev,
		       struct task_struct, rcu_node_entry);
	list_for_each_entry_continue(t, &rnp->blkd_tasks, rcu_node_entry) {
		/*
		 * We could be printing a lot while holding a spinlock.
		 * Avoid triggering hard lockup.
		 */
		touch_nmi_watchdog();
		sched_show_task(t);
	}
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
}

#else /* #ifdef CONFIG_PREEMPT_RCU */

/* Request an expedited quiescent state. */
static void rcu_exp_need_qs(void)
{
	__this_cpu_write(rcu_data.cpu_no_qs.b.exp, true);
	/* Store .exp before .rcu_urgent_qs. */
	smp_store_release(this_cpu_ptr(&rcu_data.rcu_urgent_qs), true);
	set_tsk_need_resched(current);
	set_preempt_need_resched();
}

/* Invoked on each online non-idle CPU for expedited quiescent state. */
static void rcu_exp_handler(void *unused)
{
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
	struct rcu_node *rnp = rdp->mynode;
	bool preempt_bh_enabled = !(preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK));

	if (!(READ_ONCE(rnp->expmask) & rdp->grpmask) ||
	    __this_cpu_read(rcu_data.cpu_no_qs.b.exp))
		return;
	if (rcu_is_cpu_rrupt_from_idle() ||
	    (IS_ENABLED(CONFIG_PREEMPT_COUNT) && preempt_bh_enabled)) {
		rcu_report_exp_rdp(this_cpu_ptr(&rcu_data));
		return;
	}
	rcu_exp_need_qs();
}

/* Send IPI for expedited cleanup if needed at end of CPU-hotplug operation. */
static void sync_sched_exp_online_cleanup(int cpu)
{
	unsigned long flags;
	int my_cpu;
	struct rcu_data *rdp;
	int ret;
	struct rcu_node *rnp;

	rdp = per_cpu_ptr(&rcu_data, cpu);
	rnp = rdp->mynode;
	my_cpu = get_cpu();
	/* Quiescent state either not needed or already requested, leave. */
	if (!(READ_ONCE(rnp->expmask) & rdp->grpmask) ||
	    READ_ONCE(rdp->cpu_no_qs.b.exp)) {
		put_cpu();
		return;
	}
	/* Quiescent state needed on current CPU, so set it up locally. */
	if (my_cpu == cpu) {
		local_irq_save(flags);
		rcu_exp_need_qs();
		local_irq_restore(flags);
		put_cpu();
		return;
	}
	/* Quiescent state needed on some other CPU, send IPI. */
	ret = smp_call_function_single(cpu, rcu_exp_handler, NULL, 0);
	put_cpu();
	WARN_ON_ONCE(ret);
}

/*
 * Because preemptible RCU does not exist, we never have to check for
 * tasks blocked within RCU read-side critical sections that are
 * blocking the current expedited grace period.
 */
static int rcu_print_task_exp_stall(struct rcu_node *rnp)
{
	return 0;
}

/*
 * Because preemptible RCU does not exist, we never have to print out
 * tasks blocked within RCU read-side critical sections that are blocking
 * the current expedited grace period.
 */
static void rcu_exp_print_detail_task_stall_rnp(struct rcu_node *rnp)
{
}

#endif /* #else #ifdef CONFIG_PREEMPT_RCU */

/**
如果rcu_scheduler_active不处于RCU_SCHEDULER_INACTIVE, 并且rcu_gp_is_expedited的话
就用这个函数来sync rcu.
 * synchronize_rcu_expedited - Brute-force RCU grace period
 * 通过在所有非idle非nohz的cpu上面运行ipi函数来加快gp, 
 ip函数检查cpu是不是在rcu临界区, 是的话,设置flag来通知最外层的rcu_read_unlock()报告RCU-preempt的quiescent state
 * 或者请求调度器的帮助来报告RCU-sched的quiescent state. 如果cpu不在RCU read-side critical section,
 * ipi handler会立即报告quiescent state.
 * Wait for an RCU grace period, but expedite it.  The basic idea is to
 * IPI all non-idle non-nohz online CPUs.  The IPI handler checks whether
 * the CPU is in an RCU critical section, and if so, it sets a flag that
 * causes the outermost rcu_read_unlock() to report the quiescent state
 * for RCU-preempt or asks the scheduler for help for RCU-sched.  On the
 * other hand, if the CPU is not in an RCU read-side critical section,
 * the IPI handler reports the quiescent state immediately.
 *
 * Although this is a great improvement over previous expedited
 * implementations, it is still unfriendly to real-time workloads, so is
 * thus not recommended for any sort of common-case code.  In fact, if
 * you are using synchronize_rcu_expedited() in a loop, please restructure
 * your code to batch your updates, and then use a single synchronize_rcu()
 * instead.
 *
 * This has the same semantics as (but is more brutal than) synchronize_rcu().
 */
void synchronize_rcu_expedited(void)
{
	bool boottime = (rcu_scheduler_active == RCU_SCHEDULER_INIT);
	unsigned long flags;
	struct rcu_exp_work rew;
	struct rcu_node *rnp;
	unsigned long s;

	RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
			 lock_is_held(&rcu_lock_map) ||
			 lock_is_held(&rcu_sched_lock_map),
			 "Illegal synchronize_rcu_expedited() in RCU read-side critical section");

	/* Is the state is such that the call is a grace period? */
	if (rcu_blocking_is_gp()) {
		/* 如果rcu_scheduler_active处于RCU_SCHEDULER_INACTIVE */
		// Note well that this code runs with !PREEMPT && !SMP.
		// In addition, all code that advances grace periods runs
		// at process level.  Therefore, this expedited GP overlaps
		// with other expedited GPs only by being fully nested within
		// them, which allows reuse of ->gp_seq_polled_exp_snap.
		rcu_poll_gp_seq_start_unlocked(&rcu_state.gp_seq_polled_exp_snap);
		rcu_poll_gp_seq_end_unlocked(&rcu_state.gp_seq_polled_exp_snap);

		local_irq_save(flags);
		WARN_ON_ONCE(num_online_cpus() > 1);
		rcu_state.expedited_sequence += (1 << RCU_SEQ_CTR_SHIFT);
		local_irq_restore(flags);
		return;  // Context allows vacuous grace periods.
	}

	/* If expedited grace periods are prohibited, fall back to normal. */
	if (rcu_gp_is_normal()) {
		/* 这里是加速gp被禁用的情况, 使用normal gp */
		/* 这个wait_rcu_gp内部使用wakeme_after_rcu作为rcu_head_func调用call_rcu_hurry
		call_rcu_hurry(&rs_array[i].head, wakeme_after_rcu);
		call_rcu_hurry实际上调用call_rcu
		call_rcu就是把rcu_head(wakeme_after_rcu函数)入队rcu_ctrlblk.curtail
		==========
		这个过程中gp是如何完成的 */
		wait_rcu_gp(call_rcu_hurry);
		return;
	}

	/* Take a snapshot of the sequence number.
	保存一下expedited的seq号  */
	s = rcu_exp_gp_seq_snap();
	/* 检查有没有其他人完成了gp */
	if (exp_funnel_lock(s))
		return;  /* Someone else did our work for us. */

	/* 到这里说明要自己完成expedited gp, 并且已经增加了expedited seq */
	/* Ensure that load happens before action based on it. */
	if (unlikely(boottime)) {
		/* Direct call during scheduler init and early_initcalls(). */
		rcu_exp_sel_wait_wake(s);
	} else {
		/* Marshall arguments & schedule the expedited grace period. */
		rew.rew_s = s;
		synchronize_rcu_expedited_queue_work(&rew);
	}

	/* Wait for expedited grace period to complete. */
	rnp = rcu_get_root();
	wait_event(rnp->exp_wq[rcu_seq_ctr(s) & 0x3],
		   sync_exp_work_done(s));
	smp_mb(); /* Work actions happen before return. */

	/* Let the next expedited grace period start. */
	mutex_unlock(&rcu_state.exp_mutex);

	if (likely(!boottime))
		synchronize_rcu_expedited_destroy_work(&rew);
}
EXPORT_SYMBOL_GPL(synchronize_rcu_expedited);

/*
 * Ensure that start_poll_synchronize_rcu_expedited() has the expedited
 * RCU grace periods that it needs.
 */
static void sync_rcu_do_polled_gp(struct work_struct *wp)
{
	unsigned long flags;
	int i = 0;
	struct rcu_node *rnp = container_of(wp, struct rcu_node, exp_poll_wq);
	unsigned long s;

	raw_spin_lock_irqsave(&rnp->exp_poll_lock, flags);
	s = rnp->exp_seq_poll_rq;
	rnp->exp_seq_poll_rq = RCU_GET_STATE_COMPLETED;
	raw_spin_unlock_irqrestore(&rnp->exp_poll_lock, flags);
	if (s == RCU_GET_STATE_COMPLETED)
		return;
	while (!poll_state_synchronize_rcu(s)) {
		synchronize_rcu_expedited();
		if (i == 10 || i == 20)
			pr_info("%s: i = %d s = %lx gp_seq_polled = %lx\n", __func__, i, s, READ_ONCE(rcu_state.gp_seq_polled));
		i++;
	}
	raw_spin_lock_irqsave(&rnp->exp_poll_lock, flags);
	s = rnp->exp_seq_poll_rq;
	if (poll_state_synchronize_rcu(s))
		rnp->exp_seq_poll_rq = RCU_GET_STATE_COMPLETED;
	raw_spin_unlock_irqrestore(&rnp->exp_poll_lock, flags);
}

/**
 * start_poll_synchronize_rcu_expedited - Snapshot current RCU state and start expedited grace period
 *
 * Returns a cookie to pass to a call to cond_synchronize_rcu(),
 * cond_synchronize_rcu_expedited(), or poll_state_synchronize_rcu(),
 * allowing them to determine whether or not any sort of grace period has
 * elapsed in the meantime.  If the needed expedited grace period is not
 * already slated to start, initiates that grace period.
 */
unsigned long start_poll_synchronize_rcu_expedited(void)
{
	unsigned long flags;
	struct rcu_data *rdp;
	struct rcu_node *rnp;
	unsigned long s;

	s = get_state_synchronize_rcu();
	rdp = per_cpu_ptr(&rcu_data, raw_smp_processor_id());
	rnp = rdp->mynode;
	if (rcu_init_invoked())
		raw_spin_lock_irqsave(&rnp->exp_poll_lock, flags);
	if (!poll_state_synchronize_rcu(s)) {
		if (rcu_init_invoked()) {
			rnp->exp_seq_poll_rq = s;
			queue_work(rcu_gp_wq, &rnp->exp_poll_wq);
		}
	}
	if (rcu_init_invoked())
		raw_spin_unlock_irqrestore(&rnp->exp_poll_lock, flags);

	return s;
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_rcu_expedited);

/**
 * start_poll_synchronize_rcu_expedited_full - Take a full snapshot and start expedited grace period
 * @rgosp: Place to put snapshot of grace-period state
 *
 * Places the normal and expedited grace-period states in rgosp.  This
 * state value can be passed to a later call to cond_synchronize_rcu_full()
 * or poll_state_synchronize_rcu_full() to determine whether or not a
 * grace period (whether normal or expedited) has elapsed in the meantime.
 * If the needed expedited grace period is not already slated to start,
 * initiates that grace period.
 */
void start_poll_synchronize_rcu_expedited_full(struct rcu_gp_oldstate *rgosp)
{
	get_state_synchronize_rcu_full(rgosp);
	(void)start_poll_synchronize_rcu_expedited();
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_rcu_expedited_full);

/**
 * cond_synchronize_rcu_expedited - Conditionally wait for an expedited RCU grace period
 *
 * @oldstate: value from get_state_synchronize_rcu(), start_poll_synchronize_rcu(), or start_poll_synchronize_rcu_expedited()
 *
 * If any type of full RCU grace period has elapsed since the earlier
 * call to get_state_synchronize_rcu(), start_poll_synchronize_rcu(),
 * or start_poll_synchronize_rcu_expedited(), just return.  Otherwise,
 * invoke synchronize_rcu_expedited() to wait for a full grace period.
 *
 * Yes, this function does not take counter wrap into account.
 * But counter wrap is harmless.  If the counter wraps, we have waited for
 * more than 2 billion grace periods (and way more on a 64-bit system!),
 * so waiting for a couple of additional grace periods should be just fine.
 *
 * This function provides the same memory-ordering guarantees that
 * would be provided by a synchronize_rcu() that was invoked at the call
 * to the function that provided @oldstate and that returned at the end
 * of this function.
 */
void cond_synchronize_rcu_expedited(unsigned long oldstate)
{
	if (!poll_state_synchronize_rcu(oldstate))
		synchronize_rcu_expedited();
}
EXPORT_SYMBOL_GPL(cond_synchronize_rcu_expedited);

/**
 * cond_synchronize_rcu_expedited_full - Conditionally wait for an expedited RCU grace period
 * @rgosp: value from get_state_synchronize_rcu_full(), start_poll_synchronize_rcu_full(), or start_poll_synchronize_rcu_expedited_full()
 *
 * If a full RCU grace period has elapsed since the call to
 * get_state_synchronize_rcu_full(), start_poll_synchronize_rcu_full(),
 * or start_poll_synchronize_rcu_expedited_full() from which @rgosp was
 * obtained, just return.  Otherwise, invoke synchronize_rcu_expedited()
 * to wait for a full grace period.
 *
 * Yes, this function does not take counter wrap into account.
 * But counter wrap is harmless.  If the counter wraps, we have waited for
 * more than 2 billion grace periods (and way more on a 64-bit system!),
 * so waiting for a couple of additional grace periods should be just fine.
 *
 * This function provides the same memory-ordering guarantees that
 * would be provided by a synchronize_rcu() that was invoked at the call
 * to the function that provided @rgosp and that returned at the end of
 * this function.
 */
void cond_synchronize_rcu_expedited_full(struct rcu_gp_oldstate *rgosp)
{
	if (!poll_state_synchronize_rcu_full(rgosp))
		synchronize_rcu_expedited();
}
EXPORT_SYMBOL_GPL(cond_synchronize_rcu_expedited_full);

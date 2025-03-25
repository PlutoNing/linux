// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/time_namespace.h>

#include "futex.h"

/*
 * Support for robust futexes: the kernel cleans up held futexes at
 * thread exit time.
 *
 * Implementation: user-space maintains a per-thread list of locks it
 * is holding. Upon do_exit(), the kernel carefully walks this list,
 * and marks all locks that are owned by this thread with the
 * FUTEX_OWNER_DIED bit, and wakes up a waiter (if any). The list is
 * always manipulated with the lock held, so the list is private and
 * per-thread. Userspace also maintains a per-thread 'list_op_pending'
 * field, to allow the kernel to clean up if the thread dies after
 * acquiring the lock, but just before it could have added itself to
 * the list. There can only be one such pending lock.
 */

/**
 * sys_set_robust_list() - Set the robust-futex list head of a task
 * @head:	pointer to the list-head
 * @len:	length of the list-head, as userspace expects
 */
SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head,
		size_t, len)
{
	/*
	 * The kernel knows only one size for now:
	 */
	if (unlikely(len != sizeof(*head)))
		return -EINVAL;

	current->robust_list = head;

	return 0;
}

/**
 * sys_get_robust_list() - Get the robust-futex list head of a task
 * @pid:	pid of the process [zero for current task]
 * @head_ptr:	pointer to a list-head pointer, the kernel fills it in
 * @len_ptr:	pointer to a length field, the kernel fills in the header size
 */
SYSCALL_DEFINE3(get_robust_list, int, pid,
		struct robust_list_head __user * __user *, head_ptr,
		size_t __user *, len_ptr)
{
	struct robust_list_head __user *head;
	unsigned long ret;
	struct task_struct *p;

	rcu_read_lock();

	ret = -ESRCH;
	if (!pid)
		p = current;
	else {
		p = find_task_by_vpid(pid);
		if (!p)
			goto err_unlock;
	}

	ret = -EPERM;
	if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS))
		goto err_unlock;

	head = p->robust_list;
	rcu_read_unlock();

	if (put_user(sizeof(*head), len_ptr))
		return -EFAULT;
	return put_user(head, head_ptr);

err_unlock:
	rcu_read_unlock();

	return ret;
}
/* 
Futex是一种用户态和内核态混合的同步机制，支持进程内的线程之间和进程间的同步锁操作。
*/
long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3)
{
	int cmd = op & FUTEX_CMD_MASK;
	unsigned int flags = 0;

	if (!(op & FUTEX_PRIVATE_FLAG))
		flags |= FLAGS_SHARED;

	if (op & FUTEX_CLOCK_REALTIME) {
		flags |= FLAGS_CLOCKRT;
		if (cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_WAIT_REQUEUE_PI &&
		    cmd != FUTEX_LOCK_PI2)
			return -ENOSYS;
	}

	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
		fallthrough;
	case FUTEX_WAIT_BITSET:
		return futex_wait(uaddr, flags, val, timeout, val3);
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
		fallthrough;
	case FUTEX_WAKE_BITSET:
		return futex_wake(uaddr, flags, val, val3);
	case FUTEX_REQUEUE:
		return futex_requeue(uaddr, flags, uaddr2, val, val2, NULL, 0);
	case FUTEX_CMP_REQUEUE:
		return futex_requeue(uaddr, flags, uaddr2, val, val2, &val3, 0);
	case FUTEX_WAKE_OP:
		return futex_wake_op(uaddr, flags, uaddr2, val, val2, val3);
	case FUTEX_LOCK_PI:
		flags |= FLAGS_CLOCKRT;
		fallthrough;
	case FUTEX_LOCK_PI2:
		return futex_lock_pi(uaddr, flags, timeout, 0);
	case FUTEX_UNLOCK_PI:
		return futex_unlock_pi(uaddr, flags);
	case FUTEX_TRYLOCK_PI:
		return futex_lock_pi(uaddr, flags, NULL, 1);
	case FUTEX_WAIT_REQUEUE_PI:
		val3 = FUTEX_BITSET_MATCH_ANY;
		return futex_wait_requeue_pi(uaddr, flags, val, timeout, val3,
					     uaddr2);
	case FUTEX_CMP_REQUEUE_PI:
		return futex_requeue(uaddr, flags, uaddr2, val, val2, &val3, 1);
	}
	return -ENOSYS;
}

// 下面这几种cmd有timeout?
static __always_inline bool futex_cmd_has_timeout(u32 cmd)
{
	switch (cmd) {
	case FUTEX_WAIT:
	case FUTEX_LOCK_PI:
	case FUTEX_LOCK_PI2:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAIT_REQUEUE_PI:
		return true;
	}
	return false;
}

/* 
把t转为ts
如果是FUTE_WAIT,就把t这个timeout加上当前时间

*/
static __always_inline int
futex_init_timeout(u32 cmd, u32 op, struct timespec64 *ts, ktime_t *t)
{
	if (!timespec64_valid(ts))
		return -EINVAL;

	*t = timespec64_to_ktime(*ts);
	if (cmd == FUTEX_WAIT)
		*t = ktime_add_safe(ktime_get(), *t);
	else if (cmd != FUTEX_LOCK_PI && !(op & FUTEX_CLOCK_REALTIME))
		*t = timens_ktime_to_host(CLOCK_MONOTONIC, *t);
	return 0;
}

SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
		const struct __kernel_timespec __user *, utime,
		u32 __user *, uaddr2, u32, val3)
{
	int ret, cmd = op & FUTEX_CMD_MASK;
	ktime_t t, *tp = NULL;
	struct timespec64 ts;

	if (utime && futex_cmd_has_timeout(cmd)) { // 如果是有timeout的cmd
		if (unlikely(should_fail_futex(!(op & FUTEX_PRIVATE_FLAG))))
			return -EFAULT;
		if (get_timespec64(&ts, utime))
			return -EFAULT;
		ret = futex_init_timeout(cmd, op, &ts, &t);
		if (ret)
			return ret;
		tp = &t;
	}// 刚刚初始化了一些时间

	return do_futex(uaddr, op, val, tp, uaddr2, (unsigned long)utime, val3);
}

/* Mask of available flags for each futex in futex_waitv list */
#define FUTEXV_WAITER_MASK (FUTEX_32 | FUTEX_PRIVATE_FLAG)

/**
 * futex_parse_waitv - Parse a waitv array from userspace
 * @futexv:	Kernel side list of waiters to be filled
 * @uwaitv:     Userspace list to be parsed
 * @nr_futexes: Length of futexv
 *
 * Return: Error code on failure, 0 on success
 */
static int futex_parse_waitv(struct futex_vector *futexv,
			     struct futex_waitv __user *uwaitv,
			     unsigned int nr_futexes)
{
	struct futex_waitv aux;
	unsigned int i;

	for (i = 0; i < nr_futexes; i++) {
		if (copy_from_user(&aux, &uwaitv[i], sizeof(aux)))
			return -EFAULT;

		if ((aux.flags & ~FUTEXV_WAITER_MASK) || aux.__reserved)
			return -EINVAL;

		if (!(aux.flags & FUTEX_32))
			return -EINVAL;

		futexv[i].w.flags = aux.flags;
		futexv[i].w.val = aux.val;
		futexv[i].w.uaddr = aux.uaddr;
		futexv[i].q = futex_q_init;
	}

	return 0;
}

/**
 * sys_futex_waitv - Wait on a list of futexes
 等待一组futex
 * @waiters:    List of futexes to wait on
 * @nr_futexes: Length of futexv
 * @flags:      Flag for timeout (monotonic/realtime)
 * @timeout:	Optional absolute timeout.
 * @clockid:	Clock to be used for the timeout, realtime or monotonic.
 *
 * Given an array of `struct futex_waitv`, wait on each uaddr. The thread wakes
 * if a futex_wake() is performed at any uaddr. The syscall returns immediately
 * if any waiter has *uaddr != val. *timeout is an optional timeout value for
 * the operation. Each waiter has individual flags. The `flags` argument for
 * the syscall should be used solely for specifying the timeout as realtime, if
 * needed. Flags for private futexes, sizes, etc. should be used on the
 * individual flags of each waiter.
 * 给定一个`struct futex_waitv`数组，等待每个uaddr。如果在任何uaddr上执行了futex_wake()，线程将唤醒。
 * 如果任何waiter有*uaddr != val，则立即返回。*timeout是操作的可选超时值。每个waiter都有独立的标志。
 * 系统调用的`flags`参数应仅用于指定超时为实时，如果需要的话。应在每个waiter的个别标志上使用私有futexes、
 大小等标志。
 * Returns the array index of one of the woken futexes. No further information
 * is provided: any number of other futexes may also have been woken by the
 * same event, and if more than one futex was woken, the retrned index may
 * refer to any one of them. (It is not necessaryily the futex with the
 * smallest index, nor the one most recently woken, nor...)
 返回其中一个唤醒的futexes的数组索引。不提供进一步的信息：同一事件可能唤醒了任意数量
 的其他futexes, 如果唤醒了多个futex，则返回的索引可能指向其中任何一个.
 (不一定是索引最小的futex, 也不一定是最近唤醒的futex, 也不一定是...)
 */

SYSCALL_DEFINE5(futex_waitv, 
	 struct futex_waitv __user *, waiters,
	 unsigned int, nr_futexes,
	 unsigned int, flags,
	 struct __kernel_timespec __user *, timeout,
	 clockid_t, clockid)
{
	struct hrtimer_sleeper to;
	struct futex_vector *futexv;
	struct timespec64 ts;
	ktime_t time;
	int ret;

	/* This syscall supports no flags for now */
	if (flags)
		return -EINVAL;

	if (!nr_futexes || nr_futexes > FUTEX_WAITV_MAX || !waiters)
		return -EINVAL;

	if (timeout) {
		int flag_clkid = 0, flag_init = 0;

		if (clockid == CLOCK_REALTIME) {
			flag_clkid = FLAGS_CLOCKRT;
			flag_init = FUTEX_CLOCK_REALTIME;
		}

		if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
			return -EINVAL;
		// clockid必须是CLOCK_REALTIME或CLOCK_MONOTONIC

		//把用户空间的timeout转换为内核空间的ts
		if (get_timespec64(&ts, timeout))
			return -EFAULT;

		/*
		 * Since there's no opcode for futex_waitv, use
		 * FUTEX_WAIT_BITSET that uses absolute timeout as well
		 因为futex_waitv没有opcode，所以使用FUTEX_WAIT_BITSET，它也使用绝对超时
		 */
		// 这里进行时间的调整, 现在time有可能真的是现在时间加上timeout值了
		ret = futex_init_timeout(FUTEX_WAIT_BITSET, flag_init, &ts, &time);
		if (ret)
			return ret;

		futex_setup_timer(&time, &to, flag_clkid, 0);
	}

	futexv = kcalloc(nr_futexes, sizeof(*futexv), GFP_KERNEL);
	if (!futexv) {
		ret = -ENOMEM;
		goto destroy_timer;
	}

	ret = futex_parse_waitv(futexv, waiters, nr_futexes);
	if (!ret)
		ret = futex_wait_multiple(futexv, nr_futexes, timeout ? &to : NULL);

	kfree(futexv);

destroy_timer:
	if (timeout) {
		hrtimer_cancel(&to.timer);
		destroy_hrtimer_on_stack(&to.timer);
	}
	return ret;
}

/* 
设置robust futex列表的head
*/
#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(set_robust_list,
		struct compat_robust_list_head __user *, head,
		compat_size_t, len)
{
	if (unlikely(len != sizeof(*head)))
		return -EINVAL;

	current->compat_robust_list = head;

	return 0;
}
/* 
These system calls deal with per-thread robust futex lists.  These
       lists are managed in user space: the kernel knows only about the
       location of the head of the list.  A thread can inform the kernel
       of the location of its robust futex list using set_robust_list().
       The address of a thread's robust futex list can be obtained using
       get_robust_list().
这个系统调用处理每个线程的鲁棒futex列表。这些列表在用户空间中管理：内核只知道列表头的位置。
线程可以使用set_robust_list()通知内核其鲁棒futex列表的位置。可以使用get_robust_list()
获取线程的robust futex列表的地址。
       The purpose of the robust futex list is to ensure that if a thread
       accidentally fails to unlock a futex before terminating or calling
       execve(2), another thread that is waiting on that futex is
       notified that the former owner of the futex has died.  This
       notification consists of two pieces: the FUTEX_OWNER_DIED bit is
       set in the futex word, and the kernel performs a futex(2)
       FUTEX_WAKE operation on one of the threads waiting on the futex.
robust futex list的目的是确保如果一个线程在终止或调用execve(2)之前意外地未解锁futex，
则等待该futex的另一个线程将被通知futex的前任所有者已经死亡。此通知由两部分组成：
在futex字中设置FUTEX_OWNER_DIED位，并且内核对等待futex的线程之一执行futex(2) FUTEX_WAKE操作。
       The get_robust_list() system call returns the head of the robust
       futex list of the thread whose thread ID is specified in pid.  If
       pid is 0, the head of the list for the calling thread is returned.
       The list head is stored in the location pointed to by head_ptr.
       The size of the object pointed to by **head_ptr is stored in
       sizep.
get_robust_list()系统调用返回指定pid的线程的鲁棒futex列表的头。如果pid为0，则返回调用线程的列表头。
列表头存储在head_ptr指向的位置。**head_ptr指向的对象的大小存储在sizep中.
       Permission to employ get_robust_list() is governed by a ptrace
       access mode PTRACE_MODE_READ_REALCREDS check; see ptrace(2).

       The set_robust_list() system call requests the kernel to record
       the head of the list of robust futexes owned by the calling
       thread.  The head argument is the list head to record.  The size
       argument should be sizeof(*head).
*/
COMPAT_SYSCALL_DEFINE3(get_robust_list, int, pid,
			compat_uptr_t __user *, head_ptr,
			compat_size_t __user *, len_ptr)
{
	struct compat_robust_list_head __user *head;
	unsigned long ret;
	struct task_struct *p;

	rcu_read_lock();

	ret = -ESRCH;
	if (!pid)
		p = current;
	else {
		p = find_task_by_vpid(pid);
		if (!p)
			goto err_unlock;
	}

	ret = -EPERM;
	if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS))
		goto err_unlock;

	head = p->compat_robust_list;
	rcu_read_unlock();

	if (put_user(sizeof(*head), len_ptr))
		return -EFAULT;
	return put_user(ptr_to_compat(head), head_ptr);

err_unlock:
	rcu_read_unlock();

	return ret;
}
#endif /* CONFIG_COMPAT */

/* 32版本 */
#ifdef CONFIG_COMPAT_32BIT_TIME
SYSCALL_DEFINE6(futex_time32, u32 __user *, uaddr, int, op, u32, val,
		const struct old_timespec32 __user *, utime, u32 __user *, uaddr2,
		u32, val3)
{
	int ret, cmd = op & FUTEX_CMD_MASK;
	ktime_t t, *tp = NULL;
	struct timespec64 ts;

	if (utime && futex_cmd_has_timeout(cmd)) {
		if (get_old_timespec32(&ts, utime))
			return -EFAULT;
		ret = futex_init_timeout(cmd, op, &ts, &t);
		if (ret)
			return ret;
		tp = &t;
	}

	return do_futex(uaddr, op, val, tp, uaddr2, (unsigned long)utime, val3);
}
#endif /* CONFIG_COMPAT_32BIT_TIME */


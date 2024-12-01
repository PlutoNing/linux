/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SWITCH_TO_H
#define _ASM_X86_SWITCH_TO_H

#include <linux/sched/task_stack.h>

struct task_struct; /* one of the stranger aspects of C forward declarations */

struct task_struct *__switch_to_asm(struct task_struct *prev,
				    struct task_struct *next);

__visible struct task_struct *__switch_to(struct task_struct *prev,
					  struct task_struct *next);

/* This runs runs on the previous thread's stack. */
static inline void prepare_switch_to(struct task_struct *next)
{
#ifdef CONFIG_VMAP_STACK
	/*
	 * If we switch to a stack that has a top-level paging entry
	 * that is not present in the current mm, the resulting #PF will
	 * will be promoted to a double-fault and we'll panic.  Probe
	 * the new stack now so that vmalloc_fault can fix up the page
	 * tables if needed.  This can only happen if we use a stack
	 * in vmap space.
	 *	如果我们切换到一个堆栈，该堆栈具有当前 mm 中不存在的顶级分页条目，
	 *	则将导致结果 #PF 提升为双故障，并且我们将崩溃。
	 *	现在探测新堆栈，以便 vmalloc_fault 可以在需要时修复页表。
	 *	只有在使用 vmap 空间中的堆栈时才会发生这种情况。
	 * We assume that the stack is aligned so that it never spans
	 * more than one top-level paging entry.
	 * 我们假设堆栈对齐，因此它永远不会跨越一个顶级分页条目。
	 * To minimize cache pollution, just follow the stack pointer.
			为了最小化缓存污染，只需跟随堆栈指针。
	 */
	READ_ONCE(*(unsigned char *)next->thread.sp);
#endif
}

asmlinkage void ret_from_fork(void);

/*
 * This is the structure pointed to by thread.sp for an inactive task.  The
 * order of the fields must match the code in __switch_to_asm().
 */
struct inactive_task_frame {
#ifdef CONFIG_X86_64
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
#else
	unsigned long flags;
	unsigned long si;
	unsigned long di;
#endif
	unsigned long bx;

	/*
	 * These two fields must be together.  They form a stack frame header,
	 * needed by get_frame_pointer().
	 */
	unsigned long bp;
	unsigned long ret_addr;
};

struct fork_frame {
	struct inactive_task_frame frame;
	struct pt_regs regs;
};

//切换到下一个进程
#define switch_to(prev, next, last)					\
do {									\
	prepare_switch_to(next);					\
									\
	((last) = __switch_to_asm((prev), (next)));			\
} while (0)

#ifdef CONFIG_X86_32
static inline void refresh_sysenter_cs(struct thread_struct *thread)
{
	/* Only happens when SEP is enabled, no need to test "SEP"arately: */
	if (unlikely(this_cpu_read(cpu_tss_rw.x86_tss.ss1) == thread->sysenter_cs))
		return;

	this_cpu_write(cpu_tss_rw.x86_tss.ss1, thread->sysenter_cs);
	wrmsr(MSR_IA32_SYSENTER_CS, thread->sysenter_cs, 0);
}
#endif

/* This is used when switching tasks or entering/exiting vm86 mode. */
static inline void update_task_stack(struct task_struct *task)
{
	/* sp0 always points to the entry trampoline stack, which is constant: */
#ifdef CONFIG_X86_32
	if (static_cpu_has(X86_FEATURE_XENPV))
		load_sp0(task->thread.sp0);
	else
		this_cpu_write(cpu_tss_rw.x86_tss.sp1, task->thread.sp0);
#else
	/*
	 * x86-64 updates x86_tss.sp1 via cpu_current_top_of_stack. That
	 * doesn't work on x86-32 because sp1 and
	 * cpu_current_top_of_stack have different values (because of
	 * the non-zero stack-padding on 32bit).
	 */
	if (static_cpu_has(X86_FEATURE_XENPV))
		load_sp0(task_top_of_stack(task));
#endif

}

#endif /* _ASM_X86_SWITCH_TO_H */

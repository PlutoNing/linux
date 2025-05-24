/* SPDX-License-Identifier: GPL-2.0 */
/* thread_info.h: low-level thread information
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds and Dave Miller
 */

#ifndef _ASM_X86_THREAD_INFO_H
#define _ASM_X86_THREAD_INFO_H

#include <linux/compiler.h>
#include <asm/page.h>
#include <asm/percpu.h>
#include <asm/types.h>

/*
 * TOP_OF_KERNEL_STACK_PADDING is a number of unused bytes that we
 * reserve at the top of the kernel stack.  We do it because of a nasty
 * 32-bit corner case.  On x86_32, the hardware stack frame is
 * variable-length.  Except for vm86 mode, struct pt_regs assumes a
 * maximum-length frame.  If we enter from CPL 0, the top 8 bytes of
 * pt_regs don't actually exist.  Ordinarily this doesn't matter, but it
 * does in at least one case:
 *
 * If we take an NMI early enough in SYSENTER, then we can end up with
 * pt_regs that extends above sp0.  On the way out, in the espfix code,
 * we can read the saved SS value, but that value will be above sp0.
 * Without this offset, that can result in a page fault.  (We are
 * careful that, in this case, the value we read doesn't matter.)
 *
 * In vm86 mode, the hardware frame is much longer still, so add 16
 * bytes to make room for the real-mode segments.
 *
 * x86_64 has a fixed-length stack frame.
 */
#ifdef CONFIG_X86_32
# ifdef CONFIG_VM86
#  define TOP_OF_KERNEL_STACK_PADDING 16
# else
#  define TOP_OF_KERNEL_STACK_PADDING 8
# endif
#else
# define TOP_OF_KERNEL_STACK_PADDING 0
#endif

/*
 * low level task data that entry.S needs immediate access to
 * - this struct should fit entirely inside of one cache line
 * - this struct shares the supervisor stack pages
 */
#ifndef __ASSEMBLY__
struct task_struct;
#include <asm/cpufeature.h>
#include <linux/atomic.h>

struct thread_info {
	unsigned long		flags;		/* low level flags
	比如表示是否有信号存在的flag
	*/
	unsigned long		syscall_work;	/* SYSCALL_WORK_ flags */
	u32			status;		/* thread synchronous flags */
#ifdef CONFIG_SMP
	u32			cpu;		/* 
	可以推测出什么?
	cpu正在运行p?
	current CPU */
#endif
};

#define INIT_THREAD_INFO(tsk)			\
{						\
	.flags		= 0,			\
}

#else /* !__ASSEMBLY__ */

#include <asm/asm-offsets.h>

#endif

/*
 * thread information flags
 * - these are process state flags that various assembly files
 *   may need to access
 这些是thread_info的flag
 */
/* 要求线程在返回到用户空间前执行回调（如文件描述符就绪通知） */
#define TIF_NOTIFY_RESUME	1	/* callback before returning to user */
#define TIF_SIGPENDING		2
/* signal pending , 表示进程收到了信号*/
#define TIF_NEED_RESCHED	3	/* rescheduling necessary */
#define TIF_SINGLESTEP		4	/* reenable singlestep on user return*/
#define TIF_SSBD		5	/* Speculative store bypass disable */
#define TIF_SPEC_IB		9	/* Indirect branch speculation mitigation */
#define TIF_SPEC_L1D_FLUSH	10	/* Flush L1D on mm switches (processes) */
#define TIF_USER_RETURN_NOTIFY	11	/* notify kernel of userspace return */
#define TIF_UPROBE		12	/* breakpointed or singlestepping */
#define TIF_PATCH_PENDING	13	/* pending live patching update */
#define TIF_NEED_FPU_LOAD	14	/* load FPU on return to userspace */
#define TIF_NOCPUID		15	/* CPUID is not accessible in userland */
#define TIF_NOTSC		16	/* TSC is not accessible in userland */
#define TIF_NOTIFY_SIGNAL	17	/* signal notifications exist */
#define TIF_MEMDIE		20	/* is terminating due to OOM killer */
#define TIF_POLLING_NRFLAG	21	/* idle is polling for TIF_NEED_RESCHED */
#define TIF_IO_BITMAP		22	/* uses I/O bitmap */
#define TIF_SPEC_FORCE_UPDATE	23	/* Force speculation MSR update in context switch */
#define TIF_FORCED_TF		24	/* true if TF in eflags artificially */
#define TIF_BLOCKSTEP		25	/* set when we want DEBUGCTLMSR_BTF */
#define TIF_LAZY_MMU_UPDATES	27	/* task is updating the mmu lazily */
#define TIF_ADDR32		29	/* 32-bit address space on 64 bits */



/* 要求线程在返回到用户空间前执行回调（如文件描述符就绪通知）。
​用途**​：用于异步 I/O 或事件通知机制（例如 epoll）。 */
#define _TIF_NOTIFY_RESUME	(1 << TIF_NOTIFY_RESUME)
/* 线程有未处理的信号（Pending Signals）。
​触发场景**​：当信号被发送到线程但尚未被处理时设置，内核在返回用户空间前检查并处理。 */
#define _TIF_SIGPENDING		(1 << TIF_SIGPENDING)
/* 需要重新调度当前线程（触发抢占）。
​触发场景**​：更高优先级任务就绪或时间片耗尽时设置，内核在适当时间点切换任务。 */
#define _TIF_NEED_RESCHED	(1 << TIF_NEED_RESCHED)
/* 启用单步执行（Single Step），用于调试器（如 GDB）。
​硬件支持**​：依赖 CPU 的调试寄存器（如 x86 的 EFLAGS.TF 标志）。 */
#define _TIF_SINGLESTEP (1 << TIF_SINGLESTEP)
/* 禁用推测性存储绕过（Speculative Store Bypass Disable）。
​背景**​：缓解 Spectre-V4 漏洞，防止恶意推测执行攻击。 */
#define _TIF_SSBD (1 << TIF_SSBD)
/* 间接分支预测屏障（Indirect Branch Speculation Barrier）。
​用途**​：缓解 Spectre-V2 漏洞，限制间接分支预测。 */
#define _TIF_SPEC_IB (1 << TIF_SPEC_IB)
/*  */
#define _TIF_SPEC_L1D_FLUSH (1 << TIF_SPEC_L1D_FLUSH)
/* 在返回到用户空间前执行通知回调。
​用途**​：虚拟化场景中处理 VMExit 事件。 */
#define _TIF_USER_RETURN_NOTIFY (1 << TIF_USER_RETURN_NOTIFY)
/* 线程有用户空间探针（Userspace Probe）待处理。
​用途**​：动态追踪工具（如 Uprobes）插入断点时设置。 */
#define _TIF_UPROBE (1 << TIF_UPROBE)
/* 有热补丁（Livepatch）待应用。
​用途**​：内核热补丁系统（如 Kpatch）在安全更新时使用。 */
#define _TIF_PATCH_PENDING (1 << TIF_PATCH_PENDING)
/* 线程需要加载 FPU（浮点单元）状态。
​触发场景**​：FPU 上下文切换时，延迟加载以优化性能。 */
#define _TIF_NEED_FPU_LOAD (1 << TIF_NEED_FPU_LOAD)
/* 禁止线程使用 CPUID 指令。
​用途**​：虚拟化场景中限制客户机操作。 */
#define _TIF_NOCPUID (1 << TIF_NOCPUID)
/* 禁用时间戳计数器（Time Stamp Counter, TSC）。
​用途**​：防止用户空间通过 TSC 进行侧信道攻击。 */
#define _TIF_NOTSC		(1 << TIF_NOTSC)
/* 与信号处理相关的通知（扩展信号处理）。
​内核版本**​：5.10+ 引入，支持更复杂的信号处理逻辑。 */
#define _TIF_NOTIFY_SIGNAL (1 << TIF_NOTIFY_SIGNAL)
/* 线程处于忙等待（Busy-wait）状态，主动检查是否需要调度。
​用途**​：减少无谓的中断，常用于实时任务或特定性能优化场景。 */
#define _TIF_POLLING_NRFLAG (1 << TIF_POLLING_NRFLAG)
/* 线程有独立的 I/O 权限位图（x86 架构特性）。
​用途**​：限制用户空间程序的 I/O 端口访问权限。 */
#define _TIF_IO_BITMAP (1 << TIF_IO_BITMAP)
/* 强制更新推测执行缓解策略（如 CPU 微码更新后重新配置）。 */
#define _TIF_SPEC_FORCE_UPDATE (1 << TIF_SPEC_FORCE_UPDATE)
/* 强制设置陷阱标志（Trap Flag），用于调试或模拟异常。
​触发场景**​：内核模拟调试异常时设置。 */
#define _TIF_FORCED_TF (1 << TIF_FORCED_TF)
/* 启用块步进（Block Step），单步执行一个指令块（如 x86 的 Branch Trap）。
​用途**​：更高效的调试，减少单步中断次数。 */
#define _TIF_BLOCKSTEP (1 << TIF_BLOCKSTEP)
/* 延迟 MMU（内存管理单元）更新（如页表切换）。
​用途**​：批处理 MMU 操作以减少锁竞争。 */
#define _TIF_LAZY_MMU_UPDATES (1 << TIF_LAZY_MMU_UPDATES)
/* 线程使用 32 位地址模式（x86-64 兼容模式）。
​背景**​：在 64 位内核中运行 32 位用户程序时设置。 */
#define _TIF_ADDR32 (1 << TIF_ADDR32)
/*  */

/* flags to check in __switch_to() */
#define _TIF_WORK_CTXSW_BASE					\
	(_TIF_NOCPUID | _TIF_NOTSC | _TIF_BLOCKSTEP |		\
	 _TIF_SSBD | _TIF_SPEC_FORCE_UPDATE)

/*
 * Avoid calls to __switch_to_xtra() on UP as STIBP is not evaluated.
 */
#ifdef CONFIG_SMP
# define _TIF_WORK_CTXSW	(_TIF_WORK_CTXSW_BASE | _TIF_SPEC_IB)
#else
# define _TIF_WORK_CTXSW	(_TIF_WORK_CTXSW_BASE)
#endif

#ifdef CONFIG_X86_IOPL_IOPERM
# define _TIF_WORK_CTXSW_PREV	(_TIF_WORK_CTXSW| _TIF_USER_RETURN_NOTIFY | \
				 _TIF_IO_BITMAP)
#else
# define _TIF_WORK_CTXSW_PREV	(_TIF_WORK_CTXSW| _TIF_USER_RETURN_NOTIFY)
#endif

#define _TIF_WORK_CTXSW_NEXT	(_TIF_WORK_CTXSW)

#define STACK_WARN		(THREAD_SIZE/8)

/*
 * macros/functions for gaining access to the thread information structure
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
#ifndef __ASSEMBLY__

/*
 * Walks up the stack frames to make sure that the specified object is
 * entirely contained by a single stack frame.
 *
 * Returns:
 *	GOOD_FRAME	if within a frame
 *	BAD_STACK	if placed across a frame boundary (or outside stack)
 *	NOT_STACK	unable to determine (no frame pointers, etc)
 *
 * This function reads pointers from the stack and dereferences them. The
 * pointers may not have their KMSAN shadow set up properly, which may result
 * in false positive reports. Disable instrumentation to avoid those.
 */
__no_kmsan_checks
static inline int arch_within_stack_frames(const void * const stack,
					   const void * const stackend,
					   const void *obj, unsigned long len)
{
#if defined(CONFIG_FRAME_POINTER)
	const void *frame = NULL;
	const void *oldframe;

	oldframe = __builtin_frame_address(1);
	if (oldframe)
		frame = __builtin_frame_address(2);
	/*
	 * low ----------------------------------------------> high
	 * [saved bp][saved ip][args][local vars][saved bp][saved ip]
	 *                     ^----------------^
	 *               allow copies only within here
	 */
	while (stack <= frame && frame < stackend) {
		/*
		 * If obj + len extends past the last frame, this
		 * check won't pass and the next frame will be 0,
		 * causing us to bail out and correctly report
		 * the copy as invalid.
		 */
		if (obj + len <= frame)
			return obj >= oldframe + 2 * sizeof(void *) ?
				GOOD_FRAME : BAD_STACK;
		oldframe = frame;
		frame = *(const void * const *)frame;
	}
	return BAD_STACK;
#else
	return NOT_STACK;
#endif
}

#endif  /* !__ASSEMBLY__ */

/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
#define TS_COMPAT		0x0002	/* 32bit syscall active (64BIT)*/

#ifndef __ASSEMBLY__
#ifdef CONFIG_COMPAT
#define TS_I386_REGS_POKED	0x0004	/* regs poked by 32-bit ptracer */

#define arch_set_restart_data(restart)	\
	do { restart->arch_data = current_thread_info()->status; } while (0)

#endif

#ifdef CONFIG_X86_32
#define in_ia32_syscall() true
#else
#define in_ia32_syscall() (IS_ENABLED(CONFIG_IA32_EMULATION) && \
			   current_thread_info()->status & TS_COMPAT)
#endif

extern void arch_setup_new_exec(void);
#define arch_setup_new_exec arch_setup_new_exec
#endif	/* !__ASSEMBLY__ */

#endif /* _ASM_X86_THREAD_INFO_H */

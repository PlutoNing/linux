/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MMU_H
#define _ASM_X86_MMU_H

#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/atomic.h>

/*
2024年08月09日18:24:39
硬件相关的mm ctx
 * x86 has arch-specific MMU state beyond what lives in mm_struct.
 包含成员比如:
 	- ctx_id: 唯一标识这个mm_struct的ctx_id
 	- tlb_gen: 用于TLB刷新
 	- ldt_usr_sem: 用于ldt表的用户态信号量
 	- ldt: LDT表
 	- ia32_compat: 32位兼容模式
 	- vdso: vdso基地址
 	- vdso_image: vdso镜像
 	- perf_rdpmc_allowed: 允许rdpmc
 	- pkey_allocation_map: 保护密钥分配映射
 	- execute_only_pkey: 只执行保护密钥
 	- bd_addr: 边界目录地址
 */
typedef struct {
	/*
	 * ctx_id uniquely identifies this mm_struct.  A ctx_id will never
	 * be reused, and zero is not a valid ctx_id.
	 */
	u64 ctx_id;

	/*
	 * Any code that needs to do any sort of TLB flushing for this
	 * mm will first make its changes to the page tables, then
	 * increment tlb_gen, then flush.  This lets the low-level
	 * flushing code keep track of what needs flushing.
	 *
	 * This is not used on Xen PV.
	 */
	atomic64_t tlb_gen;

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	struct rw_semaphore	ldt_usr_sem;
	struct ldt_struct	*ldt; //LDT表
#endif

#ifdef CONFIG_X86_64
	/* True if mm supports a task running in 32 bit compatibility mode. */
	unsigned short ia32_compat;
#endif

	struct mutex lock;
	void __user *vdso;			/* vdso base address */
	const struct vdso_image *vdso_image;	/* vdso image in use */

	atomic_t perf_rdpmc_allowed;	/* nonzero if rdpmc is allowed */
#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
	/*
	 * One bit per protection key says whether userspace can
	 * use it or not.  protected by mmap_sem.
	 */
	u16 pkey_allocation_map;
	s16 execute_only_pkey;
#endif
#ifdef CONFIG_X86_INTEL_MPX
	/* address of the bounds directory */
	void __user *bd_addr;
#endif
} mm_context_t;

#define INIT_MM_CONTEXT(mm)						\
	.context = {							\
		.ctx_id = 1,						\
		.lock = __MUTEX_INITIALIZER(mm.context.lock),		\
	}

void leave_mm(int cpu);

#endif /* _ASM_X86_MMU_H */

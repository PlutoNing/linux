/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_PROCESSOR_FLAGS_H
#define _UAPI_ASM_X86_PROCESSOR_FLAGS_H
/* Various flags defined: can be included from assembler. */

#include <linux/const.h>

/*
 * EFLAGS bits
 标志寄存器的flag
 */
#define X86_EFLAGS_CF_BIT	0 
/* Carry Flag
*/
#define X86_EFLAGS_CF		_BITUL(X86_EFLAGS_CF_BIT)
#define X86_EFLAGS_FIXED_BIT	1 /* Bit 1 - always on */
#define X86_EFLAGS_FIXED	_BITUL(X86_EFLAGS_FIXED_BIT)
#define X86_EFLAGS_PF_BIT	2 /* Parity Flag */
#define X86_EFLAGS_PF		_BITUL(X86_EFLAGS_PF_BIT)
#define X86_EFLAGS_AF_BIT	4 /* Auxiliary carry Flag */
#define X86_EFLAGS_AF		_BITUL(X86_EFLAGS_AF_BIT)
#define X86_EFLAGS_ZF_BIT	6 /* Zero Flag */
#define X86_EFLAGS_ZF		_BITUL(X86_EFLAGS_ZF_BIT)
#define X86_EFLAGS_SF_BIT	7 /* Sign Flag */
#define X86_EFLAGS_SF		_BITUL(X86_EFLAGS_SF_BIT)
#define X86_EFLAGS_TF_BIT	8 /* Trap Flag */
#define X86_EFLAGS_TF		_BITUL(X86_EFLAGS_TF_BIT)
#define X86_EFLAGS_IF_BIT	9 /* Interrupt Flag */
#define X86_EFLAGS_IF		_BITUL(X86_EFLAGS_IF_BIT)
#define X86_EFLAGS_DF_BIT	10 
/* Direction Flag
方向标志。DF=0时，每次执行字符串指令后，源或目的地址指针用加法自动地修改地址；
DF=1时用减法修改地址。它用来控制地址的方向变化。
 */
#define X86_EFLAGS_DF		_BITUL(X86_EFLAGS_DF_BIT)
#define X86_EFLAGS_OF_BIT	11 /* Overflow Flag */
#define X86_EFLAGS_OF		_BITUL(X86_EFLAGS_OF_BIT)
#define X86_EFLAGS_IOPL_BIT	12 /* I/O Privilege Level (2 bits) */
#define X86_EFLAGS_IOPL		(_AC(3,UL) << X86_EFLAGS_IOPL_BIT)
#define X86_EFLAGS_NT_BIT	14 
/* Nested Task
Nested task flag (286+ only),
always 1 on 8086 and 186
 */
#define X86_EFLAGS_NT		_BITUL(X86_EFLAGS_NT_BIT)
#define X86_EFLAGS_RF_BIT	16 /* Resume Flag */
#define X86_EFLAGS_RF		_BITUL(X86_EFLAGS_RF_BIT)
#define X86_EFLAGS_VM_BIT	17 /* Virtual Mode */
#define X86_EFLAGS_VM		_BITUL(X86_EFLAGS_VM_BIT)
#define X86_EFLAGS_AC_BIT	18 /* Alignment Check/Access Control */
#define X86_EFLAGS_AC		_BITUL(X86_EFLAGS_AC_BIT)
#define X86_EFLAGS_VIF_BIT	19 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIF		_BITUL(X86_EFLAGS_VIF_BIT)
#define X86_EFLAGS_VIP_BIT	20 /* Virtual Interrupt Pending */
#define X86_EFLAGS_VIP		_BITUL(X86_EFLAGS_VIP_BIT)
#define X86_EFLAGS_ID_BIT	21 /* CPUID detection */
#define X86_EFLAGS_ID		_BITUL(X86_EFLAGS_ID_BIT)

/*
 * Basic CPU control in CR0
 CR0 寄存器中的位字段包含了各种系统和处理器状态的控制位
 */
#define X86_CR0_PE_BIT		0 
/* Protection Enable
表示是保护模式还是实模式
*/
#define X86_CR0_PE		_BITUL(X86_CR0_PE_BIT)
#define X86_CR0_MP_BIT		1 
/* Monitor Coprocessor 
当 MP = 1 时，处理器监视协处理器的使用情况，当发生对协处理器的操作时，会触发异常。
*/
#define X86_CR0_MP		_BITUL(X86_CR0_MP_BIT)
#define X86_CR0_EM_BIT		2 /* Emulation */
#define X86_CR0_EM		_BITUL(X86_CR0_EM_BIT)
#define X86_CR0_TS_BIT		3 /* Task Switched */
#define X86_CR0_TS		_BITUL(X86_CR0_TS_BIT)
#define X86_CR0_ET_BIT		4 /* Extension Type */
#define X86_CR0_ET		_BITUL(X86_CR0_ET_BIT)
#define X86_CR0_NE_BIT		5 /* Numeric Error */
#define X86_CR0_NE		_BITUL(X86_CR0_NE_BIT)
#define X86_CR0_WP_BIT		16 /* Write Protect */
#define X86_CR0_WP		_BITUL(X86_CR0_WP_BIT)
#define X86_CR0_AM_BIT		18 /* Alignment Mask */
#define X86_CR0_AM		_BITUL(X86_CR0_AM_BIT)
#define X86_CR0_NW_BIT		29 /* Not Write-through */
#define X86_CR0_NW		_BITUL(X86_CR0_NW_BIT)
#define X86_CR0_CD_BIT		30 /* Cache Disable */
#define X86_CR0_CD		_BITUL(X86_CR0_CD_BIT)
#define X86_CR0_PG_BIT		31 /* Paging */
#define X86_CR0_PG		_BITUL(X86_CR0_PG_BIT)

/*
 * Paging options in CR3
 * CR3 寄存器中的位字段包含了各种分页选项的控制位
 */
#define X86_CR3_PWT_BIT		3 /* Page Write Through */
#define X86_CR3_PWT		_BITUL(X86_CR3_PWT_BIT)
#define X86_CR3_PCD_BIT		4 /* Page Cache Disable */
#define X86_CR3_PCD		_BITUL(X86_CR3_PCD_BIT)

#define X86_CR3_PCID_BITS	12
#define X86_CR3_PCID_MASK	(_AC((1UL << X86_CR3_PCID_BITS) - 1, UL))

#define X86_CR3_LAM_U57_BIT	61 /* Activate LAM for userspace, 62:57 bits masked */
#define X86_CR3_LAM_U57		_BITULL(X86_CR3_LAM_U57_BIT)
#define X86_CR3_LAM_U48_BIT	62 /* Activate LAM for userspace, 62:48 bits masked */
#define X86_CR3_LAM_U48		_BITULL(X86_CR3_LAM_U48_BIT)
#define X86_CR3_PCID_NOFLUSH_BIT 63 /* Preserve old PCID */
#define X86_CR3_PCID_NOFLUSH    _BITULL(X86_CR3_PCID_NOFLUSH_BIT)

/*
 * Intel CPU features in CR4
 * CR4 寄存器中的位字段包含了各种处理器功能的控制位
 */
#define X86_CR4_VME_BIT		0 /* enable vm86 extensions */
#define X86_CR4_VME		_BITUL(X86_CR4_VME_BIT)
#define X86_CR4_PVI_BIT		1 /* virtual interrupts flag enable */
#define X86_CR4_PVI		_BITUL(X86_CR4_PVI_BIT)
#define X86_CR4_TSD_BIT		2 /* disable time stamp at ipl 3 */
#define X86_CR4_TSD		_BITUL(X86_CR4_TSD_BIT)
#define X86_CR4_DE_BIT		3 /* enable debugging extensions */
#define X86_CR4_DE		_BITUL(X86_CR4_DE_BIT)
#define X86_CR4_PSE_BIT		4 /* enable page size extensions */
#define X86_CR4_PSE		_BITUL(X86_CR4_PSE_BIT)
#define X86_CR4_PAE_BIT		5 /* enable physical address extensions */
#define X86_CR4_PAE		_BITUL(X86_CR4_PAE_BIT)
#define X86_CR4_MCE_BIT		6 /* Machine check enable */
#define X86_CR4_MCE		_BITUL(X86_CR4_MCE_BIT)
#define X86_CR4_PGE_BIT		7 /* enable global pages 全局页表项支持，允许 TLB 缓存全局页。*/
#define X86_CR4_PGE		_BITUL(X86_CR4_PGE_BIT)
#define X86_CR4_PCE_BIT		8 /* enable performance counters at ipl 3 */
#define X86_CR4_PCE		_BITUL(X86_CR4_PCE_BIT)
#define X86_CR4_OSFXSR_BIT	9 /* enable fast FPU save and restore */
#define X86_CR4_OSFXSR		_BITUL(X86_CR4_OSFXSR_BIT)
#define X86_CR4_OSXMMEXCPT_BIT	10 /* enable unmasked SSE exceptions */
#define X86_CR4_OSXMMEXCPT	_BITUL(X86_CR4_OSXMMEXCPT_BIT)
#define X86_CR4_UMIP_BIT	11 /* enable UMIP support */
#define X86_CR4_UMIP		_BITUL(X86_CR4_UMIP_BIT)
#define X86_CR4_LA57_BIT	12 /* enable 5-level page tables */
#define X86_CR4_LA57		_BITUL(X86_CR4_LA57_BIT)
#define X86_CR4_VMXE_BIT	13 /* enable VMX virtualization */
#define X86_CR4_VMXE		_BITUL(X86_CR4_VMXE_BIT)
#define X86_CR4_SMXE_BIT	14 /* enable safer mode (TXT) */
#define X86_CR4_SMXE		_BITUL(X86_CR4_SMXE_BIT)
#define X86_CR4_FSGSBASE_BIT	16 /* enable RDWRFSGS support */
#define X86_CR4_FSGSBASE	_BITUL(X86_CR4_FSGSBASE_BIT)
#define X86_CR4_PCIDE_BIT	17 /* enable PCID support */
#define X86_CR4_PCIDE		_BITUL(X86_CR4_PCIDE_BIT)
#define X86_CR4_OSXSAVE_BIT	18 /* enable xsave and xrestore */
#define X86_CR4_OSXSAVE		_BITUL(X86_CR4_OSXSAVE_BIT)
#define X86_CR4_SMEP_BIT	20 /* enable SMEP support */
#define X86_CR4_SMEP		_BITUL(X86_CR4_SMEP_BIT)
#define X86_CR4_SMAP_BIT	21 /* enable SMAP support */
#define X86_CR4_SMAP		_BITUL(X86_CR4_SMAP_BIT)
#define X86_CR4_PKE_BIT		22 /* enable Protection Keys support */
#define X86_CR4_PKE		_BITUL(X86_CR4_PKE_BIT)
#define X86_CR4_CET_BIT		23 /* enable Control-flow Enforcement Technology */
#define X86_CR4_CET		_BITUL(X86_CR4_CET_BIT)
#define X86_CR4_LAM_SUP_BIT	28 /* LAM for supervisor pointers */
#define X86_CR4_LAM_SUP		_BITUL(X86_CR4_LAM_SUP_BIT)

/*
 * x86-64 Task Priority Register, CR8
CR8-提供对任务优先级寄存器（Task Priority Register, TPR）的读写访问。它指定优先级值，
操作系统用于控制允许中断处理器的外部中断的优先级类别。此寄存器仅在 64 位模式下可用。
 任务优先级寄存器存储了当前任务的优先级级别。优先级级别是一个 0 到 15 的值，其中 0
 表示最高优先级，15 表示最低优先级。处理器使用该寄存器中的值来确定任务的调度顺序和优先级。
 */
#define X86_CR8_TPR		_AC(0x0000000f,UL) /* task priority register */

/*
 * AMD and Transmeta use MSRs for configuration; see <asm/msr-index.h>
 */

/*
 *      NSC/Cyrix CPU configuration register indexes
 */
#define CX86_PCR0	0x20
#define CX86_GCR	0xb8
#define CX86_CCR0	0xc0
#define CX86_CCR1	0xc1
#define CX86_CCR2	0xc2
#define CX86_CCR3	0xc3
#define CX86_CCR4	0xe8
#define CX86_CCR5	0xe9
#define CX86_CCR6	0xea
#define CX86_CCR7	0xeb
#define CX86_PCR1	0xf0
#define CX86_DIR0	0xfe
#define CX86_DIR1	0xff
#define CX86_ARR_BASE	0xc4
#define CX86_RCR_BASE	0xdc

#define CR0_STATE	(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | \
			 X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | \
			 X86_CR0_PG)

#endif /* _UAPI_ASM_X86_PROCESSOR_FLAGS_H */

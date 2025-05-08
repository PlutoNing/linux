/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2014  Steven Rostedt, Red Hat Inc
 */

#include <linux/cfi_types.h>
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/ptrace.h>
#include <asm/ftrace.h>
#include <asm/export.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>
#include <asm/frame.h>
/*定义或切换到名为 .text 的段（Section），并设置段属性为 
​​可分配（allocatable）​​ 和 ​​可执行（executable）​​。*/
	.code64
	.section .text, "ax"

#ifdef CONFIG_FRAME_POINTER
/* Save parent and function stack frames (rip and rbp) */
#  define MCOUNT_FRAME_SIZE	(8+16*2)
#else
/* No need to save a stack frame */
# define MCOUNT_FRAME_SIZE	0
#endif /* CONFIG_FRAME_POINTER */

/* Size of stack used to save mcount regs in save_mcount_regs */
#define MCOUNT_REG_SIZE		(FRAME_SIZE + MCOUNT_FRAME_SIZE)

/*
 * gcc -pg option adds a call to 'mcount' in most functions.
 * When -mfentry is used, the call is to 'fentry' and not 'mcount'
 * and is done before the function's stack frame is set up.
 * They both require a set of regs to be saved before calling
 * any C code and restored before returning back to the function.
 * 可以加中文注释吗？
 * On boot up, all these calls are converted into nops. When tracing
 * is enabled, the call can jump to either ftrace_caller or
 * ftrace_regs_caller. Callbacks (tracing functions) that require
 * ftrace_regs_caller (like kprobes) need to have pt_regs passed to
 * it. For this reason, the size of the pt_regs structure will be
 * allocated on the stack and the required mcount registers will
 * be saved in the locations that pt_regs has them in.
 */

/*
 * @added: the amount of stack added before calling this
 *
 * After this is called, the following registers contain:
 *
 *  %rdi - holds the address that called the trampoline
 *  %rsi - holds the parent function (traced function's return address)
 *  %rdx - holds the original %rbp
​
​​.macro​​：GNU 汇编器（GAS）的伪指令，用于定义一个 ​​汇编宏​​。
​​save_mcount_regs​​：宏的名称，通常用于保存 mcount（函数跟踪入口）执行前的寄存器状态。
​​added=0​​：宏的参数，表示调用此宏前栈上已额外分配的字节数（默认值为 0）。
 */
.macro save_mcount_regs added=0

	/*
	CONFIG_FRAME_POINTER是一个宏定义，用于启用或禁用函数调用栈帧指针的保存。
构建完整的栈帧链，确保堆栈回溯（stack trace）能正确通过 ftrace 跳板。
​​操作​​：
​​保存原始 rbp​​：将其压入栈中。
​​保存父函数地址​​：通过 added+8 * 2(%rsp) 计算父函数返回地址的位置（跳过已压入的 rbp 和调用跳板的返回地址）。
​​构建新栈帧​​：通过 movq %rsp, %rbp 更新 rbp，形成新的栈帧。
	 */ 
#ifdef CONFIG_FRAME_POINTER
	/* Save the original rbp */
	pushq %rbp

	/*
	 * Stack traces will stop at the ftrace trampoline if the frame pointer
	 * is not set up properly. If fentry is used, we need to save a frame
	 * pointer for the parent as well as the function traced, because the
	 * fentry is called before the stack frame is set up, where as mcount
	 * is called afterward.
	 */

	/* Save the parent pointer (skip orig rbp and our return address) */
	pushq \added+8*2(%rsp)
	pushq %rbp
	movq %rsp, %rbp
	/* Save the return address (now skip orig rbp, rbp and parent) */
	pushq \added+8*3(%rsp)
	pushq %rbp
	movq %rsp, %rbp
#endif /* CONFIG_FRAME_POINTER */

	/*
	 * We add enough stack to save all regs.
	 现在开始开辟栈空间， 保存所有寄存器
	 */
	subq $(FRAME_SIZE), %rsp
	movq %rax, RAX(%rsp)
	movq %rcx, RCX(%rsp)
	movq %rdx, RDX(%rsp)
	movq %rsi, RSI(%rsp)
	movq %rdi, RDI(%rsp)
	movq %r8, R8(%rsp)
	movq %r9, R9(%rsp)
	/*写入0*/
	movq $0, ORIG_RAX(%rsp)
	/*
	 * Save the original RBP. Even though the mcount ABI does not
	 * require this, it helps out callers.
	 保存被跟踪函数的原始 rbp，供后续恢复。
	 */

#ifdef CONFIG_FRAME_POINTER
	/* Save the original rbp
	从栈中回复原始rbp */
	movq MCOUNT_REG_SIZE-8(%rsp), %rdx
#else
	/* Save the original rbp ，直接使用rbp*/	
	movq %rbp, %rdx
#endif
	/* Save the original rbp，保存到栈中RBP的位置
	偏移是20 */
	movq %rdx, RBP(%rsp)

	/* Copy the parent address into %rsi (second parameter)
	把父地址加载到rsi
	 */
	movq MCOUNT_REG_SIZE+8+\added(%rsp), %rsi

	 /* Move RIP to its proper location
	 保存返回地址rip */
	movq MCOUNT_REG_SIZE+\added(%rsp), %rdi
	movq %rdi, RIP(%rsp)

	/*
	 * Now %rdi (the first parameter) has the return address of
	 * where ftrace_call returns. But the callbacks expect the
	 * address of the call itself.
	 这个SIZE是5
	 */
	subq $MCOUNT_INSN_SIZE, %rdi
	.endm

/*定义了一个宏 restore_mcount_regs，用于恢复寄存器的值。*/
.macro restore_mcount_regs save=0

	/* ftrace_regs_caller or frame pointers require this */
	movq RBP(%rsp), %rbp

	movq R9(%rsp), %r9
	movq R8(%rsp), %r8
	movq RDI(%rsp), %rdi
	movq RSI(%rsp), %rsi
	movq RDX(%rsp), %rdx
	movq RCX(%rsp), %rcx
	movq RAX(%rsp), %rax

	addq $MCOUNT_REG_SIZE-\save, %rsp

	.endm
/* 
定义了 Linux 内核中用于 ​​函数跟踪（ftrace）​​ 的桩函数（stub function）ftrace_stub，
其主要作用是在 ftrace 未启用或回调未注册时提供一个安全的默认处理逻辑。
=================================================
.globl ftrace_stub ; .balign 16, 0x90;; .skip 16, 0x90; ; ftrace_stub: endbr64
CALL_DEPTH_ACCOUNT
jmp __x86_return_thunk
.type ftrace_stub STT_FUNC ; .set .L__sym_size_ftrace_stub, .-ftrace_stub ; .size ftrace_stub, .L__sym_size_ftrace_stub
*/
SYM_TYPED_FUNC_START(ftrace_stub)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_TYPED_FUNC_START(ftrace_stub_graph)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub_graph)
#endif

#ifdef CONFIG_DYNAMIC_FTRACE
/* 定义了一个函数 __fentry__ */
SYM_FUNC_START(__fentry__)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(__fentry__)
EXPORT_SYMBOL(__fentry__)

/* 定义ftrace_caller函数 */
SYM_FUNC_START(ftrace_caller)
	/* save_mcount_regs fills in first two parameters
	保存寄存器 */
	save_mcount_regs

	CALL_DEPTH_ACCOUNT

	/* Stack - skipping return address of ftrace_caller
	展开为
	leaq (168 + 0)+8(%rsp), %rcx
 	movq %rcx, 152(%rsp)
	 */
	leaq MCOUNT_REG_SIZE+8(%rsp), %rcx
	movq %rcx, RSP(%rsp)
/*定义内部标签，用于内核符号链接。
	在汇编中，使用 SYM_INNER_LABEL 定义一个标签，并指定其类型为 SYM_L_GLOBAL。
	这通常用于定义全局符号，以便在其他文件中引用。
	*/
SYM_INNER_LABEL(ftrace_caller_op_ptr, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* Load the ftrace_ops into the 3rd parameter
	把全局变量function_trace_op的值加载到rdx寄存器中，作为第三个参数
	 */
	movq function_trace_op(%rip), %rdx

	/* regs go into 4th parameter
	rsp作为第四个参数传入
	 */
	leaq (%rsp), %rcx

	/* Only ops with REGS flag set should have CS register set
	清空CS寄存器
	 */
	movq $0, CS(%rsp)

	/* Account for the function call below */
	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_call, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* 调用桩函数 ftrace_stub（默认空操作）。内核启动时，
	此调用会被动态替换为实际的跟踪函数（如 function_trace_call）。*/
	call ftrace_stub

	/* Handlers can change the RIP
	将栈中保存的返回地址（RIP）更新到寄存器保存区域，
	允许跟踪函数修改返回地址（如动态跳转）。 */
	movq RIP(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	restore_mcount_regs

	/*
	 * The code up to this label is copied into trampolines so
	 * think twice before adding any new code or changing the
	 * layout here.
	 */
SYM_INNER_LABEL(ftrace_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET
SYM_FUNC_END(ftrace_caller);
STACK_FRAME_NON_STANDARD_FP(ftrace_caller)

/* 开始定义 ftrace_regs_caller 函数 */
SYM_FUNC_START(ftrace_regs_caller)
	/* Save the current flags before any operations that can change them */
	pushfq

	/* added 8 bytes to save flags */
	save_mcount_regs 8
	/* save_mcount_regs fills in first two parameters */

	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_regs_caller_op_ptr, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* Load the ftrace_ops into the 3rd parameter
	48 8b 15 a3 b1 a4 02    mov    0x2a4b1a3(%rip),%rdx
	 */
	movq function_trace_op(%rip), %rdx

	/* Save the rest of pt_regs */
	movq %r15, R15(%rsp)
	movq %r14, R14(%rsp)
	movq %r13, R13(%rsp)
	movq %r12, R12(%rsp)
	movq %r11, R11(%rsp)
	movq %r10, R10(%rsp)
	movq %rbx, RBX(%rsp)
	/* Copy saved flags */
	movq MCOUNT_REG_SIZE(%rsp), %rcx
	movq %rcx, EFLAGS(%rsp)
	/* Kernel segments */
	movq $__KERNEL_DS, %rcx
	movq %rcx, SS(%rsp)
	movq $__KERNEL_CS, %rcx
	movq %rcx, CS(%rsp)
	/* Stack - skipping return address and flags */
	leaq MCOUNT_REG_SIZE+8*2(%rsp), %rcx
	movq %rcx, RSP(%rsp)

	ENCODE_FRAME_POINTER

	/* regs go into 4th parameter */
	leaq (%rsp), %rcx

	/* Account for the function call below */
	CALL_DEPTH_ACCOUNT
/* 开始调用 ftrace_stub 函数 */
	
SYM_INNER_LABEL(ftrace_regs_call, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	call ftrace_stub

	/* Copy flags back to SS, to restore them */
	movq EFLAGS(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	/* Handlers can change the RIP */
	movq RIP(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE+8(%rsp)

	/* restore the rest of pt_regs */
	movq R15(%rsp), %r15
	movq R14(%rsp), %r14
	movq R13(%rsp), %r13
	movq R12(%rsp), %r12
	movq R10(%rsp), %r10
	movq RBX(%rsp), %rbx

	movq ORIG_RAX(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE-8(%rsp)

	/*
	 * If ORIG_RAX is anything but zero, make this a call to that.
	 * See arch_ftrace_set_direct_caller().
	 */
	testq	%rax, %rax

SYM_INNER_LABEL(ftrace_regs_caller_jmp, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jnz	1f

	restore_mcount_regs
	/* Restore flags */
	popfq

	/*
	 * The trampoline will add the return.
	 */
SYM_INNER_LABEL(ftrace_regs_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET

	/* Swap the flags with orig_rax */
1:	movq MCOUNT_REG_SIZE(%rsp), %rdi
	movq %rdi, MCOUNT_REG_SIZE-8(%rsp)
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	restore_mcount_regs 8
	/* Restore flags */
	popfq
	UNWIND_HINT_FUNC

	/*
	 * The above left an extra return value on the stack; effectively
	 * doing a tail-call without using a register. This PUSH;RET
	 * pattern unbalances the RSB, inject a pointless CALL to rebalance.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	CALL .Ldo_rebalance
	int3
.Ldo_rebalance:
	add $8, %rsp
	ALTERNATIVE __stringify(RET), \
		    __stringify(ANNOTATE_UNRET_SAFE; ret; int3), \
		    X86_FEATURE_CALL_DEPTH

SYM_FUNC_END(ftrace_regs_caller)
STACK_FRAME_NON_STANDARD_FP(ftrace_regs_caller)

SYM_FUNC_START(ftrace_stub_direct_tramp)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub_direct_tramp)

#else /* ! CONFIG_DYNAMIC_FTRACE */

SYM_FUNC_START(__fentry__)
	CALL_DEPTH_ACCOUNT

	cmpq $ftrace_stub, ftrace_trace_function
	jnz trace
	RET

trace:
	/* save_mcount_regs fills in first two parameters */
	save_mcount_regs

	/*
	 * When DYNAMIC_FTRACE is not defined, ARCH_SUPPORTS_FTRACE_OPS is not
	 * set (see include/asm/ftrace.h and include/linux/ftrace.h).  Only the
	 * ip and parent ip are used and the list function is called when
	 * function tracing is enabled.
	 */
	movq ftrace_trace_function, %r8
	CALL_NOSPEC r8
	restore_mcount_regs

	jmp ftrace_stub
SYM_FUNC_END(__fentry__)
EXPORT_SYMBOL(__fentry__)
STACK_FRAME_NON_STANDARD_FP(__fentry__)

#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_CODE_START(return_to_handler)
	UNWIND_HINT_UNDEFINED
	ANNOTATE_NOENDBR
	subq  $24, %rsp

	/* Save the return values */
	movq %rax, (%rsp)
	movq %rdx, 8(%rsp)
	movq %rbp, 16(%rsp)
	movq %rsp, %rdi

	call ftrace_return_to_handler

	movq %rax, %rdi
	movq 8(%rsp), %rdx
	movq (%rsp), %rax

	addq $24, %rsp
	/*
	 * Jump back to the old return address. This cannot be JMP_NOSPEC rdi
	 * since IBT would demand that contain ENDBR, which simply isn't so for
	 * return addresses. Use a retpoline here to keep the RSB balanced.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	call .Ldo_rop
	int3
.Ldo_rop:
	mov %rdi, (%rsp)
	ALTERNATIVE __stringify(RET), \
		    __stringify(ANNOTATE_UNRET_SAFE; ret; int3), \
		    X86_FEATURE_CALL_DEPTH
SYM_CODE_END(return_to_handler)
#endif

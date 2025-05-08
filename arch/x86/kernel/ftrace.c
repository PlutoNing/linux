// SPDX-License-Identifier: GPL-2.0
/*
 * Dynamic function tracing support.
 *
 * Copyright (C) 2007-2008 Steven Rostedt <srostedt@redhat.com>
 *
 * Thanks goes to Ingo Molnar, for suggesting the idea.
 * Mathieu Desnoyers, for suggesting postponing the modifications.
 * Arjan van de Ven, for keeping me straight, and explaining to me
 * the dangers of modifying code on the run.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/memory.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>

#include <trace/syscall.h>

#include <asm/kprobes.h>
#include <asm/ftrace.h>
#include <asm/nops.h>
#include <asm/text-patching.h>

#ifdef CONFIG_DYNAMIC_FTRACE

/*  */
static int ftrace_poke_late = 0;

void ftrace_arch_code_modify_prepare(void)
    __acquires(&text_mutex)
{
	/*
	 * Need to grab text_mutex to prevent a race from module loading
	 * and live kernel patching from changing the text permissions while
	 * ftrace has it set to "read/write".
	 */
	mutex_lock(&text_mutex);
	ftrace_poke_late = 1;
}

void ftrace_arch_code_modify_post_process(void)
    __releases(&text_mutex)
{
	/*
	 * ftrace_make_{call,nop}() may be called during
	 * module load, and we need to finish the text_poke_queue()
	 * that they do, here.
	 */
	text_poke_finish();
	ftrace_poke_late = 0;
	mutex_unlock(&text_mutex);
}

/* 返回一段表示nop的字节码 */
static const char *ftrace_nop_replace(void)
{
	return x86_nops[5];
}
/* 
@ip是ftrace函数的地址,
addr是新函数的地址.
cpu执行到ip时跳转到addr.
返回的是insn的text代码buf地址
========================
更新静态的insn结构体的opcode（call指令），disp（从ip跳到addr）成员，
然后返回他的text成员buff地址
*/
static const char *ftrace_call_replace(unsigned long ip, unsigned long addr)
{
	/*
	 * No need to translate into a callthunk. The trampoline does
	 * the depth accounting itself.
	 */
	return text_gen_insn(CALL_INSN_OPCODE, (void *)ip, (void *)addr);
}

/* 准备把ip处的字节码替换为别的字节码， 先检查一下现在的字节码是不是符合预期 */
static int ftrace_verify_code(unsigned long ip, const char *old_code)
{
	char cur_code[MCOUNT_INSN_SIZE];

	/*
	 * Note:
	 * We are paranoid about modifying text, as if a bug was to happen, it
	 * could cause us to read or write to someplace that could cause harm.
	 * Carefully read and modify the code with probe_kernel_*(), and make
	 * sure what we read is what we expected it to be before modifying it.
	 */
	/* read the text we want to modify */
	if (copy_from_kernel_nofault(cur_code, (void *)ip, MCOUNT_INSN_SIZE)) {
		WARN_ON(1);
		return -EFAULT;
	}
	/* 现在cur code是ip处现在的字节码 */
	/* Make sure it is what we expect it to be */
	if (memcmp(cur_code, old_code, MCOUNT_INSN_SIZE) != 0) {
		ftrace_expected = old_code;
		WARN_ON(1);
		return -EINVAL;
	}

	return 0;
}

/*
现在ip处的代码应该是old code，替换为new code
* Marked __ref because it calls text_poke_early() which is .init.text. That is
 * ok because that call will happen early, during boot, when .init sections are
 * still present.
 */
static int __ref
ftrace_modify_code_direct(unsigned long ip, const char *old_code,
			  const char *new_code)
{
	/* 看看ip处现在的字节码是不是old code */
	int ret = ftrace_verify_code(ip, old_code);
	if (ret)
		return ret;

	/* replace the text with the new text
	开始hook
	*/
	if (ftrace_poke_late)
	/* 把hook信息计入全局的tp vec数组，等待别人后续执行 */
		text_poke_queue((void *)ip, new_code, MCOUNT_INSN_SIZE, NULL);
	else
	/* 直接现在修改 */
		text_poke_early((void *)ip, new_code, MCOUNT_INSN_SIZE);
	return 0;
}

/* 停止trace这个函数 */
int ftrace_make_nop(struct module *mod, struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long ip = rec->ip;
	const char *new, *old;

	/* 生成call字节码 */
	old = ftrace_call_replace(ip, addr);
	/* 生成nop字节码 */
	new = ftrace_nop_replace();

	/*
	 * On boot up, and when modules are loaded, the MCOUNT_ADDR
	 * is converted to a nop, and will never become MCOUNT_ADDR
	 * again. This code is either running before SMP (on boot up)
	 * or before the code will ever be executed (module load).
	 * We do not want to use the breakpoint version in this case,
	 * just modify the code directly.
	 */
	if (addr == MCOUNT_ADDR)
		return ftrace_modify_code_direct(ip, old, new);

	/*
	 * x86 overrides ftrace_replace_code -- this function will never be used
	 * in this case.
	 */
	WARN_ONCE(1, "invalid use of ftrace_make_nop");
	return -EINVAL;
}

/* 开始trace这个函数
把rec->ip处的nop指令替换为call指令
addr是rec的ip对应要跳转的addr */
int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long ip = rec->ip;
	const char *new, *old;

	/* 生成插入的nop机器码 */
	old = ftrace_nop_replace();
	/* 生成call机器码 */
	new = ftrace_call_replace(ip, addr);

	/* Should only be called when module is loaded
	现在的ip处是nop指令，替换为call指令
	*/
	return ftrace_modify_code_direct(rec->ip, old, new);
}

/*
 * Should never be called:
 *  As it is only called by __ftrace_replace_code() which is called by
 *  ftrace_replace_code() that x86 overrides, and by ftrace_update_code()
 *  which is called to turn mcount into nops or nops into function calls
 *  but not to convert a function from not using regs to one that uses
 *  regs, which ftrace_modify_call() is for.
 */
int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
				 unsigned long addr)
{
	WARN_ON(1);
	return -EINVAL;
}
/* 把ftrace func更新为此func ... */
int ftrace_update_ftrace_func(ftrace_func_t func)
{
	unsigned long ip;
	const char *new;

	ip = (unsigned long)(&ftrace_call);
	/* 生成从ip跳到func的字节码，放在new */
	new = ftrace_call_replace(ip, (unsigned long)func);
	/* 
	好像这里才是开始poke代码 */
	text_poke_bp((void *)ip, new, MCOUNT_INSN_SIZE, NULL);

	ip = (unsigned long)(&ftrace_regs_call);
	new = ftrace_call_replace(ip, (unsigned long)func);
	text_poke_bp((void *)ip, new, MCOUNT_INSN_SIZE, NULL);

	return 0;
}

void ftrace_replace_code(int enable)
{
	struct ftrace_rec_iter *iter;
	struct dyn_ftrace *rec;
	const char *new, *old;
	int ret;

	for_ftrace_rec_iter(iter) {
		rec = ftrace_rec_iter_record(iter);

		switch (ftrace_test_record(rec, enable)) {
		case FTRACE_UPDATE_IGNORE:
		default:
			continue;

		case FTRACE_UPDATE_MAKE_CALL:
			old = ftrace_nop_replace();
			break;

		case FTRACE_UPDATE_MODIFY_CALL:
		case FTRACE_UPDATE_MAKE_NOP:
			old = ftrace_call_replace(rec->ip, ftrace_get_addr_curr(rec));
			break;
		}

		ret = ftrace_verify_code(rec->ip, old);
		if (ret) {
			ftrace_expected = old;
			ftrace_bug(ret, rec);
			ftrace_expected = NULL;
			return;
		}
	}

	for_ftrace_rec_iter(iter) {
		rec = ftrace_rec_iter_record(iter);

		switch (ftrace_test_record(rec, enable)) {
		case FTRACE_UPDATE_IGNORE:
		default:
			continue;

		case FTRACE_UPDATE_MAKE_CALL:
		case FTRACE_UPDATE_MODIFY_CALL:
			new = ftrace_call_replace(rec->ip, ftrace_get_addr_new(rec));
			break;

		case FTRACE_UPDATE_MAKE_NOP:
			new = ftrace_nop_replace();
			break;
		}

		text_poke_queue((void *)rec->ip, new, MCOUNT_INSN_SIZE, NULL);
		ftrace_update_record(rec, enable);
	}
	text_poke_finish();
}

void arch_ftrace_update_code(int command)
{
	ftrace_modify_all_code(command);
}

/* Currently only x86_64 supports dynamic trampolines */
#ifdef CONFIG_X86_64

#ifdef CONFIG_MODULES
#include <linux/moduleloader.h>
/* Module allocation simplifies allocating memory for code */
static inline void *alloc_tramp(unsigned long size)
{
	return module_alloc(size);
}
static inline void tramp_free(void *tramp)
{
	module_memfree(tramp);
}
#else
/* Trampolines can only be created if modules are supported */
static inline void *alloc_tramp(unsigned long size)
{
	return NULL;
}
static inline void tramp_free(void *tramp) { }
#endif

/* Defined as markers to the end of the ftrace default trampolines */
extern void ftrace_regs_caller_end(void);
extern void ftrace_caller_end(void);
extern void ftrace_caller_op_ptr(void);
extern void ftrace_regs_caller_op_ptr(void);
extern void ftrace_regs_caller_jmp(void);

/* movq function_trace_op(%rip), %rdx */
/* 0x48 0x8b 0x15 <offset-to-ftrace_trace_op (4 bytes)> */
/* 
这里就是下面语句的反汇编
SYM_INNER_LABEL(ftrace_regs_caller_op_ptr, SYM_L_GLOBAL)
        ANNOTATE_NOENDBR
        Load the ftrace_ops into the 3rd parameter 
        movq function_trace_op(%rip), %rdx
ffffffff81113616:       48 8b 15 a3 b1 a4 02    mov    0x2a4b1a3(%rip),%rdx        # ffffffff83b5e7c0 <function_trace_op>
*/
#define OP_REF_SIZE	7

/*
 * The ftrace_ops is passed to the function callback. Since the
 * trampoline only services a single ftrace_ops, we can pass in
 * that ops directly.
 *
 * The ftrace_op_code_union is used to create a pointer to the
 * ftrace_ops that will be passed to the callback function.
 */
union ftrace_op_code_union {
	char code[OP_REF_SIZE];
	struct {
		char op[3];
		int offset;
	} __attribute__((packed));
};

/* 一般是5 */
#define RET_SIZE		(IS_ENABLED(CONFIG_RETPOLINE) ? 5 : 1 + IS_ENABLED(CONFIG_SLS))

/* 创建ops的跳板
跳板就是一块内存区域，对其进行poke
会跳转到ops->func
*/
static unsigned long
create_trampoline(struct ftrace_ops *ops, unsigned int *tramp_size)
{
	unsigned long start_offset;
	unsigned long end_offset;
	unsigned long op_offset;
	unsigned long call_offset;
	unsigned long jmp_offset;
	unsigned long offset;
	unsigned long npages;
	unsigned long size;
	unsigned long *ptr;
	void *trampoline;
	void *ip, *dest;
	/* 48 8b 15 <offset> is movq <offset>(%rip), %rdx */
	unsigned const char op_ref[] = { 0x48, 0x8b, 0x15 };
	/* retq是C3 CC */
	unsigned const char retq[] = { RET_INSN_OPCODE, INT3_INSN_OPCODE };
	union ftrace_op_code_union op_ptr;
	int ret;
/* 
$ nm -n vmlinux | grep "ftrace_regs"
ffffffff811135a0 T __pfx_ftrace_regs_caller
ffffffff811135b0 T ftrace_regs_caller
ffffffff81113616 T ftrace_regs_caller_op_ptr
ffffffff8111368b T ftrace_regs_call
ffffffff811136dd T ftrace_regs_caller_jmp
ffffffff8111370f T ftrace_regs_caller_end
*/
	if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
		start_offset = (unsigned long)ftrace_regs_caller;
		end_offset = (unsigned long)ftrace_regs_caller_end;
		op_offset = (unsigned long)ftrace_regs_caller_op_ptr;
		call_offset = (unsigned long)ftrace_regs_call;
		jmp_offset = (unsigned long)ftrace_regs_caller_jmp;
	} else {
		start_offset = (unsigned long)ftrace_caller;
		end_offset = (unsigned long)ftrace_caller_end;
		op_offset = (unsigned long)ftrace_caller_op_ptr;
		call_offset = (unsigned long)ftrace_call;
		jmp_offset = 0;
	}
/* 
paulning@laptop:~/study/linux$ nm -n vmlinux | grep "ftrace_regs"
ffffffff811135a0 T __pfx_ftrace_regs_caller
ffffffff811135b0 T ftrace_regs_caller
ffffffff81113616 T ftrace_regs_caller_op_ptr
ffffffff8111368b T ftrace_regs_call
ffffffff811136dd T ftrace_regs_caller_jmp
ffffffff8111370f T ftrace_regs_caller_end
*/
	size = end_offset - start_offset;

	/*
	 * Allocate enough size to store the ftrace_caller code,
	 * the iret , as well as the address of the ftrace_ops this
	 * trampoline is used for.
	 分配足够的内存来存储ftrace_caller代码，
	 * iret指令，以及这个跳板所使用的ftrace_ops的地址。
	 */
	trampoline = alloc_tramp(size + RET_SIZE + sizeof(void *));
	if (!trampoline)
		return 0;

	*tramp_size = size + RET_SIZE + sizeof(void *);
	npages = DIV_ROUND_UP(*tramp_size, PAGE_SIZE);

	/* Copy ftrace_caller onto the trampoline memory
	把ftrace_caller开始的一些二进制代码拷贝到trampoline内存中
	*/
	ret = copy_from_kernel_nofault(trampoline, (void *)start_offset, size);
	if (WARN_ON(ret < 0))
		goto fail;

	ip = trampoline + size;
	/* 
	接下来在ip处生成从ip跳转到x86_return_thunk的机器码，或者直接就是ret的机器码
	反正就是从ip地址处是ret作用的机器码
	​​if的目的​​：根据 CPU 是否支持 X86_FEATURE_RETHUNK，动态替换返回指令（retq）为安全版本。
​​		支持 RETHUNK​​：生成跳转到 x86_return_thunk 的指令。
​​		不支持 RETHUNK​​：直接使用原生 retq 指令。
	*/
	if (cpu_feature_enabled(X86_FEATURE_RETHUNK))
		__text_gen_insn(ip, JMP32_INSN_OPCODE, ip, x86_return_thunk, JMP32_INSN_SIZE);
	else
	/*  */
		memcpy(ip, retq, sizeof(retq));

	/* No need to test direct calls on created trampolines */
	if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
		/* NOP the jnz 1f; but make sure it's a 2 byte jnz */
		/* 现在trampoline是ftrace caller regs的一系列二进制代码
		这里让ip指向其中ftrace_regs_caller_jmp部分的指针 */
		ip = trampoline + (jmp_offset - start_offset);
		/* 
ffffffff811136dd <ftrace_regs_caller_jmp>:
ffffffff811136dd:       75 35                   jne    ffffffff81113714 <ftrace_regs_caller_end+0x5>
ffffffff811136df:       48 8b 6c 24 20          mov    0x20(%rsp),%rbp
ffffffff811136e4:       4c 8b 4c 24 40          mov    0x40(%rsp),%r9 
ftrace_regs_caller_jmp这个地方的第一个机器码应该是75，不是的话就是异常
*/
		if (WARN_ON(*(char *)ip != 0x75))
			goto fail;
		/* 把nop的机器码拷到这里 */
		ret = copy_from_kernel_nofault(ip, x86_nops[2], 2);
		if (ret < 0)
			goto fail;
	}

	/*
	 * The address of the ftrace_ops that is used for this trampoline
	 * is stored at the end of the trampoline. This will be used to
	 * load the third parameter for the callback. Basically, that
	 * location at the end of the trampoline takes the place of
	 * the global function_trace_op variable.
	 */

	ptr = (unsigned long *)(trampoline + size + RET_SIZE);
	*ptr = (unsigned long)ops;

	op_offset -= start_offset;
	/* 这里的from就是ftrace_64.S中如下语句的反汇编
	SYM_INNER_LABEL(ftrace_regs_caller_op_ptr, SYM_L_GLOBAL)
        ANNOTATE_NOENDBR
        Load the ftrace_ops into the 3rd parameter
        movq function_trace_op(%rip), %rdx
		ffffffff81113616:       48 8b 15 a3 b1 a4 02    mov    0x2a4b1a3(%rip),%rdx        # ffffffff83b5e7c0 <function_trace_op>
	 */
	/* 拷贝48 8b 15 a3 b1 a4 02七个字节到op ptr结构体 */
	memcpy(&op_ptr, trampoline + op_offset, OP_REF_SIZE);

	/* Are we pointing to the reference? */
	if (WARN_ON(memcmp(op_ptr.op, op_ref, 3) != 0))
		goto fail;

	/* Load the contents of ptr into the callback parameter */
	offset = (unsigned long)ptr;
	offset -= (unsigned long)trampoline + op_offset + OP_REF_SIZE;
	/* 
	现在trampoline开始的地方就是一系列函数
ffffffff811135b0 T ftrace_regs_caller
ffffffff81113616 T ftrace_regs_caller_op_ptr
ffffffff8111368b T ftrace_regs_call
ffffffff811136dd T ftrace_regs_caller_jmp
ffffffff8111370f T ftrace_regs_caller_end的字节码
在后面紧跟的是ftrace ops的地址
	*/
	/* 
	现在offset就是ftrace_regs_caller_op_ptr到ops的距离
	*/
	op_ptr.offset = offset;

	/* put in the new offset to the ftrace_ops
	这里的to就是trampoline字节码区域里面ftrace_regs_caller_op_ptr的地址
	修改ftrace_regs_caller_op_ptr的开头的movq function_trace_op(%rip), %rdx的语句
	语句的字节码如下48 8b 15 a3 b1 a4 02    mov    0x2a4b1a3(%rip),%rdx
	把其中的a3 b1 a4 02替换为新的地址
	*/
	memcpy(trampoline + op_offset, &op_ptr, OP_REF_SIZE);

	/* put in the call to the function */
	mutex_lock(&text_mutex);
	/* 
ffffffff8111368b T ftrace_regs_call 减去	ffffffff811135b0 T ftrace_regs_caller
其实现在call_offset就是ftrace_regs_call函数在trampoline内存中的相对偏移
ftrace_regs_call函数开头的部分字节码如下
SYM_INNER_LABEL(ftrace_regs_call, SYM_L_GLOBAL)
        ANNOTATE_NOENDBR
        call ftrace_stub
ffffffff8111368b:       e8 a0 fd ff ff          call   ffffffff81113430 <ftrace_stub>*/
	call_offset -= start_offset;
	/*
	 * No need to translate into a callthunk. The trampoline does
	 * the depth accounting before the call already.
	 */
	dest = ftrace_ops_get_func(ops);
	/* 
	所以现在trampoline + call_offset就是ftrace_regs_call函数的地址，指向e8 a0 fd ff ff这一块
	现在text_gen_insn函数的作用就是生成五个字节的从当前地址（trampoline + call_offset）跳转到
	ops的func函数（dest）的机器码
	然后memcpy把这个机器码拷贝到trampoline + call_offset处，完成hook
	*/
	memcpy(trampoline + call_offset,
	       text_gen_insn(CALL_INSN_OPCODE, trampoline + call_offset, dest),
	       CALL_INSN_SIZE);
	mutex_unlock(&text_mutex);

	/* ALLOC_TRAMP flags lets us know we created it */
	ops->flags |= FTRACE_OPS_FL_ALLOC_TRAMP;

	/* 设置这个trampoline的内存为可读可执行 */
	set_memory_rox((unsigned long)trampoline, npages);
	return (unsigned long)trampoline;
fail:
	tramp_free(trampoline);
	return 0;
}

void set_ftrace_ops_ro(void)
{
	struct ftrace_ops *ops;
	unsigned long start_offset;
	unsigned long end_offset;
	unsigned long npages;
	unsigned long size;

	do_for_each_ftrace_op(ops, ftrace_ops_list) {
		if (!(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
			continue;

		if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
			start_offset = (unsigned long)ftrace_regs_caller;
			end_offset = (unsigned long)ftrace_regs_caller_end;
		} else {
			start_offset = (unsigned long)ftrace_caller;
			end_offset = (unsigned long)ftrace_caller_end;
		}
		size = end_offset - start_offset;
		size = size + RET_SIZE + sizeof(void *);
		npages = DIV_ROUND_UP(size, PAGE_SIZE);
		set_memory_ro((unsigned long)ops->trampoline, npages);
	} while_for_each_ftrace_op(ops);
}

/* 计算ftrace_ops的跳板内存区域的开头到call指令的偏移量
paulning@laptop:~/study/linux$ nm -n vmlinux | grep "ftrace_regs"
ffffffff811135a0 T __pfx_ftrace_regs_caller
ffffffff811135b0 T ftrace_regs_caller
ffffffff81113616 T ftrace_regs_caller_op_ptr
ffffffff8111368b T ftrace_regs_call
ffffffff811136dd T ftrace_regs_caller_jmp
ffffffff8111370f T ftrace_regs_caller_end
就是call标签函数到caller函数起始处的offset
 */
static unsigned long calc_trampoline_call_offset(bool save_regs)
{
	unsigned long start_offset;
	unsigned long call_offset;

	/* 根据是否保存寄存器来选择不同的ftrace caller
	 */
	if (save_regs) {
		start_offset = (unsigned long)ftrace_regs_caller;
		call_offset = (unsigned long)ftrace_regs_call;
	} else {
		start_offset = (unsigned long)ftrace_caller;
		call_offset = (unsigned long)ftrace_call;
	}

	return call_offset - start_offset;
}

/* 更新ops的跳板
跳转到当前的func */
void arch_ftrace_update_trampoline(struct ftrace_ops *ops)
{
	ftrace_func_t func;
	unsigned long offset;
	unsigned long ip;
	unsigned int size;
	const char *new;

	if (!ops->trampoline) {
		/* 创建跳板， 跳转到ops->func */
		ops->trampoline = create_trampoline(ops, &size);
		if (!ops->trampoline)
			return;
		ops->trampoline_size = size;
		return;
	}

	/*
	 * The ftrace_ops caller may set up its own trampoline.
	 * In such a case, this code must not modify it.
	 */
	/* 如果还没有跳板，就无需更新的概念
	 */
	if (!(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return;

	/* 计算ftrace call代码在跳板代码段的offset */
	offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
	/* ip指向的就是跳板区域的call指令附近 */
	ip = ops->trampoline + offset;
	/* 基本就是ops->func */
	func = ftrace_ops_get_func(ops);

	mutex_lock(&text_mutex);
	/* Do a safe modify in case the trampoline is executing */
	/* 生成五个字节的从ip跳转到func的机器码，放在new */
	new = ftrace_call_replace(ip, (unsigned long)func);
	/* 把new里面的新机器码放到ip处，完成hook，以后跳转到新位置 */
	text_poke_bp((void *)ip, new, MCOUNT_INSN_SIZE, NULL);
	mutex_unlock(&text_mutex);
}

/* Return the address of the function the trampoline calls */
static void *addr_from_call(void *ptr)
{
	union text_poke_insn call;
	int ret;

	ret = copy_from_kernel_nofault(&call, ptr, CALL_INSN_SIZE);
	if (WARN_ON_ONCE(ret < 0))
		return NULL;

	/* Make sure this is a call */
	if (WARN_ON_ONCE(call.opcode != CALL_INSN_OPCODE)) {
		pr_warn("Expected E8, got %x\n", call.opcode);
		return NULL;
	}

	return ptr + CALL_INSN_SIZE + call.disp;
}

/*
 * If the ops->trampoline was not allocated, then it probably
 * has a static trampoline func, or is the ftrace caller itself.
 */
static void *static_tramp_func(struct ftrace_ops *ops, struct dyn_ftrace *rec)
{
	unsigned long offset;
	bool save_regs = rec->flags & FTRACE_FL_REGS_EN;
	void *ptr;

	if (ops && ops->trampoline) {
#if !defined(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS) && \
	defined(CONFIG_FUNCTION_GRAPH_TRACER)
		/*
		 * We only know about function graph tracer setting as static
		 * trampoline.
		 */
		if (ops->trampoline == FTRACE_GRAPH_ADDR)
			return (void *)prepare_ftrace_return;
#endif
		return NULL;
	}

	offset = calc_trampoline_call_offset(save_regs);

	if (save_regs)
		ptr = (void *)FTRACE_REGS_ADDR + offset;
	else
		ptr = (void *)FTRACE_ADDR + offset;

	return addr_from_call(ptr);
}

void *arch_ftrace_trampoline_func(struct ftrace_ops *ops, struct dyn_ftrace *rec)
{
	unsigned long offset;

	/* If we didn't allocate this trampoline, consider it static */
	if (!ops || !(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return static_tramp_func(ops, rec);

	offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
	return addr_from_call((void *)ops->trampoline + offset);
}

void arch_ftrace_trampoline_free(struct ftrace_ops *ops)
{
	if (!ops || !(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return;

	tramp_free((void *)ops->trampoline);
	ops->trampoline = 0;
}

#endif /* CONFIG_X86_64 */
#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

#if defined(CONFIG_DYNAMIC_FTRACE) && !defined(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS)
extern void ftrace_graph_call(void);
static const char *ftrace_jmp_replace(unsigned long ip, unsigned long addr)
{
	return text_gen_insn(JMP32_INSN_OPCODE, (void *)ip, (void *)addr);
}

static int ftrace_mod_jmp(unsigned long ip, void *func)
{
	const char *new;

	new = ftrace_jmp_replace(ip, (unsigned long)func);
	text_poke_bp((void *)ip, new, MCOUNT_INSN_SIZE, NULL);
	return 0;
}

int ftrace_enable_ftrace_graph_caller(void)
{
	unsigned long ip = (unsigned long)(&ftrace_graph_call);

	return ftrace_mod_jmp(ip, &ftrace_graph_caller);
}

int ftrace_disable_ftrace_graph_caller(void)
{
	unsigned long ip = (unsigned long)(&ftrace_graph_call);

	return ftrace_mod_jmp(ip, &ftrace_stub);
}
#endif /* CONFIG_DYNAMIC_FTRACE && !CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS */

/*
 * Hook the return address and push it in the stack of return addrs
 * in current thread info.
 */
void prepare_ftrace_return(unsigned long ip, unsigned long *parent,
			   unsigned long frame_pointer)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	int bit;

	/*
	 * When resuming from suspend-to-ram, this function can be indirectly
	 * called from early CPU startup code while the CPU is in real mode,
	 * which would fail miserably.  Make sure the stack pointer is a
	 * virtual address.
	 *
	 * This check isn't as accurate as virt_addr_valid(), but it should be
	 * good enough for this purpose, and it's fast.
	 */
	if (unlikely((long)__builtin_frame_address(0) >= 0))
		return;

	if (unlikely(ftrace_graph_is_dead()))
		return;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	bit = ftrace_test_recursion_trylock(ip, *parent);
	if (bit < 0)
		return;

	if (!function_graph_enter(*parent, ip, frame_pointer, parent))
		*parent = return_hooker;

	ftrace_test_recursion_unlock(bit);
}

#ifdef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = &fregs->regs;
	unsigned long *stack = (unsigned long *)kernel_stack_pointer(regs);

	prepare_ftrace_return(ip, (unsigned long *)stack, 0);
}
#endif

#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

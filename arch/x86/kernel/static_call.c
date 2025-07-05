// SPDX-License-Identifier: GPL-2.0
#include <linux/static_call.h>
#include <linux/memory.h>
#include <linux/bug.h>
#include <asm/text-patching.h>

enum insn_type {
	CALL = 0, /* site call */
	NOP = 1,  /* site cond-call */
	JMP = 2,  /* tramp / site tail-call */
	RET = 3,  /* tramp / site cond-tail-call */
	JCC = 4,
};

/*打印如下 0xffffffff82a18475 <tramp_ud>:	ud1    ecx,esp
 * ud1 %esp, %ecx - a 3 byte #UD that is unique to trampolines, chosen such
 * that there is no false-positive trampoline identification while also being a
 * speculation stop.
 */
static const u8 tramp_ud[] = { 0x0f, 0xb9, 0xcc };

/*
 * cs cs cs xorl %eax, %eax - a single 5 byte instruction that clears %[er]ax
 */
static const u8 xor5rax[] = { 0x2e, 0x2e, 0x2e, 0x31, 0xc0 };

static const u8 retinsn[] = { RET_INSN_OPCODE, 0xcc, 0xcc, 0xcc, 0xcc };

static u8 __is_Jcc(u8 *insn) /* Jcc.d32 */
{
	u8 ret = 0;

	if (insn[0] == 0x0f) {
		u8 tmp = insn[1];
		if ((tmp & 0xf0) == 0x80)
			ret = tmp;
	}

	return ret;
}

extern void __static_call_return(void);

asm (".global __static_call_return\n\t"
     ".type __static_call_return, @function\n\t"
     ASM_FUNC_ALIGN "\n\t"
     "__static_call_return:\n\t"
     ANNOTATE_NOENDBR
     ANNOTATE_RETPOLINE_SAFE
     "ret; int3\n\t"
     ".size __static_call_return, . - __static_call_return \n\t");
/* tp->static_call_tramp是被修改的tp的东西,func一般来说func就是刚刚添加的probe.  修改tramp为func. 通过插入指令从addr跳到func？type决定插入什么指令？ */
static void __ref __static_call_transform(void *insn, enum insn_type type,
					  void *func, bool modinit)
{
	const void *emulate = NULL;
	int size = CALL_INSN_SIZE;
	const void *code;
	u8 op, buf[6];

	if ((type == JMP || type == RET) && (op = __is_Jcc(insn)))
		type = JCC;

	switch (type) {
	case CALL:
		func = callthunks_translate_call_dest(func);
		code = text_gen_insn(CALL_INSN_OPCODE, insn, func);
		if (func == &__static_call_return0) {
			emulate = code;
			code = &xor5rax;
		}

		break;

	case NOP:
		code = x86_nops[5];
		break;

	case JMP: /* 修改指令， 跳转 */
		code = text_gen_insn(JMP32_INSN_OPCODE, insn, func);
		break; /* x/1i code : 
0xffffffff85d8fa84 <insn.1>:	jmp    0xffffffff84873344 <______f.721+20> */
	case RET:
		if (cpu_feature_enabled(X86_FEATURE_RETHUNK))
			code = text_gen_insn(JMP32_INSN_OPCODE, insn, x86_return_thunk);
		else
			code = &retinsn;
		break;

	case JCC:
		if (!func) {
			func = __static_call_return;
			if (cpu_feature_enabled(X86_FEATURE_RETHUNK))
				func = x86_return_thunk;
		}

		buf[0] = 0x0f;
		__text_gen_insn(buf+1, op, insn+1, func, 5);
		code = buf;
		size = 6;

		break;
	}
	/* x/1i code	jmp    0xffffffff84873344 <______f.721+20> x/1i insn 	jmp    0xffffffff81125370 <__traceiter_sched_wakeup> */
	if (memcmp(insn, code, size) == 0)
		return;/* 如果这个时候修改好了？ 就返回 */

	if (system_state == SYSTEM_BOOTING || modinit)/* 如果在boot时期,使用early poke */
		return text_poke_early(insn, code, size);
	/* 现在开始修改insn处的代码为code */
	text_poke_bp(insn, code, size, emulate);
}
/* insn是tp->static_call_tramp是被修改的tp的东西, 修改前进行校验 */
static void __static_call_validate(u8 *insn, bool tail, bool tramp)
{ /* 一种情况: insn的前8个字节,jmp    0xffffffff81125370 <__traceiter_sched_wakeup> ; ud1    ecx,esp */
	u8 opcode = insn[0];
	/* -exec x/3i tramp_ud : 0xffffffff82a18475 <tramp_ud>:	ud1    ecx,esp */
	if (tramp && memcmp(insn+5, tramp_ud, 3)) {/* -exec x/10i insn retint3 nop nop nop   	ud1    ecx,esp */
		pr_err("trampoline signature fail");
		BUG();
	}

	if (tail) {
		if (opcode == JMP32_INSN_OPCODE ||
		    opcode == RET_INSN_OPCODE ||
		    __is_Jcc(insn))
			return;
	} else {
		if (opcode == CALL_INSN_OPCODE ||
		    !memcmp(insn, x86_nops[5], 5) ||
		    !memcmp(insn, xor5rax, 5))
			return;
	}

	/*
	 * If we ever trigger this, our text is corrupt, we'll probably not live long.
	 */
	pr_err("unexpected static_call insn opcode 0x%x at %pS\n", opcode, insn);
	BUG();
}
/* 进行一个简单的编码 */
static inline enum insn_type __sc_insn(bool null, bool tail)
{
	/*
	 * Encode the following table without branches:
	 *
	 *	tail	null	insn
	 *	-----+-------+------
	 *	  0  |   0   |  CALL
	 *	  0  |   1   |  NOP
	 *	  1  |   0   |  JMP
	 *	  1  |   1   |  RET
	 */
	return 2*tail + null;
}
/*tp->static_call_tramp是被修改的tp的东西,func一般来说func就是刚刚添加的probe.  修改tramp为func */
void arch_static_call_transform(void *site, void *tramp, void *func, bool tail)
{
	mutex_lock(&text_mutex);

	if (tramp) {
		__static_call_validate(tramp, true, true);/* 校验tramp的字节码是否符合预期 */
		__static_call_transform(tramp, __sc_insn(!func, true), func, false);
	}

	if (IS_ENABLED(CONFIG_HAVE_STATIC_CALL_INLINE) && site) {/* static call的分支 */
		__static_call_validate(site, tail, false);
		__static_call_transform(site, __sc_insn(!func, tail), func, false);
	}

	mutex_unlock(&text_mutex);
}
EXPORT_SYMBOL_GPL(arch_static_call_transform);

#ifdef CONFIG_RETHUNK
/*
 * This is called by apply_returns() to fix up static call trampolines,
 * specifically ARCH_DEFINE_STATIC_CALL_NULL_TRAMP which is recorded as
 * having a return trampoline.
 *
 * The problem is that static_call() is available before determining
 * X86_FEATURE_RETHUNK and, by implication, running alternatives.
 *
 * This means that __static_call_transform() above can have overwritten the
 * return trampoline and we now need to fix things up to be consistent.
 */
bool __static_call_fixup(void *tramp, u8 op, void *dest)
{
	unsigned long addr = (unsigned long)tramp;
	/*
	 * Not all .return_sites are a static_call trampoline (most are not).
	 * Check if the 3 bytes after the return are still kernel text, if not,
	 * then this definitely is not a trampoline and we need not worry
	 * further.
	 *
	 * This avoids the memcmp() below tripping over pagefaults etc..
	 */
	if (((addr >> PAGE_SHIFT) != ((addr + 7) >> PAGE_SHIFT)) &&
	    !kernel_text_address(addr + 7))
		return false;

	if (memcmp(tramp+5, tramp_ud, 3)) {
		/* Not a trampoline site, not our problem. */
		return false;
	}

	mutex_lock(&text_mutex);
	if (op == RET_INSN_OPCODE || dest == &__x86_return_thunk)
		__static_call_transform(tramp, RET, NULL, true);
	mutex_unlock(&text_mutex);

	return true;
}
#endif

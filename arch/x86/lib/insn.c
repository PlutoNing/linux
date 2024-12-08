// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * x86 instruction analysis
 *
 * Copyright (C) IBM Corporation, 2002, 2004, 2009
 */

#include <linux/kernel.h>
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif
#include <asm/inat.h> /*__ignore_sync_check__ */
#include <asm/insn.h> /* __ignore_sync_check__ */
#include <asm/unaligned.h> /* __ignore_sync_check__ */

#include <linux/errno.h>
#include <linux/kconfig.h>

#include <asm/emulate_prefix.h> /* __ignore_sync_check__ */
/* 主要用于将小端字节序（little-endian）转换为 CPU 的本地字节序 */
#define leXX_to_cpu(t, r)						\
({									\
	__typeof__(t) v;						\
	switch (sizeof(t)) {						\
	case 4: v = le32_to_cpu(r); break;				\
	case 2: v = le16_to_cpu(r); break;				\
	case 1:	v = r; break;						\
	default:							\
		BUILD_BUG(); break;					\
	}								\
	v;								\
})

/* Verify next sizeof(t) bytes can be on the same instruction */
#define validate_next(t, insn, n)	\
	((insn)->next_byte + sizeof(t) + n <= (insn)->end_kaddr)

#define __get_next(t, insn)	\
	({ t r = get_unaligned((t *)(insn)->next_byte); (insn)->next_byte += sizeof(t); leXX_to_cpu(t, r); })
/* 获得insn的nth的byte, type是t. */
#define __peek_nbyte_next(t, insn, n)	\
	({ t r = get_unaligned((t *)(insn)->next_byte + n); leXX_to_cpu(t, r); })

#define get_next(t, insn)	\
	({ if (unlikely(!validate_next(t, insn, 0))) goto err_out; __get_next(t, insn); })
/* 获得insn的nth的byte, type是t.  */
#define peek_nbyte_next(t, insn, n)	\
	({ if (unlikely(!validate_next(t, insn, n))) goto err_out; __peek_nbyte_next(t, insn, n); })
/* 获取第一个指令 */
#define peek_next(t, insn)	peek_nbyte_next(t, insn, 0)

/**
初始化insn ...
ftrace的时候, insn是新结构体, kaddr是opcode(另外一个静态insn的text)
 * insn_init() - initialize struct insn
 * @insn:	&struct insn to be initialized
 * @kaddr:	address (in kernel memory) of instruction (or copy thereof)
 * @buf_len:	length of the insn buffer at @kaddr
 * @x86_64:	!0 for 64-bit kernel or 64-bit app
 */
void insn_init(struct insn *insn, const void *kaddr, int buf_len, int x86_64)
{
	/*
	 * Instructions longer than MAX_INSN_SIZE (15 bytes) are invalid
	 * even if the input buffer is long enough to hold them.
	 */
	if (buf_len > MAX_INSN_SIZE)
		buf_len = MAX_INSN_SIZE;

	memset(insn, 0, sizeof(*insn));
	insn->kaddr = kaddr;
	insn->end_kaddr = kaddr + buf_len;
	insn->next_byte = kaddr;

	insn->x86_64 = x86_64 ? 1 : 0;
	insn->opnd_bytes = 4;
	if (x86_64)
		insn->addr_bytes = 8;
	else
		insn->addr_bytes = 4;
}
/* prefix是什么
这是一串指令 */
static const insn_byte_t xen_prefix[] = { __XEN_EMULATE_PREFIX };
static const insn_byte_t kvm_prefix[] = { __KVM_EMULATE_PREFIX };
/* prefix就是kvm_prefix那些 */
static int __insn_get_emulate_prefix(struct insn *insn,
				     const insn_byte_t *prefix, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		/* 好像就是遍历insn的next_byte开始的每个byte */
		if (peek_nbyte_next(insn_byte_t, insn, i) != prefix[i])
			goto err_out;
	}
	/* 到这说明是虚拟机制的指令? */
	insn->emulate_prefix_size = len;
	/* 跳过逃逸指令, 指向实际代码 */
	insn->next_byte += len;

	return 1;

err_out:
	return 0;
}
/*

获得insn的逃逸指令相关信息
  */
static void insn_get_emulate_prefix(struct insn *insn)
{
	if (__insn_get_emulate_prefix(insn, xen_prefix, sizeof(xen_prefix)))
		return;

	__insn_get_emulate_prefix(insn, kvm_prefix, sizeof(kvm_prefix));
}

/**
获取opcode需要先获取prefix
prefix bytes是什么.
 * insn_get_prefixes - scan x86 instruction prefix bytes
 * @insn:	&struct insn containing instruction
 *
 * Populates the @insn->prefixes bitmap, and updates @insn->next_byte
 * to point to the (first) opcode.  No effect if @insn->prefixes.got
 * is already set.
 *
 * * Returns:
 * 0:  on success
 * < 0: on error
 */
int insn_get_prefixes(struct insn *insn)
{
	struct insn_field *prefixes = &insn->prefixes;
	insn_attr_t attr;
	insn_byte_t b, lb;
	int i, nb;

	if (prefixes->got)
		return 0;
	/* 获取vm的逃逸指令.好让next_byte跳过这些逃逸指令 */
	insn_get_emulate_prefix(insn);

	nb = 0;
	lb = 0;
	/* 获取next_byte之后的第一个指令byte */
	b = peek_next(insn_byte_t, insn);
	/* 查表获得b这个byte的机器码的attr */
	attr = inat_get_opcode_attribute(b);

	while (inat_is_legacy_prefix(attr)) {/* 如果b的attr是legacy prefix */
		/* Skip if same prefix */
		for (i = 0; i < nb; i++)
			if (prefixes->bytes[i] == b)
				goto found;/* nb数量的全都匹配,视为找到 */

		if (nb == 4)
			/* 越界了, Invalid instruction */
			break;
		/* 说明b这个opcode是legacy prefix code? 
		把b加入到prefixs里面*/
		prefixes->bytes[nb++] = b;

		if (inat_is_address_size_prefix(attr)) {/* 如果b的attr的prefix属性是INAT_PFX_ADDRSZ */
			/* address size switches 2/4 or 4/8 */
			if (insn->x86_64)
				insn->addr_bytes ^= 12; /* 翻转右数第三四位 */
			else
				insn->addr_bytes ^= 6; /* 翻转右数二三位 */
		} else if (inat_is_operand_size_prefix(attr)) {/* 如果b的attr的prefix属性是INAT_PFX_OPNDSZ */
			/* oprand size switches 2/4 */
			insn->opnd_bytes ^= 6;
		}

found:
		/* 找到了一个prefix byte */
		prefixes->nbytes++;
		/* 跳过一个prefix byte */
		insn->next_byte++;
		lb = b;
		/* 获取text的下一个byte */
		b = peek_next(insn_byte_t, insn);
		/* 继续获得这个新byte机器码的attr */
		attr = inat_get_opcode_attribute(b);
	}


	/* Set the last prefix
	todo 2024年10月11日01:02:47 */
	if (lb && lb != insn->prefixes.bytes[3]) {
		if (unlikely(insn->prefixes.bytes[3])) {
			/* Swap the last prefix */
			b = insn->prefixes.bytes[3];
			for (i = 0; i < nb; i++)
				if (prefixes->bytes[i] == lb)
					insn_set_byte(prefixes, i, b);
		}

		insn_set_byte(&insn->prefixes, 3, lb);
	}

	/* Decode REX prefix */
	if (insn->x86_64) {
		b = peek_next(insn_byte_t, insn);
		attr = inat_get_opcode_attribute(b);
		if (inat_is_rex_prefix(attr)) {
			/* 单字节指令用这个? */
			insn_field_set(&insn->rex_prefix, b, 1);
			/* 也跳过这个prefix指令 */
			insn->next_byte++;
			if (X86_REX_W(b))
				/* REX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		}
	}
	/* rex prefix也获取了 */
	insn->rex_prefix.got = 1;

	/* Decode VEX prefix
	这里是处理avx,vex什么的prefix */
	b = peek_next(insn_byte_t, insn);
	attr = inat_get_opcode_attribute(b);
	if (inat_is_vex_prefix(attr)) {
		insn_byte_t b2 = peek_nbyte_next(insn_byte_t, insn, 1);
		if (!insn->x86_64) {
			/*
			 * In 32-bits mode, if the [7:6] bits (mod bits of
			 * ModRM) on the second byte are not 11b, it is
			 * LDS or LES or BOUND.
			 */
			if (X86_MODRM_MOD(b2) != 3)
				goto vex_end;
		}
		insn_set_byte(&insn->vex_prefix, 0, b);
		insn_set_byte(&insn->vex_prefix, 1, b2);
		if (inat_is_evex_prefix(attr)) {
			b2 = peek_nbyte_next(insn_byte_t, insn, 2);
			insn_set_byte(&insn->vex_prefix, 2, b2);
			b2 = peek_nbyte_next(insn_byte_t, insn, 3);
			insn_set_byte(&insn->vex_prefix, 3, b2);
			insn->vex_prefix.nbytes = 4;
			insn->next_byte += 4;
			if (insn->x86_64 && X86_VEX_W(b2))
				/* VEX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		} else if (inat_is_vex3_prefix(attr)) {
			b2 = peek_nbyte_next(insn_byte_t, insn, 2);
			insn_set_byte(&insn->vex_prefix, 2, b2);
			insn->vex_prefix.nbytes = 3;
			insn->next_byte += 3;
			if (insn->x86_64 && X86_VEX_W(b2))
				/* VEX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		} else {
			/*
			 * For VEX2, fake VEX3-like byte#2.
			 * Makes it easier to decode vex.W, vex.vvvv,
			 * vex.L and vex.pp. Masking with 0x7f sets vex.W == 0.
			 */
			insn_set_byte(&insn->vex_prefix, 2, b2 & 0x7f);
			insn->vex_prefix.nbytes = 2;
			insn->next_byte += 2;
		}
	}
vex_end:
	insn->vex_prefix.got = 1;

	prefixes->got = 1;

	return 0;

err_out:
	return -ENODATA;
}

/**
get此insn的opcodes
 * insn_get_opcode - collect opcode(s)
 * @insn:	&struct insn containing instruction
 * 初始化opcode, 设置next_byte指向机器码.
 * Populates @insn->opcode, updates @insn->next_byte to point past the
 * opcode byte(s), and set @insn->attr (except for groups).
 * If necessary, first collects any preceding (prefix) bytes.
 * Sets @insn->opcode.value = opcode1.  No effect if @insn->opcode.got
 * is already 1.
 *
 * Returns:
 * 0:  on success
 * < 0: on error
 */
int insn_get_opcode(struct insn *insn)
{
	struct insn_field *opcode = &insn->opcode;
	int pfx_id, ret;
	insn_byte_t op;

	if (opcode->got)
		return 0;

	if (!insn->prefixes.got) {
		/* 这里获取各种insn的next_byte起始的各种prefix指令,
		存储到insn的对应结构体里面.然后步进next_byte跳过这些prefix */
		ret = insn_get_prefixes(insn);
		if (ret)
			return ret;
	}

	/* 函数名叫get opcode, 就是获取insn的next_byte指向的text里面的opcode
	但是text起始处不一定直接是opcode,可能有些prefix字节码.
	 所以一开始要跳过prefix指令.现在已经跳过去了,现在next_byte指向的就是opcode了
	这里开始获取opcode, 存储到opcode(insn的opcode)里面 */

	/* Get first opcode
	现在跳过了prefix, next_byte起始指向的应该是真正的opcode了,
	这里获取op. */
	op = get_next(insn_byte_t, insn);
	insn_set_byte(opcode, 0, op);
	opcode->nbytes = 1;

	/* 获取完insn的op了。后面的工作好像是设置insn的attr */
	/* Check if there is VEX prefix or not */
	if (insn_is_avx(insn)) {/* 是不是avx的insn */
		insn_byte_t m, p;
		m = insn_vex_m_bits(insn);
		p = insn_vex_p_bits(insn);
		insn->attr = inat_get_avx_attribute(op, m, p);

		if ((inat_must_evex(insn->attr) && !insn_is_evex(insn)) ||
		    (!inat_accept_vex(insn->attr) &&
		     !inat_is_group(insn->attr))) {
			/* This instruction is bad */
			insn->attr = 0;
			return -EINVAL;
		}
		/* VEX has only 1 byte for opcode */
		goto end;
	}
	/* 除去avx的情况, insn的attr就是op的attr? */
	insn->attr = inat_get_opcode_attribute(op);

	while (inat_is_escape(insn->attr)) {
		/* Get escaped opcode */
		/* 2024年10月11日01:16:02 */
		op = get_next(insn_byte_t, insn);
		opcode->bytes[opcode->nbytes++] = op;
		pfx_id = insn_last_prefix_id(insn);
		insn->attr = inat_get_escape_attribute(op, pfx_id, insn->attr);
	}

	if (inat_must_vex(insn->attr)) {
		/* This instruction is bad */
		insn->attr = 0;
		return -EINVAL;
	}
end:
	opcode->got = 1;
	return 0;

err_out:
	return -ENODATA;
}

/**
获取ModRM?
ModR/M 字节是 x86 指令中的一个重要组成部分，用于指定操作数的寻址模式。它包含三部分信息：
Mod：指示寻址模式，可以是直接地址、寄存器间接寻址或基于寄存器的寻址。
Reg：指定操作数的寄存器，通常是目标寄存器。
R/M：指明源操作数的寻址方式，可能是寄存器或内存地址。
--------------------------------------------------------------------------------
 * insn_get_modrm - collect ModRM byte, if any
 * @insn:	&struct insn containing instruction
 *
 * Populates @insn->modrm and updates @insn->next_byte to point past the
 * ModRM byte, if any.  If necessary, first collects the preceding bytes
 * (prefixes and opcode(s)).  No effect if @insn->modrm.got is already 1.
 *
 * Returns:
 * 0:  on success
 * < 0: on error
 */
int insn_get_modrm(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	insn_byte_t pfx_id, mod;
	int ret;

	if (modrm->got)
		return 0;

	if (!insn->opcode.got) {
		ret = insn_get_opcode(insn);
		if (ret)
			return ret;
	}

	if (inat_has_modrm(insn->attr)) {
		mod = get_next(insn_byte_t, insn);
		insn_field_set(modrm, mod, 1);
		if (inat_is_group(insn->attr)) {
			pfx_id = insn_last_prefix_id(insn);
			insn->attr = inat_get_group_attribute(mod, pfx_id,
							      insn->attr);
			if (insn_is_avx(insn) && !inat_accept_vex(insn->attr)) {
				/* Bad insn */
				insn->attr = 0;
				return -EINVAL;
			}
		}
	}

	if (insn->x86_64 && inat_is_force64(insn->attr))
		insn->opnd_bytes = 8;

	modrm->got = 1;
	return 0;

err_out:
	return -ENODATA;
}


/**
 * insn_rip_relative() - Does instruction use RIP-relative addressing mode?
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * ModRM byte.  No effect if @insn->x86_64 is 0.
 */
int insn_rip_relative(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	int ret;

	if (!insn->x86_64)
		return 0;

	if (!modrm->got) {
		ret = insn_get_modrm(insn);
		if (ret)
			return 0;
	}
	/*
	 * For rip-relative instructions, the mod field (top 2 bits)
	 * is zero and the r/m field (bottom 3 bits) is 0x5.
	 */
	return (modrm->nbytes && (modrm->bytes[0] & 0xc7) == 0x5);
}

/**
获取指令的SIB byte?
SIB（Scale Index Base）是x86架构中的一种寻址模式，用于有效地计算内存地址。它在使用复合地址时，能够通过组合基址寄存器、索引寄存器和缩放因子来实现更灵活的寻址。
在x86汇编中，SIB字节通常出现在某些指令的操作数中，特别是涉及到数组或结构体时。SIB字节的格式包括三个部分：
Scale（缩放因子）：可以是1、2、4或8，用于对索引寄存器的值进行缩放。
Index（索引寄存器）：通常是用于计算地址的寄存器，比如 EAX、EBX、ECX 等。
Base（基址寄存器）：用于指定基址的寄存器，类似于 EBP 或 ESI。
SIB寻址模式的一个常见例子是访问数组元素，比如在处理动态数组时，通过基址加上索引来获取特定元素的位置。
---------------------------------

分析这条汇编指令 mov eax, [ebx + esi*4] 的机器码及其组成部分。
指令分析
操作码：mov 指令的机器码。
SIB 字节：用于指定索引和基址。
位移：如果有的话，可以在最后指定。
示例指令的机器码
对于指令 mov eax, [ebx + esi*4]，它的机器码可能是类似这样的（以 32 位模式为例）：
8B 04 2B
这里的部分内容说明如下：
操作码（8B）：表示 mov 指令，操作数为 eax 和内存地址。
ModR/M 字节（04）：指示操作数类型和寻址方式。
SIB 字节（2B）：这是实际的 SIB 字节，包含索引寄存器和缩放因子的定义。
SIB 字节细分
假设 SIB 字节的内容为 2B，其结构为：

Scale：00 (1)
Index：01 (对应 esi)

 * insn_get_sib() - Get the SIB byte of instruction
 * @insn:	&struct insn containing instruction
 * 
 * If necessary, first collects the instruction up to and including the
 * ModRM byte.
 *
 * Returns:
 * 0: if decoding succeeded
 * < 0: otherwise.
 */
int insn_get_sib(struct insn *insn)
{
	insn_byte_t modrm;
	int ret;

	if (insn->sib.got)
		return 0;

	if (!insn->modrm.got) {/* 确实sib依赖于modrm */
		ret = insn_get_modrm(insn);
		if (ret)
			return ret;
	}

	if (insn->modrm.nbytes) {
		modrm = insn->modrm.bytes[0];
		if (insn->addr_bytes != 2 &&
		    X86_MODRM_MOD(modrm) != 3 && X86_MODRM_RM(modrm) == 4) {
			insn_field_set(&insn->sib,
				       get_next(insn_byte_t, insn), 1);
		}
	}
	insn->sib.got = 1;

	return 0;

err_out:
	return -ENODATA;
}


/**
获取指令的偏移量?
 * insn_get_displacement() - Get the displacement of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * SIB byte.
 * Displacement value is sign-expanded.
 *
 * * Returns:
 * 0: if decoding succeeded
 * < 0: otherwise.
 */
int insn_get_displacement(struct insn *insn)
{
	insn_byte_t mod, rm, base;
	int ret;

	if (insn->displacement.got)
		return 0;

	if (!insn->sib.got) {
		ret = insn_get_sib(insn);
		if (ret)
			return ret;
	}

	if (insn->modrm.nbytes) {
		/*
		 * Interpreting the modrm byte:
		 * mod = 00 - no displacement fields (exceptions below)
		 * mod = 01 - 1-byte displacement field
		 * mod = 10 - displacement field is 4 bytes, or 2 bytes if
		 * 	address size = 2 (0x67 prefix in 32-bit mode)
		 * mod = 11 - no memory operand
		 *
		 * If address size = 2...
		 * mod = 00, r/m = 110 - displacement field is 2 bytes
		 *
		 * If address size != 2...
		 * mod != 11, r/m = 100 - SIB byte exists
		 * mod = 00, SIB base = 101 - displacement field is 4 bytes
		 * mod = 00, r/m = 101 - rip-relative addressing, displacement
		 * 	field is 4 bytes
		 */
		mod = X86_MODRM_MOD(insn->modrm.value);
		rm = X86_MODRM_RM(insn->modrm.value);
		base = X86_SIB_BASE(insn->sib.value);
		if (mod == 3)
			goto out;
		if (mod == 1) {
			insn_field_set(&insn->displacement,
				       get_next(signed char, insn), 1);
		} else if (insn->addr_bytes == 2) {
			if ((mod == 0 && rm == 6) || mod == 2) {
				insn_field_set(&insn->displacement,
					       get_next(short, insn), 2);
			}
		} else {
			if ((mod == 0 && rm == 5) || mod == 2 ||
			    (mod == 0 && base == 5)) {
				insn_field_set(&insn->displacement,
					       get_next(int, insn), 4);
			}
		}
	}
out:
	insn->displacement.got = 1;
	return 0;

err_out:
	return -ENODATA;
}

/* Decode moffset16/32/64. Return 0 if failed */
static int __get_moffset(struct insn *insn)
{
	switch (insn->addr_bytes) {
	case 2:
		insn_field_set(&insn->moffset1, get_next(short, insn), 2);
		break;
	case 4:
		insn_field_set(&insn->moffset1, get_next(int, insn), 4);
		break;
	case 8:
		insn_field_set(&insn->moffset1, get_next(int, insn), 4);
		insn_field_set(&insn->moffset2, get_next(int, insn), 4);
		break;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}
	insn->moffset1.got = insn->moffset2.got = 1;

	return 1;

err_out:
	return 0;
}

/* Decode imm v32(Iz). Return 0 if failed */
static int __get_immv32(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn_field_set(&insn->immediate, get_next(short, insn), 2);
		break;
	case 4:
	case 8:
		insn_field_set(&insn->immediate, get_next(int, insn), 4);
		break;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}

	return 1;

err_out:
	return 0;
}

/* Decode imm v64(Iv/Ov), Return 0 if failed */
static int __get_immv(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn_field_set(&insn->immediate1, get_next(short, insn), 2);
		break;
	case 4:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		insn->immediate1.nbytes = 4;
		break;
	case 8:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		insn_field_set(&insn->immediate2, get_next(int, insn), 4);
		break;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}
	insn->immediate1.got = insn->immediate2.got = 1;

	return 1;
err_out:
	return 0;
}

/* Decode ptr16:16/32(Ap) */
static int __get_immptr(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn_field_set(&insn->immediate1, get_next(short, insn), 2);
		break;
	case 4:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		break;
	case 8:
		/* ptr16:64 is not exist (no segment) */
		return 0;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}
	insn_field_set(&insn->immediate2, get_next(unsigned short, insn), 2);
	insn->immediate1.got = insn->immediate2.got = 1;

	return 1;
err_out:
	return 0;
}

/**
获取指令的直接数
 * insn_get_immediate() - Get the immediate in an instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * displacement bytes.
 * Basically, most of immediates are sign-expanded. Unsigned-value can be
 * computed by bit masking with ((1 << (nbytes * 8)) - 1)
 *
 * Returns:
 * 0:  on success
 * < 0: on error
 */
int insn_get_immediate(struct insn *insn)
{
	int ret;

	if (insn->immediate.got) /* 已经获取了 */
		return 0;

	if (!insn->displacement.got) {
		ret = insn_get_displacement(insn);
		if (ret)
			return ret;
	}

	if (inat_has_moffset(insn->attr)) {
		if (!__get_moffset(insn))
			goto err_out;
		goto done;
	}

	if (!inat_has_immediate(insn->attr))
		/* no immediates */
		goto done;

	switch (inat_immediate_size(insn->attr)) {
	case INAT_IMM_BYTE:
		insn_field_set(&insn->immediate, get_next(signed char, insn), 1);
		break;
	case INAT_IMM_WORD:
		insn_field_set(&insn->immediate, get_next(short, insn), 2);
		break;
	case INAT_IMM_DWORD:
		insn_field_set(&insn->immediate, get_next(int, insn), 4);
		break;
	case INAT_IMM_QWORD:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		insn_field_set(&insn->immediate2, get_next(int, insn), 4);
		break;
	case INAT_IMM_PTR:
		if (!__get_immptr(insn))
			goto err_out;
		break;
	case INAT_IMM_VWORD32:
		if (!__get_immv32(insn))
			goto err_out;
		break;
	case INAT_IMM_VWORD:
		if (!__get_immv(insn))
			goto err_out;
		break;
	default:
		/* Here, insn must have an immediate, but failed */
		goto err_out;
	}
	if (inat_has_second_immediate(insn->attr)) {
		insn_field_set(&insn->immediate2, get_next(signed char, insn), 1);
	}
done:
	insn->immediate.got = 1;
	return 0;

err_out:
	return -ENODATA;
}

/**
获取insn的长度 ...
 * insn_get_length() - Get the length of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * immediates bytes.
 *
 * Returns:
 *  - 0 on success
 *  - < 0 on error
*/
int insn_get_length(struct insn *insn)
{
	int ret;

	if (insn->length)
		return 0;

	if (!insn->immediate.got) {
		/* 说明还没有运行insn_get_**函数 */
		ret = insn_get_immediate(insn);
		if (ret)
			return ret;
	}

	insn->length = (unsigned char)((unsigned long)insn->next_byte
				     - (unsigned long)insn->kaddr);

	return 0;
}

/* Ensure this instruction is decoded completely */
static inline int insn_complete(struct insn *insn)
{
	return insn->opcode.got && insn->modrm.got && insn->sib.got &&
		insn->displacement.got && insn->immediate.got;
}

/**
解码x86指令?
ftrace的时候, insn是新结构体, kaddr是opcode(另外一个静态insn的text)

 * insn_decode() - Decode an x86 instruction
 * @insn:	&struct insn to be initialized
 * @kaddr:	address (in kernel memory) of instruction (or copy thereof)
 可能是poke insn的text地址
 * @buf_len:	length of the insn buffer at @kaddr
 * @m:		insn mode, see enum insn_mode
 *
 * Returns:
 * 0: if decoding succeeded
 * < 0: otherwise.
 */
int insn_decode(struct insn *insn, const void *kaddr, int buf_len, enum insn_mode m)
{
	int ret;

/* #define INSN_MODE_KERN	-1 __ignore_sync_check__ mode is only valid in the kernel */

	if (m == INSN_MODE_KERN)/* ftrace时hook代码是这个路径 */
	/* 把新insn的kaddr和next_byte指向此kaddr(另一个insn的text) */
		insn_init(insn, kaddr, buf_len, IS_ENABLED(CONFIG_X86_64));
	else
		insn_init(insn, kaddr, buf_len, m == INSN_MODE_64);

	ret = insn_get_length(insn);

	if (ret)
		return ret;

	if (insn_complete(insn))
		return 0;

	return -EINVAL;
}

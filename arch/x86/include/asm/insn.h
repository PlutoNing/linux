/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_X86_INSN_H
#define _ASM_X86_INSN_H
/*
 * x86 instruction analysis
 *
 * Copyright (C) IBM Corporation, 2009
 */

#include <asm/byteorder.h>
/* insn_attr_t is defined in inat.h */
#include <asm/inat.h> /* __ignore_sync_check__ */

#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __LITTLE_ENDIAN : defined(__LITTLE_ENDIAN)

struct insn_field {
	union {
		insn_value_t value;
		insn_byte_t bytes[4];
	};
	/* !0 if we've run insn_get_xxx() for this field */
	unsigned char got;
	unsigned char nbytes;
};

static inline void insn_field_set(struct insn_field *p, insn_value_t v,
				  unsigned char n)
{
	p->value = v;
	p->nbytes = n;
}

static inline void insn_set_byte(struct insn_field *p, unsigned char n,
				 insn_byte_t v)
{
	p->bytes[n] = v;
}

#else

struct insn_field {
	insn_value_t value;
	union {
		insn_value_t little;
		insn_byte_t bytes[4];
	};
	/* !0 if we've run insn_get_xxx() for this field */
	unsigned char got;
	unsigned char nbytes;
};

static inline void insn_field_set(struct insn_field *p, insn_value_t v,
				  unsigned char n)
{
	p->value = v;
	p->little = __cpu_to_le32(v);
	p->nbytes = n;
}

static inline void insn_set_byte(struct insn_field *p, unsigned char n,
				 insn_byte_t v)
{
	p->bytes[n] = v;
	p->value = __le32_to_cpu(p->little);
}
#endif
/* 
在 Linux 内核中，struct insn 主要用于表示和分析机器指令，尤其是在处理 x86 架构时。
这个结构体包含了与指令相关的各种信息和字段，旨在支持指令的解码、模拟和执行。
以下是这个结构体各个字段的作用：
prefixes: 用于存储指令前缀信息，例如操作码前缀，这对指令的行为有重要影响。
rex_prefix: 用于存储 REX 前缀信息，REX 前缀在 x86-64 中用于扩展寄存器和操作数的大小。
vex_prefix: 存储 VEX 前缀信息，用于表示 AVX 指令集中的扩展。
opcode: 存储指令的操作码，通常包含多个字节，表示不同的操作。
modrm: 存储 ModRM 字节，该字节用于指示操作数的寻址模式、寄存器等信息。
sib: 存储 SIB（Scale Index Base）字节，用于复杂寻址模式。
displacement: 存储位移值，通常用于指针或地址的计算。
immediate 和 moffset: 存储立即数和内存偏移量的信息，适用于不同的指令和操作。
emulate_prefix_size: 用于表示指令前缀的大小，以便在模拟或执行指令时使用。
attr: 用于存储指令的属性，可能包括指令类型、权限等信息。
opnd_bytes 和 addr_bytes: 用于表示操作数和地址的字节大小，帮助确定指令的处理方式。
length: 表示指令的长度，有助于解析和跟踪指令流。
x86_64: 表示该指令是否为 x86-64 架构相关的指令。

next_byte: 指向下一个要处理的字节，通常用于指令解码过程中。
总体而言，struct insn 使得内核能够有效地解码和模拟 x86/x86-64 指令，
对于实现调试、动态分析和虚拟化等功能非常重要。
 */
struct insn {
	struct insn_field prefixes;	/*
					 * Prefixes
					 * prefixes.bytes[3]: last prefix
					 */
	struct insn_field rex_prefix;	/* REX prefix */
	struct insn_field vex_prefix;	/* VEX prefix */
	struct insn_field opcode;	/*
					 * opcode.bytes[0]: opcode1
					 * opcode.bytes[1]: opcode2
					 * opcode.bytes[2]: opcode3
					 */
	struct insn_field modrm;
	struct insn_field sib;
	struct insn_field displacement;
	union {
		struct insn_field immediate;
		struct insn_field moffset1;	/* for 64bit MOV */
		struct insn_field immediate1;	/* for 64bit imm or off16/32 */
	};
	union {
		struct insn_field moffset2;	/* for 64bit MOV */
		struct insn_field immediate2;	/* for 64bit imm or seg16 */
	};
	/* 虚拟机逃逸指令的长度 */
	int	emulate_prefix_size;
	insn_attr_t attr;
	unsigned char opnd_bytes;
	unsigned char addr_bytes;
	unsigned char length;
	unsigned char x86_64;

	const insn_byte_t *kaddr;	/* 
	好像是poke insn的text地址
	kernel address of insn to analyze */
	const insn_byte_t *end_kaddr;	/* kernel address of last insn in buffer */
	const insn_byte_t *next_byte;
	/* 	
	初始化的一种方式
	insn->kaddr = kaddr;
	insn->end_kaddr = kaddr + buf_len;
	insn->next_byte = kaddr; */
};
/*  */
#define MAX_INSN_SIZE	15

#define X86_MODRM_MOD(modrm) (((modrm) & 0xc0) >> 6)
#define X86_MODRM_REG(modrm) (((modrm) & 0x38) >> 3)
#define X86_MODRM_RM(modrm) ((modrm) & 0x07)

#define X86_SIB_SCALE(sib) (((sib) & 0xc0) >> 6)
#define X86_SIB_INDEX(sib) (((sib) & 0x38) >> 3)
#define X86_SIB_BASE(sib) ((sib) & 0x07)

#define X86_REX_W(rex) ((rex) & 8)
#define X86_REX_R(rex) ((rex) & 4)
#define X86_REX_X(rex) ((rex) & 2)
#define X86_REX_B(rex) ((rex) & 1)

/* VEX bit flags  */
#define X86_VEX_W(vex)	((vex) & 0x80)	/* VEX3 Byte2 */
#define X86_VEX_R(vex)	((vex) & 0x80)	/* VEX2/3 Byte1 */
#define X86_VEX_X(vex)	((vex) & 0x40)	/* VEX3 Byte1 */
#define X86_VEX_B(vex)	((vex) & 0x20)	/* VEX3 Byte1 */
#define X86_VEX_L(vex)	((vex) & 0x04)	/* VEX3 Byte2, VEX2 Byte1 */
/* VEX bit fields */
#define X86_EVEX_M(vex)	((vex) & 0x07)		/* EVEX Byte1 */
#define X86_VEX3_M(vex)	((vex) & 0x1f)		/* VEX3 Byte1 */
#define X86_VEX2_M	1			/* VEX2.M always 1 */
#define X86_VEX_V(vex)	(((vex) & 0x78) >> 3)	/* VEX3 Byte2, VEX2 Byte1 */
#define X86_VEX_P(vex)	((vex) & 0x03)		/* VEX3 Byte2, VEX2 Byte1 */
#define X86_VEX_M_MAX	0x1f			/* VEX3.M Maximum value */

extern void insn_init(struct insn *insn, const void *kaddr, int buf_len, int x86_64);
extern int insn_get_prefixes(struct insn *insn);
extern int insn_get_opcode(struct insn *insn);
extern int insn_get_modrm(struct insn *insn);
extern int insn_get_sib(struct insn *insn);
extern int insn_get_displacement(struct insn *insn);
extern int insn_get_immediate(struct insn *insn);
extern int insn_get_length(struct insn *insn);
/* poke代码的mode? */
enum insn_mode {
	INSN_MODE_32,
	INSN_MODE_64,
	/* Mode is determined by the current kernel build. */
	INSN_MODE_KERN,
	INSN_NUM_MODES,
};

extern int insn_decode(struct insn *insn, const void *kaddr, int buf_len, enum insn_mode m);
/* 
ftrace的时候, insn是新结构体, ptr是opcode(另外一个静态insn的text)

 */
#define insn_decode_kernel(_insn, _ptr) insn_decode((_insn), (_ptr), MAX_INSN_SIZE, INSN_MODE_KERN)

/* Attribute will be determined after getting ModRM (for opcode groups) */
static inline void insn_get_attribute(struct insn *insn)
{
	insn_get_modrm(insn);
}

/* Instruction uses RIP-relative addressing */
extern int insn_rip_relative(struct insn *insn);
/* avx相关 ... 
看看这个insn是不是avx指令?本质上就是看有没有avx prefix?
*/
static inline int insn_is_avx(struct insn *insn)
{
	if (!insn->prefixes.got)
		insn_get_prefixes(insn);

	return (insn->vex_prefix.value != 0);
}

static inline int insn_is_evex(struct insn *insn)
{
	if (!insn->prefixes.got)
		insn_get_prefixes(insn);
	return (insn->vex_prefix.nbytes == 4);
}

static inline int insn_has_emulate_prefix(struct insn *insn)
{
	return !!insn->emulate_prefix_size;
}

static inline insn_byte_t insn_vex_m_bits(struct insn *insn)
{
	if (insn->vex_prefix.nbytes == 2)	/* 2 bytes VEX */
		return X86_VEX2_M;
	else if (insn->vex_prefix.nbytes == 3)	/* 3 bytes VEX */
		return X86_VEX3_M(insn->vex_prefix.bytes[1]);
	else					/* EVEX */
		return X86_EVEX_M(insn->vex_prefix.bytes[1]);
}

static inline insn_byte_t insn_vex_p_bits(struct insn *insn)
{
	if (insn->vex_prefix.nbytes == 2)	/* 2 bytes VEX */
		return X86_VEX_P(insn->vex_prefix.bytes[1]);
	else
		return X86_VEX_P(insn->vex_prefix.bytes[2]);
}

/* Get the last prefix id from last prefix or VEX prefix */
static inline int insn_last_prefix_id(struct insn *insn)
{
	if (insn_is_avx(insn))
		return insn_vex_p_bits(insn);	/* VEX_p is a SIMD prefix id */

	if (insn->prefixes.bytes[3])
		return inat_get_last_prefix_id(insn->prefixes.bytes[3]);

	return 0;
}

/* Offset of each field from kaddr */
static inline int insn_offset_rex_prefix(struct insn *insn)
{
	return insn->prefixes.nbytes;
}
static inline int insn_offset_vex_prefix(struct insn *insn)
{
	return insn_offset_rex_prefix(insn) + insn->rex_prefix.nbytes;
}
static inline int insn_offset_opcode(struct insn *insn)
{
	return insn_offset_vex_prefix(insn) + insn->vex_prefix.nbytes;
}
static inline int insn_offset_modrm(struct insn *insn)
{
	return insn_offset_opcode(insn) + insn->opcode.nbytes;
}
static inline int insn_offset_sib(struct insn *insn)
{
	return insn_offset_modrm(insn) + insn->modrm.nbytes;
}
static inline int insn_offset_displacement(struct insn *insn)
{
	return insn_offset_sib(insn) + insn->sib.nbytes;
}
static inline int insn_offset_immediate(struct insn *insn)
{
	return insn_offset_displacement(insn) + insn->displacement.nbytes;
}

/**
 * for_each_insn_prefix() -- Iterate prefixes in the instruction
 * @insn: Pointer to struct insn.
 * @idx:  Index storage.
 * @prefix: Prefix byte.
 *
 * Iterate prefix bytes of given @insn. Each prefix byte is stored in @prefix
 * and the index is stored in @idx (note that this @idx is just for a cursor,
 * do not change it.)
 * Since prefixes.nbytes can be bigger than 4 if some prefixes
 * are repeated, it cannot be used for looping over the prefixes.
 */
#define for_each_insn_prefix(insn, idx, prefix)	\
	for (idx = 0; idx < ARRAY_SIZE(insn->prefixes.bytes) && (prefix = insn->prefixes.bytes[idx]) != 0; idx++)

#define POP_SS_OPCODE 0x1f
#define MOV_SREG_OPCODE 0x8e

/*
 * Intel SDM Vol.3A 6.8.3 states;
 * "Any single-step trap that would be delivered following the MOV to SS
 * instruction or POP to SS instruction (because EFLAGS.TF is 1) is
 * suppressed."
 * This function returns true if @insn is MOV SS or POP SS. On these
 * instructions, single stepping is suppressed.
 */
static inline int insn_masking_exception(struct insn *insn)
{
	return insn->opcode.bytes[0] == POP_SS_OPCODE ||
		(insn->opcode.bytes[0] == MOV_SREG_OPCODE &&
		 X86_MODRM_REG(insn->modrm.bytes[0]) == 2);
}

#endif /* _ASM_X86_INSN_H */

/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_X86_INAT_H
#define _ASM_X86_INAT_H
/*
 * x86 instruction attributes
 *
 * Written by Masami Hiramatsu <mhiramat@redhat.com>
 */
#include <asm/inat_types.h> /* __ignore_sync_check__ */

/*
 * Internal bits. Don't use bitmasks directly, because these bits are
 * unstable. You should use checking functions.
 */

#define INAT_OPCODE_TABLE_SIZE 256
#define INAT_GROUP_TABLE_SIZE 8

/* Legacy last prefixes */
/* 如果后续指令的操作数是 32 位，这个前缀会将其转换为 16 位（反之亦然）。 */
#define INAT_PFX_OPNDSZ	1	/* 0x66 */ /* LPFX1 */
/* 用于重复执行后续指令，直到条件不再满足（例如，REP 前缀通常与字符串操作指令一起使用）。 */
#define INAT_PFX_REPE	2	/* 0xF3 */ /* LPFX2 */
/* 类似于 REPE，但只在条件不相等时执行。 */
#define INAT_PFX_REPNE	3	/* 0xF2 */ /* LPFX3 */
/* Other Legacy prefixes */
// 用于在多处理器系统中，确保后续指令在执行时不会被其他处理器干扰。
#define INAT_PFX_LOCK	4	/* 0xF0 */
/* 指示后续指令应使用 CS 段寄存器。 */
#define INAT_PFX_CS	5	/* 0x2E */
/*  指示后续指令应使用 DS 段寄存器。 */
#define INAT_PFX_DS	6	/* 0x3E */
/* 指示后续指令应使用 ES 段寄存器 */
#define INAT_PFX_ES	7	/* 0x26 */
/*  指示后续指令应使用 FS 段寄存器 */
#define INAT_PFX_FS	8	/* 0x64 */
/* 指示后续指令应使用 GS 段寄存器 */
#define INAT_PFX_GS	9	/* 0x65 */
/* 指示后续指令应使用 SS 段寄存器 */
#define INAT_PFX_SS	10	/* 0x36 */
/* 影响后续指令使用的地址大小（32 位或 16 位）。 */
#define INAT_PFX_ADDRSZ	11	/* 0x67 */
/* x86-64 REX prefix */
/* 在 64 位模式下，REX 前缀用于扩展操作数的大小、选择寄存器以及切换操作数的大小。 */
#define INAT_PFX_REX	12	/* 0x4X */
/* AVX VEX prefixes */
/* 用于支持 AVX 指令集的扩展，提供额外的指令功能 */
#define INAT_PFX_VEX2	13	/* 2-bytes VEX prefix */
#define INAT_PFX_VEX3	14	/* 3-bytes VEX prefix */
#define INAT_PFX_EVEX	15	/* EVEX prefix */

#define INAT_LSTPFX_MAX	3
/* legacy prefix的范围 */
#define INAT_LGCPFX_MAX	11

/* Immediate size */
#define INAT_IMM_BYTE		1
#define INAT_IMM_WORD		2
#define INAT_IMM_DWORD		3
#define INAT_IMM_QWORD		4
#define INAT_IMM_PTR		5
#define INAT_IMM_VWORD32	6
#define INAT_IMM_VWORD		7

/* Legacy prefix */
#define INAT_PFX_OFFS	0
#define INAT_PFX_BITS	4
#define INAT_PFX_MAX    ((1 << INAT_PFX_BITS) - 1)
#define INAT_PFX_MASK	(INAT_PFX_MAX << INAT_PFX_OFFS)
/* Escape opcodes */
#define INAT_ESC_OFFS	(INAT_PFX_OFFS + INAT_PFX_BITS)
#define INAT_ESC_BITS	2
#define INAT_ESC_MAX	((1 << INAT_ESC_BITS) - 1)
#define INAT_ESC_MASK	(INAT_ESC_MAX << INAT_ESC_OFFS)
/* Group opcodes (1-16) */
#define INAT_GRP_OFFS	(INAT_ESC_OFFS + INAT_ESC_BITS)
#define INAT_GRP_BITS	5
#define INAT_GRP_MAX	((1 << INAT_GRP_BITS) - 1)
#define INAT_GRP_MASK	(INAT_GRP_MAX << INAT_GRP_OFFS)
/* Immediates */
#define INAT_IMM_OFFS	(INAT_GRP_OFFS + INAT_GRP_BITS)
#define INAT_IMM_BITS	3
#define INAT_IMM_MASK	(((1 << INAT_IMM_BITS) - 1) << INAT_IMM_OFFS)
/* Flags */
#define INAT_FLAG_OFFS	(INAT_IMM_OFFS + INAT_IMM_BITS)
#define INAT_MODRM	(1 << (INAT_FLAG_OFFS))
#define INAT_FORCE64	(1 << (INAT_FLAG_OFFS + 1))
#define INAT_SCNDIMM	(1 << (INAT_FLAG_OFFS + 2))
#define INAT_MOFFSET	(1 << (INAT_FLAG_OFFS + 3))
#define INAT_VARIANT	(1 << (INAT_FLAG_OFFS + 4))
#define INAT_VEXOK	(1 << (INAT_FLAG_OFFS + 5))
#define INAT_VEXONLY	(1 << (INAT_FLAG_OFFS + 6))
#define INAT_EVEXONLY	(1 << (INAT_FLAG_OFFS + 7))
/* Attribute making macros for attribute tables */
#define INAT_MAKE_PREFIX(pfx)	(pfx << INAT_PFX_OFFS)
#define INAT_MAKE_ESCAPE(esc)	(esc << INAT_ESC_OFFS)
#define INAT_MAKE_GROUP(grp)	((grp << INAT_GRP_OFFS) | INAT_MODRM)
#define INAT_MAKE_IMM(imm)	(imm << INAT_IMM_OFFS)

/* Identifiers for segment registers */
#define INAT_SEG_REG_IGNORE	0
#define INAT_SEG_REG_DEFAULT	1
#define INAT_SEG_REG_CS		2
#define INAT_SEG_REG_SS		3
#define INAT_SEG_REG_DS		4
#define INAT_SEG_REG_ES		5
#define INAT_SEG_REG_FS		6
#define INAT_SEG_REG_GS		7

/* Attribute search APIs */
extern insn_attr_t inat_get_opcode_attribute(insn_byte_t opcode);
extern int inat_get_last_prefix_id(insn_byte_t last_pfx);
extern insn_attr_t inat_get_escape_attribute(insn_byte_t opcode,
					     int lpfx_id,
					     insn_attr_t esc_attr);
extern insn_attr_t inat_get_group_attribute(insn_byte_t modrm,
					    int lpfx_id,
					    insn_attr_t esc_attr);
extern insn_attr_t inat_get_avx_attribute(insn_byte_t opcode,
					  insn_byte_t vex_m,
					  insn_byte_t vex_pp);

/* Attribute checking functions
legacy prefix是什么
 */
static inline int inat_is_legacy_prefix(insn_attr_t attr)
{

	attr &= INAT_PFX_MASK;/* 取得prefix的那几位bit */
	/* 如果落于legacy prefix的范围 */
	return attr && attr <= INAT_LGCPFX_MAX;
}

static inline int inat_is_address_size_prefix(insn_attr_t attr)
{
	return (attr & INAT_PFX_MASK) == INAT_PFX_ADDRSZ;
}

static inline int inat_is_operand_size_prefix(insn_attr_t attr)
{
	return (attr & INAT_PFX_MASK) == INAT_PFX_OPNDSZ;
}

static inline int inat_is_rex_prefix(insn_attr_t attr)
{
	return (attr & INAT_PFX_MASK) == INAT_PFX_REX;
}

static inline int inat_last_prefix_id(insn_attr_t attr)
{
	if ((attr & INAT_PFX_MASK) > INAT_LSTPFX_MAX)
		return 0;
	else
		return attr & INAT_PFX_MASK;
}

static inline int inat_is_vex_prefix(insn_attr_t attr)
{
	attr &= INAT_PFX_MASK;
	return attr == INAT_PFX_VEX2 || attr == INAT_PFX_VEX3 ||
	       attr == INAT_PFX_EVEX;
}

static inline int inat_is_evex_prefix(insn_attr_t attr)
{
	return (attr & INAT_PFX_MASK) == INAT_PFX_EVEX;
}

static inline int inat_is_vex3_prefix(insn_attr_t attr)
{
	return (attr & INAT_PFX_MASK) == INAT_PFX_VEX3;
}

static inline int inat_is_escape(insn_attr_t attr)
{
	return attr & INAT_ESC_MASK;
}

static inline int inat_escape_id(insn_attr_t attr)
{
	return (attr & INAT_ESC_MASK) >> INAT_ESC_OFFS;
}

static inline int inat_is_group(insn_attr_t attr)
{
	return attr & INAT_GRP_MASK;
}

static inline int inat_group_id(insn_attr_t attr)
{
	return (attr & INAT_GRP_MASK) >> INAT_GRP_OFFS;
}

static inline int inat_group_common_attribute(insn_attr_t attr)
{
	return attr & ~INAT_GRP_MASK;
}

static inline int inat_has_immediate(insn_attr_t attr)
{
	return attr & INAT_IMM_MASK;
}

static inline int inat_immediate_size(insn_attr_t attr)
{
	return (attr & INAT_IMM_MASK) >> INAT_IMM_OFFS;
}

static inline int inat_has_modrm(insn_attr_t attr)
{
	return attr & INAT_MODRM;
}

static inline int inat_is_force64(insn_attr_t attr)
{
	return attr & INAT_FORCE64;
}

static inline int inat_has_second_immediate(insn_attr_t attr)
{
	return attr & INAT_SCNDIMM;
}

static inline int inat_has_moffset(insn_attr_t attr)
{
	return attr & INAT_MOFFSET;
}

static inline int inat_has_variant(insn_attr_t attr)
{
	return attr & INAT_VARIANT;
}

static inline int inat_accept_vex(insn_attr_t attr)
{
	return attr & INAT_VEXOK;
}

static inline int inat_must_vex(insn_attr_t attr)
{
	return attr & (INAT_VEXONLY | INAT_EVEXONLY);
}

static inline int inat_must_evex(insn_attr_t attr)
{
	return attr & INAT_EVEXONLY;
}
#endif

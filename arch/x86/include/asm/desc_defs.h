/* SPDX-License-Identifier: GPL-2.0 */
/* Written 2000 by Andi Kleen */
#ifndef _ASM_X86_DESC_DEFS_H
#define _ASM_X86_DESC_DEFS_H

/*
 * Segment descriptor structure definitions, usable from both x86_64 and i386
 * archs.
 */

#ifndef __ASSEMBLY__

#include <linux/types.h>

/* 8 byte segment descriptor
表示段描述符,作用是描述段的属性,比如基地址,限制,特权级别等.
一般可能是那些段比如代码段,数据段,系统段等.
 */
struct desc_struct {
	u16	limit0;  //段限制?
	u16	base0; //基地址

	u16	base1: 8, type: 4, s: 1, dpl: 2, p: 1; //这个定义方式说明了这个结构体的位域
	//这个结构体的位域是这样的:	|base1|type|s|dpl|p|分别是8,4,1,2,1位.作用是描述段的属性,比如基地址,限制,特权级别等.
	u16	limit1: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
} __attribute__((packed));

#define GDT_ENTRY_INIT(flags, base, limit)			\
	{							\
		.limit0		= (u16) (limit),		\
		.limit1		= ((limit) >> 16) & 0x0F,	\
		.base0		= (u16) (base),			\
		.base1		= ((base) >> 16) & 0xFF,	\
		.base2		= ((base) >> 24) & 0xFF,	\
		.type		= (flags & 0x0f),		\
		.s		= (flags >> 4) & 0x01,		\
		.dpl		= (flags >> 5) & 0x03,		\
		.p		= (flags >> 7) & 0x01,		\
		.avl		= (flags >> 12) & 0x01,		\
		.l		= (flags >> 13) & 0x01,		\
		.d		= (flags >> 14) & 0x01,		\
		.g		= (flags >> 15) & 0x01,		\
	}

enum {
	GATE_INTERRUPT = 0xE,
	GATE_TRAP = 0xF,
	GATE_CALL = 0xC,
	GATE_TASK = 0x5,
};

enum {
	DESC_TSS = 0x9,
	DESC_LDT = 0x2,
	DESCTYPE_S = 0x10,	/* !system */
};

/* LDT or TSS descriptor in the GDT
这个结构体描述了GDT中的LDT或者TSS描述符 16字节LDT或TSS描述符结构
描述符作用是
 */
struct ldttss_desc {
	u16	limit0;
	u16	base0;

	u16	base1 : 8, type : 5, dpl : 2, p : 1;
	u16	limit1 : 4, zero0 : 3, g : 1, base2 : 8;
#ifdef CONFIG_X86_64
	u32	base3;
	u32	zero1;
#endif
} __attribute__((packed));

typedef struct ldttss_desc ldt_desc;
typedef struct ldttss_desc tss_desc;

struct idt_bits {
	u16		ist	: 3,
			zero	: 5,
			type	: 5,
			dpl	: 2,
			p	: 1;
} __attribute__((packed));

struct gate_struct {
	u16		offset_low;
	u16		segment;
	struct idt_bits	bits;
	u16		offset_middle;
#ifdef CONFIG_X86_64
	u32		offset_high;
	u32		reserved;
#endif
} __attribute__((packed));

typedef struct gate_struct gate_desc;

static inline unsigned long gate_offset(const gate_desc *g)
{
#ifdef CONFIG_X86_64
	return g->offset_low | ((unsigned long)g->offset_middle << 16) |
		((unsigned long) g->offset_high << 32);
#else
	return g->offset_low | ((unsigned long)g->offset_middle << 16);
#endif
}

static inline unsigned long gate_segment(const gate_desc *g)
{
	return g->segment;
}

// 这个结构记录了系统的GDT或者IDT的大小以及在系统中的线性基地
struct desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed)) ;

#endif /* !__ASSEMBLY__ */

/* Access rights as returned by LAR */
#define AR_TYPE_RODATA		(0 * (1 << 9))
#define AR_TYPE_RWDATA		(1 * (1 << 9))
#define AR_TYPE_RODATA_EXPDOWN	(2 * (1 << 9))
#define AR_TYPE_RWDATA_EXPDOWN	(3 * (1 << 9))
#define AR_TYPE_XOCODE		(4 * (1 << 9))
#define AR_TYPE_XRCODE		(5 * (1 << 9))
#define AR_TYPE_XOCODE_CONF	(6 * (1 << 9))
#define AR_TYPE_XRCODE_CONF	(7 * (1 << 9))
#define AR_TYPE_MASK		(7 * (1 << 9))

#define AR_DPL0			(0 * (1 << 13))
#define AR_DPL3			(3 * (1 << 13))
#define AR_DPL_MASK		(3 * (1 << 13))

#define AR_A			(1 << 8)   /* "Accessed" */
#define AR_S			(1 << 12)  /* If clear, "System" segment */
#define AR_P			(1 << 15)  /* "Present" */
#define AR_AVL			(1 << 20)  /* "AVaiLable" (no HW effect) */
#define AR_L			(1 << 21)  /* "Long mode" for code segments */
#define AR_DB			(1 << 22)  /* D/B, effect depends on type */
#define AR_G			(1 << 23)  /* "Granularity" (limit in pages) */

#endif /* _ASM_X86_DESC_DEFS_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_SECTIONS_H_
#define _ASM_GENERIC_SECTIONS_H_

/* References to section boundaries */

#include <linux/compiler.h>
#include <linux/types.h>

/*
 * Usage guidelines:
 * _text, _data: architecture specific, don't use them in arch-independent code,	
  架构特定，不要在与架构无关的代码中使用它们
	
 * [_stext, _etext]: contains .text.* sections, may also contain .rodata.*
 *                   and/or .init.* sections
  包含.text.*节，也可能包含.rodata.*和/或.init.*节.这些节的作用是存放代码段
 * [_sdata, _edata]: contains .data.* sections, may also contain .rodata.*
 *                   and/or .init.* sections.
  包含.data.*节，也可能包含.rodata.*和/或.init.*节.这些节的作用是存放数据段
 * [__start_rodata, __end_rodata]: contains .rodata.* sections
  包含.rodata.*节.这些节的作用是存放只读数据段
 * [__start_ro_after_init, __end_ro_after_init]:
 *		     contains .data..ro_after_init section
  这些是只读数据段
 * [__init_begin, __init_end]: contains .init.* sections, but .init.text.*
 *                   may be out of this range on some architectures.
	  包含.init.*节，但是.init.text.*可能在某些架构上超出此范围
  这些节的作用是存放初始化代码段,初始化代码段是在内核启动时执行的代码段
 * [_sinittext, _einittext]: contains .init.text.* sections
  包含.init.text.*节.这些节的作用是存放初始化代码段
 * [__bss_start, __bss_stop]: contains BSS sections
  包含BSS节.这些节的作用是存放未初始化的全局变量.
 *
 * Following global variables are optional and may be unavailable on some
 * architectures and/or kernel configurations.
  接下来的全局变量是可选的，可能在某些架构和/或内核配置中不可用
 *	_text, _data

 *	__kprobes_text_start, __kprobes_text_end是指kprobes的地址
  *	__entry_text_start, __entry_text_end是指entry的地址
  *	__ctors_start, __ctors_end是指构造函数的地址
  *	__irqentry_text_start, __irqentry_text_end是指irqentry的地址
  *	__softirqentry_text_start, __softirqentry_text_end是指softirqentry的地址
  *	__start_opd, __end_opd是指函数描述符的地址
 *	__entry_text_start, __entry_text_end
 *	__ctors_start, __ctors_end
 *	__irqentry_text_start, __irqentry_text_end
 *	__softirqentry_text_start, __softirqentry_text_end
 *	__start_opd, __end_opd
 */
extern char _text[], _stext[], _etext[]; //代码段
extern char _data[], _sdata[], _edata[]; //数据段
extern char __bss_start[], __bss_stop[]; //未初始化的全局变量
extern char __init_begin[], __init_end[];//初始化代码段
extern char _sinittext[], _einittext[];//初始化代码段
extern char __start_ro_after_init[], __end_ro_after_init[]; //只读数据段
extern char _end[]; //内核结束地址?
/* pcp相关的地址信息 */
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];
extern char __kprobes_text_start[], __kprobes_text_end[];
extern char __entry_text_start[], __entry_text_end[];
extern char __start_rodata[], __end_rodata[];
extern char __irqentry_text_start[], __irqentry_text_end[];
extern char __softirqentry_text_start[], __softirqentry_text_end[];
extern char __start_once[], __end_once[];

/* Start and end of .ctors section - used for constructor calls. */
extern char __ctors_start[], __ctors_end[];

/* Start and end of .opd section - used for function descriptors. */
extern char __start_opd[], __end_opd[];

extern __visible const void __nosave_begin, __nosave_end;

/* Function descriptor handling (if any).  Override in asm/sections.h */
#ifndef dereference_function_descriptor
#define dereference_function_descriptor(p) (p)
#define dereference_kernel_function_descriptor(p) (p)
#endif

/* random extra sections (if any).  Override
 * in asm/sections.h */
#ifndef arch_is_kernel_text
static inline int arch_is_kernel_text(unsigned long addr)
{
	return 0;
}
#endif

#ifndef arch_is_kernel_data
static inline int arch_is_kernel_data(unsigned long addr)
{
	return 0;
}
#endif

/*
 * Check if an address is part of freed initmem. This is needed on architectures
 * with virt == phys kernel mapping, for code that wants to check if an address
 * is part of a static object within [_stext, _end]. After initmem is freed,
 * memory can be allocated from it, and such allocations would then have
 * addresses within the range [_stext, _end].
 */
#ifndef arch_is_kernel_initmem_freed
static inline int arch_is_kernel_initmem_freed(unsigned long addr)
{
	return 0;
}
#endif

/**
 * memory_contains - checks if an object is contained within a memory region
 * @begin: virtual address of the beginning of the memory region
 * @end: virtual address of the end of the memory region
 * @virt: virtual address of the memory object
 * @size: size of the memory object
 *
 * Returns: true if the object specified by @virt and @size is entirely
 * contained within the memory region defined by @begin and @end, false
 * otherwise.
 */
static inline bool memory_contains(void *begin, void *end, void *virt,
				   size_t size)
{
	return virt >= begin && virt + size <= end;
}

/**
 * memory_intersects - checks if the region occupied by an object intersects
 *                     with another memory region
 * @begin: virtual address of the beginning of the memory regien
 * @end: virtual address of the end of the memory region
 * @virt: virtual address of the memory object
 * @size: size of the memory object
 *
 * Returns: true if an object's memory region, specified by @virt and @size,
 * intersects with the region specified by @begin and @end, false otherwise.
 */
static inline bool memory_intersects(void *begin, void *end, void *virt,
				     size_t size)
{
	void *vend = virt + size;

	return (virt >= begin && virt < end) || (vend >= begin && vend < end);
}

/**
 * init_section_contains - checks if an object is contained within the init
 *                         section
 * @virt: virtual address of the memory object
 * @size: size of the memory object
 *
 * Returns: true if the object specified by @virt and @size is entirely
 * contained within the init section, false otherwise.
 */
static inline bool init_section_contains(void *virt, size_t size)
{
	return memory_contains(__init_begin, __init_end, virt, size);
}

/**
 * init_section_intersects - checks if the region occupied by an object
 *                           intersects with the init section
 * @virt: virtual address of the memory object
 * @size: size of the memory object
 *
 * Returns: true if an object's memory region, specified by @virt and @size,
 * intersects with the init section, false otherwise.
 */
static inline bool init_section_intersects(void *virt, size_t size)
{
	return memory_intersects(__init_begin, __init_end, virt, size);
}

/**
 * is_kernel_rodata - checks if the pointer address is located in the
 *                    .rodata section
 *
 * @addr: address to check
 *
 * Returns: true if the address is located in .rodata, false otherwise.
 */
static inline bool is_kernel_rodata(unsigned long addr)
{
	return addr >= (unsigned long)__start_rodata &&
	       addr < (unsigned long)__end_rodata;
}

#endif /* _ASM_GENERIC_SECTIONS_H_ */

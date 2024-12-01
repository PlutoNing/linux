// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1995  Linus Torvalds
 *  Copyright (C) 2001, 2002 Andi Kleen, SuSE Labs.
 *  Copyright (C) 2008-2009, Red Hat Inc., Ingo Molnar
 */
#include <linux/sched.h>		/* test_thread_flag(), ...	*/
#include <linux/sched/task_stack.h>	/* task_stack_*(), ...		*/
#include <linux/kdebug.h>		/* oops_begin/end, ...		*/
#include <linux/extable.h>		/* search_exception_tables	*/
#include <linux/memblock.h>		/* max_low_pfn			*/
#include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
#include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
#include <linux/perf_event.h>		/* perf_sw_event		*/
#include <linux/hugetlb.h>		/* hstate_index_to_shift	*/
#include <linux/prefetch.h>		/* prefetchw			*/
#include <linux/context_tracking.h>	/* exception_enter(), ...	*/
#include <linux/uaccess.h>		/* faulthandler_disabled()	*/
#include <linux/efi.h>			/* efi_recover_from_page_fault()*/
#include <linux/mm_types.h>

#include <asm/cpufeature.h>		/* boot_cpu_has, ...		*/
#include <asm/traps.h>			/* dotraplinkage, ...		*/
#include <asm/pgalloc.h>		/* pgd_*(), ...			*/
#include <asm/fixmap.h>			/* VSYSCALL_ADDR		*/
#include <asm/vsyscall.h>		/* emulate_vsyscall		*/
#include <asm/vm86.h>			/* struct vm86			*/
#include <asm/mmu_context.h>		/* vma_pkey()			*/
#include <asm/efi.h>			/* efi_recover_from_page_fault()*/
#include <asm/desc.h>			/* store_idt(), ...		*/
#include <asm/cpu_entry_area.h>		/* exception stack		*/

#define CREATE_TRACE_POINTS
#include <asm/trace/exceptions.h>

/*
 * Returns 0 if mmiotrace is disabled, or if the fault is not
 * handled by mmiotrace:
 返回值说明：
  * 如果 mmiotrace 已禁用，或者故障未由 mmiotrace 处理，则返回 0：
 */
 /* kmmio是什么? kmmio 是内核内存输入输出（Kernel Memory-Mapped I/O）的缩写。
 它是一种技术，用于在内核空间中访问内存映射的 I/O 设备。通过 kmmio，
 内核可以直接读取和写入硬件设备的寄存器或内存，从而实现对硬件的控制和数据传输。*/
static nokprobe_inline int
kmmio_fault(struct pt_regs *regs, unsigned long addr)
{
	if (unlikely(is_kmmio_active()))
		if (kmmio_handler(regs, addr) == 1)
			return -1;
	return 0;
}

/*
instr是指令的地址,opcode是指令的值
函数作用是检查指令是否是预取指令,原理是根据指令的高四位和低四位来判断.
 * Prefetch quirks:
  作用:预取异常
 *
 * 32-bit mode:
 *
 *   Sometimes AMD Athlon/Opteron CPUs report invalid exceptions on prefetch.
 *   Check that here and ignore it.
 *	翻译:有时 AMD Athlon/Opteron CPU 在预取时会报告无效异常。在这里检查并忽略它。
 * 64-bit mode:
 *
 *   Sometimes the CPU reports invalid exceptions on prefetch.
 *   Check that here and ignore it.
 *	翻译:有时 CPU 在预取时会报告无效异常。在这里检查并忽略它。
 * Opcode checker based on code by Richard Brunner.
 */
static inline int
check_prefetch_opcode(struct pt_regs *regs, unsigned char *instr,
		      unsigned char opcode, int *prefetch)
{
	unsigned char instr_hi = opcode & 0xf0; //取高四位
	unsigned char instr_lo = opcode & 0x0f;//取低四位


	switch (instr_hi) {
	case 0x20:
	case 0x30:
		/*
		 * Values 0x26,0x2E,0x36,0x3E are valid x86 prefixes.
		 * In X86_64 long mode, the CPU will signal invalid
		 * opcode if some of these prefixes are present so
		 * X86_64 will never get here anyway
		 意思是说这些值是有效的x86前缀。在X86_64长模式下，如果存在这些前缀，
		 CPU 将发出无效的操作码信号，因此 X86_64 不会到达这里

		 */
		return ((instr_lo & 7) == 0x6);//
#ifdef CONFIG_X86_64
	case 0x40:
		/*
		 * In AMD64 long mode 0x40..0x4F are valid REX prefixes
		 * Need to figure out under what instruction mode the
		 * instruction was issued. Could check the LDT for lm,
		 * but for now it's good enough to assume that long
		 * mode only uses well known segments or kernel.
		 意思是说在 AMD64 长模式下，0x40..0x4F 是有效的 REX 前缀
		 需要弄清楚指令是在什么模式下发出的。可以检查 LDT 是否具有 lm，
		 但目前假设长模式只使用众所周知的段或内核就足够了。
		 REX表示寄存器扩展前缀,用于64位模式下的寄存器扩展,用于扩展寄存器的位数.
		 这里的lm表示long mode,长模式.
		 */
		return (!user_mode(regs) || user_64bit_mode(regs));
#endif
	case 0x60:
		/* 0x64 thru 0x67 are valid prefixes in all modes.
		 hi是6的指令中,64和67是有效的前缀 
		 */
		return (instr_lo & 0xC) == 0x4;//
	case 0xF0:
		/* 0xF0, 0xF2, 0xF3 are valid prefixes in all modes. */
		return !instr_lo || (instr_lo>>1) == 1; //只有当instr_lo=0,2,3时才返回1.
	case 0x00:
		/* Prefetch instruction is 0x0F0D or 0x0F18 */
		if (probe_kernel_address(instr, opcode))
			return 0;

		*prefetch = (instr_lo == 0xF) &&
			(opcode == 0x0D || opcode == 0x18);
		//prefetch是指令是否是预取指令,也就是说是不是0x0F0D或者0x0F18
		return 0;
	default:
		return 0;
	}
}

//检查是否是预取指令,如果是,返回prefetch=1,也就是说指令是不是0x0F0D或者0x0F18
static int
is_prefetch(struct pt_regs *regs, unsigned long error_code, unsigned long addr)
{
	unsigned char *max_instr;
	unsigned char *instr;
	int prefetch = 0;

	/*
	 * If it was a exec (instruction fetch) fault on NX page, then
	 * do not ignore the fault:
	  如果是在 NX 页上发生的执行（指令获取）故障，则不要忽略该故障：
	 */
	if (error_code & X86_PF_INSTR)
		return 0;

	instr = (void *)convert_ip_to_linear(current, regs);//获取当前指令的线性地址
	max_instr = instr + 15;//加十五是因为一条指令最多15个字节

	if (user_mode(regs) && instr >= (unsigned char *)TASK_SIZE_MAX)//如果是用户模式并且指令地址大于TASK_SIZE_MAX
		return 0;//返回0

	while (instr < max_instr) {
		unsigned char opcode;

		if (probe_kernel_address(instr, opcode)) //读取指令到opcode
			break;

		instr++; //指令地址+1,为了读取下一条指令

		//instr是指令的地址,opcode是指令的值
		if (!check_prefetch_opcode(regs, instr, opcode, &prefetch))
			break; //如果不是预取指令,则跳出循环, prefetch表示是否是预取指令,
		//也就是说是不是0x0F0D或者0x0F18
	}

	return prefetch;
}

DEFINE_SPINLOCK(pgd_lock);
LIST_HEAD(pgd_list);

#ifdef CONFIG_X86_32
static inline pmd_t *vmalloc_sync_one(pgd_t *pgd, unsigned long address)
{
	unsigned index = pgd_index(address);
	pgd_t *pgd_k;
	p4d_t *p4d, *p4d_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	pgd += index;
	pgd_k = init_mm.pgd + index;

	if (!pgd_present(*pgd_k))
		return NULL;

	/*
	 * set_pgd(pgd, *pgd_k); here would be useless on PAE
	 * and redundant with the set_pmd() on non-PAE. As would
	 * set_p4d/set_pud.
	 */
	p4d = p4d_offset(pgd, address);
	p4d_k = p4d_offset(pgd_k, address);
	if (!p4d_present(*p4d_k))
		return NULL;

	pud = pud_offset(p4d, address);
	pud_k = pud_offset(p4d_k, address);
	if (!pud_present(*pud_k))
		return NULL;

	pmd = pmd_offset(pud, address);
	pmd_k = pmd_offset(pud_k, address);

	if (pmd_present(*pmd) != pmd_present(*pmd_k))
		set_pmd(pmd, *pmd_k);

	if (!pmd_present(*pmd_k))
		return NULL;
	else
		BUG_ON(pmd_pfn(*pmd) != pmd_pfn(*pmd_k));

	return pmd_k;
}

void vmalloc_sync_all(void)
{
	unsigned long address;

	if (SHARED_KERNEL_PMD)
		return;

	for (address = VMALLOC_START & PMD_MASK;
	     address >= TASK_SIZE_MAX && address < FIXADDR_TOP;
	     address += PMD_SIZE) {
		struct page *page;

		spin_lock(&pgd_lock);
		list_for_each_entry(page, &pgd_list, lru) {
			spinlock_t *pgt_lock;

			/* the pgt_lock only for Xen */
			pgt_lock = &pgd_page_get_mm(page)->page_table_lock;

			spin_lock(pgt_lock);
			vmalloc_sync_one(page_address(page), address);
			spin_unlock(pgt_lock);
		}
		spin_unlock(&pgd_lock);
	}
}

/*
 * 32-bit:
 *
 *   Handle a fault on the vmalloc or module mapping area
 */
static noinline int vmalloc_fault(unsigned long address)
{
	unsigned long pgd_paddr;
	pmd_t *pmd_k;
	pte_t *pte_k;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	/*
	 * Synchronize this task's top level page-table
	 * with the 'reference' page table.
	 *
	 * Do _not_ use "current" here. We might be inside
	 * an interrupt in the middle of a task switch..
	 */
	pgd_paddr = read_cr3_pa();
	pmd_k = vmalloc_sync_one(__va(pgd_paddr), address);
	if (!pmd_k)
		return -1;

	if (pmd_large(*pmd_k))
		return 0;

	pte_k = pte_offset_kernel(pmd_k, address);
	if (!pte_present(*pte_k))
		return -1;

	return 0;
}
NOKPROBE_SYMBOL(vmalloc_fault);

/*
 * Did it hit the DOS screen memory VA from vm86 mode?
 */
static inline void
check_v8086_mode(struct pt_regs *regs, unsigned long address,
		 struct task_struct *tsk)
{
#ifdef CONFIG_VM86
	unsigned long bit;

	if (!v8086_mode(regs) || !tsk->thread.vm86)
		return;

	bit = (address - 0xA0000) >> PAGE_SHIFT;
	if (bit < 32)
		tsk->thread.vm86->screen_bitmap |= 1 << bit;
#endif
}

static bool low_pfn(unsigned long pfn)
{
	return pfn < max_low_pfn;
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3_pa());
	pgd_t *pgd = &base[pgd_index(address)];
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

#ifdef CONFIG_X86_PAE
	pr_info("*pdpt = %016Lx ", pgd_val(*pgd));
	if (!low_pfn(pgd_val(*pgd) >> PAGE_SHIFT) || !pgd_present(*pgd))
		goto out;
#define pr_pde pr_cont
#else
#define pr_pde pr_info
#endif
	p4d = p4d_offset(pgd, address);
	pud = pud_offset(p4d, address);
	pmd = pmd_offset(pud, address);
	pr_pde("*pde = %0*Lx ", sizeof(*pmd) * 2, (u64)pmd_val(*pmd));
#undef pr_pde

	/*
	 * We must not directly access the pte in the highpte
	 * case if the page table is located in highmem.
	 * And let's rather not kmap-atomic the pte, just in case
	 * it's allocated already:
	 */
	if (!low_pfn(pmd_pfn(*pmd)) || !pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	pr_cont("*pte = %0*Lx ", sizeof(*pte) * 2, (u64)pte_val(*pte));
out:
	pr_cont("\n");
}

#else /* CONFIG_X86_64: */

void vmalloc_sync_all(void)
{
	sync_global_pgds(VMALLOC_START & PGDIR_MASK, VMALLOC_END);
}

/*
 * 64-bit:
 *
 *   Handle a fault on the vmalloc area
 处理和 vmalloc 区域相关的故障
 返回值说明：
 */
static noinline int vmalloc_fault(unsigned long address)
{
	pgd_t *pgd, *pgd_k;
	p4d_t *p4d, *p4d_k;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* Make sure we are in vmalloc area:
	如果不在 vmalloc 区域内，则返回 -1
	*/
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	/*
	 * Copy kernel mappings over when needed. This can also
	 * happen within a race in page table update. In the later
	 * case just flush:
	 */
	pgd = (pgd_t *)__va(read_cr3_pa()) + pgd_index(address);// 读取当前进程的页目录表
	pgd_k = pgd_offset_k(address); // 读取内核页目录表
	if (pgd_none(*pgd_k))
		return -1;

	if (pgtable_l5_enabled()) {
		if (pgd_none(*pgd)) {
			set_pgd(pgd, *pgd_k);
			arch_flush_lazy_mmu_mode();
		} else {
			BUG_ON(pgd_page_vaddr(*pgd) != pgd_page_vaddr(*pgd_k));
		}
	}

	/* With 4-level paging, copying happens on the p4d level. */
	p4d = p4d_offset(pgd, address); //读取当前进程的p4d
	p4d_k = p4d_offset(pgd_k, address);//读取内核的p4d
	if (p4d_none(*p4d_k))
		return -1;

	if (p4d_none(*p4d) && !pgtable_l5_enabled()) {
		set_p4d(p4d, *p4d_k);
		arch_flush_lazy_mmu_mode();
	} else {
		BUG_ON(p4d_pfn(*p4d) != p4d_pfn(*p4d_k));
	}

	BUILD_BUG_ON(CONFIG_PGTABLE_LEVELS < 4);

	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return -1;

	if (pud_large(*pud))
		return 0;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return -1;

	if (pmd_large(*pmd))
		return 0;

	pte = pte_offset_kernel(pmd, address);//一直读取出pte
	if (!pte_present(*pte))
		return -1;//最终判断的是pte是否存在

	return 0;
}
NOKPROBE_SYMBOL(vmalloc_fault);

#ifdef CONFIG_CPU_SUP_AMD
static const char errata93_warning[] =
KERN_ERR 
"******* Your BIOS seems to not contain a fix for K8 errata #93\n"
"******* Working around it, but it may cause SEGVs or burn power.\n"
"******* Please consider a BIOS update.\n"
"******* Disabling USB legacy in the BIOS may also help.\n";
#endif

/*
 * No vm86 mode in 64-bit mode:
 */
static inline void
check_v8086_mode(struct pt_regs *regs, unsigned long address,
		 struct task_struct *tsk)
{
}

static int bad_address(void *p)
{
	unsigned long dummy;

	return probe_kernel_address((unsigned long *)p, dummy);
}

/* dump页表 */
static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3_pa());
	pgd_t *pgd = base + pgd_index(address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto bad;

	pr_info("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (bad_address(p4d))
		goto bad;

	pr_cont("P4D %lx ", p4d_val(*p4d));
	if (!p4d_present(*p4d) || p4d_large(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (bad_address(pud))
		goto bad;

	pr_cont("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto bad;

	pr_cont("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto bad;

	pr_cont("PTE %lx", pte_val(*pte));
out:
	pr_cont("\n");
	return;
bad:
	pr_info("BAD\n");
}

#endif /* CONFIG_X86_64 */

/*

 * Workaround for K8 erratum #93 & buggy BIOS.
 *	对 K8 错误 #93 和有缺陷的 BIOS 的解决方法。
 * BIOS SMM functions are required to use a specific workaround
 * to avoid corruption of the 64bit RIP register on C stepping K8.
 *这个错误是指在K8处理器上，当发生异常时，处理器会将RIP寄存器的高32位清零，导致异常处理错误。
 * A lot of BIOS that didn't get tested properly miss this.
 *	很多没有经过充分测试的 BIOS 都会忽略这个问题。
 * The OS sees this as a page fault with the upper 32bits of RIP cleared.
 * Try to work around it here.
 *		尝试在这里解决这个问题。
 * Note we only handle faults in kernel here.
 * Does nothing on 32-bit.
	 *		在这里只处理内核中的故障。,在32位上不做任何事情。
 */
static int is_errata93(struct pt_regs *regs, unsigned long address)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_CPU_SUP_AMD)
	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD
	    || boot_cpu_data.x86 != 0xf)
		return 0;  //只处理AMD

	if (address != regs->ip)
		return 0;

	if ((address >> 32) != 0)
		return 0; //说明只处理32位的地址?

	address |= 0xffffffffUL << 32; //将高32位设置为1
	if ((address >= (u64)_stext && address <= (u64)_etext) ||  //在代码段
	    (address >= MODULES_VADDR && address <= MODULES_END)) { //或者在模块区
		printk_once(errata93_warning);
		regs->ip = address; //设置ip为address,为了跳转到正确的地址
		return 1;
	}
#endif
	return 0;
}

/*
 * Work around K8 erratum #100 K8 in compat mode occasionally jumps
 * to illegal addresses >4GB.
 *
 * We catch this in the page fault handler because these addresses
 * are not reachable. Just detect this case and return.  Any code
 * segment in LDT is compatibility mode.
 */
static int is_errata100(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_64
	if ((regs->cs == __USER32_CS || (regs->cs & (1<<2))) && (address >> 32))
		return 1;
#endif
	return 0;
}

static int is_f00f_bug(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_F00F_BUG
	unsigned long nr;

	/*
	 * Pentium F0 0F C7 C8 bug workaround:
	 */
	if (boot_cpu_has_bug(X86_BUG_F00F)) {
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return 1;
		}
	}
#endif
	return 0;
}

/* 参数中gdt是全局描述符表
name是字符串,表示是什么表
index是索引,表示ldt或者tss的索引

作用是显示ldt或者tss的信息
 */
static void show_ldttss(const struct desc_ptr *gdt, const char *name, u16 index)
{
	u32 offset = (index >> 3) * sizeof(struct desc_struct); //计算偏移
	//desc的组成是limit0,base0,base1,type,p,limit1,avl,l,db,g,base2,base3巴拉巴拉

	unsigned long addr;
	struct ldttss_desc desc;

	if (index == 0) {
		pr_alert("%s: NULL\n", name);
		return;
	}

	if (offset + sizeof(struct ldttss_desc) >= gdt->size) {
		pr_alert("%s: 0x%hx -- out of bounds\n", name, index);
		return;
	}

	if (probe_kernel_read(&desc, (void *)(gdt->address + offset),
			      sizeof(struct ldttss_desc))) { //读取出desc
		pr_alert("%s: 0x%hx -- GDT entry is not readable\n",
			 name, index);
		return;
	}

	addr = desc.base0 | (desc.base1 << 16) | ((unsigned long)desc.base2 << 24);
#ifdef CONFIG_X86_64
	addr |= ((u64)desc.base3 << 32);
#endif
	pr_alert("%s: 0x%hx -- base=0x%lx limit=0x%x\n",
		 name, index, addr, (desc.limit0 | (desc.limit1 << 16)));
}

//
static void
show_fault_oops(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	if (!oops_may_print())
		return;

	if (error_code & X86_PF_INSTR) {
		unsigned int level;
		pgd_t *pgd;
		pte_t *pte;

		pgd = __va(read_cr3_pa()); //读取当前进程的页目录表
		pgd += pgd_index(address); //获取页目录表的索引

		pte = lookup_address_in_pgd(pgd, address, &level);

		if (pte && pte_present(*pte) && !pte_exec(*pte))
		//说明要执行不可执行
			pr_crit("kernel tried to execute NX-protected page - exploit attempt? (uid: %d)\n",
				from_kuid(&init_user_ns, current_uid()));

		if (pte && pte_present(*pte) && pte_exec(*pte) &&
				(pgd_flags(*pgd) & _PAGE_USER) &&
				(__read_cr4() & X86_CR4_SMEP)) //说明是用户空间代码,并且可执行,并且SMEP开启

			pr_crit("unable to execute userspace code (SMEP?) (uid: %d)\n",
				from_kuid(&init_user_ns, current_uid()));
	}

	if (address < PAGE_SIZE && !user_mode(regs))
		pr_alert("BUG: kernel NULL pointer dereference, address: %px\n",
			(void *)address);
	else
		pr_alert("BUG: unable to handle page fault for address: %px\n",
			(void *)address);

	pr_alert("#PF: %s %s in %s mode\n",
		 (error_code & X86_PF_USER)  ? "user" : "supervisor",
		 (error_code & X86_PF_INSTR) ? "instruction fetch" :
		 (error_code & X86_PF_WRITE) ? "write access" :
					       "read access",
			     user_mode(regs) ? "user" : "kernel");


	pr_alert("#PF: error_code(0x%04lx) - %s\n", error_code,
		 !(error_code & X86_PF_PROT) ? "not-present page" :
		 (error_code & X86_PF_RSVD)  ? "reserved bit violation" :
		 (error_code & X86_PF_PK)    ? "protection keys violation" :
					       "permissions violation");

	if (!(error_code & X86_PF_USER) && user_mode(regs)) {//如果不是用户模式,但是regs是用户模式?
		struct desc_ptr idt, gdt;
		u16 ldtr, tr;

		/*
		 * This can happen for quite a few reasons.  The more obvious
		 * ones are faults accessing the GDT, or LDT.  Perhaps
		 * surprisingly, if the CPU tries to deliver a benign or
		 * contributory exception from user code and gets a page fault
		 * during delivery, the page fault can be delivered as though
		 * it originated directly from user code.  This could happen
		 * due to wrong permissions on the IDT, GDT, LDT, TSS, or
		 * kernel or IST stack.
		   意思是说这可能有很多原因。更明显的原因是访问 GDT 或 LDT 时发生故障。
		   也许令人惊讶的是，如果 CPU 尝试从用户代码传递良性或有益的异常，并在传递过程中发生页面故障，
		   则页面故障可以被传递为直接源自用户代码。这可能是由于 IDT、GDT、LDT、TSS 或内核或 IST 堆栈的错误权限引起的。

		 */
		store_idt(&idt); //读取IDT

		/* Usable even on Xen PV -- it's just slow. */
		native_store_gdt(&gdt); //读取GDT

		pr_alert("IDT: 0x%lx (limit=0x%hx) GDT: 0x%lx (limit=0x%hx)\n",
			 idt.address, idt.size, gdt.address, gdt.size);

		store_ldt(ldtr); //读取LDT
		show_ldttss(&gdt, "LDTR", ldtr); //此时ldtr是LDT的索引

		store_tr(tr);
		show_ldttss(&gdt, "TR", tr);
	}

	dump_pagetable(address);
}

/* 报告页表的错误 */
static noinline void
pgtable_bad(struct pt_regs *regs, unsigned long error_code,
	    unsigned long address)
{
	struct task_struct *tsk;
	unsigned long flags;
	int sig;

	flags = oops_begin();
	tsk = current;
	sig = SIGKILL;

	printk(KERN_ALERT "%s: Corrupted page table at address %lx\n",
	       tsk->comm, address);
	dump_pagetable(address);

	if (__die("Bad pagetable", regs, error_code))
		sig = 0;

	oops_end(flags, regs, sig);
}

static void set_signal_archinfo(unsigned long address,
				unsigned long error_code)
{
	struct task_struct *tsk = current;

	/*
	 * To avoid leaking information about the kernel page
	 * table layout, pretend that user-mode accesses to
	 * kernel addresses are always protection faults.
	 *
	 * NB: This means that failed vsyscalls with vsyscall=none
	 * will have the PROT bit.  This doesn't leak any
	 * information and does not appear to cause any problems.
	 */
	if (address >= TASK_SIZE_MAX)
		error_code |= X86_PF_PROT;

	tsk->thread.trap_nr = X86_TRAP_PF;
	tsk->thread.error_code = error_code | X86_PF_USER;
	tsk->thread.cr2 = address;
}

/*  */
static noinline void
no_context(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, int signal, int si_code)
{
	struct task_struct *tsk = current;
	unsigned long flags;
	int sig;

	if (user_mode(regs)) {
		/*
		 * This is an implicit supervisor-mode access from user
		 * mode.  Bypass all the kernel-mode recovery code and just
		 * OOPS.
		到这里说明
		 */
		goto oops;
	}

	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs, X86_TRAP_PF, error_code, address)) {//表示是否有异常处理程序
		/*
		 * Any interrupt that takes a fault gets the fixup. This makes
		 * the below recursive fault logic only apply to a faults from
		 * task context. 
		意思就是如果处于中断上下文，那么就不会进入下面的逻辑
		因为
		 */
		if (in_interrupt())
			return;

		/*
		 * Per the above we're !in_interrupt(), aka. task context.
		  
		 * In this case we need to make sure we're not recursively
		 * faulting through the emulate_vsyscall() logic.
		 
		 */
		if (current->thread.sig_on_uaccess_err && signal) {
			set_signal_archinfo(address, error_code);

			/* XXX: hwpoison faults will set the wrong code. */
			force_sig_fault(signal, si_code, (void __user *)address);
		}

		/*
		 * Barring that, we can do the fixup and be happy.
		 */
		return;
	}

#ifdef CONFIG_VMAP_STACK
/* 用于控制是否启用基于 vmalloc 的内核栈 */
	/*
	 * Stack overflow?  During boot, we can fault near the initial
	 * stack in the direct map, but that's not an overflow -- check
	 * that we're in vmalloc space to avoid this.
     翻译理解:堆栈溢出？在引导过程中，我们可以在直接映射中的初始堆栈附近发生故障，
	 但这不是溢出-检查我们是否在vmalloc空间中以避免这种情况。
	  */
	if (is_vmalloc_addr((void *)address) &&
	    (((unsigned long)tsk->stack - 1 - address < PAGE_SIZE) ||
	     address - ((unsigned long)tsk->stack + THREAD_SIZE) < PAGE_SIZE)) {
			//进入if说明,是vmalloc地址,并且addr位于栈的附近.
			//计算方式为

			//获取DF stack的地址?
		unsigned long stack = __this_cpu_ist_top_va(DF) - sizeof(void *);
		/*
		 * We're likely to be running with very little stack space
		 * left.  It's plausible that we'd hit this condition but
		 * double-fault even before we get this far, in which case
		 * we're fine: the double-fault handler will deal with it.
		 *意思是说，我们可能在剩余的堆栈空间很少的情况下运行。
		 * 可能会在这种情况下触发此条件，但是在我们走到这一步之前甚至会发生双重故障，
		 * 在这种情况下，我们没问题：双重故障处理程序将处理它。
		 
		 * We don't want to make it all the way into the oops code
		 * and then double-fault, though, because we're likely to
		 * break the console driver and lose most of the stack dump.
		 *我们不希望完全进入oops代码，然后发生双重故障，因为我们很可能会破坏控制台驱动程序并丢失大部分堆栈转储。
		 */
		 /* 
		 		asm volatile ("movq %[stack], %%rsp\n\t"
			      "call handle_stack_overflow\n\t"
			      "1: jmp 1b"
			      : ASM_CALL_CONSTRAINT
			      : "D" ("kernel stack overflow (page fault)"),
				"S" (regs), "d" (address),
				[stack] "rm" (stack));
		 
		  */
		asm volatile ("movq %[stack], %%rsp\n\t"
			      "call handle_stack_overflow\n\t"
			      "1: jmp 1b"
			      : ASM_CALL_CONSTRAINT
			      : "D" ("kernel stack overflow (page fault)"),
				"S" (regs), "d" (address),
				[stack] "rm" (stack));
		unreachable();
	}
#endif

	/*
	 * 32-bit:
	 *
	 *   Valid to do another page fault here, because if this fault
	 *   had been triggered by is_prefetch fixup_exception would have
	 *   handled it.
	 *
	 * 64-bit:
	 *
	 *   Hall of shame of CPU/BIOS bugs.

	 */
	if (is_prefetch(regs, error_code, address))//为什么是prefetch就返回了
		return;

	if (is_errata93(regs, address))
		return;

	/*
	 * Buggy firmware could access regions which might page fault, try to
	 * recover from such faults.
	 有错误的固件可能会访问可能会出现页面错误的区域，尝试从这样的错误中恢复。
	 */
	if (IS_ENABLED(CONFIG_EFI))
		efi_recover_from_page_fault(address);

oops:
	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice:
	 意思是说内核尝试访问一些错误的页面。我们将不得不以极端偏见终止事情：
	 走到这里就说明异常确实是由于内核的程序设计缺陷导致的了，内核将
	   产生一个oops，下面的工作就是打印CPU寄存器和内核态堆栈的信息到控制台并
	   终结当前的进程
	 */
	flags = oops_begin(); //作用是保存当前的中断状态，然后关闭中断

	show_fault_oops(regs, error_code, address); //打印错误信息

	if (task_stack_end_corrupted(tsk))
		printk(KERN_EMERG "Thread overran stack, or stack corrupted\n");

	sig = SIGKILL;
	if (__die("Oops", regs, error_code))
		sig = 0;

	/* Executive summary in case the body of the oops scrolled away

	 */
	printk(KERN_DEFAULT "CR2: %016lx\n", address);

	oops_end(flags, regs, sig);
}

/*
 * Print out info about fatal segfaults, if the show_unhandled_signals
 * sysctl is set:
 */
static inline void
show_signal_msg(struct pt_regs *regs, unsigned long error_code,
		unsigned long address, struct task_struct *tsk)
{
	const char *loglvl = task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG;

	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %px sp %px error %lx",
		loglvl, tsk->comm, task_pid_nr(tsk), address,
		(void *)regs->ip, (void *)regs->sp, error_code);

	print_vma_addr(KERN_CONT " in ", regs->ip);

	printk(KERN_CONT "\n");

	show_opcodes(regs, loglvl);
}

/*
 * The (legacy) vsyscall page is the long page in the kernel portion
 * of the address space that has user-accessible permissions.
	取出addr的前12位?，如果是0xfffff600?，那么就是vsyscall地址
	
 */
static bool is_vsyscall_vaddr(unsigned long vaddr)
{
	return unlikely((vaddr & PAGE_MASK) == VSYSCALL_ADDR);	/*  */
}

/*  */
static void
__bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		       unsigned long address, u32 pkey, int si_code)
{
	struct task_struct *tsk = current;

	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs) && (error_code & X86_PF_USER)) {/* 
	是user mode并且是user错误 */
		/*
		 * It's possible to have interrupts off here:
		 */
		local_irq_enable();

		/*
		 * Valid to do another page fault here because this one came
		 * from user space:
		 */
		if (is_prefetch(regs, error_code, address))
			return;

		if (is_errata100(regs, address))
			return;

		/*
		 * To avoid leaking information about the kernel page table
		 * layout, pretend that user-mode accesses to kernel addresses
		 * are always protection faults.
		 */
		if (address >= TASK_SIZE_MAX)
			error_code |= X86_PF_PROT;

		if (likely(show_unhandled_signals))
			show_signal_msg(regs, error_code, address, tsk);

		set_signal_archinfo(address, error_code);

		if (si_code == SEGV_PKUERR)
			force_sig_pkuerr((void __user *)address, pkey);

		force_sig_fault(SIGSEGV, si_code, (void __user *)address);

		return;
	}

	if (is_f00f_bug(regs, address))
		return;

	no_context(regs, error_code, address, SIGSEGV, si_code);
}

/* 如果do_page_fault()函数执行到了bad_area_nosemaphore()，那么就表明这次异常是由于对非法的地址访问造成的。在内核中产生这样的结果的情况一般有两种:

1.内核通过用户空间传递的系统调用参数，访问了无效的地址

2.内核的程序设计缺陷
第一种情况内核尚且能通过异常修正机制来进行修复，而第二种情况就会导致OOPS错误了，内核将强制用SIGKILL结束当前进程。 */
static noinline void
bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		     unsigned long address)
{
	__bad_area_nosemaphore(regs, error_code, address, 0, SEGV_MAPERR);
}

static void
__bad_area(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, u32 pkey, int si_code)
{
	struct mm_struct *mm = current->mm;
	/*
	 * Something tried to access memory that isn't in our memory map..
	 * Fix it, but check if it's kernel or user first..
	 */
	up_read(&mm->mmap_sem);

	__bad_area_nosemaphore(regs, error_code, address, pkey, si_code);
}

static noinline void
bad_area(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	__bad_area(regs, error_code, address, 0, SEGV_MAPERR);
}

static inline bool bad_area_access_from_pkeys(unsigned long error_code,
		struct vm_area_struct *vma)
{
	/* This code is always called on the current mm */
	bool foreign = false;

	if (!boot_cpu_has(X86_FEATURE_OSPKE))
		return false;
	if (error_code & X86_PF_PK)
		return true;
	/* this checks permission keys on the VMA: */
	if (!arch_vma_access_permitted(vma, (error_code & X86_PF_WRITE),
				       (error_code & X86_PF_INSTR), foreign))
		return true;
	return false;
}

static noinline void
bad_area_access_error(struct pt_regs *regs, unsigned long error_code,
		      unsigned long address, struct vm_area_struct *vma)
{
	/*
	 * This OSPKE check is not strictly necessary at runtime.
	 * But, doing it this way allows compiler optimizations
	 * if pkeys are compiled out.
	 */
	if (bad_area_access_from_pkeys(error_code, vma)) {
		/*
		 * A protection key fault means that the PKRU value did not allow
		 * access to some PTE.  Userspace can figure out what PKRU was
		 * from the XSAVE state.  This function captures the pkey from
		 * the vma and passes it to userspace so userspace can discover
		 * which protection key was set on the PTE.
		 *
		 * If we get here, we know that the hardware signaled a X86_PF_PK
		 * fault and that there was a VMA once we got in the fault
		 * handler.  It does *not* guarantee that the VMA we find here
		 * was the one that we faulted on.
		 *
		 * 1. T1   : mprotect_key(foo, PAGE_SIZE, pkey=4);
		 * 2. T1   : set PKRU to deny access to pkey=4, touches page
		 * 3. T1   : faults...
		 * 4.    T2: mprotect_key(foo, PAGE_SIZE, pkey=5);
		 * 5. T1   : enters fault handler, takes mmap_sem, etc...
		 * 6. T1   : reaches here, sees vma_pkey(vma)=5, when we really
		 *	     faulted on a pte with its pkey=4.
		 */
		u32 pkey = vma_pkey(vma);

		__bad_area(regs, error_code, address, pkey, SEGV_PKUERR);
	} else {
		__bad_area(regs, error_code, address, 0, SEGV_ACCERR);
	}
}

static void
do_sigbus(struct pt_regs *regs, unsigned long error_code, unsigned long address,
	  vm_fault_t fault)
{
	/* Kernel mode? Handle exceptions or die: */
	if (!(error_code & X86_PF_USER)) {
		no_context(regs, error_code, address, SIGBUS, BUS_ADRERR);
		return;
	}

	/* User-space => ok to do another page fault: */
	if (is_prefetch(regs, error_code, address))
		return;

	set_signal_archinfo(address, error_code);

#ifdef CONFIG_MEMORY_FAILURE
	if (fault & (VM_FAULT_HWPOISON|VM_FAULT_HWPOISON_LARGE)) {
		struct task_struct *tsk = current;
		unsigned lsb = 0;

		pr_err(
	"MCE: Killing %s:%d due to hardware memory corruption fault at %lx\n",
			tsk->comm, tsk->pid, address);
		if (fault & VM_FAULT_HWPOISON_LARGE)
			lsb = hstate_index_to_shift(VM_FAULT_GET_HINDEX(fault));
		if (fault & VM_FAULT_HWPOISON)
			lsb = PAGE_SHIFT;
		force_sig_mceerr(BUS_MCEERR_AR, (void __user *)address, lsb);
		return;
	}
#endif
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)address);
}

//处理内存故障
static noinline void
mm_fault_error(struct pt_regs *regs, unsigned long error_code,
	       unsigned long address, vm_fault_t fault)
{
	if (fatal_signal_pending(current) && !(error_code & X86_PF_USER)) {
		//如果当前有致命信号，并且不是用户模式
		no_context(regs, error_code, address, 0, 0);
		return;
	}

	if (fault & VM_FAULT_OOM) {
		/* Kernel mode? Handle exceptions or die: */
		if (!(error_code & X86_PF_USER)) {
			no_context(regs, error_code, address,
				   SIGSEGV, SEGV_MAPERR);
			return;
		}

		/*
		 * We ran out of memory, call the OOM killer, and return the
		 * userspace (which will retry the fault, or kill us if we got
		 * oom-killed):
		 */
		pagefault_out_of_memory();
	} else {
		if (fault & (VM_FAULT_SIGBUS|VM_FAULT_HWPOISON|
			     VM_FAULT_HWPOISON_LARGE))
			do_sigbus(regs, error_code, address, fault);
		else if (fault & VM_FAULT_SIGSEGV)
			bad_area_nosemaphore(regs, error_code, address);
		else
			BUG();
	}
}

//检查是否是虚假故障
//返回值说明:0是虚假故障
static int spurious_kernel_fault_check(unsigned long error_code, pte_t *pte)
{
	if ((error_code & X86_PF_WRITE) && !pte_write(*pte))//是写操作，但是pte不可写
		return 0;

	if ((error_code & X86_PF_INSTR) && !pte_exec(*pte))//是指令操作，但是pte不可执行
		return 0;

	return 1;
}

/*
 * Handle a spurious fault caused by a stale TLB entry.
 *作用是处理由于TLB条目过期导致的虚假故障?
 * This allows us to lazily refresh the TLB when increasing the
 * permissions of a kernel page (RO -> RW or NX -> X).  Doing it
 * eagerly is very expensive since that implies doing a full
 * cross-processor TLB flush, even if no stale TLB entries exist
 * on other processors.
 * 这允许我们在增加内核页的权限（RO -> RW 或 NX -> X）时延迟刷新TLB。
 * 这样做是非常昂贵的，因为这意味着即使在其他处理器上不存在过期的TLB条目，
 * 也需要执行完整的跨处理器TLB刷新。
 * Spurious faults may only occur if the TLB contains an entry with
 * fewer permission than the page table entry.  Non-present (P = 0)
 * and reserved bit (R = 1) faults are never spurious.
	 * 虚假故障只有在TLB中包含权限少于页表条目的条目时才会发生。
	 * 不存在（P = 0）和保留位（R = 1）故障永远不会是虚假的。
 * There are no security implications to leaving a stale TLB when
 * increasing the permissions on a page.
 *	在增加页面的权限时保留过期的TLB没有安全影响。
 * Returns non-zero if a spurious fault was handled, zero otherwise.
 *	如果处理了虚假故障，则返回非零值，否则返回零。
 * See Intel Developer's Manual Vol 3 Section 4.10.4.3, bullet 3
 * (Optional Invalidation).
  参考Intel开发人员手册第3卷
 */
static noinline int
spurious_kernel_fault(unsigned long error_code, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	/*
	 * Only writes to RO or instruction fetches from NX may cause
	 * spurious faults.
	 *  只有对RO的写入或从NX中提取指令才会导致虚假故障。
	 
	 
	 * These could be from user or supervisor accesses but the TLB
	 * is only lazily flushed after a kernel mapping protection
	 * change, so user accesses are not expected to cause spurious
	 * faults. 
	 * 这些可能来自用户或监管访问，但是只有在内核映射保护更改后才会延迟刷新TLB，
	 * 因此不希望用户访问导致虚假故障。
	 */
	if (error_code != (X86_PF_WRITE | X86_PF_PROT) &&
	    error_code != (X86_PF_INSTR | X86_PF_PROT))
		return 0;

	pgd = init_mm.pgd + pgd_index(address);//获取pgd
	if (!pgd_present(*pgd))
		return 0;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		return 0;

	if (p4d_large(*p4d))
		return spurious_kernel_fault_check(error_code, (pte_t *) p4d);

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return spurious_kernel_fault_check(error_code, (pte_t *) pud);

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return spurious_kernel_fault_check(error_code, (pte_t *) pmd);

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		return 0;
//一直获取到pte
	ret = spurious_kernel_fault_check(error_code, pte);
	if (!ret) //返回0说明具体就是写入不可写,执行不可执行
		return 0;

	/*
	 * Make sure we have permissions in PMD.
	 * If not, then there's a bug in the page tables:
	 */
	ret = spurious_kernel_fault_check(error_code, (pte_t *) pmd);
	WARN_ONCE(!ret, "PMD has incorrect permission bits\n");

	return ret;
}
NOKPROBE_SYMBOL(spurious_kernel_fault);

int show_unhandled_signals = 1;

/*  */
static inline int
access_error(unsigned long error_code, struct vm_area_struct *vma)
{
	/* This is only called for the current mm, so: */
	bool foreign = false;

	/*
	 * Read or write was blocked by protection keys.  This is
	 * always an unconditional error and can never result in
	 * a follow-up action to resolve the fault, like a COW.
	 处理了由于保护键（Protection Keys）导致的读写操作被阻止的情况。
	 保护键是一种内存保护机制，允许对内存页设置访问权限，从而防止未经授权的访问。

注释部分解释了当读写操作被保护键阻止时，这总是一个无条件的错误，
不能通过后续操作（例如写时复制，COW）来解决故障。换句话说，当发生这种类型的故障时，
系统无法采取任何补救措施来恢复正常操作。
	 */
	if (error_code & X86_PF_PK)
		return 1;

	/*
	 * Make sure to check the VMA so that we do not perform
	 * faults just to hit a X86_PF_PK as soon as we fill in a
	 * page.
	 */
	if (!arch_vma_access_permitted(vma, (error_code & X86_PF_WRITE),
				       (error_code & X86_PF_INSTR), foreign))
		return 1;

	if (error_code & X86_PF_WRITE) {/* 对写访问错误的检查 */
		/* write, present and write, not present: */
		if (unlikely(!(vma->vm_flags & VM_WRITE)))/* 但是vma不准写入 */
			return 1;

		return 0;
	}

	/* read, present: */
	if (unlikely(error_code & X86_PF_PROT))
		return 1;

	/* read, not present: */
	if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE))))
		return 1;

	return 0;
}

/* */
static int fault_in_kernel_space(unsigned long address)
{
	/*
	 * On 64-bit systems, the vsyscall page is at an address above
	 * TASK_SIZE_MAX, but is not considered part of the kernel
	 * address space. 
	 说明vsyscall页不是内核地址空间的一部分。
	 */
	if (IS_ENABLED(CONFIG_X86_64) && is_vsyscall_vaddr(address))
		return false;

	return address >= TASK_SIZE_MAX;// 说明是内核地址空间,返回1.因为内核地址
	//空间是从TASK_SIZE_MAX开始的?
}

/*
 * Called for all faults where 'address' is part of the kernel address
 * space.  Might get called for faults that originate from *code* that
 * ran in userspace or the kernel.
 
 意思就是address是内核地址空间的一部分，可能是用户空间的代码，也可能是内核空间的代码.
 */
static void
do_kern_addr_fault(struct pt_regs *regs, unsigned long hw_error_code,
		   unsigned long address)
{
	/*
	 * Protection keys exceptions only happen on user pages.  We
	 * have no user pages in the kernel portion of the address
	 * space, so do not expect them here.
	 保护键异常只会发生在用户页上。我们在地址空间的内核部分没有用户页，
	 */
	WARN_ON_ONCE(hw_error_code & X86_PF_PK);

	/*
	 * We can fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *要求错误码必须包含X86_PF_RSVD | X86_PF_USER | X86_PF_PROT
	 因为
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * Before doing this on-demand faulting, ensure that the
	 * fault is not any of the following:
	 * 1. A fault on a PTE with a reserved bit set.
	 * 2. A fault caused by a user-mode access.  (Do not demand-
	 *    fault kernel memory due to user-mode accesses).
	 * 3. A fault caused by a page-level protection violation.
	 *    (A demand fault would be on a non-present page which
	 *     would have X86_PF_PROT==0).
	 */
	if (!(hw_error_code & (X86_PF_RSVD | X86_PF_USER | X86_PF_PROT))) {//进入if说明
	//错误码不包含X86_PF_RSVD | X86_PF_USER | X86_PF_PROT,那就可能包含X86_PF_WRITE,
	//X86_PF_INSTR
		
		if (vmalloc_fault(address) >= 0) //说明对应的pte存在
			return;
	}

	/* Was the fault spurious, caused by lazy TLB invalidation?
	如果是虚假故障，由于延迟TLB失效引起的.*/
	if (spurious_kernel_fault(hw_error_code, address))/*  */
		return;
	/* 说明写入不可写,执行不可执行 */
	
	/* kprobes don't want to hook the spurious faults: */
	if (kprobe_page_fault(regs, X86_TRAP_PF))
		return;

	/*
	 * Note, despite being a "bad area", there are quite a few
	 * acceptable reasons to get here, such as erratum fixups
	 * and handling kernel code that can fault, like get_user().
	 * 
	  说明虽然是一个“坏区域”，但是有很多可以接受的原因会导致这种情况，
	  比如勘误修复和处理可能导致故障的内核代码，例如get_user()。
	 * Don't take the mm semaphore here. If we fixup a prefetch
	 * fault we could otherwise deadlock:
	 */
	bad_area_nosemaphore(regs, hw_error_code, address);
}
NOKPROBE_SYMBOL(do_kern_addr_fault);

/* Handle faults in the user portion of the address space
bad_area做什么的. */
static inline
void do_user_addr_fault(struct pt_regs *regs,
			unsigned long hw_error_code,
			unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	vm_fault_t fault, major = 0;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	tsk = current;
	mm = tsk->mm;

	/* kprobes don't want to hook the spurious faults: */
	if (unlikely(kprobe_page_fault(regs, X86_TRAP_PF)))
		return;

	/*
	 * Reserved bits are never expected to be set on
	 * entries in the user portion of the page tables.
	 */
	if (unlikely(hw_error_code & X86_PF_RSVD))/* 如果错误码涉及X86_PF_RSVD */
	/* 报告页表错误 */
		pgtable_bad(regs, hw_error_code, address);

	/*
	SMAP 是一种硬件特性，它用于防止内核模式代码（即操作系统内核）访问用户空间的内存。
	在启用 SMAP 的情况下，内核只能访问内核空间的地址，而不能直接访问用户空间的地址，
	从而增强了安全性。
如果 SMAP 被启用且内核尝试访问用户空间，会触发硬件错误，通常这种错误会表现为一个
页面错误（Page Fault）。
	 * If SMAP is on, check for invalid kernel (supervisor) access to user
	 * pages in the user address space.  The odd case here is WRUSS,
	 * which, according to the preliminary documentation, does not respect
	 * SMAP and will have the USER bit set so, in all cases, SMAP
	 * enforcement appears to be consistent with the USER bit.
	 */
	if (unlikely(cpu_feature_enabled(X86_FEATURE_SMAP) &&
		     !(hw_error_code & X86_PF_USER) &&
		     !(regs->flags & X86_EFLAGS_AC)))
	{
		bad_area_nosemaphore(regs, hw_error_code, address);
		return;
	}

	/*
	 * If we're in an interrupt, have no user context or are running
	 * in a region with pagefaults disabled then we must not take the fault
	 */
	if (unlikely(faulthandler_disabled() || !mm)) {
		bad_area_nosemaphore(regs, hw_error_code, address);
		return;
	}

	/*
	 * It's safe to allow irq's after cr2 has been saved and the
	 * vmalloc fault has been handled.
	 *
	 * User-mode registers count as a user access even for any
	 * potential system fault or CPU buglet:
	 */
	if (user_mode(regs)) {/* 如果位于用户模式 
	在用户模式下，故障处理允许中断，并标记该故障为用户模式故障。*/
		local_irq_enable();
		flags |= FAULT_FLAG_USER;
	} else {/* 内核模式的情况 */
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (hw_error_code & X86_PF_WRITE)
		flags |= FAULT_FLAG_WRITE;
	if (hw_error_code & X86_PF_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

#ifdef CONFIG_X86_64
	/*
	 * Faults in the vsyscall page might need emulation.  The
	 vsyscall 页面是一个特殊的内存区域，用于提供快速的系统调用接口。
	 它位于高地址（大于 PAGE_OFFSET），但被视为用户地址空间的一部分。
	 它没有一个“真实”的虚拟内存区域（VMA），因此在搜索 VMA 之前需要进行仿真处理。
	 * vsyscall page is at a high address (>PAGE_OFFSET), but is
	 * considered to be part of the user address space.
	 *
	 * The vsyscall page does not have a "real" VMA, so do this
	 * emulation before we go searching for VMAs.
	 *
	 * PKRU never rejects instruction fetches, so we don't need
	 * to consider the PF_PK bit.
	 */
	if (is_vsyscall_vaddr(address)) { /* 如果是vsyscall地址 检查故障地址是否位于 vsyscall 页面。 */
		if (emulate_vsyscall(hw_error_code, regs, address))	/* 仿真处理
		代码调用 emulate_vsyscall(hw_error_code, regs, address) 函数来仿真 vsyscall 操作。 */
			return;
	}
#endif

	/*
	 * Kernel-mode access to the user address space should only occur
	 * on well-defined single instructions listed in the exception
	 * tables.  But, an erroneous kernel fault occurring outside one of
	 * those areas which also holds mmap_sem might deadlock attempting
	 * to validate the fault against the address space.
	 *	内核模式访问用户地址空间应仅发生在异常表中列出的明确定义的单个指令执行
	 的时候。
	 * 但是，发生在这些区域之外的持有mmap_sem的错误内核故障，可能会在
	 尝试根据地址空间验证故障时发生死锁。
	 
	 * Only do the expensive exception table search when we might be at
	 * risk of a deadlock.  This happens if we
	 * 1. Failed to acquire mmap_sem, and
	 * 2. The access did not originate in userspace.
	 为了避免这种情况，只有在可能存在死锁风险时才搜索这个异常表。
	 具体来说，这种情况发生在以下两种条件同时满足时：
		未能获取 mmap_sem。
		访问不是源自用户空间。
	 */
	if (unlikely(!down_read_trylock(&mm->mmap_sem))) {/* trylock失败 */
		if (!user_mode(regs) && !search_exception_tables(regs->ip)) {
			/* 内核空间的访问,并且不是表内的指令 */
			/*
			 * Fault from code in kernel from
			 * which we do not expect faults.
			 */
			bad_area_nosemaphore(regs, hw_error_code, address);
			return;
		}
retry:
		down_read(&mm->mmap_sem);
	} else {/* try lock mmap_sem成功了. */
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
		might_sleep();
	}

	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, hw_error_code, address);
		return;
	}
	if (likely(vma->vm_start <= address))
		goto good_area;

	/*address在vma之前?说明没有申请这个内存空间?	
	*/
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {/* 很遗憾这个vma不能向下生长 */
		bad_area(regs, hw_error_code, address);
		return;
	}

	/* 准备向下扩展这个vma? */

	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, hw_error_code, address);
		return;
	}
	/* 扩展成功? */

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
/* 现在出错的地址就在这个vma里面了 */
good_area:

	/* 进行权限的检查 */
	if (unlikely(access_error(hw_error_code, vma))) {
		bad_area_access_error(regs, hw_error_code, address, vma);
		return;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.  Since we never set FAULT_FLAG_RETRY_NOWAIT, if
	 * we get VM_FAULT_RETRY back, the mmap_sem has been unlocked.
	 *	如果无法处理故障，确保优雅地退出，而不是无休止地重复故障。
	 * 由于我们从未设置 FAULT_FLAG_RETRY_NOWAIT，如果我们得到 VM_FAULT_RETRY，
	 * 则 mmap_sem 已被解锁。
	 
	 * Note that handle_userfault() may also release and reacquire mmap_sem
	 * (and not return with VM_FAULT_RETRY), when returning to userland to
	 * repeat the page fault later with a VM_FAULT_NOPAGE retval
	 * (potentially after handling any pending signal during the return to
	 * userland). The return to userland is identified whenever
	 * FAULT_FLAG_USER|FAULT_FLAG_KILLABLE are both set in flags.
		handle_userfault() 函数可能会释放并重新获取 mmap_sem（内存映射信号量）。
		这意味着在处理用户故障的过程中，函数可能会暂时释放对内存映射的锁定，
		然后在需要时重新获取锁定。这种操作可以避免长时间持有锁定，从而提高系统的并发性能。
	 */
	fault = handle_mm_fault(vma, address, flags);
	major |= fault & VM_FAULT_MAJOR;

	/*
	 * If we need to retry the mmap_sem has already been released,
	 * and if there is a fatal signal pending there is no guarantee
	 * that we made any progress. Handle this case first.
	 说明需要重试，mmap_sem已经被释放，如果有致命信号挂起，我们无法保证是否取得了任何进展。?
	 */
	if (unlikely(fault & VM_FAULT_RETRY)) {
		/* Retry at most once */
		if (flags & FAULT_FLAG_ALLOW_RETRY) {//只可以重试一次
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;
			if (!fatal_signal_pending(tsk))
				goto retry; //仅在没有致命信号挂起的情况下重试
		}
		//到这里说明重试次数用完了,并且没有重试成功

		/* User mode? Just return to handle the fatal exception
			如果是用户模式，只需返回以处理致命异常 
		 */
		if (flags & FAULT_FLAG_USER)
			return;

		/* Not returning to user mode? Handle exceptions or die:
			没有返回到用户模式？处理异常或死机：
		 */
		no_context(regs, hw_error_code, address, SIGBUS, BUS_ADRERR);
		return;
	}

	up_read(&mm->mmap_sem);

	if (unlikely(fault & VM_FAULT_ERROR)) {//出现了内存错误
		mm_fault_error(regs, hw_error_code, address, fault);
		return;
	}

	/*
	 * Major/minor page fault accounting. If any of the events
	 * returned VM_FAULT_MAJOR, we account it as a major fault.
	 */
	if (major) {
		tsk->maj_flt++;
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs, address);
	} else {
		tsk->min_flt++;
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs, address);
	}

	check_v8086_mode(regs, address, tsk);
}
NOKPROBE_SYMBOL(do_user_addr_fault);

/*
什么情况下触发这个函数?
 * Explicitly marked noinline such that the function tracer sees this as the
 * page_fault entry point.
 */
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long hw_error_code,
		unsigned long address)
{
	prefetchw(&current->mm->mmap_sem);

	if (unlikely(kmmio_fault(regs, address))) // kmmio_fault是什么?
	// 如果是kmmio_fault，那么直接返回
		return;

	/* Was the fault on kernel-controlled part of the address space? */
	if (unlikely(fault_in_kernel_space(address)))/*根据地址判断是否是内核空间的地址 */
		do_kern_addr_fault(regs, hw_error_code, address);
	else
		do_user_addr_fault(regs, hw_error_code, address);
}
NOKPROBE_SYMBOL(__do_page_fault);

static __always_inline void
trace_page_fault_entries(struct pt_regs *regs, unsigned long error_code,
			 unsigned long address)
{
	if (!trace_pagefault_enabled())
		return;

	if (user_mode(regs))
		trace_page_fault_user(address, regs, error_code);
	else
		trace_page_fault_kernel(address, regs, error_code);
}

/* 这个是什么pages_fault? */
dotraplinkage void
do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	enum ctx_state prev_state;

	prev_state = exception_enter();
	trace_page_fault_entries(regs, error_code, address);
	/* 执行函数 */
	__do_page_fault(regs, error_code, address);
	exception_exit(prev_state);
}
NOKPROBE_SYMBOL(do_page_fault);

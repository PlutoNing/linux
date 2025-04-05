// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqnr.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/*
 * /proc/interrupts

 中断的/proc/irq迭代的start函数
 */
static void *int_seq_start(struct seq_file *f, loff_t *pos)
{
	return (*pos <= nr_irqs) ? pos : NULL;
}
/* 
/proc/irq迭代的next函数
*/
static void *int_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos > nr_irqs)
		return NULL;
	return pos;
}

static void int_seq_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}
/* 
/proc/interrupts的seq ops
*/
static const struct seq_operations int_seq_ops = {
	.start = int_seq_start,
	.next  = int_seq_next,
	.stop  = int_seq_stop,
	.show  = show_interrupts
};
/* 
初始化/proc/interrupts
*/
static int __init proc_interrupts_init(void)
{
	proc_create_seq("interrupts", 0, NULL, &int_seq_ops);
	return 0;
}
fs_initcall(proc_interrupts_init);

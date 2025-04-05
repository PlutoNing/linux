// SPDX-License-Identifier: GPL-2.0
#include <linux/cpufreq.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

extern const struct seq_operations cpuinfo_op;
/* 对应着/proc/cpuinfo的seq ops */
static int cpuinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cpuinfo_op);
}
/* 
/proc/cpuinfo文件的fops
*/
static const struct proc_ops cpuinfo_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	// 关键路径, 打开seq file
	.proc_open	= cpuinfo_open,
	.proc_read_iter	= seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};
/* 
创建/proc/cpuinfo文件
 * 该文件的内容由cpuinfo_op结构体中的seq_operations结构体提供
 * cpuinfo_op结构体中的show函数会被调用来填充/proc/cpuinfo文件的内容
 * 该函数会遍历系统中的每个CPU，并输出其相关信息
*/
static int __init proc_cpuinfo_init(void)
{
	proc_create("cpuinfo", 0, NULL, &cpuinfo_proc_ops);
	return 0;
}
fs_initcall(proc_cpuinfo_init);

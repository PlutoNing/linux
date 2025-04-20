// SPDX-License-Identifier: GPL-2.0
/*
 * /proc/sys/fs shared sysctls
 *
 * These sysctls are shared between different filesystems.
 */
#include <linux/init.h>
#include <linux/sysctl.h>
/* 
当文件系统遇到无法映射到合法用户/组的 UID/GID（如 NFS 服务返回的无效 ID）时，
内核会将这些溢出的 ID 转换为 overflowuid/overflowgid 指定的值，通常用于 
​​兼容性处理​​ 或 ​​安全回退​​。
*/
static struct ctl_table fs_shared_sysctls[] = {
	{
		.procname	= "overflowuid",
		.data		= &fs_overflowuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
	{
		.procname	= "overflowgid",
		.data		= &fs_overflowgid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
	{ }
};
/* fs就这俩sysctl吗 */
static int __init init_fs_sysctls(void)
{
	register_sysctl_init("fs", fs_shared_sysctls);
	return 0;
}

early_initcall(init_fs_sysctls);

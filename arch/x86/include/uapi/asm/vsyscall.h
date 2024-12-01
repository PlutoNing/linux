/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_VSYSCALL_H
#define _UAPI_ASM_X86_VSYSCALL_H

enum vsyscall_num {
	__NR_vgettimeofday,
	__NR_vtime,
	__NR_vgetcpu,
};
/* 
二进制表示为:
1001 0000 0000 0000 0000 0000 0000 0000
 */
#define VSYSCALL_ADDR (-10UL << 20)	/* vsyscall base address */

#endif /* _UAPI_ASM_X86_VSYSCALL_H */

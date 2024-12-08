/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INSTRUCTION_POINTER_H
#define _LINUX_INSTRUCTION_POINTER_H

#include <asm/linkage.h>

/* _builtin_return_address(0) 是一个 GCC 内置函数，
返回当前函数的返回地址。参数 0 表示获取调用该函数的函数的返回地址。 */
#define _RET_IP_		(unsigned long)__builtin_return_address(0)

#ifndef _THIS_IP_
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#endif

#endif /* _LINUX_INSTRUCTION_POINTER_H */

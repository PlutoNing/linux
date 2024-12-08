/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_EMULATE_PREFIX_H
#define _ASM_X86_EMULATE_PREFIX_H

/*
 * Virt escape sequences to trigger instruction emulation;
 * ideally these would decode to 'whole' instruction and not destroy
 * the instruction stream; sadly this is not true for the 'kvm' one
 这些代码段定义了特定的虚拟化逃逸序列，用于触发指令仿真。这些序列通常在虚拟化环境中被使用，
 以便在特定条件下控制指令的执行流。
解析
ud2: 这是一个无效指令，用于生成一个未定义的操作码异常，通常用于调试或触发特定的异常处理。
它的机器码是 0x0f 0x0b。
.ascii "xen" 和 .ascii "kvm": 这些指令将字符串“xen”和“kvm”以 ASCII 格式存储在内存中，
后续的指令可以利用这些字符串进行区分或特定处理。
用途
虚拟化环境中的指令仿真: 这些序列可用于识别正在执行的代码是否在 Xen 或 KVM 虚拟化环境中，
从而触发相应的指令仿真机制。
指令流控制: 虽然理想情况下，这些序列应该能够解码为完整的指令，而不会破坏指令流，但实际情况中可能并非如此。
这意味着在解析和执行指令时需要特别小心，以确保不会干扰正常的指令流。
 
  :/
 */

#define __XEN_EMULATE_PREFIX  0x0f,0x0b,0x78,0x65,0x6e  /* ud2 ; .ascii "xen" */
#define __KVM_EMULATE_PREFIX  0x0f,0x0b,0x6b,0x76,0x6d	/* ud2 ; .ascii "kvm" */

#endif

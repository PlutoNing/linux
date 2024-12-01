/* include/linux/aio_abi.h
 *
 * Copyright 2000,2001,2002 Red Hat.
 *
 * Written by Benjamin LaHaise <bcrl@kvack.org>
 *
 * Distribute under the terms of the GPLv2 (see ../../COPYING) or under 
 * the following terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied.  Red Hat makes no representations about
 * the suitability of this software for any purpose.
 *
 * IN NO EVENT SHALL RED HAT BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
 * SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
 * THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF RED HAT HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * RED HAT DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND
 * RED HAT HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES,
 * ENHANCEMENTS, OR MODIFICATIONS.
 */
#ifndef __LINUX__AIO_ABI_H
#define __LINUX__AIO_ABI_H

#include <linux/types.h>
#include <linux/fs.h>
#include <asm/byteorder.h>

typedef __kernel_ulong_t aio_context_t;

//这些是iocb的命令
enum {
	IOCB_CMD_PREAD = 0, //读
	IOCB_CMD_PWRITE = 1, //写
	IOCB_CMD_FSYNC = 2, //fsync
	IOCB_CMD_FDSYNC = 3, //fdsync
	/* 4 was the experimental IOCB_CMD_PREADX */
	IOCB_CMD_POLL = 5, //poll
	IOCB_CMD_NOOP = 6, //空操作
	IOCB_CMD_PREADV = 7, //读
	IOCB_CMD_PWRITEV = 8, //写
};

/*
 * Valid flags for the "aio_flags" member of the "struct iocb".
 * 这是iocb的标志位，用于标识iocb的一些属性。
 * IOCB_FLAG_RESFD - Set if the "aio_resfd" member of the "struct iocb"
 *                   is valid.
 这个是用来标识aio_resfd是否有效。
 * IOCB_FLAG_IOPRIO - Set if the "aio_reqprio" member of the "struct iocb"
 *                    is valid.
 这个是用来标识aio_reqprio是否有效。
 */
#define IOCB_FLAG_RESFD		(1 << 0)
#define IOCB_FLAG_IOPRIO	(1 << 1)

/* read() from /dev/aio returns these structures. */
struct io_event {
	__u64		data;		/* the data field from the iocb */
	//可能是指向对应用户态iocb的内核态iocb的data字段
	__u64		obj;		/* what iocb this event came from
	可能是指向用户态的iocb指针 
	 */
	__s64		res;		/* result code for this event */
	__s64		res2;		/* secondary result */
};

/*
 * we always use a 64bit off_t when communicating
 * with userland.  its up to libraries to do the
 * proper padding and aio_error abstraction
 */

struct iocb {
	/* these are internal to the kernel/libc. */
	__u64	aio_data;	/* data to be returned in event's data */

#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __LITTLE_ENDIAN : defined(__LITTLE_ENDIAN)
	__u32	aio_key;	/* the kernel sets aio_key to the req #
	内核态submits请求后会往这里写入东西
	 */
	__kernel_rwf_t aio_rw_flags;	/* RWF_* flags */
#elif defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	__kernel_rwf_t aio_rw_flags;	/* RWF_* flags */
	__u32	aio_key;	/* the kernel sets aio_key to the req # */
#else
#error edit for your odd byteorder.
#endif

	/* common fields */
	__u16	aio_lio_opcode;	/* see IOCB_CMD_ above */
	__s16	aio_reqprio; //请求优先级
	__u32	aio_fildes; //文件描述符

	__u64	aio_buf;
	__u64	aio_nbytes;
	__s64	aio_offset;

	/* extra parameters */
	__u64	aio_reserved2;	/* TODO: use this for a (struct sigevent *) */

	/* flags for the "struct iocb" */
	__u32	aio_flags;

	/*
	 * if the IOCB_FLAG_RESFD flag of "aio_flags" is set, this is an
	 * eventfd to signal AIO readiness to
	 */
	__u32	aio_resfd;
}; /* 64 bytes */

#undef IFBIG
#undef IFLITTLE

#endif /* __LINUX__AIO_ABI_H */


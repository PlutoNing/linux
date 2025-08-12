/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_FALLOC_H_
#define _UAPI_FALLOC_H_
/* - __作用__：保持文件大小不变
- __默认行为__：分配空间会扩展文件大小
- __使用场景__：预分配空间但不改变文件逻辑大小
 */
#define FALLOC_FL_KEEP_SIZE	0x01 /* default is extend size */
/* - __作用__：释放指定范围的磁盘空间（创建空洞）
- __效果__：被释放的空间读为0，不占用磁盘
- __配合标志__：必须与FALLOC_FL_KEEP_SIZE一起使用
- __使用场景__：稀疏文件优化，释放未使用空间
====================
被释放的空间读为0
 */
#define FALLOC_FL_PUNCH_HOLE	0x02 /* de-allocates range */
#define FALLOC_FL_NO_HIDE_STALE	0x04 /* reserved codepoint */

/*
 * FALLOC_FL_COLLAPSE_RANGE is used to remove a range of a file
 * without leaving a hole in the file. The contents of the file beyond
 * the range being removed is appended to the start offset of the range
 * being removed (i.e. the hole that was punched is "collapsed"),
 * resulting in a file layout that looks like the range that was
 * removed never existed. As such collapsing a range of a file changes
 * the size of the file, reducing it by the same length of the range
 * that has been removed by the operation.
 *
 * Different filesystems may implement different limitations on the
 * granularity of the operation. Most will limit operations to
 * filesystem block size boundaries, but this boundary may be larger or
 * smaller depending on the filesystem and/or the configuration of the
 * filesystem or file.
 *
 * Attempting to collapse a range that crosses the end of the file is
 * considered an illegal operation - just use ftruncate(2) if you need
 * to collapse a range that crosses EOF.
 - __作用__：移除文件范围而不留空洞
- __机制__：将后面的内容前移填补空缺
- __效果__：文件大小减少相应字节数
- __限制__：
  - 不能跨越文件末尾
  - 受文件系统块大小边界限制
- __使用场景__：删除文件中间数据，如日志清理
 */
#define FALLOC_FL_COLLAPSE_RANGE	0x08

/*
 * FALLOC_FL_ZERO_RANGE is used to convert a range of file to zeros preferably
 * without issuing data IO. Blocks should be preallocated for the regions that
 * span holes in the file, and the entire range is preferable converted to
 * unwritten extents - even though file system may choose to zero out the
 * extent or do whatever which will result in reading zeros from the range
 * while the range remains allocated for the file.
 *
 * This can be also used to preallocate blocks past EOF in the same way as
 * with fallocate. Flag FALLOC_FL_KEEP_SIZE should cause the inode
 * size to remain the same.
 - __作用__：将文件范围清零

- __机制__：尽可能不发出数据I/O

- __特点__：

  - 预分配空洞区域的块
  - 转换为未写入的扩展区
  - 读取时返回0，但空间已分配

- __使用场景__：快速清零大文件区域

 */
#define FALLOC_FL_ZERO_RANGE		0x10

/*
 * FALLOC_FL_INSERT_RANGE is use to insert space within the file size without
 * overwriting any existing data. The contents of the file beyond offset are
 * shifted towards right by len bytes to create a hole.  As such, this
 * operation will increase the size of the file by len bytes.
 *
 * Different filesystems may implement different limitations on the granularity
 * of the operation. Most will limit operations to filesystem block size
 * boundaries, but this boundary may be larger or smaller depending on
 * the filesystem and/or the configuration of the filesystem or file.
 *
 * Attempting to insert space using this flag at OR beyond the end of
 * the file is considered an illegal operation - just use ftruncate(2) or
 * fallocate(2) with mode 0 for such type of operations.
 - __作用__：在文件内插入空间

- __机制__：将指定偏移后的内容右移

- __效果__：文件大小增加相应字节数

- __限制__：

  - 不能在文件末尾或之后插入
  - 受文件系统块大小边界限制

- __使用场景__：在文件中插入数据块

 */
#define FALLOC_FL_INSERT_RANGE		0x20

/*
 * FALLOC_FL_UNSHARE_RANGE is used to unshare shared blocks within the
 * file size without overwriting any existing data. The purpose of this
 * call is to preemptively reallocate any blocks that are subject to
 * copy-on-write.
 *
 * Different filesystems may implement different limitations on the
 * granularity of the operation. Most will limit operations to filesystem
 * block size boundaries, but this boundary may be larger or smaller
 * depending on the filesystem and/or the configuration of the filesystem
 * or file.
 *
 * This flag can only be used with allocate-mode fallocate, which is
 * to say that it cannot be used with the punch, zero, collapse, or
 * insert range modes.
 - __作用__：取消共享块的共享

- __机制__：预分配写时复制块

- __限制__：

  - 只能与分配模式的fallocate一起使用
  - 不能与打孔、清零、折叠、插入模式共用

- __使用场景__：提前处理写时复制，避免后续延迟

 */
#define FALLOC_FL_UNSHARE_RANGE		0x40

#endif /* _UAPI_FALLOC_H_ */

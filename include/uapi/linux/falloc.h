/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_FALLOC_H_
#define _UAPI_FALLOC_H_

#define FALLOC_FL_KEEP_SIZE	0x01 /* default is extend size*/
/* 此标志告诉内核在对文件进行扩展时，不改变文件的大小。也就是说，在对文件进行区域分配时，
虽然空间会被分配，但文件的实际大小不会改变。
使用场景：如果你希望分配某些区域的空间，但不想改变文件的实际大小（例如，预留空间以避免将来发生磁盘碎片化）。 */
#define FALLOC_FL_PUNCH_HOLE	0x02 /* de-allocates range */
/* 作用：这个标志告诉内核打孔（punch hole），即将文件的指定区域从硬盘中删除（或称为释放空间），
使得文件中该部分区域的内容变为“未分配”的状态。打孔的操作通常是将该区域的内容清除，并且系统会
认为这些区域的空间变为可用。
使用场景：当你需要从文件中删除某些内容时，使用该标志可以高效地释放空间。它特别适用于文件系统
支持稀疏文件（sparse files）的情况。打孔之后，文件的逻辑大小不会改变，但物理空间会被释放。 */
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
   这个标注用来删除文件的一个范围，而不留下文件中的空洞。被删除范围之后的文件
   内容被追加到被删除范围的开始偏移处（即打孔的空洞被“折叠”），导致文件布局看
   起来像被删除的范围从未存在过。因此，折叠文件的范围会改变文件的大小，将其减
   小与操作删除的范围长度相同的长度。
 *
 * Different filesystems may implement different limitations on the
 * granularity of the operation. Most will limit operations to
 * filesystem block size boundaries, but this boundary may be larger or
 * smaller depending on the filesystem and/or the configuration of the
 * filesystem or file.
 * 不同的文件系统可能对操作的粒度实现不同的限制。大多数将操作限制在文件系统块大小边界上，
    * 但这个边界可能更大或更小，这取决于文件系统和/或文件系统或文件的配置。
 * Attempting to collapse a range that crosses the end of the file is
 * considered an illegal operation - just use ftruncate(2) if you need
 * to collapse a range that crosses EOF.
 尝试去折叠一个跨越文件末尾的范围被认为是非法操作——如果你需要折叠一个跨越EOF的
 范围，只需使用ftruncate(2)。
 */
#define FALLOC_FL_COLLAPSE_RANGE	0x08

/*
 * FALLOC_FL_ZERO_RANGE is used to convert a range of file to zeros preferably
 * without issuing data IO. Blocks should be preallocated for the regions that
 * span holes in the file, and the entire range is preferable converted to
 * unwritten extents - even though file system may choose to zero out the
 * extent or do whatever which will result in reading zeros from the range
 * while the range remains allocated for the file.
 * 这个标志用来将文件的一个范围转换为零，最好不发出数据IO。对于文件中的空洞，
    * 应该预分配块，整个范围最好转换为未写入的范围——尽管文件系统可能选择将范围
    * 零出来，或者做任何会导致从范围读取零的操作，而范围仍然分配给文件。

 * This can be also used to preallocate blocks past EOF in the same way as
 * with fallocate. Flag FALLOC_FL_KEEP_SIZE should cause the inode
 * size to remain the same.
 这也可以用来预分配超过EOF的块，就像使用fallocate一样。标志FALLOC_FL_KEEP_SIZE
    * 应该导致inode的大小保持不变。
 */
#define FALLOC_FL_ZERO_RANGE		0x10

/*
 * FALLOC_FL_INSERT_RANGE is use to insert space within the file size without
 * overwriting any existing data. The contents of the file beyond offset are
 * shifted towards right by len bytes to create a hole.  As such, this
 * operation will increase the size of the file by len bytes.
 * 这个标志用来在文件大小内插入空间，而不覆盖任何现有数据。超过偏移量的文件内容
    * 向右移动len字节，以创建一个空洞。因此，这个操作将增加文件的大小len字节。
    * 这个操作将增加文件的大小len字节。
 * Different filesystems may implement different limitations on the granularity
 * of the operation. Most will limit operations to filesystem block size
 * boundaries, but this boundary may be larger or smaller depending on
 * the filesystem and/or the configuration of the filesystem or file.
 * 不同的文件系统可能对操作的粒度实现不同的限制。大多数将操作限制在文件系统块大小边界上，
    * 但这个边界可能更大或更小，这取决于文件系统和/或文件系统或文件的配置。
 * Attempting to insert space using this flag at OR beyond the end of
 * the file is considered an illegal operation - just use ftruncate(2) or
 * fallocate(2) with mode 0 for such type of operations.
 */
#define FALLOC_FL_INSERT_RANGE		0x20

/*
 * FALLOC_FL_UNSHARE_RANGE is used to unshare shared blocks within the
 * file size without overwriting any existing data. The purpose of this
 * call is to preemptively reallocate any blocks that are subject to
 * copy-on-write.
 * 这个标志用来在文件大小内不覆盖任何现有数据的情况下取消共享块。这个调用的目的是
    * 预先重新分配任何可能被写时复制的块。目的是预先重新分配任何可能被写时复制的块。
 * Different filesystems may implement different limitations on the
 * granularity of the operation. Most will limit operations to filesystem
 * block size boundaries, but this boundary may be larger or smaller
 * depending on the filesystem and/or the configuration of the filesystem
 * or file.
 *
 * This flag can only be used with allocate-mode fallocate, which is
 * to say that it cannot be used with the punch, zero, collapse, or
 * insert range modes.
 */
#define FALLOC_FL_UNSHARE_RANGE		0x40

#endif /* _UAPI_FALLOC_H_ */

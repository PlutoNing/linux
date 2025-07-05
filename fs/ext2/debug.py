import gdb

def set_function_breakpoints():
    """直接为ext2相关函数设置断点"""
    # ext2_file_operations相关函数
    file_ops_functions = [
        # "generic_file_llseek",          # .llseek
        "ext2_file_read_iter",          # .read_iter
        "ext2_file_write_iter",         # .write_iter
        "ext2_ioctl",                   # .unlocked_ioctl
        "ext2_compat_ioctl",            # .compat_ioctl (CONFIG_COMPAT)
        "ext2_file_mmap",               # .mmap
        # "dquot_file_open",              # .open
        "ext2_release_file",            # .release
        "ext2_fsync",                   # .fsync
        # "thp_get_unmapped_area",        # .get_unmapped_area
        "filemap_splice_read",          # .splice_read
        "iter_file_splice_write"        # .splice_write
    ]

    # ext2_file_inode_operations相关函数
    inode_ops_functions = [
        # "ext2_listxattr",               # .listxattr
        # "ext2_getattr",                 # .getattr
        # "ext2_setattr",                 # .setattr
        # "ext2_get_acl",                 # .get_inode_acl
        # "ext2_set_acl",                 # .set_acl
        # "ext2_filemap",                  # .fiemap
        # "ext2_fileattr_get",            # .fileattr_get
        # "ext2_fileattr_set"             # .fileattr_set
    ]

    # ext2_dax_vm_ops相关函数
    dax_vm_ops_functions = [
        "ext2_dax_fault",               # .fault, .page_mkwrite, .pfn_mkwrite
    ]

    # ext2_aops相关函数
    aops_functions = [
        # "block_dirty_folio",            # .dirty_folio
        # "block_invalidate_folio",       # .invalidate_folio
        "ext2_read_folio",              # .read_folio
        "ext2_readahead",               # .readahead
        "ext2_write_begin",             # .write_begin
        "ext2_write_end",               # .write_end
        "ext2_bmap",                    # .bmap
        "noop_direct_IO",               # .direct_IO
        "ext2_writepages",              # .writepages
        "buffer_migrate_folio",         # .migrate_folio
        "block_is_partially_uptodate",  # .is_partially_uptodate
        "generic_error_remove_page"     # .error_remove_page
    ]

    target = [
        "ext2_prepare_chunk",
        "ext2_commit_chunk",
        "ext2_add_link",
        "ext2_prepare_chunk",
        "ext2_new_inode",
    ]
    # 合并所有函数列表
    all_functions = (
        file_ops_functions
        + inode_ops_functions
        + dax_vm_ops_functions
        + aops_functions
        + target
    )

    # 去重（有些函数可能被多个操作结构使用）
    unique_functions = list(set(all_functions))

    # 设置断点
    success_count = 0
    for func in unique_functions:
        try:
            gdb.execute(f"break {func}")
            print(f"Breakpoint set for {func}")
            success_count += 1
        except gdb.error as e:
            print(f"Failed to set breakpoint for {func}: {str(e)}")

    print(f"\nBreakpoints summary: {success_count} succeeded, "
         f"{len(unique_functions)-success_count} failed")

# 执行设置
set_function_breakpoints()

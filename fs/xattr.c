// SPDX-License-Identifier: GPL-2.0-only
/*
  File: fs/xattr.c

  Extended attribute handling.

  Copyright (C) 2001 by Andreas Gruenbacher <a.gruenbacher@computer.org>
  Copyright (C) 2001 SGI - Silicon Graphics, Inc <linux-xfs@oss.sgi.com>
  Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/evm.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fsnotify.h>
#include <linux/audit.h>
#include <linux/vmalloc.h>
#include <linux/posix_acl_xattr.h>

#include <linux/uaccess.h>

static const char *
strcmp_prefix(const char *a, const char *a_prefix)
{
	while (*a_prefix && *a == *a_prefix) {
		a++;
		a_prefix++;
	}
	return *a_prefix ? NULL : a;
}

/*
 * In order to implement different sets of xattr operations for each xattr
 * prefix, a filesystem should create a null-terminated array of struct
 * xattr_handler (one for each prefix) and hang a pointer to it off of the
 * s_xattr field of the superblock.
 */
#define for_each_xattr_handler(handlers, handler)		\
	if (handlers)						\
		for ((handler) = *(handlers)++;			\
			(handler) != NULL;			\
			(handler) = *(handlers)++)

/*
 * Find the xattr_handler with the matching prefix.
找到具有匹配前缀的xattr_handler
 */
static const struct xattr_handler *
xattr_resolve_name(struct inode *inode, const char **name)
{
	const struct xattr_handler **handlers = inode->i_sb->s_xattr;
	const struct xattr_handler *handler;

	if (!(inode->i_opflags & IOP_XATTR)) { //如果inode不支持xattr
		if (unlikely(is_bad_inode(inode))) //如果是坏inode
			return ERR_PTR(-EIO); //报告EIO

		return ERR_PTR(-EOPNOTSUPP);//如果是好inode,就是操作不支持错误
	}
	//开始遍历handlers,找到匹配的handler
	for_each_xattr_handler(handlers, handler) {
		const char *n;

		n = strcmp_prefix(*name, xattr_prefix(handler));
		if (n) {
			if (!handler->prefix ^ !*n) {
				if (*n)
					continue;
				return ERR_PTR(-EINVAL);
			}
			*name = n;
			return handler;
		}
	}
	return ERR_PTR(-EOPNOTSUPP);
}

/*
 * Check permissions for extended attribute access.  This is a bit complicated
 * because different namespaces have very different rules.
 */
static int
xattr_permission(struct inode *inode, const char *name, int mask)
{
	/*
	 * We can never set or remove an extended attribute on a read-only
	 * filesystem  or on an immutable / append-only inode.
	 */
	if (mask & MAY_WRITE) {
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
		/*
		 * Updating an xattr will likely cause i_uid and i_gid
		 * to be writen back improperly if their true value is
		 * unknown to the vfs.
		 */
		if (HAS_UNMAPPED_ID(inode))
			return -EPERM;
	}

	/*
	 * No restriction for security.* and system.* from the VFS.  Decision
	 * on these is left to the underlying filesystem / security module.
	 */
	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) ||
	    !strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return 0;

	/*
	 * The trusted.* namespace can only be accessed by privileged users.
	 */
	if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN)) {
		if (!capable(CAP_SYS_ADMIN))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		return 0;
	}

	/*
	 * In the user.* namespace, only regular files and directories can have
	 * extended attributes. For sticky directories, only the owner and
	 * privileged users can write attributes.
	 */
	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		if (S_ISDIR(inode->i_mode) && (inode->i_mode & S_ISVTX) &&
		    (mask & MAY_WRITE) && !inode_owner_or_capable(inode))
			return -EPERM;
	}

	return inode_permission(inode, mask);
}

int
__vfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
	       const void *value, size_t size, int flags)
{
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->set)
		return -EOPNOTSUPP;
	if (size == 0)
		value = "";  /* empty EA, do not remove */
	return handler->set(handler, dentry, inode, name, value, size, flags);
}
EXPORT_SYMBOL(__vfs_setxattr);

/**
 *  __vfs_setxattr_noperm - perform setxattr operation without performing
 *  permission checks.
 *
 *  @dentry - object to perform setxattr on
 *  @name - xattr name to set
 *  @value - value to set @name to
 *  @size - size of @value
 *  @flags - flags to pass into filesystem operations
 *
 *  returns the result of the internal setxattr or setsecurity operations.
 *
 *  This function requires the caller to lock the inode's i_mutex before it
 *  is executed. It also assumes that the caller will make the appropriate
 *  permission checks.
 */
int __vfs_setxattr_noperm(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error = -EAGAIN;
	int issec = !strncmp(name, XATTR_SECURITY_PREFIX,
				   XATTR_SECURITY_PREFIX_LEN);

	if (issec)
		inode->i_flags &= ~S_NOSEC;
	if (inode->i_opflags & IOP_XATTR) {
		error = __vfs_setxattr(dentry, inode, name, value, size, flags);
		if (!error) {
			fsnotify_xattr(dentry);
			security_inode_post_setxattr(dentry, name, value,
						     size, flags);
		}
	} else {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
	}
	if (error == -EAGAIN) {
		error = -EOPNOTSUPP;

		if (issec) {
			const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;

			error = security_inode_setsecurity(inode, suffix, value,
							   size, flags);
			if (!error)
				fsnotify_xattr(dentry);
		}
	}

	return error;
}


int
vfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(inode, name, MAY_WRITE);
	if (error)
		return error;

	inode_lock(inode);
	error = security_inode_setxattr(dentry, name, value, size, flags);
	if (error)
		goto out;

	error = __vfs_setxattr_noperm(dentry, name, value, size, flags);

out:
	inode_unlock(inode);
	return error;
}
EXPORT_SYMBOL_GPL(vfs_setxattr);

static ssize_t
xattr_getsecurity(struct inode *inode, const char *name, void *value,
			size_t size)
{
	void *buffer = NULL;
	ssize_t len;

	if (!value || !size) {
		len = security_inode_getsecurity(inode, name, &buffer, false);
		goto out_noalloc;
	}

	len = security_inode_getsecurity(inode, name, &buffer, true);
	if (len < 0)
		return len;
	if (size < len) {
		len = -ERANGE;
		goto out;
	}
	memcpy(value, buffer, len);
out:
	kfree(buffer);
out_noalloc:
	return len;
}

/*
 * vfs_getxattr_alloc - allocate memory, if necessary, before calling getxattr
 *
 * Allocate memory, if not already allocated, or re-allocate correct size,
 * before retrieving the extended attribute.
 *
 * Returns the result of alloc, if failed, or the getxattr operation.
 */
ssize_t
vfs_getxattr_alloc(struct dentry *dentry, const char *name, char **xattr_value,
		   size_t xattr_size, gfp_t flags)
{
	const struct xattr_handler *handler;
	struct inode *inode = dentry->d_inode;
	char *value = *xattr_value;
	int error;

	error = xattr_permission(inode, name, MAY_READ);
	if (error)
		return error;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->get)
		return -EOPNOTSUPP;
	error = handler->get(handler, dentry, inode, name, NULL, 0);
	if (error < 0)
		return error;

	if (!value || (error > xattr_size)) {
		value = krealloc(*xattr_value, error + 1, flags);
		if (!value)
			return -ENOMEM;
		memset(value, 0, error + 1);
	}

	error = handler->get(handler, dentry, inode, name, value, error);
	*xattr_value = value;
	return error;
}

//查找对应的扩展属性
ssize_t
__vfs_getxattr(struct dentry *dentry, struct inode *inode, const char *name,
	       void *value, size_t size)
{
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->get)
		return -EOPNOTSUPP;
	return handler->get(handler, dentry, inode, name, value, size);
}
EXPORT_SYMBOL(__vfs_getxattr);

//查找name对应的扩展属性
ssize_t
vfs_getxattr(struct dentry *dentry, const char *name, void *value, size_t size)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(inode, name, MAY_READ);
	if (error)
		return error;

	error = security_inode_getxattr(dentry, name);
	if (error)
		return error;

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		int ret = xattr_getsecurity(inode, suffix, value, size);
		/*
		 * Only overwrite the return value if a security module
		 * is actually active.
		 */
		if (ret == -EOPNOTSUPP)
			goto nolsm;
		return ret;
	}
nolsm:
	return __vfs_getxattr(dentry, inode, name, value, size);
}
EXPORT_SYMBOL_GPL(vfs_getxattr);

//列出扩展属性
ssize_t
vfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct inode *inode = d_inode(dentry);
	ssize_t error;

	error = security_inode_listxattr(dentry);
	if (error)
		return error;

	if (inode->i_op->listxattr && (inode->i_opflags & IOP_XATTR)) {
		error = inode->i_op->listxattr(dentry, list, size);
	} else {
		error = security_inode_listsecurity(inode, list, size);
		if (size && error > size)
			error = -ERANGE;
	}
	return error;
}
EXPORT_SYMBOL_GPL(vfs_listxattr);

//移除扩展属性
int
__vfs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = d_inode(dentry);
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(inode, &name); //找到对应的handler
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->set)
		return -EOPNOTSUPP;
	//设置value为NULL,表示删除
	return handler->set(handler, dentry, inode, name, NULL, 0, XATTR_REPLACE);
}
EXPORT_SYMBOL(__vfs_removexattr);

//移除扩展属性
int
vfs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(inode, name, MAY_WRITE);
	if (error)
		return error;

	inode_lock(inode);
	error = security_inode_removexattr(dentry, name);
	if (error)
		goto out;
	
	//真正执行删除操作
	error = __vfs_removexattr(dentry, name);

	if (!error) { //成功删除
		fsnotify_xattr(dentry); //通知fsnotify
		evm_inode_post_removexattr(dentry, name); 
	}

out:
	inode_unlock(inode);
	return error;
}
EXPORT_SYMBOL_GPL(vfs_removexattr);


/*
 * Extended attribute SET operations
 */
static long
setxattr(struct dentry *d, const char __user *name, const void __user *value,
	 size_t size, int flags)
{
	int error;
	void *kvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

	if (flags & ~(XATTR_CREATE|XATTR_REPLACE))
		return -EINVAL;

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
		kvalue = kvmalloc(size, GFP_KERNEL);
		if (!kvalue)
			return -ENOMEM;
		if (copy_from_user(kvalue, value, size)) {
			error = -EFAULT;
			goto out;
		}
		if ((strcmp(kname, XATTR_NAME_POSIX_ACL_ACCESS) == 0) ||
		    (strcmp(kname, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
			posix_acl_fix_xattr_from_user(kvalue, size);
		else if (strcmp(kname, XATTR_NAME_CAPS) == 0) {
			error = cap_convert_nscap(d, &kvalue, size);
			if (error < 0)
				goto out;
			size = error;
		}
	}

	error = vfs_setxattr(d, kname, kvalue, size, flags);
out:
	kvfree(kvalue);

	return error;
}

static int path_setxattr(const char __user *pathname,
			 const char __user *name, const void __user *value,
			 size_t size, int flags, unsigned int lookup_flags)
{
	struct path path;
	int error;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = setxattr(path.dentry, name, value, size, flags);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	return path_setxattr(pathname, name, value, size, flags, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	return path_setxattr(pathname, name, value, size, flags, 0);
}

SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
		const void __user *,value, size_t, size, int, flags)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = mnt_want_write_file(f.file);
	if (!error) {
		error = setxattr(f.file->f_path.dentry, name, value, size, flags);
		mnt_drop_write_file(f.file);
	}
	fdput(f);
	return error;
}

/*
 * Extended attribute GET operations
查找name对应的扩展属性
 */
static ssize_t
getxattr(struct dentry *d, const char __user *name, void __user *value,
	 size_t size)
{
	ssize_t error;
	void *kvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			size = XATTR_SIZE_MAX;
		kvalue = kvzalloc(size, GFP_KERNEL);
		if (!kvalue)
			return -ENOMEM;
	}

	//这里调用vfs_getxattr开始查找扩展属性
	error = vfs_getxattr(d, kname, kvalue, size);
	if (error > 0) {
		if ((strcmp(kname, XATTR_NAME_POSIX_ACL_ACCESS) == 0) ||
		    (strcmp(kname, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
			posix_acl_fix_xattr_to_user(kvalue, error);
		if (size && copy_to_user(value, kvalue, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_SIZE_MAX) {
		/* The file system tried to returned a value bigger
		   than XATTR_SIZE_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	kvfree(kvalue);

	return error;
}

//查找path对应的扩展属性
static ssize_t path_getxattr(const char __user *pathname,
			     const char __user *name, void __user *value,
			     size_t size, unsigned int lookup_flags)
{
	struct path path;
	ssize_t error;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = getxattr(path.dentry, name, value, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	return path_getxattr(pathname, name, value, size, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	return path_getxattr(pathname, name, value, size, 0);
}

//查找name对应的扩展属性
SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
		void __user *, value, size_t, size)
{
	struct fd f = fdget(fd);
	ssize_t error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = getxattr(f.file->f_path.dentry, name, value, size);
	fdput(f);
	return error;
}

/*
 * Extended attribute LIST operations
列出dentry的扩展属性
 */
static ssize_t
listxattr(struct dentry *d, char __user *list, size_t size)
{
	ssize_t error;
	char *klist = NULL;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		klist = kvmalloc(size, GFP_KERNEL);
		if (!klist)
			return -ENOMEM;
	}

	//调用vfs_listxattr
	error = vfs_listxattr(d, klist, size);
	if (error > 0) {
		if (size && copy_to_user(list, klist, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_LIST_MAX) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	kvfree(klist);

	return error;
}

//
static ssize_t path_listxattr(const char __user *pathname, char __user *list,
			      size_t size, unsigned int lookup_flags)
{
	struct path path;
	ssize_t error;
retry:
//根据pathname获取path
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	//到这里,已经获取到path
	error = listxattr(path.dentry, list, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	return path_listxattr(pathname, list, size, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	return path_listxattr(pathname, list, size, 0);
}

//列出fd的扩展属性?
SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
{
	struct fd f = fdget(fd);
	ssize_t error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);
	error = listxattr(f.file->f_path.dentry, list, size);
	fdput(f);
	return error;
}

/*
 * Extended attribute REMOVE operations
移除扩展属性
 */
static long
removexattr(struct dentry *d, const char __user *name)
{
	int error;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	return vfs_removexattr(d, kname);
}

//移除path的扩展属性
static int path_removexattr(const char __user *pathname,
			    const char __user *name, unsigned int lookup_flags)
{
	struct path path;
	int error;
retry:
	//根据pathname获取path
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	//到这里,已经获取到path

	error = mnt_want_write(path.mnt);
	if (!error) { //如果可以写
		error = removexattr(path.dentry, name);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);

	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

//通过pathname移除扩展属性
SYSCALL_DEFINE2(removexattr, const char __user *, pathname,
		const char __user *, name)
{
	return path_removexattr(pathname, name, LOOKUP_FOLLOW);
}

SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname,
		const char __user *, name)
{
	return path_removexattr(pathname, name, 0);
}

//
SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (!f.file)
		return error;
	audit_file(f.file);

	error = mnt_want_write_file(f.file);
	if (!error) {//如果可以写
		//开始操作
		error = removexattr(f.file->f_path.dentry, name);
		//这里释放刚刚mnt_want_write_file获取的引用
		mnt_drop_write_file(f.file);
	}
	fdput(f);
	return error;
}

/*
 * Combine the results of the list() operation from every xattr_handler in the
 * list.
 连接列表中每个xattr_handler的list()操作的结果
 */
ssize_t
generic_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	const struct xattr_handler *handler, **handlers = dentry->d_sb->s_xattr;
	unsigned int size = 0;

	if (!buffer) {//如果buffer空,则只计算需要的buffer大小
		for_each_xattr_handler(handlers, handler) {
			if (!handler->name ||
			    (handler->list && !handler->list(dentry)))
				continue;
			size += strlen(handler->name) + 1;
		}
	} else {//如果buffer不为空,则将所有的xattr_handler的name拷贝到buffer中
		char *buf = buffer;
		size_t len;

		for_each_xattr_handler(handlers, handler) {
			if (!handler->name ||
			    (handler->list && !handler->list(dentry)))
				continue;

			len = strlen(handler->name);
			if (len + 1 > buffer_size)
				return -ERANGE;
			memcpy(buf, handler->name, len + 1);
			buf += len + 1;
			buffer_size -= len + 1;
		}

		size = buf - buffer; //此时size为buffer中的数据大小
	}
	return size;
}
EXPORT_SYMBOL(generic_listxattr);

/**
 * xattr_full_name  -  Compute full attribute name from suffix
 * 计算完整的属性名
 * @handler:	handler of the xattr_handler operation
 * @name:	name passed to the xattr_handler operation
 *
 * The get and set xattr handler operations are called with the remainder of
 * the attribute name after skipping the handler's prefix: for example, "foo"
 * is passed to the get operation of a handler with prefix "user." to get
 * attribute "user.foo".  The full name is still "there" in the name though.
 * get和set的handler操作被调用时,会跳过handler的前缀,例如,handler的前缀是"user."
 ,那么"foo"会被传递给get操作,以获取属性"user.foo".但是完整的名字仍然在name中
 * Note: the list xattr handler operation when called from the vfs is passed a
 * NULL name; some file systems use this operation internally, with varying
 * semantics.
 注意:当从vfs调用list xattr handler操作时,会传递一个NULL name,
 一些文件系统会在内部使用这个操作,语义不同
 */
const char *xattr_full_name(const struct xattr_handler *handler,
			    const char *name)
{
	size_t prefix_len = strlen(xattr_prefix(handler));

	return name - prefix_len;
}
EXPORT_SYMBOL(xattr_full_name);

/*
 * Allocate new xattr and copy in the value; but leave the name to callers.
 给一个xattr分配内存,并且拷贝value到这个xattr中
 */
struct simple_xattr *simple_xattr_alloc(const void *value, size_t size)
{
	struct simple_xattr *new_xattr;
	size_t len;

	/* wrap around? */
	len = sizeof(*new_xattr) + size;
	if (len < sizeof(*new_xattr))
		return NULL;

	new_xattr = kmalloc(len, GFP_KERNEL);
	if (!new_xattr)
		return NULL;

	new_xattr->size = size;
	memcpy(new_xattr->value, value, size);
	return new_xattr;
}

/*
 * xattr GET operation for in-memory/pseudo filesystems
  获取指定name的xattr,拷贝到buffer中
 */
int simple_xattr_get(struct simple_xattrs *xattrs, const char *name,
		     void *buffer, size_t size)
{
	struct simple_xattr *xattr;
	int ret = -ENODATA;

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {
		if (strcmp(name, xattr->name))
			continue;
			//找到了要查找的xattr
		ret = xattr->size;
		if (buffer) {
			if (size < xattr->size)
				ret = -ERANGE;
			else
				memcpy(buffer, xattr->value, xattr->size);
		}
		break;
	}
	spin_unlock(&xattrs->lock);
	return ret;
}

/**
 * simple_xattr_set - xattr SET operation for in-memory/pseudo filesystems
 作用是设置一个xattr
 * @xattrs: target simple_xattr list, which the xattr will be added to
  
 * @name: name of the extended attribute, 属性的名字
 * @value: value of the xattr. If %NULL, will remove the attribute.
 属性的值,如果是NULL,则会删除这个属性
 * @size: size of the new xattr,属性的大小
 * @flags: %XATTR_{CREATE|REPLACE}
 *
 * %XATTR_CREATE is set, the xattr shouldn't exist already; otherwise fails
 * with -EEXIST.  If %XATTR_REPLACE is set, the xattr should exist;
 * otherwise, fails with -ENODATA.
 *	
 * Returns 0 on success, -errno on failure.
 */
int simple_xattr_set(struct simple_xattrs *xattrs, const char *name,
		     const void *value, size_t size, int flags)
{
	struct simple_xattr *xattr;
	struct simple_xattr *new_xattr = NULL;
	int err = 0;

	/* value == NULL means remove */
	if (value) { //设置新值
		new_xattr = simple_xattr_alloc(value, size);
		if (!new_xattr)
			return -ENOMEM;

		new_xattr->name = kstrdup(name, GFP_KERNEL);
		if (!new_xattr->name) {
			kfree(new_xattr);
			return -ENOMEM;
		}
	}

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {
		if (!strcmp(name, xattr->name)) {//找到了要设置的xattr
			if (flags & XATTR_CREATE) {//如果是创建,则返回-EEXIST
				xattr = new_xattr;
				err = -EEXIST;
			} else if (new_xattr) {//如果是替换,则替换
				list_replace(&xattr->list, &new_xattr->list);
			} else {//如果是删除,则删除
				list_del(&xattr->list);
			}
			goto out;
		}
	}
	if (flags & XATTR_REPLACE) {
		xattr = new_xattr;
		err = -ENODATA;
	} else {
		list_add(&new_xattr->list, &xattrs->head);
		xattr = NULL;
	}
out:
	spin_unlock(&xattrs->lock);
	if (xattr) {
		kfree(xattr->name);
		kfree(xattr);
	}
	return err;

}

//是否是trusted xattr?
static bool xattr_is_trusted(const char *name)
{
	return !strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN);
}

//查看一个xattr?
//逻辑是把name拷贝到buffer中
static int xattr_list_one(char **buffer, ssize_t *remaining_size,
			  const char *name)
{
	size_t len = strlen(name) + 1;
	if (*buffer) {
		if (*remaining_size < len)
			return -ERANGE;
		memcpy(*buffer, name, len);
		*buffer += len;
	}
	*remaining_size -= len;
	return 0;
}

/*
查看inode的xattrs
函数过程是:遍历xattrs链表,把xattr->name拷贝到buffer中
 * xattr LIST operation for in-memory/pseudo filesystems
 */
ssize_t simple_xattr_list(struct inode *inode, struct simple_xattrs *xattrs,
			  char *buffer, size_t size)
{
	bool trusted = capable(CAP_SYS_ADMIN);
	struct simple_xattr *xattr;
	ssize_t remaining_size = size;
	int err = 0;

#ifdef CONFIG_FS_POSIX_ACL
	if (IS_POSIXACL(inode)) { //如果inode支持posix_acl
		if (inode->i_acl) {
			//把XATTR_NAME_POSIX_ACL_ACCESS拷贝到buffer中?
			err = xattr_list_one(&buffer, &remaining_size,
					     XATTR_NAME_POSIX_ACL_ACCESS);
			if (err)
				return err;
		}
		if (inode->i_default_acl) {
			//把XATTR_NAME_POSIX_ACL_DEFAULT拷贝到buffer中?
			err = xattr_list_one(&buffer, &remaining_size,
					     XATTR_NAME_POSIX_ACL_DEFAULT);
			if (err)
				return err;
		}
	}
#endif

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {//遍历xattrs链表
		/* skip "trusted." attributes for unprivileged callers */
		if (!trusted && xattr_is_trusted(xattr->name))
			continue;
		//把xattr->name拷贝到buffer中
		err = xattr_list_one(&buffer, &remaining_size, xattr->name);
		if (err)
			break;
	}
	spin_unlock(&xattrs->lock);

	return err ? err : size - remaining_size;
}

/*
函数逻辑:
 * Adds an extended attribute to the list
 //添加一个xattr到list中
 */
void simple_xattr_list_add(struct simple_xattrs *xattrs,
			   struct simple_xattr *new_xattr)
{
	spin_lock(&xattrs->lock);
	list_add(&new_xattr->list, &xattrs->head);
	spin_unlock(&xattrs->lock);
	
}

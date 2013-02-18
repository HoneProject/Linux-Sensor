/*
 * Copyright (C) 2011 Battelle Memorial Institute <http://www.battelle.org>
 *
 * Author: Brandon Carpenter
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Much of the code below is based on procfs code.
 */

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	#define D_PATH(mnt, dentry, buf, size) \
		({ struct path _p = {(mnt), (dentry)}; d_path(&_p, (buf), (size)); })
#else
	#define D_PATH d_path
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	#define __get_exe_file(mm) ((mm)->exe_file)
#else
static struct file *__get_exe_file(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
			return vma->vm_file;
	}
	return NULL;
}
#endif

static char *__exe_path(struct mm_struct *mm, char *buf, int buflen)
{
	struct file *exe_file;
	char *path = NULL;

	if ((exe_file = __get_exe_file(mm))) {
		struct vfsmount *mnt;
		struct dentry *dentry;

		mnt = mntget(exe_file->f_vfsmnt);
		dentry = dget(exe_file->f_dentry);

		if (mnt && dentry) {
			path = D_PATH(mnt, dentry, buf, buflen);
			dput(dentry);
			mntput(mnt);
		}
	}

	return path;
}

static int __mm_argv(struct mm_struct *mm, char *buf, int buflen)
{
	char *pos;
	unsigned long addr, size;

	if (!buflen)
		return 0;

	pos = buf;
	addr = mm->arg_start;
	size = mm->arg_end - mm->arg_start;
	if (size > buflen)
		size = buflen;
	while (size) {
		struct page *page;
		int bytes, offset;
		void *maddr;

		if (get_user_pages(NULL, mm, addr, 1, 0, 0, &page, NULL) <= 0)
			break;

		bytes = size;
		offset = addr & (PAGE_SIZE - 1);
		if (bytes > (PAGE_SIZE - offset))
			bytes = PAGE_SIZE - offset;

		maddr = kmap(page);
		memcpy(pos, maddr + offset, bytes);
		kunmap(page);
		put_page(page);
		
		size -= bytes;
		pos += bytes;
		addr += bytes;
	}

	if (pos == buf) {
		*pos = '\0';
		pos++;
	} else if (*(pos - 1))
		*(pos - 1) = '\0';
	return pos - buf;
}

char *mm_path(struct mm_struct *mm, char *buf, int buflen)
{
	char *path;
	
	down_read(&mm->mmap_sem);
	path = __exe_path(mm, buf, buflen);
	up_read(&mm->mmap_sem);
	return path;
}

int mm_argv(struct mm_struct *mm, char *buf, int buflen)
{
	int argvlen;
	
	down_read(&mm->mmap_sem);
	argvlen = __mm_argv(mm, buf, buflen - 1);
	up_read(&mm->mmap_sem);
	buf[argvlen] = '\0';
	return argvlen;
}


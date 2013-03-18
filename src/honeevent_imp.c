/*
 * Copyright (C) 2011 Battelle Memorial Institute <http://www.battelle.org>
 *
 * Author: Brandon Carpenter
 * Contributor: Erik Jensen
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
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/stringify.h>
#include <linux/poll.h>

#include <linux/fdtable.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "process_notify.h"
#include "hone_notify.h"
#include "honeevent.h"
#include "mmutil.h"
#include "ringbuf.h"
#include "pcapng.h"
#include "version.h"

MODULE_DESCRIPTION("Hone event character device.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL");
MODULE_VERSION(HONE_VERSION);
MODULE_ALIAS("hone");

static char version[] __initdata = HONE_VERSION;

static char *devname = "hone";
module_param(devname, charp, S_IRUGO);
MODULE_PARM_DESC(devname, "The name to give the device in sysfs (default: hone).");

static int major = 0;
module_param(major, int, S_IRUGO);
MODULE_PARM_DESC(major, "The major number to give the device.  "
		"If 0 (the default), the major number is automatically assigned by the kernel.");

static char hostid_type = 0;
module_param(hostid_type, byte, S_IRUGO);
MODULE_PARM_DESC(hostid_type,
		"An integer describing how to interpret the value of hostid.  0 (the "
		"default) means hostid is a string while 1 means it is a GUID.");

static char *hostid = "";
module_param(hostid, charp, S_IRUGO);
MODULE_PARM_DESC(hostid,
		"A GUID which, if given, will be included in the output.");

static char *comment = "";
module_param(comment, charp, S_IRUGO);
MODULE_PARM_DESC(comment, "If given, will be included in the comment option "
		"of the section header block.  Spaces can be encoded as \\040 or \\x20.");

#ifndef CONFIG_HONE_DEFAULT_PAGEORDER
	#ifdef CONFIG_64BIT
		#define CONFIG_HONE_DEFAULT_PAGEORDER 3
	#else
		#define CONFIG_HONE_DEFAULT_PAGEORDER 2
	#endif
#endif

static unsigned int pageorder = CONFIG_HONE_DEFAULT_PAGEORDER;
module_param(pageorder, uint, S_IWUSR|S_IRUGO);
MODULE_PARM_DESC(pageorder,
		"Specifies the page order to use when allocating the ring buffer "
		"(default: " __stringify(CONFIG_HONE_DEFAULT_PAGEORDER) ").  The buffer "
		"size is computed as PAGESIZE * (1 << pageorder).");

static struct class *class_hone;


#define printm(level, fmt, ...) printk(level "%s: %s:%d: " fmt, mod_name, __FILE__, __LINE__, ##__VA_ARGS__)
#define mod_name (THIS_MODULE->name)

#define size_of_pages(order) (PAGE_SIZE << (order))
#define READ_BUFFER_PAGE_ORDER 5
#define READ_BUFFER_SIZE size_of_pages(READ_BUFFER_PAGE_ORDER)

#define READER_HEAD 0x00000001
#define READER_INIT 0x00000002
#define READER_TAIL 0x00000004
#define READER_FINISH 0x00000008
#define READER_RESTART 0x0000000F
#define READER_FILTER_PID 0x00000100

static struct device_info devinfo = {
	.comment = NULL,
	.host_id = NULL,
	.host_guid_is_set = false
};

struct hone_reader {
	struct semaphore sem;
	struct ring_buf ringbuf;
	struct notifier_block nb;
	unsigned int (*format)(const struct device_info *,
			const struct reader_info *, struct hone_event *, char *, unsigned int);
	struct reader_info info;
	atomic_t flags;
	struct sock *filter_sk;
	struct hone_event *event;
	unsigned int buflen;
	char *buf;
};

static DECLARE_WAIT_QUEUE_HEAD(event_wait_queue);

static struct hone_event head_event = {HONE_USER_HEAD, {ATOMIC_INIT(1)}};
static struct hone_event tail_event = {HONE_USER_TAIL, {ATOMIC_INIT(1)}};

#define reader_will_block(rdr) (ring_is_empty(&(rdr)->ringbuf) && \
		!(rdr)->event && !(atomic_read(&(rdr)->flags) & READER_RESTART))

static unsigned int format_as_text(
		const struct device_info *devinfo, const struct reader_info *info,
		struct hone_event *event, char *buf, unsigned int buflen)
{
	static const char *event_names[] = {"????", "FORK", "EXEC", "EXIT"};
	unsigned int n = 0;

#define printbuf(fmt, ...) ({ if ((n += snprintf(buf + n, buflen - n, fmt, ##__VA_ARGS__)) >= buflen) { goto out_long; }; n; })

	switch (event->type) {
	case HONE_PROCESS:
	{
		struct process_event *pev = &event->process;
		printbuf("%lu.%09lu %s %d %d %d %d %d\n",
				event->ts.tv_sec, event->ts.tv_nsec, event_names[pev->event],
				pev->pid, pev->ppid, pev->tgid, pev->uid, pev->gid);
		if (pev->event == PROC_EXEC && pev->mm) {
			char *path, *argv;
			n--;
			printbuf(" \"");
			if ((path = mm_path(pev->mm, buf + n, buflen -n - 3))) {
				int pathlen = strlen(path);
				memmove(buf + n, path, pathlen);
				n += pathlen;
			}
			printbuf("\" ");
			argv = buf + n;
			n += mm_argv(pev->mm, buf + n, buflen - n - 1);
			for ( ; argv < buf + n; argv++) {
				if (*argv == '\0')
					*argv = ' ';
			}
			printbuf("\n");
		}
		break;
	}
	case HONE_SOCKET:
	{
		struct socket_event *sockev = &event->socket;
		printbuf("%lu.%09lu SOCK %c %d %d %d %d %d %08lx\n",
				event->ts.tv_sec, event->ts.tv_nsec, sockev->event ? 'C' : 'O',
				sockev->pid, sockev->ppid, sockev->tgid, sockev->uid, sockev->gid,
				sockev->sock & 0xFFFFFFFF);
		break;
	}
	case HONE_PACKET:
	{
		struct iphdr _iph, *iph =
				skb_header_pointer(event->packet.skb, 0, sizeof(_iph), &_iph);
		printbuf("%lu.%09lu PAKT %c %08lx %u", event->ts.tv_sec,
				event->ts.tv_nsec, event->packet.dir ? 'I' : 'O',
				event->packet.sock & 0xFFFFFFFF, event->packet.pid);
		if (!iph)
			printbuf(" ? ? -> ?");
		else if (iph->version == 4) {
			if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
				struct udphdr _uh, *uh;
				if ((uh = skb_header_pointer(event->packet.skb,
						iph->ihl << 2, sizeof(_uh), &_uh))) {
					printbuf(" %sv4 %pI4:%d -> %pI4:%d",
							iph->protocol == IPPROTO_TCP ? "TCP" : "UDP",
							&iph->saddr, ntohs(uh->source),
							&iph->daddr, ntohs(uh->dest));
				} else {
					printbuf(" %sv4 ? -> ?",
							iph->protocol == IPPROTO_TCP ? "TCP" : "UDP");
				}
			} else {
				printbuf(" %u %pI4 -> %pI4", iph->protocol,
						&iph->saddr, &iph->daddr);
			}
		} else if (iph->version == 6) {
			struct ipv6hdr _iph6, *iph6 =
					skb_header_pointer(event->packet.skb, 0, sizeof(_iph6), &_iph6);
			if (iph6->nexthdr == IPPROTO_TCP || iph6->nexthdr == IPPROTO_UDP) {
				struct udphdr _uh, *uh;
				if ((uh = skb_header_pointer(event->packet.skb,
						sizeof(struct ipv6hdr), sizeof(_uh), &_uh))) {
					printbuf(" %sv6 %pI6:%d -> %pI6:%d",
							iph6->nexthdr == IPPROTO_TCP ? "TCP" : "UDP",
							&iph6->saddr, ntohs(uh->source),
							&iph6->daddr, ntohs(uh->dest));
				} else {
					printbuf(" %sv6 ? -> ?",
							iph6->nexthdr == IPPROTO_TCP ? "TCP" : "UDP");
				}
			} else {
				printbuf(" %u %pI6 -> %pI6", iph6->nexthdr,
						&iph6->saddr, &iph6->daddr);
			}
		} else {
			printbuf(" ?.%d ? -> ?", iph->version);
		}
		/*
		{
			int i;
			for (i = 0; i < pkt->caplen; i += sizeof(int))
				printbuf(" %08x", htonl(*((int *) (pkt->data + i))));
		}
		*/
		printbuf(" %u\n", event->packet.skb->len);
		break;
	}
	case HONE_USER_HEAD:
		if (devinfo->host_guid_is_set)
			printbuf("%lu.%09lu HEAD %lu.%09lu {" GUID_FMT "}\n",
					info->start_time.tv_sec, info->start_time.tv_nsec,
					info->boot_time.tv_sec, info->boot_time.tv_nsec,
					GUID_TUPLE(&devinfo->host_guid));
		else
			printbuf("%lu.%09lu HEAD %lu.%09lu\n",
					info->start_time.tv_sec, info->start_time.tv_nsec,
					info->boot_time.tv_sec, info->boot_time.tv_nsec);
		break;
	default:
		printbuf("%lu.%09lu ???? %d\n",
				event->ts.tv_sec, event->ts.tv_nsec, event->type);
		break;
	}
#undef printbuf

	return n;

out_long:
	snprintf(buf + buflen - 5, 5, "...\n");
	return buflen;
}

static void inc_stats_counter(struct statistics *stats, int type)
{
	atomic64_t *counter;

	switch(type) {
	case HONE_PROCESS:
		counter = &stats->process;
		break;
	case HONE_SOCKET:
		counter = &stats->socket;
		break;
	case HONE_PACKET:
		counter = &stats->packet;
		break;
	default:
		return;
	}
	atomic64_inc(counter);
}

static void inline enqueue_event(struct hone_reader *reader,
		struct hone_event *event)
{
	// Ignore threads for now
	if (event->type == HONE_PROCESS && event->process.pid != event->process.tgid)
		return;
	// Filter out packets for local socket, if set
	if (event->type == HONE_PACKET && reader->filter_sk &&
			event->packet.sock == (unsigned long) reader->filter_sk) {
		atomic64_inc(&reader->info.filtered);
		return;
	}
	get_hone_event(event);
	if (ring_append(&reader->ringbuf, event)) {
		inc_stats_counter(&reader->info.dropped, event->type);
		put_hone_event(event);
	}
}

static int hone_event_handler(struct notifier_block *nb, unsigned long val, void *v)
{
	struct hone_reader *reader =
			container_of(nb, struct hone_reader, nb);

	enqueue_event(reader, v);
	if (waitqueue_active(&event_wait_queue))
		wake_up_interruptible_all(&event_wait_queue);

	return 0;
}

static void free_hone_reader(struct hone_reader *reader)
{
	if (reader) {
		if (reader->ringbuf.data) {
			free_pages((unsigned long) (reader->ringbuf.data), reader->ringbuf.pageorder);
			reader->ringbuf.data = NULL;
		}
		if (reader->buf) {
			free_pages((unsigned long) (reader->buf), READ_BUFFER_PAGE_ORDER);
			reader->buf = NULL;
		}
		kfree(reader);
	}
}

static struct hone_reader *alloc_hone_reader(void)
{
	struct hone_reader *reader;
	struct ring_buf *ring;

	if (!(reader = kzalloc(sizeof(*reader), GFP_KERNEL)))
		goto alloc_failed;
	if (!(reader->buf = (typeof(reader->buf))
				__get_free_pages(GFP_KERNEL | __GFP_ZERO, READ_BUFFER_PAGE_ORDER)))
		goto alloc_failed;
	ring = &reader->ringbuf;
	ring->pageorder = pageorder;
	if (!(ring->data = (typeof(ring->data))
				__get_free_pages(GFP_KERNEL | __GFP_ZERO, ring->pageorder)))
		goto alloc_failed;
	ring->length = size_of_pages(ring->pageorder) / sizeof(*(ring->data));
	//reader->format = format_as_text;
	reader->format = format_as_pcapng;
	atomic_set(&reader->flags, READER_HEAD | READER_INIT);
	sema_init(&reader->sem, 1);
	return reader;

alloc_failed:
	free_hone_reader(reader);
	return NULL;
}


extern const struct file_operations socket_file_ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#define OPEN_FDS open_fds
#else
#define OPEN_FDS open_fds->fds_bits
#endif

static struct hone_event *__add_files(struct hone_reader *reader,
		struct hone_event *event, struct task_struct *task)
{
	struct hone_event *sk_event;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	struct socket *sock;
	struct sock *sk;
	unsigned long flags, set;
	int i, fd;
	
	if (!(files = get_files_struct(task)))
		return event;
	spin_lock_irqsave(&files->file_lock, flags);
	if (!(fdt = files_fdtable(files)))
		goto out;
	for (i = 0; (fd = i * BITS_PER_LONG) < fdt->max_fds; i++) {
		for (set = fdt->OPEN_FDS[i]; set; set >>= 1, fd++) {
			if (!(set & 1))
				continue;
			file = fdt->fd[fd];
			if (!file || file->f_op != &socket_file_ops || !file->private_data)
				continue;
			sock = file->private_data;
			sk = sock->sk;
			if (!sk || (sk->sk_family != PF_INET && sk->sk_family != PF_INET6))
				continue;

			if ((sk_event = __alloc_socket_event((unsigned long) sk,
							0, task, GFP_ATOMIC))) {
				sk_event->next = event;
				event = sk_event;
				event->ts = task->start_time;
			} else {
				atomic64_inc(&reader->info.dropped.socket);
			}
		}
	}
out:
	spin_unlock_irqrestore(&files->file_lock, flags);
	put_files_struct(files);
	return event;
}


#define prev_task(p) \
	list_entry_rcu((p)->tasks.prev, struct task_struct, tasks)

static struct hone_event *add_current_tasks(
		struct hone_reader *reader, struct hone_event *event)
{
	struct hone_event *proc_event;
	struct task_struct *task;

	rcu_read_lock();
	for (task = &init_task; (task = prev_task(task)) != &init_task; ) {
		if (task->flags & PF_EXITING)
			continue;
		event = __add_files(reader, event, task);
		if ((proc_event = __alloc_process_event(task,
						task->flags & PF_FORKNOEXEC ? PROC_FORK : PROC_EXEC,
						GFP_ATOMIC))) {
			proc_event->next = event;
			event = proc_event;
			event->ts = task->start_time;
		} else {
			atomic64_inc(&reader->info.dropped.process);
		}
	}
	rcu_read_unlock();
	return event;
}

static void free_initial_events(struct hone_reader *reader)
{
	struct hone_event *event, *next;

	for (event = reader->event; event; event = next) {
		next = event->next;
		free_hone_event(event);
	}
	reader->event = NULL;
}

static void add_initial_events(struct hone_reader *reader)
{
	free_initial_events(reader);
	reader->event = add_current_tasks(reader, NULL);
}

static int hone_open(struct inode *inode, struct file *file)
{
	struct hone_reader *reader;
	int err = -ENOMEM;

	if ((file->f_flags & O_ACCMODE) != O_RDONLY)
		return -EINVAL;
	if (!(reader = alloc_hone_reader()))
		goto reader_failed;
	if (iminor(inode) == 1)
		reader->format = format_as_text;
	file->private_data = reader;
	getboottime(&reader->info.boot_time);
	ktime_get_ts(&reader->info.start_time);
	init_statistics(&reader->info.delivered);
	init_statistics(&reader->info.dropped);
	reader->nb.notifier_call = hone_event_handler;
	if ((err = hone_notifier_register(&reader->nb))) {
		printm(KERN_ERR, "hone_notifier_register() failed with error %d\n", err);
		goto register_failed;
	}
	__module_get(THIS_MODULE);
	return 0;

register_failed:
	free_hone_reader(reader);
reader_failed:
	return err;
}

static int hone_release(struct inode *inode, struct file *file)
{
	struct hone_reader *reader = file->private_data;
	struct hone_event *event;

	if (!reader)
		return -EFAULT;

	hone_notifier_unregister(&reader->nb);
	file->private_data = NULL;
	while ((event = ring_pop(&reader->ringbuf)))
		put_hone_event(event);
	if (reader->filter_sk) {
		sock_put(reader->filter_sk);
		reader->filter_sk = NULL;
	}
	free_initial_events(reader);
	free_hone_reader(reader);
	module_put(THIS_MODULE);

	return 0;
}

static ssize_t hone_read(struct file *file, char __user *buffer,
		size_t length, loff_t *offset)
{
	struct hone_reader *reader = file->private_data;
	size_t n, copied = 0;

	if (!reader)
		return -EFAULT;

try_sleep:
	while (!*offset && reader_will_block(reader)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(event_wait_queue,
					!reader_will_block(reader)))
			return -EINTR;
	}

	if (file->f_flags & O_NONBLOCK) {
		if (down_trylock(&reader->sem))
			return -EAGAIN;
	} else if (down_interruptible(&reader->sem)) {
		return -EINTR;
	}

	while (copied < length) {
		if (!*offset) {
			int flags;
			struct hone_event *event;
			void (*free_event)(struct hone_event *);

			flags = atomic_read(&reader->flags);
			if (flags & READER_TAIL) {
				atomic_clear_mask(READER_TAIL, &reader->flags);
				event = &tail_event;
				free_event = NULL;
			} else if (flags & READER_FINISH) {
				if (copied)
					break;
				atomic_clear_mask(READER_FINISH, &reader->flags);
				up(&reader->sem);
				return 0;
			} else if (flags & READER_HEAD) {
				atomic_clear_mask(READER_HEAD, &reader->flags);
				event = &head_event;
				free_event = NULL;
			} else if (flags & READER_INIT) {
				atomic_clear_mask(READER_INIT, &reader->flags);
				add_initial_events(reader);
				continue;
			} else if (reader->event) {
				if ((event = reader->event))
					reader->event = event->next;
				free_event = free_hone_event;
			} else {
				event = ring_pop(&reader->ringbuf);
				free_event = put_hone_event;
			}

			if (!event)
				break;
			reader->buflen = reader->format(&devinfo, &reader->info,
					event, reader->buf, READ_BUFFER_SIZE);
			inc_stats_counter(&reader->info.delivered, event->type);
			if (free_event)
				free_event(event);
		}
		n = min(reader->buflen - (size_t) *offset, length - copied);
		if (copy_to_user(buffer + copied, reader->buf + *offset, n)) {
			up(&reader->sem);
			return -EFAULT;
		}
		copied += n;
		*offset += n;
		if (*offset >= reader->buflen)
			*offset = 0;
	}
	up(&reader->sem);
	if (!copied)
		goto try_sleep;
	return copied;
}

extern void fput(struct file *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static long hone_ioctl(struct file *file, unsigned int num,
		unsigned long param)
#else
static int hone_ioctl(struct inode *inode, struct file *file,
		unsigned int num, unsigned long param)
#endif
{
	struct hone_reader *reader = file->private_data;
	int err;

	if (!reader)
		return -EFAULT;

	if (_IOC_TYPE(num) != 0xE0)
		return -EINVAL;

	switch (num) {
	case HEIO_RESTART:
		atomic_set_mask(READER_RESTART, &reader->flags);
		if (waitqueue_active(&event_wait_queue))
			wake_up_interruptible_all(&event_wait_queue);
		return 0;
	case HEIO_GET_AT_HEAD:
		return atomic_read(&reader->flags) & READER_HEAD ? 1 : 0;
	case HEIO_GET_SNAPLEN:
		return put_user(reader->info.snaplen, (unsigned int __user *) param);
	case HEIO_SET_SNAPLEN:
		reader->info.snaplen = (unsigned int) param;
		atomic_set_mask(READER_HEAD, &reader->flags);
		return 0;
	case HEIO_SET_FILTER_SOCK:
	{
		int fd = (int) param;
		struct sock *sk;
		if (fd != -1) {
			struct socket *sock;
			if (!(sock = sockfd_lookup(fd, &err)))
				return err;
			sk = sock->sk;
			sock_hold(sk);
			fput(sock->file);
		} else {
			sk = NULL;
		}
		for (;;) {
			struct sock *old_sk = reader->filter_sk;
			if (cmpxchg(&reader->filter_sk, old_sk, sk) == old_sk) {
				if (old_sk)
					sock_put(old_sk);
				break;
			}
		}
		return 0;
	}
	}

	return -EINVAL;
}

static unsigned int hone_poll(struct file *file,
		struct poll_table_struct *wait)
{
	struct hone_reader *reader = file->private_data;

	if (!reader)
		return -EFAULT;

	if (!reader_will_block(reader))
		return POLLIN;

	poll_wait(file, &event_wait_queue, wait);

	if (!reader_will_block(reader))
		return POLLIN;

	return 0;
}

static const struct file_operations device_ops = {
	.read = hone_read,
	.open = hone_open,
	.release = hone_release,
	.unlocked_ioctl = hone_ioctl,
	.compat_ioctl = hone_ioctl,
	.poll = hone_poll,
};

#ifdef CONFIG_HONE_NOTIFY_COMBINED
	int hone_notify_init(void) __init;
	void hone_notify_release(void);
#else
#	define hone_notify_init() (0)
#	define hone_notify_release()
#endif

static int __init honeevent_init(void)
{
	int err;

	if (hostid && *hostid) {
		if (!hostid_type)
			devinfo.host_id = hostid;
		else if (hostid_type == 1) {
			if (parse_guid(&devinfo.host_guid, hostid)) {
				printm(KERN_ERR, "invalid host GUID: %s\n", hostid);
				return -1;
			}
			printm(KERN_DEBUG, "using host GUID {" GUID_FMT "}\n",
					GUID_TUPLE(&devinfo.host_guid));
			devinfo.host_guid_is_set = true;
		} else {
			printm(KERN_ERR, "invalid hostid_type: %d\n", hostid_type);
			return -1;
		}
	}
	if (comment && *comment)
		devinfo.comment = comment;
	if ((err = hone_notify_init()))
		return -1;
	if ((err = register_chrdev(major, devname, &device_ops)) < 0) {
		printm(KERN_ERR, "character device registration returned error %d\n", err);
		hone_notify_release();
		return -1;
	}
	if (!major)
		major = err;

	class_hone = class_create(THIS_MODULE, devname);
	if (IS_ERR(class_hone)) {
		printm(KERN_ERR, "class_create failed\n");
		return PTR_ERR(class_hone);
	}

	device_create(class_hone, NULL, MKDEV(major, 0), NULL, "%s", devname);
	device_create(class_hone, NULL, MKDEV(major, 1), NULL, "%st", devname);

	printk(KERN_INFO "%s: v%s module successfully loaded with major number %d\n",
			mod_name, version, major);
	return 0;
}

static void __exit honeevent_exit(void)
{
	device_destroy(class_hone, MKDEV(major, 0));
	device_destroy(class_hone, MKDEV(major, 1));
	class_destroy(class_hone);
	unregister_chrdev(major, devname);
	hone_notify_release();

	printk(KERN_INFO "%s: module successfully unloaded\n", mod_name);
}

module_init(honeevent_init);
module_exit(honeevent_exit);


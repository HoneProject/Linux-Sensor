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
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <linux/cred.h>
#include <linux/sched.h>

#include <net/sock.h>

#include "process_notify.h"
#include "socket_notify.h"
#include "packet_notify.h"
#include "hone_notify.h"

static struct kmem_cache *hone_cache;
static RAW_NOTIFIER_HEAD(notifier_list);
static DEFINE_RWLOCK(notifier_lock);
static struct {
	struct statistics received;
	struct statistics dropped;
} statistics = {
	{
		.process = ATOMIC64_INIT(0),
		.socket = ATOMIC64_INIT(0),
		.packet = ATOMIC64_INIT(0)
	},
	{
		.process = ATOMIC64_INIT(0),
		.socket = ATOMIC64_INIT(0),
		.packet = ATOMIC64_INIT(0)
	}
};

#define copy_atomic64(dst, src) atomic64_set(&(dst), atomic64_read(&(src)))

static void copy_statistics(const struct statistics *src, struct statistics *dst)
{
	copy_atomic64(dst->process, src->process);
	copy_atomic64(dst->socket, src->socket);
	copy_atomic64(dst->packet, src->packet);
}

void get_hone_statistics(struct statistics *received, struct statistics *dropped)
{
	if (received)
		copy_statistics(&statistics.received, received);
	if (dropped)
		copy_statistics(&statistics.dropped, dropped);
}

#ifndef rcu_dereference_raw
#define notifier_call_chain_empty() (rcu_dereference(notifier_list.head) == NULL)
#else
#define notifier_call_chain_empty() (rcu_dereference_raw(notifier_list.head) == NULL)
#endif

static void register_notifiers(void);
static void unregister_notifiers(void);

int hone_notifier_register(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	if (notifier_call_chain_empty())
		register_notifiers();
	result = raw_notifier_chain_register(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

int hone_notifier_unregister(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_unregister(&notifier_list, nb);
	if (notifier_call_chain_empty())
		unregister_notifiers();
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

static inline int hone_notifier_notify(struct hone_event *event)
{
	int result;
	unsigned long flags;

	read_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_call_chain(&notifier_list, 0, event);
	read_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

void free_hone_event(struct hone_event *event)
{
	if (event->type == HONE_PACKET) {
		if (event->packet.skb)
			kfree_skb(event->packet.skb);
	} else if (event->type == HONE_PROCESS) {
		if (event->process.mm)
			mmput(event->process.mm);
	}
	kmem_cache_free(hone_cache, event);
}

struct hone_event *alloc_hone_event(unsigned int type, gfp_t flags)
{
	struct hone_event *event;
	
	if (!(event = kmem_cache_zalloc(hone_cache, flags)))
		return NULL;
	event->type = type;
	ktime_get_ts(&event->ts);
	atomic_set(&event->users, 1);
	return event;
}

static struct mm_struct *task_mm(struct task_struct *task)
{
	struct mm_struct *mm;
	unsigned long flags;

	spin_lock_irqsave(&task->alloc_lock, flags);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_KTHREAD)
			mm = NULL;
		else
			atomic_inc(&mm->mm_users);
	}
	spin_unlock_irqrestore(&task->alloc_lock, flags);
	return mm;
}

struct hone_event *__alloc_process_event(
		struct task_struct *task, int type, gfp_t flags)
{
	struct hone_event *event;

	if ((event = alloc_hone_event(HONE_PROCESS, flags))) {
		struct process_event *pev = &event->process;
		const struct cred *cred;
		pev->mm = (type == PROC_EXEC) ? task_mm(task) : NULL;
		pev->event = type;
		pev->pid = task->pid;
		pev->ppid = task->real_parent->pid;
		pev->tgid = task->tgid;
		rcu_read_lock();
		cred = __task_cred(task);
		pev->uid = cred->euid;
		pev->gid = cred->egid;
		rcu_read_unlock();
	}
	return event;
}

static int process_event_handler(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct hone_event *event;

	if (notifier_call_chain_empty())
		return 0;
	if ((event = __alloc_process_event(v, val, GFP_ATOMIC))) {
		atomic64_inc(&statistics.received.process);
		hone_notifier_notify(event);
		put_hone_event(event);
	} else {
		atomic64_inc(&statistics.dropped.process);
	}
	return 0;
}

struct hone_event *__alloc_socket_event(unsigned long sock, int type,
		struct task_struct *task, gfp_t flags)
{
	struct hone_event *event;

	if ((event = alloc_hone_event(HONE_SOCKET, flags))) {
		struct socket_event *sockev = &event->socket;
		const struct cred *cred;
		sockev->sock = sock;
		sockev->event = type;
		sockev->pid = task->pid;
		sockev->ppid = task->real_parent->pid;
		sockev->tgid = task->tgid;
		rcu_read_lock();
		cred = __task_cred(task);
		sockev->uid = cred->euid;
		sockev->gid = cred->egid;
		rcu_read_unlock();
	}
	return event;
}

static int socket_event_handler(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct hone_event *event;

	if (notifier_call_chain_empty())
		return 0;
	if ((event = __alloc_socket_event((unsigned long) v, val, current, GFP_ATOMIC))) {
		atomic64_inc(&statistics.received.socket);
		hone_notifier_notify(event);
		put_hone_event(event);
	} else {
		atomic64_inc(&statistics.dropped.socket);
	}
	return 0;
}

static int packet_event_handler(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct hone_event *event;

	if (notifier_call_chain_empty())
		return 0;
	if ((event = alloc_hone_event(HONE_PACKET, GFP_ATOMIC))) {
		struct packet_args *args = (typeof(args)) v;
		event->packet.sock = (unsigned long) args->sk;
		event->packet.pid = (unsigned long) (args->sk ? args->sk->sk_protinfo : 0);
		event->packet.skb = skb_clone(args->skb, GFP_ATOMIC);
		event->packet.dir = (val == PKTNOT_PACKET_IN);
		atomic64_inc(&statistics.received.packet);
		hone_notifier_notify(event);
		put_hone_event(event);
	} else {
		atomic64_inc(&statistics.dropped.packet);
	}
	return 0;
}

static struct notifier_block process_notifier_block = {
	.notifier_call = process_event_handler,
};

static struct notifier_block socket_notifier_block = {
	.notifier_call = socket_event_handler,
};

static struct notifier_block packet_notifier_block = {
	.notifier_call = packet_event_handler,
};

static void register_notifiers(void)
{
	process_notifier_register(&process_notifier_block);
	sock_notifier_register(&socket_notifier_block);
	packet_notifier_register(&packet_notifier_block);
}

static void unregister_notifiers(void)
{
	packet_notifier_unregister(&packet_notifier_block);
	sock_notifier_unregister(&socket_notifier_block);
	process_notifier_unregister(&process_notifier_block);
}

int hone_notify_init(void)
{
	if (!(hone_cache = kmem_cache_create("hone_event",
					sizeof(struct hone_event), 0, 0, NULL))) {
		printk(KERN_ERR "%s: kmem_cache_create() failed\n", THIS_MODULE->name);
		return -ENOMEM;
	}

	return 0;
}

void hone_notify_release(void)
{
	kmem_cache_destroy(hone_cache);
}

static char __initdata version[] = "0.3";

static int __init hone_notify_module_init(void)
{
	if (hone_notify_init())
		return -1;
	printk("%s: v%s module successfully loaded\n", THIS_MODULE->name, version);
	return 0;
}

static void __exit hone_notify_module_exit(void)
{
	hone_notify_release();
	printk("%s: module successfully unloaded\n", THIS_MODULE->name);
}

module_init(hone_notify_module_init);
module_exit(hone_notify_module_exit);

MODULE_DESCRIPTION("Hone event notifier module.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL_GPL(get_hone_statistics);
EXPORT_SYMBOL_GPL(hone_notifier_register);
EXPORT_SYMBOL_GPL(hone_notifier_unregister);
EXPORT_SYMBOL_GPL(alloc_hone_event);
EXPORT_SYMBOL_GPL(__alloc_process_event);
EXPORT_SYMBOL_GPL(__alloc_socket_event);
EXPORT_SYMBOL_GPL(free_hone_event);


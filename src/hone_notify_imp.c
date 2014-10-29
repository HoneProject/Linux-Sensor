/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/workqueue.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
   #include <linux/uidgid.h>
#else
   #define __kuid_val(_uid) _uid
   #define __kgid_val(_gid) _gid
#endif

#include <net/sock.h>

#include "process_notify.h"
#include "socket_notify.h"
#include "packet_notify.h"
#include "hone_notify.h"
#include "version.h"

static struct kmem_cache *hone_cache;
static RAW_NOTIFIER_HEAD(notifier_list);
static DEFINE_RWLOCK(notifier_lock);

static struct timespec start_time;
static DEFINE_STATISTICS(hone_received);
static DEFINE_STATISTICS(hone_dropped);

static struct kmem_cache *mmput_cache;
static struct workqueue_struct *mmput_wq;
struct delayed_mmput_struct {
	struct work_struct ws;
	struct mm_struct *mm;
};

#define copy_atomic64(dst, src) atomic64_set(&(dst), atomic64_read(&(src)))

static void copy_statistics(const struct statistics *src, struct statistics *dst)
{
	copy_atomic64(dst->process, src->process);
	copy_atomic64(dst->socket, src->socket);
	copy_atomic64(dst->packet, src->packet);
}

void get_hone_statistics(struct statistics *received,
		struct statistics *dropped, struct timespec *ts)
{
	if (received)
		copy_statistics(&hone_received, received);
	if (dropped)
		copy_statistics(&hone_dropped, dropped);
	if (ts)
		*ts = start_time;
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

static void delayed_mmput(struct work_struct *work)
{
	struct delayed_mmput_struct *w = (struct delayed_mmput_struct*)work;
	mmput(w->mm);
	kmem_cache_free(mmput_cache, w);
}

void free_hone_event(struct hone_event *event)
{
	if (event->type == HONE_PACKET) {
		if (event->packet.skb)
			kfree_skb(event->packet.skb);
	} else if (event->type == HONE_PROCESS) {
		if (event->process.mm) {
			if (event->process.event == PROC_KTHD) {
				kfree(event->process.comm);
			} else {
				struct delayed_mmput_struct *delayed_mm =
					kmem_cache_zalloc(mmput_cache, GFP_ATOMIC);
				BUG_ON(unlikely(!delayed_mm));
				delayed_mm->mm = event->process.mm;
				INIT_WORK((struct work_struct*)delayed_mm, delayed_mmput);
				BUG_ON(unlikely(!queue_work(mmput_wq, (struct work_struct*)delayed_mm)));
			}
			event->process.mm = NULL;
		}
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
		pev->event = (type != PROC_EXIT && task->flags & PF_KTHREAD) ? PROC_KTHD : type;
		pev->pid = task->pid;
		pev->ppid = task->real_parent->pid;
		pev->tgid = task->tgid;
		if (pev->event == PROC_KTHD)
		{
			pev->comm = kstrndup(task->comm, sizeof(task->comm), flags);
			BUG_ON(unlikely(!pev->comm));
		}
		else if (type == PROC_EXEC || (type == PROC_FORK && pev->ppid == 1))
		{
			pev->mm = task_mm(task);
			BUG_ON(unlikely(!pev->mm));
		}
		rcu_read_lock();
		cred = __task_cred(task);
		pev->uid = __kuid_val(cred->uid);
		pev->euid = __kuid_val(cred->euid);
		pev->loginuid = __kuid_val(task->loginuid);
		pev->gid = __kgid_val(cred->egid);
		rcu_read_unlock();
	}
	return event;
}


#if defined(CONFIG_PROCESS_NOTIFY) || \
    defined(CONFIG_PROCESS_NOTIFY_MODULE) || \
    defined(CONFIG_PROCESS_NOTIFY_COMBINED)

static int process_event_handler(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct hone_event *event;

	if (notifier_call_chain_empty())
		return 0;
	if ((event = __alloc_process_event(v, val, GFP_ATOMIC))) {
		atomic64_inc(&hone_received.process);
		hone_notifier_notify(event);
		put_hone_event(event);
	} else {
		atomic64_inc(&hone_dropped.process);
	}
	return 0;
}

static struct notifier_block process_notifier_block = {
	.notifier_call = process_event_handler,
};

#	define register_process() process_notifier_register(&process_notifier_block)
#	define unregister_process() process_notifier_unregister(&process_notifier_block)
#else
#	define register_process()
#	define unregister_process()
#endif // CONFIG_PROCESS_NOTIFY*

#ifdef CONFIG_PROCESS_NOTIFY_COMBINED
	extern int process_notify_init(void) __init;
	extern void process_notify_remove(void);
#else
#	define process_notify_init() (0)
#	define process_notify_remove()
#endif // CONFIG_PROCESS_NOTIFY_COMBINED


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
		sockev->uid = __kuid_val(cred->euid);
		sockev->gid = __kgid_val(cred->egid);
		rcu_read_unlock();
	}
	return event;
}


#if defined(CONFIG_SOCKET_NOTIFY) || \
    defined(CONFIG_SOCKET_NOTIFY_MODULE) || \
    defined(CONFIG_SOCKET_NOTIFY_COMBINED)

static int socket_event_handler(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct hone_event *event;

	if (notifier_call_chain_empty())
		return 0;
	if ((event = __alloc_socket_event((unsigned long) v, val, current, GFP_ATOMIC))) {
		atomic64_inc(&hone_received.socket);
		hone_notifier_notify(event);
		put_hone_event(event);
	} else {
		atomic64_inc(&hone_dropped.socket);
	}
	return 0;
}

static struct notifier_block socket_notifier_block = {
	.notifier_call = socket_event_handler,
};

#	define register_socket() sock_notifier_register(&socket_notifier_block)
#	define unregister_socket() sock_notifier_unregister(&socket_notifier_block)
#else
#	define register_socket()
#	define unregister_socket()
#endif // CONFIG_SOCKET_NOTIFY*

#ifdef CONFIG_SOCKET_NOTIFY_COMBINED
	extern int socket_notify_init(void) __init;
	extern void socket_notify_remove(void);
#else
#	define socket_notify_init() (0)
#	define socket_notify_remove()
#endif // CONFIG_SOCKET_NOTIFY_COMBINED


#if defined(CONFIG_PACKET_NOTIFY) || \
    defined(CONFIG_PACKET_NOTIFY_MODULE) || \
    defined(CONFIG_PACKET_NOTIFY_COMBINED)

static int packet_event_handler(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct hone_event *event;

	if (notifier_call_chain_empty())
		return 0;
	if ((event = alloc_hone_event(HONE_PACKET, GFP_ATOMIC))) {
		struct packet_args *args = (typeof(args)) v;
		event->packet.sock = args->sock;
		event->packet.pid = args->pid;
		event->packet.skb = skb_clone(args->skb, GFP_ATOMIC);
		event->packet.dir = (val == PKTNOT_PACKET_IN);
		atomic64_inc(&hone_received.packet);
		hone_notifier_notify(event);
		put_hone_event(event);
	} else {
		atomic64_inc(&hone_dropped.packet);
	}
	return 0;
}

static struct notifier_block packet_notifier_block = {
	.notifier_call = packet_event_handler,
};

#	define register_packet() packet_notifier_register(&packet_notifier_block)
#	define unregister_packet() packet_notifier_unregister(&packet_notifier_block)
#else
#	define register_packet()
#	define unregister_packet()
#endif // CONFIG_PACKET_NOTIFY*

#ifdef CONFIG_PACKET_NOTIFY_COMBINED
	extern int packet_notify_init(void) __init;
	extern void packet_notify_remove(void);
#else
#	define packet_notify_init() (0)
#	define packet_notify_remove()
#endif // CONFIG_PACKET_NOTIFY_COMBINED


static void register_notifiers(void)
{
	register_process();
	register_socket();
	register_packet();
}

static void unregister_notifiers(void)
{
	unregister_packet();
	unregister_socket();
	unregister_process();
}

#ifdef CONFIG_HONE_NOTIFY_COMBINED
#  define _STATIC
#else
#  define _STATIC static
#endif

_STATIC int __init hone_notify_init(void)
{
	int err = 0;

	if ((err = process_notify_init()))
		goto out_process_notify;
	if ((err = socket_notify_init()))
		goto out_socket_notify;
	if ((err = packet_notify_init()))
		goto out_packet_notify;

	if (!(hone_cache = kmem_cache_create("hone_event",
					sizeof(struct hone_event), 0, 0, NULL))) {
		printk(KERN_ERR "%s: kmem_cache_create() failed\n", THIS_MODULE->name);
		err = -ENOMEM;
		goto out_hone_cache;
	}
	if (!(mmput_cache = kmem_cache_create("hone_delayed_mmput",
					      sizeof(struct delayed_mmput_struct),
					      0, 0, NULL))) {
		pr_err("%s: kmem_cache_create() failed on delayed_mm_cache\n",
		       THIS_MODULE->name);
		goto out_mmput_cache;
	}
	mmput_wq = create_workqueue("hone_mmput");
	if (!mmput_wq) {
		err = -1;
		goto out_workqueue;
	}
	ktime_get_ts(&start_time);

	return 0;

out_workqueue:
	kmem_cache_destroy(mmput_cache);
out_mmput_cache:
	kmem_cache_destroy(hone_cache);
out_hone_cache:
	packet_notify_remove();
out_packet_notify:
	socket_notify_remove();
out_socket_notify:
	process_notify_remove();
out_process_notify:
	return err;
}

_STATIC void hone_notify_release(void)
{
	packet_notify_remove();
	socket_notify_remove();
	process_notify_remove();
	kmem_cache_destroy(hone_cache);
	kmem_cache_destroy(mmput_cache);
	destroy_workqueue(mmput_wq);
}

#ifndef CONFIG_HONE_NOTIFY_COMBINED

static char version[] __initdata = HONE_VERSION;

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
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HONE_VERSION);

EXPORT_SYMBOL(get_hone_statistics);
EXPORT_SYMBOL(hone_notifier_register);
EXPORT_SYMBOL(hone_notifier_unregister);
EXPORT_SYMBOL(alloc_hone_event);
EXPORT_SYMBOL(__alloc_process_event);
EXPORT_SYMBOL(__alloc_socket_event);
EXPORT_SYMBOL(free_hone_event);

#endif // CONFIG_HONE_NOTIFY_COMBINED

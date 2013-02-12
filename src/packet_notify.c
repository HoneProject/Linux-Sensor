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
#include <linux/kprobes.h>
#include <linux/notifier.h>
#include <linux/net.h>
#include <linux/netfilter.h>

#if !defined(CONFIG_KPROBES) || !defined(CONFIG_KALLSYMS)
#error packet_notify module requires kprobes support (CONFIG_KPROBES and CONFIG_KALLSYMS)
#endif

#include "socket_lookup.h"
#include "packet_notify.h"
#include "version.h"

static RAW_NOTIFIER_HEAD(notifier_list);
static DEFINE_RWLOCK(notifier_lock);

int packet_notifier_register(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_register(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

int packet_notifier_unregister(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_unregister(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

static inline int packet_notifier_notify(
		unsigned long event, struct packet_args *pargs)
{
	int result;
	unsigned long flags;

	read_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_call_chain(&notifier_list, event, pargs);
	read_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

static int packet_rcv_handler(struct sock *sk, struct sk_buff *skb)
{
	struct packet_args pargs = {sk, skb};
	packet_notifier_notify(PKTNOT_PACKET_IN, &pargs);
	jprobe_return();
	return 0;
}

static int fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_WARNING "%s: fault %d occured in kprobe for %s\n",
			THIS_MODULE->name, trapnr, p->symbol_name);
	return 0;
}

static unsigned int nf_hook_v4_in(unsigned int hook, struct sk_buff *skb,
		const struct net_device *indev, const struct net_device *outdev,
		int (*okfn)(struct sk_buff *))
{
	struct sock *sk = lookup_v4_sock(skb, indev);
	struct packet_args pargs = {sk, skb};
	packet_notifier_notify(PKTNOT_PACKET_IN, &pargs);
	if (sk)
		put_sock(sk);
	return NF_ACCEPT;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static unsigned int nf_hook_v6_in(unsigned int hook, struct sk_buff *skb,
		const struct net_device *indev, const struct net_device *outdev,
		int (*okfn)(struct sk_buff *))
{
	struct sock *sk = lookup_v6_sock(skb, indev);
	struct packet_args pargs = {sk, skb};
	packet_notifier_notify(PKTNOT_PACKET_IN, &pargs);
	if (sk)
		put_sock(sk);
	return NF_ACCEPT;
}
#endif

static unsigned int nf_hook_out(unsigned int hook, struct sk_buff *skb,
		                          const struct net_device *indev,
		                          const struct net_device *outdev,
		                          int (*okfn)(struct sk_buff *))
{
	struct packet_args pargs = {skb->sk, skb};
	packet_notifier_notify(PKTNOT_PACKET_OUT, &pargs);
	return NF_ACCEPT;
}

static struct jprobe raw4_jprobe = {
	.kp.symbol_name = "raw_rcv",
	.kp.fault_handler = fault_handler,
	.entry = packet_rcv_handler,
};

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static struct jprobe raw6_jprobe = {
	.kp.symbol_name = "rawv6_rcv",
	.kp.fault_handler = fault_handler,
	.entry = packet_rcv_handler,
};
#endif // CONFIG_IPV6

static struct jprobe *inet_jprobes[] = {
	&raw4_jprobe,
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	&raw6_jprobe,
#endif // CONFIG_IPV6
};

static struct nf_hook_ops nf_inet_hooks[] = {
	{
		.list = {NULL, NULL},
		.hook = nf_hook_v4_in,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = INT_MAX,
	},
	{
		.list = {NULL, NULL},
		.hook = nf_hook_out,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = INT_MAX,
	},
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	{
		.list = {NULL, NULL},
		.hook = nf_hook_v6_in,
		.owner = THIS_MODULE,
		.pf = PF_INET6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = INT_MAX,
	},
	{
		.list = {NULL, NULL},
		.hook = nf_hook_out,
		.owner = THIS_MODULE,
		.pf = PF_INET6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = INT_MAX,
	},
#endif // CONFIG_IPV6
};

int packet_notify_init(void)
{
	int err;

	if ((err = register_jprobes(inet_jprobes, ARRAY_SIZE(inet_jprobes)))) {
		printk(KERN_ERR "%s: jprobes registration failed (error %d)\n",
				THIS_MODULE->name, err);
		return -1;
	}
	if ((err = nf_register_hooks(nf_inet_hooks, ARRAY_SIZE(nf_inet_hooks)))) {
		printk(KERN_ERR "%s: netfilter hook registration failed (error %d)\n",
				THIS_MODULE->name, err);
		unregister_jprobes(inet_jprobes, ARRAY_SIZE(inet_jprobes));
		return -1;
	}
	return 0;
}

void packet_notify_remove(void)
{
	unregister_jprobes(inet_jprobes, ARRAY_SIZE(inet_jprobes));
	nf_unregister_hooks(nf_inet_hooks, ARRAY_SIZE(nf_inet_hooks));
}

//#ifdef CONFIG_PACKET_NOTIFY
static char version[] __initdata = HONE_VERSION;

static int __init packet_notify_module_init(void)
{
	int err;

	if ((err = packet_notify_init())) {
		printk(KERN_ERR "packet_notify_init() failed with error %d\n", err);
		return -1;
	}
	printk(KERN_INFO "%s: v%s module loaded successfully\n",
			THIS_MODULE->name, version);
	return 0;
}

static void __exit packet_notify_module_exit(void)
{
	packet_notify_remove();
	printk(KERN_INFO "%s: module unloaded successfully\n", THIS_MODULE->name);
}

module_init(packet_notify_module_init);
module_exit(packet_notify_module_exit);

MODULE_DESCRIPTION("Internet protocol packet event notification module.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL");
MODULE_VERSION(HONE_VERSION);

EXPORT_SYMBOL_GPL(packet_notifier_register);
EXPORT_SYMBOL_GPL(packet_notifier_unregister);
//#endif /* CONFIG_PACKET_NOTIFY */


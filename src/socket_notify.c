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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/notifier.h>

#include <linux/in.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "socket_notify.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define DECLARE_CREATE_HOOK(NAME) int NAME(struct net *net, struct socket *sock, int protocol, int kern) 
#define CALL_CREATE_HOOK(NAME) NAME(net, sock, protocol, kern)
#else
#define DECLARE_CREATE_HOOK(NAME) int NAME(struct net *net, struct socket *sock, int protocol)
#define CALL_CREATE_HOOK(NAME) NAME(net, sock, protocol)
#endif

static RAW_NOTIFIER_HEAD(notifier_list);
static DEFINE_RWLOCK(notifier_lock);

static DECLARE_CREATE_HOOK(inet_create_hook);
extern const struct net_proto_family inet_family_ops;
static const struct net_proto_family hooked_inet_family_ops = {
	.family = PF_INET,
	.create = inet_create_hook,
	.owner = THIS_MODULE,
};

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static DECLARE_CREATE_HOOK(inet6_create_hook);
extern const struct net_proto_family inet6_family_ops;
static const struct net_proto_family hooked_inet6_family_ops = {
	.family = PF_INET6,
	.create = inet6_create_hook,
	.owner = THIS_MODULE,
};
#endif

int sock_notifier_register(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_register(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

int sock_notifier_unregister(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_unregister(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

static inline int sock_notifier_notify(unsigned long event, struct sock *sk)
{
	int result;
	unsigned long flags;

	read_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_call_chain(&notifier_list, event, sk);
	read_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

void inet_sock_destruct_hook(struct sock *sk)
{
	sock_notifier_notify(0xFFFFFFFF, sk);
	inet_sock_destruct(sk);
}

static DECLARE_CREATE_HOOK(inet_create_hook)
{
	int err;

	if ((err = CALL_CREATE_HOOK(inet_family_ops.create)))
		return err;
	BUG_ON(unlikely(sock->sk->sk_destruct != inet_sock_destruct));
	sock->sk->sk_destruct = inet_sock_destruct_hook;
	sock_notifier_notify(0, sock->sk);
	return err;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static DECLARE_CREATE_HOOK(inet6_create_hook)
{
	int err;

	if ((err = CALL_CREATE_HOOK(inet6_family_ops.create)))
		return err;
	BUG_ON(unlikely(sock->sk->sk_destruct != inet_sock_destruct));
	sock->sk->sk_destruct = inet_sock_destruct_hook;
	sock_notifier_notify(0, sock->sk);
	return err;
}
#endif

static int reinstall_family(const char *name,
		const struct net_proto_family *family_ops)
{
	int err;

	if ((err = sock_register(family_ops))) {
		printk(KERN_ERR "%s: unable to re-register %s family (error %d); "
				"The system will probably require a reboot to fix networking.\n",
				THIS_MODULE->name, name, err);
		return err;
	}
	module_put(family_ops->owner);
	return 0;
}

static int install_hook(const char *name,
		const struct net_proto_family *family_ops,
		const struct net_proto_family *hooked_ops)
{
	int err;

	if (family_ops->family != hooked_ops->family)
		return -EINVAL;
	if (try_module_get(family_ops->owner)) {
		sock_unregister(family_ops->family);
		if ((err = sock_register(hooked_ops))) {
			printk(KERN_ERR "%s: %s hook registration failed (error %d)\n",
					THIS_MODULE->name, name, err);
			reinstall_family(name, family_ops);
			return err;
		}
	} else {
		printk(KERN_ERR "%s: failed to get reference to %s family ops\n",
				THIS_MODULE->name, name);
		return -ENOENT;
	}
	return 0;
}

int socket_notify_init(void)
{
	int err;

	if ((err = install_hook("IPv4", &inet_family_ops, &hooked_inet_family_ops)))
		return err;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if ((err = install_hook("IPv6", &inet6_family_ops, &hooked_inet6_family_ops))) {
		sock_unregister(hooked_inet_family_ops.family);
		reinstall_family("IPv4", &inet_family_ops);
		return err;
	}
#endif
	return 0;
}

void socket_notify_remove(void)
{
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	sock_unregister(hooked_inet6_family_ops.family);
	reinstall_family("IPv6", &inet6_family_ops);
#endif
	sock_unregister(hooked_inet_family_ops.family);
	reinstall_family("IPv4", &inet_family_ops);
	synchronize_net();
}

//#ifdef CONFIG_SOCKET_NOTIFY
static char __initdata version[] = "0.3";

static int __init socket_notify_module_init(void)
{
	if (socket_notify_init())
		return -1;
	printk("%s: v%s module successfully loaded\n", THIS_MODULE->name, version);
	return 0;
}

static void __exit socket_notify_module_exit(void)
{
	socket_notify_remove();
	printk("%s: module successfully unloaded\n", THIS_MODULE->name);
}

module_init(socket_notify_module_init);
module_exit(socket_notify_module_exit);

MODULE_DESCRIPTION("Socket event notification module.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL_GPL(sock_notifier_register);
EXPORT_SYMBOL_GPL(sock_notifier_unregister);
//#endif /* CONFIG_SOCKET_NOTIFY */


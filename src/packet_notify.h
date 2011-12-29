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

#ifndef _PACKET_NOTIFY_H
#define _PACKET_NOTIFY_H

#define PKTNOT_PACKET_IN 1
#define PKTNOT_PACKET_OUT 2

struct packet_args {
	struct sock *sk;
	struct sk_buff *skb;
};

#ifdef __KERNEL__
extern int packet_notifier_register(struct notifier_block *nb);
extern int packet_notifier_unregister(struct notifier_block *nb);
extern int packet_notify_init(void);
extern void packet_notify_remove(void);
#endif /* __KERNEL__ */

#endif /* _PACKET_NOTIFY_H */


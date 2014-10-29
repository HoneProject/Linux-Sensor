/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

#ifndef _PACKET_NOTIFY_H
#define _PACKET_NOTIFY_H

#define PKTNOT_PACKET_IN 1
#define PKTNOT_PACKET_OUT 2

struct packet_args {
	unsigned long sock;
	unsigned long pid;
	struct sk_buff *skb;
};

#ifdef __KERNEL__
extern int packet_notifier_register(struct notifier_block *nb);
extern int packet_notifier_unregister(struct notifier_block *nb);
#endif /* __KERNEL__ */

#endif /* _PACKET_NOTIFY_H */


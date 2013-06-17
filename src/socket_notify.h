/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

#ifndef _SOCKET_NOTIFY_H
#define _SOCKET_NOTIFY_H

#ifdef __KERNEL__
extern int sock_notifier_register(struct notifier_block *nb);
extern int sock_notifier_unregister(struct notifier_block *nb);
#endif /* __KERNEL__ */

#endif /* _SOCKET_NOTIFY_H */

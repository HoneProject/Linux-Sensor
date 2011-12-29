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

#ifndef _SOCKET_NOTIFY_H
#define _SOCKET_NOTIFY_H

#ifdef __KERNEL__
extern int sock_notifier_register(struct notifier_block *nb);
extern int sock_notifier_unregister(struct notifier_block *nb);
extern int socket_notify_init(void);
extern void socket_notify_remove(void);
#endif /* __KERNEL__ */

#endif /* _SOCKET_NOTIFY_H */

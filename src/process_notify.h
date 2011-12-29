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

#ifndef _PROCESS_NOTIFY_H
#define _PROCESS_NOTIFY_H

#define PROC_FORK 1
#define PROC_EXEC 2
#define PROC_EXIT 3

#ifdef __KERNEL__
extern int process_notifier_register(struct notifier_block *nb);
extern int process_notifier_unregister(struct notifier_block *nb);
extern int process_notify_init(void);
extern void process_notify_remove(void);
#endif /* __KERNEL__ */

#endif /* _PROCESS_NOTIFY_H */


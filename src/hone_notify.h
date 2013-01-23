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

#ifndef _HONE_NOTIFY_H
#define _HONE_NOTIFY_H

#define pr_line() printk(KERN_DEBUG "%s: %s:%d %s\n", THIS_MODULE->name, __FILE__, __LINE__, __FUNCTION__)

#define HONE_PROCESS 1
#define HONE_SOCKET 2
#define HONE_PACKET 3
#define HONE_USER 0x8000

struct process_event {
	struct mm_struct *mm;
	int event;
	pid_t pid;
	pid_t ppid;
	pid_t tgid;
	uid_t uid;
	gid_t gid;
};

struct socket_event {
	unsigned long sock;
	int event;
	pid_t pid;
	pid_t ppid;
	pid_t tgid;
	uid_t uid;
	gid_t gid;
};

struct packet_event {
	unsigned long sock;
	int dir;
	pid_t pid;
	struct sk_buff *skb;
};

struct hone_event;

struct user_event {
	void *data;
};

struct hone_event {
	int type;
	union {
		atomic_t users;
		struct hone_event *next;
	};
	struct timespec ts;
	union {
		struct process_event process;
		struct socket_event socket;
		struct packet_event packet;
		struct user_event user;
	};
};

#ifdef __KERNEL__
extern int hone_notifier_register(struct notifier_block *nb);
extern int hone_notifier_unregister(struct notifier_block *nb);
extern int hone_notify_init(void);
extern void hone_notify_release(void);

extern struct hone_event *alloc_hone_event(unsigned int type, gfp_t flags);
extern void free_hone_event(struct hone_event *event);
extern struct hone_event *__alloc_process_event(
		struct task_struct *task, int type, gfp_t flags);
extern struct hone_event *__alloc_socket_event(unsigned long sock, int type,
		struct task_struct *task, gfp_t flags);

static inline void get_hone_event(struct hone_event *event)
{
	BUG_ON(unlikely(!atomic_read(&event->users)));
	atomic_inc(&event->users);
}

inline void put_hone_event(struct hone_event *event)
{
	BUG_ON(unlikely(!atomic_read(&event->users)));
	if (atomic_dec_and_test(&event->users))
		free_hone_event(event);
}


#endif /* __KERNEL__ */

#endif /* _HONE_NOTIFY_H */


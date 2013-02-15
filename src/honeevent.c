/*
 * Copyright (C) 2011 Battelle Memorial Institute <http://www.battelle.org>
 *
 * Author: Brandon Carpenter
 * Contributor: Erik Jensen
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
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kfifo.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/stringify.h>
#include <linux/poll.h>
#include <linux/utsname.h>

#include <linux/fdtable.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "process_notify.h"
#include "hone_notify.h"
#include "honeevent.h"
#include "mmutil.h"

MODULE_DESCRIPTION("Hone event character device.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL");
MODULE_ALIAS("hone");

static char __initdata version[] = "0.3";

static char *devname = "hone";
module_param(devname, charp, S_IRUGO);
MODULE_PARM_DESC(devname, "The name to give the device in sysfs (default: hone).");

static int major = 0;
module_param(major, int, S_IRUGO);
MODULE_PARM_DESC(major, "The major number to give the device.  "
		"If 0 (the default), the major number is automatically assigned by the kernel.");

static char *hostid = "";
module_param(hostid, charp, S_IRUGO);
MODULE_PARM_DESC(hostid,
		"A GUID which, if given, will be included in the output.");

static char *comment = "";
module_param(comment, charp, S_IRUGO);
MODULE_PARM_DESC(comment, "If given, will be included in the comment option "
		"of the section header block.  Spaces can be encoded as \\040 or \\x20.");

#ifndef CONFIG_HONE_DEFAULT_PAGEORDER
	#ifdef CONFIG_64BIT
		#define CONFIG_HONE_DEFAULT_PAGEORDER 3
	#else
		#define CONFIG_HONE_DEFAULT_PAGEORDER 2
	#endif
#endif

static unsigned int pageorder = CONFIG_HONE_DEFAULT_PAGEORDER;
module_param(pageorder, uint, S_IWUSR|S_IRUGO);
MODULE_PARM_DESC(pageorder,
		"Specifies the page order to use when allocating the ring buffer "
		"(default: " __stringify(CONFIG_HONE_DEFAULT_PAGEORDER) ").  The buffer "
		"size is computed as PAGESIZE * (1 << pageorder).");

static struct class *class_hone;


#define printm(level, fmt, ...) printk(level "%s: %s:%d: " fmt, mod_name, __FILE__, __LINE__, ##__VA_ARGS__)
#define mod_name (THIS_MODULE->name)

#define HONE_USER_HEAD (HONE_USER | 1)
#define HONE_USER_TAIL (HONE_USER | 2)

#define GUID_FMT "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define GUID_TUPLE(G) (G)->data1, (G)->data2, (G)->data3, \
		(G)->data4[0], (G)->data4[1], (G)->data4[2], (G)->data4[3], \
		(G)->data4[4], (G)->data4[5], (G)->data4[6], (G)->data4[7]

struct guid_struct {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t  data4[8];
};

struct ring_buf {
	atomic_t front;
	atomic_t back;
	unsigned int length;
	unsigned int pageorder;
	struct hone_event **data;
};

#define ring_front(ring) ((unsigned int) atomic_read(&(ring)->front))
#define ring_back(ring) ((unsigned int) atomic_read(&(ring)->back))
#define ring_used(ring) (ring_back(ring) - ring_front(ring))
#define ring_is_empty(ring) (ring_front(ring) == ring_back(ring))

static int ring_append(struct ring_buf *ring, struct hone_event *event)
{
	unsigned int back;

	for (;;) {
		back = ring_back(ring);
		if (back - ring_front(ring) >= ring->length)
			return -1;
		if ((unsigned int) atomic_cmpxchg(&ring->back, back, back + 1) == back)
			break;
	}
	ring->data[back % ring->length] = event;
	return 0;
}

static struct hone_event *ring_pop(struct ring_buf *ring)
{
	struct hone_event *event, **slot;
	unsigned int front;

	for (;;) {
		front = ring_front(ring);
		if (front == ring_back(ring))
			return NULL;
		slot = ring->data + (front % ring->length);
		if (!(event = *slot))
			continue;
		if (cmpxchg(slot, event, NULL) == event)
			break;
	}
	atomic_inc(&ring->front);
	return event;
}

#define size_of_pages(order) (PAGE_SIZE << (order))
#define READ_BUFFER_PAGE_ORDER 5
#define READ_BUFFER_SIZE size_of_pages(READ_BUFFER_PAGE_ORDER)

#define READER_HEAD 0x00000001
#define READER_INIT 0x00000002
#define READER_TAIL 0x00000004
#define READER_FINISH 0x00000008
#define READER_RESTART 0x0000000F
#define READER_FILTER_PID 0x00000100

struct hone_reader {
	struct semaphore sem;
	struct ring_buf ringbuf;
	struct notifier_block nb;
	struct timespec boot_time;
	struct timespec start_time;
	unsigned int (*format)(struct hone_reader *,
			struct hone_event *, char *, unsigned int);
	atomic_t flags;
	unsigned int snaplen;
	struct statistics delivered;
	struct statistics dropped;
	struct sock *filter_sk;
	atomic64_t filtered;
	struct hone_event *event;
	unsigned int buflen;
	char *buf;
};

static struct guid_struct host_guid;
static bool host_guid_set = false;
static DECLARE_WAIT_QUEUE_HEAD(event_wait_queue);

static struct hone_event head_event = {HONE_USER_HEAD, {ATOMIC_INIT(1)}};
static struct hone_event tail_event = {HONE_USER_TAIL, {ATOMIC_INIT(1)}};

#define reader_will_block(rdr) (ring_is_empty(&(rdr)->ringbuf) && \
		!(rdr)->event && !(atomic_read(&(rdr)->flags) & READER_RESTART))

static unsigned int format_as_text(struct hone_reader *reader,
		struct hone_event *event, char *buf, unsigned int buflen)
{
	static const char *event_names[] = {"????", "FORK", "EXEC", "EXIT"};
	unsigned int n = 0;

#define printbuf(fmt, ...) ({ if ((n += snprintf(buf + n, buflen - n, fmt, ##__VA_ARGS__)) >= buflen) { goto out_long; }; n; })

	switch (event->type) {
	case HONE_PROCESS:
	{
		struct process_event *pev = &event->process;
		printbuf("%lu.%09lu %s %d %d %d %d %d\n",
				event->ts.tv_sec, event->ts.tv_nsec, event_names[pev->event],
				pev->pid, pev->ppid, pev->tgid, pev->uid, pev->gid);
		if (pev->event == PROC_EXEC && pev->mm) {
			char *path, *argv;
			n--;
			printbuf(" \"");
			if ((path = mm_path(pev->mm, buf + n, buflen -n - 3))) {
				int pathlen = strlen(path);
				memmove(buf + n, path, pathlen);
				n += pathlen;
			}
			printbuf("\" ");
			argv = buf + n;
			n += mm_argv(pev->mm, buf + n, buflen - n - 1);
			for ( ; argv < buf + n; argv++) {
				if (*argv == '\0')
					*argv = ' ';
			}
			printbuf("\n");
		}
		break;
	}
	case HONE_SOCKET:
	{
		struct socket_event *sockev = &event->socket;
		printbuf("%lu.%09lu SOCK %c %d %d %d %d %d %08lx\n",
				event->ts.tv_sec, event->ts.tv_nsec, sockev->event ? 'C' : 'O',
				sockev->pid, sockev->ppid, sockev->tgid, sockev->uid, sockev->gid,
				sockev->sock & 0xFFFFFFFF);
		break;
	}
	case HONE_PACKET:
	{
		struct iphdr _iph, *iph =
				skb_header_pointer(event->packet.skb, 0, sizeof(_iph), &_iph);
		printbuf("%lu.%09lu PAKT %c %08lx %u", event->ts.tv_sec,
				event->ts.tv_nsec, event->packet.dir ? 'I' : 'O',
				event->packet.sock & 0xFFFFFFFF, event->packet.pid);
		if (!iph)
			printbuf(" ? ? -> ?");
		else if (iph->version == 4) {
			if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
				struct udphdr _uh, *uh;
				if ((uh = skb_header_pointer(event->packet.skb,
						iph->ihl << 2, sizeof(_uh), &_uh))) {
					printbuf(" %sv4 %pI4:%d -> %pI4:%d",
							iph->protocol == IPPROTO_TCP ? "TCP" : "UDP",
							&iph->saddr, ntohs(uh->source),
							&iph->daddr, ntohs(uh->dest));
				} else {
					printbuf(" %sv4 ? -> ?",
							iph->protocol == IPPROTO_TCP ? "TCP" : "UDP");
				}
			} else {
				printbuf(" %u %pI4 -> %pI4", iph->protocol,
						&iph->saddr, &iph->daddr);
			}
		} else if (iph->version == 6) {
			struct ipv6hdr _iph6, *iph6 =
					skb_header_pointer(event->packet.skb, 0, sizeof(_iph6), &_iph6);
			if (iph6->nexthdr == IPPROTO_TCP || iph6->nexthdr == IPPROTO_UDP) {
				struct udphdr _uh, *uh;
				if ((uh = skb_header_pointer(event->packet.skb,
						sizeof(struct ipv6hdr), sizeof(_uh), &_uh))) {
					printbuf(" %sv6 %pI6:%d -> %pI6:%d",
							iph6->nexthdr == IPPROTO_TCP ? "TCP" : "UDP",
							&iph6->saddr, ntohs(uh->source),
							&iph6->daddr, ntohs(uh->dest));
				} else {
					printbuf(" %sv6 ? -> ?",
							iph6->nexthdr == IPPROTO_TCP ? "TCP" : "UDP");
				}
			} else {
				printbuf(" %u %pI6 -> %pI6", iph6->nexthdr,
						&iph6->saddr, &iph6->daddr);
			}
		} else {
			printbuf(" ?.%d ? -> ?", iph->version);
		}
		/*
		{
			int i;
			for (i = 0; i < pkt->caplen; i += sizeof(int))
				printbuf(" %08x", htonl(*((int *) (pkt->data + i))));
		}
		*/
		printbuf(" %u\n", event->packet.skb->len);
		break;
	}
	case HONE_USER_HEAD:
		if (host_guid_set)
			printbuf("%lu.%09lu HEAD %lu.%09lu {" GUID_FMT "}\n",
					reader->start_time.tv_sec, reader->start_time.tv_nsec,
					reader->boot_time.tv_sec, reader->boot_time.tv_nsec,
					GUID_TUPLE(&host_guid));
		else
			printbuf("%lu.%09lu HEAD %lu.%09lu\n",
					reader->start_time.tv_sec, reader->start_time.tv_nsec,
					reader->boot_time.tv_sec, reader->boot_time.tv_nsec);
		break;
	default:
		printbuf("%lu.%09lu ???? %d\n",
				event->ts.tv_sec, event->ts.tv_nsec, event->type);
		break;
	}
#undef printbuf

	return n;

out_long:
	snprintf(buf + buflen - 5, 5, "...\n");
	return buflen;
}

#define PADLEN(x) (((x) & 0x3) ? 4 - ((x) & 3) : 0)
#define OPT_SIZE(x) (((x) & 0x3) ? ((((x) >> 2) + 1) << 2) : x)
#define block_set(BUF, TYPE, VAL) \
	({ *((TYPE *) (BUF)) = (VAL); sizeof(TYPE); })

static unsigned int block_opt_ptr(char *buf,
		uint16_t code, const void * ptr, unsigned int length)
{
	char *pos = buf;
	unsigned int padlen = PADLEN(length);

	pos += block_set(pos, uint16_t, code);
	pos += block_set(pos, uint16_t, length);
	if (ptr)
		memcpy(pos, ptr, length);
	pos += length;
	memset(pos, 0, padlen);
	pos += padlen;
	return (unsigned int) (pos - buf);
}

#define block_opt_t(BUF, CODE, TYPE, VAL) ({ \
		TYPE _value = (VAL); \
		unsigned int _length = block_opt_ptr(BUF, CODE, &_value, sizeof(_value)); \
		_length; })
#define block_opt(BUF, CODE, VAL) block_opt_t(BUF, CODE, typeof(VAL), VAL)
#define block_end_opt(BUF) block_opt_ptr(BUF, 0, NULL, 0)

struct timestamp {
	uint32_t ts_high;
	uint32_t ts_low;
};

static void timespec_to_tstamp(struct timestamp *tstamp, struct timespec *ts)
{
	uint64_t val = (((uint64_t) ts->tv_sec) * 1000000LL) + ts->tv_nsec / 1000;
	tstamp->ts_high = val >> 32;
	tstamp->ts_low = val & 0xFFFFFFFF;
}

/* Section Header Block {{{
  0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                   Block Type = 0x0A0D0D0A                     |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                      Byte-Order Magic                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |          Major Version        |         Minor Version         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                                                               |
   |                          Section Length                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
}}} */
static unsigned int format_sechdr_block(char *buf, unsigned int buflen)
{
	char *pos = buf;
	unsigned int *length_top, *length_end;
	int n;

	// Be sure to update this value if fields are added below.
#define SECHDR_BLOCK_MIN_LEN 52
	if (buflen < SECHDR_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x0A0D0D0A);  // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);           // block length
	pos += block_set(pos, uint32_t, 0x1A2B3C4D);  // byte-order magic
	pos += block_set(pos, uint16_t, 1);           // major version
	pos += block_set(pos, uint16_t, 0);           // minor version
	pos += block_set(pos, uint64_t, -1);          // section length
	if (host_guid_set)
		pos += block_opt(pos, 257, host_guid);
	if ((n = buflen - (pos - buf) - 16) > 0) {
		struct new_utsname *uname;
		down_read(&uts_sem);
		uname = utsname();
		snprintf(pos + 4, n, "%s %s %s %s %s",
				uname->sysname, uname->nodename, uname->release,
				uname->version, uname->machine);
		up_read(&uts_sem);
		pos[n] = '\0';
		pos += block_opt_ptr(pos, 3, NULL, strlen(pos + 4));
	}
	if (*comment && (n = buflen - (pos - buf) - 16) > 0) {
		unsigned int i, j;
		for (i = 0, j = 4; comment[i] && j < n; i++, j++) {
			if (comment[i] == '\\' && (!strncmp(comment + i + 1, "040", 3) ||
						!strncmp(comment + i + 1, "x20", 3))) {
				pos[j] = ' ';
				i += 3;
			} else
				pos[j] = comment[i];
		}
		if ((n = j - 4))
			pos += block_opt_ptr(pos, 1, NULL, n);
	}
	pos += block_end_opt(pos);
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

/* Interface Description Block {{{
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000001                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |           LinkType            |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                            SnapLen                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
}}} */	
static unsigned int format_ifdesc_block(struct hone_reader *reader,
		char *buf, int buflen)
{
	static const char *if_desc = "Hone Capture Pseudo-device";
	char *pos = buf;
	unsigned int *length_top, *length_end;

	// Be sure to update this value if fields are added below.
#define IFDESC_BLOCK_MIN_LEN 56
	if (buflen < IFDESC_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x00000001);  // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);    // block length
	pos += block_set(pos, uint16_t, 101);  // link type
	pos += block_set(pos, uint16_t, 0);    // reserved
	pos += block_set(pos, uint32_t, reader->snaplen);  // snaplen
	pos += block_opt_ptr(pos, 3, if_desc, strlen(if_desc));  // if_description
	pos += block_end_opt(pos);
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

/* Interface Statistics Block {{{
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                   Block Type = 0x00000005                     |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                         Interface ID                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
}}} */	
static unsigned int format_ifstats_block(struct hone_reader *reader,
		char *buf, int buflen)
{
	char *pos = buf;
	unsigned int *length_top, *length_end;
	struct timespec ts;
	struct timestamp tstamp, start_time;
	struct statistics received, dropped;

	get_hone_statistics(&received, &dropped, &ts);
	set_normalized_timespec(&ts, reader->boot_time.tv_sec + ts.tv_sec,
			reader->boot_time.tv_nsec + ts.tv_nsec);
	timespec_to_tstamp(&start_time, &ts);
	ktime_get_ts(&ts);
	set_normalized_timespec(&ts, reader->boot_time.tv_sec + ts.tv_sec,
			reader->boot_time.tv_nsec + ts.tv_nsec);
	timespec_to_tstamp(&tstamp, &ts);
	// Be sure to update this value if fields are added below.
#define IFSTATS_BLOCK_MIN_LEN 56
	if (buflen < IFDESC_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x00000005);              // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);                       // block length
	pos += block_set(pos, uint32_t, 0);                       // interface ID
	pos += block_set(pos, struct timestamp, tstamp);          // timestamp
	pos += block_opt_t(pos, 2, struct timestamp, start_time); // start time
	pos += block_opt_t(pos, 4, uint64_t, atomic64_read(&received.packet));
	pos += block_opt_t(pos, 5, uint64_t, atomic64_read(&dropped.packet));
	pos += block_opt_t(pos, 6, uint64_t, atomic64_read(&reader->filtered));
	pos += block_opt_t(pos, 7, uint64_t, atomic64_read(&reader->dropped.packet));
	pos += block_opt_t(pos, 8, uint64_t, atomic64_read(&reader->delivered.packet));
	pos += block_opt_t(pos, 257, uint64_t, atomic64_read(&received.process));
	pos += block_opt_t(pos, 258, uint64_t, atomic64_read(&dropped.process));
	pos += block_opt_t(pos, 259, uint64_t, atomic64_read(&reader->dropped.process));
	pos += block_opt_t(pos, 260, uint64_t, atomic64_read(&reader->delivered.process));
	pos += block_opt_t(pos, 261, uint64_t, atomic64_read(&received.socket));
	pos += block_opt_t(pos, 262, uint64_t, atomic64_read(&dropped.socket));
	pos += block_opt_t(pos, 263, uint64_t, atomic64_read(&reader->dropped.socket));
	pos += block_opt_t(pos, 264, uint64_t, atomic64_read(&reader->delivered.socket));
	pos += block_end_opt(pos);
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

static inline unsigned int maxoptlen(int buflen, unsigned int length)
{
	unsigned int alignlen = ((buflen - 16) >> 2) << 2;
	if (unlikely(buflen < 0))
		return 0;
	return alignlen < length ? alignlen : length;
}

/* Process Event Block {{{
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000101                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                          Process ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
}}} */
static size_t format_process_block(struct process_event *event,
		struct timestamp *tstamp, char *buf, size_t buflen)
{
	char *pos = buf;
	unsigned int *length_top, *length_end; //, length;

	// Be sure to update this value if fields are added below.
#define PROCESS_BLOCK_MIN_LEN 56
	if (buflen < PROCESS_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x00000101);     // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);              // block length
	pos += block_set(pos, uint32_t, event->tgid);    // PID
	pos += block_set(pos, struct timestamp, *tstamp); // timestamp
	if (event->event != PROC_EXEC)
		pos += block_opt_t(pos, 2, uint32_t, (event->event == PROC_FORK ? 1 : -1));
	pos += block_opt_t(pos, 5, uint32_t, event->ppid);
	pos += block_opt_t(pos, 6, uint32_t, event->uid);
	pos += block_opt_t(pos, 7, uint32_t, event->gid);
	if (event->mm) {
		char *tmp, *ptr;
		unsigned int n, length;
		ptr = pos + 4;
		length = buflen - (pos - buf) - 16;
		if (length > 0 && (tmp = mm_path(event->mm, ptr, length))) {
			if ((length = maxoptlen(length, strlen(tmp)))) {
				memmove(ptr, tmp, length);
				pos += block_opt_ptr(pos, 3, NULL, length);
			}
		}
		ptr = pos + 4;
		length = buflen - (pos - buf) - 16;
		if (length > 0 && (n = mm_argv(event->mm, ptr, length)))
			pos += block_opt_ptr(pos, 4, NULL, maxoptlen(length, n));
	}
	pos += block_end_opt(pos);
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

/* Connection Event Block {{{
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000102                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                        Connection ID                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                          Process ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
}}} */
static size_t format_connection_block(struct socket_event *event,
		struct timestamp *tstamp, char *buf, size_t buflen)
{
	char *pos = buf;
	unsigned int *length_top, *length_end;

	// Be sure to update this value if fields are added below.
#define CONNECTION_BLOCK_MIN_LEN 40
	if (buflen < CONNECTION_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x00000102);  // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);           // block length
	pos += block_set(pos, uint32_t, event->sock & 0xFFFFFFFF); // connection id
	pos += block_set(pos, uint32_t, event->tgid); // PID
	pos += block_set(pos, struct timestamp, *tstamp); // timestamp
	if (event->event) {
		pos += block_opt_t(pos, 2, uint32_t, -1);
		pos += block_end_opt(pos);
	}
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

/* Enhanced Packet Block {{{
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000006                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                         Interface ID                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 |                         Captured Len                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 |                          Packet Len                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28 /                                                               /
   /                          Packet Data                          /
   /           ( variable length, aligned to 32 bits )             /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
}}} */
static size_t format_packet_block(struct packet_event *event,
		unsigned int snaplen, struct timestamp *tstamp, char *buf, size_t buflen)
{
	char *pos = buf;
	unsigned int *length_top, *length_end, *length_cap;
	struct sk_buff *skb = event->skb;

	// Be sure to update this value if fields are added below.
#define PACKET_BLOCK_MIN_LEN 52
	if (buflen < PACKET_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x00000006);  // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);           // block length
	pos += block_set(pos, uint32_t, 0);           // interface ID
	pos += block_set(pos, struct timestamp, *tstamp); // timestamp
	length_cap = (typeof(length_cap)) pos;
	pos += block_set(pos, uint32_t, 0);           // captured length
	pos += block_set(pos, uint32_t, skb->len);    // packet length

	// packet data
	if ((*length_cap = maxoptlen(buflen - (pos - buf),
					(snaplen ? min(skb->len, snaplen) : skb->len)))) {
		unsigned int n = *length_cap & 3 ? 4 - (*length_cap & 3) : 0;
		if (skb_copy_bits(skb, 0, pos, *length_cap))
			BUG();
		pos += *length_cap;
		memset(pos, 0, n);
		pos += n;
	}

	// socket id
	if (event->sock)  // Only add the option if we found a socket
		pos += block_opt_t(pos, 257, uint32_t, event->sock & 0xFFFFFFFF);
	// process id
	if (event->pid)
		pos += block_opt_t(pos, 258, uint32_t, event->pid);
	pos += block_opt_t(pos, 2, uint32_t, event->dir ? 1 : 2);
	pos += block_end_opt(pos);
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

static void normalize_ts(struct timestamp *tstamp,
		struct timespec *boot_time, struct timespec *event_time)
{
	struct timespec ts;

	// The following is used instead of timespec_add()
	// because it doesn't exist in older kernel versions.
	set_normalized_timespec(&ts, boot_time->tv_sec + event_time->tv_sec,
			boot_time->tv_nsec + event_time->tv_nsec);
	timespec_to_tstamp(tstamp, &ts);
}

static unsigned int format_as_pcapng(struct hone_reader *reader,
		struct hone_event *event, char *buf, unsigned int buflen)
{
	unsigned int n = 0;
	struct timestamp tstamp;

	switch (event->type) {
	case HONE_PACKET:
		normalize_ts(&tstamp, &reader->boot_time, &event->ts);
		n = format_packet_block(
				&event->packet, reader->snaplen, &tstamp, buf, buflen);
		break;
	case HONE_PROCESS:
		normalize_ts(&tstamp, &reader->boot_time, &event->ts);
		n = format_process_block(&event->process, &tstamp, buf, buflen);
		break;
	case HONE_SOCKET:
		normalize_ts(&tstamp, &reader->boot_time, &event->ts);
		n = format_connection_block(&event->socket, &tstamp, buf, buflen);
		break;
	case HONE_USER_HEAD:
		n = format_sechdr_block(buf, buflen);
		n += format_ifdesc_block(reader, buf + n, buflen - n);
		break;
	case HONE_USER_TAIL:
		n = format_ifstats_block(reader, buf + n, buflen - n);
		break;
	}

	return n;
}

static void inc_stats_counter(struct statistics *stats, int type)
{
	atomic64_t *counter;

	switch(type) {
	case HONE_PROCESS:
		counter = &stats->process;
		break;
	case HONE_SOCKET:
		counter = &stats->socket;
		break;
	case HONE_PACKET:
		counter = &stats->packet;
		break;
	default:
		return;
	}
	atomic64_inc(counter);
}

static void inline enqueue_event(struct hone_reader *reader,
		struct hone_event *event)
{
	// Ignore threads for now
	if (event->type == HONE_PROCESS && event->process.pid != event->process.tgid)
		return;
	// Filter out packets for local socket, if set
	if (event->type == HONE_PACKET && reader->filter_sk &&
			event->packet.sock == (unsigned long) reader->filter_sk) {
		atomic64_inc(&reader->filtered);
		return;
	}
	get_hone_event(event);
	if (ring_append(&reader->ringbuf, event)) {
		inc_stats_counter(&reader->dropped, event->type);
		put_hone_event(event);
	}
}

static int hone_event_handler(struct notifier_block *nb, unsigned long val, void *v)
{
	struct hone_reader *reader =
			container_of(nb, struct hone_reader, nb);

	enqueue_event(reader, v);
	if (waitqueue_active(&event_wait_queue))
		wake_up_interruptible_all(&event_wait_queue);

	return 0;
}

static void free_hone_reader(struct hone_reader *reader)
{
	if (reader) {
		if (reader->ringbuf.data) {
			free_pages((unsigned long) (reader->ringbuf.data), reader->ringbuf.pageorder);
			reader->ringbuf.data = NULL;
		}
		if (reader->buf) {
			free_pages((unsigned long) (reader->buf), READ_BUFFER_PAGE_ORDER);
			reader->buf = NULL;
		}
		kfree(reader);
	}
}

static struct hone_reader *alloc_hone_reader(void)
{
	struct hone_reader *reader;
	struct ring_buf *ring;

	if (!(reader = kzalloc(sizeof(*reader), GFP_KERNEL)))
		goto alloc_failed;
	if (!(reader->buf = (typeof(reader->buf))
				__get_free_pages(GFP_KERNEL | __GFP_ZERO, READ_BUFFER_PAGE_ORDER)))
		goto alloc_failed;
	ring = &reader->ringbuf;
	ring->pageorder = pageorder;
	if (!(ring->data = (typeof(ring->data))
				__get_free_pages(GFP_KERNEL | __GFP_ZERO, ring->pageorder)))
		goto alloc_failed;
	ring->length = size_of_pages(ring->pageorder) / sizeof(*(ring->data));
	//reader->format = format_as_text;
	reader->format = format_as_pcapng;
	atomic_set(&reader->flags, READER_HEAD | READER_INIT);
	sema_init(&reader->sem, 1);
	return reader;

alloc_failed:
	free_hone_reader(reader);
	return NULL;
}


extern const struct file_operations socket_file_ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#define OPEN_FDS open_fds
#else
#define OPEN_FDS open_fds->fds_bits
#endif

static struct hone_event *__add_files(struct hone_reader *reader,
		struct hone_event *event, struct task_struct *task)
{
	struct hone_event *sk_event;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	struct socket *sock;
	struct sock *sk;
	unsigned long flags, set;
	int i, fd;
	
	if (!(files = get_files_struct(task)))
		return event;
	spin_lock_irqsave(&files->file_lock, flags);
	if (!(fdt = files_fdtable(files)))
		goto out;
	for (i = 0; (fd = i * BITS_PER_LONG) < fdt->max_fds; i++) {
		for (set = fdt->OPEN_FDS[i]; set; set >>= 1, fd++) {
			if (!(set & 1))
				continue;
			file = fdt->fd[fd];
			if (!file || file->f_op != &socket_file_ops || !file->private_data)
				continue;
			sock = file->private_data;
			sk = sock->sk;
			if (!sk || (sk->sk_family != PF_INET && sk->sk_family != PF_INET6))
				continue;

			if ((sk_event = __alloc_socket_event((unsigned long) sk,
							0, task, GFP_ATOMIC))) {
				sk_event->next = event;
				event = sk_event;
				event->ts = task->start_time;
			} else {
				atomic64_inc(&reader->dropped.socket);
			}
		}
	}
out:
	spin_unlock_irqrestore(&files->file_lock, flags);
	put_files_struct(files);
	return event;
}


#define prev_task(p) \
	list_entry_rcu((p)->tasks.prev, struct task_struct, tasks)

static struct hone_event *add_current_tasks(
		struct hone_reader *reader, struct hone_event *event)
{
	struct hone_event *proc_event;
	struct task_struct *task;

	rcu_read_lock();
	for (task = &init_task; (task = prev_task(task)) != &init_task; ) {
		if (task->flags & PF_EXITING)
			continue;
		event = __add_files(reader, event, task);
		if ((proc_event = __alloc_process_event(task,
						task->flags & PF_FORKNOEXEC ? PROC_FORK : PROC_EXEC,
						GFP_ATOMIC))) {
			proc_event->next = event;
			event = proc_event;
			event->ts = task->start_time;
		} else {
			atomic64_inc(&reader->dropped.process);
		}
	}
	rcu_read_unlock();
	return event;
}

static void free_initial_events(struct hone_reader *reader)
{
	struct hone_event *event, *next;

	for (event = reader->event; event; event = next) {
		next = event->next;
		free_hone_event(event);
	}
	reader->event = NULL;
}

static void add_initial_events(struct hone_reader *reader)
{
	free_initial_events(reader);
	reader->event = add_current_tasks(reader, NULL);
}

static int hone_open(struct inode *inode, struct file *file)
{
	struct hone_reader *reader;
	int err = -ENOMEM;

	if ((file->f_flags & O_ACCMODE) != O_RDONLY)
		return -EINVAL;
	if (!(reader = alloc_hone_reader()))
		goto reader_failed;
	if (iminor(inode) == 1)
		reader->format = format_as_text;
	file->private_data = reader;
	getboottime(&reader->boot_time);
	ktime_get_ts(&reader->start_time);
	init_statistics(&reader->delivered);
	init_statistics(&reader->dropped);
	reader->nb.notifier_call = hone_event_handler;
	if ((err = hone_notifier_register(&reader->nb))) {
		printm(KERN_ERR, "hone_notifier_register() failed with error %d\n", err);
		goto register_failed;
	}
	__module_get(THIS_MODULE);
	return 0;

register_failed:
	free_hone_reader(reader);
reader_failed:
	return err;
}

static int hone_release(struct inode *inode, struct file *file)
{
	struct hone_reader *reader = file->private_data;
	struct hone_event *event;

	if (!reader)
		return -EFAULT;

	hone_notifier_unregister(&reader->nb);
	file->private_data = NULL;
	while ((event = ring_pop(&reader->ringbuf)))
		put_hone_event(event);
	if (reader->filter_sk) {
		sock_put(reader->filter_sk);
		reader->filter_sk = NULL;
	}
	free_initial_events(reader);
	free_hone_reader(reader);
	module_put(THIS_MODULE);

	return 0;
}

static ssize_t hone_read(struct file *file, char __user *buffer,
		size_t length, loff_t *offset)
{
	struct hone_reader *reader = file->private_data;
	size_t n, copied = 0;

	if (!reader)
		return -EFAULT;

try_sleep:
	while (!*offset && reader_will_block(reader)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(event_wait_queue,
					!reader_will_block(reader)))
			return -EINTR;
	}

	if (file->f_flags & O_NONBLOCK) {
		if (down_trylock(&reader->sem))
			return -EAGAIN;
	} else if (down_interruptible(&reader->sem)) {
		return -EINTR;
	}

	while (copied < length) {
		if (!*offset) {
			int flags;
			struct hone_event *event;
			void (*free_event)(struct hone_event *);

			flags = atomic_read(&reader->flags);
			if (flags & READER_TAIL) {
				atomic_clear_mask(READER_TAIL, &reader->flags);
				event = &tail_event;
				free_event = NULL;
			} else if (flags & READER_FINISH) {
				if (copied)
					break;
				atomic_clear_mask(READER_FINISH, &reader->flags);
				up(&reader->sem);
				return 0;
			} else if (flags & READER_HEAD) {
				atomic_clear_mask(READER_HEAD, &reader->flags);
				event = &head_event;
				free_event = NULL;
			} else if (flags & READER_INIT) {
				atomic_clear_mask(READER_INIT, &reader->flags);
				add_initial_events(reader);
				continue;
			} else if (reader->event) {
				if ((event = reader->event))
					reader->event = event->next;
				free_event = free_hone_event;
			} else {
				event = ring_pop(&reader->ringbuf);
				free_event = put_hone_event;
			}

			if (!event)
				break;
			reader->buflen = reader->format(reader,
					event, reader->buf, READ_BUFFER_SIZE);
			inc_stats_counter(&reader->delivered, event->type);
			if (free_event)
				free_event(event);
		}
		n = min(reader->buflen - (size_t) *offset, length - copied);
		if (copy_to_user(buffer + copied, reader->buf + *offset, n)) {
			up(&reader->sem);
			return -EFAULT;
		}
		copied += n;
		*offset += n;
		if (*offset >= reader->buflen)
			*offset = 0;
	}
	up(&reader->sem);
	if (!copied)
		goto try_sleep;
	return copied;
}

extern void fput(struct file *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static long hone_ioctl(struct file *file, unsigned int num,
		unsigned long param)
#else
static int hone_ioctl(struct inode *inode, struct file *file,
		unsigned int num, unsigned long param)
#endif
{
	struct hone_reader *reader = file->private_data;
	int err;

	if (!reader)
		return -EFAULT;

	if (_IOC_TYPE(num) != 0xE0)
		return -EINVAL;

	switch (num) {
	case HEIO_RESTART:
		atomic_set_mask(READER_RESTART, &reader->flags);
		if (waitqueue_active(&event_wait_queue))
			wake_up_interruptible_all(&event_wait_queue);
		return 0;
	case HEIO_GET_AT_HEAD:
		return atomic_read(&reader->flags) & READER_HEAD ? 1 : 0;
	case HEIO_GET_SNAPLEN:
		return put_user(reader->snaplen, (unsigned int __user *) param);
	case HEIO_SET_SNAPLEN:
		reader->snaplen = (unsigned int) param;
		atomic_set_mask(READER_HEAD, &reader->flags);
		return 0;
	case HEIO_SET_FILTER_SOCK:
	{
		int fd = (int) param;
		struct sock *sk;
		if (fd != -1) {
			struct socket *sock;
			if (!(sock = sockfd_lookup(fd, &err)))
				return err;
			sk = sock->sk;
			sock_hold(sk);
			fput(sock->file);
		} else {
			sk = NULL;
		}
		for (;;) {
			struct sock *old_sk = reader->filter_sk;
			if (cmpxchg(&reader->filter_sk, old_sk, sk) == old_sk) {
				if (old_sk)
					sock_put(old_sk);
				break;
			}
		}
		return 0;
	}
	}

	return -EINVAL;
}

static unsigned int hone_poll(struct file *file,
		struct poll_table_struct *wait)
{
	struct hone_reader *reader = file->private_data;

	if (!reader)
		return -EFAULT;

	if (!reader_will_block(reader))
		return POLLIN;

	poll_wait(file, &event_wait_queue, wait);

	if (!reader_will_block(reader))
		return POLLIN;

	return 0;
}

static const struct file_operations device_ops = {
	.read = hone_read,
	.open = hone_open,
	.release = hone_release,
	.unlocked_ioctl = hone_ioctl,
	.compat_ioctl = hone_ioctl,
	.poll = hone_poll,
};

static int parse_guid(struct guid_struct *guid, const char *input)
{
	int i, val;
	const char *pos = input;
	char *buf = (typeof(buf)) guid;

	if (*pos == '{')
		pos++;
	for (i = 0; *pos && i < 32; pos++) {
		if (*pos == '-') {
			if (pos == input)
				return -1;
			continue;
		}
		if (*pos >= '0' && *pos <= '9')
			val = *pos - '0';
		else if (*pos >= 'a' && *pos <= 'f')
			val = *pos - 'W';
		else if (*pos >= 'A' && *pos <= 'F')
			val = *pos - '7';
		else
			return -1;
		if (i % 2) {
			buf[i / 2] += val;
			i++;
		} else {
			buf[i / 2] = val << 4;
			i++;
		}
	}
	if (i < 32)
		return -1;
	if (*input == '{') {
		if (*pos != '}')
			return -1;
		pos++;
	}
	if (*pos)
		return -1;
	guid->data1 = ntohl(guid->data1);
	guid->data2 = ntohs(guid->data2);
	guid->data3 = ntohs(guid->data3);
	return 0;
}


static int __init honeevent_init(void)
{
	int err;

	if (hostid && *hostid) {
		if (parse_guid(&host_guid, hostid)) {
			printm(KERN_ERR, "invalid host GUID provided\n");
			return -1;
		}
		printm(KERN_DEBUG, "using host GUID {" GUID_FMT "}\n",
				GUID_TUPLE(&host_guid));
		host_guid_set = true;
	}
	if ((err = register_chrdev(major, devname, &device_ops)) < 0) {
		printm(KERN_ERR, "character device registration returned error %d\n", err);
		return -1;
	}
	if (!major)
		major = err;

	class_hone = class_create(THIS_MODULE, devname);
	if (IS_ERR(class_hone)) {
		printm(KERN_ERR, "class_create failed\n");
		return PTR_ERR(class_hone);
	}

	device_create(class_hone, NULL, MKDEV(major, 0), NULL, "%s", devname);
	device_create(class_hone, NULL, MKDEV(major, 1), NULL, "%st", devname);

	printk(KERN_INFO "%s: v%s module successfully loaded with major number %d\n",
			mod_name, version, major);
	return 0;
}

static void __exit honeevent_exit(void)
{
	device_destroy(class_hone, MKDEV(major, 0));
	device_destroy(class_hone, MKDEV(major, 1));
	class_destroy(class_hone);
	unregister_chrdev(major, devname);

	printk(KERN_INFO "%s: module successfully unloaded\n", mod_name);
}

module_init(honeevent_init);
module_exit(honeevent_exit);


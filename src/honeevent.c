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
		"If 0 (the default), the major is automatically assigned by the kernel.");

static char *hostid = "";
module_param(hostid, charp, S_IRUGO);
MODULE_PARM_DESC(hostid,
		"A GUID which, if given, will be included in the output.");

static char *comment = "";
module_param(comment, charp, S_IRUGO);
MODULE_PARM_DESC(comment, "If given, will be included in the comment option "
		"of the section header block.  Spaces can be encoded as \\040 or \\x20.");

static unsigned int snaplen = 0;
module_param(snaplen, uint, S_IRUGO);
MODULE_PARM_DESC(snaplen, "The maximum length of packet data included in the "
		"output.  If 0 (the default), do full packet capture.");

#ifdef CONFIG_64BIT
#define DEFAULT_PAGE_ORDER 2
#define PAGE_ORDER_STR "2"
#else
#define DEFAULT_PAGE_ORDER 1
#define PAGE_ORDER_STR "1"
#endif

static unsigned char pageorder = DEFAULT_PAGE_ORDER;
module_param(pageorder, byte, S_IRUGO);
MODULE_PARM_DESC(pageorder, "Specifies the page order to use when allocating "
		"the ring buffer (default: " PAGE_ORDER_STR ").  The buffer size is "
		"computed using the formula size = PAGE_SIZE * pow(2, pageorder).");

static struct class *class_hone;


#define printm(level, fmt, ...) printk(level "%s: %s:%d: " fmt, mod_name, __FILE__, __LINE__, ##__VA_ARGS__)
#define mod_name (THIS_MODULE->name)

#define HONE_USER_RESTART (HONE_USER | 0)
#define HONE_USER_HEAD (HONE_USER | 1)

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
	unsigned int front;
	unsigned int back;
	unsigned int length;
	struct hone_event **data;
};

#define ring_unused(ring) ((ring)->length - ((ring)->back - (ring)->front))
#define ring_is_empty(ring) ((ring)->front == (ring)->back)

static int ring_append(struct ring_buf *ring, struct hone_event *event)
{
	if (!ring_unused(ring))
		return -1;
	ring->data[ring->back % ring->length] = event;
	smp_wmb();
	ring->back++;
	return 0;
}

static int ring_prepend(struct ring_buf *ring, struct hone_event *event)
{
	if (!ring_unused(ring))
		return -1;
	ring->data[(ring->front - 1) % ring->length] = event;
	smp_wmb();
	ring->front--;
	return 0;
}

static int ring_pop(struct ring_buf *ring, struct hone_event **event)
{
	if (ring_is_empty(ring))
		return -1;
	if (event)
		*event = ring->data[ring->front % ring->length];
	ring->front++;
	return 0;
}

static struct hone_event *ring_peek(struct ring_buf *ring)
{
	if (ring_is_empty(ring))
		return NULL;
	return ring->data[ring->front % ring->length];
}

static void ring_advance(struct ring_buf *ring)
{
	ring->front++;
}

#define pow2(order) ((order > 0) ? 2 << ((order) - 1) : 1)
#define size_of_pages(order) (PAGE_SIZE * pow2(order))
#define READ_BUFFER_PAGEORDER 1
#define READ_BUFFER_SIZE size_of_pages(READ_BUFFER_PAGEORDER)

struct hone_reader {
	struct ring_buf ringbuf;
	spinlock_t ring_lock;
	struct notifier_block nb;
	struct timespec start_time;
	unsigned int (*format)(struct hone_reader *,
			struct hone_event *, char *, unsigned int);
	unsigned int flags;
	unsigned int buflen;
	char *buf;
};

static struct guid_struct host_guid;
static bool host_guid_set = false;
static DECLARE_WAIT_QUEUE_HEAD(event_wait_queue);
static struct hone_event head_event = {
	.type = HONE_USER_HEAD,
	.users = ATOMIC_INIT(1),
};
static struct hone_event restart_event = {
	.type = HONE_USER_RESTART,
	.users = ATOMIC_INIT(1),
};


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
		printbuf("%lu.%09lu PAKT %c %08lx", event->ts.tv_sec, event->ts.tv_nsec,
				event->packet.dir ? 'I' : 'O', event->packet.sock & 0xFFFFFFFF);
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
	{
		struct timespec ts;

		ktime_get_ts(&ts);
		if (host_guid_set)
			printbuf("%lu.%09lu HEAD %lu.%09lu {" GUID_FMT "}\n",
					ts.tv_sec, ts.tv_nsec,
					reader->start_time.tv_sec, reader->start_time.tv_nsec,
					GUID_TUPLE(&host_guid));
		else
			printbuf("%lu.%09lu HEAD %lu.%09lu\n", ts.tv_sec, ts.tv_nsec,
					reader->start_time.tv_sec, reader->start_time.tv_nsec);
		break;
	}
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
#define block_end_opt(BUF) block_opt_ptr(BUF, 0, NULL, 0)

struct timestamp {
	uint32_t ts_high;
	uint32_t ts_low;
};

static inline struct timestamp timespec_to_tstamp(struct timespec ts)
{
	uint64_t val = (((uint64_t) ts.tv_sec) * 1000000LL) + ts.tv_nsec / 1000;
	struct timestamp tstamp = {
		.ts_high = val >> 32,
		.ts_low = val & 0xFFFFFFFF,
	};
	return tstamp;
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
static unsigned int get_sechdr_block(char *buf, unsigned int buflen)
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
		pos += block_opt_t(pos, 257, struct guid_struct, host_guid);
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
static unsigned int get_ifdesc_block(struct hone_reader *reader,
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
	pos += block_set(pos, uint32_t, snaplen);  // snaplen
	pos += block_opt_ptr(pos, 3, if_desc, strlen(if_desc));  // if_description
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
static size_t get_process_block(struct process_event *event,
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
	pos += block_set(pos, uint32_t,                  // PID
			(event->pid == event->tgid ? event->pid : event->tgid));
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
static size_t get_connection_block(struct socket_event *event,
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
	pos += block_set(pos, uint32_t,               // PID
			(event->pid == event->tgid ? event->pid : event->tgid));
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
static size_t get_packet_block(struct packet_event *event,
		struct timestamp *tstamp, char *buf, size_t buflen)
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
	pos += block_opt_t(pos, 2, uint32_t, event->dir ? 1 : 2);
	pos += block_end_opt(pos);
	length_end = (typeof(length_end)) pos;
	pos += block_set(pos, uint32_t, 0);
	*length_top = *length_end = (unsigned int) (pos - buf);
	return *length_top;
}

static unsigned int format_as_pcapng(struct hone_reader *reader,
		struct hone_event *event, char *buf, unsigned int buflen)
{
	unsigned int n = 0;
	struct timespec ts = timespec_add(event->ts, reader->start_time);
	struct timestamp tstamp = timespec_to_tstamp(ts);

	switch (event->type) {
	case HONE_USER_HEAD:
		n = get_sechdr_block(buf, buflen);
		n += get_ifdesc_block(reader, buf + n, buflen - n);
		break;
	case HONE_PROCESS:
		n = get_process_block(&event->process, &tstamp, buf, buflen);
		break;
	case HONE_SOCKET:
		n = get_connection_block(&event->socket, &tstamp, buf, buflen);
		break;
	case HONE_PACKET:
		n = get_packet_block(&event->packet, &tstamp, buf, buflen);
		break;
	}

	if (n > buflen) {
		n = buflen;
		buf[n - 1] = '\n';
	}
	return n;
}

static void inline enqueue_event(struct hone_reader *reader,
		struct hone_event *event)
{
	unsigned int added;
	unsigned long flags;

	if (event->type == HONE_PROCESS) {
		// Ignore threads for now
		if (event->process.pid != event->process.tgid)
			return;
	}
	spin_lock_irqsave(&reader->ring_lock, flags);
	added = !ring_append(&reader->ringbuf, event);
	spin_unlock_irqrestore(&reader->ring_lock, flags);
	if (added)
		get_hone_event(event);
	// XXX: else increment appropriate missed event counter
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
	free_pages((unsigned long) reader->ringbuf.data, pageorder);
	free_pages((unsigned long) reader->buf, READ_BUFFER_PAGEORDER);
	kfree(reader);
}

static struct hone_reader *alloc_hone_reader(void)
{
	struct hone_reader *reader;

	if (!(reader = kzalloc(sizeof(*reader), GFP_KERNEL)))
		goto reader_alloc_failed;
	if (!(reader->buf = (typeof(reader->buf))
				__get_free_pages(GFP_KERNEL, READ_BUFFER_PAGEORDER)))
		goto buffer_alloc_failed;
	if (!(reader->ringbuf.data = (typeof(reader->ringbuf.data))
				__get_free_pages(GFP_KERNEL, pageorder)))
		goto ring_alloc_failed;
	reader->ringbuf.length =
			size_of_pages(pageorder) / sizeof(*(reader->ringbuf.data));
	spin_lock_init(&reader->ring_lock);
	//reader->format = format_as_text;
	reader->format = format_as_pcapng;
	return reader;

ring_alloc_failed:
	free_pages((unsigned long) reader->buf, READ_BUFFER_PAGEORDER);
buffer_alloc_failed:
	free_hone_reader(reader);
reader_alloc_failed:
	return NULL;
}


extern const struct file_operations socket_file_ops;

static void __add_files(struct hone_reader *reader, struct task_struct *task)
{
	struct ring_buf *ring = &reader->ringbuf;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	struct socket *sock;
	struct sock *sk;
	struct hone_event *event, **slot;
	unsigned long flags, files_flags;
	int j;
	
	if (!(files = get_files_struct(task)))
		return;
	spin_lock_irqsave(&files->file_lock, files_flags);
	if (!(fdt = files_fdtable(files)))
		goto out;
	for (j = 0;; j++) {
		unsigned long set;
		int i = j * __NFDBITS;
		if (i >= fdt->max_fds)
			break;
		for (set = fdt->open_fds->fds_bits[j]; set; set >>= 1, i++) {
			if (!(set & 1))
				continue;
			file = fdt->fd[i];
			if (!file || file->f_op != &socket_file_ops || !file->private_data)
				continue;
			sock = file->private_data;
			sk = sock->sk;
			if (!sk || (sk->sk_family != PF_INET && sk->sk_family != PF_INET6))
				continue;

			spin_lock_irqsave(&reader->ring_lock, flags);
			if ((ring_prepend(ring, NULL)))
				slot = NULL;
			else
				slot = &ring->data[ring->front % ring->length];
			spin_unlock_irqrestore(&reader->ring_lock, flags);
			if (!slot)
				continue;   // XXX: increment missed process counter
			if (!(event = __alloc_socket_event((unsigned long) sk,
					0, task, GFP_ATOMIC))) {
				ring_pop(ring, NULL);
				continue;  // XXX: increment missed connection counter
			}
			event->ts = task->start_time;
			*slot = event;
		}
	}
out:
	spin_unlock_irqrestore(&files->file_lock, files_flags);
	put_files_struct(files);
}


#define prev_task(p) \
	list_entry_rcu((p)->tasks.prev, struct task_struct, tasks)

static void add_current_tasks(struct hone_reader *reader)
{
	struct ring_buf *ring = &reader->ringbuf;
	struct hone_event *event, **slot;
	struct task_struct *task;
	unsigned long flags;
	int type;

	rcu_read_lock();
	for (task = &init_task; (task = prev_task(task)) != &init_task; ) {
		if (task->flags & PF_EXITING)
			continue;
		else if (task->flags & PF_FORKNOEXEC)
			type = PROC_FORK;
		else
			type = PROC_EXEC;
		__add_files(reader, task);
		spin_lock_irqsave(&reader->ring_lock, flags);
		if ((ring_prepend(ring, NULL)))
			slot = NULL;
		else
			slot = &ring->data[ring->front % ring->length];
		spin_unlock_irqrestore(&reader->ring_lock, flags);
		if (!slot)
			continue;   // XXX: increment missed process counter
		if (!(event = __alloc_process_event(task, type, GFP_ATOMIC))) {
			ring_pop(ring, NULL);
			continue;   // XXX: increment missed process counter
		}
		event->ts = task->start_time;
		*slot = event;
	}
	rcu_read_unlock();
}

static void add_initial_events(struct hone_reader *reader)
{
	struct hone_event *event = NULL;
	unsigned long flags;

	add_current_tasks(reader);
	spin_lock_irqsave(&reader->ring_lock, flags);
	if (!ring_unused(&reader->ringbuf))
		ring_pop(&reader->ringbuf, &event);
	if (!ring_prepend(&reader->ringbuf, &head_event))
		get_hone_event(&head_event);
	// XXX: else increment appropriate missed event counter
	spin_unlock_irqrestore(&reader->ring_lock, flags);
	if (event)
		put_hone_event(event);   // XXX: increment missed event counter
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
	getboottime(&reader->start_time);
	reader->nb.notifier_call = hone_event_handler;
	if ((err = hone_notifier_register(&reader->nb))) {
		printm(KERN_ERR, "hone_notifier_register() failed with error %d\n", err);
		goto register_failed;
	}
	__module_get(THIS_MODULE);
	add_initial_events(reader);
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
	while (!(ring_pop(&reader->ringbuf, &event)))
		put_hone_event(event);
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
	while (!*offset && ring_is_empty(&reader->ringbuf)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(event_wait_queue,
					!ring_is_empty(&reader->ringbuf)))
			return -EINTR;
	}

	while (copied < length) {
		if (!(*offset)) {
			struct hone_event *event = ring_peek(&reader->ringbuf);

			if (!event)
				break;
			if (event == &restart_event) {
				if (copied)
					return copied;
				ring_advance(&reader->ringbuf);
				put_hone_event(event);
				add_initial_events(reader);
				event = ring_peek(&reader->ringbuf);
				return -EAGAIN;
			}
			ring_advance(&reader->ringbuf);
			reader->buflen = reader->format(reader,
					event, reader->buf, READ_BUFFER_SIZE);
			put_hone_event(event);
		}
		n = min(reader->buflen - (size_t) *offset, length - copied);
		if (copy_to_user(buffer + copied, reader->buf + *offset, n))
			return -EFAULT;
		copied += n;
		*offset += n;
		if (*offset >= reader->buflen)
			*offset = 0;
	}
	if (!copied)
		goto try_sleep;
	return copied;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static long hone_ioctl(struct file *file, unsigned int num,
		unsigned long param)
#else
static int hone_ioctl(struct inode *inode, struct file *file,
		unsigned int num, unsigned long param)
#endif
{
	struct hone_reader *reader = file->private_data;

	if (!reader)
		return -EFAULT;

	if (_IOC_TYPE(num) != 0xE0)
		return -EINVAL;

	switch (num) {
		case HEIO_RESTART:
			add_initial_events(reader);
			return 0;
		case HEIO_MARK_RESTART:
		{
			struct hone_event *event = NULL;
			unsigned long flags;

			spin_lock_irqsave(&reader->ring_lock, flags);
			if (!ring_unused(&reader->ringbuf))
				ring_pop(&reader->ringbuf, &event);
			if (!ring_prepend(&reader->ringbuf, &restart_event))
				get_hone_event(&restart_event);
			// XXX: else increment appropriate missed event counter
			spin_unlock_irqrestore(&reader->ring_lock, flags);
			if (event)
				put_hone_event(event);   // XXX: increment missed event counter
			//add_initial_events(reader);
			return 0;
		}
		case HEIO_GET_AT_HEAD:
		{
			struct hone_event *event = ring_peek(&reader->ringbuf);
			return event == &head_event ? 1 : 0;
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

	if (!ring_is_empty(&reader->ringbuf))
		return POLLIN;

	poll_wait(file, &event_wait_queue, wait);

	if (!ring_is_empty(&reader->ringbuf))
		return POLLIN;

	return 0;
}

static const struct file_operations device_ops = {
	.read = hone_read,
	.open = hone_open,
	.release = hone_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
	.unlocked_ioctl = hone_ioctl,
#else
	.ioctl = hone_ioctl,
#endif
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

	if (pageorder > 10) {
		printm(KERN_ERR, "pageorder must be <= 10\n");
		return -1;
	}
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


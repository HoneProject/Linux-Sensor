/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/utsname.h>
#include <linux/skbuff.h>

#include "process_notify.h"
#include "hone_notify.h"
#include "pcapng.h"
#include "mmutil.h"
#include "version.h"

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
static unsigned int format_sechdr_block(const struct device_info *devinfo,
		char *buf, unsigned int buflen)
{
	static const char *user_app = "Hone " HONE_VERSION;
	char *pos = buf;
	unsigned int *length_top, *length_end;
	int n;

	// Be sure to update this value if fields are added below.
#define SECHDR_BLOCK_MIN_LEN 56
	if (buflen < SECHDR_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x0A0D0D0A);  // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);           // block length
	pos += block_set(pos, uint32_t, 0x1A2B3C4D);  // byte-order magic
	pos += block_set(pos, uint16_t, 1);           // major version
	pos += block_set(pos, uint16_t, 0);           // minor version
	pos += block_set(pos, uint64_t, -1);          // section length
	if (devinfo->host_id && (n = buflen - (pos - buf) - 16) > 0) {
		snprintf(pos + 4, n, "%c%s", 0, devinfo->host_id);
		pos += block_opt_ptr(pos, 257, NULL, strlen(pos + 5) + 1);
	} else if (devinfo->host_guid_is_set) {
		memcpy(pos + 4, "\x01\x00\x00\x00", 4);
		memcpy(pos + 8, &devinfo->host_guid, sizeof(devinfo->host_guid));
		pos += block_opt_ptr(pos, 257, NULL, 20);
	}
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
	if ((n = buflen - (pos - buf) - 16) > 0)
		pos += block_opt_ptr(pos, 4, user_app, min(n, (typeof(n)) strlen(user_app)));
	if (devinfo->comment && (n = buflen - (pos - buf) - 16) > 0) {
		unsigned int i, j;
		for (i = 0, j = 4; devinfo->comment[i] && j < n; i++, j++) {
			if (devinfo->comment[i] == '\\' &&
					(!strncmp(devinfo->comment + i + 1, "040", 3) ||
					 !strncmp(devinfo->comment + i + 1, "x20", 3))) {
				pos[j] = ' ';
				i += 3;
			} else
				pos[j] = devinfo->comment[i];
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
static unsigned int format_ifdesc_block(const struct reader_info *info,
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
	pos += block_set(pos, uint32_t, info->snaplen);  // snaplen
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
static unsigned int format_ifstats_block(const struct reader_info *info,
		char *buf, int buflen)
{
	char *pos = buf;
	unsigned int *length_top, *length_end;
	struct timespec ts;
	struct timestamp tstamp, start_time;
	struct statistics received, dropped;

	get_hone_statistics(&received, &dropped, &ts);
	set_normalized_timespec(&ts, info->boot_time.tv_sec + ts.tv_sec,
			info->boot_time.tv_nsec + ts.tv_nsec);
	timespec_to_tstamp(&start_time, &ts);
	ktime_get_ts(&ts);
	set_normalized_timespec(&ts, info->boot_time.tv_sec + ts.tv_sec,
			info->boot_time.tv_nsec + ts.tv_nsec);
	timespec_to_tstamp(&tstamp, &ts);
	// Be sure to update this value if fields are added below.
#define IFSTATS_BLOCK_MIN_LEN 196
	if (buflen < IFSTATS_BLOCK_MIN_LEN)
		return 0;
	pos += block_set(pos, uint32_t, 0x00000005);              // block type
	length_top = (typeof(length_top)) pos;
	pos += block_set(pos, uint32_t, 0);                       // block length
	pos += block_set(pos, uint32_t, 0);                       // interface ID
	pos += block_set(pos, struct timestamp, tstamp);          // timestamp
	pos += block_opt_t(pos, 2, struct timestamp, start_time); // start time
	pos += block_opt_t(pos, 4, uint64_t, atomic64_read(&received.packet));
	pos += block_opt_t(pos, 5, uint64_t, atomic64_read(&dropped.packet));
	pos += block_opt_t(pos, 6, uint64_t, atomic64_read(&info->filtered));
	pos += block_opt_t(pos, 7, uint64_t, atomic64_read(&info->dropped.packet));
	pos += block_opt_t(pos, 8, uint64_t, atomic64_read(&info->delivered.packet));
	pos += block_opt_t(pos, 257, uint64_t, atomic64_read(&received.process));
	pos += block_opt_t(pos, 258, uint64_t, atomic64_read(&dropped.process));
	pos += block_opt_t(pos, 259, uint64_t, atomic64_read(&info->dropped.process));
	pos += block_opt_t(pos, 260, uint64_t, atomic64_read(&info->delivered.process));
	pos += block_opt_t(pos, 261, uint64_t, atomic64_read(&received.socket));
	pos += block_opt_t(pos, 262, uint64_t, atomic64_read(&dropped.socket));
	pos += block_opt_t(pos, 263, uint64_t, atomic64_read(&info->dropped.socket));
	pos += block_opt_t(pos, 264, uint64_t, atomic64_read(&info->delivered.socket));
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
	int offset;
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
	offset = skb_network_header(skb) - skb->data;  // offset should be <= 0
	if ((*length_cap = maxoptlen(buflen - (pos - buf),
				(snaplen ? min(skb->len - offset, snaplen) : skb->len - offset)))) {
		unsigned int n = *length_cap & 3 ? 4 - (*length_cap & 3) : 0;
		if (skb_copy_bits(skb, offset, pos, *length_cap))
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
		const struct timespec *boot_time, const struct timespec *event_time)
{
	struct timespec ts;

	// The following is used instead of timespec_add()
	// because it doesn't exist in older kernel versions.
	set_normalized_timespec(&ts, boot_time->tv_sec + event_time->tv_sec,
			boot_time->tv_nsec + event_time->tv_nsec);
	timespec_to_tstamp(tstamp, &ts);
}

unsigned int format_as_pcapng(
		const struct device_info *devinfo, const struct reader_info *info,
		struct hone_event *event, char *buf, unsigned int buflen)
{
	unsigned int n = 0;
	struct timestamp tstamp;

	switch (event->type) {
	case HONE_PACKET:
		normalize_ts(&tstamp, &info->boot_time, &event->ts);
		n = format_packet_block(
				&event->packet, info->snaplen, &tstamp, buf, buflen);
		break;
	case HONE_PROCESS:
		normalize_ts(&tstamp, &info->boot_time, &event->ts);
		n = format_process_block(&event->process, &tstamp, buf, buflen);
		break;
	case HONE_SOCKET:
		normalize_ts(&tstamp, &info->boot_time, &event->ts);
		n = format_connection_block(&event->socket, &tstamp, buf, buflen);
		break;
	case HONE_USER_HEAD:
		n = format_sechdr_block(devinfo, buf, buflen);
		n += format_ifdesc_block(info, buf + n, buflen - n);
		break;
	case HONE_USER_TAIL:
		n = format_ifstats_block(info, buf + n, buflen - n);
		break;
	}

	return n;
}

int parse_guid(struct guid_struct *guid, const char *input)
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


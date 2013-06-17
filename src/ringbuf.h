/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 *
 * Implementation of lock-free ring buffer.
 */

#ifndef _RINGBUF_H
#define _RINGBUF_H

#include <linux/types.h>

struct ring_buf {
	atomic_t front;
	atomic_t back;
	unsigned int length;
	unsigned int pageorder;
	void **data;
};

#define ring_front(ring) ((unsigned int) atomic_read(&(ring)->front))
#define ring_back(ring) ((unsigned int) atomic_read(&(ring)->back))
#define ring_used(ring) (ring_back(ring) - ring_front(ring))
#define ring_is_empty(ring) (ring_front(ring) == ring_back(ring))

int ring_append(struct ring_buf *ring, void *elem);
void *ring_pop(struct ring_buf *ring);

#endif /* _RINGBUF_H */


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

#include <asm/atomic.h>

#include "ringbuf.h"

int ring_append(struct ring_buf *ring, void *elem)
{
	unsigned int back;

	for (;;) {
		back = ring_back(ring);
		if (back - ring_front(ring) >= ring->length)
			return -1;
		if ((unsigned int) atomic_cmpxchg(&ring->back, back, back + 1) == back)
			break;
	}
	ring->data[back % ring->length] = elem;
	return 0;
}

void *ring_pop(struct ring_buf *ring)
{
	void *elem, **slot;
	unsigned int front;

	for (;;) {
		front = ring_front(ring);
		if (front == ring_back(ring))
			return NULL;
		slot = ring->data + (front % ring->length);
		if (!(elem = *slot))
			continue;
		if (cmpxchg(slot, elem, NULL) == elem)
			break;
	}
	atomic_inc(&ring->front);
	return elem;
}

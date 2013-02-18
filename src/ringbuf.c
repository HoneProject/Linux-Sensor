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

/* 
 * Implementation of lock-free ring buffer.
 */

#include <linux/atomic.h>

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

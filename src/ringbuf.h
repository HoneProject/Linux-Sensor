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


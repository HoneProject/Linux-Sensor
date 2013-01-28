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

#ifndef _HONEEVENT_H
#define _HONEEVENT_H

#define HEIO_RESTART _IO(0xE0, 0x01)
#define HEIO_GET_AT_HEAD _IO(0xE0, 0x03)
#define HEIO_GET_SNAPLEN _IOR(0xE0, 0x04, int)
#define HEIO_SET_SNAPLEN _IOW(0xE0, 0x05, int)

#endif /* _HONEEVENT_H */

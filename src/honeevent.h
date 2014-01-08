/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 *
 * Author: Brandon Carpenter
 */

#ifndef _HONEEVENT_H
#define _HONEEVENT_H

#define HEIO_RESTART _IO(0xE0, 0x01)
#define HEIO_GET_AT_HEAD _IO(0xE0, 0x03)
#define HEIO_GET_SNAPLEN _IOR(0xE0, 0x04, int)
#define HEIO_SET_SNAPLEN _IOW(0xE0, 0x05, int)
#define HEIO_SET_FILTER_SOCK _IOW(0xE0, 0x06, int)

#endif /* _HONEEVENT_H */

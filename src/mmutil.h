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
 *
 * Much of the code below is based on procfs code.
 */

#ifndef _MMUTIL_H
#define _MMUTIL_H

#include <linux/mm_types.h>

char *mm_path(struct mm_struct *mm, char *buf, int buflen);
int mm_argv(struct mm_struct *mm, char *buf, int buflen);

#endif /* _MMUTIL_H */


/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

#ifndef _MMUTIL_H
#define _MMUTIL_H

#include <linux/mm_types.h>

char *mm_path(struct mm_struct *mm, char *buf, int buflen);
int mm_argv(struct mm_struct *mm, char *buf, int buflen);

#endif /* _MMUTIL_H */


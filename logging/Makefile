#
# Copyright (C) 2011 Battelle Memorial Institute
#
# Licensed under the GNU General Public License Version 2.
# See ../src/LICENSE for the full text of the license.
# See ../src/DISCLAIMER for additional disclaimers.
# 
# Author: Brandon Carpenter
#

DESTDIR ?= /usr/local/bin
HONEDIR ?= ../src

all: honeread

clean:
	-rm -f honeread

honeread: honeread.c
	gcc -Wall -O2 $(CFLAGS) -I$(HONEDIR) -o $@ $<

install: honeread
	install -m 0755 $^ "$(DESTDIR)"

uninstall:
	rm -f "$(DESTDIR)/honeread"


#
# Copyright (C) 2011 Battelle Memorial Institute
#
# Licensed under a modified 3-clause BSD license.
# See LICENSE for the full text of the license.
# See DISCLAIMER for additional disclaimers.
# 
# Author: Brandon Carpenter
#

all: honelogd

clean:
	-rm -f honelogd

honelogd: honelogd.c
	gcc -Wall -O2 $(CFLAGS) -I../src -o $@ $<

install: honelogd
	install $^ /usr/local/sbin

uninstall:
	rm /usr/local/sbin/honelogd


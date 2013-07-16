#
# Copyright (C) 2011 Battelle Memorial Institute
#
# Licensed under the GNU General Public License Version 2.
# See ../src/LICENSE for the full text of the license.
# See ../src/DISCLAIMER for additional disclaimers.
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


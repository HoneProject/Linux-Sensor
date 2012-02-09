#
# Copyright (C) 2011 Battelle Memorial Institute <http://www.battelle.org>
#
# Author: Brandon Carpenter
#
# This package is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This package is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

ifneq ($(KERNELRELEASE),)

CONFIG_SOCKET_NOTIFY ?= m
CONFIG_PACKET_NOTIFY ?= m
CONFIG_PROCESS_NOTIFY ?= m
CONFIG_HONE_NOTIFY ?= m
CONFIG_HONEEVENT ?= m

obj-$(CONFIG_SOCKET_NOTIFY) += socket_notify.o
socket_notify-defsyms = inet_family_ops inet6_family_ops

obj-$(CONFIG_PACKET_NOTIFY) += packet_notify.o
packet_notify-defsyms = __udp6_lib_lookup nf_tproxy_get_sock_v4

obj-$(CONFIG_PROCESS_NOTIFY) += process_notify.o

obj-$(CONFIG_HONE_NOTIFY) += hone_notify.o

obj-$(CONFIG_HONEEVENT) += honeevent.o
honeevent-defsyms = uts_sem socket_file_ops get_files_struct put_files_struct

include $(src)/defsyms.mk

else

SVNVER := $(shell svnversion 2>/dev/null | grep -o '^[0-9]\+[A-Z]\?')
MODVER := $(shell date +'%y.%m.%d')
VERSION := $(MODVER)$(if $(SVNVER),+$(SVNVER))
version-name := hone-$(VERSION)
tarball-name := $(version-name).tar.gz

KVER ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KVER)/build

hone-source = dkms.conf.in dkms.conf Makefile defsyms.mk LICENSE README $(filter-out %.mod.c,$(wildcard *.[ch])) debian/* hone.spec.in hone.spec
clean-files = dkms.conf hone.spec
pkg-version = $(shell dpkg-parsechangelog | sed -r '/^Version:/!d;s/^[^:]+:\s+//' || sed -r '2,$d;s/^.*\((.*)\).*$/\1/' debian/changelog)

all: prereq_check modules

prereq_check:
	@ if [ ! -f $(KSRC)/include/linux/version.h ]; then \
		echo "Kernel source was not found. Aborting."; \
		exit 1; \
	  fi

help:
	make -C $(KSRC) M=$(CURDIR) help

modules:
	make -C $(KSRC) M=$(CURDIR) modules

modules_install install:
	make -C $(KSRC) M=$(CURDIR) modules_install

clean:
	make -C $(KSRC) M=$(CURDIR) clean
	rm -f $(clean-files)

snapshot-changelog:
	@if [ "$(call pkg-version)" != "$(VERSION)" ]; then \
	  echo "hone ($(VERSION)) unstable; urgency=low" > debian/changelog.new; \
	  echo "" >> debian/changelog.new; \
	  echo "  * New snapshot release." >> debian/changelog.new; \
	  echo "" >> debian/changelog.new; \
	  echo " -- $${DEBFULLNAME:-$$USER} <$${DEBEMAIL:-$$USER@$$HOSTNAME}>  `date -R`" >> debian/changelog.new; \
	  echo "" >> debian/changelog.new; \
	  cat debian/changelog >> debian/changelog.new; \
	  mv -f debian/changelog.new debian/changelog; \
	 fi

packages: deb rpm tarball

deb: $(tarball-name)
	-rm -rf deb-build/$(version-name)
	[ -d deb-build ] || mkdir deb-build
	tar xzf $(tarball-name) -C deb-build
	cd deb-build/$(version-name) && dpkg-buildpackage -tc -uc -us
	rm -rf deb-build/$(version-name)

rpm: $(tarball-name)
	[ -d rpm-build ] || mkdir rpm-build
	rpmbuild --define='_topdir $(CURDIR)/rpm-build' --clean -ta ./$(tarball-name)

tarball: $(tarball-name)

$(tarball-name): $(hone-source) snapshot-changelog
	tar czf $@ --transform 's@^@hone-$(VERSION)/@' --exclude .svn --exclude '.*.swp' $(hone-source)

hone.spec: hone.spec.in
	sed -r 's/^(Version: ).*$$/\1$(VERSION)/' $< > $@

dkms.conf: dkms.conf.in
	sed -r 's/^(PACKAGE_VERSION=).*$$/\1"$(VERSION)"/' $< > $@

PHONY: all prereq_check help modules modules_install install clean \
	snapshot-changelog packages deb rpm tarball

endif

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
process_notify-defsyms = copy_process compat_do_execve do_execve

obj-$(CONFIG_HONE_NOTIFY) += hone_notify.o

obj-$(CONFIG_HONEEVENT) += honeevent.o
honeevent-defsyms = uts_sem socket_file_ops get_files_struct put_files_struct

include $(src)/defsyms.mk

else

SVNVER := $(shell svnversion 2>/dev/null | grep -o '^[0-9]\+[A-Z]\?')
GITVER := $(shell git log -1 --pretty=format:"%h" 2>/dev/null)
MODVER := $(shell [ -f VERSION ] && cat VERSION || date '+%y.%m')
VERSION := $(MODVER)$(if $(SVNVER),+$(SVNVER),$(if $(GITVER),+$(GITVER)))
version-name := hone-$(VERSION)
tarball-name := $(version-name).tar.gz

KVER ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KVER)/build

hone-source = Makefile defsyms.mk $(filter-out %.mod.c,$(wildcard *.[ch]))
pkg-source = dkms.conf.in dkms.conf LICENSE README VERSION debian/* hone.spec.in hone.spec
clean-files = dkms.conf hone.spec ioctl-list.c version.h
pkg-version = $(shell dpkg-parsechangelog | sed -r '/^Version:/!d;s/^[^:]+:\s+//' || sed -r '2,$d;s/^.*\((.*)\).*$/\1/' debian/changelog)

all: prereq_check modules

tags: $(filter %.c,$(hone-source)) $(filter %.h,$(hone-source))
	ctags $^

TAGS: $(filter %.c,$(hone-source)) $(filter %.h,$(hone-source))
	etags $^

VER_NUMBER := $(firstword $(subst -, ,$(MODVER)))
VER_EXTRA := $(subst $(VER_NUMBER),,$(MODVER))
VER_SPLIT := $(subst ., ,$(VER_NUMBER))
VER_MAJOR := $(word 1,$(VER_SPLIT))
VER_MINOR := $(word 2,$(VER_SPLIT))
VER_MICRO := $(word 3,$(VER_SPLIT))
VER_BUILD := $(word 4,$(VER_SPLIT))

bump:
	@eval `date '+YEAR=%y MONTH=%m DAY=%d'`; \
	VERSION="$$YEAR.$$MONTH"; \
	if [ "$$VERSION" == "$(VER_MAJOR).$(VER_MINOR)" ]; then \
	  VERSION="$$VERSION.$$DAY"; \
	  if [ "$$DAY" == "$(VER_MICRO)" ]; then \
	    VERSION="$$VERSION.$$(( $(VER_BUILD) + 1 ))"; \
	  fi; \
	fi; \
	echo $${VERSION}$(VER_EXTRA) > VERSION

version.h: VERSION
	@echo -e '#ifndef __VERSION_H__\n#define __VERSION_H__\n#define HONE_VERSION "$(MODVER)"\n#endif' > $@

prereq_check:
	@ if [ ! -f $(KSRC)/include/linux/version.h ] && \
		  [ ! -f $(KSRC)/include/generated/uapi/linux/version.h ]; then \
		echo "Kernel source was not found. Aborting."; \
		exit 1; \
	  fi

help:
	$(MAKE) -C $(KSRC) M=$(CURDIR) help

modules: version.h
	$(MAKE) -C $(KSRC) M=$(CURDIR) modules

modules_install install:
	$(MAKE) -C $(KSRC) M=$(CURDIR) modules_install

clean:
	-rm -f *.[aos] *.ko .*.cmd *.mod.c *.defsyms .System.map.md5 \
	       defsyms.symvers Module.symvers modules.order ioctl-list
	-rm -rf .tmp_versions

distclean: clean
	-rm -f $(clean-files)

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

$(tarball-name): $(hone-source) $(pkg-source) snapshot-changelog
	tar czf $@ --transform 's@^@hone-$(VERSION)/@' --exclude .svn --exclude '.*.swp' $(hone-source) $(pkg-source)

hone.spec: hone.spec.in $(hone-source)
	sed -r 's/^(Version: ).*$$/\1$(VERSION)/' $< > $@

dkms.conf: dkms.conf.in $(hone-source)
	sed -r 's/^(PACKAGE_VERSION=).*$$/\1"$(VERSION)"/' $< > $@

ioctl-list.c: honeevent.h
	@echo '#include <sys/ioctl.h>' > $@
	@echo '#include <stdio.h>' >> $@
	@echo '#include "honeevent.h"' >> $@
	@echo 'int main(int argc, char *argv)' >> $@
	@echo '{' >> $@
	@sed -r 's/^\s*#\s*define\s+(\w+)\s+_IO.*$$/\tprintf("\1 = 0x%08x\\n", \1);/;t;d' honeevent.h >> $@
	@echo '	return 0;' >> $@
	@echo '}' >> $@

ioctl-list: ioctl-list.c
	gcc -o $@ $<

PHONY: all prereq_check help modules modules_install install clean distclean \
	snapshot-changelog packages deb rpm tarball bump

endif

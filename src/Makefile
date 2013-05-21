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

# Each of the *_NOTIFY variables below can take one of three values:
#   c - Combine the module with the dependent rather than build separate
#   m - Build as a separate module
#   n - Do not build the module at all (will likely break things)
#
# Dependencies:
#   honeevent
#   +-- hone_notify
#       +-- process_notify
#       +-- socket_notify
#       +-- packet_notify

CONFIG_SOCKET_NOTIFY ?= c
CONFIG_PACKET_NOTIFY ?= c
CONFIG_PROCESS_NOTIFY ?= c
CONFIG_HONE_NOTIFY ?= m
CONFIG_HONEEVENT ?= m

HONE_MODULES ?= $(foreach m,socket_notify packet_notify process_notify hone_notify honeevent,$(if $(filter m,$(value CONFIG_$(shell echo '$(m)' | tr '[[:lower:]]' '[[:upper:]]'))),$(m)))

ifneq ($(KERNELRELEASE),)
# This is the kernel build (Kbuild) section.

# Because hone is being built out of tree, the CONFIG_* variables are not set.
# The following lines set the variables via the compiler command-line.
CONFIG = $(if $(filter-out n,$(CONFIG_$(1))),-DCONFIG_$(1)$(or \
	$(if $(filter m,$(CONFIG_$(1))),_MODULE), \
	$(if $(filter c,$(CONFIG_$(1))),_COMBINED)))
EXTRA_CFLAGS := $(call CONFIG,SOCKET_NOTIFY) \
                $(call CONFIG,PACKET_NOTIFY) \
                $(call CONFIG,PROCESS_NOTIFY) \
                $(call CONFIG,HONE_NOTIFY) \
                $(call CONFIG,HONEEVENT)

# Used to conditionally include files when doing a combined build.
COMBINE = $(if $(filter-out c,$(CONFIG_$(1))),,$(2))

obj-$(CONFIG_SOCKET_NOTIFY) += socket_notify.o
socket_notify-defsyms := inet_family_ops inet6_family_ops

obj-$(CONFIG_PACKET_NOTIFY) += packet_notify.o
packet_notify-defsyms := __udp6_lib_lookup

obj-$(CONFIG_PROCESS_NOTIFY) += process_notify.o
process_notify-defsyms := copy_process compat_do_execve do_execve do_execve_common

obj-$(CONFIG_HONE_NOTIFY) += hone_notify.o
hone_notify-y := hone_notify_imp.o \
	$(call COMBINE,PROCESS_NOTIFY,process_notify.o) \
	$(call COMBINE,SOCKET_NOTIFY,socket_notify.o) \
	$(call COMBINE,PACKET_NOTIFY,packet_notify.o)
# Leave this empty so hone_notify.defsyms is created when combined.
hone_notify-defsyms := 

obj-$(CONFIG_HONEEVENT) += honeevent.o
honeevent-y := honeevent_imp.o mmutil.o pcapng.o ringbuf.o \
	$(call COMBINE,HONE_NOTIFY,$(hone_notify-y))
honeevent-defsyms := uts_sem socket_file_ops get_files_struct put_files_struct

# Handle all the *-defsyms magic.
include $(src)/defsyms.mk

else
# This is the main Makefile.

SVNVER := $(shell svnversion 2>/dev/null | grep -o '^[0-9]\+[A-Z]\?')
GITVER := $(shell git log -1 --pretty=format:"%h" 2>/dev/null)
BASEVER := $(shell [ -f VERSION ] && cat VERSION || date '+%y.%m')
VERSION := $(BASEVER)$(if $(SVNVER),+$(SVNVER),$(if $(GITVER),+$(GITVER)))
version-name := hone-$(VERSION)
tarball-name := $(version-name).tar.gz

# Allow overriding the kernel version and path being built against.
KVER ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KVER)/build

hone-source = Makefile defsyms.mk $(filter-out %.mod.c,$(wildcard *.[ch]))
pkg-source = dkms.conf LICENSE README VERSION debian/* hone.spec.in hone.spec version.h
clean-files = dkms.conf hone.spec ioctl-list.c version.h
pkg-version = $(shell dpkg-parsechangelog | sed -r '/^Version:/!d;s/^[^:]+:\s+//' || sed -r '2,$d;s/^.*\((.*)\).*$/\1/' debian/changelog)

all: prereq_check modules

tags: $(filter %.c,$(hone-source)) $(filter %.h,$(hone-source))
	ctags $^

TAGS: $(filter %.c,$(hone-source)) $(filter %.h,$(hone-source))
	etags $^

VER_NUMBER := $(firstword $(subst -, ,$(BASEVER)))
VER_EXTRA := $(subst $(VER_NUMBER),,$(BASEVER))
VER_SPLIT := $(subst ., ,$(VER_NUMBER))
VER_MAJOR := $(word 1,$(VER_SPLIT))
VER_MINOR := $(word 2,$(VER_SPLIT))
VER_MICRO := $(word 3,$(VER_SPLIT))
VER_BUILD := $(word 4,$(VER_SPLIT))

bump-version:
	$(MAKE) -B VERSION

VERSION:
	@eval `date '+YEAR=%y MONTH=%m DAY=%d'`; \
	VERSION="$$YEAR.$$MONTH"; \
	if [ "$$VERSION" == "$(VER_MAJOR).$(VER_MINOR)" ]; then \
	  VERSION="$$VERSION.$$DAY"; \
	  if [ "$$DAY" == "$(VER_MICRO)" ]; then \
	    VERSION="$$VERSION.$$(( $(VER_BUILD) + 1 ))"; \
	  fi; \
	fi; \
	echo $${VERSION}$(VER_EXTRA) > $@

version.h: VERSION
	@echo '#ifndef __VERSION_H__' > $@
	@echo '#define __VERSION_H__' >> $@
	@echo '#define HONE_VERSION "$(BASEVER)"' >> $@
	@echo '#endif' >> $@

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

debian/dkms: dkms.conf
	@cp $< $@

debian/install: debian/install.in VERSION
	@sed -r 's/__VERSION__/$(BASEVER)/' $< > $@

debian/changelog: VERSION
	@if [ "$(call pkg-version)" != "$(BASEVER)" ]; then \
	  echo "hone ($(BASEVER)) unstable; urgency=low" > $@.new; \
	  echo "" >> $@.new; \
	  echo "  * New snapshot release." >> $@.new; \
	  echo "" >> $@.new; \
	  echo " -- $${DEBFULLNAME:-$$USER} <$${DEBEMAIL:-$$USER@$$HOSTNAME}>  `date -R`" >> debian/changelog.new; \
	  echo "" >> $@.new; \
	  cat debian/changelog >> $@.new; \
	  mv -f $@.new $@; \
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

$(tarball-name): $(hone-source) $(pkg-source)
	tar czf $@ --transform 's@^@hone-$(VERSION)/@' --exclude .svn --exclude '.*.swp' $(hone-source) $(pkg-source)

hone.spec: hone.spec.in VERSION
	@sed -r 's/^(Version: ).*$$/\1$(BASEVER)/' $< > $@

dkms.conf: VERSION
	@echo 'PACKAGE_VERSION="$(BASEVER)"' > $@
	@echo 'PACKAGE_NAME="hone"' >>  $@
	@echo 'BUILD_EXCLUSIVE_KERNEL="^2.6.3[0-9]|3.*"' >> $@
	@i=0; for m in $(HONE_MODULES); do \
		echo "BUILT_MODULE_NAME[$$i]=\"$$m\"" >> $@; \
		echo "DEST_MODULE_LOCATION[$$i]=\"/kernel/misc\"" >> $@; \
		echo "STRIP[$$i]=\"no\"" >> $@; \
		i=$$((i+1)); \
	done

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
	snapshot-changelog packages deb rpm tarball bump-version

endif

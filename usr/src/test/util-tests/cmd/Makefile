#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
#

include $(SRC)/Makefile.master
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/util-tests
ROOTBIN = $(ROOTOPTPKG)/bin

KSHFILES =	utiltest
PLFILES =	mkrandzero bincomp
PROGS =		$(KSHFILES) $(PLFILES)

CMDS = $(PROGS:%=$(ROOTBIN)/%)
$(CMDS) := FILEMODE = 0555

all lint clean:

install: $(CMDS)

clobber: clean
	$(RM) $(PROGS)

$(CMDS): $(ROOTBIN)

$(ROOTBIN):
	$(INS.dir)

$(ROOTBIN)/%: %
	$(INS.file)

$(KSHFILES): $$@.ksh
	$(CP) $@.ksh $@

$(PLFILES): $$@.pl
	$(CP) $@.pl $@

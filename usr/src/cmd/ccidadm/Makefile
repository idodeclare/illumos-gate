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
# Copyright 2019, Joyent, Inc.
# Copyright 2025 Oxide Computer Company
#

PROG= ccidadm

include ../Makefile.cmd
include ../Makefile.ctf
include $(SRC)/common/hexdump/Makefile.com

CFLAGS += $(CCVERBOSE)
CSTD = $(CSTD_GNU17)
LDLIBS += -lofmt -lcmdutils
SRCS = ccidadm.c atr.c hexdump.o ilstr.o
OBJS = $(SRCS:%.c=%.o)
CPPFLAGS += -I$(SRC)/common/ccid

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/ccid/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/ilstr/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(PROG)

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ

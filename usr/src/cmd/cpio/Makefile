#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2023 OmniOS Community Edition (OmniOSce) Association.

PROG= cpio

OBJS= cpio.o cpiostat.o utils.o
SRCS= $(OBJS:%.o=%.c)

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

CSTD = $(CSTD_GNU17)
CPPFLAGS += -DSOLARIS_PRIVS

LDLIBS += -lsec -lcmdutils -lnvpair
XGETFLAGS += -a -x cpio.xcl

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ

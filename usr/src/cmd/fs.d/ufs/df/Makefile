#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		ufs
LIBPROG=	df
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

OBJS=	df.o

CPPFLAGS +=	-D_LARGEFILE64_SOURCE
LDLIBS += -ladm

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-function

# not linted
SMATCH=off

# for messaging catalogue file
#
POFILE= df.po
XGETFLAGS += -a -x df.xcl

catalog:        $(POFILE)

SRCS= $(LIBPROG).c

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(LIBPROG).o

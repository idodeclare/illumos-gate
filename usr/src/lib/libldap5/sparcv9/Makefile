#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/libldap5/sparcv9/Makefile
#

PR_MDUSOBJS = os_SunOS.o

include ../Makefile.com
include ../../Makefile.lib.64

LDLIBS +=	-L$(ADJUNCT_PROTO)$(NSS_LDPATH64) $(NSS_LIBS)
DYNFLAGS +=	-R$(NSS_LDPATH64)

all: $(LIBS)

install: all $(ROOTLIBS64) $(ROOTLINKS64)

.DONE:
	@$(MAKE_GITIGNORE) $(CLEANFILES) $(CLOBBERTARGFILES) $(DUPLICATE_SRC) \
	    $(LINTLIB) $(LINTOUT) $(OBJS) $(PICS)

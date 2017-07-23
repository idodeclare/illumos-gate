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
#
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
#

include         $(SRC)/lib/Makefile.lib

# mDNSResponder source code files
SRC_JAVA =	$(SRC)/contrib/mDNSResponder/mDNSShared/Java
SRC_JAVA_MODFILES +=	JNISupport.c

CLOBBERFILES +=	$(SRC_JAVA_MODFILES)

.KEEP_STATE:

all install:	transform

clean:

clobber:	clean
	$(RM) $(CLOBBERFILES)

# mDNSResponder transformation targets
transform:	$(SRC_JAVA_MODFILES)

rediff:
	for f in $(SRC_JAVA_MODFILES); do \
		$(REDIFF_MOD) -p $(SRC_JAVA)/"$$f" "$$f"; \
	done

recontrib:
	$(SCM_ADD) $(SRC_JAVA_MODFILES:%=$(SRC_JAVA)/%)

$(SRC_JAVA_MODFILES):	$(SRC_JAVA)/$$@ $$@.patch
	$(PATCH) -s -o $@ < $@.patch $(SRC_JAVA)/$@

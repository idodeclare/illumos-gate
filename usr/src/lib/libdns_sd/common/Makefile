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
SRC_MDNSSHARED =	$(SRC)/contrib/mDNSResponder/mDNSShared
SRC_MDNSSHARED_COPYFILES +=	dns_sd.h dnssd_ipc.c
SRC_MDNSSHARED_MODFILES +=	dnssd_clientlib.c dnssd_clientstub.c \
    dnssd_ipc.h
SRC_MDNSSHARED_FILES +=	$(SRC_MDNSSHARED_COPYFILES) \
    $(SRC_MDNSSHARED_MODFILES)

CLOBBERFILES +=	$(SRC_MDNSSHARED_FILES)

.KEEP_STATE:

all install:	transform

clean:

clobber:	clean
	$(RM) $(CLOBBERFILES)

# mDNSResponder transformation targets
transform:	$(SRC_MDNSSHARED_FILES)

rediff:
	for f in $(SRC_MDNSSHARED_COPYFILES); do \
		$(REDIFF_COPY) $(SRC_MDNSSHARED)/"$$f" "$$f"; \
	done
	for f in $(SRC_MDNSSHARED_MODFILES); do \
		$(REDIFF_MOD) -p $(SRC_MDNSSHARED)/"$$f" "$$f"; \
	done

recontrib:
	$(SCM_ADD) $(SRC_MDNSSHARED_FILES:%=$(SRC_MDNSSHARED)/%)

$(SRC_MDNSSHARED_COPYFILES):	$(SRC_MDNSSHARED)/$$@
	$(CP) $(SRC_MDNSSHARED)/$@ $@

$(SRC_MDNSSHARED_MODFILES):	$(SRC_MDNSSHARED)/$$@ $$@.patch
	$(PATCH) -s -o $@ < $@.patch $(SRC_MDNSSHARED)/$@

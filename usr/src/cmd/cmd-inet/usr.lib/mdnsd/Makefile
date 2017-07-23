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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
#

PROG=		mdnsd
MANIFEST=	multicast.xml

# mDNSResponder source code files
SRC_MDNSCORE =	$(SRC)/contrib/mDNSResponder/mDNSCore
SRC_MDNSCORE_COPYFILES +=	anonymous.c anonymous.h CryptoAlg.c \
    CryptoAlg.h DNSCommon.h DNSDigest.c dnssec.h nsec.h uDNS.h
SRC_MDNSCORE_MODFILES +=	DNSCommon.c mDNS.c mDNSDebug.h \
    mDNSEmbeddedAPI.h uDNS.c
SRC_MDNSCORE_FILES +=	$(SRC_MDNSCORE_COPYFILES) $(SRC_MDNSCORE_MODFILES)

SRC_MDNSPOSIX =	$(SRC)/contrib/mDNSResponder/mDNSPosix
SRC_MDNSPOSIX_COPYFILES +=	mDNSPosix.h mDNSUNP.h
SRC_MDNSPOSIX_MODFILES +=	mDNSPosix.c mDNSUNP.c PosixDaemon.c
SRC_MDNSPOSIX_FILES +=	$(SRC_MDNSPOSIX_COPYFILES) \
    $(SRC_MDNSPOSIX_MODFILES)

SRC_MDNSSHARED =	$(SRC)/contrib/mDNSResponder/mDNSShared
SRC_MDNSSHARED_COPYFILES +=	GenLinkedList.c GenLinkedList.h \
    mDNSDebug.c PlatformCommon.h uds_daemon.h
SRC_MDNSSHARED_MODFILES +=	PlatformCommon.c uds_daemon.c
SRC_MDNSSHARED_FILES +=	$(SRC_MDNSSHARED_COPYFILES) \
    $(SRC_MDNSSHARED_MODFILES)

SRC_MDNS_FILES +=	$(SRC_MDNSCORE_FILES)  $(SRC_MDNSPOSIX_FILES) \
    $(SRC_MDNSSHARED_FILES)

CLOBBERFILES +=	$(SRC_MDNS_FILES)

CMN_DIR=	$(SRC)/lib/libdns_sd/common
CMN_OBJS=	dnssd_ipc.o
CMN_SRCS=	$(CMN_OBJS:%.o=$(CMN_DIR)/%.c)

LOCAL_OBJS=	DNSCommon.o DNSDigest.o GenLinkedList.o \
		PlatformCommon.o PosixDaemon.o \
		mDNS.o mDNSDebug.o mDNSPosix.o mDNSUNP.o \
		uDNS.o uds_daemon.o CryptoAlg.o anonymous.o
LOCAL_SRCS=     $(LOCAL_OBJS:%.o=%.c)

SRCS=		$(LOCAL_SRCS) $(CMN_SRCS)
OBJS=	 	$(LOCAL_OBJS) $(CMN_OBJS)	


MDNSFLAGS=	-DNOT_HAVE_SA_LEN \
		-DLOG_PERROR=0 -DHAVE_SOLARIS -DTARGET_OS_SOLARIS \
		-D_XPG4_2 -D__EXTENSIONS__ -DHAVE_BROKEN_RECVIF_NAME \
		-DHAVE_IPV6=1 -Dasm=__asm -DMDNSD_NOROOT \
		-DPID_FILE=\"\" -DMDNSD_USER=\"noaccess\" \
		-DMDNS_VERSIONSTR_NODTS

include	../../../Makefile.cmd

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-uninitialized

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKDNS)
$(ROOTMANIFEST)		:= FILEMODE= 444

.PARALLEL:      $(LOCAL_OBJS)
.WAIT:          $(PROG)
.KEEP_STATE:

all:	$(PROG)

$(PROG):	transform .WAIT $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

include ../Makefile.lib

CSTD = $(CSTD_GNU99)
CPPFLAGS += -D_REENTRANT $(MDNSFLAGS) -I$(CMN_DIR)
LDLIBS += -lsocket -lnsl

install:	all $(ROOTLIBINETPROG) $(ROOTMANIFEST)

%.o:		$(CMN_DIR)/%.c
		$(COMPILE.c) $(OUTPUT_OPTION) $<
		$(POST_PROCESS_O)

check:		$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint:		lint_SRCS

include ../../../Makefile.targ

# mDNSResponder transformation targets
transform:	$(SRC_MDNS_FILES)

rediff:
	for f in $(SRC_MDNSCORE_COPYFILES); do \
		$(REDIFF_COPY) $(SRC_MDNSCORE)/"$$f" "$$f"; \
	done
	for f in $(SRC_MDNSCORE_MODFILES); do \
		$(REDIFF_MOD) -p $(SRC_MDNSCORE)/"$$f" "$$f"; \
	done
	for f in $(SRC_MDNSPOSIX_COPYFILES); do \
		$(REDIFF_COPY) $(SRC_MDNSPOSIX)/"$$f" "$$f"; \
	done
	for f in $(SRC_MDNSPOSIX_MODFILES); do \
		$(REDIFF_MOD) -p $(SRC_MDNSPOSIX)/"$$f" "$$f"; \
	done
	for f in $(SRC_MDNSSHARED_COPYFILES); do \
		$(REDIFF_COPY) $(SRC_MDNSSHARED)/"$$f" "$$f"; \
	done
	for f in $(SRC_MDNSSHARED_MODFILES); do \
		$(REDIFF_MOD) -p $(SRC_MDNSSHARED)/"$$f" "$$f"; \
	done

recontrib:
	$(SCM_ADD) $(SRC_MDNSCORE_FILES:%=$(SRC_MDNSCORE)/%) \
	    $(SRC_MDNSPOSIX_FILES:%=$(SRC_MDNSPOSIX)/%) \
	    $(SRC_MDNSSHARED_FILES:%=$(SRC_MDNSSHARED)/%)

$(SRC_MDNSCORE_COPYFILES):	$(SRC_MDNSCORE)/$$@
	$(CP) $(SRC_MDNSCORE)/$@ $@

$(SRC_MDNSCORE_MODFILES):	$(SRC_MDNSCORE)/$$@ $$@.patch
	$(PATCH) -s -o $@ < $@.patch $(SRC_MDNSCORE)/$@

$(SRC_MDNSPOSIX_COPYFILES):	$(SRC_MDNSPOSIX)/$$@
	$(CP) $(SRC_MDNSPOSIX)/$@ $@

$(SRC_MDNSPOSIX_MODFILES):	$(SRC_MDNSPOSIX)/$$@ $$@.patch
	$(PATCH) -s -o $@ < $@.patch $(SRC_MDNSPOSIX)/$@

$(SRC_MDNSSHARED_COPYFILES):	$(SRC_MDNSSHARED)/$$@
	$(CP) $(SRC_MDNSSHARED)/$@ $@

$(SRC_MDNSSHARED_MODFILES):	$(SRC_MDNSSHARED)/$$@ $$@.patch
	$(PATCH) -s -o $@ < $@.patch $(SRC_MDNSSHARED)/$@

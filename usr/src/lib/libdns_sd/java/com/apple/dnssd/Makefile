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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
#

include ../Makefile.com

DNSSD_PKG = com.apple.dnssd

TOP = $(SRC)/lib/libdns_sd/java
JAVASRCDIR = $(TOP)/com/apple/dnssd
CLASSPATH = $(TOP):com/apple/dnssd

# mDNSResponder source code files
SRC_JAVA =	$(SRC)/contrib/mDNSResponder/mDNSShared/Java
SRC_JAVA_COPYFILES +=	BaseListener.java BrowseListener.java \
    DNSRecord.java DNSSD.java DNSSDException.java DNSSDRegistration.java \
    DNSSDService.java DomainListener.java QueryListener.java \
    RegisterListener.java RegisterRecordListener.java \
    ResolveListener.java TXTRecord.java
SRC_JAVA_MODFILES +=	DNSSDRecordRegistrar.java
SRC_JAVA_FILES +=	$(SRC_JAVA_COPYFILES) $(SRC_JAVA_MODFILES)

CLOBBERFILES +=	$(SRC_JAVA_FILES)

JAVAFLAGS +=	-source 1.4 -target 1.4
CLASSES =	$(SRC_JAVA_FILES:java=class)
JNIH    = DNSSD.java.h
JAR_FILE = dnssd.jar

DOCDIR = $(JAVASRCDIR)/docs
DOCAPIDIR = $(JAVASRCDIR)/docs/api
DOCDESTDIR = $(ROOTDNSSDJAVAHOME)/javadoc/dnssd
DOCAPIDESTDIR = $(DOCDESTDIR)/api
DOCEXAMPLESDESTDIR = $(DOCDESTDIR)/examples
$(BLD_JAVA_8)XDOCLINT_OPTION = -Xdoclint:none

EXAMPLESDIR = $(JAVASRCDIR)/docs/examples
EXAMPLESSRC = $(JAVASRCDIR)/docs/examples/src
SIMPLECHATOBJ = $(EXAMPLESDIR)/SwingBrowseListener.class \
                $(EXAMPLESDIR)/SwingQueryListener.class \
                $(EXAMPLESDIR)/SimpleChat.class 
BROWSERAPPOBJ = $(EXAMPLESDIR)/SwingResolveListener.class \
		$(EXAMPLESDIR)/SwingDomainListener.class \
                $(EXAMPLESDIR)/BrowserApp.class 
EXAMPLEOBJS   = $(SIMPLECHATOBJ) $(BROWSERAPPOBJ)
EXAMPLEJARS   = SimpleChat.jar BrowserApp.jar

INSTALL_JAR = $(ROOTDNSSDJAVAHOME)/$(JAR_FILE)
INSTALL_EXAMPLEJARS = $(DOCEXAMPLESDESTDIR)/SimpleChat.jar \
		      $(DOCEXAMPLESDESTDIR)/BrowserApp.jar
		     
CLEAN_FILES = *.class $(JNIH) *.jar $(EXAMPLESDIR)/*.class $(EXAMPLESDIR)/*.jar

DEFINES=

INCLUDES=	-I${JAVA_HOME}/include	\
		-I${JAVA_HOME}/include/solaris

SUBDIRS =	docs/examples/src

all:=		TARGET = all
clean:=		TARGET = clean
clobber:=	TARGET = clobber
install:=	TARGET = install

.KEEP_STATE:

all:	$(SUBDIRS) .WAIT $(JNIH) $(CLASSES) $(EXAMPLEOBJS) doc

install:	$(SUBDIRS) .WAIT $(CLASSES) $(ROOTDNSSDJAVAHOME) \
		$(DOCEXAMPLESDESTDIR) $(DOCEXAMPLESSRCDESTDIR) \
		$(JAR_FILE) $(INSTALL_JAR) $(JNIH) \
		$(EXAMPLEJARS) $(INSTALL_EXAMPLEJARS) \
		install_doc

# Each class is dependent on the simultaneous existence of all .java files
# or else $(JAVAC) throws "error: cannot find symbol"
$(CLASSES):	transform

$(JNIH): $(CLASSES) 
	class="com.apple.dnssd.AppleDNSSD \
		com.apple.dnssd.AppleBrowser \
		com.apple.dnssd.AppleResolver \
		com.apple.dnssd.AppleRegistration \
		com.apple.dnssd.AppleQuery \
		com.apple.dnssd.AppleDomainEnum \
		com.apple.dnssd.AppleService"; \
	$(JAVAH) -classpath $(CLASSPATH) -jni -o $(JNIH) $$class

clean:
	$(RM) $(CLEAN_FILES)

clobber: clean
	$(RM) $(CLOBBERFILES)

$(JAR_FILE): $(CLASSES)
	cd $(TOP); \
	$(JAR) -cvf $(TOP)/com/apple/dnssd/$(JAR_FILE) com/apple/dnssd/*.class

$(EXAMPLESDIR)/%.class: $(EXAMPLESSRC)/%.java
	$(JAVAC) $(JAVAFLAGS) $< -classpath $(CLASSPATH):$(EXAMPLESDIR) -d $(EXAMPLESDIR)

SIMPLECHATMAN = $(EXAMPLESSRC)/SimpleChat.manifest

SimpleChat.jar: $(SIMPLECHATOBJ) $(SIMPLECHATMAN)
		cd $(EXAMPLESDIR); $(JAR) -cvfm $@ $(SIMPLECHATMAN) \
		SwingBrowseListener.class SwingQueryListener.class \
		SimpleChat.class SimpleChat\$$1.class \
		ListenerThread.class TargetListElem.class \
		TargetListModel.class src/SimpleChat.java \
		src/SimpleChat.manifest src/SwingBrowseListener.java \
		src/SwingQueryListener.java

BROWSERAPPMAN = $(EXAMPLESSRC)/BrowserApp.manifest

BrowserApp.jar: $(BROWSERAPPOBJ) $(BROWSERAPPMAN)
		cd $(EXAMPLESDIR); $(JAR) -cvfm $@ $(BROWSERAPPMAN) \
		BrowserApp\$$1.class BrowserApp.class \
		BrowserListModel\$$BrowserListElem.class \
		BrowserListModel.class DomainListModel.class \
		ServicesBrowserListModel.class \
		SwingResolveListener.class SwingDomainListener.class \
		src/BrowserApp.java src/SwingResolveListener.java \
		src/SwingDomainListener.java src/BrowserApp.manifest
	
$(ROOTDNSSDJAVAHOME):
	$(INS.dir)

$(ROOTDNSSDJAVAHOME)/%: %
	$(INS.file)

$(DOCDESTDIR):
	$(INS.dir)

$(DOCAPIDESTDIR): $(DOCDESTDIR)
	$(INS.dir)

$(DOCEXAMPLESDESTDIR): $(DOCDESTDIR)
	$(INS.dir)

$(DOCEXAMPLESDESTDIR)/%: %
	$(RM) $@; $(INS) -s -m $(FILEMODE) -f $(@D) $(EXAMPLESDIR)/$<

install_doc: $(CLASSES) $(DOCAPIDESTDIR)
	-$(RM) -r $(DOCAPIDESTDIR)/*
	cd $(TOP); umask 022; \
	$(JAVADOC) $(JAVASRCDIR)/*.java $(XDOCLINT_OPTION) -notimestamp -classpath \
	$(CLASSPATH) -d $(DOCAPIDESTDIR) -public $(DNSSD_PKG)

doc:
	-@mkdir -p $(DOCAPIDIR)
	cd $(TOP); umask 022; \
	$(JAVADOC) $(JAVASRCDIR)/*.java $(XDOCLINT_OPTION) -notimestamp -classpath \
     	$(CLASSPATH) -d $(DOCAPIDIR) -public $(DNSSD_PKG)

$(SUBDIRS):	FRC
	cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# mDNSResponder transformation targets
transform:	$(SRC_JAVA_FILES)

rediff:
	for f in $(SRC_JAVA_COPYFILES); do \
		$(REDIFF_COPY) $(SRC_JAVA)/"$$f" "$$f"; \
	done
	for f in $(SRC_JAVA_MODFILES); do \
		$(REDIFF_MOD) -p $(SRC_JAVA)/"$$f" "$$f"; \
	done

recontrib:
	$(SCM_ADD) $(SRC_JAVA_FILES:%=$(SRC_JAVA)/%)

$(SRC_JAVA_COPYFILES):	$(SRC_JAVA)/$$@
	$(CP) $(SRC_JAVA)/$@ $@

$(SRC_JAVA_MODFILES):	$(SRC_JAVA)/$$@ $$@.patch
	$(PATCH) -s -o $@ < $@.patch $(SRC_JAVA)/$@

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla Communicator client code, released
 * March 31, 1998.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-1999
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK *****
 *
 * ldap.h - general header file for libldap
 */

#ifndef	_LDAP_H
#define	_LDAP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_SOLARIS_SDK
#define	_SOLARIS_SDK
#endif

#ifndef	LDAP_TYPE_TIMEVAL_DEFINED
#include <sys/time.h>
#endif
#ifndef	LDAP_TYPE_SOCKET_DEFINED	/* API extension */
#include <sys/types.h>
#include <sys/socket.h>
#endif

/* Standard LDAP API functions and declarations */
#include <ldap/ldap-standard.h>

/* Extensions to the LDAP standard */
#include <ldap/ldap-extension.h>

/* A deprecated API is an API that we recommend you no longer use,
 * due to improvements in the LDAP C SDK. While deprecated APIs are
 * currently still implemented, they may be removed in future
 * implementations, and we recommend using other APIs.
 */

/* Soon-to-be deprecated functions and declarations */
#include <ldap/ldap-to-be-deprecated.h>

/* Deprecated functions and declarations */
#include <ldap/ldap-deprecated.h>

#ifdef	_SOLARIS_SDK
#define	LDAP_SASL_CRAM_MD5	"CRAM-MD5"
#define	LDAP_SASL_DIGEST_MD5 	"DIGEST-MD5"
#define	LDAP_SASL_BIND_INPROGRESS	0x0e    /* for backward compatibility */

/*
 * Simple Page control OID
 */
#define	LDAP_CONTROL_SIMPLE_PAGE	"1.2.840.113556.1.4.319"


#include <ldap/disptmpl.h>


/* Simple Page Control functions for Solaris SDK */
int ldap_create_page_control(LDAP *ld, unsigned int pagesize,
	struct berval *cookie, char isCritical, LDAPControl **output);
int ldap_parse_page_control(LDAP *ld, LDAPControl **controls,
	unsigned int *totalcount, struct berval **cookie);

/* CRAM-MD5 functions */
int ldap_sasl_cram_md5_bind_s(LDAP *ld, char *dn,
	struct berval *cred, LDAPControl **serverctrls,
	LDAPControl **clientctrls);
/* DIGEST-MD5 Function */
int ldap_x_sasl_digest_md5_bind_s(LDAP *ld, char *dn,
	struct berval *cred, LDAPControl **serverctrls,
	LDAPControl **clientctrls);
int ldap_x_sasl_digest_md5_bind(LDAP *ld, char *dn,
	struct berval *cred, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeout,
	LDAPMessage **result);

char ** ldap_get_reference_urls(LDAP *ld, LDAPMessage *res);


/*
 * URL functions:
 */
int LDAP_CALL ldap_url_parse_nodn(const char *url, LDAPURLDesc **ludpp);

/*
 * Additional URL functions plus Character set, Search Preference
 * and Display Template functions moved from internal header files
 */

/*
 * URL functions
 */
char *ldap_dns_to_url(LDAP *ld, char *dns_name, char *attrs,
	char *scope, char *filter);
char *ldap_dn_to_url(LDAP *ld, char *dn, int nameparts);

/*
 * Character set functions
 */
#ifdef	STR_TRANSLATION
void ldap_set_string_translators(LDAP *ld,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc);
int ldap_translate_from_t61(LDAP *ld, char **bufp,
	unsigned long *lenp, int free_input);
int ldap_translate_to_t61(LDAP *ld, char **bufp,
	unsigned long *lenp, int free_input);
void ldap_enable_translation(LDAP *ld, LDAPMessage *entry,
	int enable);
#ifdef	LDAP_CHARSET_8859
int ldap_t61_to_8859(char **bufp, unsigned long *buflenp,
	int free_input);
int ldap_8859_to_t61(char **bufp, unsigned long *buflenp,
	int free_input);
#endif	/* LDAP_CHARSET_8859 */
#endif	/* STR_TRANSLATION */


#include <ldap/srchpref.h>

#include <ldap/ldaprot.h>


char *ldap_dns_to_dn(char *dns_name, int *nameparts);


#include <ldap/ldap_ssl.h>

#endif	/* _SOLARIS_SDK */


#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_H */

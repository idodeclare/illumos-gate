/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
 *   Sun Microsystems
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
 */

/*
 * ldapsinit.c
 */

#if defined(NET_SSL)

#if defined( _WINDOWS )
#include <windows.h>
#endif

/* XXX:mhein The following is a workaround for the redefinition of */
/*           const problem on OSF.  Fix to be provided by NSS */
/*           This is a pretty benign workaround for us which */
/*           should not cause problems in the future even if */
/*           we forget to take it out :-) */

#ifdef OSF1V4D
#ifndef __STDC__
#  define __STDC__
#endif /* __STDC__ */
#endif /* OSF1V4D */

#include <errno.h>
#include <nspr.h>
#include <cert.h>
#include <key.h>
#include <ssl.h>
#include <sslproto.h>
#include <sslerr.h>
#include <prnetdb.h>

#include <ldap.h>
#ifdef _SOLARIS_SDK
#include <ldap/ldap_ssl.h>
#else
#include <ldap_ssl.h>
#endif /* _SOLARIS_SDK */
#include <ldappr.h>
#include <pk11func.h>

#ifdef _SOLARIS_SDK
#include "solaris-int.h"
#include <libintl.h>
#include <syslog.h>
#include <nsswitch.h>
#include <synch.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>

#define	HOST_BUF_SIZE	2048

#ifndef INADDR_NONE
#define	INADDR_NONE (-1)
#endif

extern int
str2hostent(const char *instr, int lenstr, void *ent, char *buffer,
		int buflen);

extern int
str2hostent6(const char *instr, int lenstr, void *ent, char *buffer,
		int buflen);

extern LDAPHostEnt *
_ns_gethostbyaddr(LDAP *ld, const char *addr, int length, int type,
	LDAPHostEnt *result, char *buffer, int buflen, int *statusp,
	void *extradata);

static char *host_service = NULL;

static DEFINE_NSS_DB_ROOT(db_root_hosts);
static DEFINE_NSS_DB_ROOT(db_root_ipnodes);
#endif /* _SOLARIS_SDK */

/*
 * Macro that determines how many SSL options we support. As of June, 2002
 * NSS supports 14 options numbered 1-14 (see nss/ssl.h).  We allow some
 * room for expansion.
 */
#define	LDAPSSL_MAX_SSL_OPTION		20

/*
 * Data structure to hold the standard NSPR I/O function pointers set by
 * libprldap.   We save them in our session data structure so we can call
 * them from our own I/O functions (we add functionality to support SSL
 * while using libprldap's functions as much as possible).
 */
typedef struct ldapssl_std_functions {
    LDAP_X_EXTIOF_CLOSE_CALLBACK		*lssf_close_fn;
    LDAP_X_EXTIOF_CONNECT_CALLBACK		*lssf_connect_fn;
    LDAP_X_EXTIOF_DISPOSEHANDLE_CALLBACK	*lssf_disposehdl_fn;
} LDAPSSLStdFunctions;



/*
 * LDAP session data structure.
 */
typedef struct ldapssl_session_info {
    int			lssei_using_pcks_fns;
    int			lssei_ssl_strength;
    PRBool		lssei_ssl_ready;
    PRBool		lssei_tls_init; 	/* indicates startTLS success */
    PRBool 		lssei_client_auth;
    PRBool		lssei_ssl_option_value[LDAPSSL_MAX_SSL_OPTION+1];
    PRBool		lssei_ssl_option_isset[LDAPSSL_MAX_SSL_OPTION+1];
    char		*lssei_certnickname;
    char        	*lssei_keypasswd;	/* if NULL, assume pre-auth. */
    LDAPSSLStdFunctions	lssei_std_functions;
    CERTCertDBHandle	*lssei_certdbh;
#ifdef _SOLARIS_SDK
	/*
	 * This is a hack.
	 * ld is used so that we can use libldap's gethostbyaddr
	 * resolver. This is needed to prevent recursion with libsldap.
	 */
    LDAP		*ld;
#endif	/* _SOLARIS_SDK */
} LDAPSSLSessionInfo;


/*
 * LDAP socket data structure.
 */
typedef struct ldapssl_socket_info {
    LDAPSSLSessionInfo	*soi_sessioninfo;	/* session info */
} LDAPSSLSocketInfo;


/*
 * XXXceb  This is a hack until the new IO functions are done.
 * this function MUST be called before ldapssl_enable_clientauth.
 * right now, this function is called in ldapssl_pkcs_init();
 */

static int using_pkcs_functions = 0;


void set_using_pkcs_functions( int val )
{
    using_pkcs_functions = val;
}


/*
 * Utility functions:
 */
static int set_ssl_options( PRFileDesc *sslfd, PRBool *optval,
	PRBool *optisset );
static void ldapssl_free_session_info( LDAPSSLSessionInfo **ssipp );
static void ldapssl_free_socket_info( LDAPSSLSocketInfo **soipp );
static char *ldapssl_libldap_compat_strdup(const char *s1);


/*
 *  SSL Stuff
 */

static int ldapssl_AuthCertificate(void *sessionarg, PRFileDesc *fd,
	PRBool checkSig, PRBool isServer);

/*
 * client auth stuff
 */
static SECStatus get_clientauth_data( void *sessionarg, PRFileDesc *prfd,
	CERTDistNames *caNames,  CERTCertificate **pRetCert,
	SECKEYPrivateKey **pRetKey );
static SECStatus get_keyandcert( LDAPSSLSessionInfo *ssip,
	CERTCertificate **pRetCert, SECKEYPrivateKey **pRetKey,
	char **errmsgp );
static SECStatus check_clientauth_nicknames_and_passwd( LDAP *ld,
	LDAPSSLSessionInfo *ssip );
static char *get_keypassword( PK11SlotInfo *slot, PRBool retry,
	void *sessionarg );

/*
 * Static variables.
 */
/* SSL strength setting for new LDAPS sessions */
#ifdef _SOLARIS_SDK
static int default_ssl_strength = LDAPSSL_AUTH_CNCHECK;
#else
static int default_ssl_strength = LDAPSSL_AUTH_CERT;
#endif

/*
 * Arrays to track global defaults for SSL options. These are used for
 * new LDAPS sessions. For each option, we track both the option value
 * and a Boolean that indicates whether the value has been set using
 * the ldapssl_set_option() call. If an option has not been set, we
 * don't make any NSS calls to set it; that way, the default NSS option
 * values are used. Similar arrays are included in the LDAPSSLSessionInfo
 * structure so options can be set on a per-LDAP session basis as well.
 */
static PRBool default_ssl_option_value[LDAPSSL_MAX_SSL_OPTION+1] = {0};
static PRBool default_ssl_option_isset[LDAPSSL_MAX_SSL_OPTION+1] = {0};


/*
 * Like ldap_init(), except also install I/O routines from libsec so we
 * can support SSL.  If defsecure is non-zero, SSL is enabled for the
 * default connection as well.
 */
LDAP *
LDAP_CALL
ldapssl_init( const char *defhost, int defport, int defsecure )
{
    LDAP	*ld;


#ifndef LDAP_SSLIO_HOOKS
    return( NULL );
#else
    if (0 ==defport)
	defport = LDAPS_PORT;

    if (( ld = ldap_init( defhost, defport )) == NULL ) {
	return( NULL );
    }

    if ( ldapssl_install_routines( ld ) < 0 || ldap_set_option( ld,
		LDAP_OPT_SSL, defsecure ? LDAP_OPT_ON : LDAP_OPT_OFF ) != 0 ) {
	PR_SetError( PR_GetError(), EINVAL );  /* XXXmcs: just a guess! */
	ldap_unbind( ld );
	return( NULL );
    }

    return( ld );
#endif /* !LDAP_SSLIO_HOOKS */
}


static int
ldapssl_close(int s, struct lextiof_socket_private *socketarg)
{
    PRLDAPSocketInfo	soi;
    LDAPSSLSocketInfo	*ssoip;
    LDAPSSLSessionInfo	*sseip;

    memset( &soi, 0, sizeof(soi));
    soi.soinfo_size = PRLDAP_SOCKETINFO_SIZE;
    if ( prldap_get_socket_info( s, socketarg, &soi ) != LDAP_SUCCESS ) {
	return( -1 );
    }

    ssoip = (LDAPSSLSocketInfo *)soi.soinfo_appdata;
    sseip = ssoip->soi_sessioninfo;

    ldapssl_free_socket_info( (LDAPSSLSocketInfo **)&soi.soinfo_appdata );

    return( (*(sseip->lssei_std_functions.lssf_close_fn))( s, socketarg ));
}


static int
ldapssl_connect(const char *hostlist, int defport, int timeout,
	unsigned long options, struct lextiof_session_private *sessionarg,
	struct lextiof_socket_private **socketargp )
{
    int			intfd = -1;
    PRBool		secure;
    PRLDAPSessionInfo	sei;
    PRLDAPSocketInfo	soi;
    LDAPSSLSocketInfo	*ssoip = NULL;
    LDAPSSLSessionInfo	*sseip;
    PRFileDesc		*sslfd = NULL;
#ifdef _SOLARIS_SDK
    int			port;
    int			parse_err;
    char		*host = NULL;
    char		*name;
    struct ldap_x_hostlist_status
			*status = NULL;
    in_addr_t		addr_ipv4;
    in6_addr_t		addr_ipv6;
    char		*host_buf;
    LDAPHostEnt		*hent;
    LDAPHostEnt		host_ent;
    int			stat;
    int			type;
#endif	/* _SOLARIS_SDK */

    /*
     * Determine if secure option is set.  Also, clear secure bit in options
     * the we pass to the standard connect() function (since it doesn't know
     * how to handle the secure option).
     */
    if ( 0 != ( options & LDAP_X_EXTIOF_OPT_SECURE )) {
	secure = PR_TRUE;
	options &= ~LDAP_X_EXTIOF_OPT_SECURE;
    } else {
	secure = PR_FALSE;
    }

    /*
     * Retrieve session info. so we can store a pointer to our session info.
     * in our socket info. later.
     */
    memset( &sei, 0, sizeof(sei));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if ( prldap_get_session_info( NULL, sessionarg, &sei ) != LDAP_SUCCESS ) {
	return( -1 );
    }
    sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;

    /*
     * Call the standard connect() callback to make the TCP connection.  If it
     * succeeds, *socketargp is set.
     */
    intfd = (*(sseip->lssei_std_functions.lssf_connect_fn))( hostlist, defport,
#ifdef _SOLARIS_SDK
		timeout, options, sessionarg, socketargp, &host);
#else
		timeout, options, sessionarg, socketargp );
#endif	/* _SOLARIS_SDK */
    if ( intfd < 0 ) {
	return( intfd );
    }

#ifdef _SOLARIS_SDK
        /*
         * Determine if the "host name" is an ip address. If so,
         * we must look up the actual host name corresponding to
         * it.
         */
	if ( NULL == host ) {
		goto close_socket_and_exit_with_error;
	}
        type = AF_UNSPEC;
        if (strlen(host) < INET6_ADDRSTRLEN &&
                        inet_pton(AF_INET6, host, &addr_ipv6) == 1) {
                type = AF_INET6;
        } else if (strlen(host) < INET_ADDRSTRLEN &&
                        inet_pton(AF_INET, host, &addr_ipv4) == 1) {
                type = AF_INET;
        }
        if (type == AF_INET || type == AF_INET6) {
                host_buf = malloc(HOST_BUF_SIZE);
                if (host_buf == NULL) {
			/* will free host in close_socket_and_exit_with_error */
                        goto close_socket_and_exit_with_error;
		}

                /* Call ldap layer's gethostbyaddr resolver */
                hent = _ns_gethostbyaddr(sseip->ld, host, strlen(host), type,
                        &host_ent, host_buf, HOST_BUF_SIZE, &stat, NULL);

                /* If we are unable to lookup the host addr, we fail! */
                if (hent == NULL) {
                        syslog(LOG_WARNING,
                                "libldap: do_ldapssl_connect: "
                                "Unable to resolve '%s'", host);
                        free(host_buf);
			/* will free host in close_socket_and_exit_with_error */
			goto close_socket_and_exit_with_error;
                }
                /* We support only the primary host name */
                else {
			if (hent->ldaphe_name != NULL)
                        	name = strdup(hent->ldaphe_name);
                	free(host_buf);
                	if (name == NULL)
                        	goto close_socket_and_exit_with_error;
			else
                		ldap_memfree(host); host = NULL;
                	host = name;
		}
        }
#endif	/* _SOLARIS_SDK */

    /*
     * Retrieve socket info. so we have the PRFileDesc.
     */
    memset( &soi, 0, sizeof(soi));
    soi.soinfo_size = PRLDAP_SOCKETINFO_SIZE;
    if ( prldap_get_socket_info( intfd, *socketargp, &soi ) != LDAP_SUCCESS ) {
	goto close_socket_and_exit_with_error;
    }

    /*
     * Allocate a structure to hold our socket-specific data.
     */
    if ( NULL == ( ssoip = PR_Calloc( 1, sizeof( LDAPSSLSocketInfo )))) {
	goto close_socket_and_exit_with_error;
    }
    ssoip->soi_sessioninfo = sseip;

    /*
     * Add SSL layer and enable SSL.
     */
    if (( sslfd = SSL_ImportFD( NULL, soi.soinfo_prfd )) == NULL ) {
	goto close_socket_and_exit_with_error;
    }

    if ( SSL_OptionSet( sslfd, SSL_SECURITY, secure ) != SECSuccess ||
		SSL_OptionSet( sslfd, SSL_HANDSHAKE_AS_CLIENT, secure )
		!= SECSuccess || ( secure && SSL_ResetHandshake( sslfd,
		PR_FALSE ) != SECSuccess )) {
	goto close_socket_and_exit_with_error;
    }

    /*
     * Set hostname which will be retrieved (depending on ssl strength) when
     * using client or server auth.
     */
    if ( SSL_SetURL( sslfd, hostlist ) != SECSuccess ) {
	goto close_socket_and_exit_with_error;
    }

    /*
     * Set any SSL options that were modified by a previous call to
     * the ldapssl_set_option() function.
     */
    if ( set_ssl_options( sslfd, sseip->lssei_ssl_option_value,
		sseip->lssei_ssl_option_isset ) < 0 ) {
	goto close_socket_and_exit_with_error;
    }

    /*
     * If using client auth., arrange to use a separate SSL session cache
     * for each distinct local client certificate nickname.
     */
    if ( sseip->lssei_client_auth &&
         sseip->lssei_certnickname && sseip->lssei_certnickname[0] &&
	 SSL_SetSockPeerID( sslfd, sseip->lssei_certnickname) != SECSuccess ) {
	goto close_socket_and_exit_with_error;
    }

    /*
     * Let the standard NSPR to LDAP layer know about the new socket and
     * our own socket-specific data.
     */
    soi.soinfo_prfd = sslfd;
    soi.soinfo_appdata = (void *)ssoip;
    if ( prldap_set_socket_info( intfd, *socketargp, &soi ) != LDAP_SUCCESS ) {
	goto close_socket_and_exit_with_error;
    }

#ifdef _SOLARIS_SDK
    /*
     * Set hostname which will be retrieved (depending on ssl strength) when
     * using client or server auth.
     */
    if (SSL_SetURL(sslfd, host) != SECSuccess)
	goto close_socket_and_exit_with_error;
    ldap_memfree(host);
    host = NULL;
#endif /* _SOLARIS_SDK */

    sslfd = NULL;	/* so we don't close the socket twice upon error */

    /*
     * Install certificate hook function.
     */
    SSL_AuthCertificateHook( soi.soinfo_prfd,
			     (SSLAuthCertificate)ldapssl_AuthCertificate,
			     (void *)sseip );

    if ( SSL_GetClientAuthDataHook( soi.soinfo_prfd,
		get_clientauth_data, sseip->lssei_client_auth ? sseip : NULL ) != 0 ) {
	goto close_socket_and_exit_with_error;
    }

    return( intfd );	/* success */

close_socket_and_exit_with_error:
#ifdef _SOLARIS_SDK
    if ( NULL != host ) ldap_memfree(host);
#endif /* _SOLARIS_SDK */
    if ( NULL != sslfd && sslfd != soi.soinfo_prfd ) {
	PR_Close( sslfd );
    }
    if ( NULL != ssoip ) {
	ldapssl_free_socket_info( &ssoip );
    }
    if ( intfd >= 0 && NULL != *socketargp ) {
	(*(sseip->lssei_std_functions.lssf_close_fn))( intfd, *socketargp );
    }
    return( -1 );
}


static void
ldapssl_disposehandle(LDAP *ld, struct lextiof_session_private *sessionarg)
{
    PRLDAPSessionInfo				sei;
    LDAPSSLSessionInfo				*sseip;
    LDAP_X_EXTIOF_DISPOSEHANDLE_CALLBACK	*disposehdl_fn;

    memset( &sei, 0, sizeof( sei ));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if ( prldap_get_session_info( ld, NULL, &sei ) == LDAP_SUCCESS ) {
	sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;
	disposehdl_fn = sseip->lssei_std_functions.lssf_disposehdl_fn;
	ldapssl_free_session_info( &sseip );
	(*disposehdl_fn)( ld, sessionarg );
    }
}

static
LDAPSSLSessionInfo *
ldapssl_alloc_sessioninfo()
{
    LDAPSSLSessionInfo	*ssip;

    /*
     * Allocate our own session information.
     */
    if ( NULL == ( ssip = (LDAPSSLSessionInfo *)PR_Calloc( 1,
		sizeof( LDAPSSLSessionInfo )))) {
	return( NULL );
    }

    /*
     * Initialize session info.
     * XXX: it would be nice to be able to set these on a per-session basis:
     *		lssei_using_pcks_fns
     *		lssei_certdbh
     */
    ssip->lssei_ssl_strength = default_ssl_strength;
    memcpy( ssip->lssei_ssl_option_value, default_ssl_option_value,
		sizeof(ssip->lssei_ssl_option_value));
    memcpy( ssip->lssei_ssl_option_isset, default_ssl_option_isset,
		sizeof(ssip->lssei_ssl_option_isset));
    ssip->lssei_using_pcks_fns = using_pkcs_functions;
    ssip->lssei_certdbh = CERT_GetDefaultCertDB();
    ssip->lssei_ssl_ready = PR_TRUE;

    return( ssip );
}

/*
 * Install I/O routines from libsec and NSPR into libldap to allow libldap
 * to do SSL.
 *
 * We rely on libprldap to provide most of the functions, and then we override
 * a few of them to support SSL.
 */
int
LDAP_CALL
ldapssl_install_routines( LDAP *ld )
{
#ifndef LDAP_SSLIO_HOOKS
    ldap_set_lderrno( ld, LDAP_LOCAL_ERROR, NULL, NULL );
    return( -1 );
#else
    struct ldap_x_ext_io_fns	iofns;
    LDAPSSLSessionInfo		*ssip;
    PRLDAPSessionInfo		sei;

    /* install standard NSPR functions */
#ifndef _SOLARIS_SDK
    if ( prldap_install_routines(
		ld,
		1 /* shared -- we have to assume it is */ )
		!= LDAP_SUCCESS ) {
	return( -1 );
    }
#endif /*_SOLARIS_SDK*/

    /*
     * Allocate session information.
     */
     if ( (ssip = ldapssl_alloc_sessioninfo()) == NULL )
     {
     	ldap_set_lderrno( ld, LDAP_NO_MEMORY, NULL, NULL );
	return( -1 );
     }
#ifdef _SOLARIS_SDK
    /*
     * This is part of a hack to allow the ssl portion of the
     * library to call the ldap library gethostbyaddr resolver.
     */
    ssip->ld = ld;
#endif	/* _SOLARIS_SDK */

    /*
     * override a few functions, saving a pointer to the standard function
     * in each case so we can call it from our SSL savvy functions.
     */
    memset( &iofns, 0, sizeof(iofns));
    iofns.lextiof_size = LDAP_X_EXTIO_FNS_SIZE;
    if ( ldap_get_option( ld, LDAP_X_OPT_EXTIO_FN_PTRS, (void *)&iofns ) < 0 ) {
	ldapssl_free_session_info( &ssip );
	return( -1 );
    }

    /* override socket, connect, and disposehandle */
    ssip->lssei_std_functions.lssf_connect_fn = iofns.lextiof_connect;
    iofns.lextiof_connect = ldapssl_connect;
    ssip->lssei_std_functions.lssf_close_fn = iofns.lextiof_close;
    iofns.lextiof_close = ldapssl_close;
    ssip->lssei_std_functions.lssf_disposehdl_fn = iofns.lextiof_disposehandle;
    iofns.lextiof_disposehandle = ldapssl_disposehandle;

    if ( ldap_set_option( ld, LDAP_X_OPT_EXTIO_FN_PTRS, (void *)&iofns ) < 0 ) {
	ldapssl_free_session_info( &ssip );
	return( -1 );
    }

    /*
     * Store session info. for later retrieval.
     */
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    sei.seinfo_appdata = (void *)ssip;
    if ( prldap_set_session_info( ld, NULL, &sei ) != LDAP_SUCCESS ) {
	ldapssl_free_session_info( &ssip );
	return( -1 );
    }

    return( 0 );
#endif /* LDAP_SSLIO_HOOKS */
}

/* Sets up SSL for the NSPR layered connection (or plain Text connection
 * with startTLS extended I/O request already acknowledged by the server)
 * Call this function after the call to ldaptls_setup()
 *
 * Returns an LDAP API result code (LDAP_SUCCESS if all goes well).
 */
static int
ldaptls_complete(LDAP *ld)
{
    PRBool		secure = 1;
    PRLDAPSessionInfo	sei;
    PRLDAPSocketInfo	soi;
    LDAPSSLSocketInfo	*ssoip = NULL;
    LDAPSSLSessionInfo	*sseip = NULL;
    PRFileDesc		*sslfd = NULL;
    LBER_SOCKET 	intfd = -1;
    int			rc = LDAP_LOCAL_ERROR;
    char 		*hostlist = NULL;
    struct lextiof_socket_private *socketargp = NULL;

    /*
     * Get hostlist from LDAP Handle
     */
    if ( ldap_get_option(ld, LDAP_OPT_HOST_NAME, &hostlist) < 0 ) {
    	rc = ldap_get_lderrno( ld, NULL, NULL );
		goto close_socket_and_exit_with_error;
    }

    /*
     * Get File Desc from current connection
     */
    if ( ldap_get_option(ld, LDAP_OPT_DESC, &intfd) < 0 ) {
		rc = ldap_get_lderrno( ld, NULL, NULL );
		goto close_socket_and_exit_with_error;
    }


    /*
     * Get Socket Arg Pointer
     */
    if ( ldap_get_option(ld, LDAP_X_OPT_SOCKETARG, &socketargp) < 0 ) {
		rc = ldap_get_lderrno( ld, NULL, NULL );
		goto close_socket_and_exit_with_error;
    }


    /*
     * Retrieve session info. so we can store a pointer to our session info.
     * in our socket info. later.
     */
    memset( &sei, 0, sizeof(sei));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if (LDAP_SUCCESS != (rc = prldap_get_session_info(ld, NULL, &sei))) {
		goto close_socket_and_exit_with_error;
    }
    sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;

    /*
     * Retrieve socket info.
     */
    memset( &soi, 0, sizeof(soi));
    soi.soinfo_size = PRLDAP_SOCKETINFO_SIZE;
    if (LDAP_SUCCESS !=
		(rc = prldap_get_socket_info(intfd, socketargp, &soi))) {
	goto close_socket_and_exit_with_error;
    }

    /*
     * Allocate a structure to hold our socket-specific data.
     */
    if ( NULL == ( ssoip = PR_Calloc( 1, sizeof( LDAPSSLSocketInfo )))) {
	rc = LDAP_NO_MEMORY;
	goto close_socket_and_exit_with_error;
    }
    ssoip->soi_sessioninfo = sseip;

    /*
     * Add SSL layer and enable SSL.
     */
    if (( sslfd = SSL_ImportFD( NULL, soi.soinfo_prfd )) == NULL ) {
	rc = LDAP_LOCAL_ERROR;
	goto close_socket_and_exit_with_error;
    }

    if ( SSL_OptionSet( sslfd, SSL_SECURITY, secure ) != SECSuccess ||
	 SSL_OptionSet( sslfd, SSL_ENABLE_TLS, secure ) != SECSuccess ||
	 SSL_OptionSet( sslfd, SSL_HANDSHAKE_AS_CLIENT, secure ) != SECSuccess ||
	 ( secure && SSL_ResetHandshake( sslfd, PR_FALSE ) != SECSuccess ) ) {
	rc = LDAP_LOCAL_ERROR;
	goto close_socket_and_exit_with_error;
    }

    /*
     * Set hostname which will be retrieved (depending on ssl strength) when
     * using client or server auth.
     */
    if ( SSL_SetURL( sslfd, hostlist ) != SECSuccess ) {
	rc = LDAP_LOCAL_ERROR;
	goto close_socket_and_exit_with_error;
    }
    ldap_memfree(hostlist);
    hostlist = NULL;

    /*
     * Set any SSL options that were modified by a previous call to
     * the ldapssl_set_option() function.
     */
    if ( set_ssl_options( sslfd, sseip->lssei_ssl_option_value,
		sseip->lssei_ssl_option_isset ) < 0 ) {
	rc = LDAP_LOCAL_ERROR;
	goto close_socket_and_exit_with_error;
    }

    /*
     * If using client auth., arrange to use a separate SSL session cache
     * for each distinct local client certificate nickname.
     */
    if ( sseip->lssei_client_auth &&
         sseip->lssei_certnickname && sseip->lssei_certnickname[0] &&
	 SSL_SetSockPeerID( sslfd, sseip->lssei_certnickname) != SECSuccess ) {
	rc = LDAP_LOCAL_ERROR;
	goto close_socket_and_exit_with_error;
    }

    /*
     * Let the standard NSPR to LDAP layer know about the new socket and
     * our own socket-specific data.
     */
    soi.soinfo_prfd = sslfd;
    soi.soinfo_appdata = (void *)ssoip;

    if ( LDAP_SUCCESS !=
		(rc = prldap_set_socket_info( intfd, socketargp, &soi ))) {
	goto close_socket_and_exit_with_error;
    }
    sslfd = NULL;	/* so we don't close the socket twice upon error */

    /*
     * Install certificate hook function.
     */
    SSL_AuthCertificateHook( soi.soinfo_prfd,
			     (SSLAuthCertificate)ldapssl_AuthCertificate,
			     (void *)sseip );

    if ( SSL_GetClientAuthDataHook( soi.soinfo_prfd,
		 get_clientauth_data, sseip->lssei_client_auth ? sseip : NULL ) != 0 ) {
	rc = LDAP_LOCAL_ERROR;
	goto close_socket_and_exit_with_error;
    }

    return( LDAP_SUCCESS );	/* success */

  close_socket_and_exit_with_error:

      ldap_memfree(hostlist);
      hostlist = NULL;

      if ( NULL != sslfd && sslfd != soi.soinfo_prfd ) {
               PR_Close( sslfd );
      }
      if ( NULL != ssoip ) {
                ldapssl_free_socket_info( &ssoip );
      }
      if ( intfd >= 0 && NULL != socketargp && sseip != NULL ) {
                (*(sseip->lssei_std_functions.lssf_close_fn))( intfd,
                socketargp );
      }
      return( rc );

} /* ldaptls_complete() */



/*
 * Install I/O routines from libsec and NSPR into libldap to allow libldap
 * to do TLS.
 *
 * We rely on libprldap to provide most of the functions.
 * Returns an LDAP API result code (LDAP_SUCCESS if all goes well).
 */
static int
ldaptls_setup( LDAP *ld )
{

    int				rc = LDAP_LOCAL_ERROR;
    LDAPSSLSessionInfo		*ssip;
    PRLDAPSessionInfo		sei;

    /* Check for valid input parameters. */
    if ( ld == NULL ) {
	ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL, NULL );
	return( LDAP_PARAM_ERROR );
    }

    /* Check if NSPR Layer is Installed */
    if ( !prldap_is_installed(ld) ) {
       /* No NSPR Layer installed,
        * Call prldap_import_connection() that installs the NSPR I/O layer
	* and imports connection details from Clear-text connection
	*/
	if (LDAP_SUCCESS != (rc = prldap_import_connection( ld ))) {
	    return( rc );
    	}
    }

	memset( &sei, 0, sizeof(sei));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if ( (rc = prldap_get_session_info( ld, NULL, &sei )) == LDAP_SUCCESS ) {
        ssip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;
    } else {
		return( rc );
	}

	if ( NULL == ssip ) {
		if ( (ssip = ldapssl_alloc_sessioninfo()) == NULL ) {
			ldap_set_lderrno( ld, LDAP_NO_MEMORY, NULL, NULL );
			return( LDAP_NO_MEMORY );
		}

		/*
		 * Store session info. for later retrieval.
		 */
		sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
		sei.seinfo_appdata = (void *)ssip;
		if (LDAP_SUCCESS != (rc = prldap_set_session_info( ld, NULL, &sei ))) {
			ldapssl_free_session_info( &ssip );
			return( rc );
		}
	}

	ssip->lssei_tls_init= PR_TRUE;

    return( LDAP_SUCCESS );
} /* ldaptls_setup()*/

/* Function; ldap_start_tls_s()
 * startTLS request
 * Returns an LDAP API result code (LDAP_SUCCESS if all goes well).
 *
 */
int
LDAP_CALL
ldap_start_tls_s(LDAP *ld,
		 LDAPControl **serverctrls,
		 LDAPControl **clientctrls)
{
	int rc = -1;
	int	version = LDAP_VERSION3;

	/* Error check on LDAP handle */
	if ( ld == NULL ) {
		ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL, NULL );
		return( LDAP_PARAM_ERROR );
	}


	/* Make sure we are dealing with LDAPv3 */
	if ( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) < 0 ) {
		 return( ldap_get_lderrno( ld, NULL, NULL ));
	}

	/* Issue the Start TLS extended operation */
	rc = ldap_extended_operation_s( ld, LDAP_EXOP_START_TLS, NULL, serverctrls,
									clientctrls, NULL, NULL );
	if ( rc != LDAP_SUCCESS )
	{
		return( rc );
	}

	/* Initialize TLS and enable SSL on the LDAP session */
	if ( LDAP_SUCCESS == ( rc = ldaptls_setup( ld ) ) &&
	     LDAP_SUCCESS == ( rc = ldaptls_complete( ld ) )) {
		if (ldap_set_option( ld, LDAP_OPT_SSL, LDAP_OPT_ON ) < 0 ) {
			rc = ldap_get_lderrno( ld, NULL, NULL );
		}
	}

	if (LDAP_SUCCESS != rc) {
		/* Allow to proceed in clear text if secure session fails */
		ldap_set_option( ld, LDAP_OPT_SSL, LDAP_OPT_OFF );
	}

	return( rc );
}



/*ARGSUSED*/
int
LDAP_CALL
ldapssl_enable_clientauth( LDAP *ld, char *keynickname,
        char *keypasswd, char *certnickname )
{
    LDAPSSLSessionInfo		*ssip;
    PRLDAPSessionInfo		sei;
    int	new_session_allocated = 0;

   /*
    * Check parameters
    * allow keypasswd to be NULL in case PK11_SetPasswordFunc()
    * already set by the user to their own private pin callback.
    * there is no proper way to test if PK11_SetPasswordFunc()
    * callback is already set apart from NSS private interfaces
    */
    if ( certnickname == NULL ) {
		ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL,
			ldapssl_libldap_compat_strdup(
				"A non-NULL certnickname is required" ));
		return( -1 );
    }

    /*
     * Get session info. data structure.
     */
    memset( &sei, 0, sizeof(sei));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if ( prldap_get_session_info( ld, NULL, &sei ) == LDAP_SUCCESS ) {
		ssip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;
    } else {
    	return( -1 );
    }

    if ( NULL == ssip ) { /* Failed to get ssl session info pointer */
		/*
		 * Allocate our own session information.
		 */
		if ( NULL == ( ssip = ldapssl_alloc_sessioninfo())) {
			ldap_set_lderrno( ld, LDAP_NO_MEMORY, NULL, NULL );
			return( -1 );
		}
		/*
		 * Store session info. for later retrieval.
		 */
		sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
		sei.seinfo_appdata = (void *)ssip;
		if ( prldap_set_session_info( ld, NULL, &sei ) != LDAP_SUCCESS ) {
			return( -1 );
		}
		new_session_allocated = 1;
    }

    if ( !(ssip->lssei_ssl_ready) && !new_session_allocated ) {
	/* standard SSL setup has not yet done */
	ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL,
		ldapssl_libldap_compat_strdup(
		"An SSL-ready LDAP session handle is required" ));
	return( -1 );
    }

    /*
     * Update session info. data structure.
     */
    ssip->lssei_certnickname = PL_strdup( certnickname );
    if ( keypasswd ) {
	ssip->lssei_keypasswd = PL_strdup( keypasswd );
    } else {
    /* set lssei_using_pcks_fns to prevent our own PK11_SetPasswordFunc()
	 * callback being installed in get_keyandcert() if keypasswd is NULL
	 * workaround for now til NSS comes up with proper check interface
	 */
	ssip->lssei_using_pcks_fns = 1;
	ssip->lssei_keypasswd = NULL;	/* assume pre-authenticated */
    }

    if ( NULL == ssip->lssei_certnickname ||
		( keypasswd && ( NULL == ssip->lssei_keypasswd ) ) ) {
	ldap_set_lderrno( ld, LDAP_NO_MEMORY, NULL, NULL );
	return( -1 );
    }

    if ( check_clientauth_nicknames_and_passwd( ld, ssip ) != SECSuccess ) {
	/* LDAP errno is set by check_clientauth_nicknames_and_passwd() */
	return( -1 );
    }

    /* Mark the session as client auth enabled */
    ssip->lssei_client_auth = PR_TRUE;

    return( LDAP_SUCCESS );
}


/*
 * Set the SSL strength for an existing SSL-enabled LDAP session handle.
 *
 * See the description of ldapssl_serverauth_init() above for valid
 * sslstrength values. If ld is NULL, the default for new LDAP session
 * handles is set.
 *
 * Returns 0 if all goes well and -1 if an error occurs.
 */
int
LDAP_CALL
ldapssl_set_strength( LDAP *ld, int sslstrength )
{
    int			rc = 0;	/* assume success */

    if ( sslstrength != LDAPSSL_AUTH_WEAK &&
		sslstrength != LDAPSSL_AUTH_CERT &&
		sslstrength != LDAPSSL_AUTH_CNCHECK ) {
	rc = -1;
    } else {
	if ( NULL == ld ) {	/* set default strength */
	    default_ssl_strength = sslstrength;
	} else {		/* set session-specific strength */
	    PRLDAPSessionInfo	sei;
	    LDAPSSLSessionInfo	*sseip;

	    memset( &sei, 0, sizeof( sei ));
	    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
	    if ( prldap_get_session_info( ld, NULL, &sei ) == LDAP_SUCCESS ) {
		sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;
		sseip->lssei_ssl_strength = sslstrength;
	    } else {
		rc = -1;
	    }
	}
    }

    return( rc );
}


/*
 * Set SSL options for an existing SSL-enabled LDAP session handle.
 * If ld is NULL, the default options used for all future LDAP SSL sessions
 * are the ones affected. The option values are specific to the underlying
 * SSL provider; see ssl.h within the Network Security Services (NSS)
 * distribution for the options supported by NSS (the default SSL provider).
 *
 * This function should be called before any LDAP connections are created.
 *
 * Returns: 0 if all goes well.
 */
int
LDAP_CALL
ldapssl_set_option( LDAP *ld, int option, int on )
{
    int		rc = 0;	/* assume success */

    if ( option < 0 || option > LDAPSSL_MAX_SSL_OPTION ) {
	ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL, NULL );
	rc = -1;
    } else {
	if ( NULL == ld ) {
	    /* set default options for new LDAP sessions */
	    default_ssl_option_value[option] = on;
	    default_ssl_option_isset[option] = PR_TRUE;
	} else {
	    /* set session options */
	    PRLDAPSessionInfo	sei;
	    LDAPSSLSessionInfo	*sseip;

	    memset( &sei, 0, sizeof( sei ));
	    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
	    if ( prldap_get_session_info( ld, NULL, &sei ) == LDAP_SUCCESS ) {
		sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;
		sseip->lssei_ssl_option_value[option] = on;
		sseip->lssei_ssl_option_isset[option] = PR_TRUE;
	    } else {
		rc = -1;
	    }
	}
    }

    return( rc );
}


/*
 * Retrieve SSL options for an existing SSL-enabled LDAP session handle.
 * If ld is NULL, the default options to be used for all future LDAP SSL
 * sessions are retrieved. The option values are specific to the underlying
 * SSL provider; see ssl.h within the Network Security Services (NSS)
 * distribution for the options supported by NSS (the default SSL provider).
 *
 * Returns: 0 if all goes well.
 */
int
LDAP_CALL
ldapssl_get_option( LDAP *ld, int option, int *onp )
{
    int		rc = 0;	/* assume success */

    if ( option < 0 || option > LDAPSSL_MAX_SSL_OPTION || onp == NULL ) {
	ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL, NULL );
	rc = -1;
    } else {
	int		rv = 0, set_rv = 0;

	if ( NULL == ld ) {
	     /* return default options for new LDAP sessions */
	    if ( default_ssl_option_isset[option] ) {
		rv = default_ssl_option_value[option];
		set_rv = 1;
	    }
	} else {
	    /* return session options */
	    PRLDAPSessionInfo	sei;
	    LDAPSSLSessionInfo	*sseip;

	    memset( &sei, 0, sizeof( sei ));
	    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
	    if ( prldap_get_session_info( ld, NULL, &sei )
			== LDAP_SUCCESS ) {
		sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;
		if ( sseip->lssei_ssl_option_isset[option] ) {
		    rv = sseip->lssei_ssl_option_value[option];
		    set_rv = 1;
		}
	    } else {
		rc = -1;
	    }
	}

	if ( !set_rv ) {
	    PRBool	pron = PR_FALSE;
	    if ( rc == 0 && SSL_OptionGetDefault( (PRInt32)option, &pron )
			!= SECSuccess ) {
		rc = -1;
	    }
	    rv = pron;
	}

	*onp = rv;	/* always return a value */
    }

    return( rc );
}

#ifdef LDAPSSL_DEBUG
struct optitem {
	PRInt32		om_option;
	const char	*om_string;
} optmap[] = {
	{ SSL_SECURITY,			"SSL_SECURITY" },
	{ SSL_SOCKS, 			"SSL_SOCKS" },
	{ SSL_REQUEST_CERTIFICATE, 	"SSL_REQUEST_CERTIFICATE" },
	{ SSL_HANDSHAKE_AS_CLIENT, 	"SSL_HANDSHAKE_AS_CLIENT" },
	{ SSL_HANDSHAKE_AS_SERVER, 	"SSL_HANDSHAKE_AS_SERVER" },
	{ SSL_ENABLE_SSL2, 		"SSL_ENABLE_SSL2" },
	{ SSL_ENABLE_SSL3, 		"SSL_ENABLE_SSL3" },
	{ SSL_NO_CACHE, 		"SSL_NO_CACHE" },
	{ SSL_REQUIRE_CERTIFICATE, 	"SSL_REQUIRE_CERTIFICATE" },
	{ SSL_ENABLE_FDX, 		"SSL_ENABLE_FDX" },
	{ SSL_V2_COMPATIBLE_HELLO, 	"SSL_V2_COMPATIBLE_HELLO" },
	{ SSL_ENABLE_TLS, 		"SSL_ENABLE_TLS" },
	{ SSL_ROLLBACK_DETECTION, 	"SSL_ROLLBACK_DETECTION" },
	{ -1, NULL },
};

static const char *
sslopt2string( PRInt32 option )
{
    int		i;
    const	char *s = "unknown";

    for ( i = 0; optmap[i].om_option != -1; ++i ) {
	if ( optmap[i].om_option == option ) {
	    s = optmap[i].om_string;
	    break;
	}
    }

    return( s );
}
#endif /* LDAPSSL_DEBUG */

static int
set_ssl_options( PRFileDesc *sslfd, PRBool *optval, PRBool *optisset )
{
    SECStatus	secrc = SECSuccess;
    PRInt32	option;

    for ( option = 0;
		( secrc == SECSuccess ) && ( option < LDAPSSL_MAX_SSL_OPTION );
		++option ) {
	if ( optisset[ option ] ) {
#ifdef LDAPSSL_DEBUG
	    fprintf( stderr,
		    "set_ssl_options: setting option %d - %s to %d (%s)\n",
		    option, sslopt2string(option), optval[ option ],
		    optval[ option ] ? "ON" : "OFF" );
#endif /* LDAPSSL_DEBUG */

	    secrc = SSL_OptionSet( sslfd, option, optval[ option ] );
	}
    }

    if ( secrc == SECSuccess ) {
	return( 0 );
    }

    PR_SetError( PR_GetError(), EINVAL );	/* set OS error only */
    return( -1 );
}


static void
ldapssl_free_session_info( LDAPSSLSessionInfo **ssipp )
{
    if ( NULL != ssipp && NULL != *ssipp ) {
	if ( NULL != (*ssipp)->lssei_certnickname ) {
	    PL_strfree( (*ssipp)->lssei_certnickname );
	    (*ssipp)->lssei_certnickname = NULL;
	}
	if ( NULL != (*ssipp)->lssei_keypasswd ) {
	    PL_strfree( (*ssipp)->lssei_keypasswd );
	    (*ssipp)->lssei_keypasswd = NULL;
	}
	PR_Free( *ssipp );
	*ssipp = NULL;
    }
}


static void
ldapssl_free_socket_info( LDAPSSLSocketInfo **soipp )
{
    if ( NULL != soipp && NULL != *soipp ) {
	PR_Free( *soipp );
	*soipp = NULL;
    }
}


/* this function provides cert authentication.  This is called during
 * the SSL_Handshake process.  Once the cert has been retrieved from
 * the server, the it is checked, using VerifyCertNow(), then
 * the cn is checked against the host name, set with SSL_SetURL()
 */

static int
ldapssl_AuthCertificate(void *sessionarg, PRFileDesc *fd, PRBool checkSig,
	PRBool isServer)
{
    SECStatus		rv = SECFailure;
    LDAPSSLSessionInfo	*sseip;
    CERTCertificate	*cert;
    SECCertUsage	certUsage;
    char		*hostname = (char *)0;

    if (!sessionarg || !fd) {
	return rv;
    }

    sseip = (LDAPSSLSessionInfo *)sessionarg;

    if (LDAPSSL_AUTH_WEAK == sseip->lssei_ssl_strength ) { /* no check */
	return SECSuccess;
    }

    if ( isServer ) {
	certUsage = certUsageSSLClient;
    } else {
	certUsage = certUsageSSLServer;
    }
    cert = SSL_PeerCertificate( fd );

    rv = CERT_VerifyCertNow(sseip->lssei_certdbh, cert, checkSig,
			certUsage, NULL);

    if ( rv != SECSuccess || isServer ) {
	/* must destroy cert to avoid mem leak */
	CERT_DestroyCertificate(cert);
	return rv;
    }

    if ( LDAPSSL_AUTH_CNCHECK == sseip->lssei_ssl_strength ) {
	/* cert is OK.  This is the client side of an SSL connection.
	 * Now check the name field in the cert against the desired hostname.
	 * NB: This is our only defense against Man-In-The-Middle (MITM)
	 * attacks!
	 */

	hostname = SSL_RevealURL( fd );

	if (hostname && hostname[0]) {
	  rv = CERT_VerifyCertName(cert, hostname);
	} else  {
	  rv = SECFailure;
     	}
        if (hostname) {
	  PL_strfree(hostname);
        }
	if (rv != SECSuccess) {
	  PORT_SetError(SSL_ERROR_BAD_CERT_DOMAIN);
        }
    }

    /* must destroy cert to avoid mem leak */
    CERT_DestroyCertificate(cert);
    return((int)rv);
}


/*
 * called during SSL client auth. when server wants our cert and key.
 * returns: SECSuccess if we succeeded and set *pRetCert and *pRetKey,
 *			SECFailure otherwise.
 * if SECFailure is returned SSL will proceed without sending a cert.
 */
/*ARGSUSED*/
static SECStatus
get_clientauth_data( void *sessionarg, PRFileDesc *prfd,
        CERTDistNames *caNames,  CERTCertificate **pRetCert,
        SECKEYPrivateKey **pRetKey )

{
    LDAPSSLSessionInfo	*ssip;

    if (( ssip = (LDAPSSLSessionInfo *)sessionarg ) == NULL ) {
	return( SECFailure );       /* client auth. not enabled */
    }

    return( get_keyandcert( ssip, pRetCert, pRetKey, NULL ));
}

static SECStatus
get_keyandcert( LDAPSSLSessionInfo *ssip,
	CERTCertificate **pRetCert, SECKEYPrivateKey **pRetKey,
	char **errmsgp )
{
    CERTCertificate		*cert;
    SECKEYPrivateKey	*key;

    if ( !ssip->lssei_using_pcks_fns && (NULL != ssip->lssei_keypasswd) ) {
	/*
	 * XXX: This function should be called only once, and probably
	 *      in one of the ldapssl_.*_init() calls.
	 */
	PK11_SetPasswordFunc( get_keypassword );
    }

    if (( cert = CERT_FindUserCertByUsage( CERT_GetDefaultCertDB(),
    				ssip->lssei_certnickname, certUsageSSLClient,
    				PR_FALSE, (void *)ssip )) == NULL ) {
	if ( errmsgp != NULL ) {
	    *errmsgp = "unable to find certificate";
	}
	return( SECFailure );
    }

    if (( key = PK11_FindKeyByAnyCert( cert, (void *)ssip )) == NULL ) {
	CERT_DestroyCertificate( cert );
	if ( errmsgp != NULL ) {
	    *errmsgp = "bad key or key password";
	}
	return( SECFailure );
    }

    *pRetCert = cert;
    *pRetKey = key;
    return( SECSuccess );
}


/*
 * This function returns the password to NSS.
 * This function is enable through PK11_SetPasswordFunc
 * only if pkcs functions are not being used.
 */
/*ARGSUSED*/
static char *
get_keypassword( PK11SlotInfo *slot, PRBool retry, void *sessionarg )
{
    LDAPSSLSessionInfo	*ssip;

    if ( retry)
      return (NULL);

    ssip = (LDAPSSLSessionInfo *)sessionarg;
    if ( NULL == ssip || NULL == ssip->lssei_keypasswd ) {
	return( NULL );
    }

    return( PL_strdup(ssip->lssei_keypasswd) );
}


/*
 * performs some basic checks on clientauth cert and key/password
 *
 * XXXmcs: could perform additional checks... see servers/slapd/ssl.c
 *	1) check expiration
 *	2) check that public key in cert matches private key
 * see ns/netsite/ldap/servers/slapd/ssl.c:slapd_ssl_init() for example code.
 */
static SECStatus
check_clientauth_nicknames_and_passwd( LDAP *ld, LDAPSSLSessionInfo *ssip )
{
    char		*errmsg = NULL;
    CERTCertificate	*cert = NULL;
    SECKEYPrivateKey	*key = NULL;
    SECStatus		rv;

    rv = get_keyandcert( ssip, &cert, &key, &errmsg );

    if ( rv != SECSuccess ) {
    	if ( errmsg != NULL ) {
	    errmsg = ldapssl_libldap_compat_strdup( errmsg );
	}
	ldap_set_lderrno( ld, LDAP_PARAM_ERROR, NULL, errmsg );
	return( rv );
    }

    if ( cert != NULL ) {
	CERT_DestroyCertificate( cert );
    }
    if ( key != NULL ) {
	SECKEY_DestroyPrivateKey( key );
    }
    return( SECSuccess );
}


/*
 * A strdup() work-alike that uses libldap's memory allocator.
 */
static char *
ldapssl_libldap_compat_strdup(const char *s1)
{
    char	*s2;

    if ( NULL == s1 ) {
	s2 = NULL;
    } else {
	size_t	len = strlen( s1 );

	if ( NULL != ( s2 = (char *)ldap_x_malloc( len + 1 ))) {
	    strcpy( s2, s1 );
	}
    }

    return s2;
}


#if 0	/* NOT_NEEDED_IN_LIBLDAP */
/* there are patches and kludges.  this is both.  force some linkers to
 * link this stuff in
 */
int stubs_o_stuff( void )
{
    PRExplodedTime exploded;
    PLArenaPool pool;

    const char *name ="t";
    PRUint32 size = 0, align = 0;

    PR_ImplodeTime( &exploded );
    PL_InitArenaPool( &pool, name, size, align);
    PR_Cleanup();
    PR_fprintf((PRFileDesc*)stderr, "Bad IDEA!!");

    return 0;

}
#endif	/* NOT_NEEDED_IN_LIBLDAP */


/*
 * Import the file descriptor corresponding to the socket of an already
 * open LDAP connection into SSL, and update the socket and session
 * information accordingly. Returns 0 if all goes well.
 */
int
LDAP_CALL
ldapssl_import_fd ( LDAP *ld, int secure )
{
    PRLDAPSessionInfo				sei;
    PRLDAPSocketInfo				soi;
    LDAPSSLSocketInfo				*ssoip = NULL;
    LDAPSSLSessionInfo				*sseip;
    PRFileDesc						*sslfd = NULL;
	LBER_SOCKET						intfd = -1;
	char							*hostlist;
	struct lextiof_socket_private	*socketargp;

	/*
     * Get hostlist from LDAP Handle
     */
    if ( ldap_get_option(ld, LDAP_OPT_HOST_NAME, &hostlist) < 0 ) {
		return( -1 );
    }

	/*
     * Get File Desc from current connection
     */
    if ( ldap_get_option(ld, LDAP_OPT_DESC, &intfd) < 0 ) {
		return( -1 );
    }

    /*
     * Get Socket Arg Pointer
     */
    if ( ldap_get_option(ld, LDAP_X_OPT_SOCKETARG, &socketargp) < 0 ) {
		return( -1 );
    }

    /*
     * Retrieve session info. so we can store a pointer to our session info.
     * in our socket info. later.
     */
    memset( &sei, 0, sizeof(sei));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if ( prldap_get_session_info( ld, NULL, &sei ) != LDAP_SUCCESS ) {
        return( -1 );
    }
    sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;


    /*
     * Retrieve socket info. so we have the PRFileDesc.
     */
    memset( &soi, 0, sizeof(soi));
    soi.soinfo_size = PRLDAP_SOCKETINFO_SIZE;
    if ( prldap_get_socket_info( intfd, socketargp, &soi ) != LDAP_SUCCESS ) {
        return( -1 );
    }

    /*
     * Allocate a structure to hold our socket-specific data.
     */
    if ( NULL == ( ssoip = PR_Calloc( 1, sizeof( LDAPSSLSocketInfo )))) {
        goto reset_socket_and_exit_with_error;
    }
    ssoip->soi_sessioninfo = sseip;

    /*
     * Add SSL layer and let the standard NSPR to LDAP layer and enable SSL.
     */
    if (( sslfd = SSL_ImportFD( NULL, soi.soinfo_prfd )) == NULL ) {
        goto reset_socket_and_exit_with_error;
    }

    if ( SSL_OptionSet( sslfd, SSL_SECURITY, secure ) != SECSuccess ||
				SSL_OptionSet( sslfd, SSL_ENABLE_TLS, secure ) ||
                SSL_OptionSet( sslfd, SSL_HANDSHAKE_AS_CLIENT, secure )
                != SECSuccess || ( secure && SSL_ResetHandshake( sslfd,
                PR_FALSE ) != SECSuccess )) {
        goto reset_socket_and_exit_with_error;
    }

	/*
     * Set hostname which will be retrieved (depending on ssl strength) when
     * using client or server auth.
     */
    if ( SSL_SetURL( sslfd, hostlist ) != SECSuccess ) {
		goto reset_socket_and_exit_with_error;
    }

	/*
     * Set any SSL options that were modified by a previous call to
     * the ldapssl_set_option() function.
     */
    if ( set_ssl_options( sslfd, sseip->lssei_ssl_option_value,
						  sseip->lssei_ssl_option_isset ) < 0 ) {
		goto reset_socket_and_exit_with_error;
    }

    /*
     * If using client auth., arrange to use a separate SSL session cache
     * for each distinct local client certificate nickname.
     */
    if ( sseip->lssei_client_auth &&
         sseip->lssei_certnickname && sseip->lssei_certnickname[0] &&
	 SSL_SetSockPeerID( sslfd, sseip->lssei_certnickname) != SECSuccess ) {
	goto reset_socket_and_exit_with_error;
    }

    /*
     * Let the standard NSPR to LDAP layer know about the new socket and
     * our own socket-specific data.
     */
    soi.soinfo_prfd = sslfd;
    soi.soinfo_appdata = (void *)ssoip;
    if ( prldap_set_default_socket_info( ld, &soi ) != LDAP_SUCCESS ) {
        goto reset_socket_and_exit_with_error;
    }

    /*
     * Install certificate hook function.
     */
    if ( SSL_AuthCertificateHook( soi.soinfo_prfd,
                                  (SSLAuthCertificate)ldapssl_AuthCertificate,
                                  (void *)sseip) != 0 ) {
        goto reset_socket_and_exit_with_error;
    }

    if ( SSL_GetClientAuthDataHook( soi.soinfo_prfd,
                get_clientauth_data, sseip->lssei_certnickname ? sseip : NULL )
		!= 0 ) {
        goto reset_socket_and_exit_with_error;
    }

    return 0;

 reset_socket_and_exit_with_error:
    if ( NULL != sslfd ) {
        /*
         * "Unimport" the socket from SSL, i.e. get rid of the upper layer of
         * the file descriptor stack, which represents SSL.
         */
        soi.soinfo_prfd = sslfd;
        sslfd = PR_PopIOLayer( soi.soinfo_prfd, PR_TOP_IO_LAYER );
        sslfd->dtor( sslfd );
    }
    if ( NULL != ssoip ) {
        ldapssl_free_socket_info( &ssoip );
        soi.soinfo_appdata = NULL;
    }
    prldap_set_default_socket_info( ld, &soi );

    return( -1 );
}


/*
 * Reset an LDAP session from SSL to a non-secure status. Basically,
 * this function undoes the work done by ldapssl_install_routines.
 * Returns 0 if all goes well.
 */
int
LDAP_CALL
ldapssl_reset_to_nonsecure ( LDAP *ld )
{
    PRLDAPSessionInfo   sei;
    LDAPSSLSessionInfo  *sseip;

    struct ldap_x_ext_io_fns    iofns;
    int rc = 0;

    /*
     * Retrieve session info.
     */
    memset( &sei, 0, sizeof(sei));
    sei.seinfo_size = PRLDAP_SESSIONINFO_SIZE;
    if ( prldap_get_session_info( ld, NULL, &sei ) != LDAP_SUCCESS ) {
        return( -1 );
    }
    sseip = (LDAPSSLSessionInfo *)sei.seinfo_appdata;

    if ( sseip != NULL ) {
        /*
         * Reset the standard extended io functions.
         */
        memset( &iofns, 0, sizeof(iofns));
        iofns.lextiof_size = LDAP_X_EXTIO_FNS_SIZE;
        if ( ldap_get_option( ld, LDAP_X_OPT_EXTIO_FN_PTRS, (void *)&iofns )
		< 0) {
            rc = -1;
            goto free_session_info;
        }

        /* reset socket, connect, and ioctl */
        iofns.lextiof_connect = sseip->lssei_std_functions.lssf_connect_fn;
        iofns.lextiof_close = sseip->lssei_std_functions.lssf_close_fn;
        iofns.lextiof_disposehandle =
			sseip->lssei_std_functions.lssf_disposehdl_fn;

        if ( ldap_set_option( ld, LDAP_X_OPT_EXTIO_FN_PTRS, (void *)&iofns )
		< 0) {
            rc = -1;
            goto free_session_info;
        }

free_session_info:
        ldapssl_free_session_info( &sseip );
        sei.seinfo_appdata = NULL;
        if ( prldap_set_session_info( ld, NULL, &sei ) != LDAP_SUCCESS ) {
            rc = -1;
        }
    } /* if ( sseip && *sseip ) */

    if ( ldap_set_option( ld, LDAP_OPT_SSL, LDAP_OPT_OFF ) < 0 ) {
        return (-1);
    }

    return rc;
}


#ifdef _SOLARIS_SDK
static void
_nss_initf_ipnodes(nss_db_params_t *p)
{
	static char *no_service = "";

	p->name = NSS_DBNAM_IPNODES;
        p->flags |= NSS_USE_DEFAULT_CONFIG;
        p->default_config = host_service == NULL ? no_service : host_service;
}

static void
_nss_initf_hosts(nss_db_params_t *p)
{
	static char *no_service = "";

	p->name = NSS_DBNAM_HOSTS;
        p->flags |= NSS_USE_DEFAULT_CONFIG;
        p->default_config = host_service == NULL ? no_service : host_service;
}

static struct hostent *
_switch_gethostbyaddr_r(const char *addr, int len, int type,
	struct hostent *result, char *buffer, int buflen,
	int *h_errnop)
{
        nss_XbyY_args_t arg;
        nss_status_t    res;
	int		(*str2ent)();
	void		(*nss_initf)();
	nss_db_root_t	*nss_db_root;

	if (AF_INET == type) {
		str2ent		= str2hostent;
		nss_initf	= _nss_initf_hosts;
		nss_db_root	= &db_root_hosts; 
	} else if (AF_INET6 == type) {
		str2ent		= str2hostent6;
		nss_initf	= _nss_initf_ipnodes;
		nss_db_root	= &db_root_ipnodes;
	} else {
		return NULL;
	}

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2ent);

        arg.key.hostaddr.addr	= addr;
        arg.key.hostaddr.len	= len;
        arg.key.hostaddr.type	= type;
        arg.stayopen		= 0;

        res = nss_search(nss_db_root, nss_initf,
        	NSS_DBOP_HOSTS_BYADDR, &arg);
        arg.status = res;
        *h_errnop = arg.h_errno;
        return (struct hostent *)NSS_XbyY_FINI(&arg);
}

/*
 * ns_gethostbyaddr is used to be a substitute gethostbyaddr for
 * libldap when ssl will need to determine the fully qualified
 * host name from an address when it is unsafe to use the normal
 * nameservice functions.
 *
 * Note that the ldap name service resolver calls this with the address as
 * a character string - which we must convert into address form.
 */

/*ARGSUSED*/
static LDAPHostEnt *
ns_gethostbyaddr(const char *addr, int len, int type,
	LDAPHostEnt *result, char *buffer, int buflen, int *statusp,
	void *extradata)
{
	LDAPHostEnt	*ldap_hent;
	int		h_errno;
	struct hostent	h_ent;
	struct hostent	*h_e = NULL;
	struct in_addr	a;
	struct in6_addr	a6;
	int		inet_error;	/* error returned by inet_pton */


	if (addr == NULL || result == NULL || buffer == NULL ||
			(type != AF_INET && type != AF_INET6))
		return (NULL);


	(void) memset(&h_ent, 0, sizeof (h_ent));

	if (AF_INET == type) {
		if (inet_pton(type, addr, &a.s_addr) == 1) {
			h_e = _switch_gethostbyaddr_r((char *)&a,
				sizeof (a.s_addr), type, &h_ent,
				buffer, buflen, &h_errno);
		}
	} else if (AF_INET6 == type) {
		if (inet_pton(type, addr, &a6.s6_addr) == 1) {
			h_e = _switch_gethostbyaddr_r((char *)&a6,
				sizeof (a6.s6_addr), type, &h_ent,
				buffer, buflen, &h_errno);
		}
	}

	if (h_e == NULL) {
		ldap_hent = NULL;
	} else {
		(void) memset(result, 0, sizeof (LDAPHostEnt));
		ldap_hent = result;
		result->ldaphe_name = h_e->h_name;
 		result->ldaphe_aliases = h_e->h_aliases;
 		result->ldaphe_addrtype = h_e->h_addrtype;
 		result->ldaphe_length = h_e->h_length;
 		result->ldaphe_addr_list = h_e->h_addr_list;
	}
	return (ldap_hent);
}

/*
 * ldapssl_install_gethostbyaddr attempts to prevent recursion in
 * gethostbyaddr calls when an ip address is given to ssl. This ip address
 * must be resolved to a host name.
 * 
 * For example, libsldap cannot use LDAP to resolve this address to a
 * name because of recursion. The caller is instructing libldap to skip
 * the specified name service when resolving addresses for the specified
 * ldap connection.
 *
 * Currently only ldap and dns name services always return fully qualified
 * names. The other name services (files, nis, and nisplus) will returned
 * fully qualified names if the host names are stored as fully qualified names
 * in these name services.
 *
 * Note:
 *
 *	Since host_service applies to all connections, calling
 *	ldapssl_install_gethostbyaddr with different name services to
 *	skip will lead to unpredictable results.
 *
 * Returns:
 *	0	if success
 *	-1	if failure
 */

int
ldapssl_install_gethostbyaddr(LDAP *ld, const char *skip)
{
	enum __nsw_parse_err		pserr;
	struct __nsw_switchconfig	*conf;
	struct __nsw_lookup		*lkp;
	struct ldap_dns_fns		dns_fns;
	char				*name_list = NULL;
	char				*tmp;
	const char			*name;
	int				len;
	boolean_t			got_skip = B_FALSE;

	/*
	 * db_root_hosts.lock mutex is used to ensure that the name list
	 * is not in use by the name service switch while we are updating
	 * the host_service
	 */

	(void) mutex_lock(&db_root_hosts.lock);
	conf = __nsw_getconfig("hosts", &pserr);
	if (conf == NULL) {
		(void) mutex_unlock(&db_root_hosts.lock);
		return (0);
	}

	/* check for ldap and count other backends */
	for (lkp = conf->lookups; lkp != NULL; lkp = lkp->next) {
		name = lkp->service_name;
		if (strcmp(name, skip) == 0) {
			got_skip = B_TRUE;
			continue;
		}
		if (name_list == NULL)
			name_list = strdup(name);
		else {
			len = strlen(name_list);
			tmp = realloc(name_list, len + strlen(name) + 2);
			if (tmp == NULL) {
				free(name_list);
				name_list = NULL;
			} else {
				name_list = tmp;
				name_list[len++] = ' ';
				(void) strcpy(name_list+len, name);
			}
		}
		if (name_list == NULL) {	/* alloc error */
			(void) mutex_unlock(&db_root_hosts.lock);
			__nsw_freeconfig(conf);
			return (-1);
		}
	}
	__nsw_freeconfig(conf);
	if (!got_skip) {
		/*
		 * Since skip name service not used for hosts, we do not need
		 * to install our private address resolution function
		 */
		(void) mutex_unlock(&db_root_hosts.lock);
		if (name_list != NULL)
			free(name_list);
		return (0);
	}
	if (host_service != NULL)
		free(host_service);
	host_service = name_list;
	(void) mutex_unlock(&db_root_hosts.lock);

	if (ldap_get_option(ld, LDAP_OPT_DNS_FN_PTRS, &dns_fns) != 0)
		return (-1);
	dns_fns.lddnsfn_gethostbyaddr = ns_gethostbyaddr;
	if (ldap_set_option(ld, LDAP_OPT_DNS_FN_PTRS, &dns_fns) != 0)
		return (-1);
	return (0);
}
#endif	/* _SOLARIS_SDK */
#endif /* NET_SSL */

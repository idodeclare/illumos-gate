/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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
 * The Original Code is Sun LDAP C SDK.
 *
 * The Initial Developer of the Original Code is Sun Microsystems, Inc.
 *
 * Portions created by Sun Microsystems, Inc are Copyright (C) 2005
 * Sun Microsystems, Inc. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
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

#ifdef LDAP_SASLIO_HOOKS
#include <assert.h>
#include "ldap-int.h"
#ifdef _SOLARIS_SDK
#include "../ber/lber-int.h"
#include <sasl/sasl.h>
#include <thread.h>
#include <synch.h>
#else
#include "../liblber/lber-int.h"
#include <sasl.h>
#endif /* _SOLARIS_SDK */
/* Should be pulled in from lber-int.h */
#define	READBUFSIZ	8192

#define SEARCH_TIMEOUT_SECS	120
#define NSLDAPI_SM_BUF	128

#ifdef _SOLARIS_SDK
extern void *sasl_create_context(void);
extern void sasl_free_context(void *ctx);
extern int _sasl_client_init(void *ctx, const sasl_callback_t *callbacks);
extern int _sasl_client_new(void *ctx, const char *service,
	const char *serverFQDN, const char *iplocalport,
	const char *ipremoteport,
	const sasl_callback_t *prompt_supp,
	unsigned flags, sasl_conn_t **pconn);
extern int _sasl_server_init(void *ctx,
	const sasl_callback_t *callbacks, const char *appname);
extern int _sasl_server_new(void *ctx, const char *service,
	const char *serverFQDN, const char *user_realm,
	const char *iplocalport, const char *ipremoteport,
	const sasl_callback_t *callbacks,
	unsigned flags, sasl_conn_t **pconn);

static int nsldapi_sasl_close( LDAP *ld, Sockbuf *sb );
static void destroy_sasliobuf(Sockbuf *sb);

/*
 * SASL Dependent routines
 *
 * SASL security and integrity options are supported through the
 * use of the extended I/O functionality.  Because the extended
 * I/O functions may already be in use prior to enabling encryption,
 * when SASL encryption is enabled, these routine interpose themselves
 * over the existng extended I/O routines and add an additional level
 * of indirection.
 *  IE: Before SASL:  client->libldap->lber->extio
 *      After  SASL:  client->libldap->lber->saslio->extio
 * Any extio functions are still used for the raw i/O [IE prldap]
 * but SASL will decrypt before passing to lber.
 * SASL cannot decrypt a stream so full packets must be read
 * before proceeding.
 */

static int nsldapi_sasl_fail()
{
	return( SASL_FAIL );
}

/*
 * Global SASL Init data
 */

static sasl_callback_t client_callbacks[] = {
	{ SASL_CB_GETOPT, nsldapi_sasl_fail, NULL },
	{ SASL_CB_GETREALM, NULL, NULL },
	{ SASL_CB_USER, NULL, NULL },
	{ SASL_CB_AUTHNAME, NULL, NULL },
	{ SASL_CB_PASS, NULL, NULL },
	{ SASL_CB_ECHOPROMPT, NULL, NULL },
	{ SASL_CB_NOECHOPROMPT, NULL, NULL },
	{ SASL_CB_LIST_END, NULL, NULL }
};
static mutex_t sasl_mutex = DEFAULTMUTEX;
static int nsldapi_sasl_inited = 0;
static void *gctx;  /* intentially not freed - avoid libsasl re-inits */

int nsldapi_sasl_init( void )
{
	int	saslrc;

	mutex_lock(&sasl_mutex);
	if ( nsldapi_sasl_inited ) {
		mutex_unlock(&sasl_mutex);
		return( 0 );
	}
	if ((gctx = (void *)sasl_create_context()) != NULL) {
		saslrc = _sasl_client_init(gctx, client_callbacks);
		if (saslrc == SASL_OK ) {
			nsldapi_sasl_inited = 1;
			mutex_unlock(&sasl_mutex);
			return( 0 );
		}
	}
	mutex_unlock(&sasl_mutex);
	return( -1 );
}
#endif /* _SOLARIS_SDK */

/*
 * Data structures:
 */

/* data structure that populates the I/O callback socket-specific arg. */
typedef struct lextiof_socket_private {
	struct ldap_x_ext_io_fns sess_io_fns; /* the saved layered ld fns from the layer we are "pushing" */
	struct lber_x_ext_io_fns sock_io_fns; /* the saved layered ber fns from the layer we are "pushing" */
	sasl_conn_t     *sasl_ctx;     /* the sasl context - pointer to the one from the connection */
	char            *sb_sasl_ibuf; /* sasl decrypted input buffer */
	char            *sb_sasl_iptr; /* current location in buffer */
	int             sb_sasl_bfsz;  /* Alloc'd size of input buffer */
	int             sb_sasl_ilen;  /* remaining length to process */
	LDAP            *ld;           /* used to set errno */
	Sockbuf         *sb;           /* pointer to our associated sockbuf */
} SASLIOSocketArg;

static void
destroy_SASLIOSocketArg(SASLIOSocketArg** sockarg)
{
	if (sockarg && *sockarg) {
		NSLDAPI_FREE((*sockarg)->sb_sasl_ibuf);
		NSLDAPI_FREE((*sockarg));
		*sockarg = NULL;
	}
}

static SASLIOSocketArg*
new_SASLIOSocketArg(sasl_conn_t *ctx, int bufsiz, LDAP *ld, Sockbuf *sb)
{
	SASLIOSocketArg *sockarg = NULL;

	if (bufsiz <= 0) {
		return sockarg;
	}

	sockarg = (SASLIOSocketArg*)NSLDAPI_CALLOC(1, sizeof(SASLIOSocketArg));
	if (sockarg) {
		sockarg->sasl_ctx = ctx;
		sockarg->sb_sasl_ibuf = NSLDAPI_MALLOC(bufsiz);
		if (!sockarg->sb_sasl_ibuf) {
			destroy_SASLIOSocketArg(&sockarg);
			return sockarg;
		}
		sockarg->sb_sasl_iptr = NULL;
		sockarg->sb_sasl_bfsz = bufsiz;
		sockarg->sb_sasl_ilen = 0;
		sockarg->ld           = ld;
		sockarg->sb           = sb;
	}

	return sockarg;
}

/*
 * SASL Dependent routines
 *
 * SASL security and integrity options are supported through the
 * use of the extended I/O functionality.  Because the extended
 * I/O functions may already be in use prior to enabling encryption,
 * when SASL encryption si enabled, these routine interpose themselves
 * over the exitng extended I/O routines and add an additional level
 * of indirection.
 *  IE: Before SASL:  client->libldap->lber->extio
 *      After  SASL:  client->libldap->lber->saslio->extio
 * Any extio function are stilled used for the raw i/O [IE prldap]
 * but SASL will decrypt before passing to lber.
 * SASL cannot decrypt a stream so full packaets must be read
 * before proceeding.
 */

/*
 * Get the 4 octet header [size] for a sasl encrypted buffer.
 * See RFC222 [section 3].
 */
static int
nsldapi_sasl_pktlen( char *buf, int maxbufsize )
{
	int	size;

#if defined( _WINDOWS ) || defined( _WIN32 )
	size = ntohl(*(long *)buf);
#else
	size = ntohl(*(uint32_t *)buf);
#endif
   
	if ( size < 0 || size > maxbufsize ) {
		return (-1 );
	}

	return( size + 4 ); /* include the first 4 bytes */
}

/*
 * SASL encryption routines
 */

static int
nsldapi_sasl_read( int s, void *buf, int  len,
	struct lextiof_socket_private *arg)
{
	LDAP		*ld;
	const char	*dbuf;
	char		*cp;
	int		ret;
	unsigned	dlen, blen;
   
	ld = (LDAP *)arg->ld;

	/* Is there anything left in the existing buffer? */
	if ((ret = arg->sb_sasl_ilen) > 0) {
		ret = (ret > len ? len : ret);
		SAFEMEMCPY( buf, arg->sb_sasl_iptr, ret );
		if (ret == arg->sb_sasl_ilen) {
			arg->sb_sasl_ilen = 0;
			arg->sb_sasl_iptr = NULL;
		} else {
			arg->sb_sasl_ilen -= ret;
			arg->sb_sasl_iptr += ret;
		}
		return( ret );
	}

	/* buffer is empty - fill it */
	cp = arg->sb_sasl_ibuf;
	dlen = 0;
	
	/* Read the length of the packet */
	while ( dlen < 4 ) {
		if (arg->sock_io_fns.lbextiofn_read != NULL) {
			ret = arg->sock_io_fns.lbextiofn_read(
				s, cp, 4 - dlen,
				arg->sock_io_fns.lbextiofn_socket_arg);
		} else {
			ret = read( s, cp, 4 - dlen );
		}
#ifdef EINTR
		if ( ( ret < 0 ) && ( LDAP_GET_ERRNO(ld) == EINTR ) )
			continue;
#endif
		if ( ret <= 0 )
			return( ret );

		cp += ret;
		dlen += ret;
	}

	blen = 4;

	ret = nsldapi_sasl_pktlen( arg->sb_sasl_ibuf, arg->sb_sasl_bfsz );
	if (ret < 0) {
		LDAP_SET_ERRNO(ld, EIO);
		return( -1 );
	}
	dlen = ret - dlen;

	/* read the rest of the encrypted packet */
	while ( dlen > 0 ) {
		if (arg->sock_io_fns.lbextiofn_read != NULL) {
			ret = arg->sock_io_fns.lbextiofn_read(
				s, cp, dlen,
				arg->sock_io_fns.lbextiofn_socket_arg);
		} else {
			ret = read( s, cp, dlen );
		}

#ifdef EINTR
		if ( ( ret < 0 ) && ( LDAP_GET_ERRNO(ld) == EINTR ) )
			continue;
#endif
		if ( ret <= 0 )
			return( ret );

		cp += ret;
		blen += ret;
		dlen -= ret;
   	}

	/* Decode the packet */
	ret = sasl_decode( arg->sasl_ctx,
			   arg->sb_sasl_ibuf, blen,
			   &dbuf, &dlen);
	if ( ret != SASL_OK ) {
		/* sb_sasl_read: failed to decode packet, drop it, error */
		arg->sb_sasl_iptr = NULL;
		arg->sb_sasl_ilen = 0;
		LDAP_SET_ERRNO(ld, EIO);
		return( -1 );
	}
	
	/* copy decrypted packet to the input buffer */
	SAFEMEMCPY( arg->sb_sasl_ibuf, dbuf, dlen );
	arg->sb_sasl_iptr = arg->sb_sasl_ibuf;
	arg->sb_sasl_ilen = dlen;

	ret = (dlen > (unsigned) len ? len : dlen);
	SAFEMEMCPY( buf, arg->sb_sasl_iptr, ret );
	if (ret == arg->sb_sasl_ilen) {
		arg->sb_sasl_ilen = 0;
		arg->sb_sasl_iptr = NULL;
	} else {
		arg->sb_sasl_ilen -= ret;
		arg->sb_sasl_iptr += ret;
	}
	return( ret );
}

static int
nsldapi_sasl_write( int s, const void *buf, int  len,
	struct lextiof_socket_private *arg)
{
	int		ret = 0;
	const char	*obuf, *optr, *cbuf = (const char *)buf;
	unsigned	olen, clen, tlen = 0;
	unsigned	*maxbuf;

	ret = sasl_getprop(arg->sasl_ctx, SASL_MAXOUTBUF,
					     (const void **)&maxbuf);
	if ( ret != SASL_OK ) {
		/* just a sanity check, should never happen */
		return( -1 );
	}

	while (len > 0) {
		clen = (len > *maxbuf) ? *maxbuf : len;
		/* encode the next packet. */
		ret = sasl_encode( arg->sasl_ctx, cbuf, clen, &obuf, &olen);
		if ( ret != SASL_OK ) {
			/* XXX Log error? "sb_sasl_write: failed to encode packet..." */
			return( -1 );
		}
		/* Write everything now, buffer is only good until next sasl_encode */
		optr = obuf;
		while (olen > 0) {
			if (arg->sock_io_fns.lbextiofn_write != NULL) {
				ret = arg->sock_io_fns.lbextiofn_write(
					s, optr, olen,
					arg->sock_io_fns.lbextiofn_socket_arg);
			} else {
				ret = write( s, optr, olen);
			}
			if ( ret < 0 )
				return( ret );
			optr += ret;
			olen -= ret;
		}
		len -= clen;
		cbuf += clen;
		tlen += clen;
	}
	return( tlen );
}

/*
 * What's all this then?
 * First, take a look at os-ip.c:nsldapi_add_to_cb_pollfds().  When a new descriptor is
 * added to the pollfds array, the lpoll_socketarg field is initialized to the value from
 * the socketarg field - sb->sb_ext_io_fns.lbextiofn_socket_arg.  In our case, since we
 * override this with our sasl data (see below nsldapi_sasl_install), we need to restore
 * the previous value so that the layer below us (i.e. prldap) can use the lpoll_socketarg
 * which it sets.
 * So how do which know which fds[i] is a "sasl" fd?
 * We initialize the lextiof_session_private *arg (see nsldapi_sasl_install) to point to
 * the socket_private data in sb->sb_ext_io_fns.lbextiofn_socket_arg for "sasl" sockets,
 * which is then used to initialize lpoll_socketarg (see above).
 * So, if the arg which gets passed into nsldapi_sasl_poll is the same as the
 * fds[i].lpoll_socketarg, we know it is a "sasl" socket and we need to "pop" the sasl
 * layer.  We do this by replacing lpoll_socketarg with the one we saved when we "pushed"
 * the sasl layer.
 * So why the loop to restore the sasl lpoll_socketarg?
 * The lower layer only uses lpoll_socketarg during poll().  See ldappr-io.c:prldap_poll()
 * for more information about how that works.  However, after the polling is done, there
 * is some special magic in os-ip.c in the functions nsldapi_add_to_cb_pollfds(),
 * nsldapi_clear_from_cb_pollfds(), and nsldapi_find_in_cb_pollfds() to find the correct
 * Sockbuf to operate on.  This is the macro NSLDAPI_CB_POLL_MATCH().  For the extended
 * io function callbacks to work correctly, it is not sufficient to say that the file
 * descriptor in the Sockbuf matches the one that poll says has activity - we also need
 * to match the lpoll_socketarg with the sb->sb_ext_io_fns.lbextiofn_socket_arg to make
 * sure this really is the Sockbuf we want to use.  So we have to restore the
 * lpoll_socketarg with the original one.
 * Why have origarg and staticorigarg?
 * To avoid malloc.  The sizeof staticorigarg should be large enough to accomodate almost
 * all clients without incurring too much additional overhead.  However, if we need more
 * room, origarg will grow to nfds.  If this proves to be inadequate, the size of the
 * staticorigarg is a good candidate for a #define set by configure.
 */
static int
nsldapi_sasl_poll(
	LDAP_X_PollFD fds[], int nfds, int timeout,
	struct lextiof_session_private *arg ) 
{
	LDAP_X_EXTIOF_POLL_CALLBACK *origpoll; /* poll fn from the pushed layer */
	struct lextiof_session_private *origsess = NULL; /* session arg from the pushed layer */
	SASLIOSocketArg **origarg = NULL; /* list of saved original socket args */
	SASLIOSocketArg *staticorigarg[1024]; /* default list to avoid malloc */
	int origargsize = sizeof(staticorigarg)/sizeof(staticorigarg[0]);
	int rc = -1; /* the return code - -1 means failure */

	if (arg == NULL) { /* should not happen */
		return( rc );
	}

	origarg = staticorigarg;
	/* if the static array is not large enough, alloc a dynamic one */
	if (origargsize < nfds) {
		origarg = (SASLIOSocketArg **)NSLDAPI_MALLOC(nfds*sizeof(SASLIOSocketArg *));
	}

	if (fds && nfds > 0) {
		int i;
		for(i = 0; i < nfds; i++) {
			/* save the original socket arg */
			origarg[i] = fds[i].lpoll_socketarg;
			if (arg == (struct lextiof_session_private *)fds[i].lpoll_socketarg) {
				/* lpoll_socketarg is a sasl socket arg - we need to replace it
				   with the one from the layer we pushed (i.e. prldap) */
				SASLIOSocketArg *sockarg = (SASLIOSocketArg *)fds[i].lpoll_socketarg;
				/* reset to pushed layer's socket arg */
				fds[i].lpoll_socketarg = sockarg->sock_io_fns.lbextiofn_socket_arg;
				/* grab the pushed layers' poll fn and its session arg */
				if (!origsess) {
					origpoll = sockarg->sess_io_fns.lextiof_poll;
					origsess = sockarg->sess_io_fns.lextiof_session_arg;
				}
			}
		}
	}

	if (origsess == NULL) { /* should not happen */
		goto done;
	}

	/* call the "real" poll function */
	rc = origpoll( fds, nfds, timeout, origsess );

	/* reset the lpoll_socketarg values to their original values because
	   they must match what's in sb->iofns->lbextiofn_socket_arg in order
	   for NSLDAPI_CB_POLL_MATCH to work - see os-ip.c */
	if (fds && nfds > 0) {
		int i;
		for(i = 0; i < nfds; i++) {
			if ((SASLIOSocketArg *)arg == origarg[i]) {
				fds[i].lpoll_socketarg = origarg[i];
			}
		}
	}

done:
	/* if we had to use a dynamic array, free it */
	if (origarg != staticorigarg) {
		NSLDAPI_FREE(origarg);
	}

	return rc;
}

int
nsldapi_sasl_open( LDAP *ld, LDAPConn *lconn, sasl_conn_t **ctx, sasl_ssf_t ssf )
{
        int saslrc;
        char *host = NULL;

        if ( !NSLDAPI_VALID_LDAP_POINTER( ld )) {
                LDAP_SET_LDERRNO( ld, LDAP_LOCAL_ERROR, NULL, NULL );
                return( LDAP_LOCAL_ERROR );
        }

        if ( lconn == NULL ) {
                if ( ld->ld_defconn == NULL ||
                     ld->ld_defconn->lconn_status != LDAP_CONNST_CONNECTED) {
                        int rc = nsldapi_open_ldap_defconn( ld );
                        if( rc < 0 )  {
                                return( LDAP_GET_LDERRNO( ld, NULL, NULL ) );
                        }
                }
                lconn = ld->ld_defconn;
        }

        /* need to clear out the old context for this connection, if any */
        /* client may have re-bind-ed this connection without closing first */
        if (lconn->lconn_sasl_ctx) {
            sasl_dispose(&lconn->lconn_sasl_ctx);
            lconn->lconn_sasl_ctx = NULL;
        }

        if ( 0 != ldap_get_option( ld, LDAP_OPT_HOST_NAME, &host ) ) {
                LDAP_SET_LDERRNO( ld, LDAP_LOCAL_ERROR, NULL, NULL );
                return( LDAP_LOCAL_ERROR );
        }

        saslrc = sasl_client_new( "ldap", host,
                NULL, NULL, /* iplocalport, ipremoteport - use defaults */
                NULL, 0, ctx );
        ldap_memfree(host);

        if ( (saslrc != SASL_OK) || (!*ctx) ) {
                return( nsldapi_sasl_cvterrno( ld, saslrc, NULL ) );
        }

        if( ssf ) {
                sasl_ssf_t extprops;
                memset(&extprops, 0L, sizeof(extprops));
                extprops = ssf;

                (void) sasl_setprop( *ctx, SASL_SSF_EXTERNAL,
                        (void *) &extprops );
        }

        /* (re)set security properties */
        sasl_setprop( *ctx, SASL_SEC_PROPS, &ld->ld_sasl_secprops );

        /* set the connection context */
        lconn->lconn_sasl_ctx = *ctx;

        return( LDAP_SUCCESS );
}

#ifdef _SOLARIS_SDK
static int
nsldapi_sasl_ne_write( int s, const void *buf, int  len,
	struct lextiof_socket_private *arg)
{
	Sockbuf		*sb = (Sockbuf *)arg;

	if (sb == NULL) {
		return( -1 );
	}

	return( sb->sb_sasl_fns.lbextiofn_write( s, buf, len,
			sb->sb_sasl_fns.lbextiofn_socket_arg) );
}
#endif /* _SOLARIS_SDK */

static int
nsldapi_sasl_close( struct lextiof_socket_private *arg )
{
	/* undo function pointer interposing */
	ldap_set_option( arg->ld, LDAP_X_OPT_EXTIO_FN_PTRS, &arg->sess_io_fns );
	/* have to do this separately to make sure the socketarg is set correctly */
	ber_sockbuf_set_option( arg->sb,
							LBER_SOCKBUF_OPT_EXT_IO_FNS,
							(void *)&arg->sock_io_fns );

	destroy_SASLIOSocketArg(&arg);
	return( LDAP_SUCCESS );
}

static int
nsldapi_sasl_close_socket(int s, struct lextiof_socket_private *arg ) 
{
	LDAP_X_EXTIOF_CLOSE_CALLBACK *origclose;
	struct lextiof_socket_private *origsock;

	if (arg == NULL) {
		return( -1 );
	}

	origclose = arg->sess_io_fns.lextiof_close;
	origsock = arg->sock_io_fns.lbextiofn_socket_arg;

	/* undo SASL */
	nsldapi_sasl_close( arg );
	arg = NULL;
	/* arg is destroyed at this point - do not use it */

	if (origclose )
		return ( origclose( s, origsock ) );
	else {
		/* This is a copy of nsldapi_os_closesocket()
		 * from os-ip.c. It is declared static there,
		 * hence the copy of it.
		 */
	        int     rc;

#ifdef NSLDAPI_AVOID_OS_SOCKETS
		rc = -1;
#else /* NSLDAPI_AVOID_OS_SOCKETS */
#ifdef _WINDOWS
		rc = closesocket( s );
#else /* _WINDOWS */
		rc = close( s );
#endif /* _WINDOWS */
#endif /* NSLDAPI_AVOID_OS_SOCKETS */
		return( rc );
	}
		
}

/*
 * install encryption routines if security has been negotiated
 */
int
nsldapi_sasl_install( LDAP *ld, LDAPConn *lconn )
{
        struct lber_x_ext_io_fns        fns;
        struct ldap_x_ext_io_fns        iofns;
        sasl_security_properties_t      *secprops;
        int     rc, value;
        int     bufsiz;
        Sockbuf *sb = NULL;
        sasl_conn_t *ctx = NULL;
        SASLIOSocketArg *sockarg = NULL;

        if ( lconn == NULL ) {
                lconn = ld->ld_defconn;
                if ( lconn == NULL ) {
                        return( LDAP_LOCAL_ERROR );
                }
        }
        if ( (sb = lconn->lconn_sb) == NULL ) {
                return( LDAP_LOCAL_ERROR );
        }
        rc = ber_sockbuf_get_option( sb,
                        LBER_SOCKBUF_OPT_TO_FILE_ONLY,
                        (void *) &value);
        if (rc != 0 || value != 0) {
                return( LDAP_LOCAL_ERROR );
        }

        /* the sasl context in the lconn must have been set prior to this */
        ctx = lconn->lconn_sasl_ctx;
        rc = sasl_getprop( ctx, SASL_SEC_PROPS,
                           (const void **)&secprops );
        if (rc != SASL_OK)
                return( LDAP_LOCAL_ERROR );
        bufsiz = secprops->maxbufsize;
        if (bufsiz <= 0) {
                return( LDAP_LOCAL_ERROR );
        }

        /* create our socket specific context */
        sockarg = new_SASLIOSocketArg(ctx, bufsiz, ld, sb);
        if (!sockarg) {
                return( LDAP_LOCAL_ERROR );
        }

        /* save a copy of the existing io fns and the session arg */
        memset( &sockarg->sess_io_fns, 0, LDAP_X_EXTIO_FNS_SIZE );
        sockarg->sess_io_fns.lextiof_size = LDAP_X_EXTIO_FNS_SIZE;
        rc = ldap_get_option( ld, LDAP_X_OPT_EXTIO_FN_PTRS,
                              &sockarg->sess_io_fns );
        if (rc != 0) {
                destroy_SASLIOSocketArg(&sockarg);
                return( LDAP_LOCAL_ERROR );
        }

        /* save a copy of the existing ber io fns and the socket arg */
        memset( &sockarg->sock_io_fns, 0, LBER_X_EXTIO_FNS_SIZE );
        sockarg->sock_io_fns.lbextiofn_size = LBER_X_EXTIO_FNS_SIZE;
        rc = ber_sockbuf_get_option( sb,
                        LBER_SOCKBUF_OPT_EXT_IO_FNS,
                        (void *)&sockarg->sock_io_fns);
        if (rc != 0) {
                destroy_SASLIOSocketArg(&sockarg);
                return( LDAP_LOCAL_ERROR );
        }

	/* Always set the ext io close fn pointer to ensure we
	 * clean up our sockarg context */
	memset( &iofns, 0, sizeof(iofns));
	/* first, copy struct - sets defaults */
	iofns = sockarg->sess_io_fns;
	iofns.lextiof_close = nsldapi_sasl_close_socket;
	iofns.lextiof_session_arg = sockarg; /* needed for close and poll */

        /* Set new values for the other ext io funcs if there are any -
           when using the native io fns (as opposed to prldap) there
           won't be any */
        if (  sockarg->sess_io_fns.lextiof_read != NULL ||
              sockarg->sess_io_fns.lextiof_write != NULL ||
              sockarg->sess_io_fns.lextiof_poll != NULL ||
              sockarg->sess_io_fns.lextiof_connect != NULL ) {
		/* next, just reset those functions we want to override */
                iofns.lextiof_read = nsldapi_sasl_read;
                iofns.lextiof_write = nsldapi_sasl_write;
                iofns.lextiof_poll = nsldapi_sasl_poll;
        }

	/* set the ext io funcs */
	rc = ldap_set_option( ld, LDAP_X_OPT_EXTIO_FN_PTRS, &iofns );
	if (rc != 0) {
		/* frees everything and resets fns above */
		nsldapi_sasl_close(sockarg);
		return( LDAP_LOCAL_ERROR );
	}

        /* set the new ber io funcs and socket arg */
        (void) memset( &fns, 0, LBER_X_EXTIO_FNS_SIZE);
        fns.lbextiofn_size = LBER_X_EXTIO_FNS_SIZE;
        fns.lbextiofn_read = nsldapi_sasl_read;
        fns.lbextiofn_write = nsldapi_sasl_write;
        fns.lbextiofn_socket_arg = sockarg;
        rc = ber_sockbuf_set_option( sb,
                        LBER_SOCKBUF_OPT_EXT_IO_FNS,
                        (void *)&fns);
        if (rc != 0) {
                /* frees everything and resets fns above */
                nsldapi_sasl_close(sockarg);
                return( LDAP_LOCAL_ERROR );
        }

        return( LDAP_SUCCESS );
}

#ifdef _SOLARIS_SDK
static int
nsldapi_sasl_cvterrno( LDAP *ld, int err, char *msg )
{
	int rc = LDAP_LOCAL_ERROR;

	switch (err) {
	case SASL_OK:
		rc = LDAP_SUCCESS;
		break;
	case SASL_NOMECH:
		rc = LDAP_AUTH_UNKNOWN;
		break;
	case SASL_BADSERV:
		rc = LDAP_CONNECT_ERROR;
		break;
	case SASL_DISABLED:
	case SASL_ENCRYPT:
	case SASL_EXPIRED:
	case SASL_NOUSERPASS:
	case SASL_NOVERIFY:
	case SASL_PWLOCK:
	case SASL_TOOWEAK:
	case SASL_UNAVAIL:
	case SASL_WEAKPASS:
		rc = LDAP_INAPPROPRIATE_AUTH;
		break;
	case SASL_BADAUTH:
	case SASL_NOAUTHZ:
		rc = LDAP_INVALID_CREDENTIALS;
		break;
	case SASL_NOMEM:
		rc = LDAP_NO_MEMORY;
		break;
	case SASL_NOUSER:
		rc = LDAP_NO_SUCH_OBJECT;
		break;
	case SASL_CONTINUE:
	case SASL_FAIL:
	case SASL_INTERACT:
	default:
		rc = LDAP_LOCAL_ERROR;
		break;
	}

	LDAP_SET_LDERRNO( ld, rc, NULL, msg );
	return( rc );
}

static void
destroy_sasliobuf(Sockbuf *sb)
{
	if (sb != NULL && sb->sb_sasl_ibuf != NULL) {
		NSLDAPI_FREE(sb->sb_sasl_ibuf);
		sb->sb_sasl_ibuf = NULL;
		sb->sb_sasl_iptr = NULL;
		sb->sb_sasl_bfsz = 0;
		sb->sb_sasl_ilen = 0;
	}
}

static int
nsldapi_sasl_close( LDAP *ld, Sockbuf *sb )
{
	sasl_conn_t	*ctx = (sasl_conn_t *)sb->sb_sasl_ctx;

	destroy_sasliobuf(sb);

	if( ctx != NULL ) {
		sasl_dispose( &ctx );
		sb->sb_sasl_ctx = NULL;
	}
	return( LDAP_SUCCESS );
}

static int
nsldapi_sasl_do_bind( LDAP *ld, const char *dn,
	const char *mechs, unsigned flags,
	LDAP_SASL_INTERACT_PROC *callback, void *defaults,
	LDAPControl **sctrl, LDAPControl **cctrl )
{
	sasl_interact_t *prompts = NULL;
	sasl_conn_t	*ctx;
	sasl_ssf_t	*ssf = NULL;
	const char	*mech = NULL;
	int		saslrc, rc;
	struct berval	ccred;
	unsigned	credlen;
	int		stepnum = 1;
	char *sasl_username = NULL;

	if (NSLDAPI_LDAP_VERSION( ld ) < LDAP_VERSION3) {
		LDAP_SET_LDERRNO( ld, LDAP_NOT_SUPPORTED, NULL, NULL );
		return( LDAP_NOT_SUPPORTED );
	}

	/* shouldn't happen */
	if (callback == NULL) {
		return( LDAP_LOCAL_ERROR );
	}

	if ( ld->ld_defconn == NULL ||
	     ld->ld_defconn->lconn_status != LDAP_CONNST_CONNECTED) {
		rc = nsldapi_open_ldap_defconn( ld );
		if( rc < 0 )  {
			return( LDAP_GET_LDERRNO( ld, NULL, NULL ) );
		}
	}   

	/* should have a valid ld connection - now create sasl connection */
	if ((rc = nsldapi_sasl_open(ld)) != LDAP_SUCCESS) {
		LDAP_SET_LDERRNO( ld, rc, NULL, NULL );
		return( rc );
	}

	/* expect context to be initialized when connection is open */
	ctx = (sasl_conn_t *)ld->ld_defconn->lconn_sb->sb_sasl_ctx;

	if( ctx == NULL ) {
		LDAP_SET_LDERRNO( ld, LDAP_LOCAL_ERROR, NULL, NULL );
		return( LDAP_LOCAL_ERROR );
	}

	/* (re)set security properties */
	sasl_setprop( ctx, SASL_SEC_PROPS, &ld->ld_sasl_secprops );

	ccred.bv_val = NULL;
	ccred.bv_len = 0;

	LDAPDebug(LDAP_DEBUG_TRACE, "Starting SASL/%s authentication\n",
		  (mech ? mech : ""), 0, 0 );

	do {
		saslrc = sasl_client_start( ctx,
			mechs,
			&prompts,
			(const char **)&ccred.bv_val,
			&credlen,
			&mech );

		LDAPDebug(LDAP_DEBUG_TRACE, "Doing step %d of client start for SASL/%s authentication\n",
			  stepnum, (mech ? mech : ""), 0 );
		stepnum++;

		if( saslrc == SASL_INTERACT &&
		    (callback)(ld, flags, defaults, prompts) != LDAP_SUCCESS ) {
			break;
		}
	} while ( saslrc == SASL_INTERACT );

	ccred.bv_len = credlen;

	if ( (saslrc != SASL_OK) && (saslrc != SASL_CONTINUE) ) {
		return( nsldapi_sasl_cvterrno( ld, saslrc, nsldapi_strdup( sasl_errdetail( ctx ) ) ) );
	}

	stepnum = 1;

	do {
		struct berval *scred;
		int clientstepnum = 1;

		scred = NULL;

		LDAPDebug(LDAP_DEBUG_TRACE, "Doing step %d of bind for SASL/%s authentication\n",
                          stepnum, (mech ? mech : ""), 0 );
                stepnum++;

		/* notify server of a sasl bind step */
		rc = ldap_sasl_bind_s(ld, dn, mech, &ccred,
				      sctrl, cctrl, &scred);

		if ( ccred.bv_val != NULL ) {
			ccred.bv_val = NULL;
		}

		if ( rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS ) {
			ber_bvfree( scred );
			return( rc );
		}

		if( rc == LDAP_SUCCESS && saslrc == SASL_OK ) {
			/* we're done, no need to step */
			if( scred ) {
			    if (scred->bv_len  == 0 ) { /* MS AD sends back empty screds */
				LDAPDebug(LDAP_DEBUG_ANY,
					  "SASL BIND complete - ignoring empty credential response\n",
					  0, 0, 0);
				ber_bvfree( scred );
			    } else {
				/* but server provided us with data! */
				LDAPDebug(LDAP_DEBUG_TRACE,
					  "SASL BIND complete but invalid because server responded with credentials - length [%u]\n",
					  scred->bv_len, 0, 0);
				ber_bvfree( scred );
				LDAP_SET_LDERRNO( ld, LDAP_LOCAL_ERROR,
				    NULL, nsldapi_strdup( dgettext(TEXT_DOMAIN,
				    "Error during SASL handshake - "
				    "invalid server credential response") ));
				return( LDAP_LOCAL_ERROR );
			    }
			}
			break;
		}

		/* perform the next step of the sasl bind */
		do {
			LDAPDebug(LDAP_DEBUG_TRACE, "Doing client step %d of bind step %d for SASL/%s authentication\n",
				  clientstepnum, stepnum, (mech ? mech : "") );
			clientstepnum++;
			saslrc = sasl_client_step( ctx,
				(scred == NULL) ? NULL : scred->bv_val,
				(scred == NULL) ? 0 : scred->bv_len,
				&prompts,
				(const char **)&ccred.bv_val,
				&credlen );

			if( saslrc == SASL_INTERACT &&
			    (callback)(ld, flags, defaults, prompts)
							!= LDAP_SUCCESS ) {
				break;
			}
		} while ( saslrc == SASL_INTERACT );

		ccred.bv_len = credlen;
		ber_bvfree( scred );

		if ( (saslrc != SASL_OK) && (saslrc != SASL_CONTINUE) ) {
			return( nsldapi_sasl_cvterrno( ld, saslrc, nsldapi_strdup( sasl_errdetail( ctx ) ) ) );
		}
	} while ( rc == LDAP_SASL_BIND_IN_PROGRESS );

	if ( rc != LDAP_SUCCESS ) {
		return( rc );
	}

	if ( saslrc != SASL_OK ) {
		return( nsldapi_sasl_cvterrno( ld, saslrc, nsldapi_strdup( sasl_errdetail( ctx ) ) ) );
	}

	saslrc = sasl_getprop( ctx, SASL_USERNAME, (const void **) &sasl_username );
	if ( (saslrc == SASL_OK) && sasl_username ) {
		LDAPDebug(LDAP_DEBUG_TRACE, "SASL identity: %s\n", sasl_username, 0, 0);
	}

	saslrc = sasl_getprop( ctx, SASL_SSF, (const void **) &ssf );
	if( saslrc == SASL_OK ) {
		if( ssf && *ssf ) {
			LDAPDebug(LDAP_DEBUG_TRACE,
				"SASL install encryption, for SSF: %lu\n",
				(unsigned long) *ssf, 0, 0 );
		}
		rc = nsldapi_sasl_install(ld, ld->ld_conns->lconn_sb, ctx, ssf);
	}

	return( rc );
}

#ifdef LDAP_SASLIO_GET_MECHS_FROM_SERVER
/*
 * Get available SASL Mechanisms supported by the server
 */

static int
nsldapi_get_sasl_mechs ( LDAP *ld, char **pmech )
{
	char *attr[] = { "supportedSASLMechanisms", NULL };
	char **values, **v, *mech, *m;
	LDAPMessage *res, *e;
	struct timeval	timeout;
	int slen, rc;

	if ( !NSLDAPI_VALID_LDAP_POINTER( ld )) {
		return( LDAP_PARAM_ERROR );
	}

	timeout.tv_sec = SEARCH_TIMEOUT_SECS;
	timeout.tv_usec = 0;

	rc = ldap_search_st( ld, "", LDAP_SCOPE_BASE,
		"objectclass=*", attr, 0, &timeout, &res );

	if ( rc != LDAP_SUCCESS ) {
		return( LDAP_GET_LDERRNO( ld, NULL, NULL ) );
	}
		
	e = ldap_first_entry( ld, res );
	if ( e == NULL ) {
		ldap_msgfree( res );
		if ( ld->ld_errno == LDAP_SUCCESS ) {
			LDAP_SET_LDERRNO( ld, LDAP_NO_SUCH_OBJECT, NULL, NULL );
		}
		return( LDAP_GET_LDERRNO( ld, NULL, NULL ) );
	}

	values = ldap_get_values( ld, e, "supportedSASLMechanisms" );
	if ( values == NULL ) {
		ldap_msgfree( res );
		LDAP_SET_LDERRNO( ld, LDAP_NO_SUCH_ATTRIBUTE, NULL, NULL );
		return( LDAP_NO_SUCH_ATTRIBUTE );
	}

	slen = 0;
	for(v = values; *v != NULL; v++ ) {
		slen += strlen(*v) + 1;
	}
	if ( (mech = NSLDAPI_CALLOC(1, slen)) == NULL) {
		ldap_value_free( values );
		ldap_msgfree( res );
		LDAP_SET_LDERRNO( ld, LDAP_NO_MEMORY, NULL, NULL );
		return( LDAP_NO_MEMORY );
	} 
	m = mech;
	for(v = values; *v; v++) {
		if (v != values) {
			*m++ = ' ';
		}
		slen = strlen(*v);
		strncpy(m, *v, slen);
		m += slen;
	}
	*m = '\0';

	ldap_value_free( values );
	ldap_msgfree( res );

	*pmech = mech;

	return( LDAP_SUCCESS );
}
#endif

int nsldapi_sasl_secprops(
	const char *in,
	sasl_security_properties_t *secprops )
{
	int i;
	char **props = NULL;
	char *inp;
	unsigned sflags = 0;
	sasl_ssf_t max_ssf = 0;
	sasl_ssf_t min_ssf = 0;
	unsigned maxbufsize = 0;
	int got_sflags = 0;
	int got_max_ssf = 0;
	int got_min_ssf = 0;
	int got_maxbufsize = 0;

	if (in == NULL) {
		return LDAP_PARAM_ERROR;
	}
	inp = nsldapi_strdup(in);
	if (inp == NULL) {
		return LDAP_PARAM_ERROR;
	}
	props = ldap_str2charray( inp, "," );
	NSLDAPI_FREE( inp );
	
	if( props == NULL || secprops == NULL ) {
		return LDAP_PARAM_ERROR;
	}

	for( i=0; props[i]; i++ ) {
		if( strcasecmp(props[i], "none") == 0 ) {
			got_sflags++;

		} else if( strcasecmp(props[i], "noactive") == 0 ) {
			got_sflags++;
			sflags |= SASL_SEC_NOACTIVE;

		} else if( strcasecmp(props[i], "noanonymous") == 0 ) {
			got_sflags++;
			sflags |= SASL_SEC_NOANONYMOUS;

		} else if( strcasecmp(props[i], "nodict") == 0 ) {
			got_sflags++;
			sflags |= SASL_SEC_NODICTIONARY;

		} else if( strcasecmp(props[i], "noplain") == 0 ) {
			got_sflags++;
			sflags |= SASL_SEC_NOPLAINTEXT;

		} else if( strcasecmp(props[i], "forwardsec") == 0 ) {
			got_sflags++;
			sflags |= SASL_SEC_FORWARD_SECRECY;

		} else if( strcasecmp(props[i], "passcred") == 0 ) {
			got_sflags++;
			sflags |= SASL_SEC_PASS_CREDENTIALS;

		} else if( strncasecmp(props[i],
			"minssf=", sizeof("minssf")) == 0 ) {
			if( isdigit( props[i][sizeof("minssf")] ) ) {
				got_min_ssf++;
				min_ssf = atoi( &props[i][sizeof("minssf")] );
			} else {
				return LDAP_NOT_SUPPORTED;
			}

		} else if( strncasecmp(props[i],
			"maxssf=", sizeof("maxssf")) == 0 ) {
			if( isdigit( props[i][sizeof("maxssf")] ) ) {
				got_max_ssf++;
				max_ssf = atoi( &props[i][sizeof("maxssf")] );
			} else {
				return LDAP_NOT_SUPPORTED;
			}

		} else if( strncasecmp(props[i],
			"maxbufsize=", sizeof("maxbufsize")) == 0 ) {
			if( isdigit( props[i][sizeof("maxbufsize")] ) ) {
				got_maxbufsize++;
				maxbufsize = atoi( &props[i][sizeof("maxbufsize")] );
				if( maxbufsize &&
				    (( maxbufsize < SASL_MIN_BUFF_SIZE )
				    || (maxbufsize > SASL_MAX_BUFF_SIZE ))) {
					return( LDAP_PARAM_ERROR );
				}
			} else {
				return( LDAP_NOT_SUPPORTED );
			}
		} else {
			return( LDAP_NOT_SUPPORTED );
		}
	}

	if(got_sflags) {
		secprops->security_flags = sflags;
	}
	if(got_min_ssf) {
		secprops->min_ssf = min_ssf;
	}
	if(got_max_ssf) {
		secprops->max_ssf = max_ssf;
	}
	if(got_maxbufsize) {
		secprops->maxbufsize = maxbufsize;
	}

	ldap_charray_free( props );
	return( LDAP_SUCCESS );
}

/*
 * SASL Authentication Interface: ldap_sasl_interactive_bind_s
 *
 * This routine takes a DN, SASL mech list, and a SASL callback
 * and performs the necessary sequencing to complete a SASL bind
 * to the LDAP connection ld.  The user provided callback can
 * use an optionally provided set of default values to complete
 * any necessary interactions.
 *
 * Currently inpose the following restrictions:
 *   A mech list must be provided, only LDAP_SASL_INTERACTIVE
 *   mode is supported
 */
int
LDAP_CALL
ldap_sasl_interactive_bind_s( LDAP *ld, const char *dn,
	const char *saslMechanism,
	LDAPControl **sctrl, LDAPControl **cctrl, unsigned flags,
	LDAP_SASL_INTERACT_PROC *callback, void *defaults )
{
#ifdef LDAP_SASLIO_GET_MECHS_FROM_SERVER
	char *smechs;
#endif
	int rc;

	LDAPDebug(LDAP_DEBUG_TRACE, "ldap_sasl_interactive_bind_s\n", 0, 0, 0);

	if ( !NSLDAPI_VALID_LDAP_POINTER( ld )) {
		return( LDAP_PARAM_ERROR );
	}

	if (flags != LDAP_SASL_INTERACTIVE || callback == NULL) {
		return( LDAP_PARAM_ERROR );
	}

	LDAP_MUTEX_LOCK(ld, LDAP_SASL_LOCK );

	if( saslMechanism == NULL || *saslMechanism == '\0' ) {
#ifdef LDAP_SASLIO_GET_MECHS_FROM_SERVER
		rc = nsldapi_get_sasl_mechs( ld, &smechs );
		if( rc != LDAP_SUCCESS ) {
			LDAP_MUTEX_UNLOCK(ld, LDAP_SASL_LOCK );
			return( rc );
		}
		saslMechanism = smechs;
#else
		LDAP_MUTEX_UNLOCK(ld, LDAP_SASL_LOCK );
		return( LDAP_PARAM_ERROR );
#endif
	}

	/* initialize SASL library */
	if ( nsldapi_sasl_init() < 0 ) {
	    return( LDAP_PARAM_ERROR );
	}

	rc = nsldapi_sasl_do_bind( ld, dn, saslMechanism,
			flags, callback, defaults, sctrl, cctrl);

	LDAP_MUTEX_UNLOCK(ld, LDAP_SASL_LOCK );
	return( rc );
}

#endif
#endif

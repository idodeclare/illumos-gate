/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* GSSAPI SASL plugin
 * Leif Johansson
 * Rob Siemborski (SASL v2 Conversion)
 * $Id: gssapi.c,v 1.75 2003/07/02 13:13:42 rjs3 Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#ifdef WIN32
#  include <winsock2.h>

#  ifndef R_OK
#    define R_OK 04
#  endif
/* we also need io.h for access() prototype */
#  include <io.h>
#else
#  include <sys/param.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif /* WIN32 */
#include <fcntl.h>
#include <stdio.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

/*****************************  Common Section  *****************************/

#ifndef _SUN_SDK_
static const char plugin_id[] = "$Id: gssapi.c,v 1.75 2003/07/02 13:13:42 rjs3 Exp $";
#endif /* !_SUN_SDK_ */

static const char * GSSAPI_BLANK_STRING = "";

#ifndef HAVE_GSS_C_NT_HOSTBASED_SERVICE
extern gss_OID gss_nt_service_name;
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif

#ifdef _SUN_SDK_
static int
get_oid(const sasl_utils_t *utils, gss_OID *oid);
#ifdef GSSAPI_PROTECT
DEFINE_STATIC_MUTEX(global_mutex);
#endif /* GSSAPI_PROTECT */
#endif /* _SUN_SDK_ */

#ifdef WANT_KERBEROS5_3DES
/* Check if CyberSafe flag is defined */
#ifdef CSF_GSS_C_DES3_FLAG
#define K5_MAX_SSF	112
#endif

/* Heimdal and MIT use the following */
#ifdef GSS_KRB5_CONF_C_QOP_DES3_KD
#define K5_MAX_SSF	112
#endif

#endif

#ifndef K5_MAX_SSF
/* All Kerberos implementations support DES */
#define K5_MAX_SSF	56
#endif

/* GSSAPI SASL Mechanism by Leif Johansson <leifj@matematik.su.se>
 * inspired by the kerberos mechanism and the gssapi_server and
 * gssapi_client from the heimdal distribution by Assar Westerlund
 * <assar@sics.se> and Johan Danielsson <joda@pdc.kth.se>. 
 * See the configure.in file for details on dependencies.
 *
 * Important contributions from Sam Hartman <hartmans@fundsxpress.com>.
 *
 * This code was tested with the following distributions of Kerberos:
 * Heimdal (http://www.pdc.kth.se/heimdal), MIT (http://web.mit.edu/kerberos/www/)
 * CyberSafe (http://www.cybersafe.com/) and SEAM.
 */

#ifdef GSS_USE_MUTEXES
#define GSS_LOCK_MUTEX(utils)  \
    if(((sasl_utils_t *)(utils))->mutex_lock(gss_mutex) != 0) { \
       return SASL_FAIL; \
    }

#define GSS_UNLOCK_MUTEX(utils) \
    if(((sasl_utils_t *)(utils))->mutex_unlock(gss_mutex) != 0) { \
        return SASL_FAIL; \
    }

static void *gss_mutex = NULL;
#else
#define GSS_LOCK_MUTEX(utils)
#define GSS_UNLOCK_MUTEX(utils)
#endif

typedef struct context {
    int state;
    
    gss_ctx_id_t gss_ctx;
    gss_name_t   client_name;
    gss_name_t   server_name;
    gss_cred_id_t server_creds;
    gss_cred_id_t client_creds;

    sasl_ssf_t limitssf, requiressf; /* application defined bounds, for the
					server */
#ifdef _SUN_SDK_
    gss_cred_id_t client_creds;
    gss_OID	mech_oid;
    int		use_authid;
#endif /* _SUN_SDK_ */
    const sasl_utils_t *utils;
    
    /* layers buffering */
    decode_context_t decode_context;
    
    char *encode_buf;                /* For encoding/decoding mem management */
    char *decode_buf;
    char *decode_once_buf;
    unsigned encode_buf_len;
    unsigned decode_buf_len;
    unsigned decode_once_buf_len;
    buffer_info_t *enc_in_buf;
    
    char *out_buf;                   /* per-step mem management */
    unsigned out_buf_len;    
    
    char *authid; /* hold the authid between steps - server */
    const char *user;   /* hold the userid between steps - client */
#ifdef _SUN_SDK_
    const char *client_authid;
#endif /* _SUN_SDK_ */
#ifdef _INTEGRATED_SOLARIS_
    void *h;
#endif /* _INTEGRATED_SOLARIS_ */
} context_t;

enum {
    SASL_GSSAPI_STATE_AUTHNEG = 1,
    SASL_GSSAPI_STATE_SSFCAP = 2,
    SASL_GSSAPI_STATE_SSFREQ = 3,
    SASL_GSSAPI_STATE_AUTHENTICATED = 4
};

#ifdef _SUN_SDK_
/* sasl_gss_log only logs gss_display_status() error string */
#define sasl_gss_log(x,y,z) sasl_gss_seterror_(text,y,z,1)
#define sasl_gss_seterror(x,y,z) sasl_gss_seterror_(text,y,z,0)

static void
sasl_gss_seterror_(const context_t *text, OM_uint32 maj, OM_uint32 min, 
	int logonly)
#else
/* sasl_gss_log: only logs status string returned from gss_display_status() */
#define sasl_gss_log(x,y,z) sasl_gss_seterror_(x,y,z,1)
#define sasl_gss_seterror(x,y,z) sasl_gss_seterror_(x,y,z,0)

static int
sasl_gss_seterror_(const sasl_utils_t *utils, OM_uint32 maj, OM_uint32 min,
		   int logonly)
#endif /* _SUN_SDK_ */
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;
    int ret;
    char *out = NULL;
#ifdef _SUN_SDK_
    unsigned len, curlen = 0;
    const sasl_utils_t *utils = text->utils;
    char *prefix = dgettext(TEXT_DOMAIN, "GSSAPI Error: ");
#else
    size_t len, curlen = 0;
    const char prefix[] = "GSSAPI Error: ";
#endif /* _SUN_SDK_ */
    
    len = sizeof(prefix);
    ret = _plug_buf_alloc(utils, &out, &curlen, 256);
#ifdef _INTEGRATED_SOLARIS_
    if(ret != SASL_OK) return SASL_NOMEM;
#else
    if(ret != SASL_OK) return SASL_OK;
#endif /* _INTEGRATED_SOLARIS_ */
    
    strcpy(out, prefix);
    
    msg_ctx = 0;
    while (1) {
	GSS_LOCK_MUTEX(utils);
	maj_stat = gss_display_status(&min_stat, maj,
#ifdef _SUN_SDK_
				      GSS_C_GSS_CODE, text->mech_oid,
#else
				      GSS_C_GSS_CODE, GSS_C_NULL_OID,
#endif /* _SUN_SDK_ */
				      &msg_ctx, &msg);
	GSS_UNLOCK_MUTEX(utils);
	
	if(GSS_ERROR(maj_stat)) {
	    if (logonly) {
		utils->log(utils->conn, SASL_LOG_FAIL,
			"GSSAPI Failure: (could not get major error message)");
	    } else {
		utils->seterror(utils->conn, 0,
				"GSSAPI Failure "
				"(could not get major error message)");
	    }
	    utils->free(out);
	    return SASL_OK;
	}
	
	len += len + msg.length;
	ret = _plug_buf_alloc(utils, &out, &curlen, len);
	
	if(ret != SASL_OK) {
	    utils->free(out);
#ifdef _INTEGRATED_SOLARIS_
	    return SASL_NOMEM;
#else
	    return SASL_OK;
#endif /* _INTEGRATED_SOLARIS_ */
	}
	
	strcat(out, msg.value);
	
	GSS_LOCK_MUTEX(utils);
 	gss_release_buffer(&min_stat, &msg);
	GSS_UNLOCK_MUTEX(utils);
	
	if (!msg_ctx)
	    break;
    }
    
    /* Now get the minor status */
    
    len += 2;
    ret = _plug_buf_alloc(utils, &out, &curlen, len);
    if(ret != SASL_OK) {
	utils->free(out);
	return SASL_NOMEM;
    }
    
    strcat(out, " (");
    
    msg_ctx = 0;
    while (1) {
	GSS_LOCK_MUTEX(utils);
	maj_stat = gss_display_status(&min_stat, min,
#ifdef _SUN_SDK_
				      GSS_C_MECH_CODE, text->mech_oid,
#else
				      GSS_C_MECH_CODE, GSS_C_NULL_OID,
#endif /* _SUN_SDK_ */
				      &msg_ctx, &msg);
	GSS_UNLOCK_MUTEX(utils);
	
	if(GSS_ERROR(maj_stat)) {
	    if (logonly) {
		utils->log(utils->conn, SASL_LOG_FAIL,
			"GSSAPI Failure: (could not get minor error message)");
	    } else {
		utils->seterror(utils->conn, 0,
				"GSSAPI Failure "
				"(could not get minor error message)");
	    }
	    utils->free(out);
	    return SASL_OK;
	}
	
	len += len + msg.length;
	ret = _plug_buf_alloc(utils, &out, &curlen, len);	
	if(ret != SASL_OK) {
	    utils->free(out);
	    return SASL_NOMEM;
	}
	
	strcat(out, msg.value);
	
	GSS_LOCK_MUTEX(utils);
 	gss_release_buffer(&min_stat, &msg);
	GSS_UNLOCK_MUTEX(utils);
	
	if (!msg_ctx)
	    break;
    }
    
    len += 1;
    ret = _plug_buf_alloc(utils, &out, &curlen, len);
    if(ret != SASL_OK) {
	utils->free(out);
	return SASL_NOMEM;
    }
    
    strcat(out, ")");
    
    if (logonly) {
	utils->log(utils->conn, SASL_LOG_FAIL, out);
    } else {
	utils->seterror(utils->conn, 0, out);
    }
    utils->free(out);

    return SASL_OK;
}

static int 
sasl_gss_encode(void *context, const struct iovec *invec, unsigned numiov,
		const char **output, unsigned *outputlen, int privacy)
{
    context_t *text = (context_t *)context;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    int ret;
    struct buffer_info *inblob, bufinfo;
    
    if(!output) return SASL_BADPARAM;
    
    if(numiov > 1) {
	ret = _plug_iovec_to_buf(text->utils, invec, numiov, &text->enc_in_buf);
	if(ret != SASL_OK) return ret;
	inblob = text->enc_in_buf;
    } else {
	bufinfo.data = invec[0].iov_base;
	bufinfo.curlen = invec[0].iov_len;
	inblob = &bufinfo;
    }
    
    if (text->state != SASL_GSSAPI_STATE_AUTHENTICATED) return SASL_NOTDONE;
    
    input_token = &real_input_token;
    
    real_input_token.value  = inblob->data;
    real_input_token.length = inblob->curlen;
    
    output_token = &real_output_token;
    output_token->value = NULL;
    output_token->length = 0;
    
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    GSS_LOCK_MUTEX(text->utils);
    maj_stat = gss_wrap (&min_stat,
			 text->gss_ctx,
			 privacy,
			 GSS_C_QOP_DEFAULT,
			 input_token,
			 NULL,
			 output_token);
    GSS_UNLOCK_MUTEX(text->utils);
    
    if (GSS_ERROR(maj_stat))
	{
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    if (output_token->value) {
		GSS_LOCK_MUTEX(text->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(text->utils);
	    }
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
	    return SASL_FAIL;
	}
    
    if (output_token->value && output) {
	int len;
	
	ret = _plug_buf_alloc(text->utils, &(text->encode_buf),
			      &(text->encode_buf_len), output_token->length + 4);
	
	if (ret != SASL_OK) {
	    GSS_LOCK_MUTEX(text->utils);
 	    gss_release_buffer(&min_stat, output_token);
	    GSS_UNLOCK_MUTEX(text->utils);
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
	    return ret;
	}
	
	len = htonl(output_token->length);
	memcpy(text->encode_buf, &len, 4);
	memcpy(text->encode_buf + 4, output_token->value, output_token->length);
    }
    
    if (outputlen) {
	*outputlen = output_token->length + 4;
    }
    
    *output = text->encode_buf;
    
    if (output_token->value) {
	GSS_LOCK_MUTEX(text->utils);
 	gss_release_buffer(&min_stat, output_token);
	GSS_UNLOCK_MUTEX(text->utils);
    } 
    
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */

    return SASL_OK;
}

static int gssapi_privacy_encode(void *context, const struct iovec *invec,
				 unsigned numiov, const char **output,
				 unsigned *outputlen)
{
    return sasl_gss_encode(context,invec,numiov,output,outputlen,1);
}

static int gssapi_integrity_encode(void *context, const struct iovec *invec,
				   unsigned numiov, const char **output,
				   unsigned *outputlen) 
{
    return sasl_gss_encode(context,invec,numiov,output,outputlen,0);
}

static int gssapi_decode_packet(void *context,
				const char *input, unsigned inputlen,
				char **output, unsigned *outputlen)
{
    context_t *text = (context_t *) context;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    int result;
    
    if (text->state != SASL_GSSAPI_STATE_AUTHENTICATED) {
#ifdef _INTEGRATED_SOLARIS_
	SETERROR(text->utils, gettext("GSSAPI Failure"));
#else
	SETERROR(text->utils, "GSSAPI Failure");
#endif /* _INTEGRATED_SOLARIS_ */
	return SASL_NOTDONE;
    }
    
    input_token = &real_input_token; 
    real_input_token.value = (char *) text->buffer;
    real_input_token.length = inputlen;
    
    output_token = &real_output_token;
    output_token->value = NULL;
    output_token->length = 0;
    
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */

    GSS_LOCK_MUTEX(text->utils);
    maj_stat = gss_unwrap (&min_stat,
			   text->gss_ctx,
			   input_token,
			   output_token,
			   NULL,
			   NULL);
    GSS_UNLOCK_MUTEX(text->utils);
    
    if (GSS_ERROR(maj_stat))
	{
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    if (output_token->value) {
		GSS_LOCK_MUTEX(text->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(text->utils);
	    }
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
	    return SASL_FAIL;
	}
    
    if (outputlen)
	*outputlen = output_token->length;
    
    if (output_token->value) {
	if (output) {
	    result = _plug_buf_alloc(text->utils, &text->decode_once_buf,
				     &text->decode_once_buf_len,
				     *outputlen);
	    if(result != SASL_OK) {
		GSS_LOCK_MUTEX(text->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(text->utils);
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
		return result;
	    }
	    *output = text->decode_once_buf;
	    memcpy(*output, output_token->value, *outputlen);
	}
	GSS_LOCK_MUTEX(text->utils);
 	gss_release_buffer(&min_stat, output_token);
	GSS_UNLOCK_MUTEX(text->utils);
    }
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    
    return SASL_OK;
}

static int gssapi_decode(void *context,
			 const char *input, unsigned inputlen,
			 const char **output, unsigned *outputlen)
{
    context_t *text = (context_t *) context;
    int ret;
    
    ret = _plug_decode(&text->decode_context, input, inputlen,
		       &text->decode_buf, &text->decode_buf_len, outputlen,
		       gssapi_decode_packet, text);
    
    *output = text->decode_buf;
    
    return ret;
}

static context_t *sasl_gss_new_context(const sasl_utils_t *utils)
{
    context_t *ret;
    
    ret = utils->malloc(sizeof(context_t));
    if(!ret) return NULL;
    
    memset(ret,0,sizeof(context_t));
    ret->utils = utils;
#ifdef _SUN_SDK_
    ret->gss_ctx = GSS_C_NO_CONTEXT;
    ret->client_name = GSS_C_NO_NAME;
    ret->server_name = GSS_C_NO_NAME;
    ret->server_creds = GSS_C_NO_CREDENTIAL;
    ret->client_creds = GSS_C_NO_CREDENTIAL;
    if (get_oid(utils, &ret->mech_oid) != SASL_OK) {
	utils->free(ret);
	return (NULL);
    }
#endif /* _SUN_SDK_ */
    
    return ret;
}

static int sasl_gss_free_context_contents(context_t *text)
{
    OM_uint32 maj_stat, min_stat;
    
    if (!text) return SASL_OK;
    
    GSS_LOCK_MUTEX(text->utils);

    if (text->gss_ctx != GSS_C_NO_CONTEXT) {
	maj_stat = gss_delete_sec_context(&min_stat,&text->gss_ctx,
					  GSS_C_NO_BUFFER);
	text->gss_ctx = GSS_C_NO_CONTEXT;
    }
    
    if (text->client_name != GSS_C_NO_NAME) {
	maj_stat = gss_release_name(&min_stat,&text->client_name);
	text->client_name = GSS_C_NO_NAME;
    }
    
    if (text->server_name != GSS_C_NO_NAME) {
	maj_stat = gss_release_name(&min_stat,&text->server_name);
	text->server_name = GSS_C_NO_NAME;
    }
    
    if ( text->server_creds != GSS_C_NO_CREDENTIAL) {
	maj_stat = gss_release_cred(&min_stat, &text->server_creds);
	text->server_creds = GSS_C_NO_CREDENTIAL;
    }

    if ( text->client_creds != GSS_C_NO_CREDENTIAL) {
	maj_stat = gss_release_cred(&min_stat, &text->client_creds);
	text->client_creds = GSS_C_NO_CREDENTIAL;
    }

    GSS_UNLOCK_MUTEX(text->utils);

#ifdef _SUN_SDK_
    /*
     * Note that the oid returned by rpc_gss_mech_to_oid should not
     * be released
     */
#endif /* _SUN_SDK_ */
    
    if (text->out_buf) {
	text->utils->free(text->out_buf);
	text->out_buf = NULL;
    }
    
    if (text->encode_buf) {
	text->utils->free(text->encode_buf);
	text->encode_buf = NULL;
    }
    
    if (text->decode_buf) {
	text->utils->free(text->decode_buf);
	text->decode_buf = NULL;
    }
    
    if (text->decode_once_buf) {
	text->utils->free(text->decode_once_buf);
	text->decode_once_buf = NULL;
    }
    
    if (text->enc_in_buf) {
	if(text->enc_in_buf->data) text->utils->free(text->enc_in_buf->data);
	text->utils->free(text->enc_in_buf);
	text->enc_in_buf = NULL;
    }

    _plug_decode_free(&text->decode_context);
    
    if (text->authid) { /* works for both client and server */
	text->utils->free(text->authid);
	text->authid = NULL;
    }

    return SASL_OK;
}

#ifdef _SUN_SDK_

#ifdef HAVE_RPC_GSS_MECH_TO_OID
#include <rpc/rpcsec_gss.h>
#endif /* HAVE_RPC_GSS_MECH_TO_OID */

static int
get_oid(const sasl_utils_t *utils, gss_OID *oid)
{
#ifdef HAVE_RPC_GSS_MECH_TO_OID
    static gss_OID_desc kerb_v5 =
	{9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};
	/* 1.2.840.113554.1.2.2 */
    *oid = &kerb_v5;
#endif /* HAVE_RPC_GSS_MECH_TO_OID */
    return (SASL_OK);
}

static int
add_mech_to_set(context_t *text, gss_OID_set *desired_mechs)
{
    OM_uint32 maj_stat, min_stat;

    maj_stat = gss_create_empty_oid_set(&min_stat, desired_mechs);

    if (GSS_ERROR(maj_stat)) {
	sasl_gss_seterror(text->utils, maj_stat, min_stat);
	sasl_gss_free_context_contents(text);
	return SASL_FAIL;
    }

    maj_stat = gss_add_oid_set_member(&min_stat, text->mech_oid, desired_mechs);
    if (GSS_ERROR(maj_stat)) {
	sasl_gss_seterror(text->utils, maj_stat, min_stat);
	sasl_gss_free_context_contents(text);
	(void) gss_release_oid_set(&min_stat, desired_mechs);
	return SASL_FAIL;
    }
    return SASL_OK;
}
#endif /* _SUN_SDK_ */

static void gssapi_common_mech_dispose(void *conn_context,
				       const sasl_utils_t *utils)
{
#ifdef _SUN_SDK_
    if (conn_context == NULL)
	return;
#ifdef _INTEGRATED_SOLARIS_
    convert_prompt(utils, &((context_t *)conn_context)->h, NULL);
#endif /* _INTEGRATED_SOLARIS_ */
#endif /* _SUN_SDK_ */
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    (void) LOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    sasl_gss_free_context_contents((context_t *)(conn_context));
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    utils->free(conn_context);
}

static void gssapi_common_mech_free(void *global_context __attribute__((unused)),
				    const sasl_utils_t *utils)
{
#ifdef GSS_USE_MUTEXES
    if (gss_mutex) {
      utils->mutex_free(gss_mutex);
      gss_mutex=NULL;
    }
#endif
}

/*****************************  Server Section  *****************************/

static int 
gssapi_server_mech_new(void *glob_context __attribute__((unused)), 
		       sasl_server_params_t *params,
		       const char *challenge __attribute__((unused)), 
		       unsigned challen __attribute__((unused)),
		       void **conn_context)
{
    context_t *text;
    
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    text = sasl_gss_new_context(params->utils);
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    if (text == NULL) {
#ifndef _SUN_SDK_
	MEMERROR(params->utils);
#endif /* !_SUN_SDK_ */
	return SASL_NOMEM;
    }
    
    text->gss_ctx = GSS_C_NO_CONTEXT;
    text->client_name = GSS_C_NO_NAME;
    text->server_name = GSS_C_NO_NAME;
    text->server_creds = GSS_C_NO_CREDENTIAL;
    text->client_creds = GSS_C_NO_CREDENTIAL;
    text->state = SASL_GSSAPI_STATE_AUTHNEG;
    
    *conn_context = text;
    
    return SASL_OK;
}

static int 
gssapi_server_mech_step(void *conn_context,
			sasl_server_params_t *params,
			const char *clientin,
			unsigned clientinlen,
			const char **serverout,
			unsigned *serveroutlen,
			sasl_out_params_t *oparams)
{
    context_t *text = (context_t *)conn_context;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    OM_uint32 maj_stat = 0, min_stat = 0;
#ifdef _SUN_SDK_
    OM_uint32 max_input_size;
    gss_OID_set desired_mechs = GSS_C_NULL_OID_SET;
#else
    OM_uint32 max_input;
#endif /* _SUN_SDK_ */
    gss_buffer_desc name_token;
    int ret, out_flags = 0 ;
    
    input_token = &real_input_token;
    output_token = &real_output_token;
    output_token->value = NULL; output_token->length = 0;
    input_token->value = NULL; input_token->length = 0;
    
    if(!serverout) {
	PARAMERROR(text->utils);
	return SASL_BADPARAM;
    }
    
    *serverout = NULL;
    *serveroutlen = 0;	
	    
    switch (text->state) {

    case SASL_GSSAPI_STATE_AUTHNEG:
	if (text->server_name == GSS_C_NO_NAME) { /* only once */
	    name_token.length = strlen(params->service) + 1 + strlen(params->serverFQDN);
	    name_token.value = (char *)params->utils->malloc((name_token.length + 1) * sizeof(char));
	    if (name_token.value == NULL) {
		MEMERROR(text->utils);
		sasl_gss_free_context_contents(text);
		return SASL_NOMEM;
	    }
#ifdef _SUN_SDK_
	    snprintf(name_token.value, name_token.length + 1,
		"%s@%s", params->service, params->serverFQDN);
#else
	    sprintf(name_token.value,"%s@%s", params->service, params->serverFQDN);
#endif /* _SUN_SDK_ */
	    
	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_import_name (&min_stat,
					&name_token,
					GSS_C_NT_HOSTBASED_SERVICE,
					&text->server_name);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    params->utils->free(name_token.value);
	    name_token.value = NULL;
	    
	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }
	    
	    if ( text->server_creds != GSS_C_NO_CREDENTIAL) {
	    	GSS_LOCK_MUTEX(params->utils);
		maj_stat = gss_release_cred(&min_stat, &text->server_creds);
	    	GSS_UNLOCK_MUTEX(params->utils);
		text->server_creds = GSS_C_NO_CREDENTIAL;
	    }
	    
#ifdef _SUN_SDK_
	    if (text->mech_oid != GSS_C_NULL_OID) {
		ret = add_mech_to_set(text, &desired_mechs);
		if (ret != SASL_OK)
		    return (ret);
	    }
#endif /* _SUN_SDK_ */

	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_acquire_cred(&min_stat, 
					text->server_name,
					GSS_C_INDEFINITE, 
#ifdef _SUN_SDK_
					desired_mechs,
#else
					GSS_C_NO_OID_SET,
#endif /* _SUN_SDK_ */
					GSS_C_ACCEPT,
					&text->server_creds, 
					NULL, 
					NULL);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
#ifdef _SUN_SDK_
	    if (desired_mechs != GSS_C_NULL_OID_SET) {
		OM_uint32 min_stat2;
		(void) gss_release_oid_set(&min_stat2, &desired_mechs);
	    }
#endif /* _SUN_SDK_ */

	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }
	}
	
	if (clientinlen) {
	    real_input_token.value = (void *)clientin;
	    real_input_token.length = clientinlen;
	}
	
	GSS_LOCK_MUTEX(params->utils);
	maj_stat =
	    gss_accept_sec_context(&min_stat,
				   &(text->gss_ctx),
				   text->server_creds,
				   input_token,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   &text->client_name,
				   NULL,	/* resulting mech_name */
				   output_token,
				   &out_flags,
				   NULL,	/* context validity period */
				   &(text->client_creds));
	GSS_UNLOCK_MUTEX(params->utils);
	
	if (GSS_ERROR(maj_stat)) {
#ifdef _SUN_SDK_
	    /* log the local error info, set a more generic error */
	    sasl_gss_log(text->utils, maj_stat, min_stat);
	    text->utils->seterror(text->utils->conn, SASL_NOLOG, 
		    gettext("GSSAPI Failure: accept security context error"));
#else
	    sasl_gss_log(text->utils, maj_stat, min_stat);
	    text->utils->seterror(text->utils->conn, SASL_NOLOG, "GSSAPI Failure: gss_accept_sec_context");
#endif /* _SUN_SDK_ */
	    if (output_token->value) {
		GSS_LOCK_MUTEX(params->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
	    }
	    sasl_gss_free_context_contents(text);
	    return SASL_BADAUTH;
	}
	    

	if ((params->props.security_flags & SASL_SEC_PASS_CREDENTIALS) &&
	    (!(out_flags & GSS_C_DELEG_FLAG) ||
	     text->client_creds == GSS_C_NO_CREDENTIAL) )
	{
#ifdef _SUN_SDK_
	    text->utils->seterror(text->utils->conn, SASL_LOG_WARN,
	      gettext("GSSAPI warning: no credentials were passed"));
#else
	    text->utils->seterror(text->utils->conn, SASL_LOG_WARN,
				  "GSSAPI warning: no credentials were passed");
#endif
	    /* continue with authentication */
	}

	if (serveroutlen)
	    *serveroutlen = output_token->length;
	if (output_token->value) {
	    if (serverout) {
		ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				      &(text->out_buf_len), *serveroutlen);
		if(ret != SASL_OK) {
		    GSS_LOCK_MUTEX(params->utils);
 		    gss_release_buffer(&min_stat, output_token);
		    GSS_UNLOCK_MUTEX(params->utils);
		    return ret;
		}
		memcpy(text->out_buf, output_token->value, *serveroutlen);
		*serverout = text->out_buf;
	    }
	    
	    GSS_LOCK_MUTEX(params->utils);
 	    gss_release_buffer(&min_stat, output_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	} else {
	    /* No output token, send an empty string */
	    *serverout = GSSAPI_BLANK_STRING;
#ifndef _SUN_SDK_
	    serveroutlen = 0;
#endif /* !_SUN_SDK_ */
	}
	
	
	if (maj_stat == GSS_S_COMPLETE) {
	    /* Switch to ssf negotiation */
	    text->state = SASL_GSSAPI_STATE_SSFCAP;
	}
	
	return SASL_CONTINUE;

    case SASL_GSSAPI_STATE_SSFCAP: {
	unsigned char sasldata[4];
	gss_buffer_desc name_token;
#ifndef _SUN_SDK_
	gss_buffer_desc name_without_realm;
	gss_name_t without = NULL;
	int equal;
#endif /* !_SUN_SDK_ */
	
	name_token.value = NULL;
#ifndef _SUN_SDK_
	name_without_realm.value = NULL;
#endif /* !_SUN_SDK_ */
	
	/* We ignore whatever the client sent us at this stage */
	
	GSS_LOCK_MUTEX(params->utils);
	maj_stat = gss_display_name (&min_stat,
				     text->client_name,
				     &name_token,
				     NULL);
	GSS_UNLOCK_MUTEX(params->utils);
	
	if (GSS_ERROR(maj_stat)) {
#ifdef _INTEGRATED_SOLARIS_
	    SETERROR(text->utils, gettext("GSSAPI Failure"));
#else
	    SETERROR(text->utils, "GSSAPI Failure");
#endif /* _INTEGRATED_SOLARIS_ */
	    sasl_gss_free_context_contents(text);
	    return SASL_BADAUTH;
	}
	
#ifndef _SUN_SDK_
	/* If the id contains a realm get the identifier for the user
	   without the realm and see if it's the same id (i.e. 
	   tmartin == tmartin@ANDREW.CMU.EDU. If this is the case we just want
	   to return the id (i.e. just "tmartin" */
	if (strchr((char *) name_token.value, (int) '@') != NULL) {
	    /* NOTE: libc malloc, as it is freed below by a gssapi internal
	     *       function! */
	    name_without_realm.value = params->utils->malloc(strlen(name_token.value)+1);
	    if (name_without_realm.value == NULL) {
		if (name_token.value) {
	    	    GSS_LOCK_MUTEX(params->utils);
		    gss_release_buffer(&min_stat, &name_token);
	    	    GSS_UNLOCK_MUTEX(params->utils);
		}
		MEMERROR(text->utils);
		return SASL_NOMEM;
	    }
	    
	    strcpy(name_without_realm.value, name_token.value);
	    
	    /* cut off string at '@' */
	    (strchr(name_without_realm.value,'@'))[0] = '\0';
	    
	    name_without_realm.length = strlen( (char *) name_without_realm.value );
	    
	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_import_name (&min_stat,
					&name_without_realm,
	    /* Solaris 8/9 gss_import_name doesn't accept GSS_C_NULL_OID here,
	       so use GSS_C_NT_USER_NAME instead if available.  */
#ifdef HAVE_GSS_C_NT_USER_NAME
					GSS_C_NT_USER_NAME,
#else
					GSS_C_NULL_OID,
#endif
					&without);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    if (GSS_ERROR(maj_stat)) {
		params->utils->free(name_without_realm.value);
		if (name_token.value) {
	    	    GSS_LOCK_MUTEX(params->utils);
		    gss_release_buffer(&min_stat, &name_token);
	    	    GSS_UNLOCK_MUTEX(params->utils);
		}
		SETERROR(text->utils, "GSSAPI Failure");
		sasl_gss_free_context_contents(text);
		return SASL_BADAUTH;
	    }
	    
	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_compare_name(&min_stat,
					text->client_name,
					without,
					&equal);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    if (GSS_ERROR(maj_stat)) {
		params->utils->free(name_without_realm.value);
		if (name_token.value) {
	    	    GSS_LOCK_MUTEX(params->utils);
		    gss_release_buffer(&min_stat, &name_token);
	    	    GSS_UNLOCK_MUTEX(params->utils);
		}
		if (without) {
	    	    GSS_LOCK_MUTEX(params->utils);
 		    gss_release_name(&min_stat, &without);
	    	    GSS_UNLOCK_MUTEX(params->utils);
		}
		SETERROR(text->utils, "GSSAPI Failure");
		sasl_gss_free_context_contents(text);
		return SASL_BADAUTH;
	    }
	    
	    GSS_LOCK_MUTEX(params->utils);
 	    gss_release_name(&min_stat,&without);
	    GSS_UNLOCK_MUTEX(params->utils);
	} else {
	    equal = 0;
	}
	
	if (equal) {
	    text->authid = strdup(name_without_realm.value);
	    
	    if (text->authid == NULL) {
		MEMERROR(params->utils);
		return SASL_NOMEM;
	    }
	} else {
	    text->authid = strdup(name_token.value);
	    
	    if (text->authid == NULL) {
		MEMERROR(params->utils);
		return SASL_NOMEM;
	    }
	}
#else
	{
	    ret = _plug_strdup(params->utils, name_token.value,
		&text->authid, NULL);
	}
#endif /* _SUN_SDK_ */
	
	if (name_token.value) {
	    GSS_LOCK_MUTEX(params->utils);
	    gss_release_buffer(&min_stat, &name_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	}

#ifdef _SUN_SDK_
	if (ret != SASL_OK)
	    return (ret);
#else
	if (name_without_realm.value) {
	    params->utils->free(name_without_realm.value);
	}	
#endif /* _SUN_SDK_ */
	
	
	/* we have to decide what sort of encryption/integrity/etc.,
	   we support */
	if (params->props.max_ssf < params->external_ssf) {
	    text->limitssf = 0;
	} else {
	    text->limitssf = params->props.max_ssf - params->external_ssf;
	}
	if (params->props.min_ssf < params->external_ssf) {
	    text->requiressf = 0;
	} else {
	    text->requiressf = params->props.min_ssf - params->external_ssf;
	}
	
	/* build up our security properties token */
        if (params->props.maxbufsize > 0xFFFFFF) {
            /* make sure maxbufsize isn't too large */
            /* maxbufsize = 0xFFFFFF */
            sasldata[1] = sasldata[2] = sasldata[3] = 0xFF;
        } else {
            sasldata[1] = (params->props.maxbufsize >> 16) & 0xFF;
            sasldata[2] = (params->props.maxbufsize >> 8) & 0xFF;
            sasldata[3] = (params->props.maxbufsize >> 0) & 0xFF;
        }
	sasldata[0] = 0;
	if(text->requiressf != 0 && !params->props.maxbufsize) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		"GSSAPI needs a security layer but one is forbidden");
#else
	    params->utils->seterror(params->utils->conn, 0,
				    "GSSAPI needs a security layer but one is forbidden");
#endif /* _SUN_SDK_ */
	    return SASL_TOOWEAK;
	}
	
	if (text->requiressf == 0) {
	    sasldata[0] |= 1; /* authentication */
	}
	if (text->requiressf <= 1 && text->limitssf >= 1
	    && params->props.maxbufsize) {
	    sasldata[0] |= 2;
	}
	if (text->requiressf <= K5_MAX_SSF && text->limitssf >= K5_MAX_SSF
	    && params->props.maxbufsize) {
	    sasldata[0] |= 4;
	}
	
	real_input_token.value = (void *)sasldata;
	real_input_token.length = 4;
	
	GSS_LOCK_MUTEX(params->utils);
	maj_stat = gss_wrap(&min_stat,
			    text->gss_ctx,
			    0, /* Just integrity checking here */
			    GSS_C_QOP_DEFAULT,
			    input_token,
			    NULL,
			    output_token);
	GSS_UNLOCK_MUTEX(params->utils);
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    if (output_token->value) {
		GSS_LOCK_MUTEX(params->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
	    }
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}
	
	
	if (serveroutlen)
	    *serveroutlen = output_token->length;
	if (output_token->value) {
	    if (serverout) {
		ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				      &(text->out_buf_len), *serveroutlen);
		if(ret != SASL_OK) {
		    GSS_LOCK_MUTEX(params->utils);
 		    gss_release_buffer(&min_stat, output_token);
		    GSS_UNLOCK_MUTEX(params->utils);
		    return ret;
		}
		memcpy(text->out_buf, output_token->value, *serveroutlen);
		*serverout = text->out_buf;
	    }
	    
	    GSS_LOCK_MUTEX(params->utils);
 	    gss_release_buffer(&min_stat, output_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	}
	
	/* Wait for ssf request and authid */
	text->state = SASL_GSSAPI_STATE_SSFREQ; 
	
	return SASL_CONTINUE;
    }

    case SASL_GSSAPI_STATE_SSFREQ: {
	int layerchoice;
	
	real_input_token.value = (void *)clientin;
	real_input_token.length = clientinlen;
	
	GSS_LOCK_MUTEX(params->utils);
	maj_stat = gss_unwrap(&min_stat,
			      text->gss_ctx,
			      input_token,
			      output_token,
			      NULL,
			      NULL);
	GSS_UNLOCK_MUTEX(params->utils);
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}
	
	layerchoice = (int)(((char *)(output_token->value))[0]);
	if (layerchoice == 1 && text->requiressf == 0) { /* no encryption */
	    oparams->encode = NULL;
	    oparams->decode = NULL;
	    oparams->mech_ssf = 0;
	} else if (layerchoice == 2 && text->requiressf <= 1 &&
		   text->limitssf >= 1) { /* integrity */
	    oparams->encode=&gssapi_integrity_encode;
	    oparams->decode=&gssapi_decode;
	    oparams->mech_ssf=1;
	} else if (layerchoice == 4 && text->requiressf <= K5_MAX_SSF &&
		   text->limitssf >= K5_MAX_SSF) { /* privacy */
	    oparams->encode = &gssapi_privacy_encode;
	    oparams->decode = &gssapi_decode;
	    /* FIX ME: Need to extract the proper value here */
	    oparams->mech_ssf = K5_MAX_SSF;
	} else {
	    /* not a supported encryption layer */
#ifdef _SUN_SDK_
	    text->utils->log(text->utils->conn, SASL_LOG_ERR,
		"protocol violation: client requested invalid layer");
#else
	    SETERROR(text->utils,
		     "protocol violation: client requested invalid layer");
#endif /* _SUN_SDK_ */
	    /* Mark that we attempted negotiation */
	    oparams->mech_ssf = 2;
	    if (output_token->value) {
		GSS_LOCK_MUTEX(params->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
	    }
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}
	
	if (output_token->length > 4) {
	    int ret;
	    
	    ret = params->canon_user(params->utils->conn,
				     ((char *) output_token->value) + 4,
				     (output_token->length - 4) * sizeof(char),
				     SASL_CU_AUTHZID, oparams);
	    
	    if (ret != SASL_OK) {
		sasl_gss_free_context_contents(text);
		return ret;
	    }
	    
	    ret = params->canon_user(params->utils->conn,
				     text->authid,
				     0, /* strlen(text->authid) */
				     SASL_CU_AUTHID, oparams);
	    if (ret != SASL_OK) {
		sasl_gss_free_context_contents(text);
		return ret;
	    }
	} else if(output_token->length == 4) {
	    /* null authzid */
	    int ret;
	    
	    ret = params->canon_user(params->utils->conn,
				     text->authid,
				     0, /* strlen(text->authid) */
				     SASL_CU_AUTHZID | SASL_CU_AUTHID,
				     oparams);
	    
	    if (ret != SASL_OK) {
		sasl_gss_free_context_contents(text);
		return ret;
	    }	    
	} else {
#ifdef _SUN_SDK_
	    text->utils->log(text->utils->conn, SASL_LOG_ERR,
	    		     "token too short");
#else
	    SETERROR(text->utils,
		     "token too short");
#endif /* _SUN_SDK_ */
	    GSS_LOCK_MUTEX(params->utils);
 	    gss_release_buffer(&min_stat, output_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}	
	
	/* No matter what, set the rest of the oparams */

	if (text->client_creds != GSS_C_NO_CREDENTIAL)	{
	    oparams->client_creds =  &text->client_creds;
	}
	else {
	    oparams->client_creds = NULL;
	}

        oparams->maxoutbuf =
	    (((unsigned char *) output_token->value)[1] << 16) |
            (((unsigned char *) output_token->value)[2] << 8) |
            (((unsigned char *) output_token->value)[3] << 0);

#ifdef _SUN_SDK_
	if (oparams->mech_ssf) {
	    oparams->maxoutbuf -= 4;	/* Allow for 4 byte tag */
	    maj_stat = gss_wrap_size_limit(&min_stat,
					text->gss_ctx,
					oparams->mech_ssf > 1,
					GSS_C_QOP_DEFAULT,
					oparams->maxoutbuf,
					&max_input_size);
	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		GSS_LOCK_MUTEX(params->utils);
		(void) gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
		sasl_gss_free_context_contents(text);
		return (SASL_FAIL);
	    }

	    /*
	     * gss_wrap_size_limit will return very big sizes for
	     * small input values
	     */
	    if (max_input_size < oparams->maxoutbuf)
 		oparams->maxoutbuf = max_input_size;
	    else {
		oparams->maxoutbuf = 0;
	    }
	}
#else
	if (oparams->mech_ssf) {
 	    maj_stat = gss_wrap_size_limit( &min_stat,
					    text->gss_ctx,
					    1,
					    GSS_C_QOP_DEFAULT,
					    (OM_uint32) oparams->maxoutbuf,
					    &max_input);

	    if(max_input > oparams->maxoutbuf) {
		/* Heimdal appears to get this wrong */
		oparams->maxoutbuf -= (max_input - oparams->maxoutbuf);
	    } else {
		/* This code is actually correct */
		oparams->maxoutbuf = max_input;
	    }
	}
#endif /* _SUN_SDK_ */
	
	GSS_LOCK_MUTEX(params->utils);
 	gss_release_buffer(&min_stat, output_token);
	GSS_UNLOCK_MUTEX(params->utils);
	
	text->state = SASL_GSSAPI_STATE_AUTHENTICATED;
	
	/* used by layers */
	_plug_decode_init(&text->decode_context, text->utils,
			  (params->props.maxbufsize > 0xFFFFFF) ? 0xFFFFFF :
			  params->props.maxbufsize);

	oparams->doneflag = 1;
	
	return SASL_OK;
    }
    
    default:
#ifdef _SUN_SDK_
	params->utils->log(text->utils->conn, SASL_LOG_ERR,
			   "Invalid GSSAPI server step %d", text->state);
#else
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid GSSAPI server step %d\n", text->state);
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }
    
#ifndef _SUN_SDK_
    return SASL_FAIL; /* should never get here */
#endif /* !_SUN_SDK_ */
}

#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
static int 
_gssapi_server_mech_step(void *conn_context,
			sasl_server_params_t *params,
			const char *clientin,
			unsigned clientinlen,
			const char **serverout,
			unsigned *serveroutlen,
			sasl_out_params_t *oparams)
{
    int ret;

    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);

    ret = gssapi_server_mech_step(conn_context, params, clientin, clientinlen,
	serverout, serveroutlen, oparams);

    UNLOCK_MUTEX(&global_mutex);
    return (ret);
}
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */

static sasl_server_plug_t gssapi_server_plugins[] = 
{
    {
	"GSSAPI",			/* mech_name */
	K5_MAX_SSF,			/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOACTIVE
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH		/* security_flags */
	| SASL_SEC_PASS_CREDENTIALS,
	SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY
	| SASL_FEAT_DONTUSE_USERPASSWD,	/* features */
	NULL,				/* glob_context */
	&gssapi_server_mech_new,	/* mech_new */
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	&_gssapi_server_mech_step,	/* mech_step */
#else
	&gssapi_server_mech_step,	/* mech_step */
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
	&gssapi_common_mech_dispose,	/* mech_dispose */
	&gssapi_common_mech_free,	/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech_avail */
	NULL				/* spare */
    }
};

int gssapiv2_server_plug_init(
#ifndef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
    const sasl_utils_t *utils __attribute__((unused)),
#else
    const sasl_utils_t *utils,
#endif 
    int maxversion,
    int *out_version,
    sasl_server_plug_t **pluglist,
    int *plugcount)
{
#ifdef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
    const char *keytab = NULL;
    char keytab_path[1024];
    unsigned int rl;
#endif
    
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	return SASL_BADVERS;
    }
    
#ifndef _SUN_SDK_
#ifdef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
    /* unfortunately, we don't check for readability of keytab if it's
       the standard one, since we don't know where it is */
    
    /* FIXME: This code is broken */
    
    utils->getopt(utils->getopt_context, "GSSAPI", "keytab", &keytab, &rl);
    if (keytab != NULL) {
	if (access(keytab, R_OK) != 0) {
	    utils->log(NULL, SASL_LOG_ERR,
		       "Could not find keytab file: %s: %m",
		       keytab, errno);
	    return SASL_FAIL;
	}
	
	if(strlen(keytab) > 1024) {
	    utils->log(NULL, SASL_LOG_ERR,
		       "path to keytab is > 1024 characters");
	    return SASL_BUFOVER;
	}
	
	strncpy(keytab_path, keytab, 1024);
	
	gsskrb5_register_acceptor_identity(keytab_path);
    }
#endif
#endif /* !_SUN_SDK_ */
    
#ifdef _INTEGRATED_SOLARIS_
    /*
     * Let libsasl know that we are a "Sun" plugin so that privacy
     * and integrity will be allowed.
     */
    REG_PLUG("GSSAPI", gssapi_server_plugins);
#endif /* _INTEGRATED_SOLARIS_ */

    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = gssapi_server_plugins;
    *plugcount = 1;  

#ifdef GSS_USE_MUTEXES
    if (!gss_mutex) {
       gss_mutex = utils->mutex_alloc();
       if (!gss_mutex) {
           return SASL_FAIL;
       }
    }
#endif
    
    return SASL_OK;
}

/*****************************  Client Section  *****************************/

static int gssapi_client_mech_new(void *glob_context __attribute__((unused)), 
				  sasl_client_params_t *params,
				  void **conn_context)
{
    context_t *text;
#ifdef _SUN_SDK_
    const char *use_authid = NULL;
#endif /* _SUN_SDK_ */
    
    /* holds state are in */
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    text = sasl_gss_new_context(params->utils);
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
    if (text == NULL) {
#ifndef _SUN_SDK_
	MEMERROR(params->utils);
#endif /* !_SUN_SDK_ */
	return SASL_NOMEM;
    }
    
    text->state = SASL_GSSAPI_STATE_AUTHNEG;
    text->gss_ctx = GSS_C_NO_CONTEXT;
    text->client_name = GSS_C_NO_NAME;
    text->server_creds = GSS_C_NO_CREDENTIAL;
    text->client_creds  = GSS_C_NO_CREDENTIAL;

#ifdef _SUN_SDK_
    params->utils->getopt(params->utils->getopt_context,
			  "GSSAPI", "use_authid", &use_authid, NULL);
    text->use_authid = (use_authid != NULL) &&
	(*use_authid == 'y' || *use_authid == 'Y' || *use_authid == '1');
#endif /* _SUN_SDK_ */
    
    *conn_context = text;
    
    return SASL_OK;
}

static int gssapi_client_mech_step(void *conn_context,
				   sasl_client_params_t *params,
				   const char *serverin,
				   unsigned serverinlen,
				   sasl_interact_t **prompt_need,
				   const char **clientout,
				   unsigned *clientoutlen,
				   sasl_out_params_t *oparams)
{
    context_t *text = (context_t *)conn_context;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    OM_uint32 maj_stat = 0, min_stat = 0;
#ifdef _SUN_SDK_
    OM_uint32 max_input_size;
#else
    OM_uint32 max_input;
#endif /* _SUN_SDK_ */
    gss_buffer_desc name_token;
    int ret;
    OM_uint32 req_flags = 0, out_req_flags = 0;
    input_token = &real_input_token;
    output_token = &real_output_token;
    output_token->value = NULL;
    input_token->value = NULL; 
    input_token->length = 0;
    
    *clientout = NULL;
    *clientoutlen = 0;
    
    switch (text->state) {

    case SASL_GSSAPI_STATE_AUTHNEG:
	/* try to get the userid */
#ifdef _SUN_SDK_
	if (text->user == NULL ||
		(text->use_authid && text->client_authid == NULL)) {
	    int auth_result = SASL_OK;
	    int user_result = SASL_OK;

	    if (text->use_authid && text->client_authid == NULL) {
		auth_result = _plug_get_authid(params->utils,
					       &text->client_authid,
					       prompt_need);
	
		if ((auth_result != SASL_OK) &&
			(auth_result != SASL_INTERACT)) {
		    sasl_gss_free_context_contents(text);
		    return auth_result;
		}
	    }
	    if (text->user == NULL) {
		user_result = _plug_get_userid(params->utils, &text->user,
					       prompt_need);
	    
		if ((user_result != SASL_OK) &&
			(user_result != SASL_INTERACT)) {
		    sasl_gss_free_context_contents(text);
		    return user_result;
		}
	    }
#else
	if (text->user == NULL) {
	    int user_result = SASL_OK;
	    
	    user_result = _plug_get_userid(params->utils, &text->user,
					   prompt_need);
	    
	    if ((user_result != SASL_OK) && (user_result != SASL_INTERACT)) {
		sasl_gss_free_context_contents(text);
		return user_result;
	    }
#endif /* _SUN_SDK_ */
		    
	    /* free prompts we got */
	    if (prompt_need && *prompt_need) {
		params->utils->free(*prompt_need);
		*prompt_need = NULL;
	    }
		    
	    /* if there are prompts not filled in */
#ifdef _SUN_SDK_
	    if ((user_result == SASL_INTERACT) ||
			(auth_result == SASL_INTERACT)) {
		/* make the prompt list */
#ifdef _INTEGRATED_SOLARIS_
		int result = _plug_make_prompts(params->utils, &text->h,
			   prompt_need,
			   user_result == SASL_INTERACT ?
			   convert_prompt(params->utils, &text->h,
			    gettext("Please enter your authorization name"))
				: NULL, NULL,
			   auth_result == SASL_INTERACT ?
			   convert_prompt(params->utils, &text->h,
			    gettext("Please enter your authentication name"))
				: NULL, NULL,
			   NULL, NULL,
			   NULL, NULL, NULL,
			   NULL, NULL, NULL);
#else
		int result = _plug_make_prompts(params->utils, prompt_need,
			   user_result == SASL_INTERACT ?
			   	"Please enter your authorization name"
				: NULL, NULL,
			   auth_result == SASL_INTERACT ?
			   	"Please enter your authentication name"
				: NULL, NULL,
			   NULL, NULL,
			   NULL, NULL, NULL,
			   NULL, NULL, NULL);
#endif /* _INTEGRATED_SOLARIS_ */
	
		if (result != SASL_OK) return result;

		return SASL_INTERACT;
	    }
#else
	    if (user_result == SASL_INTERACT) {
		/* make the prompt list */
		int result =
		    _plug_make_prompts(params->utils, prompt_need,
				       user_result == SASL_INTERACT ?
				       "Please enter your authorization name" : NULL, NULL,
				       NULL, NULL,
				       NULL, NULL,
				       NULL, NULL, NULL,
				       NULL, NULL, NULL);
		if (result != SASL_OK) return result;
		
		return SASL_INTERACT;
	    }
#endif /* _SUN_SDK_ */
	}
	    
	if (text->server_name == GSS_C_NO_NAME) { /* only once */
	    if (params->serverFQDN == NULL
		|| strlen(params->serverFQDN) == 0) {
#ifdef _SUN_SDK_
		text->utils->log(text->utils->conn, SASL_LOG_ERR,
				 "GSSAPI Failure: no serverFQDN");
#else
		SETERROR(text->utils, "GSSAPI Failure: no serverFQDN");
#endif /* _SUN_SDK_ */
		return SASL_FAIL;
	    }
	    name_token.length = strlen(params->service) + 1 + strlen(params->serverFQDN);
	    name_token.value = (char *)params->utils->malloc((name_token.length + 1) * sizeof(char));
	    if (name_token.value == NULL) {
		sasl_gss_free_context_contents(text);
		return SASL_NOMEM;
	    }
	    
#ifdef _SUN_SDK_
	    snprintf(name_token.value, name_token.length + 1,
		"%s@%s", params->service, params->serverFQDN);
#else
	    sprintf(name_token.value,"%s@%s", params->service, params->serverFQDN);
#endif /* _SUN_SDK_ */
	    
	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_import_name (&min_stat,
					&name_token,
					GSS_C_NT_HOSTBASED_SERVICE,
					&text->server_name);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    params->utils->free(name_token.value);
	    name_token.value = NULL;
	    
	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }
	}
	    
	if (serverinlen == 0)
	    input_token = GSS_C_NO_BUFFER;

	if (serverinlen) {
	    real_input_token.value = (void *)serverin;
	    real_input_token.length = serverinlen;
	}
	else if (text->gss_ctx != GSS_C_NO_CONTEXT ) {
	    /* This can't happen under GSSAPI: we have a non-null context
	     * and no input from the server.  However, thanks to Imap,
	     * which discards our first output, this happens all the time.
	     * Throw away the context and try again. */
	    GSS_LOCK_MUTEX(params->utils);
 	    maj_stat = gss_delete_sec_context (&min_stat,&text->gss_ctx,GSS_C_NO_BUFFER);
	    GSS_UNLOCK_MUTEX(params->utils);
	    text->gss_ctx = GSS_C_NO_CONTEXT;
	}
	    
	/* Setup req_flags properly */
	req_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
	if(params->props.max_ssf > params->external_ssf) {
	    /* We are requesting a security layer */
	    req_flags |= GSS_C_INTEG_FLAG;
	    /* Any SSF bigger than 1 is confidentiality. */
	    /* Let's check if the client of the API requires confidentiality,
	       and it wasn't already provided by an external layer */
	    if(params->props.max_ssf - params->external_ssf > 1) {
		/* We want to try for privacy */
		req_flags |= GSS_C_CONF_FLAG;
	    }
	}
	
	if (params->props.security_flags & SASL_SEC_PASS_CREDENTIALS)
	    req_flags = req_flags |  GSS_C_DELEG_FLAG;

#ifdef _SUN_SDK_
	if (text->use_authid && text->client_creds == GSS_C_NO_CREDENTIAL) {
	    gss_OID_set desired_mechs = GSS_C_NULL_OID_SET;
	    gss_buffer_desc name_token;

	    name_token.length = strlen(text->client_authid);
	    name_token.value = (char *)text->client_authid;

	    maj_stat = gss_import_name (&min_stat,
					&name_token,
#ifdef HAVE_GSS_C_NT_USER_NAME
					GSS_C_NT_USER_NAME,
#else
					GSS_C_NULL_OID,
#endif
					&text->client_name);
	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }

	    if (text->mech_oid != GSS_C_NULL_OID) {
		ret = add_mech_to_set(text, &desired_mechs);
		if (ret != SASL_OK)
		    return (ret);
	    }

	    maj_stat = gss_acquire_cred(&min_stat, 
					text->client_name,
					GSS_C_INDEFINITE, 
					desired_mechs,
					GSS_C_INITIATE,
					&text->client_creds, 
					NULL, 
					NULL);

	    if (desired_mechs != GSS_C_NULL_OID_SET) {
		OM_uint32 min_stat2;
		(void) gss_release_oid_set(&min_stat2, &desired_mechs);
	    }

	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }
	}
#endif /* _SUN_SDK_ */

	GSS_LOCK_MUTEX(params->utils);
	maj_stat = gss_init_sec_context(&min_stat,
#ifdef _SUN_SDK_
					text->client_creds,
#else
					GSS_C_NO_CREDENTIAL,
#endif /* _SUN_SDK_ */
					&text->gss_ctx,
					text->server_name,
#ifdef _SUN_SDK_
					text->mech_oid,
#else
					GSS_C_NO_OID,
#endif /* _SUN_SDK_ */
					req_flags,
					0,
					GSS_C_NO_CHANNEL_BINDINGS,
					input_token,
					NULL,
					output_token,
					&out_req_flags,
					NULL);
	GSS_UNLOCK_MUTEX(params->utils);
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    if (output_token->value) {
		GSS_LOCK_MUTEX(params->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
	    }
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}

	if ((out_req_flags & GSS_C_DELEG_FLAG) != (req_flags & GSS_C_DELEG_FLAG)) {
#ifdef _SUN_SDK_
	    text->utils->seterror(text->utils->conn, SASL_LOG_WARN,
	      gettext("GSSAPI warning: no credentials were passed"));
#else
	    text->utils->seterror(text->utils->conn, SASL_LOG_WARN, "GSSAPI warning: no credentials were passed");
#endif /* _INTEGRATED_SOLARIS_ */
	    /* not a fatal error */
	}

	*clientoutlen = output_token->length;
	    
	if (output_token->value) {
	    if (clientout) {
		ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				      &(text->out_buf_len), *clientoutlen);
		if(ret != SASL_OK) {
		    GSS_LOCK_MUTEX(params->utils);
 		    gss_release_buffer(&min_stat, output_token);
		    GSS_UNLOCK_MUTEX(params->utils);
		    return ret;
		}
		memcpy(text->out_buf, output_token->value, *clientoutlen);
		*clientout = text->out_buf;
	    }
	    
	    GSS_LOCK_MUTEX(params->utils);
 	    gss_release_buffer(&min_stat, output_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	}
	
	if (maj_stat == GSS_S_COMPLETE) {
	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_inquire_context(&min_stat,
					   text->gss_ctx,
					   &text->client_name,
					   NULL,       /* targ_name */
					   NULL,       /* lifetime */
					   NULL,       /* mech */
					   /* FIX ME: Should check the resulting flags here */
					   NULL,       /* flags */
					   NULL,       /* local init */
					   NULL);      /* open */
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }
	    
	    name_token.length = 0;
	    GSS_LOCK_MUTEX(params->utils);
	    maj_stat = gss_display_name(&min_stat,
					text->client_name,
					&name_token,
					NULL);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    if (GSS_ERROR(maj_stat)) {
		if (name_token.value) {
		    GSS_LOCK_MUTEX(params->utils);
 		    gss_release_buffer(&min_stat, &name_token);
		    GSS_UNLOCK_MUTEX(params->utils);
		}
#ifdef _INTEGRATED_SOLARIS_
		SETERROR(text->utils, gettext("GSSAPI Failure"));
#else
		SETERROR(text->utils, "GSSAPI Failure");
#endif /* _INTEGRATED_SOLARIS_ */
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	    }
	    
	    if (text->user && text->user[0]) {
		ret = params->canon_user(params->utils->conn,
					 text->user, 0,
					 SASL_CU_AUTHZID, oparams);
		if (ret == SASL_OK) 
		    ret = params->canon_user(params->utils->conn,
					     name_token.value, 0,
					     SASL_CU_AUTHID, oparams);
	    } else {
		ret = params->canon_user(params->utils->conn,
					 name_token.value, 0,
					 SASL_CU_AUTHID | SASL_CU_AUTHZID,
					 oparams);
	    }
	    GSS_LOCK_MUTEX(params->utils);
 	    gss_release_buffer(&min_stat, &name_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	    
	    if (ret != SASL_OK) return ret;
	    
	    /* Switch to ssf negotiation */
	    text->state = SASL_GSSAPI_STATE_SSFCAP;
	}
	
	return SASL_CONTINUE;

    case SASL_GSSAPI_STATE_SSFCAP: {
	sasl_security_properties_t *secprops = &(params->props);
	unsigned int alen, external = params->external_ssf;
	sasl_ssf_t need, allowed;
	char serverhas, mychoice;
	
	real_input_token.value = (void *) serverin;
	real_input_token.length = serverinlen;
	
	GSS_LOCK_MUTEX(params->utils);
	maj_stat = gss_unwrap(&min_stat,
			      text->gss_ctx,
			      input_token,
			      output_token,
			      NULL,
			      NULL);
	GSS_UNLOCK_MUTEX(params->utils);
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    sasl_gss_free_context_contents(text);
	    if (output_token->value) {
		GSS_LOCK_MUTEX(params->utils);
 		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
	    }
	    return SASL_FAIL;
	}
	
	/* taken from kerberos.c */
	if (secprops->min_ssf > (K5_MAX_SSF + external)) {
	    return SASL_TOOWEAK;
	} else if (secprops->min_ssf > secprops->max_ssf) {
	    return SASL_BADPARAM;
	}
	
	/* need bits of layer -- sasl_ssf_t is unsigned so be careful */
	if (secprops->max_ssf >= external) {
	    allowed = secprops->max_ssf - external;
	} else {
	    allowed = 0;
	}
	if (secprops->min_ssf >= external) {
	    need = secprops->min_ssf - external;
	} else {
	    /* good to go */
	    need = 0;
	}
	
	/* bit mask of server support */
	serverhas = ((char *)output_token->value)[0];
	
	/* if client didn't set use strongest layer available */
	if (allowed >= K5_MAX_SSF && need <= K5_MAX_SSF && (serverhas & 4)) {
	    /* encryption */
	    oparams->encode = &gssapi_privacy_encode;
	    oparams->decode = &gssapi_decode;
	    /* FIX ME: Need to extract the proper value here */
	    oparams->mech_ssf = K5_MAX_SSF;
	    mychoice = 4;
	} else if (allowed >= 1 && need <= 1 && (serverhas & 2)) {
	    /* integrity */
	    oparams->encode = &gssapi_integrity_encode;
	    oparams->decode = &gssapi_decode;
	    oparams->mech_ssf = 1;
	    mychoice = 2;
#ifdef _SUN_SDK_
	} else if (need == 0 && (serverhas & 1)) {
#else
	} else if (need <= 0 && (serverhas & 1)) {
#endif /* _SUN_SDK_ */
	    /* no layer */
	    oparams->encode = NULL;
	    oparams->decode = NULL;
	    oparams->mech_ssf = 0;
	    mychoice = 1;
	} else {
	    /* there's no appropriate layering for us! */
	    sasl_gss_free_context_contents(text);
	    return SASL_TOOWEAK;
	}
	
        oparams->maxoutbuf =
	    (((unsigned char *) output_token->value)[1] << 16) |
            (((unsigned char *) output_token->value)[2] << 8) |
            (((unsigned char *) output_token->value)[3] << 0);

#ifdef _SUN_SDK_
	if (oparams->mech_ssf > 0) {
	    oparams->maxoutbuf -= 4;	/* Space for 4 byte length header */
	    maj_stat = gss_wrap_size_limit(&min_stat,
					text->gss_ctx,
					oparams->mech_ssf > 1,
					GSS_C_QOP_DEFAULT,
					oparams->maxoutbuf,
					&max_input_size);
	    if (GSS_ERROR(maj_stat)) {
		sasl_gss_seterror(text->utils, maj_stat, min_stat);
		GSS_LOCK_MUTEX(params->utils);
		(void) gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
		sasl_gss_free_context_contents(text);
		return (SASL_FAIL);
	    }

	/*
	 * This is a workaround for a Solaris bug where
	 * gss_wrap_size_limit may return very big sizes for
	 * small input values
	 */
	    if (max_input_size < oparams->maxoutbuf)
 		oparams->maxoutbuf = max_input_size;
	    else {
		oparams->maxoutbuf = 0;
	    }
	}
#else
	if(oparams->mech_ssf) {
            maj_stat = gss_wrap_size_limit( &min_stat,
                                            text->gss_ctx,
                                            1,
                                            GSS_C_QOP_DEFAULT,
                                            (OM_uint32) oparams->maxoutbuf,
                                            &max_input);

	    if(max_input > oparams->maxoutbuf) {
		/* Heimdal appears to get this wrong */
		oparams->maxoutbuf -= (max_input - oparams->maxoutbuf);
	    } else {
		/* This code is actually correct */
		oparams->maxoutbuf = max_input;
	    }
	}
#endif /* _SUN_SDK_ */
	
	GSS_LOCK_MUTEX(params->utils);
 	gss_release_buffer(&min_stat, output_token);
	GSS_UNLOCK_MUTEX(params->utils);
	
	/* oparams->user is always set, due to canon_user requirements.
	 * Make sure the client actually requested it though, by checking
	 * if our context was set.
	 */
	if (text->user && text->user[0])
	    alen = strlen(oparams->user);
	else
	    alen = 0;
	
	input_token->length = 4 + alen;
	input_token->value =
	    (char *)params->utils->malloc((input_token->length + 1)*sizeof(char));
	if (input_token->value == NULL) {
	    sasl_gss_free_context_contents(text);
	    return SASL_NOMEM;
	}
	
	if (alen)
	    memcpy((char *)input_token->value+4,oparams->user,alen);

	/* build up our security properties token */
        if (params->props.maxbufsize > 0xFFFFFF) {
            /* make sure maxbufsize isn't too large */
            /* maxbufsize = 0xFFFFFF */
            ((unsigned char *)input_token->value)[1] = 0xFF;
            ((unsigned char *)input_token->value)[2] = 0xFF;
            ((unsigned char *)input_token->value)[3] = 0xFF;
        } else {
            ((unsigned char *)input_token->value)[1] = 
                (params->props.maxbufsize >> 16) & 0xFF;
            ((unsigned char *)input_token->value)[2] = 
                (params->props.maxbufsize >> 8) & 0xFF;
            ((unsigned char *)input_token->value)[3] = 
                (params->props.maxbufsize >> 0) & 0xFF;
        }
	((unsigned char *)input_token->value)[0] = mychoice;
	
	GSS_LOCK_MUTEX(params->utils);
	maj_stat = gss_wrap (&min_stat,
			     text->gss_ctx,
			     0, /* Just integrity checking here */
			     GSS_C_QOP_DEFAULT,
			     input_token,
			     NULL,
			     output_token);
	GSS_UNLOCK_MUTEX(params->utils);
	
	params->utils->free(input_token->value);
	input_token->value = NULL;
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_seterror(text->utils, maj_stat, min_stat);
	    if (output_token->value) {
		GSS_LOCK_MUTEX(params->utils);
		gss_release_buffer(&min_stat, output_token);
		GSS_UNLOCK_MUTEX(params->utils);
	    }
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}
	
	if (clientoutlen)
	    *clientoutlen = output_token->length;
	if (output_token->value) {
	    if (clientout) {
		ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				      &(text->out_buf_len), *clientoutlen);
		if (ret != SASL_OK) {
		    GSS_LOCK_MUTEX(params->utils);
 		    gss_release_buffer(&min_stat, output_token);
		    GSS_UNLOCK_MUTEX(params->utils);
		    return ret;
		}
		memcpy(text->out_buf, output_token->value, *clientoutlen);
		*clientout = text->out_buf;
	    }
	    
	    GSS_LOCK_MUTEX(params->utils);
	    gss_release_buffer(&min_stat, output_token);
	    GSS_UNLOCK_MUTEX(params->utils);
	}
	
	text->state = SASL_GSSAPI_STATE_AUTHENTICATED;
	
	oparams->doneflag = 1;
	
	/* used by layers */
	_plug_decode_init(&text->decode_context, text->utils,
			  (params->props.maxbufsize > 0xFFFFFF) ? 0xFFFFFF :
			  params->props.maxbufsize);

	return SASL_OK;
    }
	
    default:
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "Invalid GSSAPI client step %d", text->state);
#else
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid GSSAPI client step %d\n", text->state);
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }
    
#ifndef _SUN_SDK_
    return SASL_FAIL; /* should never get here */
#endif /* !_SUN_SDK_ */
}

#ifdef _SUN_SDK_
static const unsigned long gssapi_required_prompts[] = {
#else
static const long gssapi_required_prompts[] = {
#endif /* _SUN_SDK_ */
    SASL_CB_LIST_END
};  

#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
static int _gssapi_client_mech_step(void *conn_context,
				   sasl_client_params_t *params,
				   const char *serverin,
				   unsigned serverinlen,
				   sasl_interact_t **prompt_need,
				   const char **clientout,
				   unsigned *clientoutlen,
				   sasl_out_params_t *oparams)
{
    int ret;

    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);

    ret = gssapi_client_mech_step(conn_context, params, serverin, serverinlen,
	prompt_need, clientout, clientoutlen, oparams);

    UNLOCK_MUTEX(&global_mutex);
    return (ret);
}
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */

static sasl_client_plug_t gssapi_client_plugins[] = 
{
    {
	"GSSAPI",			/* mech_name */
	K5_MAX_SSF,			/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOACTIVE
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH
	| SASL_SEC_PASS_CREDENTIALS,    /* security_flags */
	SASL_FEAT_NEEDSERVERFQDN
	| SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	gssapi_required_prompts,	/* required_prompts */
	NULL,				/* glob_context */
	&gssapi_client_mech_new,	/* mech_new */
#if defined _SUN_SDK_ && defined GSSAPI_PROTECT
	&_gssapi_client_mech_step,	/* mech_step */
#else
	&gssapi_client_mech_step,	/* mech_step */
#endif /* _SUN_SDK_ && GSSAPI_PROTECT */
	&gssapi_common_mech_dispose,	/* mech_dispose */
	&gssapi_common_mech_free,	/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int gssapiv2_client_plug_init(const sasl_utils_t *utils __attribute__((unused)), 
			      int maxversion,
			      int *out_version, 
			      sasl_client_plug_t **pluglist,
			      int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "Version mismatch in GSSAPI");
	return SASL_BADVERS;
    }
    
#ifdef _INTEGRATED_SOLARIS_
    /*
     * Let libsasl know that we are a "Sun" plugin so that privacy
     * and integrity will be allowed.
     */
    REG_PLUG("GSSAPI", gssapi_client_plugins);
#endif /* _INTEGRATED_SOLARIS_ */

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = gssapi_client_plugins;
    *plugcount = 1;

#ifdef GSS_USE_MUTEXES
    if(!gss_mutex) {
      gss_mutex = utils->mutex_alloc();
      if(!gss_mutex) {
        return SASL_FAIL;
      }
    }
#endif
    
    return SASL_OK;
}

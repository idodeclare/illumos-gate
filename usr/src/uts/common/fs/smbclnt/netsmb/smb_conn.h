/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_conn.h,v 1.32.42.1 2005/05/27 02:35:29 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright (C) 2001 - 2013 Apple Inc. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 */

#ifndef _SMB_CONN_H
#define	_SMB_CONN_H

#include <sys/dditypes.h>
#include <sys/t_lock.h>
#include <sys/queue.h> /* for SLIST below */
#include <sys/uio.h>
#include <netsmb/smb_dev.h>
#include <netsmb/nsmb_kcrypt.h>

/*
 * Credentials of user/process for processing in the connection procedures
 */
typedef struct smb_cred {
	struct cred *scr_cred;
} smb_cred_t;

/*
 * Common object flags
 */
#define	SMBO_GONE		0x1000000

/*
 * Bits in vc_flags (a.k.a. vc_co.co_flags)
 * Note: SMBO_GONE is also in vc_flags
 */
#define	SMBV_UNICODE		0x0040	/* conn configured to use Unicode */
#define	SMBV_EXT_SEC		0x0080	/* conn to use extended security */
#define	SMBV_SIGNING		0x0100	/* negotiated signing */
#define	SMBV_SMB2		0x0200	/* VC using SMB 2 or 3 */
#define	SMBV_HAS_FILEIDS	0x0400	/* Use File IDs for hash and inums */
#define	SMBV_NO_WRITE_THRU	0x0800	/* Can't use ... */

/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBV_GONE		SMBO_GONE

/*
 * bits in smb_share ss_flags (a.k.a. ss_co.co_flags)
 */
#define	SMBS_RECONNECTING	0x0002
#define	SMBS_CONNECTED		0x0004
#define	SMBS_TCON_WAIT		0x0008
#define	SMBS_FST_FAT		0x0010	/* share FS Type is FAT */
/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBS_GONE		SMBO_GONE

/*
 * bits in smb_fh fh_flags (a.k.a. ss_co.co_flags)
 */
#define	SMBFH_VALID		0x0002	/* FID is valid */
/*
 * Note: the common "obj" level uses this GONE flag by
 * the name SMBO_GONE.  Keep this alias as a reminder.
 */
#define	SMBFH_GONE		SMBO_GONE

struct smb_rq;
/* This declares struct smb_rqhead */
TAILQ_HEAD(smb_rqhead, smb_rq);

#define	SMB_NBTIMO	15
#define	SMB_DEFRQTIMO	30	/* 30 for oplock revoke/writeback */
#define	SMBWRTTIMO	60
#define	SMBSSNSETUPTIMO	60
#define	SMBNOREPLYWAIT (0)

#define	SMB_DIALECT(vcp)	((vcp)->vc_sopt.sv_proto)

/*
 * Connection object
 */

#define	SMB_CO_LOCK(cp)		mutex_enter(&(cp)->co_lock)
#define	SMB_CO_UNLOCK(cp)	mutex_exit(&(cp)->co_lock)

/*
 * Common part of smb_vc, smb_share
 * Locking: co_lock protects most
 * fields in this struct, except
 * as noted below:
 */
struct smb_connobj {
	kmutex_t		co_lock;
	int			co_level;	/* SMBL_ */
	int			co_flags;
	int			co_usecount;

	/* Note: must lock co_parent before child. */
	struct smb_connobj	*co_parent;

	/* this.co_lock protects the co_children list */
	SLIST_HEAD(, smb_connobj) co_children;

	/*
	 * Linkage in parent's list of children.
	 * Must hold parent.co_lock to traverse.
	 */
	SLIST_ENTRY(smb_connobj) co_next;

	/* These two are set only at creation. */
	void (*co_gone)(struct smb_connobj *);
	void (*co_free)(struct smb_connobj *);
};
typedef struct smb_connobj smb_connobj_t;

/*
 * "Level" in the connection object hierarchy
 */
enum smbco_level {
	SMBL_SM = 0,
	SMBL_VC = 1,
	SMBL_SHARE = 2,
	SMBL_FH = 3
};

/*
 * SMB1 Negotiated protocol parameters
 * Note:  All set to zero at start of nsmb_iod_negotiate
 */
struct smb_sopt {
	uint16_t	sv_proto;	/* protocol dialect */
	uchar_t		sv_sm;		/* security mode */
	int16_t		sv_tz;		/* offset in min relative to UTC */
	uint16_t	sv_maxmux;	/* max number of outstanding rq's */
	uint16_t	sv_maxvcs;	/* max number of VCs */
	uint16_t	sv_rawmode;
	uint32_t	sv_maxtx;	/* maximum transmit buf size */
	uint32_t	sv_maxraw;	/* maximum raw-buffer size */
	uint32_t	sv_skey;	/* session key */
	uint32_t	sv_caps;	/* capabilites SMB_CAP_ */

	/* SMB2+ fields */
	uint32_t	sv2_capabilities;	/* capabilities */
	uint32_t	sv2_maxtransact;	/* max transact size */
	uint32_t	sv2_maxread;	/* max read size */
	uint32_t	sv2_maxwrite;	/* max write size */
	uint16_t	sv2_security_mode;	/* security mode */
	uint16_t	sv2_sessflags;	/* final session setup reply flags */
	uint8_t		sv2_guid[16];	/* GUID */
};
typedef struct smb_sopt smb_sopt_t;

/*
 * SMB1 I/O Deamon state
 */
struct smb_iods {
	uint8_t		is_hflags;	/* SMB header flags */
	uint16_t	is_hflags2;	/* SMB header flags2 */
	uint16_t	is_smbuid;	/* SMB header UID */
	uint16_t	is_next_mid;	/* SMB header MID */
	uint32_t	is_txmax;	/* max tx/rx packet size */
	uint32_t	is_rwmax;	/* max read/write data size */
	uint32_t	is_rxmax;	/* max readx data size */
	uint32_t	is_wxmax;	/* max writex data size */
	/* Signing state */
	uint32_t	is_next_seq;	/* my next sequence number */

};
typedef struct smb_iods smb_iods_t;

/*
 * Virtual Circuit to a server (really connection + session).
 * Yes, calling this a "Virtual Circuit" is confusining,
 * because it has nothing to do with the SMB notion of a
 * "Virtual Circuit".
 */
typedef struct smb_vc {
	struct smb_connobj	vc_co;	/* keep first! See CPTOVC */
	enum smbiod_state	vc_state;
	kcondvar_t		vc_statechg;

	zoneid_t		vc_zoneid;
	uid_t			vc_owner;	/* Unix owner */
	int			vc_genid;	/* "generation" ID */

	int			vc_mackeylen;	/* MAC key length */
	int			vc_ssnkeylen;	/* session key length */
	uint8_t			*vc_mackey;	/* MAC key buffer */
	uint8_t			*vc_ssnkey;	/* session key buffer */
	smb_crypto_mech_t	vc_signmech;
	struct smb_mac_ops	*vc_sign_ops;

	struct smb_tran_desc	*vc_tdesc;	/* transport ops. vector */
	void			*vc_tdata;	/* transport control block */

	/* SMB2+ fields */
	uint64_t	vc2_oldest_message_id;
	uint64_t	vc2_next_message_id;
	uint64_t	vc2_limit_message_id;
	uint64_t	vc2_session_id;		/* session id */
	uint64_t	vc2_prev_session_id;	/* for reconnect */
	uint32_t	vc2_lease_key;		/* lease key gen */

	/* SMB3+ fields */
	smb_crypto_mech_t *vc3_crypt_mech;

	uint8_t		vc3_encrypt_key[SMB3_KEYLEN];
	uint32_t	vc3_encrypt_key_len;

	uint8_t		vc3_decrypt_key[SMB3_KEYLEN];
	uint32_t	vc3_decrypt_key_len;

	/* SMB 3 Nonce used for encryption */
	uint64_t	vc3_nonce_high;
	uint64_t	vc3_nonce_low;

	kcondvar_t		iod_idle;	/* IOD thread idle CV */
	krwlock_t		iod_rqlock;	/* iod_rqlist */
	struct smb_rqhead	iod_rqlist;	/* list of active reqs */
	struct _kthread		*iod_thr;	/* the IOD (reader) thread */
	int			iod_flags;	/* see SMBIOD_* below */
	uint_t			iod_muxcnt;	/* num. active requests */
	uint_t			iod_muxwant;	/* waiting to be active */
	kcondvar_t		iod_muxwait;
	boolean_t		iod_noresp;	/* Logged "not responding" */

	smb_iods_t		vc_iods;
	smb_sopt_t		vc_sopt;

	/* This is copied in/out when IOD enters/returns */
	smbioc_ssn_work_t	vc_work;

	/* session identity, etc. */
	smbioc_ossn_t		vc_ssn;
} smb_vc_t;

#define	vc_lock		vc_co.co_lock
#define	vc_flags	vc_co.co_flags

/* defines for members in vc_ssn */
#define	vc_owner	vc_ssn.ssn_owner
#define	vc_vopt		vc_ssn.ssn_vopt
#define	vc_minver	vc_ssn.ssn_minver
#define	vc_maxver	vc_ssn.ssn_maxver
#define	vc_srvname	vc_ssn.ssn_srvname
#define	vc_srvaddr	vc_ssn.ssn_id.id_srvaddr
#define	vc_domain	vc_ssn.ssn_id.id_domain
#define	vc_username	vc_ssn.ssn_id.id_user

/* defines for members in vc_work */
#define	vc_cl_guid	vc_work.wk_cl_guid

/* defines for members in vc_sopt ? */
#define	vc_maxmux	vc_sopt.sv_maxmux

/* defines for members in vc_iods */
#define	vc_hflags	vc_iods.is_hflags
#define	vc_hflags2	vc_iods.is_hflags2
#define	vc_smbuid	vc_iods.is_smbuid
#define	vc_next_mid	vc_iods.is_next_mid
#define	vc_txmax	vc_iods.is_txmax
#define	vc_rwmax	vc_iods.is_rwmax
#define	vc_rxmax	vc_iods.is_rxmax
#define	vc_wxmax	vc_iods.is_wxmax
#define	vc_next_seq	vc_iods.is_next_seq

#define	SMB_VC_LOCK(vcp)	mutex_enter(&(vcp)->vc_lock)
#define	SMB_VC_UNLOCK(vcp)	mutex_exit(&(vcp)->vc_lock)

#define	CPTOVC(cp)	((struct smb_vc *)((void *)(cp)))
#define	VCTOCP(vcp)	(&(vcp)->vc_co)

#define	SMB_UNICODE_STRINGS(vcp) \
	(((vcp)->vc_flags & SMBV_SMB2) != 0 ||	\
	((vcp)->vc_hflags2 & SMB_FLAGS2_UNICODE) != 0)

/* Bits in iod_flags */
#define	SMBIOD_RUNNING		0x0001
#define	SMBIOD_SHUTDOWN		0x0002

/*
 * smb_share structure describes connection to the given SMB share (tree).
 * Connection to share is always built on top of the VC.
 */

typedef struct smb_share {
	struct smb_connobj ss_co;	/* keep first! See CPTOSS */
	kcondvar_t	ss_conn_done;	/* wait for reconnect */
	int		ss_conn_waiters;
	int		ss_vcgenid;	/* check VC generation ID */
	uint16_t	ss_tid;		/* TID */
	uint16_t	ss_options;	/* option support bits */
	uint32_t	ss2_tree_id;
	uint32_t	ss2_share_flags;
	uint32_t	ss2_share_caps;
	smbioc_oshare_t ss_ioc;
} smb_share_t;

#define	ss_lock		ss_co.co_lock
#define	ss_flags	ss_co.co_flags

#define	ss_use		ss_ioc.sh_use
#define	ss_type		ss_ioc.sh_type
#define	ss_name		ss_ioc.sh_name
#define	ss_pass		ss_ioc.sh_pass

#define	SMB_SS_LOCK(ssp)	mutex_enter(&(ssp)->ss_lock)
#define	SMB_SS_UNLOCK(ssp)	mutex_exit(&(ssp)->ss_lock)

#define	CPTOSS(cp)	((struct smb_share *)((void *)(cp)))
#define	SSTOCP(ssp)	(&(ssp)->ss_co)
#define	SSTOVC(ssp)	CPTOVC(((ssp)->ss_co.co_parent))

typedef struct smb2fid {
	uint64_t fid_persistent;
	uint64_t fid_volatile;
} smb2fid_t;

/*
 * smb_fh struct describes an open file handle under some share.
 */
typedef struct smb_fh {
	struct smb_connobj fh_co;	/* keep first! See CPTOSS */
	int	fh_vcgenid;		/* check VC generation ID */
	uint32_t fh_rights;		/* granted access */
	smb2fid_t fh_fid2;
	uint16_t fh_fid1;
} smb_fh_t;

#define	fh_lock		fh_co.co_lock
#define	fh_flags	fh_co.co_flags

#define	SMB_FH_LOCK(fhp)	mutex_enter(&(fhp)->fh_lock)
#define	SMB_FH_UNLOCK(fhp)	mutex_exit(&(fhp)->fh_lock)

#define	CPTOFH(cp)	((struct smb_fh *)((void *)(cp)))
#define	FHTOCP(fhp)	(&(fhp)->fh_co)
#define	FHTOSS(fhp)	CPTOSS(((fhp)->fh_co.co_parent))

/*
 * Call-back operations vector, so the netsmb module
 * can notify smbfs about events affecting mounts.
 * Installed in netsmb after smbfs loads.
 * Note: smbfs only uses the fscb_discon hook.
 */
typedef struct smb_fscb {
	/* Called when the VC has disconnected. */
	void (*fscb_disconn)(smb_share_t *);
	/* Called when the VC has reconnected. */
	void (*fscb_connect)(smb_share_t *);
} smb_fscb_t;
/* Install the above vector, or pass NULL to clear it. */
void smb_fscb_set(smb_fscb_t *);

/*
 * The driver per open instance object.
 * Mostly used in: smb_dev.c, smb_usr.c
 */
typedef struct smb_dev {
	kmutex_t	sd_lock;
	struct smb_vc	*sd_vc;		/* Reference to VC */
	struct smb_share *sd_share;	/* Reference to share if any */
	struct smb_fh	*sd_fh;		/* Reference to FH, if any */
	int		sd_level;	/* SMBL_VC, ... */
	int		sd_vcgenid;	/* Generation of share or VC */
	int		sd_poll;	/* Future use */
	int		sd_flags;	/* State of connection */
#define	NSMBFL_OPEN		0x0001	/* Device minor is open */
#define	NSMBFL_IOD		0x0004	/* Open by IOD */
#define	NSMBFL_IOCTL		0x0010	/* Serialize ioctl calls */
	zoneid_t	zoneid;		/* Zone id */
} smb_dev_t;

extern const uint32_t nsmb_version;

/*
 * smb_dev.c
 */
int  smb_dev2share(int fd, struct smb_share **sspp);


/*
 * smb_usr.c
 */
int smb_usr_ioctl(smb_dev_t *, int, intptr_t, int, cred_t *);

int smb_usr_get_flags2(smb_dev_t *sdp, intptr_t arg, int flags);
int smb_usr_get_ssnkey(smb_dev_t *sdp, intptr_t arg, int flags);
int smb_usr_dup_dev(smb_dev_t *sdp, intptr_t arg, int flags);

int smb_usr_simplerq(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr);
int smb_usr_t2request(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr);

int smb_usr_closefh(smb_dev_t *, cred_t *);
int smb_usr_rw(smb_dev_t *sdp, int cmd, intptr_t arg, int flags, cred_t *cr);
int smb_usr_ntcreate(smb_dev_t *, intptr_t, int, cred_t *);
int smb_usr_printjob(smb_dev_t *, intptr_t, int, cred_t *);

int smb_usr_get_ssn(smb_dev_t *, int, intptr_t, int, cred_t *);
int smb_usr_drop_ssn(smb_dev_t *sdp, int cmd);

int smb_usr_get_tree(smb_dev_t *, int, intptr_t, int, cred_t *);
int smb_usr_drop_tree(smb_dev_t *sdp, int cmd);

int smb_usr_iod_work(smb_dev_t *sdp, intptr_t arg, int flags, cred_t *cr);
int smb_usr_iod_ioctl(smb_dev_t *sdp, int cmd, intptr_t arg, int flags,
    cred_t *cr);

int smb_pkey_ioctl(int, intptr_t, int, cred_t *);


/*
 * IOD functions
 */
int  smb_iod_create(smb_vc_t *vcp);
int  smb_iod_destroy(smb_vc_t *vcp);
void smb_iod_disconnect(smb_vc_t *vcp);
int  smb2_iod_addrq(struct smb_rq *rqp);
int  smb1_iod_addrq(struct smb_rq *rqp);
int  smb1_iod_multirq(struct smb_rq *rqp);
int  smb_iod_waitrq(struct smb_rq *rqp);
int  smb_iod_waitrq_int(struct smb_rq *rqp);
void smb_iod_removerq(struct smb_rq *rqp);
int  smb_iod_sendrecv(struct smb_rq *, int);
void smb_iod_shutdown_share(smb_share_t *ssp);

void smb_iod_sendall(smb_vc_t *);
int smb_iod_recvall(smb_vc_t *, boolean_t);

int nsmb_iod_connect(smb_vc_t *vcp, cred_t *cr);
int nsmb_iod_negotiate(smb_vc_t *vcp, cred_t *cr);
int nsmb_iod_ssnsetup(smb_vc_t *vcp, cred_t *cr);
int smb_iod_vc_work(smb_vc_t *, int, cred_t *);
int smb_iod_vc_idle(smb_vc_t *);
int smb_iod_vc_rcfail(smb_vc_t *);
int smb_iod_reconnect(smb_vc_t *);

/*
 * Session level functions
 */
int  smb_sm_init(void);
int  smb_sm_idle(void);
void smb_sm_done(void);

/*
 * VC level functions
 */
void smb_vc_hold(smb_vc_t *vcp);
void smb_vc_rele(smb_vc_t *vcp);
void smb_vc_kill(smb_vc_t *vcp);

int smb_vc_findcreate(smbioc_ossn_t *, smb_cred_t *, smb_vc_t **);
int smb_vc_create(smbioc_ossn_t *ossn, smb_cred_t *scred, smb_vc_t **vcpp);

const char *smb_vc_getpass(smb_vc_t *vcp);
uint16_t smb_vc_nextmid(smb_vc_t *vcp);
void *smb_vc_getipaddr(smb_vc_t *vcp, int *ipvers);

typedef void (*walk_share_func_t)(smb_share_t *);
void smb_vc_walkshares(struct smb_vc *,	walk_share_func_t);

/*
 * share level functions
 */

int smb_share_findcreate(smbioc_tcon_t *, smb_vc_t *,
	smb_share_t **, smb_cred_t *);

void smb_share_hold(smb_share_t *ssp);
void smb_share_rele(smb_share_t *ssp);
void smb_share_kill(smb_share_t *ssp);

void smb_share_invalidate(smb_share_t *ssp);
int  smb_share_tcon(smb_share_t *, smb_cred_t *);

/*
 * File handle level functions
 */
int smb_fh_create(smb_share_t *ssp, struct smb_fh **fhpp);
void smb_fh_opened(struct smb_fh *fhp);
void smb_fh_close(struct smb_fh *fhp);
void smb_fh_hold(struct smb_fh *fhp);
void smb_fh_rele(struct smb_fh *fhp);

#endif /* _SMB_CONN_H */

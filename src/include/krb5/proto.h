/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Protocol message definitions.
 */


#ifndef	KRB5_PROTO__
#define KRB5_PROTO__

/* Protocol version number */
#define	KRB5_PVNO	5

/* Message types */

#define	KRB5_AS_REQ	((krb5_msgtype)10) /* Req for initial authentication */
#define	KRB5_AS_REP	((krb5_msgtype)11) /* Response to KRB_AS_REQ request */
#define	KRB5_TGS_REQ	((krb5_msgtype)12) /* TGS request to server */
#define	KRB5_TGS_REP	((krb5_msgtype)13) /* Response to KRB_TGS_REQ req */
#define	KRB5_AP_REQ	((krb5_msgtype)14) /* application request to server */
#define	KRB5_AP_REP	((krb5_msgtype)15) /* Response to KRB_AP_REQ_MUTUAL */
#define	KRB5_SAFE	((krb5_msgtype)20) /* Safe application message */
#define	KRB5_PRIV	((krb5_msgtype)21) /* Private application message */
#define	KRB5_ERROR	((krb5_msgtype)30) /* Error response */

/* LastReq types */
#define KRB5_LRQ_NONE			0
#define KRB5_LRQ_ALL_LAST_TGT		1
#define KRB5_LRQ_ONE_LAST_TGT		(-1)
#define KRB5_LRQ_ALL_LAST_INITIAL	2
#define KRB5_LRQ_ONE_LAST_INITIAL	(-2)
#define KRB5_LRQ_ALL_LAST_TGT_ISSUED	3
#define KRB5_LRQ_ONE_LAST_TGT_ISSUED	(-3)
#define KRB5_LRQ_ALL_LAST_RENEWAL	4
#define KRB5_LRQ_ONE_LAST_RENEWAL	(-4)
#define KRB5_LRQ_ALL_LAST_REQ		5
#define KRB5_LRQ_ONE_LAST_REQ		(-5)

/* PADATA types */
#define	KRB5_PADATA_AP_REQ		1
#define	KRB5_PADATA_TGS_REQ		KRB5_PADATA_AP_REQ
#define KRB5_PADATA_ENC_TIMESTAMPS	2
#define	KRB5_PADATA_PW_SALT		3

/* Transited encoding types */
#define	KRB5_DOMAIN_X500_COMPRESS	1

/* alternate authentication types */
#define	KRB5_ALTAUTH_ATT_CHALLENGE_RESPONSE	64

/* authorization data types */
#define	KRB5_AUTHDATA_OSF_DCE	64

#endif /* KRB5_PROTO__ */

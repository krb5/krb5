/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Protocol message definitions.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_PROTO__
#define __KRB5_PROTO__

/* Protocol version number */
#define	KRB5_PVNO	5

/* Message types */

#define	KRB5_AS_REQ	((krb5_msgtype)2) /* Req for initial authentication */
#define	KRB5_AS_REP	((krb5_msgtype)4) /* Response to KRB_AS_REQ request */
#define	KRB5_AP_REQ	((krb5_msgtype)6) /* application request to server */
#define	KRB5_TGS_REQ	((krb5_msgtype)8) /* TGS request to server */
#define	KRB5_AP_REP	((krb5_msgtype)10) /* Response to KRB_AP_REQ_MUTUAL */
#define	KRB5_PRIV	((krb5_msgtype)12) /* Private application message */
#define	KRB5_SAFE	((krb5_msgtype)14) /* Safe application message */
#define	KRB5_TGS_REP	((krb5_msgtype)16) /* Response to KRB_TGS_REQ req */
#define	KRB5_ERROR	((krb5_msgtype)32) /* Error response */

#endif /* __KRB5_PROTO__ */

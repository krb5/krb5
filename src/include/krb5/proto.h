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

#define	KRB5_AS_REQ		2	/* Req for initial authentication */
#define	KRB5_AS_REP		4	/* Response to KRB_AS_REQ request */
#define	KRB5_AP_REQ		6	/* application request to server */
#define	KRB5_AP_REP		10	/* Response to KRB_AP_REQ_MUTUAL */
#define	KRB5_PRIV		12	/* Private application message */
#define	KRB5_SAFE		14	/* Safe application message */
#define	KRB5_TGS_REP		16	/* Response to KRB_TGS_REQ request */
#define	KRB5_ERROR		32	/* Error response */

#endif /* __KRB5_PROTO__ */

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
 * Definitions for the field bits for Kerberos protocol
 * version 5.
 */

#include <krb5/mit-copyright.h>

#ifndef __KRB5_FIELDBITS__
#define __KRB5_FIELDBITS__

/* kdc_options for kdc_request */
/* options is 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	KDC_OPT_RESERVED	0x80000000 */
#define	KDC_OPT_FORWARDABLE		0x40000000
#define	KDC_OPT_FORWARDED		0x20000000
#define	KDC_OPT_PROXIABLE		0x10000000
#define	KDC_OPT_PROXY			0x08000000
#define	KDC_OPT_ALLOW_POSTDATE		0x04000000
#define	KDC_OPT_POSTDATED		0x02000000
/* #define	KDC_OPT_UNUSED		0x01000000 */
#define	KDC_OPT_RENEWABLE		0x00800000
/* #define	KDC_OPT_UNUSED		0x00400000 */
#define	KDC_OPT_DUPLICATE_SKEY		0x00200000
/* #define	KDC_OPT_RESERVED	0x00100000 */
/* #define	KDC_OPT_RESERVED	0x00080000 */
/* #define	KDC_OPT_RESERVED	0x00040000 */
/* #define	KDC_OPT_RESERVED	0x00020000 */
/* #define	KDC_OPT_RESERVED	0x00010000 */
/* #define	KDC_OPT_RESERVED	0x00008000 */
/* #define	KDC_OPT_RESERVED	0x00004000 */
/* #define	KDC_OPT_RESERVED	0x00002000 */
/* #define	KDC_OPT_RESERVED	0x00001000 */
/* #define	KDC_OPT_RESERVED	0x00000800 */
/* #define	KDC_OPT_RESERVED	0x00000400 */
/* #define	KDC_OPT_RESERVED	0x00000200 */
/* #define	KDC_OPT_RESERVED	0x00000100 */
/* #define	KDC_OPT_RESERVED	0x00000080 */
/* #define	KDC_OPT_RESERVED	0x00000040 */
/* #define	KDC_OPT_RESERVED	0x00000020 */
#define	KDC_OPT_RENEWABLE_OK		0x00000010
#define	KDC_OPT_ENC_TKT_IN_SKEY		0x00000008
#define	KDC_OPT_REUSE_SKEY		0x00000004
#define	KDC_OPT_RENEW			0x00000002
#define	KDC_OPT_VALIDATE		0x00000001

/* definitions for ap_options fields */
/* ap_options are 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
#define	AP_OPTS_RESERVED		0x80000000
#define	AP_OPTS_USE_SESSION_KEY		0x40000000
#define	AP_OPTS_MUTUAL_REQUIRED		0x20000000
/* #define	AP_OPTS_RESERVED	0x10000000 */
/* #define	AP_OPTS_RESERVED	0x08000000 */
/* #define	AP_OPTS_RESERVED	0x04000000 */
/* #define	AP_OPTS_RESERVED	0x02000000 */
/* #define	AP_OPTS_RESERVED	0x01000000 */
/* #define	AP_OPTS_RESERVED	0x00800000 */
/* #define	AP_OPTS_RESERVED	0x00400000 */
/* #define	AP_OPTS_RESERVED	0x00200000 */
/* #define	AP_OPTS_RESERVED	0x00100000 */
/* #define	AP_OPTS_RESERVED	0x00080000 */
/* #define	AP_OPTS_RESERVED	0x00040000 */
/* #define	AP_OPTS_RESERVED	0x00020000 */
/* #define	AP_OPTS_RESERVED	0x00010000 */
/* #define	AP_OPTS_RESERVED	0x00008000 */
/* #define	AP_OPTS_RESERVED	0x00004000 */
/* #define	AP_OPTS_RESERVED	0x00002000 */
/* #define	AP_OPTS_RESERVED	0x00001000 */
/* #define	AP_OPTS_RESERVED	0x00000800 */
/* #define	AP_OPTS_RESERVED	0x00000400 */
/* #define	AP_OPTS_RESERVED	0x00000200 */
/* #define	AP_OPTS_RESERVED	0x00000100 */
/* #define	AP_OPTS_RESERVED	0x00000080 */
/* #define	AP_OPTS_RESERVED	0x00000040 */
/* #define	AP_OPTS_RESERVED	0x00000020 */
/* #define	AP_OPTS_RESERVED	0x00000010 */
/* #define	AP_OPTS_RESERVED	0x00000008 */
/* #define	AP_OPTS_RESERVED	0x00000004 */
/* #define	AP_OPTS_RESERVED	0x00000002 */
/* #define	AP_OPTS_RESERVED	0x00000001 */

/* definitions for ad_type fields. */
#define	AD_TYPE_RESERVED	0x8000
#define	AD_TYPE_EXTERNAL	0x4000
#define	AD_TYPE_REGISTERED	0x2000

#define AD_TYPE_FIELD_TYPE_MASK	0x1fff

/* Ticket flags */
/* flags are 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	TKT_FLG_RESERVED	0x80000000 */
#define	TKT_FLG_FORWARDABLE		0x40000000
#define	TKT_FLG_FORWARDED		0x20000000
#define	TKT_FLG_PROXIABLE		0x10000000
#define	TKT_FLG_PROXY			0x08000000
#define	TKT_FLG_MAY_POSTDATE		0x04000000
#define	TKT_FLG_POSTDATED		0x02000000
#define	TKT_FLG_INVALID			0x01000000
#define	TKT_FLG_RENEWABLE		0x00800000
#define	TKT_FLG_INITIAL			0x00400000
#define	TKT_FLG_DUPLICATE_SKEY		0x00200000
/* #define	TKT_FLG_RESERVED	0x00100000 */
/* #define	TKT_FLG_RESERVED	0x00080000 */
/* #define	TKT_FLG_RESERVED	0x00040000 */
/* #define	TKT_FLG_RESERVED	0x00020000 */
/* #define	TKT_FLG_RESERVED	0x00010000 */
/* #define	TKT_FLG_RESERVED	0x00008000 */
/* #define	TKT_FLG_RESERVED	0x00004000 */
/* #define	TKT_FLG_RESERVED	0x00002000 */
/* #define	TKT_FLG_RESERVED	0x00001000 */
/* #define	TKT_FLG_RESERVED	0x00000800 */
/* #define	TKT_FLG_RESERVED	0x00000400 */
/* #define	TKT_FLG_RESERVED	0x00000200 */
/* #define	TKT_FLG_RESERVED	0x00000100 */
/* #define	TKT_FLG_RESERVED	0x00000080 */
/* #define	TKT_FLG_RESERVED	0x00000040 */
/* #define	TKT_FLG_RESERVED	0x00000020 */
/* #define	TKT_FLG_RESERVED	0x00000010 */
/* #define	TKT_FLG_RESERVED	0x00000008 */
/* #define	TKT_FLG_RESERVED	0x00000004 */
/* #define	TKT_FLG_RESERVED	0x00000002 */
/* #define	TKT_FLG_RESERVED	0x00000001 */

/* kdc_options for kdc_request */
/* options is 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	KDC_OPT_RESERVED	0x80000000 */
#define	KDC_OPT_FORWARDABLE		0x40000000
#define	KDC_OPT_FORWARDED		0x20000000
#define	KDC_OPT_PROXIABLE		0x10000000
#define	KDC_OPT_PROXY			0x08000000
#define	KDC_OPT_ALLOW_POSTDATE		0x04000000
#define	KDC_OPT_POSTDATED		0x02000000
/* #define	KDC_OPT_UNUSED		0x01000000 */
#define	KDC_OPT_RENEWABLE		0x00800000
/* #define	KDC_OPT_UNUSED		0x00400000 */
#define	KDC_OPT_DUPLICATE_SKEY		0x00200000
/* #define	KDC_OPT_RESERVED	0x00100000 */
/* #define	KDC_OPT_RESERVED	0x00080000 */
/* #define	KDC_OPT_RESERVED	0x00040000 */
/* #define	KDC_OPT_RESERVED	0x00020000 */
/* #define	KDC_OPT_RESERVED	0x00010000 */
/* #define	KDC_OPT_RESERVED	0x00008000 */
/* #define	KDC_OPT_RESERVED	0x00004000 */
/* #define	KDC_OPT_RESERVED	0x00002000 */
/* #define	KDC_OPT_RESERVED	0x00001000 */
/* #define	KDC_OPT_RESERVED	0x00000800 */
/* #define	KDC_OPT_RESERVED	0x00000400 */
/* #define	KDC_OPT_RESERVED	0x00000200 */
/* #define	KDC_OPT_RESERVED	0x00000100 */
/* #define	KDC_OPT_RESERVED	0x00000080 */
/* #define	KDC_OPT_RESERVED	0x00000040 */
/* #define	KDC_OPT_RESERVED	0x00000020 */
#define	KDC_OPT_RENEWABLE_OK		0x00000010
#define	KDC_OPT_ENC_TKT_IN_SKEY		0x00000008
#define	KDC_OPT_REUSE_SKEY		0x00000004
#define	KDC_OPT_RENEW			0x00000002
#define	KDC_OPT_VALIDATE		0x00000001

/* definitions for lr_type fields. */
#define	LR_TYPE_THIS_SERVER_ONLY	0x8000

#define LR_TYPE_INTERPRETATION_MASK	0x7fff

#endif /* __KRB5_FIELDBITS__ */



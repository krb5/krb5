/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * KDC Database interface definitions.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KDB5__
#define __KRB5_KDB5__

typedef struct {
    krb5_principal principal;
    krb5_keyblock *key;
    krb5_kvno kvno;
    krb5_deltat	max_life;
    krb5_deltat	max_renewable_life;
    krb5_kvno mkvno;			/* master encryption key vno */
    krb5_timestamp expiration;
    krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
} krb5_kdb_principal;

#define	KRB5_KDB_DISALLOW_POSTDATED	0x00000001
#define	KRB5_KDB_DISALLOW_FORWARDABLE	0x00000002
#define	KRB5_KDB_DISALLOW_TGT_BASED	0x00000004
#define	KRB5_KDB_DISALLOW_RENEWABLE	0x00000008
#define	KRB5_KDB_DISALLOW_PROXIABLE	0x00000010
#define	KRB5_KDB_DISALLOW_DUP_SKEY	0x00000020

#endif /* __KRB5_KDB5__ */

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

typedef struct _krb5_kdb_principal {
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

/* XXX depends on knowledge of krb5_parse_name() formats */
#define KRB5_KDB_M_NAME		"K/M"	/* Kerberos/Master */

/* libkdb.spec */
krb5_error_code krb5_db_set_name
	PROTOTYPE((char *name ));
krb5_error_code krb5_db_set_nonblocking
	PROTOTYPE((krb5_boolean newmode,
		   krb5_boolean *oldmode ));
krb5_error_code krb5_db_init
	PROTOTYPE((void ));
krb5_error_code krb5_db_fini
	PROTOTYPE((void ));
krb5_error_code krb5_db_get_age
	PROTOTYPE((char *db_name,
		   krb5_timestamp *age ));
krb5_error_code krb5_db_create
	PROTOTYPE((char *db_name ));
krb5_error_code krb5_db_rename
	PROTOTYPE((char *from,
		   char *to ));
krb5_error_code krb5_db_get_principal
	PROTOTYPE((krb5_principal searchfor,
		   krb5_kdb_principal *principal,
		   int *nprincs,
		   krb5_boolean *more ));
krb5_error_code krb5_db_free_principal
	PROTOTYPE((krb5_kdb_principal *principal,
		   int nprincs ));
krb5_error_code krb5_db_put_principal
	PROTOTYPE((krb5_kdb_principal *principal,
		   int nprincs,
		   int *nstored ));
krb5_error_code krb5_db_iterate
	PROTOTYPE((krb5_error_code (*func ) PROTOTYPE((krb5_pointer,
						       krb5_kdb_principal *)),
		   krb5_pointer iterate_arg ));

#endif /* __KRB5_KDB5__ */

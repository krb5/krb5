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

#ifndef __KRB5_KDB5_DBM__
#define __KRB5_KDB5_DBM__

/* libkdb.spec */
krb5_error_code krb5_dbm_db_set_name
	PROTOTYPE((char *name ));
krb5_error_code krb5_dbm_db_set_nonblocking
	PROTOTYPE((krb5_boolean newmode,
		   krb5_boolean *oldmode ));
krb5_error_code krb5_dbm_db_init
	PROTOTYPE((void ));
krb5_error_code krb5_dbm_db_fini
	PROTOTYPE((void ));
krb5_error_code krb5_dbm_db_get_age
	PROTOTYPE((char *db_name,
		   krb5_timestamp *age ));
krb5_error_code krb5_dbm_db_create
	PROTOTYPE((char *db_name ));
krb5_error_code krb5_dbm_db_rename
	PROTOTYPE((char *from,
		   char *to ));
krb5_error_code krb5_dbm_db_get_principal
	PROTOTYPE((krb5_principal searchfor,
		   krb5_kdb_principal *principal,
		   int *nprincs,
		   krb5_boolean *more ));
krb5_error_code krb5_dbm_db_free_principal
	PROTOTYPE((krb5_kdb_principal *principal,
		   int nprincs ));
krb5_error_code krb5_dbm_db_put_principal
	PROTOTYPE((krb5_kdb_principal *principal,
		   int nprincs,
		   int *nstored ));
krb5_error_code krb5_dbm_db_iterate
	PROTOTYPE((krb5_error_code (*func ) PROTOTYPE((krb5_pointer,
						       krb5_kdb_principal *)),
		   krb5_pointer iterate_arg ));
#endif /* __KRB5_KDB5_DBM__ */

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

#define	DEFAULT_DBM_FILE		"/krb5/principal"

/* libkdb.spec */
krb5_error_code krb5_dbm_db_set_name PROTOTYPE((char * ));
krb5_error_code krb5_dbm_db_set_nonblocking PROTOTYPE((krb5_boolean,
						       krb5_boolean * ));
krb5_error_code krb5_dbm_db_init PROTOTYPE((void ));
krb5_error_code krb5_dbm_db_fini PROTOTYPE((void ));
krb5_error_code krb5_dbm_db_get_age PROTOTYPE((char *, time_t * ));
krb5_error_code krb5_dbm_db_create PROTOTYPE((char * ));
krb5_error_code krb5_dbm_db_rename PROTOTYPE((char *, char * ));
krb5_error_code krb5_dbm_db_get_principal PROTOTYPE((krb5_principal,
						     krb5_kdb_principal *,
						     int *,
						     krb5_boolean * ));
void krb5_dbm_db_free_principal PROTOTYPE((krb5_kdb_principal *, int ));
krb5_error_code krb5_dbm_db_put_principal PROTOTYPE((krb5_kdb_principal *,
						     int * ));
krb5_error_code krb5_dbm_db_iterate
    PROTOTYPE((krb5_error_code (*) PROTOTYPE((krb5_pointer,
					      krb5_kdb_principal *)),
	       krb5_pointer ));
#endif /* __KRB5_KDB5_DBM__ */

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * KDC Database interface definitions.
 */

#include <krb5/copyright.h>

#ifndef KRB5_KDB5_DBM__
#define KRB5_KDB5_DBM__

#define	DEFAULT_DBM_FILE		"/krb5/principal"

/* #define these to avoid an indirection function; for future implementations,
   these may be redirected from a dispatch table/routine */
#define krb5_dbm_db_set_name krb5_db_set_name
#define krb5_dbm_db_set_nonblocking krb5_db_set_nonblocking
#define krb5_dbm_db_init krb5_db_init
#define krb5_dbm_db_fini krb5_db_fini
#define krb5_dbm_db_get_age krb5_db_get_age
#define krb5_dbm_db_create krb5_db_create
#define krb5_dbm_db_rename krb5_db_rename
#define krb5_dbm_db_get_principal krb5_db_get_principal
#define krb5_dbm_db_free_principal krb5_db_free_principal
#define krb5_dbm_db_put_principal krb5_db_put_principal
#define krb5_dbm_db_delete_principal krb5_db_delete_principal
#define krb5_dbm_db_iterate krb5_db_iterate

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
						     krb5_db_entry *,
						     int *,
						     krb5_boolean * ));
void krb5_dbm_db_free_principal PROTOTYPE((krb5_db_entry *, int ));
krb5_error_code krb5_dbm_db_put_principal PROTOTYPE((krb5_db_entry *,
						     int * ));
krb5_error_code krb5_dbm_db_iterate
    PROTOTYPE((krb5_error_code (*) PROTOTYPE((krb5_pointer,
					      krb5_db_entry *)),
	       krb5_pointer ));
#endif /* KRB5_KDB5_DBM__ */

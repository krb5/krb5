/*
 * kadmin/v5server/keytab.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#include "k5-int.h"
#include "kdb_dbc.h"

krb5_error_code krb5_ktkdb_get_entry(krb5_context, krb5_keytab, krb5_principal,
		   krb5_kvno, krb5_enctype, krb5_keytab_entry *);

krb5_kt_ops krb5_kt_kdb_ops = {
    0,
    "KDB", 	/* Prefix -- this string should not appear anywhere else! */
    NULL,
    NULL,
    NULL,
    krb5_ktkdb_get_entry,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, 		/* (void *) &krb5_ktfile_ser_entry */
};

typedef struct krb5_ktkdb_data {
    char * name;
} krb5_ktkdb_data;

krb5_error_code
krb5_ktkdb_resolve(context, kdb, id)
    krb5_context  	  context;
    krb5_db_context 	* kdb;
    krb5_keytab		* id;
{
    krb5_db_context 	* data;

    if ((*id = (krb5_keytab) malloc(sizeof(**id))) == NULL)
        return(ENOMEM);

    if ((data = (krb5_ktkdb_data *)malloc(sizeof(krb5_db_context))) == NULL) {
        krb5_xfree(*id);
        return(ENOMEM);
    }

    memcpy(data, kdb, sizeof(krb5_db_context)); 
    (*id)->data = (krb5_pointer)data;
    (*id)->ops = &krb5_kt_kdb_ops;
    (*id)->magic = KV5M_KEYTAB;
    return(0);
}

krb5_error_code
krb5_ktkdb_get_entry(context, id, principal, kvno, enctype, entry)
    krb5_context 	  context;
    krb5_keytab 	  id;
    krb5_principal 	  principal;
    krb5_kvno 	 	  kvno;
    krb5_enctype 	  enctype;
    krb5_keytab_entry 	* entry;
{
    krb5_encrypt_block  * master_key;
    krb5_error_code 	  kerror = 0;
    krb5_key_data 	* key_data;
    krb5_db_entry 	  db_entry;
    krb5_boolean 	  more = 0;
    int 	 	  n = 0;

    /* Open database */
    /* krb5_dbm_db_init(context); */
    if (kerror = krb5_dbm_db_open_database(context)) 
        return(kerror);

    /* get_principal */
    if (kerror = krb5_dbm_db_get_principal(context, principal, &db_entry,
					   &n, &more)) {
        krb5_dbm_db_close_database(context);
        return(kerror);
    }

    /* match key */
    krb5_dbm_db_get_mkey(context, id->ops, &master_key);
    krb5_dbe_find_enctype(context, &db_entry, enctype, -1, kvno, &key_data);
    if (kerror = krb5_dbekd_decrypt_key_data(context, master_key, key_data, 
					     &entry->key, NULL)) 
	goto error;

    if (kerror = krb5_copy_principal(context, principal, &entry->principal)) 
	goto error;

    /* Close database */
error:;
    krb5_dbe_free_contents(context, &db_entry);
    krb5_dbm_db_close_database(context);
    return(kerror);
}


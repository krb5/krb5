/*
 * lib/kdb/kdb_cpw.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#include "k5-int.h"
#include <stdio.h>
#include <errno.h>

/*
 * Change password for a krb5_db_entry for a specific key version number
 */
krb5_error_code
krb5_kdb_cpw_dbe_for_kvno(context, db_entry, password, kvno) 
    krb5_context	  context;
    krb5_db_entry	* db_entry;
    char 		* password;
    int			  kvno;
{
    krb5_error_code 	  retval;
    int			  key;

    for (key = 0; key < db_entry.n_key_data; key++) {
	if (db_entry.key_data[key] == kvno) {
	}
    }
    return retval;
}

/*
 * Change password for a krb5_db_entry 
 * Assumes the max kvno
 */
krb5_error_code
krb5_kdb_cpw_dbe_for_kvno(context, db_entry, password) 
    krb5_context	  context;
    krb5_db_entry	* db_entry;
    char 		* password;
    int			  kvno;
{
    int			  key, kvno;

    for (kvno = key = 0; key < db_entry.n_key_data; key++) {
	if (kvno < db_entry.key_data[key].key_data_kvno) {
	    kvno = db_entry.key_data[key].key_data_kvno;
	}
    }
    return(krb5_kdb_cpw_dbe_for_kvno(context, db_entry, password, kvno));
}

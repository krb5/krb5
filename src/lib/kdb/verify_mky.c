/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * 
 * krb5_db_verify_master_key();
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_verify_mky_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/ext-proto.h>

/*
 * Verify that the master key in *mkey matches the database entry
 * for mprinc.
 *
 * eblock points to an encrypt_block used for the realm in question.
 */

krb5_error_code
krb5_db_verify_master_key(mprinc, mkey, eblock)
krb5_principal mprinc;
krb5_keyblock *mkey;
krb5_encrypt_block *eblock;
{
    krb5_error_code retval;
    krb5_db_entry master_entry;
    int nprinc;
    krb5_boolean more;
    krb5_keyblock tempkey;

    nprinc = 1;
    if (retval = krb5_db_get_principal(mprinc, &master_entry, &nprinc, &more))
	return(retval);
	
    if (nprinc != 1) {
	if (nprinc)
	    krb5_db_free_principal(&master_entry, nprinc);
	return(KRB5_KDB_NOMASTERKEY);
    } else if (more) {
	krb5_db_free_principal(&master_entry, nprinc);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }	

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(eblock, mkey)) {
	krb5_db_free_principal(&master_entry, nprinc);
	return(retval);
    }
    if (retval = krb5_kdb_decrypt_key(eblock, &master_entry.key, &tempkey)) {
	(void) krb5_finish_key(eblock);
	krb5_db_free_principal(&master_entry, nprinc);
	return retval;
    }
    if (mkey->length != tempkey.length ||
	memcmp((char *)mkey->contents, (char *)tempkey.contents,mkey->length)) {
	retval = KRB5_KDB_BADMASTERKEY;
	(void) krb5_finish_key(eblock);
    } else
	retval = krb5_finish_key(eblock);

    memset((char *)tempkey.contents, 0, tempkey.length);
    xfree(tempkey.contents);
    krb5_db_free_principal(&master_entry, nprinc);
    
    return retval;
}

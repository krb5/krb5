/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 * 
 * krb5_db_verify_master_key();
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_verify_mky_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/krb5_err.h>
#include <krb5/kdb5_err.h>
#include <errno.h>

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
    if (retval = (*eblock->crypto_entry->process_key)(eblock, mkey)) {
	return(retval);
    }
    if (retval = krb5_kdb_decrypt_key(eblock, &master_entry.key, &tempkey)) {
	(void) (*eblock->crypto_entry->finish_key)(eblock);
	return retval;
    }
    if (!bcmp((char *)mkey->contents, (char *)tempkey.contents,
	      mkey->length)) {
	retval = KRB5_KDB_BADMASTERKEY;
	(void) (*eblock->crypto_entry->finish_key)(eblock);
    } else
	retval = (*eblock->crypto_entry->finish_key)(eblock);
    
    return retval;
}

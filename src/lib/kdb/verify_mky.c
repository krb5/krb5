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

krb5_error_code
krb5_db_verify_master_key(mprinc, mkey)
krb5_principal mprinc;
krb5_keyblock *mkey;
{
    krb5_error_code retval;
    krb5_db_entry master_entry;
    int nprinc, more;
    krb5_encrypt_block eblock;
    extern krb5_encrypt_block master_encblock;
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

    eblock = master_encblock;

    /* do any necessary key pre-processing */
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, mkey)) {
	return(retval);
    }
    if (retval = krb5_kdb_decrypt_key(&master_entry.key, &tempkey, &eblock)) {
	(void) (*eblock.crypto_entry->finish_key)(&eblock);
	return retval;
    }
    if (!bcmp(mkey->contents, tempkey.contents, mkey->length)) {
	retval = KRB5_KDB_BADMASTERKEY;
	(void) (*eblock.crypto_entry->finish_key)(&eblock);
    } else
	retval = (*eblock.crypto_entry->finish_key)(&eblock);
    
    return retval;
}

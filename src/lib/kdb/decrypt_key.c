/*
 * lib/kdb/decrypt_key.c
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
 * krb5_kdb_encrypt_key(), krb5_kdb_decrypt_key functions
 */

#include "k5-int.h"

/*
 * Decrypt a key from storage in the database.  "eblock" is used
 * to decrypt the key in "in" into "out"; the storage pointed to by "out"
 * is allocated before use.
 */

krb5_error_code
krb5_dbekd_decrypt_key_data(context, eblock, key_data, keyblock, keysalt)
    krb5_context 	  context;
    krb5_encrypt_block 	* eblock;
    const krb5_key_data	* key_data;
    krb5_keyblock 	* keyblock;
    krb5_keysalt 	* keysalt;
{
    krb5_error_code 	  retval;
    krb5_int16		  tmplen;
    krb5_octet		* ptr;

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->enctype = key_data->key_data_type[0];

    /* Decrypt key_data_contents */
    if ((keyblock->contents = (krb5_octet *)malloc(krb5_encrypt_size(
      key_data->key_data_length[0] - 2, eblock->crypto_entry))) == NULL)
	return ENOMEM;

    keyblock->length = 0;
    ptr = key_data->key_data_contents[0];
    krb5_kdb_decode_int16(ptr, tmplen);
    ptr += 2;
    keyblock->length = (int) tmplen;
    if ((retval = krb5_decrypt(context, (krb5_pointer) ptr,
			       (krb5_pointer)keyblock->contents,
			       key_data->key_data_length[0] - 2, 
			       eblock, 0))) {
    	krb5_xfree(keyblock->contents);
	keyblock->contents = 0;
	keyblock->length = 0;
	return retval;
    }

    /* Decode salt data */
    if (keysalt) {
	if (key_data->key_data_ver == 2) {
	    keysalt->type = key_data->key_data_type[1];
	    if (keysalt->data.length = key_data->key_data_length[1]) {
		if (!(keysalt->data.data=(char *)malloc(keysalt->data.length))){
		    krb5_xfree(keyblock->contents);
		    keyblock->contents = 0;
		    keyblock->length = 0;
		    return ENOMEM;
		}
		memcpy(keysalt->data.data, key_data->key_data_contents[1],
		       (size_t) keysalt->data.length);
	    } else
		keysalt->data.data = (char *) NULL;
	} else {
	    keysalt->type = KRB5_KDB_SALTTYPE_NORMAL;
	    keysalt->data.length = 0;
	}
    }
    return retval;
}

/*
 * lib/kdb/encrypt_key.c
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
 * Encrypt a key for storage in the database.  "eblock" is used
 * to encrypt the key in "in" into "out"; the storage pointed to by "out"
 * is allocated before use.
 */

krb5_error_code
krb5_dbekd_encrypt_key_data(context, eblock, keyblock, keysalt, keyver,key_data)
    krb5_context 		  context;
    krb5_encrypt_block 		* eblock;
    const krb5_keyblock 	* keyblock;
    const krb5_keysalt		* keysalt;
    int				  keyver;
    krb5_key_data	        * key_data;
{
    krb5_error_code 		  retval;
    krb5_keyblock 		  tmp;
    krb5_octet			* ptr;
    krb5_int16			  len;
    int				  i;

    for (i = 0; i < key_data->key_data_ver; i++)
	if (key_data->key_data_contents[i])
	    krb5_xfree(key_data->key_data_contents[i]);

    key_data->key_data_ver = 1;
    key_data->key_data_kvno = keyver;

    /* 
     * The First element of the type/length/contents 
     * fields is the key type/length/contents
     */
    key_data->key_data_type[0] = keyblock->keytype;
    key_data->key_data_length[0] = krb5_encrypt_size(keyblock->length, 
						     eblock->crypto_entry) + 2;

    /* 
     * because of checksum space requirements imposed by the encryption
     * interface, we need to copy the input key into a larger area. 
     */
    tmp.contents = (krb5_octet *)malloc(key_data->key_data_length[0] - 2);
    len = tmp.length = keyblock->length;
    if (tmp.contents == NULL)
	return ENOMEM;

    memcpy((char *)tmp.contents, (const char *)keyblock->contents, tmp.length);
    key_data->key_data_contents[0] = ptr = (krb5_octet *)malloc(
					key_data->key_data_length[0]);
    if (key_data->key_data_contents[0] == NULL) {
	krb5_xfree(tmp.contents);
	return ENOMEM;
    }

    krb5_kdb_encode_int16(len, ptr);
    ptr += 2;
    if ((retval = krb5_encrypt(context, (krb5_pointer) tmp.contents,
			       (krb5_pointer)(ptr), tmp.length,
			       eblock, 0))) {
	krb5_xfree(key_data->key_data_contents[0]);
    	krb5_xfree(tmp.contents);
	return retval;
    }

    krb5_xfree(tmp.contents);

    /* After key comes the salt in necessary */
    if (keysalt) {
	key_data->key_data_type[1] = keysalt->type;
	if (key_data->key_data_type[1] >= 0) {
	    key_data->key_data_ver++;
	    key_data->key_data_length[1] = keysalt->data.length;
	    if (keysalt && keysalt->data.length) {
		key_data->key_data_contents[1] =
		    (krb5_octet *)malloc(keysalt->data.length);
		if (key_data->key_data_contents[1] == NULL) {
		    krb5_xfree(key_data->key_data_contents[0]);
		    return ENOMEM;
		}
		memcpy(key_data->key_data_contents[1],
		       keysalt->data.data,
		       (size_t) keysalt->data.length);
	    }
	}
    }
    return retval;
}

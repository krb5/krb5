/*
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

/*
 * This routine takes a key and a krb5_enc_data structure as input, and
 * outputs the decrypted data in a krb5_data structure.  Note that
 * the krb5_data structure is not allocated.
 */
krb5_error_code
krb5_decrypt_data(context, key, ivec, enc_data, data)
    krb5_context	context;
    krb5_keyblock *	key;
    krb5_pointer	ivec;
    krb5_enc_data *	enc_data;
    krb5_data *		data;
{
    krb5_error_code	retval;
    krb5_encrypt_block	eblock;

    krb5_use_enctype(context, &eblock, key->enctype);
    data->length = enc_data->ciphertext.length;
    if (!(data->data = malloc(data->length)))
	return ENOMEM;

    if ((retval = krb5_process_key(context, &eblock, key)) != 0)
	goto cleanup;

    if ((retval = krb5_decrypt(context,
			       (krb5_pointer) enc_data->ciphertext.data,
			       (krb5_pointer) data->data,
			       enc_data->ciphertext.length, &eblock, ivec))) {
    	krb5_finish_key(context, &eblock);
        goto cleanup;
    }
    (void) krb5_finish_key(context, &eblock);

    return 0;

cleanup:
    if (data->data) {
	free(data->data);
	data->data = 0;
    }
    return retval;
}

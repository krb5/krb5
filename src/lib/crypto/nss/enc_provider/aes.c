/*
 * lib/crypto/nss/enc_provider/aes.c
 *
 * Copyright (C) 2003, 2007, 2008, 2009 by the Massachusetts Institute of Technology.
 * Copyright (C) 2010 Red Hat, Inc.
 * All rights reserved.
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
 */

#include "k5-int.h"
#include "enc_provider.h"
#include "rand2key.h"
#include "aead.h"
#include "nss_gen.h"


krb5_error_code
krb5int_aes_encrypt(krb5_key key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int ret;
    ret = k5_nss_gen_import(key, CKM_AES_CBC, CKA_ENCRYPT);
    if (ret != 0) {
	return ret;
    }
    return k5_nss_gen_cts_iov(key, CKM_AES_CBC, CKA_ENCRYPT, 
				ivec, data, num_data);
}

krb5_error_code
krb5int_aes_decrypt(krb5_key key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int ret;
    ret = k5_nss_gen_import(key, CKM_AES_CBC, CKA_DECRYPT);
    if (ret != 0) {
	return ret;
    }
    return k5_nss_gen_cts_iov(key, CKM_AES_CBC, CKA_DECRYPT, 
				ivec, data, num_data);
}

/*
 * perhaps we should store the NSS context in the krb5_data state here?
 */
static krb5_error_code
aes_init_state (const krb5_keyblock *key, krb5_keyusage usage,
			krb5_data *state)
{
    state->length = 16;
    state->data = (void *) malloc(16);
    if (state->data == NULL)
	return ENOMEM;
    memset(state->data, 0, state->length);
    return 0;
}

const struct krb5_enc_provider krb5int_enc_aes128 = {
    16,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_make_key,
    aes_init_state,
    krb5int_default_free_state,
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    16,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_make_key,
    aes_init_state,
    krb5int_default_free_state,
    k5_nss_gen_cleanup
};

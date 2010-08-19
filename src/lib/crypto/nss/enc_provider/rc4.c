/*  lib/crypto/nss/enc_provider/rc4.c
 *
 * #include STD_DISCLAIMER
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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

/* arcfour.c
 *
 * Copyright (c) 2000 by Computer Science Laboratory,
 *                       Rensselaer Polytechnic Institute
 *
 * #include STD_DISCLAIMER
 */


#include "k5-int.h"
#include <aead.h>
#include <rand2key.h>
#include "nss_gen.h"

#define RC4_KEY_SIZE 16
#define RC4_BLOCK_SIZE 1

/* In-place IOV crypto */
static krb5_error_code
k5_arcfour_encrypt_iov(krb5_key key,
               const krb5_data *state,
               krb5_crypto_iov *data,
               size_t num_data)
{
    int ret;
    ret = k5_nss_gen_import(key, CKM_RC4, CKA_ENCRYPT);
    if (ret != 0) {
	return ret;
    }
    return k5_nss_gen_stream_iov(key, state, CKM_RC4, CKA_ENCRYPT, 
				 data, num_data);
}

/* In-place IOV crypto */
static krb5_error_code
k5_arcfour_decrypt_iov(krb5_key key,
               const krb5_data *state,
               krb5_crypto_iov *data,
               size_t num_data)
{
    int ret;
    ret = k5_nss_gen_import(key, CKM_RC4, CKA_DECRYPT);
    if (ret != 0) {
	return ret;
    }
    return k5_nss_gen_stream_iov(key, state, CKM_RC4, CKA_DECRYPT, 
				 data, num_data);
}

static krb5_error_code
k5_arcfour_free_state ( krb5_data *state)
{
   return k5_nss_stream_free_state(state);
}

static krb5_error_code
k5_arcfour_init_state (const krb5_keyblock *key,
                       krb5_keyusage keyusage, krb5_data *new_state)
{
   /* key can't quite be used here. see comment in k5_arcfour_init_state */
   return k5_nss_stream_init_state(new_state);

}

const struct krb5_enc_provider krb5int_enc_arcfour = {
    /* This seems to work... although I am not sure what the
       implications are in other places in the kerberos library */
    RC4_BLOCK_SIZE,
    /* Keysize is arbitrary in arcfour, but the constraints of the
       system, and to attempt to work with the MSFT system forces us
       to 16byte/128bit.  Since there is no parity in the key, the
       byte and length are the same.  */
    RC4_KEY_SIZE, RC4_KEY_SIZE,
    k5_arcfour_encrypt_iov,
    k5_arcfour_decrypt_iov,
    NULL,
    krb5int_arcfour_make_key,
    k5_arcfour_init_state, 
    k5_arcfour_free_state,
    k5_nss_gen_cleanup
};

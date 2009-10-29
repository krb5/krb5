/*  lib/crypto/openssl/enc_provider/rc4.c
 *
 * #include STD_DISCLAIMER
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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
#include <openssl/evp.h>

#define RC4_KEY_SIZE 16
#define RC4_BLOCK_SIZE 1 

/* Interface layer to kerb5 crypto layer */

/* prototypes */
static krb5_error_code
k5_arcfour_docrypt(krb5_key, const krb5_data *,
           const krb5_data *, krb5_data *);
static krb5_error_code 
k5_arcfour_free_state ( krb5_data *state);
static krb5_error_code
k5_arcfour_init_state (const krb5_keyblock *key,
               krb5_keyusage keyusage, krb5_data *new_state);

/* The workhorse of the arcfour system,
 * this impliments the cipher
 */

/* In-place rc4 crypto */
static krb5_error_code
k5_arcfour_docrypt(krb5_key key, const krb5_data *state,
           const krb5_data *input, krb5_data *output)
{
    int ret = 0, tmp_len = 0;
    unsigned char   *tmp_buf = NULL;
    EVP_CIPHER_CTX  ciph_ctx;

    if (key->keyblock.length != RC4_KEY_SIZE)
        return(KRB5_BAD_KEYSIZE);

    if (input->length != output->length)
        return(KRB5_BAD_MSIZE);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_rc4(), NULL, key->keyblock.contents, NULL);
    if (ret) {
        tmp_buf=(unsigned char *)output->data;
        ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf,  &tmp_len,
                                (unsigned char *)input->data, input->length);
        output->length = tmp_len;
    }
    if (ret) {
        tmp_buf += tmp_len;
        ret = EVP_EncryptFinal_ex(&ciph_ctx, tmp_buf, &tmp_len);
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;

    output->length += tmp_len;

    return 0;
}

/* In-place IOV crypto */
static krb5_error_code
k5_arcfour_docrypt_iov(krb5_key key,
               const krb5_data *state,
               krb5_crypto_iov *data,
               size_t num_data)
{
    size_t i;
    int ret = 0, tmp_len = 0;
    unsigned char   *tmp_buf = NULL;
    krb5_crypto_iov *iov     = NULL;
    EVP_CIPHER_CTX  ciph_ctx;


    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_rc4(), NULL, key->keyblock.contents, NULL);
    if (!ret){
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    for (i = 0; i < num_data; i++) {
        iov = &data[i];
        if (iov->data.length <= 0) break;
        tmp_len = iov->data.length;

        if (ENCRYPT_IOV(iov)) {
            tmp_buf=(unsigned char *)iov->data.data;
            ret = EVP_EncryptUpdate(&ciph_ctx,
                      tmp_buf, &tmp_len,
                      (unsigned char *)iov->data.data, iov->data.length);
            if (!ret) break;
            iov->data.length = tmp_len;
        }
    }
    if(ret)
        ret = EVP_EncryptFinal_ex(&ciph_ctx, (unsigned char *)tmp_buf, &tmp_len);

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;

    iov->data.length += tmp_len;

    return 0;
}

static krb5_error_code
k5_arcfour_free_state ( krb5_data *state)
{
   return 0; /* not implemented */
}

static krb5_error_code
k5_arcfour_init_state (const krb5_keyblock *key,
                       krb5_keyusage keyusage, krb5_data *new_state)
{
   return 0; /* not implemented */

}

/* Since the arcfour cipher is identical going forwards and backwards, 
   we just call "docrypt" directly
*/
const struct krb5_enc_provider krb5int_enc_arcfour = {
    /* This seems to work... although I am not sure what the
       implications are in other places in the kerberos library */
    RC4_BLOCK_SIZE,
    /* Keysize is arbitrary in arcfour, but the constraints of the
       system, and to attempt to work with the MSFT system forces us
       to 16byte/128bit.  Since there is no parity in the key, the
       byte and length are the same.  */
    RC4_KEY_SIZE, RC4_KEY_SIZE, 
    k5_arcfour_docrypt,
    k5_arcfour_docrypt,
    krb5int_arcfour_make_key,
    k5_arcfour_init_state, /*xxx not implemented */
    k5_arcfour_free_state, /*xxx not implemented */
    k5_arcfour_docrypt_iov,
    k5_arcfour_docrypt_iov
};


/*
 * lib/crypto/krb/dk/checksum_gmac.c
 *
 * Copyright 2010 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "etypes.h"
#include "dk.h"
#include "aead.h"
#include "cksumtypes.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

krb5_error_code
krb5int_dk_gmac_checksum(const struct krb5_cksumtypes *ctp,
                         krb5_key key, krb5_keyusage usage,
                         const krb5_crypto_iov *data, size_t num_data,
                         krb5_data *output)
{
    const struct krb5_keytypes *ktp;
    const struct krb5_enc_provider *enc;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data datain;
    krb5_key kc;
    unsigned int header_len;
    unsigned int trailer_len;
    krb5_crypto_iov *sign_data;
    size_t i;

    /* Use the key's enctype (more flexible than setting an enctype in ctp). */
    ktp = find_enctype(key->keyblock.enctype);
    if (ktp == NULL)
        return KRB5_BAD_ENCTYPE;
    enc = ktp->enc;
    if (key->keyblock.length != enc->keylength)
        return KRB5_BAD_KEYSIZE;

    header_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_HEADER);
    trailer_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_TRAILER);

    if (ctp->compute_size != header_len + trailer_len)
        return KRB5_BAD_MSIZE;

    if (output->length < ctp->compute_size)
        return KRB5_BAD_MSIZE;

    sign_data = k5alloc((num_data + 2) * sizeof(krb5_crypto_iov), &ret);
    if (sign_data == NULL)
        return ret;

    for (i = 0; i < num_data; i++) {
        sign_data[i].data = data[i].data;

        if (SIGN_IOV(&data[i])) {
            sign_data[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
        } else {
            sign_data[i].flags = KRB5_CRYPTO_TYPE_EMPTY;
        }
    }

    sign_data[i].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[i].data = make_data(output->data, header_len);
    i++;

    sign_data[i].flags = KRB5_CRYPTO_TYPE_TRAILER;
    sign_data[i].data = make_data(&output->data[header_len], trailer_len);
    i++;

    /* Derive the key. */
    datain = make_data(constantdata, K5CLENGTH);
    store_32_be(usage, constantdata);
    constantdata[4] = (char) 0x99;
    ret = krb5int_derive_key(enc, key, &kc, &datain);
    if (ret != 0) {
        free(sign_data);
        return ret;
    }

    /* Hash the data. */
    ret = krb5int_gcm_encrypt(ktp, kc, usage, NULL, sign_data, i);
    if (ret != 0)
        memset(output->data, 0, output->length);

    output->length = header_len + trailer_len;

    krb5_k_free_key(NULL, kc);
    free(sign_data);
    return ret;
}

krb5_error_code
krb5int_dk_gmac_verify(const struct krb5_cksumtypes *ctp,
                       krb5_key key, krb5_keyusage usage,
                       const krb5_crypto_iov *data, size_t num_data,
                       const krb5_data *input, krb5_boolean *valid)
{
    const struct krb5_keytypes *ktp;
    const struct krb5_enc_provider *enc;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data datain;
    krb5_key kc;
    unsigned int header_len;
    unsigned int trailer_len;
    krb5_crypto_iov *sign_data;
    size_t i;

    *valid = FALSE;

    /* Use the key's enctype (more flexible than setting an enctype in ctp). */
    ktp = find_enctype(key->keyblock.enctype);
    if (ktp == NULL)
        return KRB5_BAD_ENCTYPE;
    enc = ktp->enc;
    if (key->keyblock.length != enc->keylength)
        return KRB5_BAD_KEYSIZE;

    header_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_HEADER);
    trailer_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_TRAILER);

    if (ctp->compute_size != header_len + trailer_len)
        return KRB5_BAD_MSIZE;

    if (input->length != ctp->compute_size)
        return KRB5_BAD_MSIZE;

    sign_data = k5alloc((num_data + 2) * sizeof(krb5_crypto_iov), &ret);
    if (sign_data == NULL)
        return ret;

    for (i = 0; i < num_data; i++) {
        sign_data[i].data = data[i].data;

        if (SIGN_IOV(&data[i])) {
            sign_data[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
        } else {
            sign_data[i].flags = KRB5_CRYPTO_TYPE_EMPTY;
        }
    }

    sign_data[i].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[i].data = make_data(input->data, header_len);
    i++;

    sign_data[i].flags = KRB5_CRYPTO_TYPE_TRAILER;
    sign_data[i].data = make_data(&input->data[header_len], trailer_len);
    i++;

    /* Derive the key. */
    datain = make_data(constantdata, K5CLENGTH);
    store_32_be(usage, constantdata);
    constantdata[4] = (char) 0x99;
    ret = krb5int_derive_key(enc, key, &kc, &datain);
    if (ret != 0) {
        free(sign_data);
        return ret;
    }

    /* Verify the data. */
    ret = krb5int_gcm_decrypt(ktp, kc, usage, NULL, sign_data, i);
    if (ret == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
        ret = 0;
    } else if (ret == 0) {
        *valid = TRUE;
    }

    krb5_k_free_key(NULL, kc);
    free(sign_data);

    return ret;
}


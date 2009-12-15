/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/arcfour/arcfour_aead.c
 *
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
#include "arcfour.h"
#include "arcfour-int.h"
#include "hash_provider/hash_provider.h"
#include "aead.h"

/* AEAD */

unsigned int
krb5int_arcfour_crypto_length(const struct krb5_keytypes *ktp,
                              krb5_cryptotype type)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
        return ktp->hash->hashsize + CONFOUNDERLENGTH;
    case KRB5_CRYPTO_TYPE_PADDING:
    case KRB5_CRYPTO_TYPE_TRAILER:
        return 0;
    case KRB5_CRYPTO_TYPE_CHECKSUM:
        return ktp->hash->hashsize;
    default:
        assert(0 &&
               "invalid cryptotype passed to krb5int_arcfour_crypto_length");
        return 0;
    }
}

/* Encrypt or decrypt using a keyblock. */
static krb5_error_code
keyblock_crypt(const struct krb5_enc_provider *enc, krb5_keyblock *keyblock,
               const krb5_data *ivec, krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;
    krb5_key key;

    ret = krb5_k_create_key(NULL, keyblock, &key);
    if (ret != 0)
        return ret;
    /* Works for encryption or decryption since arcfour is a stream cipher. */
    ret = enc->encrypt(key, ivec, data, num_data);
    krb5_k_free_key(NULL, key);
    return ret;
}

krb5_error_code
krb5int_arcfour_encrypt(const struct krb5_keytypes *ktp, krb5_key key,
                        krb5_keyusage usage, const krb5_data *ivec,
                        krb5_crypto_iov *data, size_t num_data)
{
    const struct krb5_enc_provider *enc = ktp->enc;
    const struct krb5_hash_provider *hash = ktp->hash;
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer;
    krb5_keyblock *usage_keyblock = NULL, *enc_keyblock = NULL;
    krb5_data checksum, confounder, header_data;
    size_t i;

    /*
     * Caller must have provided space for the header, padding
     * and trailer; per RFC 4757 we will arrange it as:
     *
     *      Checksum | E(Confounder | Plaintext)
     */

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL ||
        header->data.length < hash->hashsize + CONFOUNDERLENGTH)
        return KRB5_BAD_MSIZE;

    header_data = header->data;

    /* Trailer may be absent. */
    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer != NULL)
        trailer->data.length = 0;

    /* Ensure that there is no padding. */
    for (i = 0; i < num_data; i++) {
        if (data[i].flags == KRB5_CRYPTO_TYPE_PADDING)
            data[i].data.length = 0;
    }

    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &usage_keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Derive a usage key from the session key and usage. */
    ret = krb5int_arcfour_usage_key(enc, hash, &key->keyblock, usage,
                                    usage_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Generate a confounder in the header block, after the checksum. */
    header->data.length = hash->hashsize + CONFOUNDERLENGTH;
    confounder = make_data(header->data.data + hash->hashsize,
                           CONFOUNDERLENGTH);
    ret = krb5_c_random_make_octets(0, &confounder);
    if (ret != 0)
        goto cleanup;
    checksum = make_data(header->data.data, hash->hashsize);

    /* Adjust pointers so confounder is at start of header. */
    header->data.length -= hash->hashsize;
    header->data.data += hash->hashsize;

    /* Compute the checksum using the usage key. */
    ret = krb5int_hmac_keyblock(hash, usage_keyblock, data, num_data,
                                &checksum);
    if (ret != 0)
        goto cleanup;

    /* Derive the encryption key from the usage key and checksum. */
    ret = krb5int_arcfour_enc_key(enc, hash, usage_keyblock, &checksum,
                                  enc_keyblock);
    if (ret)
        goto cleanup;

    ret = keyblock_crypt(enc, enc_keyblock, ivec, data, num_data);

cleanup:
    header->data = header_data; /* Restore header pointers. */
    krb5int_c_free_keyblock(NULL, usage_keyblock);
    krb5int_c_free_keyblock(NULL, enc_keyblock);
    return ret;
}

krb5_error_code
krb5int_arcfour_decrypt(const struct krb5_keytypes *ktp, krb5_key key,
                        krb5_keyusage usage, const krb5_data *ivec,
                        krb5_crypto_iov *data, size_t num_data)
{
    const struct krb5_enc_provider *enc = ktp->enc;
    const struct krb5_hash_provider *hash = ktp->hash;
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer;
    krb5_keyblock *usage_keyblock = NULL, *enc_keyblock = NULL;
    krb5_data checksum, header_data, comp_checksum = empty_data();

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL ||
        header->data.length != hash->hashsize + CONFOUNDERLENGTH)
        return KRB5_BAD_MSIZE;

    header_data = header->data;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer != NULL && trailer->data.length != 0)
        return KRB5_BAD_MSIZE;

    /* Allocate buffers. */
    ret = alloc_data(&comp_checksum, hash->hashsize);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &usage_keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &enc_keyblock);
    if (ret != 0)
        goto cleanup;

    checksum = make_data(header->data.data, hash->hashsize);

    /* Adjust pointers so confounder is at start of header. */
    header->data.length -= hash->hashsize;
    header->data.data += hash->hashsize;

    /* We may have to try two usage values; see below. */
    do {
        /* Derive a usage key from the session key and usage. */
        ret = krb5int_arcfour_usage_key(enc, hash, &key->keyblock, usage,
                                        usage_keyblock);
        if (ret != 0)
            goto cleanup;

        /* Derive the encryption key from the usage key and checksum. */
        ret = krb5int_arcfour_enc_key(enc, hash, usage_keyblock, &checksum,
                                      enc_keyblock);
        if (ret)
            goto cleanup;

        /* Decrypt the ciphertext. */
        ret = keyblock_crypt(enc, enc_keyblock, ivec, data, num_data);
        if (ret != 0)
            goto cleanup;

        /* Compute HMAC(usage key, plaintext) to get the checksum. */
        ret = krb5int_hmac_keyblock(hash, usage_keyblock, data, num_data,
                                    &comp_checksum);
        if (ret != 0)
            goto cleanup;

        if (memcmp(checksum.data, comp_checksum.data, hash->hashsize) != 0) {
            if (usage == 9) {
                /*
                 * RFC 4757 specifies usage 8 for TGS-REP encrypted parts
                 * encrypted in a subkey, but the value used by MS is actually
                 * 9.  We now use 9 to start with, but fall back to 8 on
                 * failure in case we are communicating with a KDC using the
                 * value from the RFC.  ivec is always NULL in this case.
                 * We need to re-encrypt the data in the wrong key first.
                 */
                ret = keyblock_crypt(enc, enc_keyblock, NULL, data, num_data);
                if (ret != 0)
                    goto cleanup;
                usage = 8;
                continue;
            }
            ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
            goto cleanup;
        }

        break;
    } while (1);

cleanup:
    header->data = header_data; /* Restore header pointers. */
    krb5int_c_free_keyblock(NULL, usage_keyblock);
    krb5int_c_free_keyblock(NULL, enc_keyblock);
    zapfree(comp_checksum.data, comp_checksum.length);
    return ret;
}

krb5_error_code
krb5int_arcfour_gsscrypt(const krb5_keyblock *keyblock, krb5_keyusage usage,
                         const krb5_data *kd_data, krb5_crypto_iov *data,
                         size_t num_data)
{
    const struct krb5_enc_provider *enc = &krb5int_enc_arcfour;
    const struct krb5_hash_provider *hash = &krb5int_hash_md5;
    krb5_keyblock *usage_keyblock = NULL, *enc_keyblock = NULL;
    krb5_error_code ret;

    ret = krb5int_c_init_keyblock(NULL, keyblock->enctype, enc->keybytes,
                                  &usage_keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, keyblock->enctype, enc->keybytes,
                                  &enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Derive a usage key from the session key and usage. */
    ret = krb5int_arcfour_usage_key(enc, hash, keyblock, usage,
                                    usage_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Derive the encryption key from the usage key and kd_data. */
    ret = krb5int_arcfour_enc_key(enc, hash, usage_keyblock, kd_data,
                                  enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Encrypt or decrypt (encrypt_iov works for both) the input. */
    ret = keyblock_crypt(enc, enc_keyblock, 0, data, num_data);

cleanup:
    krb5int_c_free_keyblock(NULL, usage_keyblock);
    krb5int_c_free_keyblock(NULL, enc_keyblock);
    return ret;
}

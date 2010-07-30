/*
 * lib/crypto/krb/dk/dk_ccm.c
 *
 * Copyright 2008-2010 by the Massachusetts Institute of Technology.
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
#include "dk.h"
#include "aead.h"

/*
 * Implement AEAD_AES_{128,256}_CCM as described in section 5.3 of RFC 5116.
 *
 * This is the CCM mode as described in NIST 800-38C, with a 12 byte nonce
 * and 16 byte checksum. Multiple buffers of the same type are logically
 * concatenated.
 *
 * The IOV should be laid out as follows:
 *
 *    HEADER | SIGN_DATA | DATA | PADDING | TRAILER
 *
 * SIGN_DATA and PADDING may be absent.
 *
 * Upon decryption, one can pass in explicit buffers as for encryption, or
 * one can pass in STREAM, being the concatenation of HEADER | DATA | TRAILER.
 *
 *    STREAM | SIGN_DATA | DATA
 *
 * Upon output, DATA will contain a pointer into the STREAM buffer with the
 * decrypted payload. SIGN_DATA should be ordered relative to the output DATA
 * buffer as it was upon encryption.
 *
 * For compatibility with RFC 5116, a single key is used both for encryption
 * and checksumming. The key derivation function is as follows:
 *
 *    Kc = DK(base-key, usage | 0xCC)
 *
 * Again as required by the CCM specification, SIGN_DATA is processed before
 * DATA for the purpose of checksumming.
 *
 * Because the base keys are compatible with RFC 3962, the two encryption
 * types defined here (ENCTYPE_AES128_CCM_128 and ENCTYPE_AES256_CCM_128)
 * are most useful in conjunction with RFC 4537.
 */

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

#define CCM_FLAG_MASK_Q                 0x07
#define CCM_FLAG_MASK_T                 0x38
#define CCM_FLAG_ADATA                  0x40
#define CCM_FLAG_RESERVED               0x80

unsigned int
krb5int_dk_ccm_crypto_length(const struct krb5_keytypes *ktp,
                             krb5_cryptotype type)
{
    unsigned int length;

    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
        length = 12; /* RFC 5116 5.3 */
        break;
    case KRB5_CRYPTO_TYPE_PADDING:
        length = 0; /* CTR mode requires no padding */
        break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
        length = ktp->enc->block_size;
        break;
    default:
        assert(0 && "invalid cryptotype passed to ccm_crypto_length");
        length = ~0;
        break;
    }

    return length;
}

static krb5_error_code
encode_a_len(krb5_data *a, krb5_ui_8 adata_len)
{
    size_t len;
    unsigned char *p;

    if (adata_len > (1LL << 32))
        len = 10;
    else if (adata_len > (1LL << 16) - (1LL << 8))
        len = 6;
    else if (adata_len)
        len = 2;
    else
        len = 0;

    if (a->length < len)
        return KRB5_BAD_MSIZE;

    p = (unsigned char *)a->data;

    switch (len) {
    case 2:
        p[0] = (adata_len >> 8) & 0xFF;
        p[1] = (adata_len     ) & 0xFF;
        break;
    case 6:
        p[0] = 0xFF;
        p[1] = 0xFE;
        p[2] = (adata_len >> 24) & 0xFF;
        p[3] = (adata_len >> 16) & 0xFF;
        p[4] = (adata_len >> 8 ) & 0xFF;
        p[5] = (adata_len      ) & 0xFF;
        break;
    case 10:
        p[0] = 0xFF;
        p[1] = 0xFF;
        p[2] = (adata_len >> 56) & 0xFF;
        p[3] = (adata_len >> 48) & 0xFF;
        p[4] = (adata_len >> 40) & 0xFF;
        p[5] = (adata_len >> 32) & 0xFF;
        p[6] = (adata_len >> 24) & 0xFF;
        p[7] = (adata_len >> 16) & 0xFF;
        p[8] = (adata_len >> 8 ) & 0xFF;
        p[9] = (adata_len      ) & 0xFF;
        break;
    }

    a->length = len;

    return 0;
}

/*
 * format_B0() allows the tradeoff between nonce and payload length to
 * be parameterized by replacing the crypto_length() callback
 */
static krb5_error_code
format_B0(krb5_data *B0,            /* B0 */
          krb5_data *nonce,         /* N */
          size_t trailer_len,       /* t */
          krb5_ui_8 adata_len,      /* a */
          krb5_ui_8 payload_len)    /* Q */
{
    unsigned char flags;
    unsigned char *p;
    krb5_octet q, i = 0;

    if (B0->length != 16)
        return KRB5_BAD_MSIZE;

    /* SP800-38C A.1: Length Requirements */

    /* t is an elements of {4, 6, 8, 10, 12, 14, 16} */
    if (trailer_len % 2 ||
        (trailer_len < 4 || trailer_len > 16))
        return KRB5_BAD_MSIZE;

    /* n is an element of {7, 8, 9, 10, 11, 12, 13} */
    if (nonce->length < 7 || nonce->length > 13)
        return KRB5_BAD_MSIZE;

    q = 15 - nonce->length;

    /* P consists of fewer than 2^(8q) octets */
    if (payload_len >= (1UL << (8 * q)))
        return KRB5_BAD_MSIZE;

    /* SP800-38C A.1: Formatting of the Control Information and the Nonce */
    flags = q - 1;
    flags |= (((trailer_len - 2) / 2) << 3);
    if (adata_len != 0)
        flags |= CCM_FLAG_ADATA;

    p = (unsigned char *)B0->data;
    p[i++] = flags;

    memcpy(&p[i], nonce->data, nonce->length);
    i += nonce->length;

    for (; i < B0->length; i++) {
        register krb5_octet s;

        s = (q - (i - nonce->length)) * 8;

        p[i] = (payload_len >> s) & 0xFF;
    }

    return 0;
}

/*
 * Format initial counter block. Counter may be chained
 * across invocations.
 */
static krb5_error_code
format_Ctr0(krb5_data *counter,
            const krb5_data *nonce,
            const krb5_data *state,
            unsigned int n)
{
    krb5_octet q; /* counter length */

    assert(n >= 7 && n <= 13);

    q = 15 - n;
    counter->data[0] = q - 1;
    memcpy(&counter->data[1], nonce->data, n);

    if (state != NULL)
        memcpy(&counter->data[1 + n], &state->data[1 + n], q);
    else
        memset(&counter->data[1 + n], 0, q);

    return 0;
}

static krb5_boolean
valid_payload_length_p(const struct krb5_keytypes *ktp,
                       unsigned int n,
                       unsigned int payload_len)
{
    unsigned int block_size = ktp->enc->block_size;
    unsigned int nblocks, maxblocks;
    krb5_octet q;

    assert(n >= 7 && n <= 13);

    q = 15 - n;

    maxblocks = (1U << (8 * q)) - 1 /* tag */;

    nblocks = (payload_len + block_size - 1) / block_size;

    return (nblocks <= maxblocks);
}

static krb5_error_code
ccm_encrypt(const struct krb5_keytypes *ktp,
            krb5_key kc,
            krb5_keyusage usage,
            const krb5_data *state,
            krb5_crypto_iov *data,
            size_t num_data)
{
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    size_t i, num_sign_data = 0;
    unsigned int header_len;
    unsigned int trailer_len;
    size_t payload_len = 0;
    size_t adata_len = 0;
    char adata_len_buf[6];
    unsigned char B0[16], Ctr[16];
    krb5_data counter = make_data(Ctr, sizeof(Ctr));

    header_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_HEADER);

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length < header_len) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    trailer_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_TRAILER);

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length < trailer_len) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    for (i = 0; i < num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        switch (iov->flags) {
        case KRB5_CRYPTO_TYPE_DATA:
            payload_len += iov->data.length;
            break;
        case KRB5_CRYPTO_TYPE_SIGN_ONLY:
            adata_len += iov->data.length;
            break;
        case KRB5_CRYPTO_TYPE_PADDING:
            iov->data.length = 0;
            break;
        default:
            break;
        }
    }

    if (!valid_payload_length_p(ktp, header_len, payload_len)) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    header->data.length = header_len;
    trailer->data.length = trailer_len;

    /* Initialize nonce */
    ret = krb5_c_random_make_octets(NULL, &header->data);
    if (ret != 0)
        goto cleanup;

    /* Initialize counter block */
    ret = format_Ctr0(&counter, &header->data, state, header_len);
    if (ret != 0)
        goto cleanup;

    sign_data = k5alloc((num_data + 1) * sizeof(krb5_crypto_iov), &ret);
    if (sign_data == NULL)
        goto cleanup;

    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[num_sign_data].data = make_data(B0, sizeof(B0));
    ret = format_B0(&sign_data[num_sign_data].data, &header->data, trailer_len,
                    (krb5_ui_8)adata_len, (krb5_ui_8)payload_len);
    if (ret != 0)
        goto cleanup;
    num_sign_data++;

    /* Include length of associated data in CBC-MAC */
    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    sign_data[num_sign_data].data = make_data(adata_len_buf, sizeof(adata_len_buf));
    ret = encode_a_len(&sign_data[num_sign_data].data, (krb5_ui_8)adata_len);
    if (ret != 0)
        goto cleanup;
    num_sign_data++;

    /* Reorder input IOV so SIGN_ONLY data is before DATA */
    for (i = 0; i < num_data; i++) {
        if (data[i].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
            sign_data[num_sign_data++] = data[i];
    }
    for (i = 0; i < num_data; i++) {
        if (data[i].flags == KRB5_CRYPTO_TYPE_DATA)
            sign_data[num_sign_data++] = data[i];
    }

    assert(ktp->enc->encrypt != NULL);
    assert(ktp->enc->cbc_mac != NULL);

    /* Make checksum and place in trailer */
    ret = ktp->enc->cbc_mac(kc, sign_data, num_sign_data, NULL, &trailer->data);
    if (ret != 0)
        goto cleanup;

    /* Encrypt checksum in trailer */
    {
        krb5_crypto_iov cksum[1];

        cksum[0].flags = KRB5_CRYPTO_TYPE_DATA;
        cksum[0].data = trailer->data;

        ret = ktp->enc->encrypt(kc, &counter, cksum, 1);
        if (ret != 0)
            goto cleanup;
    }

    /* Don't encrypt B0 (header), but encrypt everything else */
    ret = ktp->enc->encrypt(kc, &counter, data, num_data);
    if (ret != 0)
        goto cleanup;

    if (state != NULL)
        memcpy(state->data, counter.data, counter.length);

cleanup:
    free(sign_data);

    return ret;
}

krb5_error_code
krb5int_dk_ccm_encrypt(const struct krb5_keytypes *ktp,
                       krb5_key key,
                       krb5_keyusage usage,
                       const krb5_data *state,
                       krb5_crypto_iov *data,
                       size_t num_data)
{
    unsigned char constantdata[K5CLENGTH];
    krb5_error_code ret;
    krb5_key kc;
    krb5_data d1;

    d1.data = (char *)constantdata;
    d1.length = K5CLENGTH;

    d1.data[0] = (usage >> 24) & 0xFF;
    d1.data[1] = (usage >> 16) & 0xFF;
    d1.data[2] = (usage >> 8 ) & 0xFF;
    d1.data[3] = (usage      ) & 0xFF;

    d1.data[4] = 0xCC;

    ret = krb5int_derive_key(ktp->enc, key, &kc, &d1);
    if (ret != 0)
        return ret;

    ret = ccm_encrypt(ktp, kc, usage, state, data, num_data);

    krb5_k_free_key(NULL, kc);

    return ret;
}

static krb5_error_code
ccm_decrypt(const struct krb5_keytypes *ktp,
            krb5_key kc,
            krb5_keyusage usage,
            const krb5_data *state,
            krb5_crypto_iov *data,
            size_t num_data)
{
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    size_t i, num_sign_data = 0;
    unsigned int header_len;
    unsigned int trailer_len;
    size_t adata_len = 0;
    size_t payload_len = 0;
    char adata_len_buf[6];
    unsigned char B0[16], Ctr[16];
    krb5_data made_cksum = empty_data();
    krb5_data counter = make_data(Ctr, sizeof(Ctr));

    header_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_HEADER);

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length != header_len) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    trailer_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_TRAILER);

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length != trailer_len) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    for (i = 0; i < num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        switch (iov->flags) {
        case KRB5_CRYPTO_TYPE_DATA:
            payload_len += iov->data.length;
            break;
        case KRB5_CRYPTO_TYPE_SIGN_ONLY:
            adata_len += iov->data.length;
            break;
        case KRB5_CRYPTO_TYPE_PADDING:
            if (iov->data.length != 0) {
                ret = KRB5_BAD_MSIZE;
                goto cleanup;
            }
            break;
        default:
            break;
        }
    }

    if (!valid_payload_length_p(ktp, header_len, payload_len)) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    /* Initialize counter block */
    ret = format_Ctr0(&counter, &header->data, state, header_len);
    if (ret != 0)
        goto cleanup;

    sign_data = k5alloc((num_data + 1) * sizeof(krb5_crypto_iov), &ret);
    if (sign_data == NULL)
        goto cleanup;

    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[num_sign_data].data = make_data(B0, sizeof(B0));
    ret = format_B0(&sign_data[num_sign_data].data, &header->data, trailer_len,
                    (krb5_ui_8)adata_len, (krb5_ui_8)payload_len);
    if (ret != 0)
        goto cleanup;
    num_sign_data++;

    /* Include length of associated data in CBC-MAC */
    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    sign_data[num_sign_data].data = make_data(adata_len_buf, sizeof(adata_len_buf));
    ret = encode_a_len(&sign_data[num_sign_data].data, (krb5_ui_8)adata_len);
    if (ret != 0)
        goto cleanup;
    num_sign_data++;

    assert(ktp->enc->decrypt != NULL);
    assert(ktp->enc->cbc_mac != NULL);

    made_cksum.data = k5alloc(trailer_len, &ret);
    if (made_cksum.data == NULL)
        goto cleanup;
    made_cksum.length = trailer_len;

    /* Decrypt checksum from trailer */
    {
        krb5_crypto_iov got_cksum[1];

        got_cksum[0].flags = KRB5_CRYPTO_TYPE_DATA;
        got_cksum[0].data = trailer->data;

        ret = ktp->enc->decrypt(kc, &counter, got_cksum, 1);
        if (ret != 0)
            goto cleanup;
    }

    /* Don't decrypt B0 (header), but decrypt everything else */
    ret = ktp->enc->decrypt(kc, &counter, data, num_data);
    if (ret != 0)
        goto cleanup;

    /* Reorder input IOV so SIGN_ONLY data is before DATA */
    for (i = 0; i < num_data; i++) {
        if (data[i].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
            sign_data[num_sign_data++] = data[i];
    }
    for (i = 0; i < num_data; i++) {
        if (data[i].flags == KRB5_CRYPTO_TYPE_DATA)
            sign_data[num_sign_data++] = data[i];
    }

    /* Now, calculate hash for comparison (including B0) */
    ret = ktp->enc->cbc_mac(kc, sign_data, num_sign_data, NULL, &made_cksum);
    if (ret != 0)
        goto cleanup;

    if (made_cksum.length != trailer->data.length ||
        memcmp(made_cksum.data, trailer->data.data, trailer->data.length) != 0) {
        ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        goto cleanup;
    }

    if (state != NULL)
        memcpy(state->data, counter.data, counter.length);

cleanup:
    free(made_cksum.data);
    free(sign_data);

    return ret;
}

krb5_error_code
krb5int_dk_ccm_decrypt(const struct krb5_keytypes *ktp,
                       krb5_key key,
                       krb5_keyusage usage,
                       const krb5_data *state,
                       krb5_crypto_iov *data,
                       size_t num_data)
{
    unsigned char constantdata[K5CLENGTH];
    krb5_error_code ret;
    krb5_key kc;
    krb5_data d1;

    d1.data = (char *)constantdata;
    d1.length = K5CLENGTH;

    d1.data[0] = (usage >> 24) & 0xFF;
    d1.data[1] = (usage >> 16) & 0xFF;
    d1.data[2] = (usage >> 8 ) & 0xFF;
    d1.data[3] = (usage      ) & 0xFF;

    d1.data[4] = 0xCC;

    ret = krb5int_derive_key(ktp->enc, key, &kc, &d1);
    if (ret != 0)
        return ret;

    ret = ccm_decrypt(ktp, kc, usage, state, data, num_data);

    krb5_k_free_key(NULL, kc);

    return ret;
}


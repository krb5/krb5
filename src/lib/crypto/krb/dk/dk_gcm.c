/*
 * lib/crypto/krb/dk/dk_gcm.c
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
#include "dk.h"
#include "aead.h"

/*
 * Implement AEAD_AES_{128,256}_GCM as described in section 5.1 of RFC 5116.
 *
 * This is the GCM mode as described in NIST 800-38D, with a 12 byte IV
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
 *    Kc = DK(base-key, usage | 0x6C)
 *
 * Again as required by the GCM specification, SIGN_DATA is processed before
 * DATA for the purpose of checksumming.
 *
 * Because the base keys are compatible with RFC 3962, the two encryption
 * types defined here (ENCTYPE_AES128_GCM_128 and ENCTYPE_AES256_GCM_128)
 * are most useful in conjunction with RFC 4537.
 */

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

#define BLOCK_SIZE 16

static char zeros[BLOCK_SIZE];

unsigned int
krb5int_dk_gcm_crypto_length(const struct krb5_keytypes *ktp,
                             krb5_cryptotype type)
{
    unsigned int length;

    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
        length = 12; /* RFC 5116 5.1 */
        break;
    case KRB5_CRYPTO_TYPE_PADDING:
        length = 0; /* CTR mode requires no padding */
        break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
        length = ktp->enc->block_size;
        assert(length <= BLOCK_SIZE); /* SP-800-38D requires this */
        break;
    default:
        assert(0 && "invalid cryptotype passed to gcm_crypto_length");
        length = ~0;
        break;
    }

    return length;
}

static krb5_boolean
valid_payload_length_p(const struct krb5_keytypes *ktp,
                       unsigned int n,
                       unsigned int payload_len)
{
    unsigned int block_size = ktp->enc->block_size;
    unsigned long nblocks, maxblocks;

    maxblocks = (1UL << 32);

    nblocks = 1; /* tag */
    nblocks += (payload_len + block_size - 1) / block_size;

    return (nblocks <= maxblocks);
}

static void
xor_128(unsigned char a[BLOCK_SIZE],
        unsigned char b[BLOCK_SIZE],
        unsigned char out[BLOCK_SIZE])
{
    unsigned char z;

    for (z = 0; z < 4; z++) {
        unsigned char *aptr = &a[z * 4];
        unsigned char *bptr = &b[z * 4];
        unsigned char *outptr = &out[z * 4];

        store_32_n(load_32_n(aptr) ^ load_32_n(bptr), outptr);
    }
}

static void
rightshift_onebit(unsigned char input[BLOCK_SIZE],
                  unsigned char output[BLOCK_SIZE])
{
    unsigned char last_overflow = 0, overflow;
    unsigned char i;

    for (i = 0; i < BLOCK_SIZE; i++) {
        overflow = (input[i] & 1) ? 0x80 : 0;
        output[i] = (input[i] >> 1) & 0x7F;
        output[i] |= last_overflow;
        last_overflow = overflow;
    }
}

static void
block_product(unsigned char X[BLOCK_SIZE],
              unsigned char Y[BLOCK_SIZE],
              unsigned char out[BLOCK_SIZE])
{
    unsigned char V[BLOCK_SIZE];
    unsigned char Z[BLOCK_SIZE];
    unsigned char i;

    memset(Z, 0, BLOCK_SIZE);
    memcpy(V, X, BLOCK_SIZE);

    for (i = 0; i < 128; i++) {
        unsigned char j = 7 - (i % 8);

        if (Y[i / 8] & (1 << j))
            xor_128(Z, V, Z);

        if (V[15] & 1) {
            rightshift_onebit(V, V);
            V[0] ^= 0xE1; /* R */
        } else
            rightshift_onebit(V, V);
    }

    memcpy(out, Z, BLOCK_SIZE);
}

static krb5_error_code
GHASH(unsigned char H[BLOCK_SIZE],
      krb5_crypto_iov *data,
      size_t num_data,
      unsigned char Y[BLOCK_SIZE])
{
    struct iov_block_state iov_state;
    unsigned char X[BLOCK_SIZE];

    memset(Y, 0, BLOCK_SIZE);

    IOV_BLOCK_STATE_INIT(&iov_state);
    iov_state.include_sign_only = 1;
    iov_state.pad_to_boundary = 1;

    while (krb5int_c_iov_get_block(X, sizeof(X), data, num_data, &iov_state)) {
        xor_128(Y, X, Y);
        block_product(Y, H, Y);
    }

    return 0;
}

/*
 * Format initial counter block. Counter may be chained
 * across invocations.
 */
static krb5_error_code
format_J0(unsigned char H[BLOCK_SIZE],
          unsigned char J0[BLOCK_SIZE],
          const krb5_data *iv,
          const krb5_data *state)
{
    if (iv->length != 12) {
        /*
         * SP800-38D 7.1.2: if a non-96-bit nonce is specified,
         * then the initial counter block is:
         *
         *    GHASH(H, IV || pad || [0]64 || [len(IV)]64)
         *
         * Note that len(IV) is the bit length of the IV.
         */
        krb5_crypto_iov ivdata[2];
        unsigned char ivlength[BLOCK_SIZE];

        store_64_be((krb5_ui_8)0,              &ivlength[0]);
        store_64_be((krb5_ui_8)iv->length * 8, &ivlength[8]);

        ivdata[0].flags = KRB5_CRYPTO_TYPE_DATA;
        ivdata[0].data = *iv;
        ivdata[1].flags = KRB5_CRYPTO_TYPE_HEADER;
        ivdata[1].data = make_data(ivlength, BLOCK_SIZE);

        GHASH(H, ivdata, 2, J0);
    } else {
        /* Otherwise J0 is IV || [1]32 */
        memcpy(J0, iv->data, iv->length);
        store_32_be(1, &J0[12]);
    }

    /*
     * If non-initial cipher state, propagate counter value
     * to support chaining.
     */
    if (state != NULL) {
        krb5_ui_4 i;

        if (state->length < 4)
            return KRB5_BAD_MSIZE;

        i = load_32_be(&state->data[state->length - 4]);
        if (i != 0)
            store_32_be(i, &J0[12]);
    }

    return 0;
}

static void
format_ICB(unsigned char J0[BLOCK_SIZE],
           unsigned char ICB[BLOCK_SIZE])
{
    krb5_ui_4 i;

    i = load_32_be(&J0[12]);
    memcpy(ICB, J0, 12);
    store_32_be(i + 1, &ICB[12]);
}

static krb5_error_code
derive_H(const struct krb5_keytypes *ktp,
         krb5_key kg,
         unsigned char H[BLOCK_SIZE])
{
    krb5_crypto_iov data[1];
    krb5_data H_data;

    data[0].flags = KRB5_CRYPTO_TYPE_DATA;
    data[0].data = make_data(zeros, sizeof(zeros));

    H_data = make_data(H, BLOCK_SIZE);

    assert(ktp->enc->cbc_mac != NULL);

    return ktp->enc->cbc_mac(kg, data, 1, NULL, &H_data);
}

krb5_error_code
krb5int_gcm_encrypt(const struct krb5_keytypes *ktp,
                    krb5_key kg,
                    krb5_keyusage usage,
                    const krb5_data *state,
                    krb5_crypto_iov *data,
                    size_t num_data)
{
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    size_t i, num_sign_data = 0;
    unsigned int header_len, trailer_len;
    size_t plain_len = 0,  adata_len = 0;
    char len_buf[BLOCK_SIZE];
    unsigned char H[BLOCK_SIZE], J0[BLOCK_SIZE];
    unsigned char ICB[BLOCK_SIZE], S[BLOCK_SIZE];
    krb5_data counter;

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
            plain_len += iov->data.length;
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

    if (!valid_payload_length_p(ktp, header_len, plain_len)) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    header->data.length = header_len;

    /* Initialize IV */
    ret = krb5_c_random_make_octets(NULL, &header->data);
    if (ret != 0)
        goto cleanup;

    /* Derive H subkey */
    ret = derive_H(ktp, kg, H);
    if (ret != 0)
        goto cleanup;

    /* Initialize counter block */
    ret = format_J0(H, J0, &header->data, state);
    if (ret != 0)
        goto cleanup;

    format_ICB(J0, ICB);
    counter = make_data((char *)ICB, sizeof(ICB));

    if (plain_len != 0) {
        /* Encrypt plaintext */
        ret = ktp->enc->encrypt(kg, &counter, data, num_data);
        if (ret != 0)
            goto cleanup;
    }

    sign_data = k5alloc((num_data + 1) * sizeof(krb5_crypto_iov), &ret);
    if (sign_data == NULL)
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

    /* Append bit length of SIGN_ONLY and DATA */
    store_64_be((krb5_ui_8)adata_len * 8, &len_buf[0]);
    store_64_be((krb5_ui_8)plain_len * 8, &len_buf[8]);

    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[num_sign_data].data = make_data(len_buf, sizeof(len_buf));
    num_sign_data++;

    /* Make checksum */
    ret = GHASH(H, sign_data, num_sign_data, S);
    if (ret != 0)
        goto cleanup;

    /* Encrypt checksum and place (possibly truncated) into trailer */
    {
        krb5_data J0_data = make_data((char *)J0, sizeof(J0));
        krb5_crypto_iov cksum[1];

        cksum[0].flags = KRB5_CRYPTO_TYPE_DATA;
        cksum[0].data = make_data(S, sizeof(S));

        ret = ktp->enc->encrypt(kg, &J0_data, cksum, 1);
        if (ret != 0)
            goto cleanup;

        memcpy(trailer->data.data, S, trailer_len);
        trailer->data.length = trailer_len;
    }

    if (state != NULL)
        memcpy(state->data, counter.data, counter.length);

cleanup:
    free(sign_data);
    zap(S, sizeof(S));
    zap(ICB, sizeof(ICB));
    zap(J0, sizeof(J0));
    zap(H, sizeof(H));

    return ret;
}

krb5_error_code
krb5int_dk_gcm_encrypt(const struct krb5_keytypes *ktp,
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

    d1.data[4] = 0x6C;

    ret = krb5int_derive_key(ktp->enc, key, &kc, &d1);
    if (ret != 0)
        return ret;

    ret = krb5int_gcm_encrypt(ktp, kc, usage, state, data, num_data);

    krb5_k_free_key(NULL, kc);

    return ret;
}

krb5_error_code
krb5int_gcm_decrypt(const struct krb5_keytypes *ktp,
                    krb5_key kg,
                    krb5_keyusage usage,
                    const krb5_data *state,
                    krb5_crypto_iov *data,
                    size_t num_data)
{
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    size_t i, num_sign_data = 0;
    unsigned int header_len, trailer_len;
    size_t plain_len = 0,  adata_len = 0;
    char len_buf[BLOCK_SIZE];
    unsigned char H[BLOCK_SIZE], J0[BLOCK_SIZE];
    krb5_data counter;
    unsigned char made_cksum[BLOCK_SIZE];
    krb5_crypto_iov made_cksum_data[1];

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
            plain_len += iov->data.length;
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

    if (!valid_payload_length_p(ktp, header_len, plain_len)) {
        ret = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    /* Derive H subkey */
    ret = derive_H(ktp, kg, H);
    if (ret != 0)
        goto cleanup;

    /* Initialize counter block */
    ret = format_J0(H, J0, &header->data, state);
    if (ret != 0)
        goto cleanup;

    counter = make_data((char *)J0, sizeof(J0));

    sign_data = k5alloc((num_data + 1) * sizeof(krb5_crypto_iov), &ret);
    if (sign_data == NULL)
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

    /* Append bit length of SIGN_ONLY and DATA */
    store_64_be((krb5_ui_8)adata_len * 8, &len_buf[0]);
    store_64_be((krb5_ui_8)plain_len * 8, &len_buf[8]);

    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[num_sign_data].data = make_data(len_buf, sizeof(len_buf));
    num_sign_data++;

    /* Calculate hash for comparison */
    ret = GHASH(H, sign_data, num_sign_data, made_cksum);
    if (ret != 0)
        goto cleanup;

    /* Encrypt checksum for comparison */
    made_cksum_data[0].flags = KRB5_CRYPTO_TYPE_DATA;
    made_cksum_data[0].data = make_data(made_cksum, sizeof(made_cksum));

    ret = ktp->enc->encrypt(kg, &counter, made_cksum_data, 1);
    if (ret != 0)
        goto cleanup;

    /* Compare (possibly truncated) checksum */
    if (memcmp(made_cksum, trailer->data.data, trailer_len) != 0) {
        ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        goto cleanup;
    }

    /* Decrypt plaintext */
    if (plain_len != 0) {
        ret = ktp->enc->decrypt(kg, &counter, data, num_data);
        if (ret != 0)
            goto cleanup;
    }

    if (state != NULL)
        memcpy(state->data, counter.data, counter.length);

cleanup:
    free(sign_data);
    zap(J0, sizeof(J0));
    zap(H, sizeof(H));
    zap(made_cksum, sizeof(made_cksum));

    return ret;
}

krb5_error_code
krb5int_dk_gcm_decrypt(const struct krb5_keytypes *ktp,
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

    d1.data[4] = 0x6C;

    ret = krb5int_derive_key(ktp->enc, key, &kc, &d1);
    if (ret != 0)
        return ret;

    ret = krb5int_gcm_decrypt(ktp, kc, usage, state, data, num_data);

    krb5_k_free_key(NULL, kc);

    return ret;
}

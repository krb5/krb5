/*
 * lib/crypto/openssl/enc_provider/aes_ctr.c
 *
 * Copyright (C) 2003, 2007-2010 by the Massachusetts Institute of Technology.
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

#ifdef AES_CCM

#include "k5-int.h"
#include "enc_provider.h"
#include "rand2key.h"
#include "aead.h"
#include "hash_provider/hash_provider.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#define NUM_BITS 8

#define CCM_FLAG_MASK_Q                0x07

#define CCM_DEFAULT_COUNTER_LEN        3 /* default q=3 from RFC 5116 5.3 */

static void
xorblock(unsigned char *out, const unsigned char *in)
{
    int z;
    for (z = 0; z < AES_BLOCK_SIZE/4; z++) {
        unsigned char *outptr = &out[z*4];
        unsigned char *inptr = (unsigned char *)&in[z*4];
        /*
         * Use unaligned accesses.  On x86, this will probably still be faster
         * than multiple byte accesses for unaligned data, and for aligned data
         * should be far better.  (One test indicated about 2.4% faster
         * encryption for 1024-byte messages.)
         *
         * If some other CPU has really slow unaligned-word or byte accesses,
         * perhaps this function (or the load/store helpers?) should test for
         * alignment first.
         *
         * If byte accesses are faster than unaligned words, we may need to
         * conditionalize on CPU type, as that may be hard to determine
         * automatically.
         */
        store_32_n (load_32_n(outptr) ^ load_32_n(inptr), outptr);
    }
}

static const EVP_CIPHER * 
map_mode(krb5_key key)
{
    switch (krb5_k_key_enctype(NULL, key)) {
    case ENCTYPE_AES128_CCM_128:
        return EVP_aes_128_cbc(); 
    case ENCTYPE_AES256_CCM_128:
        return EVP_aes_256_cbc();
    default:
        break;
    }
    return NULL;
}

/* Maximum number of invocations with a given nonce and key */
#define maxblocks(q)            (1UL << (8 * (q)))

/*
 * ivec must be a correctly formatted counter block per SP800-38C A.3
 */
static krb5_error_code
krb5int_aes_encrypt_ctr(krb5_key key,
                        const krb5_data *ivec,
                        krb5_crypto_iov *data,
                        size_t num_data)
{
    AES_KEY enck;
    unsigned char ctr[AES_BLOCK_SIZE];
    krb5_ui_8 blockno;
    struct iov_block_state input_pos, output_pos;

    AES_set_encrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &enck);

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Don't encrypt the header (B0), and use zero instead of IOV padding */
    input_pos.ignore_header = output_pos.ignore_header = 1;
    input_pos.pad_to_boundary = output_pos.pad_to_boundary = 1;

    if (ivec != NULL) {
        if (ivec->length != AES_BLOCK_SIZE || (ivec->data[0] & ~(CCM_FLAG_MASK_Q)))
            return KRB5_BAD_MSIZE;

        memcpy(ctr, ivec->data, AES_BLOCK_SIZE);
    } else {
        memset(ctr, 0, AES_BLOCK_SIZE);
        ctr[0] = CCM_DEFAULT_COUNTER_LEN - 1;
    }

    for (blockno = 0; ; blockno++) {
        unsigned char plain[AES_BLOCK_SIZE];
        unsigned char cipher[AES_BLOCK_SIZE];
        unsigned char ectr[AES_BLOCK_SIZE];
        unsigned int num = 0;

        if (blockno >= maxblocks(ctr[0] + 1))
            return KRB5_CRYPTO_INTERNAL;

        if (!krb5int_c_iov_get_block(plain, AES_BLOCK_SIZE, data, num_data, &input_pos))
            break;

        memset(ectr, 0, sizeof(ectr));
        AES_ctr128_encrypt(plain, cipher, AES_BLOCK_SIZE, &enck,
                           ctr, ectr, &num);
        assert(num == 0);

        krb5int_c_iov_put_block(data, num_data, cipher, AES_BLOCK_SIZE, &output_pos);
    }

    if (ivec != NULL)
        memcpy(ivec->data, ctr, sizeof(ctr));

    return 0;
}

static krb5_error_code
krb5int_aes_decrypt_ctr(krb5_key key,
                        const krb5_data *ivec,
                        krb5_crypto_iov *data,
                        size_t num_data)
{
    AES_KEY enck;
    unsigned char ctr[AES_BLOCK_SIZE];
    krb5_ui_8 blockno;
    struct iov_block_state input_pos, output_pos;

    AES_set_encrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &enck);

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Don't encrypt the header (B0), and use zero instead of IOV padding */
    input_pos.ignore_header = output_pos.ignore_header = 1;
    input_pos.pad_to_boundary = output_pos.pad_to_boundary = 1;

    if (ivec != NULL) {
        if (ivec->length != AES_BLOCK_SIZE || (ivec->data[0] & ~(CCM_FLAG_MASK_Q)))
            return KRB5_BAD_MSIZE;

        memcpy(ctr, ivec->data, AES_BLOCK_SIZE);
    } else {
        memset(ctr, 0, AES_BLOCK_SIZE);
        ctr[0] = CCM_DEFAULT_COUNTER_LEN - 1;
    }

    for (blockno = 0; ; blockno++) {
        unsigned char cipher[AES_BLOCK_SIZE];
        unsigned char plain[AES_BLOCK_SIZE];
        unsigned char ectr[AES_BLOCK_SIZE];
        unsigned int num = 0;

        if (blockno >= maxblocks(ctr[0] + 1))
            return KRB5_CRYPTO_INTERNAL;

        if (!krb5int_c_iov_get_block(cipher, AES_BLOCK_SIZE, data, num_data, &input_pos))
            break;

        memset(ectr, 0, sizeof(ectr));
        AES_ctr128_encrypt(cipher, plain, AES_BLOCK_SIZE, &enck,
                           ctr, ectr, &num);
        assert(num == 0);

        krb5int_c_iov_put_block(data, num_data, plain, AES_BLOCK_SIZE, &output_pos);
    }

    if (ivec != NULL)
        memcpy(ivec->data, ctr, sizeof(ctr));

    return 0;
}

static krb5_error_code
krb5int_aes_cbc_mac(krb5_key key,
                    const krb5_crypto_iov *data,
                    size_t num_data,
                    const krb5_data *iv,
                    krb5_data *output)
{
    unsigned char blockY[AES_BLOCK_SIZE];
    struct iov_block_state iov_state;
    krb5_error_code ret;
    EVP_CIPHER_CTX ciph_ctx;

    if (output->length < AES_BLOCK_SIZE)
        return KRB5_BAD_MSIZE;

    if (iv != NULL)
        memcpy(blockY, iv->data, AES_BLOCK_SIZE);
    else
        memset(blockY, 0, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX_init(&ciph_ctx);
    if (EVP_EncryptInit_ex(&ciph_ctx, map_mode(key),
                           NULL, key->keyblock.contents, NULL) == 0) {
        return KRB5_CRYPTO_INTERNAL;
    }

    IOV_BLOCK_STATE_INIT(&iov_state);
    EVP_CIPHER_CTX_set_padding(&ciph_ctx, 0);

    /*
     * The CCM header may not fit in a block, because it includes a variable
     * length encoding of the associated data length. This encoding plus the
     * associated data itself is padded to the block size.
     */
    iov_state.include_sign_only = 1;
    iov_state.pad_to_boundary = 1;

    for (ret = 0; ;) {
        unsigned char blockB[AES_BLOCK_SIZE];
        int olen = AES_BLOCK_SIZE;

        if (!krb5int_c_iov_get_block(blockB, AES_BLOCK_SIZE, data, num_data, &iov_state))
            break;

        xorblock(blockB, blockY);

        if (EVP_EncryptUpdate(&ciph_ctx, blockY, &olen, blockB, AES_BLOCK_SIZE) == 0) {
            ret = KRB5_CRYPTO_INTERNAL;
            break;
        }
    }

    output->length = AES_BLOCK_SIZE;
    memcpy(output->data, blockY, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    return ret;
}

static krb5_error_code
krb5int_aes_init_state_ctr (const krb5_keyblock *key, krb5_keyusage usage,
                                 krb5_data *state)
{
    unsigned int n, q;
    krb5_error_code code;

    code = krb5_c_crypto_length(NULL, key->enctype, KRB5_CRYPTO_TYPE_HEADER, &n);
    if (code != 0)
        return code;

    assert(n >= 7 && n <= 13);

    state->length = 16;
    state->data = k5alloc(state->length, &code);
    if (code != 0)
        return code;

    q = 15 - n;
    state->data[0] = q - 1;

    return 0;
}

const struct krb5_enc_provider krb5int_enc_aes128_ctr = {
    16,
    16, 16,
    krb5int_aes_encrypt_ctr,
    krb5int_aes_decrypt_ctr,
    krb5int_aes_cbc_mac,
    krb5int_aes_make_key,
    krb5int_aes_init_state_ctr,
    krb5int_default_free_state,
    NULL
};

const struct krb5_enc_provider krb5int_enc_aes256_ctr = {
    16,
    32, 32,
    krb5int_aes_encrypt_ctr,
    krb5int_aes_decrypt_ctr,
    krb5int_aes_cbc_mac,
    krb5int_aes_make_key,
    krb5int_aes_init_state_ctr,
    krb5int_default_free_state,
    NULL
};

#endif

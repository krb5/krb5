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

    assert(ivec != NULL);

    if (ivec->length != AES_BLOCK_SIZE)
        return KRB5_BAD_MSIZE;

    memcpy(ctr, ivec->data, AES_BLOCK_SIZE);

    for (blockno = 0; ; blockno++) {
        unsigned char storage[AES_BLOCK_SIZE], *block;
        unsigned char ectr[AES_BLOCK_SIZE];
        unsigned int num = 0;

        block = iov_next_block(storage, AES_BLOCK_SIZE, data, num_data, &input_pos);
        if (block == NULL)
            break;

        /* We should not need to initialise ectr because we're on a block boundary. */
        AES_ctr128_encrypt(block, block, AES_BLOCK_SIZE, &enck, ctr, ectr, &num);
        assert(num == 0);

        iov_store_block(data, num_data, block, storage, AES_BLOCK_SIZE, &output_pos);
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
    AES_KEY enck;
    unsigned char blockY[AES_BLOCK_SIZE];
    struct iov_block_state iov_state;

    if (output->length < AES_BLOCK_SIZE)
        return KRB5_BAD_MSIZE;

    AES_set_encrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &enck);

    if (iv != NULL)
        memcpy(blockY, iv->data, AES_BLOCK_SIZE);
    else
        memset(blockY, 0, AES_BLOCK_SIZE);

    IOV_BLOCK_STATE_INIT(&iov_state);

    /*
     * The CCM header may not fit in a block, because it includes a variable
     * length encoding of the associated data length. This encoding plus the
     * associated data itself is padded to the block size.
     */
    iov_state.include_sign_only = 1;
    iov_state.pad_to_boundary = 1;

    for (;;) {
        unsigned char blockB[AES_BLOCK_SIZE];

        if (!krb5int_c_iov_get_block(blockB, AES_BLOCK_SIZE, data, num_data, &iov_state))
            break;

        xorblock(blockB, blockY);

        AES_ecb_encrypt(blockB, blockY, &enck, 1);
    }

    output->length = AES_BLOCK_SIZE;
    memcpy(output->data, blockY, AES_BLOCK_SIZE);

    return 0;
}

static krb5_error_code
krb5int_aes_init_state_ctr (const krb5_keyblock *key, krb5_keyusage usage,
                            krb5_data *state)
{
    return alloc_data(state, 16);
}

const struct krb5_enc_provider krb5int_enc_aes128_ctr = {
    16,
    16, 16,
    krb5int_aes_encrypt_ctr,
    krb5int_aes_encrypt_ctr,
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
    krb5int_aes_encrypt_ctr,
    krb5int_aes_cbc_mac,
    krb5int_aes_make_key,
    krb5int_aes_init_state_ctr,
    krb5int_default_free_state,
    NULL
};

#endif

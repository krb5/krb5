/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2008 by the Massachusetts Institute of Technology.
 * Copyright 1995 by Richard P. Basch.  All Rights Reserved.
 * Copyright 1995 by Lehman Brothers, Inc.  All Rights Reserved.
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
 * the name of Richard P. Basch, Lehman Brothers and M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Richard P. Basch,
 * Lehman Brothers and M.I.T. make no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include "des_int.h"
#include "f_tables.h"
#include "aead.h"

const mit_des_cblock mit_des_zeroblock /* = all zero */;

void
krb5int_des_cbc_encrypt(krb5_crypto_iov *data, unsigned long num_data,
                        const mit_des_key_schedule schedule,
                        mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp;
    const unsigned char *ip;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MIT_DES_BLOCK_LENGTH], *block = NULL, *ptr;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Get key pointer here.  This won't need to be reinitialized. */
    kp = (const unsigned DES_INT32 *)schedule;

    /* Initialize left and right with the contents of the initial vector. */
    ip = (ivec != NULL) ? ivec : mit_des_zeroblock;
    GET_HALF_BLOCK(left, ip);
    GET_HALF_BLOCK(right, ip);

    /* Work the length down 8 bytes at a time. */
    for (;;) {
        unsigned DES_INT32 temp;

        ptr = iov_next_block(storage, MIT_DES_BLOCK_LENGTH, data, num_data,
                             &input_pos);
        if (ptr == NULL)
            break;
        block = ptr;

        /* Decompose this block and xor it with the previous ciphertext. */
        GET_HALF_BLOCK(temp, ptr);
        left  ^= temp;
        GET_HALF_BLOCK(temp, ptr);
        right ^= temp;

        /* Encrypt what we have and store back into block. */
        DES_DO_ENCRYPT(left, right, kp);
        ptr = block;
        PUT_HALF_BLOCK(left, ptr);
        PUT_HALF_BLOCK(right, ptr);

        iov_store_block(data, num_data, block, storage, MIT_DES_BLOCK_LENGTH,
                        &output_pos);
    }

    if (ivec != NULL && block != NULL) {
        ptr = ivec;
        PUT_HALF_BLOCK(left, ptr);
        PUT_HALF_BLOCK(right, ptr);
    }
}

void
krb5int_des_cbc_decrypt(krb5_crypto_iov *data, unsigned long num_data,
                        const mit_des_key_schedule schedule,
                        mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp;
    const unsigned char *ip;
    unsigned DES_INT32 ocipherl, ocipherr;
    unsigned DES_INT32 cipherl, cipherr;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MIT_DES_BLOCK_LENGTH], *block = NULL, *ptr;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Get key pointer here.  This won't need to be reinitialized. */
    kp = (const unsigned DES_INT32 *)schedule;

    /*
     * Decrypting is harder than encrypting because of
     * the necessity of remembering a lot more things.
     * Should think about this a little more...
     */

    /* Prime the old cipher with ivec. */
    ip = (ivec != NULL) ? ivec : mit_des_zeroblock;
    GET_HALF_BLOCK(ocipherl, ip);
    GET_HALF_BLOCK(ocipherr, ip);

    /* Work the length down 8 bytes at a time. */
    for (;;) {
        ptr = iov_next_block(storage, MIT_DES_BLOCK_LENGTH, data, num_data,
                             &input_pos);
        if (ptr == NULL)
            break;
        block = ptr;

        /* Split this block into left and right. */
        GET_HALF_BLOCK(left, ptr);
        GET_HALF_BLOCK(right, ptr);
        cipherl = left;
        cipherr = right;

        /* Decrypt and xor with the old cipher to get plain text. */
        DES_DO_DECRYPT(left, right, kp);
        left ^= ocipherl;
        right ^= ocipherr;

        /* Store the encrypted halves back into block. */
        ptr = block;
        PUT_HALF_BLOCK(left, ptr);
        PUT_HALF_BLOCK(right, ptr);

        /* Save current cipher block halves. */
        ocipherl = cipherl;
        ocipherr = cipherr;

        iov_store_block(data, num_data, block, storage, MIT_DES_BLOCK_LENGTH,
                        &output_pos);
    }

    if (ivec != NULL && block != NULL) {
        ptr = ivec;
        PUT_HALF_BLOCK(ocipherl, ptr);
        PUT_HALF_BLOCK(ocipherr, ptr);
    }
}

void
krb5int_des_cbc_mac(const krb5_crypto_iov *data, unsigned long num_data,
                    const mit_des_key_schedule schedule, mit_des_cblock ivec,
                    mit_des_cblock out)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp;
    const unsigned char *ip;
    struct iov_block_state input_pos;
    unsigned char storage[MIT_DES_BLOCK_LENGTH], *block = NULL, *ptr;

    IOV_BLOCK_STATE_INIT(&input_pos);
    input_pos.include_sign_only = 1;

    /* Get key pointer here.  This won't need to be reinitialized. */
    kp = (const unsigned DES_INT32 *)schedule;

    /* Initialize left and right with the contents of the initial vector. */
    ip = (ivec != NULL) ? ivec : mit_des_zeroblock;
    GET_HALF_BLOCK(left, ip);
    GET_HALF_BLOCK(right, ip);

    /* Work the length down 8 bytes at a time. */
    for (;;) {
        unsigned DES_INT32 temp;

        ptr = iov_next_block(storage, MIT_DES_BLOCK_LENGTH, data, num_data,
                             &input_pos);
        if (ptr == NULL)
            break;
        block = ptr;

        /* Decompose this block and xor it with the previous ciphertext. */
        GET_HALF_BLOCK(temp, ptr);
        left  ^= temp;
        GET_HALF_BLOCK(temp, ptr);
        right ^= temp;

        /* Encrypt what we have. */
        DES_DO_ENCRYPT(left, right, kp);
    }

    /* Output the final ciphertext block. */
    ptr = out;
    PUT_HALF_BLOCK(left, ptr);
    PUT_HALF_BLOCK(right, ptr);
}

#if defined(CONFIG_SMALL) && !defined(CONFIG_SMALL_NO_CRYPTO)
void krb5int_des_do_encrypt_2 (unsigned DES_INT32 *left,
                               unsigned DES_INT32 *right,
                               const unsigned DES_INT32 *kp)
{
    DES_DO_ENCRYPT_1 (*left, *right, kp);
}

void krb5int_des_do_decrypt_2 (unsigned DES_INT32 *left,
                               unsigned DES_INT32 *right,
                               const unsigned DES_INT32 *kp)
{
    DES_DO_DECRYPT_1 (*left, *right, kp);
}
#endif

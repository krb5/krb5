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

#include "crypto_int.h"
#include "des_int.h"
#include "f_tables.h"

void
krb5int_des3_cbc_encrypt(krb5_crypto_iov *data, unsigned long num_data,
                         const mit_des_key_schedule ks1,
                         const mit_des_key_schedule ks2,
                         const mit_des_key_schedule ks3,
                         mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp1, *kp2, *kp3;
    const unsigned char *ip;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MIT_DES_BLOCK_LENGTH], *block = NULL, *ptr;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Get key pointers here.  These won't need to be reinitialized. */
    kp1 = (const unsigned DES_INT32 *)ks1;
    kp2 = (const unsigned DES_INT32 *)ks2;
    kp3 = (const unsigned DES_INT32 *)ks3;

    /* Initialize left and right with the contents of the initial vector. */
    ip = (ivec != NULL) ? ivec : mit_des_zeroblock;
    GET_HALF_BLOCK(left, ip);
    GET_HALF_BLOCK(right, ip);

    /* Work the length down 8 bytes at a time. */
    for (;;) {
        unsigned DES_INT32 temp;

        if (!krb5int_c_iov_get_block_nocopy(storage, MIT_DES_BLOCK_LENGTH,
                                            data, num_data, &input_pos, &ptr))
            break;
        block = ptr;

        /* Decompose this block and xor it with the previous ciphertext. */
        GET_HALF_BLOCK(temp, ptr);
        left  ^= temp;
        GET_HALF_BLOCK(temp, ptr);
        right ^= temp;

        /* Encrypt what we have and store it back into block. */
        DES_DO_ENCRYPT(left, right, kp1);
        DES_DO_DECRYPT(left, right, kp2);
        DES_DO_ENCRYPT(left, right, kp3);
        ptr = block;
        PUT_HALF_BLOCK(left, ptr);
        PUT_HALF_BLOCK(right, ptr);

        krb5int_c_iov_put_block_nocopy(data, num_data, storage,
                                       MIT_DES_BLOCK_LENGTH, &output_pos,
                                       block);
    }

    if (ivec != NULL && block != NULL) {
        ptr = ivec;
        PUT_HALF_BLOCK(left, ptr);
        PUT_HALF_BLOCK(right, ptr);
    }
}

void
krb5int_des3_cbc_decrypt(krb5_crypto_iov *data, unsigned long num_data,
                         const mit_des_key_schedule ks1,
                         const mit_des_key_schedule ks2,
                         const mit_des_key_schedule ks3,
                         mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp1, *kp2, *kp3;
    const unsigned char *ip;
    unsigned DES_INT32 ocipherl, ocipherr;
    unsigned DES_INT32 cipherl, cipherr;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MIT_DES_BLOCK_LENGTH], *block = NULL, *ptr;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Get key pointers here.  These won't need to be reinitialized. */
    kp1 = (const unsigned DES_INT32 *)ks1;
    kp2 = (const unsigned DES_INT32 *)ks2;
    kp3 = (const unsigned DES_INT32 *)ks3;

    /*
     * Decrypting is harder than encrypting because of
     * the necessity of remembering a lot more things.
     * Should think about this a little more...
     */

    /* Prime the old cipher with ivec.*/
    ip = (ivec != NULL) ? ivec : mit_des_zeroblock;
    GET_HALF_BLOCK(ocipherl, ip);
    GET_HALF_BLOCK(ocipherr, ip);

    /* Work the length down 8 bytes at a time. */
    for (;;) {
        if (!krb5int_c_iov_get_block_nocopy(storage, MIT_DES_BLOCK_LENGTH,
                                            data, num_data, &input_pos, &ptr))
            break;
        block = ptr;

        /* Split this block into left and right. */
        GET_HALF_BLOCK(left, ptr);
        GET_HALF_BLOCK(right, ptr);
        cipherl = left;
        cipherr = right;

        /* Decrypt and xor with the old cipher to get plain text. */
        DES_DO_DECRYPT(left, right, kp3);
        DES_DO_ENCRYPT(left, right, kp2);
        DES_DO_DECRYPT(left, right, kp1);
        left ^= ocipherl;
        right ^= ocipherr;

        /* Store the encrypted halves back into block. */
        ptr = block;
        PUT_HALF_BLOCK(left, ptr);
        PUT_HALF_BLOCK(right, ptr);

        /* Save current cipher block halves. */
        ocipherl = cipherl;
        ocipherr = cipherr;

        krb5int_c_iov_put_block_nocopy(data, num_data, storage,
                                       MIT_DES_BLOCK_LENGTH, &output_pos,
                                       block);
    }

    if (ivec != NULL && block != NULL) {
        ptr = ivec;
        PUT_HALF_BLOCK(ocipherl, ptr);
        PUT_HALF_BLOCK(ocipherr, ptr);
    }
}

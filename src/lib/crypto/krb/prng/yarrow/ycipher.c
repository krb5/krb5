/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/yarrow/ycipher.c
 *
 * Copyright (C) 2001, 2007 by the Massachusetts Institute of Technology.
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
 *
 *
 *
 *  Routines  to implement krb5 cipher operations.
 */
#include "k5-int.h"
#include "yarrow.h"
#include "ycipher.h"
#include "enc_provider.h"
#include "assert.h"

int
krb5int_yarrow_cipher_init(CIPHER_CTX *ctx, unsigned const char * key)
{
    size_t keybytes, keylength;
    const struct krb5_enc_provider *enc = &yarrow_enc_provider;
    krb5_error_code ret;
    krb5_data randombits;
    krb5_keyblock keyblock;

    keybytes = enc->keybytes;
    keylength = enc->keylength;
    assert (keybytes == CIPHER_KEY_SIZE);
    krb5_k_free_key(NULL, ctx->key);
    ctx->key = NULL;
    keyblock.contents = malloc(keylength);
    keyblock.length = keylength;
    keyblock.enctype = yarrow_enc_type;
    if (keyblock.contents == NULL)
        return (YARROW_NOMEM);
    randombits.data = (char *) key;
    randombits.length = keybytes;
    ret = enc->make_key(&randombits, &keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5_k_create_key(NULL, &keyblock, &ctx->key);
cleanup:
    free(keyblock.contents);
    if (ret)
        return YARROW_FAIL;
    return YARROW_OK;
}

int krb5int_yarrow_cipher_encrypt_block(CIPHER_CTX *ctx,
                                        const unsigned char *in,
                                        unsigned char *out)
{
    krb5_error_code ret;
    krb5_crypto_iov iov;
    const struct krb5_enc_provider *enc = &yarrow_enc_provider;

    memcpy(out, in, CIPHER_BLOCK_SIZE);
    iov.flags = KRB5_CRYPTO_TYPE_DATA;
    iov.data = make_data(out, CIPHER_BLOCK_SIZE);
    ret = enc->encrypt(ctx->key, 0, &iov, 1);
    return (ret == 0) ? YARROW_OK : YARROW_FAIL;
}

void
krb5int_yarrow_cipher_final(CIPHER_CTX *ctx)
{
    krb5_k_free_key(NULL, ctx->key);
    ctx->key = NULL;
}

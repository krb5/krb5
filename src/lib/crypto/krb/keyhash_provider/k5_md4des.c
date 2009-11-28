/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "des_int.h"
#include "rsa-md4.h"
#include "keyhash_provider.h"

#define CONFLENGTH 8

/* Force acceptance of krb5-beta5 md4des checksum for now. */
#define KRB5int_MD4DES_BETA5_COMPAT

/* des-cbc(xorkey, conf | rsa-md4(conf | data)) */

extern struct krb5_enc_provider krb5int_enc_des;

/* Derive a key by XOR with 0xF0 bytes. */
static krb5_error_code
mk_xorkey(krb5_key origkey, krb5_key *xorkey)
{
    krb5_error_code retval = 0;
    unsigned char xorbytes[8];
    krb5_keyblock xorkeyblock;
    size_t i = 0;

    if (origkey->keyblock.length != sizeof(xorbytes))
        return KRB5_CRYPTO_INTERNAL;
    memcpy(xorbytes, origkey->keyblock.contents, sizeof(xorbytes));
    for (i = 0; i < sizeof(xorbytes); i++)
        xorbytes[i] ^= 0xf0;

    /* Do a shallow copy here. */
    xorkeyblock = origkey->keyblock;
    xorkeyblock.contents = xorbytes;

    retval = krb5_k_create_key(0, &xorkeyblock, xorkey);
    zap(xorbytes, sizeof(xorbytes));
    return retval;
}

static krb5_error_code
k5_md4des_hash(krb5_key key, krb5_keyusage usage, const krb5_data *ivec,
               const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret;
    krb5_data data;
    krb5_MD4_CTX ctx;
    unsigned char conf[CONFLENGTH];
    krb5_key xorkey = NULL;
    struct krb5_enc_provider *enc = &krb5int_enc_des;

    if (output->length != (CONFLENGTH+RSA_MD4_CKSUM_LENGTH))
        return(KRB5_CRYPTO_INTERNAL);

    /* create the confouder */

    data.length = CONFLENGTH;
    data.data = (char *) conf;
    if ((ret = krb5_c_random_make_octets(/* XXX */ 0, &data)))
        return(ret);

    ret = mk_xorkey(key, &xorkey);
    if (ret)
        return ret;

    /* hash the confounder, then the input data */

    krb5int_MD4Init(&ctx);
    krb5int_MD4Update(&ctx, conf, CONFLENGTH);
    krb5int_MD4Update(&ctx, (unsigned char *) input->data,
                      (unsigned int) input->length);
    krb5int_MD4Final(&ctx);

    /* construct the buffer to be encrypted */

    memcpy(output->data, conf, CONFLENGTH);
    memcpy(output->data+CONFLENGTH, ctx.digest, RSA_MD4_CKSUM_LENGTH);

    ret = enc->encrypt(xorkey, NULL, output, output);

    krb5_k_free_key(NULL, xorkey);

    return (ret);
}

static krb5_error_code
k5_md4des_verify(krb5_key key, krb5_keyusage usage,
                 const krb5_data *ivec,
                 const krb5_data *input, const krb5_data *hash,
                 krb5_boolean *valid)
{
    krb5_error_code ret;
    krb5_MD4_CTX ctx;
    unsigned char plaintext[CONFLENGTH+RSA_MD4_CKSUM_LENGTH];
    krb5_key xorkey = NULL;
    int compathash = 0;
    struct krb5_enc_provider *enc = &krb5int_enc_des;
    krb5_data output, iv;

    iv.data = NULL;
    iv.length = 0;

    if (key->keyblock.length != 8)
        return(KRB5_BAD_KEYSIZE);
    if (hash->length != (CONFLENGTH+RSA_MD4_CKSUM_LENGTH)) {
#ifdef KRB5int_MD4DES_BETA5_COMPAT
        if (hash->length != RSA_MD4_CKSUM_LENGTH)
            return(KRB5_CRYPTO_INTERNAL);
        else
            compathash = 1;
#else
        return(KRB5_CRYPTO_INTERNAL);
#endif
        return(KRB5_CRYPTO_INTERNAL);
    }

    if (compathash) {
        iv.data = malloc(key->keyblock.length);
        if (!iv.data) return ENOMEM;
        iv.length = key->keyblock.length;
        if (key->keyblock.contents)
            memcpy(iv.data, key->keyblock.contents, key->keyblock.length);
    } else {
        ret = mk_xorkey(key, &xorkey);
        if (ret)
            return ret;
    }

    /* decrypt it */
    output.data = (char *)plaintext;
    output.length = hash->length;

    if (!compathash) {
        ret = enc->decrypt(xorkey, NULL, hash, &output);
        krb5_k_free_key(NULL, xorkey);
    } else {
        ret = enc->decrypt(key, &iv, hash, &output);
        zap(iv.data, iv.length);
        free(iv.data);
    }

    if (ret) return(ret);

    if (output.length > CONFLENGTH+RSA_MD4_CKSUM_LENGTH)
        return KRB5_CRYPTO_INTERNAL;

    /* hash the confounder, then the input data */

    krb5int_MD4Init(&ctx);
    if (!compathash) {
        krb5int_MD4Update(&ctx, plaintext, CONFLENGTH);
    }
    krb5int_MD4Update(&ctx, (unsigned char *) input->data,
                      (unsigned int) input->length);
    krb5int_MD4Final(&ctx);

    /* compare the decrypted hash to the computed one */

    if (!compathash) {
        *valid =
            (memcmp(plaintext+CONFLENGTH, ctx.digest, RSA_MD4_CKSUM_LENGTH)
             == 0);
    } else {
        *valid =
            (memcmp(plaintext, ctx.digest, RSA_MD4_CKSUM_LENGTH) == 0);
    }

    memset(plaintext, 0, sizeof(plaintext));

    return(0);
}

const struct krb5_keyhash_provider krb5int_keyhash_md4des = {
    CONFLENGTH+RSA_MD4_CKSUM_LENGTH,
    k5_md4des_hash,
    k5_md4des_verify,
    NULL,
    NULL
};

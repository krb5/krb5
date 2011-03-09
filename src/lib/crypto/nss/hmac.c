/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/hmac.c */
/*
 * Copyright (c) 2010 Red Hat, Inc.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 *  * Neither the name of Red Hat, Inc., nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypto_int.h"
#include "nss_gen.h"
#include "pk11pub.h"

/*
 * the HMAC transform looks like:
 *
 * H(K XOR opad, H(K XOR ipad, text))
 *
 * where H is a cryptographic hash
 * K is an n byte key
 * ipad is the byte 0x36 repeated blocksize times
 * opad is the byte 0x5c repeated blocksize times
 * and text is the data being protected
 */

static CK_MECHANISM_TYPE
digest_to_hmac(const struct krb5_hash_provider *hash)
{
    /* use strcmp so we don't confuse SHA1 with SHA128 */
    /* handle the obvious cases first */
    if (!strcmp(hash->hash_name, "SHA1"))
        return CKM_SHA_1_HMAC;
    if (!strcmp(hash->hash_name, "MD5"))
        return CKM_MD5_HMAC;
    return CKM_INVALID_MECHANISM;
}

krb5_error_code
krb5int_hmac(const struct krb5_hash_provider *hash, krb5_key key,
             const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    unsigned int i = 0;
    CK_MECHANISM_TYPE mech;
    PK11Context *ctx = NULL;
    krb5_error_code ret = 0;
    SECStatus rv;
    SECItem param;

    if (output->length < hash->hashsize)
        return KRB5_BAD_MSIZE;

    mech = digest_to_hmac(hash);
    if (mech == CKM_INVALID_MECHANISM)
        return KRB5_CRYPTO_INTERNAL; /* unsupported alg */

    ret = k5_nss_gen_import(key, mech, CKA_SIGN);
    if (ret != 0)
        return ret;

    param.data = NULL;
    param.len = 0;
    ctx = k5_nss_create_context(key, mech, CKA_SIGN, &param);
    if (ctx == NULL)
        goto fail;

    rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess)
        goto fail;

    for (i=0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (iov->data.length && SIGN_IOV(iov)) {
            rv = PK11_DigestOp(ctx,(const unsigned char*)iov->data.data,
                               iov->data.length);
            if (rv != SECSuccess)
                goto fail;
        }

    }
    rv = PK11_DigestFinal(ctx, (unsigned char *) output->data, &output->length,
                          output->length);
    if (rv != SECSuccess)
        goto fail;
    PK11_DestroyContext(ctx, PR_TRUE);
    return 0;
fail:
    ret = k5_nss_map_last_error();
    if (ctx)
        PK11_DestroyContext(ctx, PR_TRUE);
    return ret;
}

krb5_error_code
krb5int_hmac_keyblock(const struct krb5_hash_provider *hash,
                      const krb5_keyblock *keyblock,
                      const krb5_crypto_iov *data, size_t num_data,
                      krb5_data *output)
{
    krb5_key key;
    krb5_error_code code;

    if (keyblock->length > hash->blocksize)
        return KRB5_CRYPTO_INTERNAL;

    memset(&key, 0, sizeof(key));

    code = krb5_k_create_key(NULL, keyblock, &key);
    if (code)
        return code;
    code = krb5int_hmac(hash, key, data, num_data, output);
    krb5_k_free_key(NULL, key);
    return code;
}

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/hmac.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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
#include "aead.h"
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

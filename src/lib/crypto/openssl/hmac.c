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
#include <openssl/hmac.h>
#include <openssl/evp.h>

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

static const EVP_MD *
map_digest(const struct krb5_hash_provider *hash)
{
    if (!strncmp(hash->hash_name, "SHA1",4))
        return EVP_sha1();
    else if (!strncmp(hash->hash_name, "MD5", 3))
        return EVP_md5();
    else if (!strncmp(hash->hash_name, "MD4", 3))
        return EVP_md4();
    else
        return NULL;
}

krb5_error_code
krb5int_hmac_keyblock(const struct krb5_hash_provider *hash,
                      const krb5_keyblock *keyblock,
                      const krb5_crypto_iov *data, size_t num_data,
                      krb5_data *output)
{
    unsigned int i = 0, md_len = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    HMAC_CTX c;
    size_t hashsize, blocksize;

    hashsize = hash->hashsize;
    blocksize = hash->blocksize;

    if (keyblock->length > blocksize)
        return(KRB5_CRYPTO_INTERNAL);
    if (output->length < hashsize)
        return(KRB5_BAD_MSIZE);

    if (!map_digest(hash))
        return(KRB5_CRYPTO_INTERNAL); // unsupported alg

    HMAC_CTX_init(&c);
    HMAC_Init(&c, keyblock->contents, keyblock->length, map_digest(hash));
    for (i = 0; i < num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        if (SIGN_IOV(iov))
            HMAC_Update(&c, (unsigned char*) iov->data.data, iov->data.length);
    }
    HMAC_Final(&c,(unsigned char *)md, &md_len);
    if ( md_len <= output->length) {
        output->length = md_len;
        memcpy(output->data, md, output->length);
    }
    HMAC_CTX_cleanup(&c);
    return 0;


}

krb5_error_code
krb5int_hmac(const struct krb5_hash_provider *hash, krb5_key key,
             const krb5_crypto_iov *data, size_t num_data,
             krb5_data *output)
{
    return krb5int_hmac_keyblock(hash, &key->keyblock, data, num_data, output);
}

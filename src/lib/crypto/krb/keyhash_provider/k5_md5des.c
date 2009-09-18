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
#include "rsa-md5.h"
#include "keyhash_provider.h"

#define CONFLENGTH 8

/* Force acceptance of krb5-beta5 md5des checksum for now. */
#define KRB5_MD5DES_BETA5_COMPAT

/* des-cbc(xorkey, conf | rsa-md5(conf | data)) */

extern struct krb5_enc_provider krb5int_enc_des;

static krb5_error_code
k5_md5des_hash(const krb5_keyblock *key, krb5_keyusage usage, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret;
    krb5_data data;
    krb5_MD5_CTX ctx;
    unsigned char conf[CONFLENGTH];
    struct krb5_enc_provider *enc = &krb5int_enc_des;

    if (output->length != (CONFLENGTH+RSA_MD5_CKSUM_LENGTH))
	return(KRB5_CRYPTO_INTERNAL);

    /* create the confouder */

    data.length = CONFLENGTH;
    data.data = (char *) conf;
    if ((ret = krb5_c_random_make_octets(/* XXX */ 0, &data)))
	return(ret);

    /* hash the confounder, then the input data */

    krb5_MD5Init(&ctx);
    krb5_MD5Update(&ctx, conf, CONFLENGTH);
    krb5_MD5Update(&ctx, (unsigned char *) input->data, 
		   (unsigned int) input->length);
    krb5_MD5Final(&ctx);

    /* construct the buffer to be encrypted */

    memcpy(output->data, conf, CONFLENGTH);
    memcpy(output->data+CONFLENGTH, ctx.digest, RSA_MD5_CKSUM_LENGTH);

    ret = enc->encrypt(key, NULL, output, output);

    return ret;

}

static krb5_error_code
k5_md5des_verify(const krb5_keyblock *key, krb5_keyusage usage, const krb5_data *ivec,
		 const krb5_data *input, const krb5_data *hash,
		 krb5_boolean *valid)
{
    krb5_error_code ret;
    krb5_MD5_CTX ctx;
    unsigned char plaintext[CONFLENGTH+RSA_MD5_CKSUM_LENGTH];
    unsigned char *ivptr = NULL, *outptr = NULL;
    int compathash = 0;
    struct krb5_enc_provider *enc = &krb5int_enc_des;
    krb5_data output, iv;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);

    if (hash->length != (CONFLENGTH+RSA_MD5_CKSUM_LENGTH)) {
#ifdef KRB5_MD5DES_BETA5_COMPAT
	if (hash->length != RSA_MD5_CKSUM_LENGTH)
	    return(KRB5_CRYPTO_INTERNAL);
	else
	    compathash = 1;
#else
	return(KRB5_CRYPTO_INTERNAL);
#endif
    }

    if (compathash) {
        iv.data = malloc(key->length);
        if (!iv.data) return ENOMEM;
        iv.length = key->length;
        if (key->contents)
            memcpy(iv.data, key->contents, key->length);
    }

    /* decrypt it */
    output.data = plaintext;
    output.length = hash->length;

    if (!compathash) {
        ret = enc->decrypt(key, NULL, hash, &output);
    } else {
        ret = enc->decrypt(key, &iv, hash, &output);
    }

    if (compathash && iv.data) {
        free (iv.data);
    }

    if (ret) return(ret);

    if (output.length > CONFLENGTH+RSA_MD5_CKSUM_LENGTH)
        return KRB5_CRYPTO_INTERNAL;

    /* hash the confounder, then the input data */

    krb5_MD5Init(&ctx);
    if (!compathash) {
	krb5_MD5Update(&ctx, plaintext, CONFLENGTH);
    }
    krb5_MD5Update(&ctx, (unsigned char *) input->data,
		   (unsigned) input->length);
    krb5_MD5Final(&ctx);

    /* compare the decrypted hash to the computed one */

    if (!compathash) {
	*valid =
	    (memcmp(plaintext+CONFLENGTH, ctx.digest, RSA_MD5_CKSUM_LENGTH)
	     == 0);
    } else {
	*valid = 
	    (memcmp(plaintext, ctx.digest, RSA_MD5_CKSUM_LENGTH) == 0);
    }
    memset(plaintext, 0, sizeof(plaintext));

    return(0);
}

const struct krb5_keyhash_provider krb5int_keyhash_md5des = {
    CONFLENGTH+RSA_MD5_CKSUM_LENGTH,
    k5_md5des_hash,
    k5_md5des_verify,
    NULL,
    NULL
};

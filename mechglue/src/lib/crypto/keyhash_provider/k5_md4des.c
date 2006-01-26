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
#define KRB5_MD4DES_BETA5_COMPAT

/* des-cbc(xorkey, conf | rsa-md4(conf | data)) */

/* this could be done in terms of the md4 and des providers, but
   that's less efficient, and there's no need for this to be generic */

static krb5_error_code
k5_md4des_hash(const krb5_keyblock *key, krb5_keyusage usage, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output)
{
    krb5_error_code ret;
    krb5_data data;
    krb5_MD4_CTX ctx;
    unsigned char conf[CONFLENGTH];
    unsigned char xorkey[8];
    int i;
    mit_des_key_schedule schedule;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if (ivec)
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length != (CONFLENGTH+RSA_MD4_CKSUM_LENGTH))
	return(KRB5_CRYPTO_INTERNAL);

    /* create the confouder */

    data.length = CONFLENGTH;
    data.data = (char *) conf;
    if ((ret = krb5_c_random_make_octets(/* XXX */ 0, &data)))
	return(ret);

    /* create and schedule the encryption key */

    memcpy(xorkey, key->contents, sizeof(xorkey));
    for (i=0; i<sizeof(xorkey); i++)
	xorkey[i] ^= 0xf0;
    
    switch (ret = mit_des_key_sched(xorkey, schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }

    /* hash the confounder, then the input data */

    krb5_MD4Init(&ctx);
    krb5_MD4Update(&ctx, conf, CONFLENGTH);
    krb5_MD4Update(&ctx, (unsigned char *) input->data,
		   (unsigned int) input->length);
    krb5_MD4Final(&ctx);

    /* construct the buffer to be encrypted */

    memcpy(output->data, conf, CONFLENGTH);
    memcpy(output->data+CONFLENGTH, ctx.digest, RSA_MD4_CKSUM_LENGTH);

    /* encrypt it, in place.  this has a return value, but it's
       always zero.  */

    mit_des_cbc_encrypt((krb5_pointer) output->data,
			(krb5_pointer) output->data, output->length,
			schedule, (unsigned char *) mit_des_zeroblock, 1);

    return(0);
}

static krb5_error_code
k5_md4des_verify(const krb5_keyblock *key, krb5_keyusage usage,
		 const krb5_data *ivec,
		 const krb5_data *input, const krb5_data *hash,
		 krb5_boolean *valid)
{
    krb5_MD4_CTX ctx;
    unsigned char plaintext[CONFLENGTH+RSA_MD4_CKSUM_LENGTH];
    unsigned char xorkey[8];
    int i;
    mit_des_key_schedule schedule;
    int compathash = 0;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if (ivec)
	return(KRB5_CRYPTO_INTERNAL);
    if (hash->length != (CONFLENGTH+RSA_MD4_CKSUM_LENGTH)) {
#ifdef KRB5_MD4DES_BETA5_COMPAT
	if (hash->length != RSA_MD4_CKSUM_LENGTH)
	    return(KRB5_CRYPTO_INTERNAL);
	else
	    compathash = 1;
#else
	return(KRB5_CRYPTO_INTERNAL);
#endif
	return(KRB5_CRYPTO_INTERNAL);
    }

    /* create and schedule the encryption key */

    memcpy(xorkey, key->contents, sizeof(xorkey));
    if (!compathash) {
	for (i=0; i<sizeof(xorkey); i++)
	    xorkey[i] ^= 0xf0;
    }
    
    switch (mit_des_key_sched(xorkey, schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }

    /* decrypt it.  this has a return value, but it's always zero.  */

    if (!compathash) {
	mit_des_cbc_encrypt((krb5_pointer) hash->data,
			    (krb5_pointer) plaintext, hash->length,
			    schedule, (unsigned char *) mit_des_zeroblock, 0);
    } else {
	mit_des_cbc_encrypt((krb5_pointer) hash->data,
			    (krb5_pointer) plaintext, hash->length,
			    schedule, xorkey, 0);
    }

    /* hash the confounder, then the input data */

    krb5_MD4Init(&ctx);
    if (!compathash) {
	krb5_MD4Update(&ctx, plaintext, CONFLENGTH);
    }
    krb5_MD4Update(&ctx, (unsigned char *) input->data, 
		   (unsigned int) input->length);
    krb5_MD4Final(&ctx);

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
    k5_md4des_verify
};

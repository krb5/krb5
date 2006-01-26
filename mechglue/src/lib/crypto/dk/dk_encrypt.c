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
#include "dk.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

/* the spec says that the confounder size and padding are specific to
   the encryption algorithm.  This code (dk_encrypt_length and
   dk_encrypt) assume the confounder is always the blocksize, and the
   padding is always zero bytes up to the blocksize.  If these
   assumptions ever fails, the keytype table should be extended to
   include these bits of info. */

void
krb5_dk_encrypt_length(const struct krb5_enc_provider *enc,
		       const struct krb5_hash_provider *hash,
		       size_t inputlen, size_t *length)
{
    size_t blocksize, hashsize;

    blocksize = enc->block_size;
    hashsize = hash->hashsize;
    *length = krb5_roundup(blocksize+inputlen, blocksize) + hashsize;
}

krb5_error_code
krb5_dk_encrypt(const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, krb5_keyusage usage,
		const krb5_data *ivec, const krb5_data *input,
		krb5_data *output)
{
    size_t blocksize, keybytes, keylength, plainlen, enclen;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1, d2;
    unsigned char *plaintext, *kedata, *kidata, *cn;
    krb5_keyblock ke, ki;

    /* allocate and set up plaintext and to-be-derived keys */

    blocksize = enc->block_size;
    keybytes = enc->keybytes;
    keylength = enc->keylength;
    plainlen = krb5_roundup(blocksize+input->length, blocksize);

    krb5_dk_encrypt_length(enc, hash, input->length, &enclen);

    /* key->length, ivec will be tested in enc->encrypt */

    if (output->length < enclen)
	return(KRB5_BAD_MSIZE);

    if ((kedata = (unsigned char *) malloc(keylength)) == NULL)
	return(ENOMEM);
    if ((kidata = (unsigned char *) malloc(keylength)) == NULL) {
	free(kedata);
	return(ENOMEM);
    }
    if ((plaintext = (unsigned char *) malloc(plainlen)) == NULL) {
	free(kidata);
	free(kedata);
	return(ENOMEM);
    }

    ke.contents = kedata;
    ke.length = keylength;
    ki.contents = kidata;
    ki.length = keylength;

    /* derive the keys */

    d1.data = constantdata;
    d1.length = K5CLENGTH;

    d1.data[0] = (usage>>24)&0xff;
    d1.data[1] = (usage>>16)&0xff;
    d1.data[2] = (usage>>8)&0xff;
    d1.data[3] = usage&0xff;

    d1.data[4] = (char) 0xAA;

    if ((ret = krb5_derive_key(enc, key, &ke, &d1)))
	goto cleanup;

    d1.data[4] = 0x55;

    if ((ret = krb5_derive_key(enc, key, &ki, &d1)))
	goto cleanup;

    /* put together the plaintext */

    d1.length = blocksize;
    d1.data = plaintext;

    if ((ret = krb5_c_random_make_octets(/* XXX */ 0, &d1)))
	goto cleanup;

    memcpy(plaintext+blocksize, input->data, input->length);

    memset(plaintext+blocksize+input->length, 0,
	   plainlen - (blocksize+input->length));

    /* encrypt the plaintext */

    d1.length = plainlen;
    d1.data = plaintext;

    d2.length = plainlen;
    d2.data = output->data;

    if ((ret = ((*(enc->encrypt))(&ke, ivec, &d1, &d2))))
	goto cleanup;

    if (ivec != NULL && ivec->length == blocksize)
	cn = d2.data + d2.length - blocksize;
    else
	cn = NULL;

    /* hash the plaintext */

    d2.length = enclen - plainlen;
    d2.data = output->data+plainlen;

    output->length = enclen;

    if ((ret = krb5_hmac(hash, &ki, 1, &d1, &d2))) {
	memset(d2.data, 0, d2.length);
	goto cleanup;
    }

    /* update ivec */
    if (cn != NULL)
	memcpy(ivec->data, cn, blocksize);

    /* ret is set correctly by the prior call */

cleanup:
    memset(kedata, 0, keylength);
    memset(kidata, 0, keylength);
    memset(plaintext, 0, plainlen);

    free(plaintext);
    free(kidata);
    free(kedata);

    return(ret);
}

/* Not necessarily "AES", per se, but "a CBC+CTS mode block cipher
   with a 96-bit truncated HMAC".  */
void
krb5int_aes_encrypt_length(const struct krb5_enc_provider *enc,
			   const struct krb5_hash_provider *hash,
			   size_t inputlen, size_t *length)
{
    size_t blocksize, hashsize;

    blocksize = enc->block_size;
    hashsize = 96 / 8;

    /* No roundup, since CTS requires no padding once we've hit the
       block size.  */
    *length = blocksize+inputlen + hashsize;
}

static krb5_error_code
trunc_hmac (const struct krb5_hash_provider *hash,
	    const krb5_keyblock *ki, int num,
	    const krb5_data *input, const krb5_data *output)
{
    size_t hashsize;
    krb5_data tmp;
    krb5_error_code ret;

    hashsize = hash->hashsize;
    if (hashsize < output->length)
	return KRB5_CRYPTO_INTERNAL;
    tmp.length = hashsize;
    tmp.data = malloc(hashsize);
    if (tmp.data == NULL)
	return errno;
    ret = krb5_hmac(hash, ki, num, input, &tmp);
    if (ret == 0)
	memcpy(output->data, tmp.data, output->length);
    memset(tmp.data, 0, hashsize);
    free(tmp.data);
    return ret;
}

krb5_error_code
krb5int_aes_dk_encrypt(const struct krb5_enc_provider *enc,
		       const struct krb5_hash_provider *hash,
		       const krb5_keyblock *key, krb5_keyusage usage,
		       const krb5_data *ivec, const krb5_data *input,
		       krb5_data *output)
{
    size_t blocksize, keybytes, keylength, plainlen, enclen;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1, d2;
    unsigned char *plaintext, *kedata, *kidata, *cn;
    krb5_keyblock ke, ki;

    /* allocate and set up plaintext and to-be-derived keys */

    blocksize = enc->block_size;
    keybytes = enc->keybytes;
    keylength = enc->keylength;
    plainlen = blocksize+input->length;

    krb5int_aes_encrypt_length(enc, hash, input->length, &enclen);

    /* key->length, ivec will be tested in enc->encrypt */

    if (output->length < enclen)
	return(KRB5_BAD_MSIZE);

    if ((kedata = (unsigned char *) malloc(keylength)) == NULL)
	return(ENOMEM);
    if ((kidata = (unsigned char *) malloc(keylength)) == NULL) {
	free(kedata);
	return(ENOMEM);
    }
    if ((plaintext = (unsigned char *) malloc(plainlen)) == NULL) {
	free(kidata);
	free(kedata);
	return(ENOMEM);
    }

    ke.contents = kedata;
    ke.length = keylength;
    ki.contents = kidata;
    ki.length = keylength;

    /* derive the keys */

    d1.data = constantdata;
    d1.length = K5CLENGTH;

    d1.data[0] = (usage>>24)&0xff;
    d1.data[1] = (usage>>16)&0xff;
    d1.data[2] = (usage>>8)&0xff;
    d1.data[3] = usage&0xff;

    d1.data[4] = (char) 0xAA;

    if ((ret = krb5_derive_key(enc, key, &ke, &d1)))
	goto cleanup;

    d1.data[4] = 0x55;

    if ((ret = krb5_derive_key(enc, key, &ki, &d1)))
	goto cleanup;

    /* put together the plaintext */

    d1.length = blocksize;
    d1.data = plaintext;

    if ((ret = krb5_c_random_make_octets(/* XXX */ 0, &d1)))
	goto cleanup;

    memcpy(plaintext+blocksize, input->data, input->length);

    /* Ciphertext stealing; there should be no more.  */
    if (plainlen != blocksize + input->length)
	abort();

    /* encrypt the plaintext */

    d1.length = plainlen;
    d1.data = plaintext;

    d2.length = plainlen;
    d2.data = output->data;

    if ((ret = ((*(enc->encrypt))(&ke, ivec, &d1, &d2))))
	goto cleanup;

    if (ivec != NULL && ivec->length == blocksize) {
	int nblocks = (d2.length + blocksize - 1) / blocksize;
	cn = d2.data + blocksize * (nblocks - 2);
    } else
	cn = NULL;

    /* hash the plaintext */

    d2.length = enclen - plainlen;
    d2.data = output->data+plainlen;
    if (d2.length != 96 / 8)
	abort();

    if ((ret = trunc_hmac(hash, &ki, 1, &d1, &d2))) {
	memset(d2.data, 0, d2.length);
	goto cleanup;
    }

    output->length = enclen;

    /* update ivec */
    if (cn != NULL) {
	memcpy(ivec->data, cn, blocksize);
#if 0
	{
	    int i;
	    printf("\n%s: output:", __func__);
	    for (i = 0; i < output->length; i++) {
		if (i % 16 == 0)
		    printf("\n%s: ", __func__);
		printf(" %02x", i[(unsigned char *)output->data]);
	    }
	    printf("\n%s: outputIV:", __func__);
	    for (i = 0; i < ivec->length; i++) {
		if (i % 16 == 0)
		    printf("\n%s: ", __func__);
		printf(" %02x", i[(unsigned char *)ivec->data]);
	    }
	    printf("\n");  fflush(stdout);
	}
#endif
    }

    /* ret is set correctly by the prior call */

cleanup:
    memset(kedata, 0, keylength);
    memset(kidata, 0, keylength);
    memset(plaintext, 0, plainlen);

    free(plaintext);
    free(kidata);
    free(kedata);

    return(ret);
}


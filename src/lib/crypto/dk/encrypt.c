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
krb5_dk_encrypt_length(enc, hash, inputlen, length)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     size_t inputlen;
     size_t *length;
{
    size_t blocksize, hashsize;

    (*(enc->block_size))(&blocksize);
    (*(hash->hash_size))(&hashsize);

    *length = krb5_roundup(blocksize+inputlen, blocksize) + hashsize;
}

krb5_error_code
krb5_dk_encrypt(enc, hash, key, usage, ivec, input, output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    size_t blocksize, keybytes, keylength, plainlen, enclen;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1, d2;
    unsigned char *plaintext, *kedata, *kidata;
    krb5_keyblock ke, ki;

    /* allocate and set up plaintext and to-be-derived keys */

    (*(enc->block_size))(&blocksize);
    (*(enc->keysize))(&keybytes, &keylength);
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

    d1.data[4] = 0xAA;

    if (ret = krb5_derive_key(enc, key, &ke, &d1))
	goto cleanup;

    d1.data[4] = 0x55;

    if (ret = krb5_derive_key(enc, key, &ki, &d1))
	goto cleanup;

    /* put together the plaintext */

    d1.length = blocksize;
    d1.data = plaintext;

    if (ret = krb5_c_random_make_octets(/* XXX */ 0, &d1))
	goto cleanup;

    memcpy(plaintext+blocksize, input->data, input->length);

    memset(plaintext+blocksize+input->length, 0,
	   plainlen - (blocksize+input->length));

    /* encrypt the plaintext */

    d1.length = plainlen;
    d1.data = plaintext;

    d2.length = plainlen;
    d2.data = output->data;

    if (ret = ((*(enc->encrypt))(&ke, ivec, &d1, &d2)))
	goto cleanup;

    /* hash the plaintext */

    d2.length = enclen - plainlen;
    d2.data = output->data+plainlen;

    output->length = enclen;

    if (ret = krb5_hmac(hash, &ki, 1, &d1, &d2))
	memset(d2.data, 0, d2.length);

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

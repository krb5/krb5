#include "k5-int.h"

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

krb5_error_code
krb5_hmac(hash, key, icount, input, output)
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     unsigned int icount;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    size_t hashsize, blocksize;
    unsigned char *xorkey, *ihash;
    int i;
    krb5_data *hashin, hashout;
    krb5_error_code ret;

    (*(hash->hash_size))(&hashsize);
    (*(hash->block_size))(&blocksize);

    if (key->length > blocksize)
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length < hashsize)
	return(KRB5_BAD_MSIZE);
    /* if this isn't > 0, then there won't be enough space in this
       array to compute the outer hash */
    if (icount == 0)
	return(KRB5_CRYPTO_INTERNAL);

    /* allocate space for the xor key, hash input vector, and inner hash */

    if ((xorkey = (unsigned char *) malloc(blocksize)) == NULL)
	return(ENOMEM);
    if ((ihash = (unsigned char *) malloc(hashsize)) == NULL) {
	free(xorkey);
	return(ENOMEM);
    }
    if ((hashin = (krb5_data *)malloc(sizeof(krb5_data)*(icount+1))) == NULL) {
	free(ihash);
	free(xorkey);
	return(ENOMEM);
    }

    /* create the inner padded key */

    memset(xorkey, 0x36, blocksize);

    for (i=0; i<key->length; i++)
	xorkey[i] ^= key->contents[i];

    /* compute the inner hash */

    for (i=0; i<icount; i++) {
	hashin[0].length = blocksize;
	hashin[0].data = xorkey;
	hashin[i+1] = input[i];
    }

    hashout.length = hashsize;
    hashout.data = ihash;

    if (ret = ((*(hash->hash))(icount+1, hashin, &hashout)))
	goto cleanup;

    /* create the outer padded key */

    memset(xorkey, 0x5c, blocksize);

    for (i=0; i<key->length; i++)
	xorkey[i] ^= key->contents[i];

    /* compute the outer hash */

    hashin[0].length = blocksize;
    hashin[0].data = xorkey;
    hashin[1] = hashout;

    output->length = hashsize;

    if (ret = ((*(hash->hash))(2, hashin, output)))
	memset(output->data, 0, output->length);

    /* ret is set correctly by the prior call */

cleanup:
    memset(xorkey, 0, blocksize);
    memset(ihash, 0, hashsize);

    free(hashin);
    free(ihash);
    free(xorkey);

    return(ret);
}

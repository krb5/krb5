#include "k5-int.h"
#include "old.h"

void
krb5_old_encrypt_length(enc, hash, inputlen, length)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     size_t inputlen;
     size_t *length;
{
    size_t blocksize, hashsize;

    (*(enc->block_size))(&blocksize);
    (*(hash->hash_size))(&hashsize);

    *length = krb5_roundup(blocksize+hashsize+inputlen, blocksize);
}

krb5_error_code
krb5_old_encrypt(enc, hash, key, usage, ivec, input, output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    krb5_error_code ret;
    size_t blocksize, hashsize, enclen;
    krb5_data datain, crcivec;

    (*(enc->block_size))(&blocksize);
    (*(hash->hash_size))(&hashsize);

    krb5_old_encrypt_length(enc, hash, input->length, &enclen);

    if (output->length < enclen)
	return(KRB5_BAD_MSIZE);

    output->length = enclen;

    /* fill in confounded, padded, plaintext buffer with zero checksum */

    memset(output->data, 0, output->length);

    datain.length = blocksize;
    datain.data = output->data;

    if (ret = krb5_c_random_make_octets(/* XXX */ 0, &datain))
	return(ret);
    memcpy(output->data+blocksize+hashsize, input->data, input->length);

    /* compute the checksum */

    datain.length = hashsize;
    datain.data = output->data+blocksize;

    if (ret = ((*(hash->hash))(1, output, &datain)))
	goto cleanup;

    /* encrypt it */

    /* XXX this is gross, but I don't have much choice */
    if ((key->enctype == ENCTYPE_DES_CBC_CRC) && (ivec == 0)) {
	crcivec.length = key->length;
	crcivec.data = key->contents;
	ivec = &crcivec;
    }

    if (ret = ((*(enc->encrypt))(key, ivec, output, output)))
	goto cleanup;

cleanup:
    if (ret)
	memset(output->data, 0, output->length);

    return(ret);
}

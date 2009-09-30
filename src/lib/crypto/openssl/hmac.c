/* lib/crypto/openssl/hmac.c
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
krb5_hmac(const struct krb5_hash_provider *hash, const krb5_keyblock *key,
          unsigned int icount, const krb5_data *input, krb5_data *output)
{
    unsigned int i = 0, md_len = 0; 
    unsigned char md[EVP_MAX_MD_SIZE];
    HMAC_CTX c;
    size_t hashsize, blocksize;

    hashsize = hash->hashsize;
    blocksize = hash->blocksize;

    if (key->length > blocksize)
        return(KRB5_CRYPTO_INTERNAL);
    if (output->length < hashsize)
        return(KRB5_BAD_MSIZE);
    /* if this isn't > 0, then there won't be enough space in this
       array to compute the outer hash */
    if (icount == 0)
        return(KRB5_CRYPTO_INTERNAL);

    if (!map_digest(hash))
        return(KRB5_CRYPTO_INTERNAL); // unsupported alg

    HMAC_CTX_init(&c);
    HMAC_Init(&c, key->contents, key->length, map_digest(hash));
    for ( i = 0; i < icount; i++ ) {
        HMAC_Update(&c,(const unsigned char*)input[i].data, input[i].length);
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
krb5int_hmac_iov(const struct krb5_hash_provider *hash, const krb5_keyblock *key,
                 const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    krb5_data *sign_data;
    size_t num_sign_data;
    krb5_error_code ret;
    size_t i, j;

    /* Create a checksum over all the data to be signed */
    for (i = 0, num_sign_data = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (SIGN_IOV(iov))
            num_sign_data++;
    }

    /* XXX cleanup to avoid alloc */
    sign_data = (krb5_data *)calloc(num_sign_data, sizeof(krb5_data));
    if (sign_data == NULL)
        return ENOMEM;

    for (i = 0, j = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (SIGN_IOV(iov))
            sign_data[j++] = iov->data;
    }

    /* caller must store checksum in iov as it may be TYPE_TRAILER or TYPE_CHECKSUM */
    ret = krb5_hmac(hash, key, num_sign_data, sign_data, output);

    free(sign_data);

    return ret;
}


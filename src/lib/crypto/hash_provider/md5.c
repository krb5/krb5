#include "k5-int.h"
#include "rsa-md5.h"
#include "hash_provider.h"

static void
k5_md5_hash_size(size_t *output)
{
    *output = RSA_MD5_CKSUM_LENGTH;
}

static void
k5_md5_block_size(size_t *output)
{
    *output = 64;
}

static krb5_error_code
k5_md5_hash(unsigned int icount, krb5_const krb5_data *input,
	    krb5_data *output)
{
    krb5_MD5_CTX ctx;
    int i;

    if (output->length != RSA_MD5_CKSUM_LENGTH)
	return(KRB5_CRYPTO_INTERNAL);

    krb5_MD5Init(&ctx);
    for (i=0; i<icount; i++)
	krb5_MD5Update(&ctx, input[i].data, input[i].length);
    krb5_MD5Final(&ctx);

    memcpy(output->data, ctx.digest, RSA_MD5_CKSUM_LENGTH);

    return(0);
}

struct krb5_hash_provider krb5_hash_md5 = {
    k5_md5_hash_size,
    k5_md5_block_size,
    k5_md5_hash
};

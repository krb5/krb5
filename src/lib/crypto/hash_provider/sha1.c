#include "k5-int.h"
#include "shs.h"
#include "hash_provider.h"

static void
k5_sha1_hash_size(size_t *output)
{
    *output = SHS_DIGESTSIZE;
}

static void
k5_sha1_block_size(size_t *output)
{
    *output = SHS_DATASIZE;
}

static krb5_error_code
k5_sha1_hash(unsigned int icount, krb5_const krb5_data *input,
	     krb5_data *output)
{
    SHS_INFO ctx;
    int i;

    if (output->length != SHS_DIGESTSIZE)
	return(KRB5_CRYPTO_INTERNAL);

    shsInit(&ctx);
    for (i=0; i<icount; i++)
	shsUpdate(&ctx, input[i].data, input[i].length);
    shsFinal(&ctx);

    for (i=0; i<(sizeof(ctx.digest)/sizeof(ctx.digest[0])); i++) {
	output->data[i*4] = (ctx.digest[i]>>24)&0xff;
	output->data[i*4+1] = (ctx.digest[i]>>16)&0xff;
	output->data[i*4+2] = (ctx.digest[i]>>8)&0xff;
	output->data[i*4+3] = ctx.digest[i]&0xff;
    }

    return(0);
}

struct krb5_hash_provider krb5_hash_sha1 = {
    k5_sha1_hash_size,
    k5_sha1_block_size,
    k5_sha1_hash
};

#include "k5-int.h"
#include "crc-32.h"
#include "hash_provider.h"

static void
k5_crc32_hash_size(size_t *output)
{
    *output = CRC32_CKSUM_LENGTH;
}

static void
k5_crc32_block_size(size_t *output)
{
    *output = 1;
}

static krb5_error_code
k5_crc32_hash(unsigned int icount, krb5_const krb5_data *input,
	      krb5_data *output)
{
    unsigned long c, cn;
    int i;
    
    if (output->length != CRC32_CKSUM_LENGTH)
	return(KRB5_CRYPTO_INTERNAL);

    c = 0;
    for (i=0; i<icount; i++) {
	mit_crc32(input[i].data, input[i].length, &cn);
	c ^= cn;
    }

    output->data[0] = c&0xff;
    output->data[1] = (c>>8)&0xff;
    output->data[2] = (c>>16)&0xff;
    output->data[3] = (c>>24)&0xff;

    return(0);
}

struct krb5_hash_provider krb5_hash_crc32 = {
    k5_crc32_hash_size,
    k5_crc32_block_size,
    k5_crc32_hash
};

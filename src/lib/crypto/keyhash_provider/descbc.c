#include "k5-int.h"
#include "des_int.h"
#include "keyhash_provider.h"

static mit_des_cblock mit_des_zeroblock[8] = {0,0,0,0,0,0,0,0};

static void
k5_descbc_hash_size(size_t *output)
{
    *output = 8;
}

static krb5_error_code
k5_descbc_hash(krb5_const krb5_keyblock *key, krb5_const krb5_data *ivec,
	       krb5_const krb5_data *input, krb5_data *output)
{
    mit_des_key_schedule schedule;
    int ret;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length != 8)
	return(KRB5_CRYPTO_INTERNAL);

    switch (ret = mit_des_key_sched(key->contents, schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }

    /* this has a return value, but it's useless to us */

    mit_des_cbc_cksum(input->data, output->data, input->length,
		      schedule, ivec?ivec->data:(char *)mit_des_zeroblock);

    memset(schedule, 0, sizeof(schedule));

    return(0);
}

struct krb5_keyhash_provider krb5_keyhash_descbc = {
    k5_descbc_hash_size,
    k5_descbc_hash,
    NULL
};

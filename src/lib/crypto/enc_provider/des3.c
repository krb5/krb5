#include "k5-int.h"
#include "des_int.h"

static mit_des_cblock mit_des_zeroblock[8] = {0,0,0,0,0,0,0,0};

static void
k5_des3_block_size(size_t *blocksize)
{
    *blocksize = 8;
}

static void
k5_des3_keysize(size_t *keybytes, size_t *keylength)
{
    *keybytes = 21;
    *keylength = 24;
}

static krb5_error_code
k5_des3_docrypt(krb5_const krb5_keyblock *key, krb5_const krb5_data *ivec,
		krb5_const krb5_data *input, krb5_data *output, int encrypt)
{
    mit_des3_key_schedule schedule;
    int ret;

    /* key->enctype was checked by the caller */

    if (key->length != 24)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
	return(KRB5_BAD_MSIZE);

    switch (ret = mit_des3_key_sched(*(mit_des3_cblock *)key->contents,
				     schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }

    /* this has a return value, but the code always returns zero */

    mit_des3_cbc_encrypt((krb5_pointer) input->data,
			 (krb5_pointer) output->data, input->length,
			 schedule[0], schedule[1], schedule[2],
			 ivec?ivec->data:(char *)mit_des_zeroblock,
			 encrypt);

    memset(schedule, 0, sizeof(schedule));

    return(0);
}

static krb5_error_code
k5_des3_encrypt(krb5_const krb5_keyblock *key, krb5_const krb5_data *ivec,
		krb5_const krb5_data *input, krb5_data *output)
{
    return(k5_des3_docrypt(key, ivec, input, output, 1));
}

static krb5_error_code
k5_des3_decrypt(krb5_const krb5_keyblock *key, krb5_const krb5_data *ivec,
		krb5_const krb5_data *input, krb5_data *output)
{
    return(k5_des3_docrypt(key, ivec, input, output, 0));
}

static krb5_error_code
k5_des3_make_key(krb5_const krb5_data *randombits, krb5_keyblock *key)
{
    int i;

    if (key->length != 24)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != 21)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;
    key->length = 24;

    /* take the seven bytes, move them around into the top 7 bits of the
       8 key bytes, then compute the parity bits.  Do this three times. */

    for (i=0; i<3; i++) {
	memcpy(key->contents+i*8, randombits->data+i*7, 7);
	key->contents[i*8+7] = (((key->contents[i*8]&1)<<1) |
				((key->contents[i*8+1]&1)<<2) |
				((key->contents[i*8+2]&1)<<3) |
				((key->contents[i*8+3]&1)<<4) |
				((key->contents[i*8+4]&1)<<5) |
				((key->contents[i*8+5]&1)<<6) |
				((key->contents[i*8+6]&1)<<7));

	mit_des_fixup_key_parity(key->contents+i*8);
    }

    return(0);
}

struct krb5_enc_provider krb5_enc_des3 = {
    k5_des3_block_size,
    k5_des3_keysize,
    k5_des3_encrypt,
    k5_des3_decrypt,
    k5_des3_make_key
};

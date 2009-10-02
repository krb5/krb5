/* lib/crypto/openssl/des/d3_cbc.c
 *
 * Copyright 2009 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 */
#include "des_int.h"

/*
 * Triple-DES CBC encryption mode.
 */

#undef mit_des3_cbc_encrypt
int
mit_des3_cbc_encrypt(const mit_des_cblock *in, mit_des_cblock *out,
		     unsigned long length, const mit_des_key_schedule ks1,
		     const mit_des_key_schedule ks2,
		     const mit_des_key_schedule ks3,
		     const mit_des_cblock ivec, int enc)
{
    /* Unsupported operation */
    return KRB5_CRYPTO_INTERNAL;
}

void
krb5int_des3_cbc_encrypt(const mit_des_cblock *input,
			 mit_des_cblock *output,
			 unsigned long length,
			 const mit_des_key_schedule key,
			 const mit_des_key_schedule ks2,
			 const mit_des_key_schedule ks3,
			 const mit_des_cblock ivec)
{
    /* Unsupported operation */
    abort();
}

void
krb5int_des3_cbc_decrypt(const mit_des_cblock *in,
			 mit_des_cblock *out,
			 unsigned long length,
			 const mit_des_key_schedule ks1,
			 const mit_des_key_schedule ks2,
			 const mit_des_key_schedule ks3,
			 const mit_des_cblock ivec)
{
    /* Unsupported operation */
    abort();
}


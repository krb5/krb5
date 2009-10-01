/* lib/crypto/openssl/des/d3_aead.c
 *
 * Copyright 2009 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 */
#include "des_int.h"
#include "aead.h"

void
krb5int_des3_cbc_encrypt_iov(krb5_crypto_iov *data,
			     unsigned long num_data,
			     const mit_des_key_schedule ks1,
			     const mit_des_key_schedule ks2,
			     const mit_des_key_schedule ks3,
			     mit_des_cblock ivec)
{
    /* Unsupported operation */
    abort();
}

void
krb5int_des3_cbc_decrypt_iov(krb5_crypto_iov *data,
			     unsigned long num_data,
			     const mit_des_key_schedule ks1,
			     const mit_des_key_schedule ks2,
			     const mit_des_key_schedule ks3,
			     mit_des_cblock ivec)
{
    /* Unsupported operation */
    abort();
}


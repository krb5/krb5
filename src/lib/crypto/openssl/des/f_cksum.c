/*
 * lib/crypto/openssl/des/f_cksum.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
 */

#include "des_int.h"

unsigned long
mit_des_cbc_cksum(const krb5_octet *in, krb5_octet *out,
		  unsigned long length, const mit_des_key_schedule schedule,
		  const krb5_octet *ivec)
{
    /* Unsupported operation */
    return KRB5_CRYPTO_INTERNAL; 
}


/*
 * lib/crypto/openssl/des/key_sched.c
 *
 * Copyright 2009 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 */

#include "des_int.h"

int
mit_des_key_sched(mit_des_cblock k, mit_des_key_schedule schedule)
{
    /* Unsupported operation */
    return KRB5_CRYPTO_INTERNAL; 
}


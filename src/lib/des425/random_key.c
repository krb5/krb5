/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#ifndef	lint
static char rcsid_random_key_c[] =
"$Header$";
#endif /* lint */

#include "des.h"

/* random_key */
int
des_random_key(key)
    mit_des_cblock *key;
{
    mit_des_random_key_seed	p_seed;
    mit_des_cblock		nullkey;

    bzero(nullkey, sizeof(mit_des_cblock));
    mit_des_fixup_key_parity(key);
    mit_des_init_random_number_generator(nullkey,&p_seed);
    do {
	mit_des_generate_random_block(key, &p_seed);
	mit_des_fixup_key_parity(key);
    } while (mit_des_is_weak_key(key));

    return(0);
}


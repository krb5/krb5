/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_init_rkey_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "des_int.h"

/*
        initialize the random key generator using the encryption key,
        "seedblock", and allocating private sequence information, filling
        in "seed" with the address of such information.
        "seed" is later passed to the random_key() function to provide
        sequence information.
 */

krb5_error_code mit_des_init_random_key (DECLARG(const krb5_keyblock *,seedblock),
					 DECLARG(krb5_pointer *,seed))
OLDDECLARG(const krb5_keyblock *,seedblock)
OLDDECLARG(krb5_pointer *,seed)
{
    mit_des_random_key_seed * p_seed;
    if (seedblock->keytype != KEYTYPE_DES)
	return KRB5_BAD_KEYTYPE;
    if ( !(p_seed = (mit_des_random_key_seed *) 
	   malloc(sizeof(mit_des_random_key_seed))) ) 
	return ENOMEM;
    memset((char *)p_seed, 0, sizeof(mit_des_random_key_seed) );
    mit_des_init_random_number_generator(seedblock->contents, p_seed);
    *seed = (krb5_pointer) p_seed;
    return 0;
}

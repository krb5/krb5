/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char des_inr_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <sys/errno.h>

#include <krb5/krb5.h>
#include <krb5/des.h>
#include <krb5/ext-proto.h>
#include <krb5/krb5_err.h>

extern void des_init_random_number_generator();

/*
        initialize the random key generator using the encryption key,
        "seedblock", and allocating private sequence information, filling
        in "seed" with the address of such information.
        "seed" is later passed to the random_key() function to provide
        sequence information.
 */

krb5_error_code mit_des_init_random_key (DECLARG(krb5_keyblock *,seedblock),
					 DECLARG(krb5_pointer *,seed))
OLDDECLARG(krb5_keyblock *,seedblock)
OLDDECLARG(krb5_pointer *,seed)
{
    des_random_key_seed * p_seed;
    if (seedblock->keytype != KEYTYPE_DES)
	return KRB5_BAD_KEYTYPE;	  /* XXX error code bad keytype */
    if ( !(p_seed = (des_random_key_seed *) 
	   malloc(sizeof(des_random_key_seed))) ) 
	return ENOMEM;
    bzero( (char *)p_seed, sizeof(des_random_key_seed) );
    des_init_random_number_generator(seedblock->contents, p_seed);
    *seed = (krb5_pointer) p_seed;
    return 0;
}

/*
 * lib/crypto/des/init_rkey.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "des_int.h"

/*
        initialize the random key generator using the encryption key,
        "seedblock", and allocating private sequence information, filling
        in "seed" with the address of such information.
        "seed" is later passed to the random_key() function to provide
        sequence information.
 */

krb5_error_code
mit_des_init_random_key (seedblock, seed)
    const krb5_keyblock * seedblock;
    krb5_pointer * seed;
{
    mit_des_random_key_seed * p_seed;
    if ((seedblock->keytype != KEYTYPE_DES_CBC_CRC) &&
	(seedblock->keytype != KEYTYPE_DES_CBC_MD4) && 
	(seedblock->keytype != KEYTYPE_DES_CBC_MD5) && 
	(seedblock->keytype != KEYTYPE_DES_CBC_RAW))
	return KRB5_BAD_KEYTYPE;
    if ( !(p_seed = (mit_des_random_key_seed *) 
	   malloc(sizeof(mit_des_random_key_seed))) ) 
	return ENOMEM;
    memset((char *)p_seed, 0, sizeof(mit_des_random_key_seed) );
    mit_des_init_random_number_generator(seedblock->contents, p_seed);
    *seed = (krb5_pointer) p_seed;
    return 0;
}

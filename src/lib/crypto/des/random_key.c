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

#if !defined(lint) && !defined(SABER)
static char rcsid_random_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "des_int.h"
/*
        generate a random encryption key, allocating storage for it and
        filling in the keyblock address in *keyblock
 */

krb5_error_code mit_des_random_key (DECLARG(krb5_pointer, seed),
				    DECLARG(krb5_keyblock **, keyblock))
OLDDECLARG(krb5_pointer, seed)
OLDDECLARG(krb5_keyblock **, keyblock)
{
    krb5_keyblock *randkey;

    if (!(randkey = (krb5_keyblock *)malloc(sizeof(*randkey))))
	return ENOMEM;
    if (!(randkey->contents = (krb5_octet *)malloc(sizeof(mit_des_cblock)))) {
	xfree(randkey);
	return ENOMEM;
    }
    randkey->length = sizeof(mit_des_cblock);
    randkey->keytype = KEYTYPE_DES;
    mit_des_new_random_key(randkey->contents, (mit_des_random_key_seed *) seed);
    *keyblock = randkey;
    return 0;
}

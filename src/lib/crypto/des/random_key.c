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
static char des_ran_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <sys/errno.h>

#include <krb5/krb5.h>
#include <krb5/des.h>
#include <krb5/ext-proto.h>

extern int des_new_random_key();

/*
        generate a random encryption key, allocating storage for it and
        filling in the keyblock address in *keyblock
 */

krb5_error_code random_key (DECLARG(krb5_pointer, seed),
				   DECLARG(krb5_keyblock **, keyblock))
OLDDECLARG(krb5_pointer, seed)
OLDDECLARG(krb5_keyblock **, keyblock)
{
    krb5_keyblock *randkey;

    if (!(randkey = (krb5_keyblock *)malloc(sizeof(*randkey))))
	return ENOMEM;
    if (!(randkey->contents = (krb5_octet *)malloc(sizeof(des_cblock)))) {
	free((char *)randkey);
	return ENOMEM;
    }
    randkey->length = sizeof(des_cblock);
    randkey->keytype = KEYTYPE_DES;
    des_new_random_key(randkey->contents, (des_random_key_seed *) seed);
    *keyblock = randkey;
    return 0;
}

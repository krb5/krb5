/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * 
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

/*
 * Copyright 1995 by Richard P. Basch.  All Rights Reserved.
 * Copyright 1995 by Lehman Brothers, Inc.  All Rights Reserved.
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
 * the name of Richard P. Basch, Lehman Brothers and M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Richard P. Basch,
 * Lehman Brothers and M.I.T. make no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include "k5-int.h"
#include "des_int.h"

krb5_error_code
mit_des3_random_key (eblock, seed, keyblock)
    const krb5_encrypt_block * eblock;
    krb5_pointer seed;
    krb5_keyblock ** keyblock;
{
    krb5_keyblock *randkey;

    if (!(randkey = (krb5_keyblock *)malloc(sizeof(*randkey))))
	return ENOMEM;
    if (!(randkey->contents=(krb5_octet *)malloc(sizeof(mit_des3_cblock)))) {
	krb5_xfree(randkey);
	return ENOMEM;
    }
    randkey->magic = KV5M_KEYBLOCK;
    randkey->length = sizeof(mit_des3_cblock);
    randkey->enctype = eblock->crypto_entry->proto_enctype;
    mit_des_new_random_key(*(mit_des_cblock *)randkey->contents,
			   (mit_des_random_key_seed *) seed);
    mit_des_new_random_key(*((mit_des_cblock *)randkey->contents + 1),
			   (mit_des_random_key_seed *) seed);
    mit_des_new_random_key(*((mit_des_cblock *)randkey->contents + 2),
			   (mit_des_random_key_seed *) seed);
    *keyblock = randkey;
    return 0;
}

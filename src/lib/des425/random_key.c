/*
 * lib/des425/random_key.c
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


#include "des.h"

extern krb5_pointer des425_random_state;

/* random_key */
int
des_random_key(key)
    mit_des_cblock *key;
{
    krb5_encrypt_block	eblock;
    krb5_keyblock	keyblock;
    krb5_keyblock	*new_key;
    krb5_error_code	kret;
    mit_des_cblock	nullkey;

    krb5_use_enctype(NULL, &eblock, ENCTYPE_DES_CBC_CRC);

    memset(nullkey, 0, sizeof(mit_des_cblock));
    mit_des_fixup_key_parity(*key);

    keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    keyblock.length = sizeof(mit_des_cblock);
    keyblock.contents = (krb5_octet *)nullkey;

    if (! des425_random_state)
	mit_des_init_random_key(&eblock, &keyblock, &des425_random_state);

    kret = mit_des_random_key(NULL, des425_random_state, &new_key);
    if (kret) return kret;

    memcpy(key, new_key->contents, sizeof(mit_des_cblock));
    krb5_free_keyblock(NULL, new_key);
    return(0);
}


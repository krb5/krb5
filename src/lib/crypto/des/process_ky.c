/*
 * lib/crypto/des/process_ky.c
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
        does any necessary key preprocessing (such as computing key
                schedules for DES).
        eblock->crypto_entry must be set by the caller; the other elements
        of eblock are to be assigned by this function.
        [in particular, eblock->key must be set by this function if the key
        is needed in raw form by the encryption routine]

        The caller may not move or reallocate "keyblock" before calling
        finish_key on "eblock"

        returns: errors
 */

krb5_error_code
mit_des_process_key (eblock, keyblock)
    krb5_encrypt_block * eblock;
    const krb5_keyblock * keyblock;
{
    struct mit_des_ks_struct       *schedule;      /* pointer to key schedules */
    
    if (keyblock->length != sizeof (mit_des_cblock))
	return KRB5_BAD_KEYSIZE;

    if ( !(schedule = (struct mit_des_ks_struct *) malloc(sizeof(mit_des_key_schedule))) )
        return ENOMEM;
#define cleanup() { free( (char *) schedule); }

    switch (mit_des_key_sched (keyblock->contents, schedule)) {
    case -1:
	cleanup();
	return KRB5DES_BAD_KEYPAR;

    case -2:
	cleanup();
	return KRB5DES_WEAK_KEY;

    default:
	eblock->key = (krb5_keyblock *) keyblock;
	eblock->priv = (krb5_pointer) schedule;
	eblock->priv_size = (krb5_int32) sizeof(mit_des_key_schedule);
	return 0;
    }
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_process_ky_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

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

krb5_error_code mit_des_process_key (DECLARG(krb5_encrypt_block *, eblock),
				     DECLARG(const krb5_keyblock *,keyblock))
OLDDECLARG(krb5_encrypt_block *, eblock)
OLDDECLARG(const krb5_keyblock *,keyblock)
{
    struct mit_des_ks_struct       *schedule;      /* pointer to key schedules */
    
    if (keyblock->length != sizeof (mit_des_cblock))
	return KRB5_BAD_KEYSIZE;	/* XXX error code-bad key size */

    if ( !(schedule = (struct mit_des_ks_struct *) malloc(sizeof(mit_des_key_schedule))) )
        return ENOMEM;
#define cleanup() { free( (char *) schedule); }

    switch (mit_des_key_sched (keyblock->contents, schedule)) {
    case -1:
	cleanup();
	return KRB5DES_BAD_KEYPAR;	/* XXX error code-bad key parity */

    case -2:
	cleanup();
	return KRB5DES_WEAK_KEY;	/* XXX error code-weak key */

    default:
	eblock->key = (krb5_keyblock *) keyblock;
	eblock->priv = (krb5_pointer) schedule;
	return 0;
    }
}

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
mit_des3_process_key (eblock, keyblock)
    krb5_encrypt_block * eblock;
    const krb5_keyblock * keyblock;
{
    struct mit_des_ks_struct       *schedule;      /* pointer to key schedules */

    if ((keyblock->enctype != ENCTYPE_DES3_CBC_SHA) &&
	(keyblock->enctype != ENCTYPE_DES3_CBC_RAW))
	return KRB5_PROG_ETYPE_NOSUPP;

    if (keyblock->length != sizeof (mit_des3_cblock))
	return KRB5_BAD_KEYSIZE;

    if ( !(schedule = (struct mit_des_ks_struct *) malloc(3*sizeof(mit_des_key_schedule))) )
        return ENOMEM;
#define cleanup() { free( (char *) schedule); }

    switch (mit_des3_key_sched (*(mit_des3_cblock *)keyblock->contents,
				*(mit_des3_key_schedule *)schedule)) {
    case -1:
	cleanup();
	return KRB5DES_BAD_KEYPAR;

    case -2:
	cleanup();
	return KRB5DES_WEAK_KEY;
    }

    eblock->key = (krb5_keyblock *) keyblock;
    eblock->priv = (krb5_pointer) schedule;
    eblock->priv_size = (krb5_int32) 3*sizeof(mit_des_key_schedule);

    return 0;
}

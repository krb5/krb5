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

/*
 * Triple-DES string-to-key algorithm
 *
 * 1. Concatenate the input string and salt, and pad with zeroes until
 *    it is at least 24 bits, and a multiple of eight.
 * 2. Fanfold the bits into a 24 bytes of key information (3 DES keys).
 * 3. Use the three DES keys to perform a triple CBC encryption and return
 *    the last 24 bytes (similar to the MAC computation for DES in FIPS 81).
 *
 * This routine assumes that the triple CBC checksum will do the appropriate
 * padding and that its return value will be 24 bytes.
 */

static mit_des_cblock zero_ivec = { 0, 0, 0, 0, 0, 0, 0, 0 };

krb5_error_code
mit_des3_string_to_key (eblock, keyblock, data, salt)
const krb5_encrypt_block FAR * eblock;
krb5_keyblock FAR * keyblock;
const krb5_data FAR * data;
const krb5_data FAR * salt;
{
    register char *str, *copystr;
    register mit_des_cblock *key;
    register int j;

    register long length;
    mit_des3_key_schedule ks;
    krb5_enctype enctype = eblock->crypto_entry->proto_enctype;

    if (enctype == ENCTYPE_DES3_CBC_MD5)
	keyblock->length = sizeof(mit_des3_cblock);
    else
	return (KRB5_PROG_ETYPE_NOSUPP);

    if ( !(keyblock->contents = (krb5_octet *)malloc(keyblock->length)) )
	return(ENOMEM);

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->enctype = enctype;
    key = (mit_des_cblock *)keyblock->contents;

    if (salt)
	length = data->length + salt->length;
    else
	length = data->length;

    if (length < keyblock->length)
	length = keyblock->length;

    copystr = malloc((size_t) length);
    if (!copystr) {
	free(keyblock->contents);
	keyblock->contents = 0;
	return ENOMEM;
    }

    memset(copystr, 0, length);
    memcpy(copystr, (char *) data->data, data->length);
    if (salt)
	memcpy(copystr + data->length, (char *)salt->data, salt->length);

    /* n-fold into des3 key */
    if (mit_des_n_fold(copystr, length, keyblock->contents, keyblock->length))
	return EINVAL;
	
    /* fix key parity */
    for (j = 0; j < keyblock->length/sizeof(mit_des_cblock); j++)
	mit_des_fixup_key_parity(*((mit_des_cblock *)key+j));

    /* Now, CBC encrypt with itself */
    (void) mit_des3_key_sched(*((mit_des3_cblock *)key), ks);
    (void) mit_des3_cbc_encrypt((mit_des_cblock *)key,
				(mit_des_cblock *)key,
				keyblock->length,
				((mit_des_key_schedule *)ks)[0],
				((mit_des_key_schedule *)ks)[1],
				((mit_des_key_schedule *)ks)[2],
				zero_ivec, TRUE);

    /* erase key_sked */
    memset((char *)ks, 0, sizeof(ks));

    /* clean & free the input string */
    memset(copystr, 0, (size_t) length);
    krb5_xfree(copystr);

    /* now fix up key parity again */
    for (j = 0; j < keyblock->length/sizeof(mit_des_cblock); j++)
	mit_des_fixup_key_parity(*((mit_des_cblock *)key+j));

    return 0;
}

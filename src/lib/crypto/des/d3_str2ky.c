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
 * 168-fold the input string (appended with any salt), and treat the resulting
 * 168 bits as three DES keys sans parity.  Process each set of 56 bits into
 * a usable DES key with odd parity, and then encrypt the set of three usable
 * DES keys using Triple-DES CBC mode.  The result is then treated as three
 * DES keys, and should be corrected for parity.  Any DES key that is weak or
 * semi-weak is to be corrected by eXclusive-ORing the first octet with the
 * value 0xF0.
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

    /* n-fold into des3 key sans parity */
    if (mit_des_n_fold(copystr, length, keyblock->contents,
		       keyblock->length * 7 / 8))
	return EINVAL;

    /* Add space for parity (low bit) */
    for (j = keyblock->length; j--; ) {
	register int k;

	k = (8-(j%8)) & 7;
	keyblock->contents[j] =
	    ((keyblock->contents[j*7/8] << k) & 0xfe) +
	    ((k>1) ? keyblock->contents[j*7/8 +1] >> (8-k) : 0);
    }
	
    /* fix key parity */
    for (j = 0; j < keyblock->length/sizeof(mit_des_cblock); j++) {
	mit_des_fixup_key_parity(key[j]);
	if (mit_des_is_weak_key(key[j]))
	    *((krb5_octet *)(key[j])) ^= 0xf0;
    }

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
    for (j = 0; j < keyblock->length/sizeof(mit_des_cblock); j++) {
	mit_des_fixup_key_parity(key[j]);
	if (mit_des_is_weak_key(key[j]))
	    *((krb5_octet *)(key[j])) ^= 0xf0;
    }

    return 0;
}

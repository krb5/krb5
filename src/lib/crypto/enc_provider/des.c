/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "des_int.h"
#include "enc_provider.h"

static krb5_error_code
k5_des_docrypt(const krb5_keyblock *key, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output, int enc)
{
    mit_des_key_schedule schedule;

    /* key->enctype was checked by the caller */

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
	return(KRB5_BAD_MSIZE);

    switch (mit_des_key_sched(key->contents, schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }

    /* this has a return value, but the code always returns zero */

    mit_des_cbc_encrypt((krb5_pointer) input->data,
			(krb5_pointer) output->data, input->length,
			schedule,
			(ivec
			 ? (unsigned char *) ivec->data
			 : (unsigned char *) mit_des_zeroblock),
			enc);

    memset(schedule, 0, sizeof(schedule));

    return(0);
}

static krb5_error_code
k5_des_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output)
{
    return(k5_des_docrypt(key, ivec, input, output, 1));
}

static krb5_error_code
k5_des_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output)
{
    return(k5_des_docrypt(key, ivec, input, output, 0));
}

static krb5_error_code
k5_des_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != 7)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;
    key->length = 8;

    /* take the seven bytes, move them around into the top 7 bits of the
       8 key bytes, then compute the parity bits */

    memcpy(key->contents, randombits->data, randombits->length);
    key->contents[7] = (((key->contents[0]&1)<<1) | ((key->contents[1]&1)<<2) |
			((key->contents[2]&1)<<3) | ((key->contents[3]&1)<<4) |
			((key->contents[4]&1)<<5) | ((key->contents[5]&1)<<6) |
			((key->contents[6]&1)<<7));

    mit_des_fixup_key_parity(key->contents);

    return(0);
}

const struct krb5_enc_provider krb5int_enc_des = {
    8,
    7, 8,
    k5_des_encrypt,
    k5_des_decrypt,
    k5_des_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state
};

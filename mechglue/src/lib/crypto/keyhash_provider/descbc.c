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
#include "keyhash_provider.h"

static krb5_error_code
k5_descbc_hash(const krb5_keyblock *key, krb5_keyusage usage, const krb5_data *ivec,
	       const krb5_data *input, krb5_data *output)
{
    mit_des_key_schedule schedule;

    if (key->length != 8)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_CRYPTO_INTERNAL);
    if (output->length != 8)
	return(KRB5_CRYPTO_INTERNAL);

    switch (mit_des_key_sched(key->contents, schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }

    /* this has a return value, but it's useless to us */

    mit_des_cbc_cksum((unsigned char *) input->data, 
		      (unsigned char *) output->data, input->length,
		      schedule, 
		      ivec? (unsigned char *)ivec->data: 
		            (unsigned char *)mit_des_zeroblock);

    memset(schedule, 0, sizeof(schedule));

    return(0);
}

const struct krb5_keyhash_provider krb5int_keyhash_descbc = {
    8,
    k5_descbc_hash,
    NULL
};

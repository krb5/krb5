/*
 * lib/crypto/des/random_key.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * Copyright 1996 by Lehman Brothers, Inc.
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
 * the name of M.I.T. or Lehman Brothers not be used in advertising or
 * publicity pertaining to distribution of the software without
 * specific, written prior permission.  M.I.T. and Lehman Brothers
 * make no representations about the suitability of this software for
 * any purpose.  It is provided "as is" without express or implied
 * warranty.
 */

#include "k5-int.h"
#include "des_int.h"

static void mit_des_generate_random_key
	PROTOTYPE((mit_des_random_state * state, krb5_keyblock * randkey));


/*
        generate a random encryption key, allocating storage for it and
        filling in the keyblock address in *keyblock
 */

krb5_error_code
mit_des_random_key (eblock, state, keyblock)
    const krb5_encrypt_block * eblock;
    krb5_pointer state;
    krb5_keyblock ** keyblock;
{
    krb5_keyblock *randkey;
    int keysize = ((mit_des_random_state *)state)->eblock.crypto_entry->keysize;

    if (eblock == NULL)
	/* We are being called from the random number initialization routine */
	eblock = &((mit_des_random_state *)state)->eblock;

    if (!(randkey = (krb5_keyblock *)malloc(sizeof(*randkey))))
	return ENOMEM;
    if (!(randkey->contents = (krb5_octet *)malloc(keysize))) {
	krb5_xfree(randkey);
	return ENOMEM;
    }
    randkey->magic = KV5M_KEYBLOCK;
    randkey->length = keysize;
    randkey->enctype = eblock->crypto_entry->proto_enctype;

    do {
	mit_des_generate_random_key(state, randkey);
	mit_des_fixup_keyblock_parity(randkey);
    } while (mit_des_is_weak_keyblock(randkey));

    *keyblock = randkey;
    return 0;
}

static mit_des_cblock zero_ivec = { 0, 0, 0, 0, 0, 0, 0, 0 };

static void
mit_des_generate_random_key(state, randkey)
    mit_des_random_state * state;
    krb5_keyblock * randkey;
{
    krb5_encrypt_block *eblock = &state->eblock;
    int i;

    (* state->eblock.crypto_entry->encrypt_func)
	(state->sequence.data /*in*/, randkey->contents /*out*/,
	 state->sequence.length, eblock, zero_ivec);
    (* state->eblock.crypto_entry->encrypt_func)
	(randkey->contents /*in*/, randkey->contents /*out*/,
	 randkey->length, eblock,
	 randkey->contents + randkey->length - sizeof(mit_des_cblock));

    /* Increment the sequence number, with wraparound (LSB) */
    for (i = 0; i < state->sequence.length; i++) {
	state->sequence.data[i] = (state->sequence.data[i] + 1) & 0xff;
	if (state->sequence.data[i])
	    break;
    }
}

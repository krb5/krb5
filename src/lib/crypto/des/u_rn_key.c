/*
 * Copyright 1996 by Richard P. Basch.  All Rights Reserved.
 * Copyright 1996 by Lehman Brothers, Inc.  All Rights Reserved.
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
 *
 *
 * Based on the version written by Mark Lillibridge, MIT Project Athena.
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 */

#include "k5-int.h"
#include "des_int.h"

int
mit_des_is_weak_keyblock(keyblock)
    krb5_keyblock * keyblock;
{
    int i;
    
    for (i = 0; i < keyblock->length/sizeof(mit_des_cblock); i++)
	if (mit_des_is_weak_key(*((mit_des_cblock *)keyblock->contents + i)))
	    return 1;
    return 0;
}

void
mit_des_fixup_keyblock_parity(keyblock)
    krb5_keyblock * keyblock;
{
    int i;
    
    for (i = 0; i < keyblock->length/sizeof(mit_des_cblock); i++)
	mit_des_fixup_key_parity(*((mit_des_cblock *)keyblock->contents + i));
}

/*
 * mit_des_set_random_generator_seed: this routine is used to select a random
 *                                number stream.  The stream that results is
 *                                totally determined by the passed in key.
 *                                (I.e., calling this routine again with the
 *                                same key allows repeating a sequence of
 *                                random numbers)
 */
krb5_error_code
mit_des_set_random_generator_seed(seed, p_state)
    const krb5_data * seed;
    krb5_pointer p_state;
{
    krb5_error_code kret;
    register int i;
    mit_des_cblock *new_key;
    mit_des_random_state *state = p_state;

    if (state->eblock.key) {
	if (state->eblock.key->contents) {
	    memset(state->eblock.key->contents, 0, state->eblock.key->length);
	    krb5_xfree(state->eblock.key->contents);
	}
    }

    state->eblock.key = (krb5_keyblock *)malloc(sizeof(krb5_keyblock));
    if (! state->eblock.key)
	return ENOMEM;

    state->eblock.key->enctype = state->eblock.crypto_entry->proto_enctype;
    state->eblock.key->length = state->eblock.crypto_entry->keysize;
    state->eblock.key->contents = (krb5_octet *)malloc(state->eblock.key->length);
    if (! state->eblock.key->contents) {
	krb5_xfree(state->eblock.key);
	state->eblock.key = 0;
	return ENOMEM;
    }

    kret = mit_des_n_fold(seed->data, seed->length,
		state->eblock.key->contents, state->eblock.key->length);
    if (kret) return kret;

    mit_des_fixup_keyblock_parity(state->eblock.key);

    for (i = 0; i < state->eblock.key->length/sizeof(mit_des_cblock); i++) {
	new_key = (mit_des_cblock *)state->eblock.key->contents + i;
	if (mit_des_is_weak_key(*new_key)) {
	    (*new_key)[0] ^= 0xF0;
	    mit_des_fixup_key_parity(*new_key);
	}
    }

    /* destroy any old key schedule */
    mit_des_finish_key(&state->eblock);
    
    /* compute the key schedule */
    (* state->eblock.crypto_entry->process_key)
	(&state->eblock, state->eblock.key);

    /* now we can destroy the key... */
    memset(state->eblock.key->contents, 0, state->eblock.key->length);
    krb5_xfree(state->eblock.key->contents);
    krb5_xfree(state->eblock.key);
    state->eblock.key = (krb5_keyblock *) 0;

    /* "seek" to the start of the stream: */
    memset(state->sequence.data, 0, state->sequence.length);

    return 0;
}

krb5_error_code
mit_des_set_random_sequence_number(sequence, p_state)
    const krb5_data *sequence;
    krb5_pointer p_state;
{
    mit_des_random_state *state = p_state;
    int length = state->eblock.crypto_entry->keysize;

    if (length > sequence->length)
	length = sequence->length;

    memcpy(state->sequence.data, sequence->data, length);
    
    return 0;
}

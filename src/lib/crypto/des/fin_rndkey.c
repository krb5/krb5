/*
 * lib/crypto/des/fin_rndkey.c
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

/*
        free any resources held by "seed" and assigned by init_random_key()
 */

krb5_error_code mit_des_finish_random_key (eblock, p_state)
    const krb5_encrypt_block * eblock;
    krb5_pointer * p_state;
{
    mit_des_random_state * state = *p_state;

    if (! state) return 0;

    if (state->sequence.data) {
	memset((char *)state->sequence.data, 0, state->sequence.length);
	krb5_xfree(state->sequence.data);
    }

    mit_des_finish_key(&state->eblock);

    krb5_xfree(state);
    *p_state = 0;
    return 0;
}

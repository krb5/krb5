/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * 
 *
 */

#ifndef	lint
static char rcsid_random_key_c[] =
"$Header$";
#endif /* lint */

#include "des.h"

/* random_key */
int
des_random_key(key)
    mit_des_cblock *key;
{
    mit_des_random_key_seed	p_seed;
    mit_des_cblock		nullkey;

    memset(nullkey, 0, sizeof(mit_des_cblock));
    mit_des_fixup_key_parity(key);
    mit_des_init_random_number_generator(nullkey,&p_seed);
    do {
	mit_des_generate_random_block(key, &p_seed);
	mit_des_fixup_key_parity(key);
    } while (mit_des_is_weak_key(key));

    return(0);
}


/*
 * lib/des425/new_rnd_key.c
 *
 * Copyright 1988,1990 by the Massachusetts Institute of Technology.
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


#include "des.h"

/*
 * des_init_random_number_generator:
 *
 *    This routine takes a secret key possibly shared by a number
 * of servers and uses it to generate a random number stream that is
 * not shared by any of the other servers.  It does this by using the current
 * process id, host id, and the current time to the nearest second.  The
 * resulting stream seed is not useful information for cracking the secret
 * key.   Moreover, this routine keeps no copy of the secret key.
 * This routine is used for example, by the kerberos server(s) with the
 * key in question being the kerberos master key.
 *
 * Note: this routine calls des_set_random_generator_seed.
 */
void
des_init_random_number_generator(key)
    mit_des_cblock key;
{
    krb5_data seed;

    seed.length = sizeof(key);
    seed.data = key;

    if (krb5_c_random_seed(/* XXX */ 0, &seed))
	/* XXX */ abort();
}

/*
 * des_new_random_key: create a random des key
 *
 * Requires: des_set_random_number_generater_seed must be at called least
 *           once before this routine is called.
 *
 * Notes: the returned key has correct parity and is guarenteed not
 *        to be a weak des key.  Des_generate_random_block is used to
 *        provide the random bits.
 */
KRB5_DLLIMP int KRB5_CALLCONV
des_new_random_key(key)
    mit_des_cblock key;
{
    krb5_keyblock keyblock;
    krb5_error_code kret;

    kret = krb5_c_make_random_key(/* XXX */ 0, ENCTYPE_DES_CBC_CRC, &keyblock);
    if (kret) return kret;
    
    memcpy(key, keyblock.contents, sizeof(mit_des_cblock));
    krb5_free_keyblock_contents(/* XXX */ 0, &keyblock);

    return 0;
}


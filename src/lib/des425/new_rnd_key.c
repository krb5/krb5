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


#include "des.h"

krb5_pointer des425_random_state = 0;

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
int
des_new_random_key(key)
    mit_des_cblock key;
{
    krb5_keyblock * keyblock;
    krb5_error_code kret;

    kret = mit_des_random_key(NULL, des425_random_state, &keyblock);
    if (kret) return kret;
    
    memcpy(key, keyblock->contents, sizeof(mit_des_cblock));
    krb5_free_keyblock(NULL, keyblock);
    return 0;
}

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
    krb5_keyblock keyblock;
    krb5_encrypt_block eblock;

    krb5_use_enctype(NULL, &eblock, ENCTYPE_DES_CBC_CRC);

    keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    keyblock.length = sizeof(mit_des_cblock);
    keyblock.contents = (krb5_octet *)key;

    if (des425_random_state)
	mit_des_finish_random_key(&eblock, &des425_random_state);
    mit_des_init_random_key(&eblock, &keyblock, &des425_random_state);
}

/*
 * This module implements a random number generator faculty such that the next
 * number in any random number stream is very hard to predict without knowing
 * the seed for that stream even given the preceeding random numbers.
 */

/*
 * des_set_random_generator_seed: this routine is used to select a random
 *                                number stream.  The stream that results is
 *                                totally determined by the passed in key.
 *                                (I.e., calling this routine again with the
 *                                same key allows repeating a sequence of
 *                                random numbers)
 *
 * Requires: key is a valid des key.  I.e., has correct parity and is not a
 *           weak des key.
 */
void
des_set_random_generator_seed(key)
    mit_des_cblock key;
{
    krb5_data seed;

    seed.length = sizeof(mit_des_cblock);
    seed.data = (krb5_pointer) key;

    if (!des425_random_state)
	des_init_random_number_generator(key);
    mit_des_set_random_generator_seed(&seed, des425_random_state);
}


/*
 * des_set_sequence_number: this routine is used to set the sequence number
 *                          of the current random number stream.  This routine
 *                          may be used to "seek" within the current random
 *                          number stream.
 *
 * Note that des_set_random_generator_seed resets the sequence number to 0.
 */
void
des_set_sequence_number(new_sequence_number)
    mit_des_cblock new_sequence_number;
{
    krb5_data sequence;

    sequence.length = sizeof(new_sequence_number);
    sequence.data = (char FAR *)new_sequence_number;
    mit_des_set_random_sequence_number(&sequence, des425_random_state);
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1988,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#ifndef	lint
static char rcsid_new_rnd_key_c[] =
"$Id$";
#endif	/* lint */

#include "des.h"

extern void mit_des_fixup_key_parity();
extern int mit_des_is_weak_key();
extern int mit_des_init_random_number_generator();
extern void mit_des_set_random_generator_seed();
extern void mit_des_set_sequence_number();
extern void mit_des_generate_random_block();
extern int mit_des_new_random_key();
extern void mit_des_generate_random_block();


void des_set_random_generator_seed(), des_set_sequence_number();
void des_generate_random_block();

/*
 * The secret des key schedule and sequence number for the current
 * stream of random numbers
 */
static mit_des_random_key_seed random_sequence_state;

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
    return(mit_des_new_random_key(key, &random_sequence_state));
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
void des_init_random_number_generator(key)
     mit_des_cblock key;
{
     mit_des_init_random_number_generator(key, &random_sequence_state);
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
     mit_des_set_random_generator_seed(key, &random_sequence_state);
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
     mit_des_set_sequence_number(new_sequence_number, &random_sequence_state);
}

/*
 * des_generate_random_block: routine to return the next random number
 *                            from the current random number stream.
 *                            The returned number is 64 bits long.
 *
 * Requires: des_set_random_generator_seed must have been called at least once
 *           before this routine is called.
 */
void des_generate_random_block(block)
     mit_des_cblock block;
{
    mit_des_generate_random_block(block, &random_sequence_state);
}


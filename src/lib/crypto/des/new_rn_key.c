/*
 * lib/crypto/des/new_rn_key.c
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
 * New pseudo-random key generator, using DES encryption to make the
 * pseudo-random cycle as hard to break as DES.
 *
 * Written by Mark Lillibridge, MIT Project Athena
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 */

#include "k5-int.h"
#include "des_int.h"

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

/*
 * mit_des_new_random_key: create a random des key
 *
 * Requires: mit_des_set_random_number_generater_seed must be at called least
 *           once before this routine is called.
 *
 * Notes: the returned key has correct parity and is guarenteed not
 *        to be a weak des key.  Mit_Des_generate_random_block is used to
 *        provide the random bits.
 */
int
mit_des_new_random_key(key, p_seed)
    mit_des_cblock key;
    mit_des_random_key_seed	*p_seed;
{
    do {
	mit_des_generate_random_block(key, p_seed);
	mit_des_fixup_key_parity(key);
    } while (mit_des_is_weak_key(key));

    return(0);
}

/*
 * mit_des_init_random_number_generator:
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
 * Note: this routine calls mit_des_set_random_generator_seed.
 */

void
mit_des_init_random_number_generator(key,p_seed)
    mit_des_cblock key;
    mit_des_random_key_seed	*p_seed;
{
    mit_des_cblock seed; /* This must be 64 bits exactly */
    struct tval {
	krb5_int32 seconds;
	krb5_int32 microseconds;
    } timenow;
    mit_des_cblock new_key;

    krb5_address **addrs = 0;

    /*
     * use a host id in generating the seed to ensure
     * that different servers have different streams:
     */
    memset((char *)seed, 0, sizeof(seed));
    if (!krb5_crypto_os_localaddr(&addrs) && addrs && *addrs) {
	memcpy((char *)seed, (char *)addrs[0]->contents,
	      min(sizeof(seed), addrs[0]->length));
	/* XXX may not do all of the seed. */
    }
    if (addrs) {
	/* can't use krb5_free_addresses due to circular dependencies in
	   libraries */
	register krb5_address **addr2;
	for (addr2 = addrs; *addr2; addr2++) {
	    krb5_xfree((*addr2)->contents);
	    krb5_xfree(*addr2);
	}
	krb5_xfree(addrs);
    }
    /*
     * Generate a temporary value that depends on the key and host_id
     * such that it gives no useful information about the key:
     */
    mit_des_set_random_generator_seed(key, p_seed);
    mit_des_set_sequence_number(seed, p_seed);
    mit_des_new_random_key(new_key, p_seed);

    /*
     * use it to select a random stream:
     */      
    mit_des_set_random_generator_seed(new_key, p_seed);

    /*
     * use a time stamp to ensure that a server started later does not reuse
     * an old stream:
     */
    /* XXX return value */
    (void) krb5_crypto_us_timeofday(&timenow.seconds,
				    &timenow.microseconds);
    mit_des_set_sequence_number((unsigned char *)&timenow, p_seed);

    /*
     * use the time stamp finally to select the final seed using the
     * current random number stream:
     */
    mit_des_new_random_key(new_key, p_seed);
    mit_des_set_random_generator_seed(new_key, p_seed);
}

/*
 * This module implements a random number generator faculty such that the next
 * number in any random number stream is very hard to predict without knowing
 * the seed for that stream even given the preceeding random numbers.
 */

/*
 * mit_des_set_random_generator_seed: this routine is used to select a random
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
mit_des_set_random_generator_seed(key, p_seed)
    mit_des_cblock key;
    mit_des_random_key_seed	*p_seed;
{
    register int i;

    /* select the new stream: (note errors are not possible here...) */
    mit_des_key_sched(key, p_seed->random_sequence_key);

    /* "seek" to the start of the stream: */
    for (i=0; i<8; i++)
      p_seed->sequence_number[i] = 0;
}

/*
 * mit_des_set_sequence_number: this routine is used to set the sequence number
 *                          of the current random number stream.  This routine
 *                          may be used to "seek" within the current random
 *                          number stream.
 *
 * Note that mit_des_set_random_generator_seed resets the sequence number to 0.
 */
void
mit_des_set_sequence_number(new_sequence_number, p_seed)
    mit_des_cblock new_sequence_number;
    mit_des_random_key_seed	*p_seed;
{
    memcpy((char *)p_seed->sequence_number, (char *)new_sequence_number,
	  sizeof(p_seed->sequence_number));
}

/*
 * mit_des_generate_random_block: routine to return the next random number
 *                            from the current random number stream.
 *                            The returned number is 64 bits long.
 *
 * Requires: mit_des_set_random_generator_seed must have been called at least once
 *           before this routine is called.
 */
void
mit_des_generate_random_block(block, p_seed)
    mit_des_cblock block;
    mit_des_random_key_seed	*p_seed;
{
    int i;

    /*
     * Encrypt the sequence number to get the new random block:
     */
    mit_des_ecb_encrypt((mit_des_cblock *)p_seed->sequence_number, 
		    (mit_des_cblock *)block, 
		    p_seed->random_sequence_key, 1);

    /*
     * Increment the sequence number as an 8 byte unsigned number with wrap:
     * (using LSB here)
     */
    for (i=0; i<8; i++) {
	p_seed->sequence_number[i] = (p_seed->sequence_number[i] + 1) & 0xff;
	if (p_seed->sequence_number[i])
	  break;
    }
}

/*
 * lib/crypto/des/init_rkey.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include "des_int.h"

/*
        initialize the random key generator using the encryption key,
        "seedblock", and allocating private sequence information, filling
        in "seed" with the address of such information.
        "seed" is later passed to the random_key() function to provide
        sequence information.
 */

#ifndef min
#define min(a,b) (((a) > (b)) ? (b) : (a))
#endif

krb5_error_code
mit_des_init_random_key (eblock, seedblock, state)
    const krb5_encrypt_block * eblock;
    const krb5_keyblock * seedblock;
    krb5_pointer * state;
{
    mit_des_random_state * p_state = 0;
    krb5_keyblock *new_key;
    krb5_enctype enctype = eblock->crypto_entry->proto_enctype;
    krb5_error_code kret = 0;
    krb5_address **addrs = 0;
    krb5_data seed;
    krb5_int32 now;
    krb5_int32 unow;
    unsigned char *cp;

    switch (enctype)
    {
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_MD5:
    case ENCTYPE_DES_CBC_RAW:
	enctype = ENCTYPE_DES_CBC_RAW;
	break;

    case ENCTYPE_DES3_CBC_SHA:
    case ENCTYPE_DES3_CBC_RAW:
	enctype = ENCTYPE_DES3_CBC_RAW;
	break;

    default:
	return KRB5_BAD_ENCTYPE;
    }

    p_state = (mit_des_random_state *) malloc(sizeof(mit_des_random_state));
    *state = (krb5_pointer) p_state;

    if (! p_state) {
	kret = ENOMEM;
	goto cleanup;
    }

    memset(p_state, 0, sizeof(*p_state));
    p_state->eblock.crypto_entry = krb5_enctype_array[enctype]->system;
    p_state->sequence.length = p_state->eblock.crypto_entry->keysize;
    p_state->sequence.data = (krb5_pointer) malloc(p_state->sequence.length);

    if (! p_state->sequence.data) {
	kret = ENOMEM;
	goto cleanup;
    }

    /*
     * Generate a temporary value that is based on the
     * input seed and the hostid (sequence number)
     * such that it gives no useful information about the input.
     *
     * Then use the temporary value as the new seed and the current
     * time as a sequence number to give us a stream that was not
     * previously used.
     *
     * This result will be the seed for the random number stream
     * (the sequence number will start at zero).
     */

    /* seed = input */
    seed.data = seedblock->contents;
    seed.length = seedblock->length;
    kret = mit_des_set_random_generator_seed(&seed, p_state);
    if (kret) goto cleanup;

    /* sequence = hostid */
    if (!krb5_crypto_os_localaddr(&addrs) && addrs && *addrs) {
	memcpy((char *)p_state->sequence.data, (char *)addrs[0]->contents,
	      min(p_state->sequence.length, addrs[0]->length));
	/* XXX may not do all of the sequence number. */
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

    /* tmp.seed = random(input,hostid) */
    kret = mit_des_random_key(NULL, p_state, &new_key);
    if (kret) goto cleanup;
    seed.data = new_key->contents;
    seed.length = new_key->length;
    kret = mit_des_set_random_generator_seed(&seed, p_state);
    (void) memset(new_key->contents, 0, new_key->length);
    krb5_xfree(new_key->contents);
    krb5_xfree(new_key);
    if (kret) goto cleanup;

    /* sequence = time */
    (void) krb5_crypto_us_timeofday(&now, &unow);
    cp = p_state->sequence.data;
    *cp++ = (now >> 24) & 0xff;
    *cp++ = (now >> 16) & 0xff;
    *cp++ = (now >> 8) & 0xff;
    *cp++ = now & 0xff;
    *cp++ = (unow >> 24) & 0xff;
    *cp++ = (unow >> 16) & 0xff;
    *cp++ = (unow >> 8) & 0xff;
    *cp++ = unow &0xff;

    /* seed = random(tmp.seed, time) */
    kret = mit_des_random_key(NULL, p_state, &new_key);
    if (kret) goto cleanup;
    seed.data = new_key->contents;
    seed.length = new_key->length;
    kret = mit_des_set_random_generator_seed(&seed, p_state);
    (void) memset(new_key->contents, 0, new_key->length);
    krb5_xfree(new_key->contents);
    krb5_xfree(new_key);
    if (kret) goto cleanup;
    
    return 0;

cleanup:
    if (kret)
	mit_des_finish_random_key(eblock, state);
    return kret;
}

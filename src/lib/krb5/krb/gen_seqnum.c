/*
 * lib/krb5/krb/gen_seqnum.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Routine to automatically generate a starting sequence number.
 * We do this by getting a random key and encrypting something with it,
 * then taking the output and slicing it up.
 */

#include "k5-int.h"

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

krb5_error_code
krb5_generate_seq_number(context, key, seqno)
    krb5_context context;
    const krb5_keyblock *key;
    krb5_int32 *seqno;
{
    krb5_pointer random_state;
    krb5_encrypt_block eblock;
    krb5_keyblock *subkey = 0;
    krb5_error_code retval;
    struct tval {
	krb5_int32 seconds;
	krb5_int32 microseconds;
    } timenow;
    krb5_octet *intmp = 0, *outtmp = 0;
    int esize;

    if (!valid_keytype(key->keytype))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    krb5_use_keytype(context, &eblock, key->keytype);

    if ((retval = krb5_init_random_key(context, &eblock, key, &random_state)))
	return(retval);
	
    if ((retval = krb5_random_key(context, &eblock, random_state, &subkey))) {
	(void) krb5_finish_random_key(context, &eblock, &random_state);
	return retval;
    }	
    /* ignore the error if any, since we've already gotten the key out */
    if ((retval = krb5_finish_random_key(context, &eblock, &random_state))) {
	krb5_free_keyblock(context, subkey);
	return retval;
    }

    esize = krb5_encrypt_size(sizeof(timenow), eblock.crypto_entry);
    intmp = (krb5_octet *)malloc(esize);
    if (!intmp) {
	    retval = ENOMEM;
	    goto cleanup;
    }
    outtmp = (krb5_octet *)malloc(esize);
    if (!outtmp) {
	    retval = ENOMEM;
	    goto cleanup;
    }
    if ((retval = krb5_process_key(context, &eblock, subkey))) {
	goto cleanup;
    }

    if ((retval = krb5_us_timeofday(context, &timenow.seconds,
				    &timenow.microseconds))) {
	goto cleanup;
    }
    memcpy((char *)intmp, (char *)&timenow, sizeof(timenow));

    retval = krb5_encrypt(context, (krb5_pointer)intmp, (krb5_pointer)outtmp,
			  sizeof(timenow), &eblock, 0);
    (void) krb5_finish_key(context, &eblock);
    if (retval)
	    goto cleanup;

    memcpy((char *) seqno, (char *)outtmp, sizeof(krb5_int32));
    
cleanup:
    if (subkey)
	    krb5_free_keyblock(context, subkey);
    if (intmp)
	    krb5_xfree(intmp);
    if (outtmp)
	    krb5_xfree(outtmp);
    return retval;
}


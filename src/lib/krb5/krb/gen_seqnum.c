/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Routine to automatically generate a starting sequence number.
 * We do this by getting a random key and encrypting something with it,
 * then taking the output and slicing it up.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_gen_seqnum_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

krb5_error_code
krb5_generate_seq_number(key, seqno)
const krb5_keyblock *key;
krb5_int32 *seqno;
{
    krb5_pointer random_state;
    krb5_encrypt_block eblock;
    krb5_keyblock *subkey;
    krb5_error_code retval;
    struct tval {
	krb5_int32 seconds;
	krb5_int32 microseconds;
    } timenow;
    krb5_octet *intmp, *outtmp;
    int esize;
    char *outseqno;

    if (!valid_keytype(key->keytype))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    krb5_use_keytype(&eblock, key->keytype);

    if (retval = krb5_init_random_key(&eblock, key, &random_state))
	return(retval);
	
    if (retval = krb5_random_key(&eblock, random_state, &subkey)) {
	(void) krb5_finish_random_key(&eblock, random_state);
	return retval;
    }	
    /* ignore the error if any, since we've already gotten the key out */
    if (retval = krb5_finish_random_key(&eblock, &random_state)) {
	krb5_free_keyblock(subkey);
	return retval;
    }

    esize = krb5_encrypt_size(sizeof(timenow), eblock.crypto_entry);
    intmp = (krb5_octet *)malloc(esize);
    if (!intmp) {
	krb5_free_keyblock(subkey);
	return ENOMEM;
    }
    outtmp = (krb5_octet *)malloc(esize);
    if (!outtmp) {
	xfree(intmp);
	krb5_free_keyblock(subkey);
	return ENOMEM;
    }
    if (retval = krb5_process_key(&eblock, subkey)) {
	goto cleanup;
    }
    outseqno = (char *)seqno;

    if (retval = krb5_us_timeofday(&timenow.seconds,
				   &timenow.microseconds)) {
	goto cleanup;
    }
    memcpy((char *)intmp, (char *)&timenow, sizeof(timenow));

    while (outseqno < (char *)(seqno+1)) {
	memset((char *)intmp, 0, esize);

	if (retval = krb5_encrypt((krb5_pointer)intmp,
				  (krb5_pointer)outtmp,
				  sizeof(timenow),
				  &eblock,
				  0)) {
	    (void) krb5_finish_key(&eblock);
	    goto cleanup;
	}
	memcpy(outseqno, (char *)outtmp, MIN((char *)(seqno+1)-outseqno,
					     esize));
	outseqno += MIN((char *)(seqno+1)-outseqno, esize);
	/* chain along */
	memcpy((char *)intmp,(char *)outtmp,esize);
    }
    (void) krb5_finish_key(&eblock);
 cleanup:
    krb5_free_keyblock(subkey);
    xfree(intmp);
    xfree(outtmp);
    return retval;
}


/*
 * lib/crypto/des/cksum.c
 *
 * Copyright 1985, 1986, 1987, 1988, 1990 by the Massachusetts Institute
 * of Technology.
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
 * These routines perform encryption and decryption using the DES
 * private key algorithm, or else a subset of it-- fewer inner loops.
 * (AUTH_DES_ITER defaults to 16, may be less.)
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 * 
 * These routines form the library interface to the DES facilities.
 *
 *	spm	8/85	MIT project athena
 */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "des_int.h"

extern int mit_des_debug;

/*
 * This routine performs DES cipher-block-chaining checksum operation,
 * a.k.a.  Message Authentication Code.  It ALWAYS encrypts from input
 * to a single 64 bit output MAC checksum.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext. The cleartext and ciphertext should be in host order.
 *
 * NOTE-- the output is ALWAYS 8 bytes long.  If not enough space was
 * provided, your program will get trashed.
 *
 * The input is null padded, at the end (highest addr), to an integral
 * multiple of eight bytes.
 */

void
mit_des_cbc_cksum(in,out,length,key,iv)
    krb5_octet  *in;		/* >= length bytes of inputtext */
    krb5_octet  *out;		/* >= length bytes of outputtext */
    register long length;	/* in bytes */
    mit_des_key_schedule key;		/* precomputed key schedule */
    krb5_octet  *iv;		/* 8 bytes of ivec */
{
    register unsigned long *input = (unsigned long *) in;
    register unsigned long *output = (unsigned long *) out;
    unsigned long *ivec = (unsigned long *) iv;

    unsigned long i,j;
    unsigned long t_input[2];
    unsigned long t_output[8];
    unsigned char *t_in_p;

    t_in_p = (unsigned char *) t_input;
#ifdef MUSTALIGN
    if ((long) ivec & 3) {
	memcpy((char *)&t_output[0],(char *)ivec++,sizeof(t_output[0]));
	memcpy((char *)&t_output[1],(char *)ivec,sizeof(t_output[1]));
    }
    else
#endif
    {
	t_output[0] = *ivec++;
	t_output[1] = *ivec;
    }

    for (i = 0; length > 0; i++, length -= 8) {
	/* get input */
#ifdef MUSTALIGN
	if ((long) input & 3) {
	    memcpy((char *)&t_input[0],(char *)input++,sizeof(t_input[0]));
	    memcpy((char *)&t_input[1],(char *)input++,sizeof(t_input[1]));
	}
	else
#endif
	{
	    t_input[0] = *input++;
	    t_input[1] = *input++;
	}

	/* zero pad */
	if (length < 8)
	    for (j = length; j <= 7; j++)
		*(t_in_p+j)= 0;

#ifdef DEBUG
	if (mit_des_debug)
	    mit_des_debug_print("clear",length,t_input[0],t_input[1]);
#endif
	/* do the xor for cbc into the temp */
	t_input[0] ^= t_output[0] ;
	t_input[1] ^= t_output[1] ;
	/* encrypt */
	(void) mit_des_ecb_encrypt(t_input,t_output,key,1);
#ifdef DEBUG
	if (mit_des_debug) {
	    mit_des_debug_print("xor'ed",i,t_input[0],t_input[1]);
	    mit_des_debug_print("cipher",i,t_output[0],t_output[1]);
	}
#else
#ifdef lint
	i = i;
#endif
#endif
    }
    /* copy temp output and save it for checksum */
#ifdef MUSTALIGN
    if ((long) output & 3) {
	memcpy((char *)output++,(char *)&t_output[0],sizeof(t_output[0]));
	memcpy((char *)output,(char *)&t_output[1],sizeof(t_output[1]));
    }
    else
#endif
    {
	*output++ = t_output[0];
	*output = t_output[1];
    }

    return;
}

/*
 * lib/des425/enc_dec.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 */

#include "des_int.h"
#include "des.h"

int
des_cbc_encrypt(in,out,length,key,iv,enc)
    des_cblock   *in;	/* >= length bytes of input text */
    des_cblock  *out;		/* >= length bytes of output text */
    register unsigned long length;	/* in bytes */
    const mit_des_key_schedule key;		/* precomputed key schedule */
    const des_cblock *iv;		/* 8 bytes of ivec */
    int enc;		/* 0 ==> decrypt, else encrypt */
{
	return (mit_des_cbc_encrypt((const des_cblock *) in,
				    out, length, key,
				    (const unsigned char *)iv, /* YUCK! */
				    enc));
}

/*
 * lib/des425/str_to_key.c
 *
 * Copyright 1985, 1986, 1987, 1988, 1989,1990 by the Massachusetts Institute
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
 * These routines perform encryption and decryption using the DES
 * private key algorithm, or else a subset of it-- fewer inner loops.
 * (AUTH_DES_ITER defaults to 16, may be less.)
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.  The cleartext and ciphertext should be in host order.
 *
 * These routines form the library interface to the DES facilities.
 *
 *	spm	8/85	MIT project athena
 */


#include <stdio.h>
#include <string.h>
#include "des_int.h"
#include "des.h"

extern int mit_des_debug;

/*
 * Convert an arbitrary length string to a DES key.
 */

/*
 * For krb5, a change was made to this algorithm: When each key is
 * generated, after fixing parity, a check for weak and semi-weak keys
 * is done.  If the key is weak or semi-weak, we XOR the last byte
 * with 0xF0.  (In the case of the intermediate key, the weakness is
 * probably irrelevant, but there it is.)  The odds that this will
 * generate a different key for a random input string are pretty low,
 * but non-zero.  So we need this different function for krb4 to use.
 */
int KRB5_CALLCONV
des_string_to_key(str,key)
    const char *str;
    register mit_des_cblock key;
{
    const char *in_str;
    register unsigned temp;
    register int j;
    unsigned long i, length;
    unsigned char *k_p;
    int forward;
    register char *p_char;
    char k_char[64];
    mit_des_key_schedule key_sked;

    in_str = str;
    forward = 1;
    p_char = k_char;
    length = strlen(str);

    /* init key array for bits */
    memset(k_char, 0,sizeof(k_char));

#ifdef DEBUG
    if (mit_des_debug)
	fprintf(stdout,
		"\n\ninput str length = %ld  string = %s\nstring = 0x ",
		length,str);
#endif

    /* get next 8 bytes, strip parity, xor */
    for (i = 1; i <= length; i++) {
	/* get next input key byte */
	temp = (unsigned int) *str++;
#ifdef DEBUG
	if (mit_des_debug)
	    fprintf(stdout,"%02x ",temp & 0xff);
#endif
	/* loop through bits within byte, ignore parity */
	for (j = 0; j <= 6; j++) {
	    if (forward)
		*p_char++ ^= (int) temp & 01;
	    else
		*--p_char ^= (int) temp & 01;
	    temp = temp >> 1;
	}

	/* check and flip direction */
	if ((i%8) == 0)
	    forward = !forward;
    }

    /* now stuff into the key des_cblock, and force odd parity */
    p_char = k_char;
    k_p = (unsigned char *) key;

    for (i = 0; i <= 7; i++) {
	temp = 0;
	for (j = 0; j <= 6; j++)
	    temp |= *p_char++ << (1+j);
	*k_p++ = (unsigned char) temp;
    }

    /* fix key parity */
    des_fixup_key_parity(key);

    /* Now one-way encrypt it with the folded key */
    (void) des_key_sched(key, key_sked);
    (void) des_cbc_cksum((const des_cblock *)in_str, (des_cblock *)key,
			 length, key_sked, (const des_cblock *)key);
    /* erase key_sked */
    memset(key_sked, 0,sizeof(key_sked));

    /* now fix up key parity again */
    des_fixup_key_parity(key);

#ifdef DEBUG
    if (mit_des_debug)
	fprintf(stdout,
		"\nResulting string_to_key = 0x%x 0x%x\n",
		*((unsigned long *) key),
		*((unsigned long *) key+1));
#endif /* DEBUG */
    return 0;			/* Really should be returning void, */
				/* but the original spec was for it to */
				/* return an int, and ANSI compilers */
				/* can do dumb things sometimes */
}

void afs_string_to_key(char *str, char *cell, des_cblock key)
{
    krb5_data str_data;
    krb5_data cell_data;
    krb5_keyblock keyblock;

    str_data.data = str;
    str_data.length = strlen(str);
    cell_data.data = cell;
    cell_data.length = strlen(cell);
    keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    keyblock.length = sizeof(des_cblock);
    keyblock.contents = key;

    mit_afs_string_to_key(&keyblock, &str_data, &cell_data);
}

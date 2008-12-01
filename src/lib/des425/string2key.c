/* THIS FILE DOES NOT GET COMPILED.  AUDIT BEFORE USE.  */
/*
 * lib/des425/string2key.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Wrapper for the V4 libdes for use with kerberos V5.
 */


#include "des.h"
#include "des_int.h"

#ifdef DEBUG
#include <stdio.h>
extern int des_debug;
#endif

/*
	converts the string pointed to by "data" into an encryption key
	of type "enctype".  *keyblock is filled in with the key info;
	in particular, keyblock->contents is to be set to allocated storage.
	It is the responsibility of the caller to release this storage
	when the generated key no longer needed.

	The routine may use "princ" to seed or alter the conversion
	algorithm.

	If the particular function called does not know how to make a
	key of type "enctype", an error may be returned.

	returns: errors
 */

krb5_error_code mit_des_string_to_key (enctype, keyblock, data, princ)
    const krb5_enctype enctype;
    krb5_keyblock * keyblock;
    const krb5_data * data;
    krb5_const_principal princ;
{
    char copystr[512];

    register char *str = copystr;
    register krb5_octet *key;

    register unsigned temp,i;
    register int j;
    register long length;
    unsigned char *k_p;
    int forward;
    register char *p_char;
    char k_char[64];
    mit_des_key_schedule key_sked;

#define min(A, B) ((A) < (B) ? (A): (B))

    if ( enctype != ENCTYPE_DES )
	return (KRB5_PROG_ENCTYPE_NOSUPP);

    if ( !(keyblock->contents = (krb5_octet *)malloc(sizeof(mit_des_cblock))) )
	return(ENOMEM);

#define cleanup() {memset(keyblock->contents, 0, sizeof(mit_des_cblock));\
		       krb5_xfree(keyblock->contents);}

    keyblock->enctype = ENCTYPE_DES;
    keyblock->length = sizeof(mit_des_cblock);
    key = keyblock->contents;

    memset(copystr, 0, sizeof(copystr));
    j = min(data->length, 511);
    (void) strncpy(copystr, data->data, j);
    if ( princ != 0 )
	for (i=0; princ[i] != 0 && j < 511; i++) {
	    (void) strncpy(copystr+j, princ[i]->data, 
			   min(princ[i]->length, 511-j));
	    j += min(princ[i]->length, 511-j);
	}

    /* convert copystr to des key */
    forward = 1;
    p_char = k_char;
    length = strlen(str);

    /* init key array for bits */
    memset(k_char,0,sizeof(k_char));

#ifdef DEBUG
    if (mit_des_debug)
	fprintf(stdout,
		"\n\ninput str length = %d  string = %s\nstring = 0x ",
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

    /* now stuff into the key mit_des_cblock, and force odd parity */
    p_char = k_char;
    k_p = (unsigned char *) key;

    for (i = 0; i <= 7; i++) {
	temp = 0;
	for (j = 0; j <= 6; j++)
	    temp |= *p_char++ << (1+j);
	*k_p++ = (unsigned char) temp;
    }

    /* fix key parity */
    mit_des_fixup_key_parity(key);

    /* Now one-way encrypt it with the folded key */
    (void) mit_des_key_sched(key, key_sked);
    (void) mit_des_cbc_cksum((krb5_octet *)copystr, key, length, key_sked, key);
    /* erase key_sked */
    memset((char *)key_sked, 0, sizeof(key_sked));

    /* now fix up key parity again */
    mit_des_fixup_key_parity(key);

#ifdef DEBUG
    if (mit_des_debug)
	fprintf(stdout,
		"\nResulting string_to_key = 0x%x 0x%x\n",
		*((unsigned long *) key),
		*((unsigned long *) key+1));
#endif
    
    return 0;
}





/*
 * lib/crypto/des/string2key.c
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
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "des_int.h"

/*
	converts the string pointed to by "data" into an encryption key
	of type "enctype".  *keyblock is filled in with the key info;
	in particular, keyblock->contents is to be set to allocated storage.
	It is the responsibility of the caller to release this storage
	when the generated key no longer needed.

	The routine may use "salt" to seed or alter the conversion
	algorithm.

	If the particular function called does not know how to make a
	key of type "enctype", an error may be returned.

	returns: errors
 */

/*#define PRINT_TEST_VECTORS*/

krb5_error_code
mit_des_string_to_key_int (keyblock, data, salt)
    krb5_keyblock * keyblock;
    const krb5_data * data;
    const krb5_data * salt;
{
    register krb5_octet *str, *copystr;
    register krb5_octet *key;

    register unsigned temp;
    register long i;        
    register int j;
    register unsigned long length;
    unsigned char *k_p;
    int forward;
    register char *p_char;
    char k_char[64];
    mit_des_key_schedule key_sked;

#ifdef PRINT_TEST_VECTORS
    unsigned char tmp_array[56];
    unsigned char *t_char;
#endif

#ifndef min
#define min(A, B) ((A) < (B) ? (A): (B))
#endif

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->length = sizeof(mit_des_cblock);
    key = keyblock->contents;

    if (salt) {
	if (salt->length == SALT_TYPE_AFS_LENGTH || salt->length == (unsigned) -1) {
	    krb5_data salt2;
	    char *c;
	    c = strchr(salt->data, '@');
	    if (c != NULL) *c = '\0'; /* workaround from krb5-clients/1146 */
	    salt2.data = salt->data;
	    salt2.length = strlen (salt2.data);
	    /* cheat and do AFS string2key instead */
	    return mit_afs_string_to_key (keyblock, data, &salt2);
	} else 
	    length = data->length + salt->length;
    } else
	length = data->length;

    copystr = malloc((size_t) length);
    if (!copystr) {
	free(keyblock->contents);
	keyblock->contents = 0;
	return ENOMEM;
    }

    memcpy(copystr, (char *) data->data, data->length);
    if (salt)
	memcpy(copystr + data->length, (char *)salt->data, salt->length);

    /* convert to des key */
    forward = 1;

    /* init key array for bits */
    p_char = k_char;
    memset(k_char,0,sizeof(k_char));
#ifdef PRINT_TEST_VECTORS
    t_char = tmp_array;
#endif

#if 0
    if (mit_des_debug)
	fprintf(stdout,
		"\n\ninput str length = %d  string = %*s\nstring = 0x ",
		length,length,str);
#endif

    str = copystr;

    /* get next 8 bytes, strip parity, xor */
    for (i = 1; i <= length; i++) {
	/* get next input key byte */
	temp = (unsigned int) *str++;
#if 0
	if (mit_des_debug)
	    fprintf(stdout,"%02x ",temp & 0xff);
#endif
	/* loop through bits within byte, ignore parity */
	for (j = 0; j <= 6; j++) {
	    unsigned int x = temp & 1;
	    if (forward) {
		*p_char++ ^= x;
#ifdef PRINT_TEST_VECTORS
		*t_char++ = x;
#endif
	    } else {
		*--p_char ^= x;
#ifdef PRINT_TEST_VECTORS
		*--t_char = x;
#endif
	    }
	    temp = temp >> 1;
	}

	/* check and flip direction */
	if ((i%8) == 0) {
#ifdef PRINT_TEST_VECTORS
	    printf("%-20s ",
		   forward ? "forward block:" : "reversed block:");
	    for (j = 0; j <= 7; j++) {
		int k, num = 0;
		for (k = 0; k <= 6; k++)
		    num |= tmp_array[j * 7 + k] << k;
		printf(" %02x", num);
	    }
	    printf("\n");

	    printf("%-20s ", "xor result:");
	    for (j = 0; j <= 7; j++) {
		int k, num = 0;
		for (k = 0; k <= 6; k++)
		    num |= k_char[j * 7 + k] << k;
		printf(" %02x", num);
	    }
	    printf("\n");
#endif
	    forward = !forward;
	}
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

#ifdef PRINT_TEST_VECTORS
    printf("%-20s ", "after fanfolding:");
    for (i = 0; i <= 7; i++)
	printf(" %02x", i[(unsigned char *)key]);
    printf("\n");

    printf("%-20s ", "after shifting:");
    for (i = 0; i <= 7; i++)
	printf(" %02x", i[(unsigned char *)key]);
    printf("\n");
#endif

    /* fix key parity */
    mit_des_fixup_key_parity(key);
    if (mit_des_is_weak_key(key))
	((krb5_octet *)key)[7] ^= 0xf0;

#ifdef PRINT_TEST_VECTORS
    printf("after fixing parity and weak keys: {");
    for (i = 0; i <= 7; i++)
	printf(" %02x", i[(unsigned char *)key]);
    printf(" }\n");
#endif

    /* Now one-way encrypt it with the folded key */
    (void) mit_des_key_sched(key, key_sked);
    (void) mit_des_cbc_cksum(copystr, key, length, key_sked, key);
    /* erase key_sked */
    memset((char *)key_sked, 0, sizeof(key_sked));

    /* clean & free the input string */
    memset(copystr, 0, length);
    krb5_xfree(copystr);

    /* now fix up key parity again */
    mit_des_fixup_key_parity(key);
    if (mit_des_is_weak_key(key))
	((krb5_octet *)key)[7] ^= 0xf0;

#if 0
    if (mit_des_debug)
	fprintf(stdout,
		"\nResulting string_to_key = 0x%x 0x%x\n",
		*((unsigned long *) key),
		*((unsigned long *) key+1));
#endif
    
    return 0;
}

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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "des_int.h"

/*
	converts the string pointed to by "data" into an encryption key
	of type "keytype".  *keyblock is filled in with the key info;
	in particular, keyblock->contents is to be set to allocated storage.
	It is the responsibility of the caller to release this storage
	when the generated key no longer needed.

	The routine may use "salt" to seed or alter the conversion
	algorithm.

	If the particular function called does not know how to make a
	key of type "keytype", an error may be returned.

	returns: errors
 */

krb5_error_code
mit_des_string_to_key (eblock, keytype, keyblock, data, salt)
const krb5_encrypt_block FAR * eblock;
const krb5_keytype keytype;
krb5_keyblock FAR * keyblock;
const krb5_data FAR * data;
const krb5_data FAR * salt;
{
    register char *str, *copystr;
    register krb5_octet *key;

    register unsigned temp;
    register long i;        
    register int j;
    register long length;
    unsigned char *k_p;
    int forward;
    register char *p_char;
    char k_char[64];
    mit_des_key_schedule key_sked;

#ifndef min
#define min(A, B) ((A) < (B) ? (A): (B))
#endif

    if ((keytype != KEYTYPE_DES_CBC_CRC) && (keytype != KEYTYPE_DES_CBC_MD4) &&
       (keytype != KEYTYPE_DES_CBC_MD5) && (keytype != KEYTYPE_DES_CBC_RAW)) 
	return (KRB5_PROG_KEYTYPE_NOSUPP);

    if ( !(keyblock->contents = (krb5_octet *)malloc(sizeof(mit_des_cblock))) )
	return(ENOMEM);

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->length = sizeof(mit_des_cblock);
    keyblock->keytype = eblock->crypto_entry->proto_keytype;
    key = keyblock->contents;

    if (salt)
	length = data->length + salt->length;
    else
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
    p_char = k_char;

    /* init key array for bits */
    memset(k_char,0,sizeof(k_char));

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
    (void) mit_des_cbc_cksum(copystr, key, length, key_sked, key);
    /* erase key_sked */
    memset((char *)key_sked, 0, sizeof(key_sked));

    /* clean & free the input string */
    memset(copystr, 0, (size_t) length);
    krb5_xfree(copystr);

    /* now fix up key parity again */
    mit_des_fixup_key_parity(key);

#if 0
    if (mit_des_debug)
	fprintf(stdout,
		"\nResulting string_to_key = 0x%x 0x%x\n",
		*((unsigned long *) key),
		*((unsigned long *) key+1));
#endif
    
    return 0;
}

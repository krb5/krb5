/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Wrapper for the V4 libdes for use with kerberos V5.
 */

#if !defined(lint) && !defined(SABER)
static char des_st2_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "des_int.h"

#ifdef DEBUG
#include <stdio.h>
extern int des_debug;
#endif

/*
	converts the string pointed to by "data" into an encryption key
	of type "keytype".  *keyblock is filled in with the key info;
	in particular, keyblock->contents is to be set to allocated storage.
	It is the responsibility of the caller to release this storage
	when the generated key no longer needed.

	The routine may use "princ" to seed or alter the conversion
	algorithm.

	If the particular function called does not know how to make a
	key of type "keytype", an error may be returned.

	returns: errors
 */

krb5_error_code mit_des_string_to_key (DECLARG(krb5_keytype, keytype),
				       DECLARG(krb5_keyblock *,keyblock),
				       DECLARG(krb5_data *,data),
				       DECLARG(krb5_principal, princ))
OLDDECLARG(krb5_keytype, keytype)
OLDDECLARG(krb5_keyblock *,keyblock)
OLDDECLARG(krb5_data *,data)
OLDDECLARG(krb5_principal, princ)
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

    if ( keytype != KEYTYPE_DES )
	return (KRB5_PROG_KEYTYPE_NOSUPP);

    if ( !(keyblock->contents = (krb5_octet *)malloc(sizeof(mit_des_cblock))) )
	return(ENOMEM);

#define cleanup() {bzero(keyblock->contents, sizeof(mit_des_cblock));\
		       (void) free((char *) keyblock->contents);}

    keyblock->keytype = KEYTYPE_DES;
    keyblock->length = sizeof(mit_des_cblock);
    key = keyblock->contents;

    bzero(copystr, sizeof(copystr));
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
    bzero(k_char,sizeof(k_char));

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
    bzero((char *)key_sked, sizeof(key_sked));

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

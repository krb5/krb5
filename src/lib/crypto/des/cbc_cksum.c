/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1986, 1987, 1988, 1990 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * These routines form the library interface to the DES facilities.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_cbc_cksum_c[] =
"$Id$";
#endif	/* !lint & !SABER */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "des_int.h"

/*
	produces cbc cheksum of sequence "in" of the length "in_length" 
	with the help of key "key" of size "key_size" (which should be 8);
	fills out krb5_checksum structure.

	caller is responsible for freeing "contents" element in 
	krb5_checksum structure.

	returns: errors
*/
krb5_error_code mit_des_cbc_checksum(DECLARG(krb5_pointer, in),
				     DECLARG(size_t, in_length),
				     DECLARG(krb5_pointer, key),
				     DECLARG(size_t, key_size),
				     DECLARG(krb5_checksum *, cksum))
OLDDECLARG(krb5_pointer, in)
OLDDECLARG(size_t, in_length)
OLDDECLARG(krb5_pointer, key)
OLDDECLARG(size_t, key_size)
OLDDECLARG(krb5_checksum *, cksum)
{
    struct mit_des_ks_struct       *schedule;      /* pointer to key schedules */
    krb5_octet 	*contents;

    if (key_size != sizeof(mit_des_cblock))
	return KRB5_BAD_KEYSIZE;

    if (!(schedule = (struct mit_des_ks_struct *) malloc(sizeof(mit_des_key_schedule))))
        return ENOMEM;

#define cleanup() { memset((char *)schedule, 0, sizeof(mit_des_key_schedule));\
		    free( (char *) schedule); }

    switch (mit_des_key_sched ((krb5_octet *)key, schedule)) {
    case -1:
        cleanup();
        return KRB5DES_BAD_KEYPAR;

    case -2:
        cleanup();
        return KRB5DES_WEAK_KEY;

    default:
        ;
    }

    if (!(contents = (krb5_octet *) malloc(sizeof(mit_des_cblock)))) {
	cleanup();
        return ENOMEM;
    }

    mit_des_cbc_cksum((krb5_octet *)in, contents, in_length,
		  schedule, (krb5_octet *)key);

    cksum->checksum_type = CKSUMTYPE_DESCBC;
    cksum->length = sizeof(mit_des_cblock);
    cksum->contents = contents;
    cleanup();

    return 0;
}
    

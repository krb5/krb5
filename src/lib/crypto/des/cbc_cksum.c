/*
 * lib/crypto/des/cbc_cksum.c
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
 */

#include "k5-int.h"
#include "des_int.h"

/*
	produces cbc cheksum of sequence "in" of the length "in_length" 
	with the help of key "key" of size "key_size" (which should be 8);
	fills out krb5_checksum structure.

	caller is responsible for allocating & freeing "contents" element in 
	krb5_checksum structure.

	returns: errors
*/

static krb5_error_code mit_des_cbc_checksum
    PROTOTYPE((krb5_const krb5_pointer,
	       krb5_const size_t,
	       krb5_const krb5_pointer,
	       krb5_const size_t,
	       krb5_checksum FAR * ));

static krb5_error_code mit_des_cbc_verf_cksum
    PROTOTYPE ((krb5_const krb5_checksum FAR *,
		krb5_const krb5_pointer,
		krb5_const size_t,
		krb5_const krb5_pointer,
                krb5_const size_t ));

static krb5_error_code
mit_des_cbc_checksum(in, in_length, key, key_size, cksum)
    krb5_const krb5_pointer in;
    krb5_const size_t in_length;
    krb5_const krb5_pointer key;
    krb5_const size_t key_size;
    krb5_checksum FAR * cksum;
{
    struct mit_des_ks_struct       *schedule;      /* pointer to key schedules */

    if (cksum->length < sizeof(mit_des_cblock))
	return KRB5_BAD_MSIZE;
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

    cksum->checksum_type = CKSUMTYPE_DESCBC;
    cksum->length = sizeof(mit_des_cblock);
    mit_des_cbc_cksum(in, cksum->contents, in_length, schedule, key);

    cleanup();

    return 0;
}
    
static krb5_error_code
mit_des_cbc_verf_cksum(cksum, in, in_length, key, key_size)
    krb5_const krb5_checksum FAR * cksum;
    krb5_const krb5_pointer in;
    krb5_const size_t in_length;
    krb5_const krb5_pointer key;
    krb5_const size_t key_size;
{
    struct mit_des_ks_struct       *schedule;      /* pointer to key schedules */
    mit_des_cblock	contents;
    krb5_error_code	retval;

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

    mit_des_cbc_cksum(in, contents, in_length, schedule, key);

    retval = 0;
    if (cksum->checksum_type == CKSUMTYPE_DESCBC) {
	if (cksum->length == sizeof(mit_des_cblock)) {
	    if (memcmp((char *) cksum->contents,
		       (char *) contents,
		       sizeof(mit_des_cblock)))
		retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	}
	else
	    retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    else
	retval = KRB5KRB_AP_ERR_INAPP_CKSUM;
    cleanup();

    return retval;
}

krb5_checksum_entry krb5_des_cbc_cksumtable_entry = {
    0,
    mit_des_cbc_checksum,
    mit_des_cbc_verf_cksum,
    sizeof(mit_des_cblock),
    1,					/* is collision proof */
    1,					/* is keyed */
};

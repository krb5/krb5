/*
 * lib/crypto/md4/md4glue.c
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
 * 
 * Kerberos glue for MD4 sample implementation.
 */

#include "k5-int.h"
#include "rsa-md4.h"

/* Windows needs to these prototypes for the assignment below */

krb5_error_code
krb5_md4_sum_func PROTOTYPE((krb5_pointer in, size_t in_length,
    krb5_pointer seed, size_t seed_length, krb5_checksum *outcksum));

krb5_error_code
krb5_md4_verify_func PROTOTYPE((krb5_checksum FAR *cksum, krb5_pointer in,
	size_t in_length, krb5_pointer seed, size_t seed_length));

krb5_error_code
krb5_md4_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum FAR *outcksum;
{
    krb5_octet *input = (krb5_octet *)in;
    krb5_MD4_CTX working;

    if (outcksum->length < RSA_MD4_CKSUM_LENGTH)
	return KRB5_BAD_MSIZE;
    
    krb5_MD4Init(&working);
    krb5_MD4Update(&working, input, in_length);
    krb5_MD4Final(&working);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD4;
    outcksum->length = RSA_MD4_CKSUM_LENGTH;

    memcpy((char *)outcksum->contents, (char *)&working.digest[0],
	   RSA_MD4_CKSUM_LENGTH);

    memset((char *)&working, 0, sizeof(working));
    return 0;
}

krb5_error_code
krb5_md4_verify_func(cksum, in, in_length, seed, seed_length)
krb5_checksum FAR *cksum;
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
{
    krb5_octet *input = (krb5_octet *)in;
    krb5_MD4_CTX working;
    krb5_error_code retval;

    retval = 0;
    if (cksum->checksum_type == CKSUMTYPE_RSA_MD4) {
	if (cksum->length == RSA_MD4_CKSUM_LENGTH) {
	    krb5_MD4Init(&working);
	    krb5_MD4Update(&working, input, in_length);
	    krb5_MD4Final(&working);

	    if (memcmp((char *) cksum->contents,
		       (char *) &working.digest[0],
		       RSA_MD4_CKSUM_LENGTH))
		retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    memset((char *)&working, 0, sizeof(working));
	}
	else
	    retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    else
	retval = KRB5KRB_AP_ERR_INAPP_CKSUM;
    return retval;
}

krb5_checksum_entry rsa_md4_cksumtable_entry = {
    0,
    krb5_md4_sum_func,
    krb5_md4_verify_func,
    RSA_MD4_CKSUM_LENGTH,
    1,					/* is collision proof */
    0,					/* doesn't use key */
};

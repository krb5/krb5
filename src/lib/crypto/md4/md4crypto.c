/*
 * lib/crypto/md4/md4crypto.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Kerberos glue for MD4 sample implementation.
 */

#include "k5-int.h"
#include "rsa-md4.h"
#include "des_int.h"	/* we cheat a bit and call it directly... */

krb5_error_code
md4_crypto_sum_func KRB5_NPROTOTYPE((krb5_pointer in, size_t in_length,
    krb5_pointer seed, size_t seed_length, krb5_checksum *outcksum));

krb5_error_code
md4_crypto_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum FAR *outcksum;
{
    krb5_octet outtmp[RSA_MD4_DES_CKSUM_LENGTH];
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;

    MD4_CTX working;

    MD4Init(&working);
    MD4Update(&working, input, in_length);
    MD4Final(&working);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD4_DES;
    outcksum->length = RSA_MD4_DES_CKSUM_LENGTH;

    memcpy((char *)outtmp, (char *)&working.digest[0], 16);

    memset((char *)&working, 0, sizeof(working));

    keyblock.length = seed_length;
    keyblock.contents = (krb5_octet *)seed;
    keyblock.keytype = KEYTYPE_DES;

    if ((retval = mit_des_process_key(&eblock, &keyblock)))
	return retval;
    /* now encrypt it */
    retval = mit_des_cbc_encrypt((mit_des_cblock *)&outtmp[0],
				 (mit_des_cblock *)outcksum->contents,
				 RSA_MD4_DES_CKSUM_LENGTH,
				 (struct mit_des_ks_struct *)eblock.priv,
				 keyblock.contents,
				 MIT_DES_ENCRYPT);
    if (retval) {
	(void) mit_des_finish_key(&eblock);
	return retval;
    }
    return mit_des_finish_key(&eblock);
}


krb5_checksum_entry rsa_md4_des_cksumtable_entry = {
    0,
    md4_crypto_sum_func,
    RSA_MD4_DES_CKSUM_LENGTH,
    1,					/* is collision proof */
    1,					/* uses key */
};

/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Kerberos glue for MD4 sample implementation.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_md4crypto_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/rsa-md4.h>

#include "../des/des_int.h"	/* we cheat a bit and call it directly... */

static krb5_error_code
md4_crypto_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum *outcksum;
{
    krb5_octet outtmp[RSA_MD4_DES_CKSUM_LENGTH];
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;

    MD4_CTX working;

    MD4Init(&working);
    MD4Update(&working, input, in_length*8);
    MD4Final(&working);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD4_DES;
    outcksum->length = RSA_MD4_DES_CKSUM_LENGTH;

    memcpy((char *)outtmp, (char *)&working.digest[0], 16);

    memset((char *)&working, 0, sizeof(working));

    keyblock.length = seed_length;
    keyblock.contents = (krb5_octet *)seed;
    keyblock.keytype = KEYTYPE_DES;

    if (retval = mit_des_process_key(&eblock, &keyblock))
	return retval;
    /* now encrypt it */
    retval = mit_des_cbc_encrypt(&outtmp[0],
				 outcksum->contents,
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
    md4_crypto_sum_func,
    RSA_MD4_DES_CKSUM_LENGTH,
    1,					/* is collision proof */
    1,					/* uses key */
};

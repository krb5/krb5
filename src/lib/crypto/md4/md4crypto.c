/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
    krb5_octet *output, outtmp[RSA_MD4_DES_CKSUM_LENGTH];
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;

    register int i, j;
    MDstruct working;

    MDbegin(&working);

    for (i = in_length; i >= 64; i -= 64, input += 64)
	/* MD4 works in 512 bit chunks (64 bytes) */
	MDupdate(&working, input, 512);
    /* now close out remaining stuff.  Even if i == 0, we want to
       "close out" the MD4 algorithm */
    MDupdate(&working, input, i*8);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD4_DES;
    outcksum->length = RSA_MD4_DES_CKSUM_LENGTH;

    /* the output code here is adapted from MDprint;
       it needs to assemble it into proper byte order. */

    output = &outtmp[0];
    for (i = 0; i < 4; i++)
	for (j = 0; j < 32; j += 8)
	    *output++ = (working.buffer[i] >> j) & 0xFF;

    keyblock.length = seed_length;
    keyblock.contents = (krb5_octet *)seed;
    keyblock.keytype = KEYTYPE_DES;

    if (retval = mit_des_process_key(&eblock, &keyblock))
	return retval;
    /* now encrypt it */
    retval = mit_des_cbc_encrypt(output,
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
    RSA_MD4_CKSUM_LENGTH, /* CRC-32 is 4 octets */
    1,					/* is collision proof */
    1,					/* uses key */
};

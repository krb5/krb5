/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Kerberos glue for MD4 sample implementation.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_md4glue_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/rsa-md4.h>

static krb5_error_code
md4_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum *outcksum;
{
    krb5_octet *output;
    krb5_octet *input = (krb5_octet *)in;
    register int i, j;
    MDstruct working;

    MDbegin(&working);

    for (i = in_length; i >= 64; i -= 64, input += 64)
	/* MD4 works in 512 bit chunks (64 bytes) */
	MDupdate(&working, input, 512);
    /* now close out remaining stuff.  Even if i == 0, we want to
       "close out" the MD4 algorithm */
    MDupdate(&working, input, i*8);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD4;
    outcksum->length = RSA_MD4_CKSUM_LENGTH;

    /* the output code here is adapted from MDprint */

    output = outcksum->contents;
    for (i = 0; i < 4; i++)
	for (j = 0; j < 32; j += 8)
	    *output++ = (working.buffer[i] >> j) & 0xFF;

    return 0;
}


krb5_checksum_entry crc32_cksumtable_entry = {
    md4_sum_func,
    RSA_MD4_CKSUM_LENGTH, /* CRC-32 is 4 octets */
};

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

/*
 * In Kerberos V5 Beta 5 and previous releases the RSA-MD4-DES implementation
 * did not follow RFC1510.  The folowing definitions control the compatibility
 * with these releases.
 *
 * If MD4_K5BETA_COMPAT is defined, then compatability mode is enabled.  That
 * means that both checksum functions are compiled and available for use and
 * the additional interface md4_crypto_compat_ctl() is defined.
 *
 * If MD4_K5BETA_COMPAT_DEF is defined and compatability mode is enabled, then
 * the compatible behaviour becomes the default.
 *
 */

static void
md4_calculate_cksum(md4ctx, in, in_length, confound, confound_length)
    MD4_CTX		*md4ctx;
    krb5_pointer	in;
    size_t		in_length;
    krb5_pointer	confound;
    size_t		confound_length;
{
    MD4Init(md4ctx);
    if (confound && confound_length)
	MD4Update(md4ctx, confound, confound_length);
    MD4Update(md4ctx, in, in_length);
    MD4Final(md4ctx);
}

#ifdef	MD4_K5BETA_COMPAT
/*
 * Generate the RSA-MD4-DES checksum in a manner which is compatible with
 * K5 Beta implementations.  Sigh...
 */
krb5_error_code
md4_crypto_compat_sum_func(in, in_length, seed, seed_length, outcksum)
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
    keyblock.enctype = ENCTYPE_DES_CBC_MD4;

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
#endif	/* MD4_K5BETA_COMPAT */

/*
 * Generate the RSA-MD4-DES checksum correctly.
 */
krb5_error_code
md4_crypto_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum FAR *outcksum;
{
    krb5_octet outtmp[RSA_MD4_DES_CKSUM_LENGTH+
		      RSA_MD4_DES_CONFOUND_LENGTH];
    mit_des_cblock	tmpkey;
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;
    int i;

    MD4_CTX working;

    /* Generate the confounder in place */
    if (retval = krb5_random_confounder(RSA_MD4_DES_CONFOUND_LENGTH,
					outtmp))
	return(retval);

    /* Calculate the checksum */
    md4_calculate_cksum(&working,
			(krb5_pointer) outtmp,
			(size_t) RSA_MD4_DES_CONFOUND_LENGTH,
			in,
			in_length);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD4_DES;
    outcksum->length = RSA_MD4_DES_CKSUM_LENGTH + RSA_MD4_DES_CONFOUND_LENGTH;

    /* Now blast in the digest */
    memcpy((char *) &outtmp[RSA_MD4_DES_CONFOUND_LENGTH],
	   (char *) &working.digest[0],
	   RSA_MD4_DES_CKSUM_LENGTH);

    /* Clean up droppings */
    memset((char *)&working, 0, sizeof(working));

    /* Set up the temporary copy of the key (see RFC 1510 section 6.4.3) */
    memset((char *) tmpkey, 0, sizeof(mit_des_cblock));
    for (i=0; (i<seed_length) && (i<sizeof(mit_des_cblock)); i++)
	tmpkey[i] = (((krb5_octet *) seed)[i]) ^ 0xf0;

    keyblock.length = sizeof(mit_des_cblock);
    keyblock.contents = (krb5_octet *) tmpkey;
    keyblock.enctype = ENCTYPE_DES_CBC_MD4;

    if ((retval = mit_des_process_key(&eblock, &keyblock)))
	return retval;
    /* now encrypt it */
    retval = mit_des_cbc_encrypt((mit_des_cblock *)&outtmp[0],
				 (mit_des_cblock *)outcksum->contents,
				 RSA_MD4_DES_CKSUM_LENGTH +
				 RSA_MD4_DES_CONFOUND_LENGTH,
				 (struct mit_des_ks_struct *)eblock.priv,
				 keyblock.contents,
				 MIT_DES_ENCRYPT);
    if (retval) {
	(void) mit_des_finish_key(&eblock);
	return retval;
    }
    return mit_des_finish_key(&eblock);
}

krb5_error_code
md4_crypto_verify_func(cksum, in, in_length, seed, seed_length)
krb5_checksum FAR *cksum;
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
{
    krb5_octet outtmp[RSA_MD4_DES_CKSUM_LENGTH+
		      RSA_MD4_DES_CONFOUND_LENGTH];
    krb5_octet outtmp1[RSA_MD4_DES_CKSUM_LENGTH+
		      RSA_MD4_DES_CONFOUND_LENGTH];
    mit_des_cblock	tmpkey;
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;
    int i;

    MD4_CTX working;

    retval = 0;
    if (cksum->checksum_type == CKSUMTYPE_RSA_MD4_DES) {
#ifdef	MD4_K5BETA_COMPAT
	/*
	 * We have a backwards compatibility problem here.  Kerberos version 5
	 * Beta 5 and previous releases did not correctly generate RSA-MD4-DES
	 * checksums.  The way that we can differentiate is by the length of
	 * the provided checksum.  If it's only RSA_MD4_DES_CKSUM_LENGTH, then
	 * it's the old style, otherwise it's the correct implementation.
	 */
	if (cksum->length == RSA_MD4_DES_CKSUM_LENGTH) {
	    /*
	     * If we're verifying the Old Style (tm) checksum, then we can just
	     * recalculate the checksum and encrypt it and see if it's the
	     * same.
	     */

	    /* Recalculate the checksum with no confounder */
	    md4_calculate_cksum(&working,
				(krb5_pointer) NULL,
				(size_t) 0,
				in,
				in_length);

	    /* Use the key "as-is" */
	    keyblock.length = seed_length;
	    keyblock.contents = (krb5_octet *) seed;
	    keyblock.enctype = ENCTYPE_DES_CBC_MD4;

	    if ((retval = mit_des_process_key(&eblock, &keyblock)))
		return retval;
	    /* now encrypt the checksum */
	    retval = mit_des_cbc_encrypt((mit_des_cblock *)&working.digest[0],
					 (mit_des_cblock *)&outtmp[0],
					 RSA_MD4_DES_CKSUM_LENGTH,
					 (struct mit_des_ks_struct *)
					 	eblock.priv,
					 keyblock.contents,
					 MIT_DES_ENCRYPT);
	    if (retval) {
		(void) mit_des_finish_key(&eblock);
		return retval;
	    }
	    if (retval = mit_des_finish_key(&eblock))
		return(retval);

	    /* Compare the encrypted checksums */
	    if (memcmp((char *) &outtmp[0],
		       (char *) cksum->contents,
		       RSA_MD4_DES_CKSUM_LENGTH))
		retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	}
	else
#endif	/* MD4_K5BETA_COMPAT */
	if (cksum->length == (RSA_MD4_DES_CKSUM_LENGTH +
			      RSA_MD4_DES_CONFOUND_LENGTH)) {
	    /*
	     * If we're verifying the correct implementation, then we have
	     * to do a little more work because we must decrypt the checksum
	     * because it contains the confounder in it.  So, figure out
	     * what our key variant is and then do it!
	     */

	    /* Set up the variant of the key (see RFC 1510 section 6.4.3) */
	    memset((char *) tmpkey, 0, sizeof(mit_des_cblock));
	    for (i=0; (i<seed_length) && (i<sizeof(mit_des_cblock)); i++)
		tmpkey[i] = (((krb5_octet *) seed)[i]) ^ 0xf0;

	    keyblock.length = sizeof(mit_des_cblock);
	    keyblock.contents = (krb5_octet *) tmpkey;
	    keyblock.enctype = ENCTYPE_DES_CBC_MD4;

	    if ((retval = mit_des_process_key(&eblock, &keyblock)))
		return retval;
	    /* now decrypt it */
	    retval = mit_des_cbc_encrypt((mit_des_cblock *)cksum->contents,
					 (mit_des_cblock *)&outtmp[0],
					 RSA_MD4_DES_CKSUM_LENGTH +
					 RSA_MD4_DES_CONFOUND_LENGTH,
					 (struct mit_des_ks_struct *)
					 	eblock.priv,
					 keyblock.contents,
					 MIT_DES_DECRYPT);
	    if (retval) {
		(void) mit_des_finish_key(&eblock);
		return retval;
	    }
	    if (retval = mit_des_finish_key(&eblock))
		return(retval);

	    /* Now that we have the decrypted checksum, try to regenerate it */
	    md4_calculate_cksum(&working,
				(krb5_pointer) outtmp,
				(size_t) RSA_MD4_DES_CONFOUND_LENGTH,
				in,
				in_length);

	    /* Compare the checksums */
	    if (memcmp((char *) &outtmp[RSA_MD4_DES_CONFOUND_LENGTH],
		       (char *) &working.digest[0],
		       RSA_MD4_DES_CKSUM_LENGTH))
		retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	}
	else 
	    retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    else
	retval = KRB5KRB_AP_ERR_INAPP_CKSUM;

    /* Clean up droppings */
    memset((char *)&working, 0, sizeof(working));
    return(retval);
}

krb5_checksum_entry rsa_md4_des_cksumtable_entry = 
#if	defined(MD4_K5BETA_COMPAT) && defined(MD4_K5BETA_COMPAT_DEF)
{
    0,
    md4_crypto_compat_sum_func,
    md4_crypto_verify_func,
    RSA_MD4_DES_CKSUM_LENGTH,
    1,					/* is collision proof */
    1,					/* uses key */
};
#else	/* MD4_K5BETA_COMPAT && MD4_K5BETA_COMPAT_DEF */
{
    0,
    md4_crypto_sum_func,
    md4_crypto_verify_func,
    RSA_MD4_DES_CKSUM_LENGTH+RSA_MD4_DES_CONFOUND_LENGTH,
    1,					/* is collision proof */
    1,					/* uses key */
};
#endif	/* MD4_K5BETA_COMPAT && MD4_K5BETA_COMPAT_DEF */

#ifdef	MD4_K5BETA_COMPAT
/*
 * Turn on/off compatible checksum generation.
 */
void
md4_crypto_compat_ctl(scompat)
    krb5_boolean	scompat;
{
    if (scompat) {
	rsa_md4_des_cksumtable_entry.sum_func = md4_crypto_compat_sum_func;
	rsa_md4_des_cksumtable_entry.checksum_length =
	    RSA_MD4_DES_CKSUM_LENGTH;
    }
    else {
	rsa_md4_des_cksumtable_entry.sum_func = md4_crypto_sum_func;
	rsa_md4_des_cksumtable_entry.checksum_length =
	    RSA_MD4_DES_CKSUM_LENGTH + RSA_MD4_DES_CONFOUND_LENGTH;
    }
}
#endif	/* MD4_K5BETA_COMPAT */

#include "k5-int.h"
#include "shs.h"
#include "des_int.h"	/* we cheat a bit and call it directly... */

/* Windows needs to these prototypes for the assignment below */

krb5_error_code
krb5_sha_crypto_sum_func
	PROTOTYPE((krb5_pointer in,
		   size_t in_length,
		   krb5_pointer seed,
		   size_t seed_length,
		   krb5_checksum FAR *outcksum));

krb5_error_code
krb5_sha_crypto_verify_func
	PROTOTYPE((krb5_checksum FAR *cksum,
		   krb5_pointer in,
		   size_t in_length,
		   krb5_pointer seed,
		   size_t seed_length));

static void
krb5_sha_calculate_cksum(ctx, in, in_length, confound, confound_length)
    SHS_INFO		*ctx;
    krb5_pointer	in;
    size_t		in_length;
    krb5_pointer	confound;
    size_t		confound_length;
{
    shsInit(ctx);
    if (confound && confound_length)
	shsUpdate(ctx, confound, confound_length);
    shsUpdate(ctx, in, in_length);
    shsFinal(ctx);
}

static krb5_error_code
shs_crypto_sum_func(in, in_length, seed, seed_length, outcksum)
    krb5_pointer in;
    size_t in_length;
    krb5_pointer seed;
    size_t seed_length;
    krb5_checksum FAR *outcksum;
{
    krb5_octet outtmp[NIST_SHA_DES3_CKSUM_LENGTH+
		      NIST_SHA_DES3_CONFOUND_LENGTH];
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;
    mit_des3_cblock tmpkey;
    size_t i;

    SHS_INFO working;

    /* Generate the confounder in place */
    if (retval = krb5_random_confounder(NIST_SHA_DES3_CONFOUND_LENGTH,
					outtmp))
	return(retval);

    /* Calculate the checksum */
    krb5_sha_calculate_cksum(&working,
			     in,
			     in_length,
			     (krb5_pointer) outtmp,
			     (size_t) NIST_SHA_DES3_CONFOUND_LENGTH);

    outcksum->checksum_type = CKSUMTYPE_NIST_SHA_DES3;
    outcksum->length =
	NIST_SHA_DES3_CKSUM_LENGTH + NIST_SHA_DES3_CONFOUND_LENGTH;

    /* Now blast in the digest */
    memset((char *)&outtmp[NIST_SHA_DES3_CONFOUND_LENGTH], 0,
	   NIST_SHA_DES3_CKSUM_LENGTH);
    memcpy((char *)&outtmp[NIST_SHA_DES3_CONFOUND_LENGTH],
	   (char *)&working.digest[0], NIST_SHA_CKSUM_LENGTH);

    /* Clean up the droppings */
    memset((char *)&working, 0, sizeof(working));

    /* Set up the temporary copy of the key (see RFC 1510 section 6.4.5) */
    memset((char *) tmpkey, 0, sizeof(tmpkey));
    for (i=0; (i<seed_length) && (i<sizeof(tmpkey)); i++)
	((krb5_octet *)tmpkey)[i] = (((krb5_octet *) seed)[i]) ^ 0xf0;

    keyblock.length = sizeof(tmpkey);
    keyblock.contents = (krb5_octet *) tmpkey;
    keyblock.enctype = ENCTYPE_DES3_CBC_SHA;

    if ((retval = mit_des3_process_key(&eblock, &keyblock)))
	return retval;

    /* now that we have computed the key schedules, zero the key as the IV */
    memset((char *) tmpkey, 0, sizeof(tmpkey));

    /* now encrypt it */
    retval = mit_des3_cbc_encrypt((mit_des_cblock *)&outtmp[0],
				  (mit_des_cblock *)outcksum->contents,
				  NIST_SHA_DES3_CKSUM_LENGTH +
				  NIST_SHA_DES3_CONFOUND_LENGTH,
				  (struct mit_des_ks_struct *)eblock.priv,
				  ((struct mit_des_ks_struct *)eblock.priv)+1,
				  ((struct mit_des_ks_struct *)eblock.priv)+2,
				  keyblock.contents,
				  MIT_DES_ENCRYPT);

    if (retval)
	(void) mit_des_finish_key(&eblock);
    else
	retval = mit_des_finish_key(&eblock);

    return retval;
}

static krb5_error_code
shs_crypto_verify_func(cksum, in, in_length, seed, seed_length)
    krb5_checksum FAR *cksum;
    krb5_pointer in;
    size_t in_length;
    krb5_pointer seed;
    size_t seed_length;
{
    krb5_octet outtmp[NIST_SHA_DES3_CKSUM_LENGTH +
		      NIST_SHA_DES3_CONFOUND_LENGTH];
    krb5_octet *input = (krb5_octet *)in;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock;
    krb5_error_code retval;
    mit_des3_cblock tmpkey;
    size_t i;

    SHS_INFO working;

    retval = 0;
    if (cksum->checksum_type == CKSUMTYPE_NIST_SHA_DES3) {
	if (cksum->length == (NIST_SHA_DES3_CKSUM_LENGTH +
			      NIST_SHA_DES3_CONFOUND_LENGTH)) {
	    /*
	     * If we're verifying the correct implementation, then we have
	     * to do a little more work because we must decrypt the checksum
	     * because it contains the confounder in it.  So, figure out
	     * what our key variant is and then do it!
	     */

	    /* Set up the variant of the key (see RFC 1510 section 6.4.5) */
	    memset((char *) tmpkey, 0, sizeof(tmpkey));
	    for (i=0; (i<seed_length) && (i<sizeof(tmpkey)); i++)
		((krb5_octet *)tmpkey)[i] = (((krb5_octet *) seed)[i]) ^ 0xf0;

	    keyblock.length = sizeof(tmpkey);
	    keyblock.contents = (krb5_octet *) tmpkey;
	    keyblock.enctype = ENCTYPE_DES3_CBC_SHA;

	    if ((retval = mit_des3_process_key(&eblock, &keyblock)))
		return retval;

	    /* now zero the key for use as the IV */
	    memset((char *) tmpkey, 0, sizeof(tmpkey));

	    /* now decrypt it */
	    retval = mit_des3_cbc_encrypt((mit_des_cblock *)cksum->contents,
					  (mit_des_cblock *)&outtmp[0],
					  NIST_SHA_DES3_CKSUM_LENGTH +
					  NIST_SHA_DES3_CONFOUND_LENGTH,
					  (struct mit_des_ks_struct *)
					 	eblock.priv,
					  ((struct mit_des_ks_struct *)
					 	eblock.priv) + 1,
					  ((struct mit_des_ks_struct *)
					 	eblock.priv) + 2,
					  keyblock.contents,
					  MIT_DES_DECRYPT);
	    if (retval)
		(void) mit_des_finish_key(&eblock);
	    else
		retval = mit_des_finish_key(&eblock);
	    if (retval) return retval;

	    /* Now that we have the decrypted checksum, try to regenerate it */
	    krb5_sha_calculate_cksum(&working,
				     in,
				     in_length,
				     (krb5_pointer) outtmp,
				     (size_t) NIST_SHA_DES3_CONFOUND_LENGTH);

	    /* Compare the checksums */
	    if (memcmp((char *) &outtmp[NIST_SHA_DES3_CONFOUND_LENGTH],
		       (char *) &working.digest[0],
		       NIST_SHA_CKSUM_LENGTH))
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

krb5_checksum_entry nist_sha_des3_cksumtable_entry =
{
    0,
    shs_crypto_sum_func,
    shs_crypto_verify_func,
    NIST_SHA_DES3_CKSUM_LENGTH + NIST_SHA_DES3_CONFOUND_LENGTH,
    1,					/* is collision proof */
    1,					/* uses key */
};

#include "shs.h"

krb5_error_code
krb5_sha_sum_func
	PROTOTYPE((krb5_const krb5_pointer	in,
		   krb5_const size_t		in_length,
		   krb5_const krb5_pointer	seed,
		   krb5_const size_t		seed_length,
		   krb5_checksum		FAR *outcksum));

krb5_error_code
krb5_sha_verify_func
	PROTOTYPE((krb5_const krb5_checksum	FAR *cksum,
		   krb5_const krb5_pointer	in,
		   krb5_const size_t		in_length,
		   krb5_const krb5_pointer	seed,
		   krb5_const size_t		seed_length));

krb5_error_code
krb5_sha_sum_func(in, in_length, seed, seed_length, outcksum)
	krb5_const krb5_pointer	in;
	krb5_const size_t	in_length;
	krb5_const krb5_pointer	seed;
	krb5_const size_t	seed_length;
	krb5_checksum		FAR *outcksum;
{
    krb5_octet *input = (krb5_octet *)in;
    krb5_octet *cp;
    LONG *lp;
    SHS_INFO working;

    if (outcksum->length < SHS_DIGESTSIZE)
	return KRB5_BAD_MSIZE;
    
    shsInit(&working);
    shsUpdate(&working, input, in_length);
    shsFinal(&working);

    outcksum->checksum_type = CKSUMTYPE_NIST_SHA;
    outcksum->length = SHS_DIGESTSIZE;

    cp = outcksum->contents;
    lp = working.digest;
    while (lp < working.digest + 16) {
	*cp++ = (*lp >> 24) & 0xff;
	*cp++ = (*lp >> 16) & 0xff;
	*cp++ = (*lp >> 8) & 0xff;
	*cp++ = (*lp++) & 0xff;
    }
    memset((char *)&working, 0, sizeof(working));
    return 0;
}

krb5_error_code
krb5_sha_verify_func(cksum, in, in_length, seed, seed_length)
	krb5_const krb5_checksum	FAR *cksum;
	krb5_const krb5_pointer		in;
	krb5_const size_t		in_length;
	krb5_const krb5_pointer		seed;
	krb5_const size_t		seed_length;
{
    krb5_octet *input = (krb5_octet *)in;
    SHS_INFO working;
    krb5_error_code retval;
    int i;
    krb5_octet *cp;

    if (cksum->checksum_type != CKSUMTYPE_NIST_SHA)
	return KRB5KRB_AP_ERR_INAPP_CKSUM;
    if (cksum->length != SHS_DIGESTSIZE)
	return KRB5KRB_AP_ERR_BAD_INTEGRITY;

    shsInit(&working);
    shsUpdate(&working, input, in_length);
    shsFinal(&working);

    retval = 0;
    for (i = 0, cp = cksum->contents; i < 5; i++, cp += 4) {
	if (working.digest[i] !=
	    (LONG) cp[0] << 24 | (LONG) cp[1] << 16 |
	    (LONG) cp[2] << 8 | (LONG) cp[3]) {
	    retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    break;
	}
    }
    memset((char *) &working, 0, sizeof(working));
    return retval;
}

krb5_checksum_entry nist_sha_cksumtable_entry = {
    0,
    krb5_sha_sum_func,
    krb5_sha_verify_func,
    SHS_DIGESTSIZE,
    1,					/* is collision proof */
    0,					/* doesn't use key */
};

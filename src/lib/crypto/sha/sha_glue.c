#include "k5-int.h"
#include "shs.h"

krb5_error_code
krb5_sha_sum_func
	PROTOTYPE((krb5_pointer		in,
		   size_t		in_length,
		   krb5_pointer		seed,
		   size_t		seed_length,
		   krb5_checksum	*outcksum));

krb5_error_code
krb5_sha_verify_func
	PROTOTYPE((krb5_checksum	FAR *cksum,
		   krb5_pointer		in,
		   size_t		in_length,
		   krb5_pointer		seed,
		   size_t		seed_length));

krb5_error_code
krb5_sha_sum_func(in, in_length, seed, seed_length, outcksum)
	krb5_pointer	in;
	size_t		in_length;
	krb5_pointer	seed;
	size_t		seed_length;
	krb5_checksum	*outcksum;
{
    krb5_octet *input = (krb5_octet *)in;
    SHS_INFO working;

    shsInit(&working);
    shsUpdate(&working, input, in_length);
    shsFinal(&working);

    outcksum->checksum_type = CKSUMTYPE_NIST_SHA;
    outcksum->length = SHS_DIGESTSIZE;

    memcpy((char *)outcksum->contents,
	   (char *)&working.digest[0],
	   outcksum->length);
    memset((char *)&working, 0, sizeof(working));
    return 0;
}

krb5_error_code
krb5_sha_verify_func(cksum, in, in_length, seed, seed_length)
	krb5_checksum	FAR *cksum;
	krb5_pointer	in;
	size_t		in_length;
	krb5_pointer	seed;
	size_t		seed_length;
{
    krb5_octet *input = (krb5_octet *)in;
    SHS_INFO working;
    krb5_error_code retval;

    if (cksum->checksum_type != CKSUMTYPE_NIST_SHA)
	return KRB5KRB_AP_ERR_INAPP_CKSUM;
    if (cksum->length != SHS_DIGESTSIZE)
	return KRB5KRB_AP_ERR_BAD_INTEGRITY;

    shsInit(&working);
    shsUpdate(&working, input, in_length);
    shsFinal(&working);

    retval = 0;
    if (memcmp((char *) cksum->contents,
	       (char *) &working.digest[0],
	       cksum->length))
	retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
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

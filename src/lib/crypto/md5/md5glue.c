#include "k5-int.h"
#include "rsa-md5.h"

/* Windows needs to these prototypes for the assignment below */

krb5_error_code
krb5_md5_sum_func PROTOTYPE((
	krb5_const krb5_pointer in,
	krb5_const size_t in_length,
	krb5_const krb5_pointer seed,
	krb5_const size_t seed_length,
	krb5_checksum FAR *outcksum));

krb5_error_code
krb5_md5_verify_func PROTOTYPE((
	krb5_const krb5_checksum FAR *cksum,
	krb5_const krb5_pointer in,
	krb5_const size_t in_length,
	krb5_const krb5_pointer seed,
	krb5_const size_t seed_length));

krb5_error_code
krb5_md5_sum_func(in, in_length, seed, seed_length, outcksum)
    krb5_const krb5_pointer in;
    krb5_const size_t in_length;
    krb5_const krb5_pointer seed;
    krb5_const size_t seed_length;
    krb5_checksum FAR *outcksum;
{
    krb5_octet *input = (krb5_octet *)in;
    krb5_MD5_CTX working;

    if (outcksum->length < RSA_MD5_CKSUM_LENGTH)
	return KRB5_BAD_MSIZE;
    
    krb5_MD5Init(&working);
    krb5_MD5Update(&working, input, in_length);
    krb5_MD5Final(&working);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD5;
    outcksum->length = RSA_MD5_CKSUM_LENGTH;

    memcpy((char *)outcksum->contents, (char *)&working.digest[0], 16);

    memset((char *)&working, 0, sizeof(working));
    return 0;
}

krb5_error_code
krb5_md5_verify_func(cksum, in, in_length, seed, seed_length)
    krb5_const krb5_checksum FAR *cksum;
    krb5_const krb5_pointer in;
    krb5_const size_t in_length;
    krb5_const krb5_pointer seed;
    krb5_const size_t seed_length;
{
    krb5_octet *input = (krb5_octet *)in;
    krb5_MD5_CTX working;
    krb5_error_code retval;

    retval = 0;
    if (cksum->checksum_type == CKSUMTYPE_RSA_MD5) {
	if (cksum->length == RSA_MD5_CKSUM_LENGTH) {
	    krb5_MD5Init(&working);
	    krb5_MD5Update(&working, input, in_length);
	    krb5_MD5Final(&working);

	    if (memcmp((char *) cksum->contents,
		       (char *) &working.digest[0],
		       RSA_MD5_CKSUM_LENGTH))
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

krb5_checksum_entry rsa_md5_cksumtable_entry = {
    0,
    krb5_md5_sum_func,
    krb5_md5_verify_func,
    RSA_MD5_CKSUM_LENGTH,
    1,					/* is collision proof */
    0,					/* doesn't use key */
};

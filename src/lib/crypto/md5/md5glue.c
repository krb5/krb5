#include "k5-int.h"
#include "rsa-md5.h"

/* Windows needs to these prototypes for the assignment below */

krb5_error_code
md5_sum_func PROTOTYPE((krb5_pointer in, size_t in_length,
    krb5_pointer seed, size_t seed_length, krb5_checksum *outcksum));

krb5_error_code
md5_verify_func PROTOTYPE((krb5_checksum FAR *cksum, krb5_pointer in,
	size_t in_length, krb5_pointer seed, size_t seed_length));

krb5_error_code
md5_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum FAR *outcksum;
{
    krb5_octet *input = (krb5_octet *)in;
    MD5_CTX working;

    MD5Init(&working);
    MD5Update(&working, input, in_length);
    MD5Final(&working);

    outcksum->checksum_type = CKSUMTYPE_RSA_MD5;
    outcksum->length = RSA_MD5_CKSUM_LENGTH;

    memcpy((char *)outcksum->contents, (char *)&working.digest[0], 16);

    memset((char *)&working, 0, sizeof(working));
    return 0;
}

krb5_error_code
md5_verify_func(cksum, in, in_length, seed, seed_length)
krb5_checksum FAR *cksum;
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
{
    krb5_octet *input = (krb5_octet *)in;
    MD5_CTX working;
    krb5_error_code retval;

    retval = 0;
    if (cksum->checksum_type == CKSUMTYPE_RSA_MD5) {
	if (cksum->length == RSA_MD5_CKSUM_LENGTH) {
	    MD5Init(&working);
	    MD5Update(&working, input, in_length);
	    MD5Final(&working);

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
    md5_sum_func,
    md5_verify_func,
    RSA_MD5_CKSUM_LENGTH,
    1,					/* is collision proof */
    0,					/* doesn't use key */
};

#include "shs.h"

/* Windows needs to these prototypes for the assignment below */

static krb5_error_code
krb5_sha_crypto_sum_func
	PROTOTYPE((krb5_const krb5_pointer in,
		   krb5_const size_t in_length,
		   krb5_const krb5_pointer seed,
		   krb5_const size_t seed_length,
		   krb5_checksum FAR *outcksum));

static krb5_error_code
krb5_sha_crypto_verify_func
	PROTOTYPE((krb5_const krb5_checksum FAR *cksum,
		   krb5_const krb5_pointer in,
		   krb5_const size_t in_length,
		   krb5_const krb5_pointer seed,
		   krb5_const size_t seed_length));

static krb5_error_code
krb5_sha_crypto_sum_func(in, in_length, seed, seed_length, outcksum)
    krb5_const krb5_pointer in;
    krb5_const size_t in_length;
    krb5_const krb5_pointer seed;
    krb5_const size_t seed_length;
    krb5_checksum FAR *outcksum;
{
    krb5_error_code retval;

    if (outcksum->length < HMAC_SHA_CKSUM_LENGTH)
	return KRB5_BAD_MSIZE;

    outcksum->checksum_type = CKSUMTYPE_HMAC_SHA;
    outcksum->length = HMAC_SHA_CKSUM_LENGTH;

    retval = hmac_sha(in, in_length, seed, seed_length, outcksum->contents);
    return retval;
}

static krb5_error_code
krb5_sha_crypto_verify_func(cksum, in, in_length, seed, seed_length)
    krb5_const krb5_checksum FAR *cksum;
    krb5_const krb5_pointer in;
    krb5_const size_t in_length;
    krb5_const krb5_pointer seed;
    krb5_const size_t seed_length;
{
    krb5_octet digest[HMAC_SHA_CKSUM_LENGTH];
    krb5_error_code retval;

    if (cksum->checksum_type != CKSUMTYPE_HMAC_SHA)
	return KRB5KRB_AP_ERR_INAPP_CKSUM;
    if (cksum->length != HMAC_SHA_CKSUM_LENGTH)
	return KRB5KRB_AP_ERR_BAD_INTEGRITY;

    retval = hmac_sha(in, in_length, seed, seed_length, digest);
    if (retval) goto cleanup;

    if (memcmp((char *)digest, (char *)cksum->contents, cksum->length))
	retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;

cleanup:
    memset((char *)digest, 0, sizeof(digest));
    return retval;
}

krb5_checksum_entry hmac_sha_cksumtable_entry =
{
    0,
    krb5_sha_crypto_sum_func,
    krb5_sha_crypto_verify_func,
    HMAC_SHA_CKSUM_LENGTH,
    1,					/* is collision proof */
    1,					/* uses key */
};

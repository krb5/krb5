#if !defined(lint) && !defined(SABER)
static char rcsid_md5glue_c[] = "$Id$";
#endif

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/rsa-md5.h>

static krb5_error_code
md5_sum_func(in, in_length, seed, seed_length, outcksum)
krb5_pointer in;
size_t in_length;
krb5_pointer seed;
size_t seed_length;
krb5_checksum *outcksum;
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

krb5_checksum_entry rsa_md5_cksumtable_entry = {
    md5_sum_func,
    RSA_MD5_CKSUM_LENGTH,
    1,					/* is collision proof */
    0,					/* doesn't use key */
};

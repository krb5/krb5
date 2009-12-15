/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "k5-int.h"
#include "k5-utf8.h"
#include "rsa-md4.h"
#include "arcfour-int.h"

#if TARGET_OS_MAC && !defined(DEPEND)
#include <CoreFoundation/CFString.h>
#endif

krb5_error_code
krb5int_arcfour_string_to_key(const struct krb5_keytypes *ktp,
                              const krb5_data *string, const krb5_data *salt,
                              const krb5_data *params, krb5_keyblock *key)
{
    krb5_error_code err = 0;
    krb5_MD4_CTX md4_context;
    unsigned char *copystr;
    size_t copystrlen;

    if (params != NULL)
        return KRB5_ERR_BAD_S2K_PARAMS;

    if (key->length != 16)
        return (KRB5_BAD_MSIZE);

    /* We ignore salt per the Microsoft spec*/

    /* compute the space needed for the new string.
       Since the password must be stored in unicode, we need to increase
       that number by 2x.
    */

    err = krb5int_utf8cs_to_ucs2les(string->data, string->length, &copystr, &copystrlen);
    if (err)
        return err;

    /* the actual MD4 hash of the data */
    krb5int_MD4Init(&md4_context);
    krb5int_MD4Update(&md4_context, copystr, copystrlen);
    krb5int_MD4Final(&md4_context);
    memcpy(key->contents, md4_context.digest, 16);

#if 0
    /* test the string_to_key function */
    printf("Hash=");
    {
        int counter;
        for(counter=0;counter<16;counter++)
            printf("%02x", md4_context.digest[counter]);
        printf("\n");
    }
#endif /* 0 */

    /* Zero out the data behind us */
    memset(copystr, 0, copystrlen);
    memset(&md4_context, 0, sizeof(md4_context));
    free(copystr);
    return err;
}

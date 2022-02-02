/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* stdcc_util.h
 *
 * Frank Dabek, July 1998
 */

#if defined(_WIN32) || defined(USE_CCAPI)

#include "autoconf.h"

#include <CredentialsCache.h>

#include "krb5.h"

/* prototypes for private functions declared in stdcc_util.c */
krb5_error_code
copy_cc_cred_union_to_krb5_creds (krb5_context in_context,
                                  const cc_credentials_union *in_cred_union,
                                  krb5_creds *out_creds);
krb5_error_code
copy_krb5_creds_to_cc_cred_union (krb5_context in_context,
                                  krb5_creds *in_creds,
                                  cc_credentials_union **out_cred_union);

krb5_error_code
cred_union_release (cc_credentials_union *in_cred_union);

#define kAddressArray 4
#define kAuthDataArray 5

#endif /* defined(_WIN32) || defined(USE_CCAPI) */

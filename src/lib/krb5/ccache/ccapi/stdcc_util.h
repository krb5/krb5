/* stdcc_util.h
 *
 * Frank Dabek, July 1998
 */

#if USE_CCAPI
#include <CredentialsCache2.h>
#endif

#if defined(_WIN32)
#include "cacheapi.h"
#endif

#include "krb5.h"

/* protoypes for private functions declared in stdcc_util.c */
int copyCCDataArrayToK5(cc_creds *cc, krb5_creds *kc, char whichArray);
int copyK5DataArrayToCC(krb5_creds *kc, cc_creds *cc, char whichArray);
void dupCCtoK5(krb5_context context, cc_creds *src, krb5_creds *dest);
void dupK5toCC(krb5_context context, krb5_creds *creds, cred_union **cu);
int stdccCredsMatch(krb5_context context, krb5_creds *base, krb5_creds *match, int whichfields);
int bitTst(int var, int mask);
cc_int32 krb5_free_cc_cred_union (cred_union** creds);

#define kAddressArray 4 
#define kAuthDataArray 5


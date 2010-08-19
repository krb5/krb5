/* lib/crypto/openssl/md5/md5.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "rsa-md5.h"
#include "pk11pub.h"
#include "nss_gen.h"


/* The routine krb5int_MD5Init initializes the message-digest context
   mdContext.
 */
void
krb5int_MD5Init (krb5_MD5_CTX *mdContext)
{
    if (k5_nss_init()) {
	mdContext->nss_ctxt = NULL;
	return;
    }
    mdContext->nss_ctxt = PK11_CreateDigestContext(SEC_OID_MD5);
    if (mdContext->nss_ctxt == NULL) {
	return;
    }
    PK11_DigestBegin((PK11Context *)mdContext->nss_ctxt);
}

/* The routine krb5int_MD5Update updates the message-digest context to
   account for the presence of each of the characters inBuf[0..inLen-1]
   in the message whose digest is being computed.
 */
void
krb5int_MD5Update (krb5_MD5_CTX *mdContext, const unsigned char *inBuf, unsigned int inLen)
{
   if (mdContext->nss_ctxt == NULL) {
	return;
   }
   PK11_DigestOp((PK11Context *)mdContext->nss_ctxt, inBuf, inLen);
}

/* The routine krb5int_MD5Final terminates the message-digest computation and
   ends with the desired message digest in mdContext->digest[0...15].
 */
void
krb5int_MD5Final (krb5_MD5_CTX *mdContext)
{
   unsigned int digestLength;

   if (mdContext->nss_ctxt == NULL) {
	return;
   }
   PK11_DigestFinal((PK11Context *)mdContext->nss_ctxt, mdContext->digest, 
		&digestLength, sizeof (mdContext->digest));
   /* since there is not separate cleanup step, free the context now. 
    * (otherwise we could have reused the context for another MD5 operation
    * in the future).
    */
   PK11_DestroyContext((PK11Context *)mdContext->nss_ctxt, PR_TRUE);
   mdContext->nss_ctxt = NULL;
}

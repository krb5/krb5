/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/md5/md5.c
 *
 * Copyright (c) 2010 Red Hat, Inc.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 *  * Neither the name of Red Hat, Inc., nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "rsa-md5.h"
#include "pk11pub.h"
#include "nss_gen.h"


/* Initialize the message-digest context mdContext. */
void
krb5int_MD5Init(krb5_MD5_CTX *mdContext)
{
    if (k5_nss_init()) {
        mdContext->nss_ctxt = NULL;
        return;
    }
    mdContext->nss_ctxt = PK11_CreateDigestContext(SEC_OID_MD5);
    if (mdContext->nss_ctxt == NULL)
        return;
    PK11_DigestBegin((PK11Context *)mdContext->nss_ctxt);
}

/*
 * Update the message-digest context to account for the presence of each of the
 * characters inBuf[0..inLen-1] in the message whose digest is being computed.
 */
void
krb5int_MD5Update(krb5_MD5_CTX *mdContext, const unsigned char *inBuf,
                  unsigned int inLen)
{
   if (mdContext->nss_ctxt == NULL)
        return;
   PK11_DigestOp((PK11Context *)mdContext->nss_ctxt, inBuf, inLen);
}

/* Terminate the message-digest computation and end with the desired message
 * digest in mdContext->digest[0...15]. */
void
krb5int_MD5Final(krb5_MD5_CTX *mdContext)
{
   unsigned int digestLength;

   if (mdContext->nss_ctxt == NULL)
        return;
   PK11_DigestFinal((PK11Context *)mdContext->nss_ctxt, mdContext->digest,
                    &digestLength, sizeof (mdContext->digest));
   /* since there is not separate cleanup step, free the context now.
    * (otherwise we could have reused the context for another MD5 operation
    * in the future).
    */
   PK11_DestroyContext((PK11Context *)mdContext->nss_ctxt, PR_TRUE);
   mdContext->nss_ctxt = NULL;
}

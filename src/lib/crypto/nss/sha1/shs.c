/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/sha1/shs.c
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
#include "shs.h"
#include "pk11pub.h"
#include "nss_gen.h"

/* Initialize the SHS values */
void shsInit(SHS_INFO *shsInfo)
{
    if (k5_nss_init()) {
        shsInfo->nss_ctxt = NULL;
        return;
    }
    shsInfo->nss_ctxt = PK11_CreateDigestContext(SEC_OID_SHA1);
    if (shsInfo->nss_ctxt == NULL)
        return;
    PK11_DigestBegin((PK11Context *)shsInfo->nss_ctxt);
}

/* Update SHS for a block of data */
void shsUpdate(SHS_INFO *shsInfo, const SHS_BYTE *buffer, unsigned int count)
{
    if (shsInfo->nss_ctxt == NULL)
        return;
    PK11_DigestOp((PK11Context *)shsInfo->nss_ctxt, buffer, count);
}


/* Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first) */
void shsFinal(SHS_INFO *shsInfo)
{
   if (shsInfo->nss_ctxt == NULL)
        return;
   PK11_DigestFinal((PK11Context *)shsInfo->nss_ctxt, shsInfo->digestBuf,
                    &shsInfo->digestLen, sizeof (shsInfo->digestBuf));
   /* Since there is not separate cleanup step, free the context now.
    * (otherwise we could have reused the context for another MD5 operation
    * in the future).
    */
   PK11_DestroyContext((PK11Context *)shsInfo->nss_ctxt, PR_TRUE);
   shsInfo->nss_ctxt = NULL;
}

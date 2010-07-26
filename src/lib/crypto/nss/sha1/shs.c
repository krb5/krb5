/* lib/crypto/openssl/sha1/shs.c
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
    if (shsInfo->nss_ctxt == NULL) {
	return;
    }
    PK11_DigestBegin((PK11Context *)shsInfo->nss_ctxt);
}

/* Update SHS for a block of data */
void shsUpdate(SHS_INFO *shsInfo, const SHS_BYTE *buffer, unsigned int count)
{
   if (shsInfo->nss_ctxt == NULL) {
	return;
   }
   PK11_DigestOp((PK11Context *)shsInfo->nss_ctxt, buffer, count);
}


/* Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */
void shsFinal(SHS_INFO *shsInfo)
{
   if (shsInfo->nss_ctxt == NULL) {
	return;
   }
   PK11_DigestFinal((PK11Context *)shsInfo->nss_ctxt, shsInfo->digestBuf, 
		&shsInfo->digestLen, sizeof (shsInfo->digestBuf));
   /* since there is not separate cleanup step, free the context now. 
    * (otherwise we could have reused the context for another MD5 operation
    * in the future).
    */
   PK11_DestroyContext((PK11Context *)shsInfo->nss_ctxt, PR_TRUE);
   shsInfo->nss_ctxt = NULL;
}


/*
 * Copyright (c) 2004-2008 Apple Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Apple Inc. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Apple Inc. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/*
 * pkinit_client.h - Client side routines for PKINIT
 *
 * Created 20 May 2004 by Doug Mitchell at Apple.
 */

#ifndef _PKINIT_CLIENT_H_
#define _PKINIT_CLIENT_H_

#include <krb5/krb5.h>
#include "pkinit_cms.h"
#include "pkinit_cert_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a PA-PK-AS-REQ message.
 */
krb5_error_code krb5int_pkinit_as_req_create(
    krb5_context		context,
    krb5_timestamp		kctime,      
    krb5_int32			cusec,		/* microseconds */
    krb5_ui_4			nonce,
    const krb5_checksum		*cksum,
    krb5_pkinit_signing_cert_t	client_cert,	/* required! */
    
    /* 
     * trusted_CAs correponds to PA-PK-AS-REQ.trustedCertifiers.
     * Expressed here as an optional list of DER-encoded certs. 
     */
    const krb5_data		*trusted_CAs,	
    krb5_ui_4			num_trusted_CAs,
    
    /* optional PA-PK-AS-REQ.kdcPkId, expressed here as a 
     * DER-encoded cert */
    const krb5_data		*kdc_cert,	
    krb5_data			*as_req);	/* mallocd and RETURNED */

/*
 * Parse PA-PK-AS-REP message. Optionally evaluates the message's certificate chain. 
 * Optionally returns various components. 
 */
krb5_error_code krb5int_pkinit_as_rep_parse(
    krb5_context		context,
    const krb5_data		*as_rep,
    krb5_pkinit_signing_cert_t   client_cert,	/* required for decryption */
    krb5_keyblock		*key_block,     /* RETURNED */
    krb5_checksum		*checksum,	/* checksum of corresponding AS-REQ */
						/*   contents mallocd and RETURNED */
    krb5int_cert_sig_status	*cert_status,   /* RETURNED */

    /*
     * Cert fields, all optionally RETURNED.
     *
     * signer_cert is the DER-encoded leaf cert from the incoming SignedData.
     * all_certs is an array of all of the certs in the incoming SignedData,
     *    in full DER-encoded form. 
     */
    krb5_data		    *signer_cert,   /* content mallocd */
    unsigned		    *num_all_certs, /* sizeof *all_certs */
    krb5_data		    **all_certs);   /* krb5_data's and their content mallocd */

#ifdef __cplusplus
}
#endif

#endif  /* _PKINIT_CLIENT_H_ */

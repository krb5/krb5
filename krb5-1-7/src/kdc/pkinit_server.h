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
 * pkinit_server.h - Server side routines for PKINIT
 *
 * Created 21 May 2004 by Doug Mitchell at Apple.
 */

#ifndef _PKINIT_SERVER_H_
#define _PKINIT_SERVER_H_

#include "krb5.h"
#include "pkinit_cms.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Parse PA-PK-AS-REQ message. Optionally evaluates the message's certificate chain
 * if cert_status is non-NULL. Optionally returns various components. 
 */
krb5_error_code krb5int_pkinit_as_req_parse(
    krb5_context	context,
    const krb5_data	*as_req,
    krb5_timestamp      *kctime,	/* optionally RETURNED */
    krb5_ui_4		*cusec,		/* microseconds, optionally RETURNED */
    krb5_ui_4		*nonce,		/* optionally RETURNED */
    krb5_checksum       *pa_cksum,	/* optional, contents mallocd and RETURNED */
    krb5int_cert_sig_status *cert_status,   /* optionally RETURNED */
    krb5_ui_4		*num_cms_types,	/* optionally RETURNED */
    krb5int_algorithm_id **cms_types,	/* optionally mallocd and RETURNED */

    /*
     * Cert fields, all optionally RETURNED.
     *
     * signer_cert is the full X.509 leaf cert from the incoming SignedData.
     * all_certs is an array of all of the certs in the incoming SignedData,
     *    in full X.509 form. 
     */
    krb5_data		*signer_cert,   /* content mallocd */
    krb5_ui_4		*num_all_certs, /* sizeof *all_certs */
    krb5_data		**all_certs,    /* krb5_data's and their content mallocd */
    
    /*
     * Array of trustedCertifiers, optionally RETURNED. These are DER-encoded 
     * issuer/serial numbers. 
     */
    krb5_ui_4		*num_trusted_CAs,   /* sizeof *trustedCAs */
    krb5_data		**trusted_CAs,      /* krb5_data's and their content mallocd */
    
    /* KDC cert specified by client as kdcPkId. DER-encoded issuer/serial number. */
    krb5_data		*kdc_cert);
    
    
/*
 * Create a PA-PK-AS-REP message, public key (no Diffie Hellman) version.
 *
 * PA-PK-AS-REP is based on ReplyKeyPack like so:
 *
 * PA-PK-AS-REP ::= EnvelopedData(SignedData(ReplyKeyPack))
 */
krb5_error_code krb5int_pkinit_as_rep_create(
    krb5_context		context,
    const krb5_keyblock		*key_block,
    const krb5_checksum		*checksum,		/* checksum of corresponding AS-REQ */
    krb5_pkinit_signing_cert_t	signer_cert,		/* server's cert */
    krb5_boolean		include_server_cert,	/* include signer_cert in SignerInfo */
    const krb5_data		*recipient_cert,	/* client's cert */
    
    /* 
     * These correspond to the same out-parameters from 
     * krb5int_pkinit_as_req_parse(). All are optional. 
     */
    krb5_ui_4			num_cms_types,
    const krb5int_algorithm_id	*cms_types,	
    krb5_ui_4			num_trusted_CAs,
    krb5_data			*trusted_CAs,   
    krb5_data			*kdc_cert,
    
    /* result here, mallocd and RETURNED */
    krb5_data			*as_rep);
    
#ifdef __cplusplus
}
#endif

#endif  /* _PKINIT_SERVER_H_ */

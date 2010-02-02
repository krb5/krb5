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
 * pkinit_asn1.h - ASN.1 encode/decode routines for PKINIT
 *
 * Created 18 May 2004 by Doug Mitchell.
 */
 
#ifndef	_PKINIT_ASN1_H_
#define _PKINIT_ASN1_H_

#include <krb5/krb5.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 3280 AlgorithmIdentifier */
typedef struct {
    krb5_data	algorithm;	/* OID */
    krb5_data	parameters;	/* ASN_ANY, defined by algorithm */
} krb5int_algorithm_id;

/* 
 * Encode and decode AuthPack, public key version (no Diffie-Hellman components).
 */
krb5_error_code krb5int_pkinit_auth_pack_encode(
    krb5_timestamp		kctime,      
    krb5_int32			cusec,		    /* microseconds */
    krb5_ui_4			nonce,
    const krb5_checksum		*pa_checksum,
    const krb5int_algorithm_id	*cms_types,	    /* optional */
    krb5_ui_4			num_cms_types,
    krb5_data			*auth_pack);	    /* mallocd and RETURNED */
    
/* all returned values are optional - pass NULL if you don't want them */
krb5_error_code krb5int_pkinit_auth_pack_decode(
    const krb5_data	*auth_pack,	    /* DER encoded */
    krb5_timestamp      *kctime,	    /* RETURNED */
    krb5_ui_4		*cusec,		    /* microseconds, RETURNED */
    krb5_ui_4		*nonce,		    /* RETURNED */
    krb5_checksum       *pa_checksum,	    /* contents mallocd and RETURNED */
    krb5int_algorithm_id **cms_types,	    /* mallocd and RETURNED */
    krb5_ui_4		*num_cms_types);    /* RETURNED */
    
    
/*
 * Given DER-encoded issuer and serial number, create an encoded 
 * IssuerAndSerialNumber.
 */
krb5_error_code krb5int_pkinit_issuer_serial_encode(
    const krb5_data *issuer,		    /* DER encoded */
    const krb5_data *serial_num,
    krb5_data       *issuer_and_serial);    /* content mallocd and RETURNED */

/*
 * Decode IssuerAndSerialNumber.
 */
krb5_error_code krb5int_pkinit_issuer_serial_decode(
    const krb5_data *issuer_and_serial,     /* DER encoded */
    krb5_data       *issuer,		    /* DER encoded, RETURNED */
    krb5_data       *serial_num);	    /* RETURNED */

/*
 * Top-level encode for PA-PK-AS-REQ.  
 * The signed_auth_pack field is wrapped in an OCTET STRING, content
 * specific tag 0, during encode. 
 */
krb5_error_code krb5int_pkinit_pa_pk_as_req_encode(
    const krb5_data *signed_auth_pack,	/* DER encoded ContentInfo */
    const krb5_data *trusted_CAs,	/* optional: trustedCertifiers. Contents are
					 * DER-encoded issuer/serialNumbers. */
    krb5_ui_4	    num_trusted_CAs,
    const krb5_data *kdc_cert,		/* optional kdcPkId, DER encoded issuer/serial */
    krb5_data       *pa_pk_as_req);	/* mallocd and RETURNED */

/*
 * Top-level decode for PA-PK-AS-REQ. Does not perform cert verification on the 
 * ContentInfo; that is returned in BER-encoded form and processed elsewhere.
 * The OCTET STRING wrapping the signed_auth_pack field is removed during the 
 * decode.
 */
krb5_error_code krb5int_pkinit_pa_pk_as_req_decode(
    const krb5_data *pa_pk_as_req,
    krb5_data *signed_auth_pack,	/* DER encoded ContentInfo, RETURNED */
    /* 
     * Remainder are optionally RETURNED (specify NULL for pointers to 
     * items you're not interested in).
     */
    krb5_ui_4 *num_trusted_CAs,		/* sizeof trusted_CAs */
    krb5_data **trusted_CAs,		/* mallocd array of DER-encoded TrustedCAs 
					 *   issuer/serial */
    krb5_data *kdc_cert);		/* DER encoded issuer/serial */

/* 
 * Encode a ReplyKeyPack. The result is used as the Content of a SignedData.
 */
krb5_error_code krb5int_pkinit_reply_key_pack_encode(
    const krb5_keyblock *key_block,
    const krb5_checksum *checksum,
    krb5_data		*reply_key_pack);   /* mallocd and RETURNED */

/* 
 * Decode a ReplyKeyPack.
 */
krb5_error_code krb5int_pkinit_reply_key_pack_decode(
    const krb5_data	*reply_key_pack,
    krb5_keyblock       *key_block,	    /* RETURNED */
    krb5_checksum	*checksum);	    /* contents mallocd and RETURNED */

/* 
 * Encode a PA-PK-AS-REP.
 * Exactly one of {dh_signed_data, enc_key_pack} is non-NULL on entry;
 * each is a previously encoded item. 
 *
 * dh_signed_data, if specified, is an encoded DHRepInfo.
 * enc_key_pack, if specified, is EnvelopedData(signedData(ReplyKeyPack)
 */
krb5_error_code krb5int_pkinit_pa_pk_as_rep_encode(
    const krb5_data     *dh_signed_data, 
    const krb5_data     *enc_key_pack,	    /* EnvelopedData(signedData(ReplyKeyPack) */
    krb5_data		*pa_pk_as_rep);	    /* mallocd and RETURNED */

/* 
 * Decode a PA-PK-AS-REP.
 * On successful return, exactly one of {dh_signed_data, enc_key_pack}
 * will be non-NULL, each of which is mallocd and must be freed by
 * caller. 
 *
 * dh_signed_data, if returned, is an encoded DHRepInfo.
 * enc_key_pack, if specified, is EnvelopedData(signedData(ReplyKeyPack)
 */
krb5_error_code krb5int_pkinit_pa_pk_as_rep_decode(
    const krb5_data     *pa_pk_as_rep,
    krb5_data		*dh_signed_data, 
    krb5_data		*enc_key_pack);

/*
 * Given a DER encoded certificate, obtain the associated IssuerAndSerialNumber.
 */
krb5_error_code krb5int_pkinit_get_issuer_serial(
    const krb5_data	*cert,
    krb5_data		*issuer_and_serial);

#ifdef __cplusplus
}
#endif

#endif	/* _PKINIT_ASN1_H_ */

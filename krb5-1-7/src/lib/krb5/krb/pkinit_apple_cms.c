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
 * pkinit_apple_cms.c - CMS encode/decode routines, Mac OS X version
 *
 * Created 19 May 2004 by Doug Mitchell at Apple.
 */

#if APPLE_PKINIT

#include "pkinit_cms.h"
#include "pkinit_asn1.h"
#include "pkinit_apple_utils.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CMSEncoder.h>
#include <Security/CMSDecoder.h>
#include <Security/Security.h>
#include <assert.h>
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacTypes.h>

/* 
 * Custom OIDS to specify as eContentType 
 */
#define OID_PKINIT	0x2B, 6, 1, 5, 2, 3
#define OID_PKINIT_LEN	6

static const uint8	OID_PKINIT_AUTH_DATA[]	    = {OID_PKINIT, 1};
static const uint8	OID_PKINIT_RKEY_DATA[]	    = {OID_PKINIT, 3};

/* these may go public so keep these symbols private */
static const CSSM_OID	_CSSMOID_PKINIT_AUTH_DATA = 
	{OID_PKINIT_LEN+1, (uint8 *)OID_PKINIT_AUTH_DATA};
static const CSSM_OID	_CSSMOID_PKINIT_RKEY_DATA = 
	{OID_PKINIT_LEN+1, (uint8 *)OID_PKINIT_RKEY_DATA};


#pragma mark ----- CMS utilities ----

#define CFRELEASE(cf) if(cf) { CFRelease(cf); }

/*
 * Convert platform-specific cert/signature status to krb5int_cert_sig_status.
 */
static krb5int_cert_sig_status pkiCertSigStatus(
    OSStatus certStatus)
{
    switch(certStatus) {
	case CSSM_OK:
	    return pki_cs_good;
	case CSSMERR_CSP_VERIFY_FAILED:
	    return pki_cs_sig_verify_fail;
	case CSSMERR_TP_NOT_TRUSTED:
	    return pki_cs_no_root;
	case CSSMERR_TP_INVALID_ANCHOR_CERT:
	    return pki_cs_unknown_root;
	case CSSMERR_TP_CERT_EXPIRED:
	    return pki_cs_expired;
	case CSSMERR_TP_CERT_NOT_VALID_YET:
	    return pki_cs_not_valid_yet;
	case CSSMERR_TP_CERT_REVOKED:
	    return pki_cs_revoked;
	case KRB5_KDB_UNAUTH:
	    return pki_cs_untrusted;
	case CSSMERR_TP_INVALID_CERTIFICATE:
	    return pki_cs_bad_leaf;
	default:
	    return pki_cs_other_err;
    }
}

/*
 * Infer krb5int_cert_sig_status from CMSSignerStatus and a CSSM TO
 * cert veriofy result code (obtained via the certVerifyResultCode argument
 * in CMSDecoderCopySignerStatus()).
 */
static krb5int_cert_sig_status pkiInferSigStatus(
    CMSSignerStatus cms_status,
    OSStatus	    tp_status)
{
    switch(cms_status) {
	case kCMSSignerUnsigned:
	    return pki_not_signed;
	case kCMSSignerValid:
	    return pki_cs_good;
	case kCMSSignerNeedsDetachedContent:
	    return pki_bad_cms;
	case kCMSSignerInvalidSignature:
	    return pki_cs_sig_verify_fail;
	case kCMSSignerInvalidCert:
	    /* proceed with TP status */
	    break;
	default:
	    return pki_cs_other_err;
    }
    
    /* signature good, infer end status from TP verify */
    return pkiCertSigStatus(tp_status);
}

/*
 * Cook up a SecCertificateRef from a krb5_data.
 */
static OSStatus pkiKrb5DataToSecCert(
    const krb5_data *rawCert,
    SecCertificateRef *secCert)     /* RETURNED */
{
    CSSM_DATA certData;
    OSStatus ortn;
    
    assert((rawCert != NULL) && (secCert != NULL));
    
    certData.Data = (uint8 *)rawCert->data;
    certData.Length = rawCert->length;
    ortn = SecCertificateCreateFromData(&certData, CSSM_CERT_X_509v3, 
	CSSM_CERT_ENCODING_DER, secCert);
    if(ortn) {
	pkiCssmErr("SecCertificateCreateFromData", ortn);
    }
    return ortn;
}

/*
 * Convert CFArray of SecCertificateRefs to a mallocd array of krb5_datas.
 */
static krb5_error_code pkiCertArrayToKrb5Data(
    CFArrayRef  cf_certs,
    unsigned	*num_all_certs,
    krb5_data   **all_certs)	
{
    CFIndex num_certs;
    krb5_data *allCerts = NULL;
    krb5_error_code krtn = 0;
    CFIndex dex;
    
    if(cf_certs == NULL) {
	*all_certs = NULL;
	return 0;
    }
    num_certs = CFArrayGetCount(cf_certs);
    *num_all_certs = (unsigned)num_certs;
    if(num_certs == 0) {
	*all_certs = NULL;
	return 0;
    }
    allCerts = (krb5_data *)malloc(sizeof(krb5_data) * num_certs);
    if(allCerts == NULL) {
	return ENOMEM;
    }
    for(dex=0; dex<num_certs; dex++) {	
	CSSM_DATA cert_data;
	OSStatus ortn;
	SecCertificateRef sec_cert;
	
	sec_cert = (SecCertificateRef)CFArrayGetValueAtIndex(cf_certs, dex);
	ortn = SecCertificateGetData(sec_cert, &cert_data);
	if(ortn) {
	    pkiCssmErr("SecCertificateGetData", ortn);
	    krtn = KRB5_PARSE_MALFORMED;
	    break;
	}
	krtn = pkiCssmDataToKrb5Data(&cert_data, &allCerts[dex]);
	if(krtn) {
	    break;
	}
    }
    if(krtn) {
	if(allCerts) {
	    free(allCerts);
	}
    }
    else {
	*all_certs = allCerts;
    }
    return krtn;
}

#pragma mark ----- Create CMS message -----

/*
 * Create a CMS message: either encrypted (EnvelopedData), signed 
 * (SignedData), or both (EnvelopedData(SignedData(content)).
 *
 * The message is signed iff signing_cert is non-NULL.
 * The message is encrypted iff recip_cert is non-NULL.
 *
 * The content_type argument specifies to the eContentType
 * for a SignedData's EncapsulatedContentInfo. 
 */
krb5_error_code krb5int_pkinit_create_cms_msg(
    const krb5_data		*content,	/* Content */
    krb5_pkinit_signing_cert_t	signing_cert,	/* optional: signed by this cert */
    const krb5_data		*recip_cert,	/* optional: encrypted with this cert */
    krb5int_cms_content_type	content_type,   /* OID for EncapsulatedData */
    krb5_ui_4			num_cms_types,	/* optional, unused here */
    const krb5int_algorithm_id	*cms_types,	/* optional, unused here */
    krb5_data			*content_info)  /* contents mallocd and RETURNED */
{
    krb5_error_code krtn;
    OSStatus ortn;
    SecCertificateRef sec_recip = NULL;
    CFDataRef cf_content = NULL;
    const CSSM_OID *eContentOid = NULL;
    
    if((signing_cert == NULL) && (recip_cert == NULL)) {
	/* must have one or the other */
	pkiDebug("krb5int_pkinit_create_cms_msg: no signer or recipient\n");
	return KRB5_CRYPTO_INTERNAL;
    }
    
    /* 
     * Optional signer cert. Note signing_cert, if present, is 
     * a SecIdentityRef. 
     */
    if(recip_cert) {
	if(pkiKrb5DataToSecCert(recip_cert, &sec_recip)) {
	    krtn = ASN1_BAD_FORMAT;
	    goto errOut;
	}
    }
    
    /* optional eContentType */
    if(signing_cert) {
	switch(content_type) {
	    case ECT_PkAuthData:
		eContentOid = &_CSSMOID_PKINIT_AUTH_DATA;
		break;
	    case ECT_PkReplyKeyKata:
		eContentOid = &_CSSMOID_PKINIT_RKEY_DATA;
		break;
	    case ECT_Data:
		/* the only standard/default case we allow */
		break;
	    default:
		/* others: no can do */
		pkiDebug("krb5int_pkinit_create_cms_msg: bad contentType\n");
		krtn = KRB5_CRYPTO_INTERNAL;
		goto errOut;
	}
    }
    
    /* GO */
    ortn = CMSEncode((SecIdentityRef)signing_cert, sec_recip,
	eContentOid, 
	FALSE,		/* detachedContent */
	kCMSAttrNone,	/* no signed attributes that I know of */
	content->data, content->length,
	&cf_content);
    if(ortn) {
	pkiCssmErr("CMSEncode", ortn);
	krtn = KRB5_CRYPTO_INTERNAL;
	goto errOut;
    }
    krtn = pkiCfDataToKrb5Data(cf_content, content_info);
errOut:
    CFRELEASE(sec_recip);
    CFRELEASE(cf_content);
    return krtn;
}

#pragma mark ----- Generalized parse ContentInfo ----

/*
 * Parse a ContentInfo as best we can. All return fields are optional.
 * If signer_cert_status is NULL on entry, NO signature or cert evaluation 
 * will be performed. 
 */
krb5_error_code krb5int_pkinit_parse_cms_msg(
    const krb5_data	    *content_info,
    krb5_pkinit_cert_db_t   cert_db,		/* may be required for SignedData */
    krb5_boolean	    is_client_msg,	/* TRUE : msg is from client */
    krb5_boolean	    *is_signed,		/* RETURNED */
    krb5_boolean	    *is_encrypted,	/* RETURNED */
    krb5_data		    *raw_data,		/* RETURNED */
    krb5int_cms_content_type *inner_content_type,/* Returned, ContentType of */
						/*    EncapsulatedData */
    krb5_data		    *signer_cert,	/* RETURNED */
    krb5int_cert_sig_status *signer_cert_status,/* RETURNED */
    unsigned		    *num_all_certs,	/* size of *all_certs RETURNED */
    krb5_data		    **all_certs)	/* entire cert chain RETURNED */
{
    SecPolicySearchRef policy_search = NULL;
    SecPolicyRef policy = NULL;
    OSStatus ortn;
    krb5_error_code krtn = 0;
    CMSDecoderRef decoder = NULL;
    size_t num_signers;
    CMSSignerStatus signer_status;
    OSStatus cert_verify_status;
    CFArrayRef cf_all_certs = NULL;
    int msg_is_signed = 0;
    
    if(content_info == NULL) {
	pkiDebug("krb5int_pkinit_parse_cms_msg: no ContentInfo\n");
	return KRB5_CRYPTO_INTERNAL;
    }
    
    ortn = CMSDecoderCreate(&decoder);
    if(ortn) {
	return ENOMEM;
    }
    ortn = CMSDecoderUpdateMessage(decoder, content_info->data, content_info->length);
    if(ortn) {
	/* no verify yet, must be bad message */
	krtn = KRB5_PARSE_MALFORMED;
	goto errOut;
    }
    ortn = CMSDecoderFinalizeMessage(decoder);
    if(ortn) {
	pkiCssmErr("CMSDecoderFinalizeMessage", ortn);
	krtn = KRB5_PARSE_MALFORMED;
	goto errOut;
    }

    /* expect zero or one signers */
    ortn = CMSDecoderGetNumSigners(decoder, &num_signers);
    switch(num_signers) {
	case 0:
	    msg_is_signed = 0;
	    break;
	case 1:
	    msg_is_signed = 1;
	    break;
	default:
	    krtn = KRB5_PARSE_MALFORMED;
	    goto errOut;
    }

    /*
     * We need a cert verify policy even if we're not actually evaluating 
     * the cert due to requirements in libsecurity_smime.
     */
    ortn = SecPolicySearchCreate(CSSM_CERT_X_509v3,
	is_client_msg ? &CSSMOID_APPLE_TP_PKINIT_CLIENT : &CSSMOID_APPLE_TP_PKINIT_SERVER, 
	NULL, &policy_search);
    if(ortn) {
	pkiCssmErr("SecPolicySearchCreate", ortn);
	krtn = KRB5_CRYPTO_INTERNAL;
	goto errOut;
    }
    ortn = SecPolicySearchCopyNext(policy_search, &policy);
    if(ortn) {
	pkiCssmErr("SecPolicySearchCopyNext", ortn);
	krtn = KRB5_CRYPTO_INTERNAL;
	goto errOut;
    }
    
    /* get some basic status that doesn't need heavyweight evaluation */
    if(msg_is_signed) {
	if(is_signed) {
	    *is_signed = TRUE;
	}
	if(inner_content_type) {
	    CSSM_OID ec_oid = {0, NULL};
	    CFDataRef ec_data = NULL;
	    
	    krb5int_cms_content_type ctype;
	    
	    ortn = CMSDecoderCopyEncapsulatedContentType(decoder, &ec_data);
	    if(ortn || (ec_data == NULL)) {
		pkiCssmErr("CMSDecoderCopyEncapsulatedContentType", ortn);
		krtn = KRB5_CRYPTO_INTERNAL;
		goto errOut;
	    }
	    ec_oid.Data = (uint8 *)CFDataGetBytePtr(ec_data);
	    ec_oid.Length = CFDataGetLength(ec_data);
	    if(pkiCompareCssmData(&ec_oid, &CSSMOID_PKCS7_Data)) {
		ctype = ECT_Data;
	    }
	    else if(pkiCompareCssmData(&ec_oid, &CSSMOID_PKCS7_SignedData)) {
		ctype = ECT_SignedData;
	    }
	    else if(pkiCompareCssmData(&ec_oid, &CSSMOID_PKCS7_EnvelopedData)) {
		ctype = ECT_EnvelopedData;
	    }
	    else if(pkiCompareCssmData(&ec_oid, &CSSMOID_PKCS7_EncryptedData)) {
		ctype = ECT_EncryptedData;
	    }
	    else if(pkiCompareCssmData(&ec_oid, &_CSSMOID_PKINIT_AUTH_DATA)) {
		ctype = ECT_PkAuthData;
	    }
	    else if(pkiCompareCssmData(&ec_oid, &_CSSMOID_PKINIT_RKEY_DATA)) {
		ctype = ECT_PkReplyKeyKata;
	    }
	    else {
		ctype = ECT_Other;
	    }
	    *inner_content_type = ctype;
	    CFRelease(ec_data);
	}
	
	/* 
	 * Get SignedData's certs if the caller wants them
	 */
	if(all_certs) {	    
	    ortn = CMSDecoderCopyAllCerts(decoder, &cf_all_certs);
	    if(ortn) {
		pkiCssmErr("CMSDecoderCopyAllCerts", ortn);
		krtn = KRB5_CRYPTO_INTERNAL;
		goto errOut;
	    }
	    krtn = pkiCertArrayToKrb5Data(cf_all_certs, num_all_certs, all_certs);
	    if(krtn) {
		goto errOut;
	    }
	}
	
	/* optional signer cert */
	if(signer_cert) {
	    SecCertificateRef sec_signer_cert = NULL;
	    CSSM_DATA cert_data;

	    ortn = CMSDecoderCopySignerCert(decoder, 0, &sec_signer_cert);
	    if(ortn) {
		/* should never happen if it's signed */
		pkiCssmErr("CMSDecoderCopySignerStatus", ortn);
		krtn = KRB5_CRYPTO_INTERNAL;
		goto errOut;
	    }
	    ortn = SecCertificateGetData(sec_signer_cert, &cert_data);
	    if(ortn) {
		pkiCssmErr("SecCertificateGetData", ortn);
		CFRelease(sec_signer_cert);
		krtn = KRB5_CRYPTO_INTERNAL;
		goto errOut;
	    }
	    krtn = pkiDataToKrb5Data(cert_data.Data, cert_data.Length, signer_cert);
	    CFRelease(sec_signer_cert);
	    if(krtn) {
		goto errOut;
	    }
	}
    }
    else {
	/* not signed */
	if(is_signed) {
	    *is_signed = FALSE;
	}
	if(inner_content_type) {
	    *inner_content_type = ECT_Other;
	}
	if(signer_cert) {
	    signer_cert->data = NULL;
	    signer_cert->length = 0;
	}
	if(signer_cert_status) {
	    *signer_cert_status = pki_not_signed;
	}
	if(num_all_certs) {
	    *num_all_certs = 0;
	}
	if(all_certs) {
	    *all_certs = NULL;
	}
    }
    if(is_encrypted) {
	Boolean bencr;
	ortn = CMSDecoderIsContentEncrypted(decoder, &bencr);
	if(ortn) {
	    pkiCssmErr("CMSDecoderCopySignerStatus", ortn);
	    krtn = KRB5_CRYPTO_INTERNAL;
	    goto errOut;
	}
	*is_encrypted = bencr ? TRUE : FALSE;
    }
    
    /* 
     * Verify signature and cert. The actual verify operation is optional,
     * per our signer_cert_status argument, but we do this anyway if we need
     * to get the signer cert.
     */
    if((signer_cert_status != NULL) || (signer_cert != NULL)) {
	
	ortn = CMSDecoderCopySignerStatus(decoder, 
	    0,					    /* signerIndex */
	    policy,
	    signer_cert_status ? TRUE : FALSE,	    /* evaluateSecTrust */
	    &signer_status,
	    NULL,				    /* secTrust - not needed */
	    &cert_verify_status);
	if(ortn) {
	    /* gross error - subsequent processing impossible */
	    pkiCssmErr("CMSDecoderCopySignerStatus", ortn);
	    krtn = KRB5_PARSE_MALFORMED;
	    goto errOut;
	}
    }
    /* obtain & return status */
    if(signer_cert_status) {
	*signer_cert_status = pkiInferSigStatus(signer_status, cert_verify_status);
    }
    
    /* finally, the payload */
    if(raw_data) {
	CFDataRef cf_content = NULL;
	
	ortn = CMSDecoderCopyContent(decoder, &cf_content);
	if(ortn) {
	    pkiCssmErr("CMSDecoderCopyContent", ortn);
	    krtn = KRB5_PARSE_MALFORMED;
	    goto errOut;
	}
	krtn = pkiCfDataToKrb5Data(cf_content, raw_data);
	CFRELEASE(cf_content);
    }
errOut:
    CFRELEASE(policy_search);
    CFRELEASE(policy);
    CFRELEASE(cf_all_certs);
    CFRELEASE(decoder);
    return krtn;
}

krb5_error_code krb5int_pkinit_get_cms_types(
    krb5int_algorithm_id    **supported_cms_types,	/* RETURNED */
    krb5_ui_4		    *num_supported_cms_types)	/* RETURNED */
{
    /* no preference */
    *supported_cms_types = NULL;
    *num_supported_cms_types = 0;
    return 0;
}

krb5_error_code krb5int_pkinit_free_cms_types(
    krb5int_algorithm_id    *supported_cms_types,
    krb5_ui_4		    num_supported_cms_types)
{
    /* 
     * We don't return anything from krb5int_pkinit_get_cms_types(), and
     * if we did, it would be a pointer to a statically declared array,
     * so this is a nop. 
     */
    return 0;
}

#endif /* APPLE_PKINIT */

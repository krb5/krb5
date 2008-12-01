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
 * pkinit_apple_asn1.c - ASN.1 encode/decode routines for PKINIT, Mac OS X version
 *
 * Created 19 May 2004 by Doug Mitchell.
 */

#if APPLE_PKINIT

#include "k5-int.h"
#include "pkinit_asn1.h"
#include "pkinit_apple_utils.h"
#include <stddef.h>
#include <Security/SecAsn1Types.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Coder.h>
#include <Security/Security.h>
#include <sys/errno.h>
#include <assert.h>
#include <strings.h>

#pragma mark ----- utility routines -----

/* malloc a NULL-ed array of pointers of size num+1 */
static void **pkiNssNullArray(
    uint32 num,
    SecAsn1CoderRef coder)
{
    unsigned len = (num + 1) * sizeof(void *);
    void **p = (void **)SecAsn1Malloc(coder, len);
    memset(p, 0, len);
    return p;
}

#pragma mark ====== begin PA-PK-AS-REQ components ======

#pragma mark ----- pkAuthenticator -----

/* 
 * There is a unique error code for "missing paChecksum", so we mark it here
 * as optional so the decoder can process a pkAuthenticator without the 
 * checksum; caller must verify that paChecksum.Data != NULL.
 */
typedef struct {
    CSSM_DATA       cusec;			/* INTEGER, microseconds */
    CSSM_DATA       kctime;			/* UTC time (with trailing 'Z') */
    CSSM_DATA       nonce;			/* INTEGER */
    CSSM_DATA	    paChecksum;			/* OCTET STRING */
} KRB5_PKAuthenticator;

static const SecAsn1Template KRB5_PKAuthenticatorTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_PKAuthenticator) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 0,
      offsetof(KRB5_PKAuthenticator,cusec), 
      kSecAsn1IntegerTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 1,
      offsetof(KRB5_PKAuthenticator,kctime), 
      kSecAsn1GeneralizedTimeTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 2,
      offsetof(KRB5_PKAuthenticator,nonce), 
      kSecAsn1IntegerTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 
	    SEC_ASN1_OPTIONAL | 3,
      offsetof(KRB5_PKAuthenticator,paChecksum), 
      &kSecAsn1OctetStringTemplate },
    { 0 }
};

#pragma mark ----- AuthPack -----

typedef struct {
    KRB5_PKAuthenticator		pkAuth;
    CSSM_X509_SUBJECT_PUBLIC_KEY_INFO   *pubKeyInfo;	    /* OPTIONAL */
    CSSM_X509_ALGORITHM_IDENTIFIER	**supportedCMSTypes;/* OPTIONAL */
    CSSM_DATA				*clientDHNonce;	    /* OPTIONAL */
} KRB5_AuthPack;

/* 
 * These are copied from keyTemplates.c in the libsecurity_asn1 project;
 * they aren't public API.
 */
 
/* AlgorithmIdentifier : CSSM_X509_ALGORITHM_IDENTIFIER */
static const SecAsn1Template AlgorithmIDTemplate[] = {
    { SEC_ASN1_SEQUENCE,
	  0, NULL, sizeof(CSSM_X509_ALGORITHM_IDENTIFIER) },
    { SEC_ASN1_OBJECT_ID,
	  offsetof(CSSM_X509_ALGORITHM_IDENTIFIER,algorithm), },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_ANY,
	  offsetof(CSSM_X509_ALGORITHM_IDENTIFIER,parameters), },
    { 0, }
};


/* SubjectPublicKeyInfo : CSSM_X509_SUBJECT_PUBLIC_KEY_INFO */
static const SecAsn1Template SubjectPublicKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
	  0, NULL, sizeof(CSSM_X509_SUBJECT_PUBLIC_KEY_INFO) },
    { SEC_ASN1_INLINE,
	  offsetof(CSSM_X509_SUBJECT_PUBLIC_KEY_INFO,algorithm),
	  AlgorithmIDTemplate },
    { SEC_ASN1_BIT_STRING,
	  offsetof(CSSM_X509_SUBJECT_PUBLIC_KEY_INFO,subjectPublicKey), },
    { 0, }
};

/* end of copied templates */

static const SecAsn1Template kSecAsn1SequenceOfAlgIdTemplate[] = {
    { SEC_ASN1_SEQUENCE_OF, 0, AlgorithmIDTemplate }
};

static const SecAsn1Template KRB5_AuthPackTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_AuthPack) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 0,
      offsetof(KRB5_AuthPack,pkAuth), 
      KRB5_PKAuthenticatorTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_OPTIONAL |
	SEC_ASN1_EXPLICIT | SEC_ASN1_POINTER | 1,
      offsetof(KRB5_AuthPack,pubKeyInfo), 
      SubjectPublicKeyInfoTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_OPTIONAL |
	SEC_ASN1_EXPLICIT | SEC_ASN1_POINTER | 2,
      offsetof(KRB5_AuthPack,supportedCMSTypes), 
      kSecAsn1SequenceOfAlgIdTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_OPTIONAL |
	SEC_ASN1_EXPLICIT | SEC_ASN1_POINTER | 3,
      offsetof(KRB5_AuthPack,clientDHNonce), 
      kSecAsn1OctetStringTemplate },
    { 0 }
};

/* 
 * Encode AuthPack, public key version (no Diffie-Hellman components).
 */
krb5_error_code krb5int_pkinit_auth_pack_encode(
    krb5_timestamp		kctime,      
    krb5_int32			cusec,		    /* microseconds */
    krb5_ui_4			nonce,
    const krb5_checksum		*pa_checksum,
    const krb5int_algorithm_id	*cms_types,	    /* optional */
    krb5_ui_4			num_cms_types,
    krb5_data			*auth_pack) /* mallocd and RETURNED */
{
    KRB5_AuthPack localAuthPack;
    SecAsn1CoderRef coder;
    CSSM_DATA *cksum = &localAuthPack.pkAuth.paChecksum;
    krb5_error_code ourRtn = 0;
    CSSM_DATA ber = {0, NULL};
    OSStatus ortn;
    char *timeStr = NULL;
    
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    memset(&localAuthPack, 0, sizeof(localAuthPack));
    if(pkiKrbTimestampToStr(kctime, &timeStr)) {
	ourRtn = -1;
	goto errOut;
    }
    localAuthPack.pkAuth.kctime.Data = (uint8 *)timeStr;
    localAuthPack.pkAuth.kctime.Length = strlen(timeStr);
    if(pkiIntToData(cusec, &localAuthPack.pkAuth.cusec, coder)) {
	ourRtn = ENOMEM;
	goto errOut;
    }
    if(pkiIntToData(nonce, &localAuthPack.pkAuth.nonce, coder)) {
	ourRtn = ENOMEM;
	goto errOut;
    }
    cksum->Data = (uint8 *)pa_checksum->contents;
    cksum->Length = pa_checksum->length;
    
    if((cms_types != NULL) && (num_cms_types != 0)) {
	unsigned dex;
	CSSM_X509_ALGORITHM_IDENTIFIER **algIds;
	
	/* build a NULL_terminated array of CSSM_X509_ALGORITHM_IDENTIFIERs */
	localAuthPack.supportedCMSTypes = (CSSM_X509_ALGORITHM_IDENTIFIER **)
	    SecAsn1Malloc(coder,
		(num_cms_types + 1) * sizeof(CSSM_X509_ALGORITHM_IDENTIFIER *));
	algIds = localAuthPack.supportedCMSTypes;
	for(dex=0; dex<num_cms_types; dex++) {
	    algIds[dex] = (CSSM_X509_ALGORITHM_IDENTIFIER *)
		SecAsn1Malloc(coder, sizeof(CSSM_X509_ALGORITHM_IDENTIFIER));
	    pkiKrb5DataToCssm(&cms_types[dex].algorithm, 
		&algIds[dex]->algorithm, coder);
	    if(cms_types[dex].parameters.data != NULL) {
		pkiKrb5DataToCssm(&cms_types[dex].parameters, 
		    &algIds[dex]->parameters, coder);
	    }
	    else {
		algIds[dex]->parameters.Data = NULL;
		algIds[dex]->parameters.Length = 0;
	    }
	}
	algIds[num_cms_types] = NULL;
    }
    ortn = SecAsn1EncodeItem(coder, &localAuthPack, KRB5_AuthPackTemplate, &ber);
    if(ortn) {
	ourRtn = ENOMEM;
	goto errOut;
    }
    
    if(pkiCssmDataToKrb5Data(&ber, auth_pack)) {
	ourRtn = ENOMEM;
    }
    else {
	auth_pack->magic = KV5M_AUTHENTICATOR;
	ourRtn = 0;
    }
errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}

/*
 * Decode AuthPack, public key version (no Diffie-Hellman components).
 */
krb5_error_code krb5int_pkinit_auth_pack_decode(
    const krb5_data	*auth_pack,     /* DER encoded */
    krb5_timestamp      *kctime,	/* RETURNED */
    krb5_ui_4		*cusec,		/* microseconds, RETURNED */
    krb5_ui_4		*nonce,		/* RETURNED */
    krb5_checksum       *pa_checksum,	/* contents mallocd and RETURNED */
    krb5int_algorithm_id **cms_types,	/* optionally mallocd and RETURNED */
    krb5_ui_4		*num_cms_types)	/* optionally RETURNED */
{
    KRB5_AuthPack localAuthPack;
    SecAsn1CoderRef coder;
    CSSM_DATA der = {0, NULL};
    krb5_error_code ourRtn = 0;
    CSSM_DATA *cksum = &localAuthPack.pkAuth.paChecksum;
    
    /* Decode --> localAuthPack */
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    PKI_KRB_TO_CSSM_DATA(auth_pack, &der);
    memset(&localAuthPack, 0, sizeof(localAuthPack));
    if(SecAsn1DecodeData(coder, &der, KRB5_AuthPackTemplate, &localAuthPack)) {
	ourRtn = ASN1_BAD_FORMAT;
	goto errOut;
    }
    
    /* optionally Convert KRB5_AuthPack to caller's params */
    if(kctime) {
	if((ourRtn = pkiTimeStrToKrbTimestamp((char *)localAuthPack.pkAuth.kctime.Data,
		localAuthPack.pkAuth.kctime.Length, kctime))) {
	    goto errOut;
	}
    }
    if(cusec) {
	if((ourRtn = pkiDataToInt(&localAuthPack.pkAuth.cusec, (krb5_int32 *)cusec))) {
	    goto errOut;
	}
    }
    if(nonce) {
	if((ourRtn = pkiDataToInt(&localAuthPack.pkAuth.nonce, (krb5_int32 *)nonce))) {
	    goto errOut;
	}
    }
    if(pa_checksum) {
	if(cksum->Length == 0) {
	    /* This is the unique error for "no paChecksum" */
	    ourRtn = KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED;
	    goto errOut;
	}
	else {
	    pa_checksum->contents = (krb5_octet *)malloc(cksum->Length);
	    if(pa_checksum->contents == NULL) {
		ourRtn = ENOMEM;
		goto errOut;
	    }
	    pa_checksum->length = cksum->Length;
	    memmove(pa_checksum->contents, cksum->Data, pa_checksum->length);
	    pa_checksum->magic = KV5M_CHECKSUM;
	    /* This used to be encoded with the checksum but no more... */
	    pa_checksum->checksum_type = CKSUMTYPE_NIST_SHA;
	}
    }
    if(cms_types) {
	if(localAuthPack.supportedCMSTypes == NULL) {
	    *cms_types = NULL;
	    *num_cms_types = 0;
	}
	else {
	    /*
	     * Convert NULL-terminated array of CSSM-style algIds to
	     * krb5int_algorithm_ids.
	     */
	    unsigned dex;
	    unsigned num_types = 0;
	    CSSM_X509_ALGORITHM_IDENTIFIER **alg_ids;
	    krb5int_algorithm_id *kalg_ids;
	     
	    for(alg_ids=localAuthPack.supportedCMSTypes;
	        *alg_ids;
		alg_ids++) {
		num_types++;
	    }
	    *cms_types = kalg_ids = (krb5int_algorithm_id *)calloc(num_types,
		sizeof(krb5int_algorithm_id));
	    *num_cms_types = num_types;
	    alg_ids = localAuthPack.supportedCMSTypes;
	    for(dex=0; dex<num_types; dex++) {
		if(alg_ids[dex]->algorithm.Data) {
		    pkiCssmDataToKrb5Data(&alg_ids[dex]->algorithm, 
			&kalg_ids[dex].algorithm);
		}
		if(alg_ids[dex]->parameters.Data) {
		    pkiCssmDataToKrb5Data(&alg_ids[dex]->parameters, 
			&kalg_ids[dex].parameters);
		}
	    }
	}
    }
    ourRtn = 0;
errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}

#pragma mark ----- IssuerAndSerialNumber -----

/*
 * Issuer/serial number - specify issuer as ASN_ANY because we can get it from
 * CL in DER-encoded state.
 */
typedef struct {
    CSSM_DATA		    derIssuer;
    CSSM_DATA		    serialNumber;
} KRB5_IssuerAndSerial;

static const SecAsn1Template KRB5_IssuerAndSerialTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_IssuerAndSerial) },
    { SEC_ASN1_ANY, offsetof(KRB5_IssuerAndSerial, derIssuer) },
    { SEC_ASN1_INTEGER, offsetof(KRB5_IssuerAndSerial, serialNumber) },
    { 0 }
};

/*
 * Given DER-encoded issuer and serial number, create an encoded 
 * IssuerAndSerialNumber.
 */
krb5_error_code krb5int_pkinit_issuer_serial_encode(
    const krb5_data *issuer,		    /* DER encoded */
    const krb5_data *serial_num,
    krb5_data       *issuer_and_serial)     /* content mallocd and RETURNED */
{
    KRB5_IssuerAndSerial issuerSerial;
    SecAsn1CoderRef coder;
    CSSM_DATA ber = {0, NULL};
    OSStatus ortn;

    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    PKI_KRB_TO_CSSM_DATA(issuer, &issuerSerial.derIssuer);
    PKI_KRB_TO_CSSM_DATA(serial_num, &issuerSerial.serialNumber);
    ortn = SecAsn1EncodeItem(coder, &issuerSerial, KRB5_IssuerAndSerialTemplate, &ber);
    if(ortn) {
	ortn = ENOMEM;
	goto errOut;
    }
    ortn = pkiCssmDataToKrb5Data(&ber, issuer_and_serial);
errOut:
    SecAsn1CoderRelease(coder);
    return ortn;
}

/*
 * Decode IssuerAndSerialNumber.
 */
krb5_error_code krb5int_pkinit_issuer_serial_decode(
    const krb5_data *issuer_and_serial,     /* DER encoded */
    krb5_data       *issuer,		    /* DER encoded, RETURNED */
    krb5_data       *serial_num)	    /* RETURNED */
{
    KRB5_IssuerAndSerial issuerSerial;
    SecAsn1CoderRef coder;
    CSSM_DATA der = {issuer_and_serial->length, (uint8 *)issuer_and_serial->data};
    krb5_error_code ourRtn = 0;
    
    /* Decode --> issuerSerial */
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    memset(&issuerSerial, 0, sizeof(issuerSerial));
    if(SecAsn1DecodeData(coder, &der, KRB5_IssuerAndSerialTemplate, &issuerSerial)) {
	ourRtn = ASN1_BAD_FORMAT;
	goto errOut;
    }
    
    /* Convert KRB5_IssuerAndSerial to caller's params */
    if((ourRtn = pkiCssmDataToKrb5Data(&issuerSerial.derIssuer, issuer))) {
	goto errOut;
    }
    if((ourRtn = pkiCssmDataToKrb5Data(&issuerSerial.serialNumber, serial_num))) {
	ourRtn = ENOMEM;
	goto errOut;
    }

errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}

#pragma mark ----- ExternalPrincipalIdentifier -----

/* 
 * Shown here for completeness; this module only implements the 
 * issuerAndSerialNumber option. 
 */
typedef struct {
    CSSM_DATA	    subjectName;	    /* [0] IMPLICIT OCTET STRING OPTIONAL */
					    /* contents = encoded Name */
    CSSM_DATA	    issuerAndSerialNumber;  /* [1] IMPLICIT OCTET STRING OPTIONAL */
					    /* contents = encoded Issuer&Serial */
    CSSM_DATA	    subjectKeyIdentifier;   /* [2] IMPLICIT OCTET STRING OPTIONAL */
					    /* contents = encoded subjectKeyIdentifier extension */
} KRB5_ExternalPrincipalIdentifier;

static const SecAsn1Template KRB5_ExternalPrincipalIdentifierTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_ExternalPrincipalIdentifier) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_OPTIONAL | 0,
      offsetof(KRB5_ExternalPrincipalIdentifier, subjectName), 
      kSecAsn1OctetStringTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_OPTIONAL | 1,
      offsetof(KRB5_ExternalPrincipalIdentifier, issuerAndSerialNumber), 
      kSecAsn1OctetStringTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_OPTIONAL | 2,
      offsetof(KRB5_ExternalPrincipalIdentifier, subjectKeyIdentifier), 
      kSecAsn1OctetStringTemplate },
    { 0 }
};

static const SecAsn1Template KRB5_SequenceOfExternalPrincipalIdentifierTemplate[] = {
    { SEC_ASN1_SEQUENCE_OF, 0, KRB5_ExternalPrincipalIdentifierTemplate }
};

#pragma mark ----- PA-PK-AS-REQ -----

/*
 * Top-level PA-PK-AS-REQ. All fields except for trusted_CAs are pre-encoded 
 * before we encode this and are still DER-encoded after we decode. 
 * The signedAuthPack and kdcPkId fields are wrapped in OCTET STRINGs
 * during encode; we strip off the OCTET STRING wrappers during decode. 
 */
typedef struct {
    CSSM_DATA		    signedAuthPack;	    /* ContentInfo, SignedData */
						    /* Content is KRB5_AuthPack */
    KRB5_ExternalPrincipalIdentifier
			    **trusted_CAs;	    /* optional */
    CSSM_DATA		    kdcPkId;		    /* optional */
} KRB5_PA_PK_AS_REQ;

static const SecAsn1Template KRB5_PA_PK_AS_REQTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_PA_PK_AS_REQ) },
    { SEC_ASN1_CONTEXT_SPECIFIC | 0,
      offsetof(KRB5_PA_PK_AS_REQ, signedAuthPack), 
      kSecAsn1OctetStringTemplate },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 
      SEC_ASN1_EXPLICIT | 1,
      offsetof(KRB5_PA_PK_AS_REQ, trusted_CAs), 
      KRB5_SequenceOfExternalPrincipalIdentifierTemplate },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONTEXT_SPECIFIC | 2,
      offsetof(KRB5_PA_PK_AS_REQ, kdcPkId), 
      kSecAsn1AnyTemplate },
    { 0 }
};

/*
 * Top-level encode for PA-PK-AS-REQ.
 */
krb5_error_code krb5int_pkinit_pa_pk_as_req_encode(
    const krb5_data *signed_auth_pack,      /* DER encoded ContentInfo */
    const krb5_data *trusted_CAs,	    /* optional: trustedCertifiers. Contents are
					     * DER-encoded issuer/serialNumbers. */
    krb5_ui_4	    num_trusted_CAs,
    const krb5_data *kdc_cert,		    /* optional kdcPkId, DER encoded issuer/serial */
    krb5_data	    *pa_pk_as_req)	    /* mallocd and RETURNED */
{
    KRB5_PA_PK_AS_REQ req;
    SecAsn1CoderRef coder;
    CSSM_DATA ber = {0, NULL};
    OSStatus ortn;
    unsigned dex;
    
    assert(signed_auth_pack != NULL);
    assert(pa_pk_as_req != NULL);

    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    
    /* krb5_data ==> CSSM format */
    
    memset(&req, 0, sizeof(req));
    PKI_KRB_TO_CSSM_DATA(signed_auth_pack, &req.signedAuthPack);
    if(num_trusted_CAs) {
	/* 
	 * Set up a NULL-terminated array of KRB5_ExternalPrincipalIdentifier
	 * pointers. We malloc the actual KRB5_ExternalPrincipalIdentifiers as 
	 * a contiguous array; it's in temp SecAsn1CoderRef memory. The referents 
	 * are just dropped in from the caller's krb5_datas. 
	 */
	KRB5_ExternalPrincipalIdentifier *cas = 
	    (KRB5_ExternalPrincipalIdentifier *)SecAsn1Malloc(coder, 
		num_trusted_CAs * sizeof(KRB5_ExternalPrincipalIdentifier));
	req.trusted_CAs = 
	    (KRB5_ExternalPrincipalIdentifier **)
		pkiNssNullArray(num_trusted_CAs, coder);
	for(dex=0; dex<num_trusted_CAs; dex++) {
	    req.trusted_CAs[dex] = &cas[dex];
	    memset(&cas[dex], 0, sizeof(KRB5_ExternalPrincipalIdentifier));
	    PKI_KRB_TO_CSSM_DATA(&trusted_CAs[dex], 
		&cas[dex].issuerAndSerialNumber);
	}
    }
    if(kdc_cert) {
	PKI_KRB_TO_CSSM_DATA(kdc_cert, &req.kdcPkId);
    }
    
    /* encode */
    ortn = SecAsn1EncodeItem(coder, &req, KRB5_PA_PK_AS_REQTemplate, &ber);
    if(ortn) {
	ortn = ENOMEM;
	goto errOut;
    }
    ortn = pkiCssmDataToKrb5Data(&ber, pa_pk_as_req);

errOut:
    SecAsn1CoderRelease(coder);
    return ortn;
}
    
/*
 * Top-level decode for PA-PK-AS-REQ.
 */
krb5_error_code krb5int_pkinit_pa_pk_as_req_decode(
    const krb5_data *pa_pk_as_req,
    krb5_data *signed_auth_pack,	    /* DER encoded ContentInfo, RETURNED */
    /* 
     * Remainder are optionally RETURNED (specify NULL for pointers to 
     * items you're not interested in).
     */
    krb5_ui_4 *num_trusted_CAs,     /* sizeof trusted_CAs */
    krb5_data **trusted_CAs,	    /* mallocd array of DER-encoded TrustedCAs issuer/serial */
    krb5_data *kdc_cert)	    /* DER encoded issuer/serial */
{
    KRB5_PA_PK_AS_REQ asReq;
    SecAsn1CoderRef coder;
    CSSM_DATA der;
    krb5_error_code ourRtn = 0;
    
    assert(pa_pk_as_req != NULL);
    
    /* Decode --> KRB5_PA_PK_AS_REQ */
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    PKI_KRB_TO_CSSM_DATA(pa_pk_as_req, &der);
    memset(&asReq, 0, sizeof(asReq));
    if(SecAsn1DecodeData(coder, &der, KRB5_PA_PK_AS_REQTemplate, &asReq)) {
	ourRtn = ASN1_BAD_FORMAT;
	goto errOut;
    }

    /* Convert decoded results to caller's args; each is optional */
    if(signed_auth_pack != NULL) {
	if((ourRtn = pkiCssmDataToKrb5Data(&asReq.signedAuthPack, signed_auth_pack))) {
	    goto errOut;
	}
    }
    if(asReq.trusted_CAs && (trusted_CAs != NULL)) {
	/* NULL-terminated array of CSSM_DATA ptrs */
	unsigned numCas = pkiNssArraySize((const void **)asReq.trusted_CAs);
	unsigned dex;
	krb5_data *kdcCas;
	
	kdcCas = (krb5_data *)malloc(sizeof(krb5_data) * numCas);
	if(kdcCas == NULL) {
	    ourRtn = ENOMEM;
	    goto errOut;
	}
	for(dex=0; dex<numCas; dex++) {
	    KRB5_ExternalPrincipalIdentifier *epi = asReq.trusted_CAs[dex];
	    if(epi->issuerAndSerialNumber.Data) {
		/* the only variant we support */
		pkiCssmDataToKrb5Data(&epi->issuerAndSerialNumber, &kdcCas[dex]);
	    }
	}
	*trusted_CAs = kdcCas;
	*num_trusted_CAs = numCas;
    }
    if(asReq.kdcPkId.Data && kdc_cert) {
	if((ourRtn = pkiCssmDataToKrb5Data(&asReq.kdcPkId, kdc_cert))) {
	    goto errOut;
	}
    }
errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;   
}

#pragma mark ====== begin PA-PK-AS-REP components ======

typedef struct {
    CSSM_DATA       subjectPublicKey;       /* BIT STRING */
    CSSM_DATA       nonce;		    /* from KRB5_PKAuthenticator.nonce */
    CSSM_DATA       *expiration;	    /* optional UTC time */
} KRB5_KDC_DHKeyInfo;

typedef struct {
    CSSM_DATA		keyType;
    CSSM_DATA		keyValue;
} KRB5_EncryptionKey;

static const SecAsn1Template KRB5_EncryptionKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_EncryptionKey) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 0,
      offsetof(KRB5_EncryptionKey, keyType), 
      kSecAsn1IntegerTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 1,
      offsetof(KRB5_EncryptionKey, keyValue), 
      kSecAsn1OctetStringTemplate },
    { 0 }
};

#pragma mark ----- Checksum -----
 
typedef struct {
    CSSM_DATA   checksumType;
    CSSM_DATA   checksum;
} KRB5_Checksum;

static const SecAsn1Template KRB5_ChecksumTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_Checksum) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 0,
      offsetof(KRB5_Checksum,checksumType), 
      kSecAsn1IntegerTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 1,
      offsetof(KRB5_Checksum,checksum), 
      kSecAsn1OctetStringTemplate },
    { 0 }
};

typedef struct {
    KRB5_EncryptionKey  encryptionKey;
    KRB5_Checksum	asChecksum;
} KRB5_ReplyKeyPack;

static const SecAsn1Template KRB5_ReplyKeyPackTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_ReplyKeyPack) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 0,
      offsetof(KRB5_ReplyKeyPack, encryptionKey), 
      KRB5_EncryptionKeyTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | 1,
      offsetof(KRB5_ReplyKeyPack,asChecksum), 
      KRB5_ChecksumTemplate },
    { 0 }
};

/* 
 * Encode a ReplyKeyPack. The result is used as the Content of a SignedData.
 */
krb5_error_code krb5int_pkinit_reply_key_pack_encode(
    const krb5_keyblock *key_block,
    const krb5_checksum *checksum,
    krb5_data		*reply_key_pack)      /* mallocd and RETURNED */
{
    KRB5_ReplyKeyPack repKeyPack;
    SecAsn1CoderRef coder;
    krb5_error_code ourRtn = 0;
    CSSM_DATA der = {0, NULL};
    OSStatus ortn;
    KRB5_EncryptionKey *encryptKey = &repKeyPack.encryptionKey;
    KRB5_Checksum *cksum = &repKeyPack.asChecksum;
    
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    memset(&repKeyPack, 0, sizeof(repKeyPack));
    
    if((ourRtn = pkiIntToData(key_block->enctype, &encryptKey->keyType, coder))) {
	goto errOut;
    }
    encryptKey->keyValue.Length = key_block->length,
    encryptKey->keyValue.Data = (uint8 *)key_block->contents;
    
    if((ourRtn = pkiIntToData(checksum->checksum_type, &cksum->checksumType, coder))) {
	goto errOut;
    }
    cksum->checksum.Data = (uint8 *)checksum->contents;
    cksum->checksum.Length = checksum->length;

    ortn = SecAsn1EncodeItem(coder, &repKeyPack, KRB5_ReplyKeyPackTemplate, &der);
    if(ortn) {
	ourRtn = ENOMEM;
	goto errOut;
    }
    ourRtn = pkiCssmDataToKrb5Data(&der, reply_key_pack);
errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}

/* 
 * Decode a ReplyKeyPack.
 */
krb5_error_code krb5int_pkinit_reply_key_pack_decode(
    const krb5_data	*reply_key_pack,
    krb5_keyblock       *key_block,     /* RETURNED */
    krb5_checksum	*checksum)	/* contents mallocd and RETURNED */
{
    KRB5_ReplyKeyPack repKeyPack;
    SecAsn1CoderRef coder;
    krb5_error_code ourRtn = 0;
    KRB5_EncryptionKey *encryptKey = &repKeyPack.encryptionKey;
    CSSM_DATA der = {reply_key_pack->length, (uint8 *)reply_key_pack->data};
    krb5_data tmpData;
    KRB5_Checksum *cksum = &repKeyPack.asChecksum;
    
    /* Decode --> KRB5_ReplyKeyPack */
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    memset(&repKeyPack, 0, sizeof(repKeyPack));
    if(SecAsn1DecodeData(coder, &der, KRB5_ReplyKeyPackTemplate, &repKeyPack)) {
	ourRtn = ASN1_BAD_FORMAT;
	goto errOut;
    }
    
    if((ourRtn = pkiDataToInt(&encryptKey->keyType, (krb5_int32 *)&key_block->enctype))) {
	goto errOut;
    }
    if((ourRtn = pkiCssmDataToKrb5Data(&encryptKey->keyValue, &tmpData))) {
	goto errOut;
    }
    key_block->contents = (krb5_octet *)tmpData.data;
    key_block->length = tmpData.length;
    
    if((ourRtn = pkiDataToInt(&cksum->checksumType, &checksum->checksum_type))) {
	goto errOut;
    }
    checksum->contents = (krb5_octet *)malloc(cksum->checksum.Length);
    if(checksum->contents == NULL) {
	ourRtn = ENOMEM;
	goto errOut;
    }
    checksum->length = cksum->checksum.Length;
    memmove(checksum->contents, cksum->checksum.Data, checksum->length);
    checksum->magic = KV5M_CHECKSUM;

errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}


#pragma mark ----- KRB5_PA_PK_AS_REP -----
/*
 * Top-level PA-PK-AS-REP. Exactly one of the optional fields must be present.
 */
typedef struct {
    CSSM_DATA	*dhSignedData;      /* ContentInfo, SignedData */
				    /* Content is KRB5_KDC_DHKeyInfo */
    CSSM_DATA	*encKeyPack;	    /* ContentInfo, SignedData */
				    /* Content is ReplyKeyPack */
} KRB5_PA_PK_AS_REP;
    
static const SecAsn1Template KRB5_PA_PK_AS_REPTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(KRB5_PA_PK_AS_REP) },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_OPTIONAL |
      SEC_ASN1_EXPLICIT | 0,
      offsetof(KRB5_PA_PK_AS_REP, dhSignedData), 
      kSecAsn1PointerToAnyTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_CONSTRUCTED | SEC_ASN1_OPTIONAL |
      SEC_ASN1_EXPLICIT | 1,
      offsetof(KRB5_PA_PK_AS_REP, encKeyPack), 
      kSecAsn1PointerToAnyTemplate },
    { 0 }
};

/* 
 * Encode a KRB5_PA_PK_AS_REP.
 */
krb5_error_code krb5int_pkinit_pa_pk_as_rep_encode(
    const krb5_data *dh_signed_data, 
    const krb5_data *enc_key_pack, 
    krb5_data       *pa_pk_as_rep)      /* mallocd and RETURNED */
{
    KRB5_PA_PK_AS_REP asRep;
    SecAsn1CoderRef coder;
    krb5_error_code ourRtn = 0;
    CSSM_DATA	    der = {0, NULL};
    OSStatus	    ortn;
    CSSM_DATA	    dhSignedData;
    CSSM_DATA	    encKeyPack;
    
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    memset(&asRep, 0, sizeof(asRep));
    if(dh_signed_data) {
	PKI_KRB_TO_CSSM_DATA(dh_signed_data, &dhSignedData);
	asRep.dhSignedData = &dhSignedData;
    }
    if(enc_key_pack) {
	PKI_KRB_TO_CSSM_DATA(enc_key_pack, &encKeyPack);
	asRep.encKeyPack = &encKeyPack;
    }

    ortn = SecAsn1EncodeItem(coder, &asRep, KRB5_PA_PK_AS_REPTemplate, &der);
    if(ortn) {
	ourRtn = ENOMEM;
	goto errOut;
    }
    ourRtn = pkiCssmDataToKrb5Data(&der, pa_pk_as_rep);

errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}

/* 
 * Decode a KRB5_PA_PK_AS_REP.
 */
krb5_error_code krb5int_pkinit_pa_pk_as_rep_decode(
    const krb5_data *pa_pk_as_rep,
    krb5_data *dh_signed_data, 
    krb5_data *enc_key_pack)
{
    KRB5_PA_PK_AS_REP asRep;
    SecAsn1CoderRef coder;
    CSSM_DATA der = {pa_pk_as_rep->length, (uint8 *)pa_pk_as_rep->data};
    krb5_error_code ourRtn = 0;
    
    /* Decode --> KRB5_PA_PK_AS_REP */
    if(SecAsn1CoderCreate(&coder)) {
	return ENOMEM;
    }
    memset(&asRep, 0, sizeof(asRep));
    if(SecAsn1DecodeData(coder, &der, KRB5_PA_PK_AS_REPTemplate, &asRep)) {
	ourRtn = ASN1_BAD_FORMAT;
	goto errOut;
    }
    
    if(asRep.dhSignedData) {
	if((ourRtn = pkiCssmDataToKrb5Data(asRep.dhSignedData, dh_signed_data))) {
	    goto errOut;
	}
    }
    if(asRep.encKeyPack) {
	ourRtn = pkiCssmDataToKrb5Data(asRep.encKeyPack, enc_key_pack);
    }
    
errOut:
    SecAsn1CoderRelease(coder);
    return ourRtn;
}

#pragma mark ====== General utilities ======

/*
 * Given a DER encoded certificate, obtain the associated IssuerAndSerialNumber.
 */
krb5_error_code krb5int_pkinit_get_issuer_serial(
    const krb5_data *cert,
    krb5_data       *issuer_and_serial)
{
    CSSM_HANDLE cacheHand = 0;
    CSSM_RETURN crtn = CSSM_OK;
    CSSM_DATA certData = { cert->length, (uint8 *)cert->data };
    CSSM_HANDLE resultHand = 0;
    CSSM_DATA_PTR derIssuer = NULL;
    CSSM_DATA_PTR serial;
    krb5_data krb_serial;
    krb5_data krb_issuer;
    uint32 numFields;
    krb5_error_code ourRtn = 0;
    
    CSSM_CL_HANDLE clHand = pkiClStartup();
    if(clHand == 0) {
	return CSSMERR_CSSM_ADDIN_LOAD_FAILED;
    }
    /* subsequent errors to errOut: */
    
    crtn = CSSM_CL_CertCache(clHand, &certData, &cacheHand);
    if(crtn) {
	pkiCssmErr("CSSM_CL_CertCache", crtn);
	ourRtn = ASN1_PARSE_ERROR;
	goto errOut;
    }
    
    /* obtain the two fields; issuer is DER encoded */
    crtn = CSSM_CL_CertGetFirstCachedFieldValue(clHand, cacheHand,
	&CSSMOID_X509V1IssuerNameStd, &resultHand, &numFields, &derIssuer);
    if(crtn) {
	pkiCssmErr("CSSM_CL_CertGetFirstCachedFieldValue(issuer)", crtn);
	ourRtn = ASN1_PARSE_ERROR;
	goto errOut;
    }
    crtn = CSSM_CL_CertGetFirstCachedFieldValue(clHand, cacheHand,
	&CSSMOID_X509V1SerialNumber, &resultHand, &numFields, &serial);
    if(crtn) {
	pkiCssmErr("CSSM_CL_CertGetFirstCachedFieldValue(serial)", crtn);
	ourRtn = ASN1_PARSE_ERROR;
	goto errOut;
    }
    PKI_CSSM_TO_KRB_DATA(derIssuer, &krb_issuer);
    PKI_CSSM_TO_KRB_DATA(serial, &krb_serial);
    ourRtn = krb5int_pkinit_issuer_serial_encode(&krb_issuer, &krb_serial, issuer_and_serial);
    
errOut:
    if(derIssuer) {
	CSSM_CL_FreeFieldValue(clHand, &CSSMOID_X509V1IssuerNameStd, derIssuer);
    }
    if(serial) {
	CSSM_CL_FreeFieldValue(clHand, &CSSMOID_X509V1SerialNumber, serial);
    }
    if(cacheHand) {
	CSSM_CL_CertAbortCache(clHand, cacheHand);
    }
    if(clHand) {
	pkiClDetachUnload(clHand);
    }
    return ourRtn;
}

#endif /* APPLE_PKINIT */

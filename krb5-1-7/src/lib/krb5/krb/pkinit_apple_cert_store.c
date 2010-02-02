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
 * pkinit_apple_cert_store.c - PKINIT certificate storage/retrieval utilities, 
 *			       MAC OS X version
 *
 * Created 26 May 2004 by Doug Mitchell at Apple.
 */
 
#if APPLE_PKINIT

#include "pkinit_cert_store.h"
#include "pkinit_asn1.h"
#include "pkinit_apple_utils.h"
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <assert.h>
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/errno.h>

/*
 * Client cert info is stored in preferences with this following parameters:
 *
 * key      = kPkinitClientCertKey
 * appID    = kPkinitClientCertApp
 * username = kCFPreferencesCurrentUser
 * hostname = kCFPreferencesAnyHost   
 *
 * The stored property list is a CFDictionary. Keys in the dictionary are
 * principal names (e.g. foobar@REALM.LOCAL). 
 *
 * Values in the dictionary are raw data containing the DER-encoded issuer and
 * serial number of the certificate. 
 *
 * When obtaining a PKINIT cert, if an entry in the CFDictionary for the specified
 * principal is not found, the entry for the default will be used if it's there.
 */

/* 
 * NOTE: ANSI C code requires an Apple-Custom -fconstant-cfstrings CFLAGS to 
 * use CFSTR in a const declaration so we just declare the C strings here. 
 */
#define kPkinitClientCertKey		"KRBClientCert"
#define kPkinitClientCertApp		"edu.mit.Kerberos.pkinit"

/*
 * KDC cert stored in this keychain. It's linked to systemkeychain so that if
 * a root process tries to unlock it, it auto-unlocks.
 */
#define KDC_KEYCHAIN    "/var/db/krb5kdc/kdc.keychain"

/* 
 * Given a certificate, obtain the DER-encoded issuer and serial number. Result
 * is mallocd and must be freed by caller. 
 */
static OSStatus pkinit_get_cert_issuer_sn(
    SecCertificateRef certRef, 
    CSSM_DATA *issuerSerial)		/* mallocd and RETURNED */
{
    OSStatus ortn;
    CSSM_DATA certData;
    krb5_data INIT_KDATA(issuerSerialKrb);
    krb5_data certDataKrb;
    krb5_error_code krtn;
    
    assert(certRef != NULL);
    assert(issuerSerial != NULL);
    
    ortn = SecCertificateGetData(certRef, &certData);
    if(ortn) {
	pkiCssmErr("SecCertificateGetData", ortn);
	return ortn;
    }
    PKI_CSSM_TO_KRB_DATA(&certData, &certDataKrb);
    krtn = krb5int_pkinit_get_issuer_serial(&certDataKrb, &issuerSerialKrb);
    if(krtn) {
	return CSSMERR_CL_INVALID_DATA;
    }
    PKI_KRB_TO_CSSM_DATA(&issuerSerialKrb, issuerSerial);
    return noErr;
}

/* 
 * Determine if specified identity's cert's issuer and serial number match the
 * provided issuer and serial number. Returns nonzero on match, else returns zero.
 */
static int pkinit_issuer_sn_match(
    SecIdentityRef idRef, 
    const CSSM_DATA *matchIssuerSerial)
{
    OSStatus ortn;
    SecCertificateRef certRef = NULL;
    CSSM_DATA INIT_CDATA(certIssuerSerial);
    int ourRtn = 0;

    assert(idRef != NULL);
    assert(matchIssuerSerial != NULL);
    
    /* Get this cert's issuer/serial number */
    ortn = SecIdentityCopyCertificate(idRef, &certRef);
    if(ortn) {
	pkiCssmErr("SecIdentityCopyCertificate", ortn);
	return 0;
    }
    /* subsequent errors to errOut: */
    ortn = pkinit_get_cert_issuer_sn(certRef, &certIssuerSerial);
    if(ortn) {
	pkiCssmErr("SecIdentityCopyCertificate", ortn);
	goto errOut;
    }
    ourRtn = pkiCompareCssmData(matchIssuerSerial, &certIssuerSerial) ? 1 : 0;
errOut:
    if(certRef != NULL) {
	CFRelease(certRef);
    }
    if(certIssuerSerial.Data != NULL) {
	free(certIssuerSerial.Data);
    }
    return ourRtn;
}

/*
 * Search specified keychain/array/NULL (NULL meaning the default search list) for
 * an Identity matching specified key usage and optional Issuer/Serial number. 
 * If issuer/serial is specified and no identities match, or if no identities found
 * matching specified Key usage, errSecItemNotFound is returned.
 *
 * Caller must CFRelease a non-NULL returned idRef. 
 */
static OSStatus pkinit_search_ident(
    CFTypeRef		keychainOrArray,
    CSSM_KEYUSE		keyUsage,
    const CSSM_DATA     *issuerSerial,  /* optional */
    SecIdentityRef      *foundId)	/* RETURNED */
{
    OSStatus ortn;
    SecIdentityRef idRef = NULL;
    SecIdentitySearchRef srchRef = NULL;
    
    ortn = SecIdentitySearchCreate(keychainOrArray, keyUsage, &srchRef);
    if(ortn) {
	pkiCssmErr("SecIdentitySearchCreate", ortn);
	return ortn;
    }
    do {
	ortn = SecIdentitySearchCopyNext(srchRef, &idRef);
	if(ortn != noErr) {
	    break;
	}
	if(issuerSerial == NULL) {
	    /* no match needed, we're done - this is the KDC cert case */
	    break;
	}
	else if(pkinit_issuer_sn_match(idRef, issuerSerial)) {
	    /* match, we're done */
	    break;
	}
	/* finished with this one */
	CFRelease(idRef);
	idRef = NULL;
    } while(ortn == noErr);
    
    CFRelease(srchRef);
    if(idRef == NULL) {
	return errSecItemNotFound;
    }
    else {
	*foundId = idRef;
	return noErr;
    }
}

/*
 * In Mac OS terms, get the keychain on which a given identity resides. 
 */
static krb5_error_code pkinit_cert_to_db(
    krb5_pkinit_signing_cert_t   idRef,
    krb5_pkinit_cert_db_t	 *dbRef)
{
    SecKeychainRef kcRef = NULL;
    SecKeyRef keyRef = NULL;
    OSStatus ortn;

    /* that's an identity - get the associated key's keychain */
    ortn = SecIdentityCopyPrivateKey((SecIdentityRef)idRef, &keyRef);
    if(ortn) {
	pkiCssmErr("SecIdentityCopyPrivateKey", ortn);
	return ortn;
    }
    ortn = SecKeychainItemCopyKeychain((SecKeychainItemRef)keyRef, &kcRef);
    if(ortn) {
	pkiCssmErr("SecKeychainItemCopyKeychain", ortn);
    }
    else {
	*dbRef = (krb5_pkinit_cert_db_t)kcRef;
    }
    CFRelease(keyRef);
    return ortn;
}

/* 
 * Obtain the CFDictionary representing this user's PKINIT client cert prefs, if it 
 * exists. Returns noErr or errSecItemNotFound as appropriate. 
 */
static OSStatus pkinit_get_pref_dict(
    CFDictionaryRef *dict)
{
    CFDictionaryRef theDict;
    theDict = (CFDictionaryRef)CFPreferencesCopyValue(CFSTR(kPkinitClientCertKey),
	CFSTR(kPkinitClientCertApp), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if(theDict == NULL) {
	pkiDebug("pkinit_get_pref_dict: no kPkinitClientCertKey\n");
	return errSecItemNotFound;
    }
    if(CFGetTypeID(theDict) != CFDictionaryGetTypeID()) {
	pkiDebug("pkinit_get_pref_dict: bad kPkinitClientCertKey pref\n");
	CFRelease(theDict);
	return errSecItemNotFound;
    }
    *dict = theDict;
    return noErr;
}

#pragma mark --- Public client side functions ---

/*
 * Obtain signing cert for specified principal. On successful return, 
 * caller must eventually release the cert with krb5_pkinit_release_cert().
 */
krb5_error_code krb5_pkinit_get_client_cert(
    const char			*principal,     /* full principal string */
    krb5_pkinit_signing_cert_t	*client_cert)
{
    CFDataRef issuerSerial = NULL;
    CSSM_DATA issuerSerialData;
    SecIdentityRef idRef = NULL;
    OSStatus ortn;
    CFDictionaryRef theDict = NULL;
    CFStringRef cfPrinc = NULL;
    krb5_error_code ourRtn = 0;
    
    if(principal == NULL) {
	return KRB5_PRINC_NOMATCH;
    }
    
    /* Is there a stored preference for PKINIT certs for this user? */
    ortn = pkinit_get_pref_dict(&theDict);
    if(ortn) {
	return KRB5_PRINC_NOMATCH;
    }
    
    /* Entry in the dictionary for specified principal? */
    cfPrinc = CFStringCreateWithCString(NULL, principal, 
                                        kCFStringEncodingASCII);
    issuerSerial = (CFDataRef)CFDictionaryGetValue(theDict, cfPrinc);
    CFRelease(cfPrinc);
    if(issuerSerial == NULL) {
	pkiDebug("krb5_pkinit_get_client_cert: no identity found\n");
	ourRtn = KRB5_PRINC_NOMATCH;
	goto errOut;
    }
    if(CFGetTypeID(issuerSerial) != CFDataGetTypeID()) {
	pkiDebug("krb5_pkinit_get_client_cert: bad kPkinitClientCertKey value\n");
	ourRtn = KRB5_PRINC_NOMATCH;
	goto errOut;
    }
    
    issuerSerialData.Data = (uint8 *)CFDataGetBytePtr(issuerSerial);
    issuerSerialData.Length = CFDataGetLength(issuerSerial);
    
    /* find a cert with that issuer/serial number in default search list */
    ortn = pkinit_search_ident(NULL, CSSM_KEYUSE_SIGN | CSSM_KEYUSE_ENCRYPT, 
	&issuerSerialData, &idRef);
    if(ortn) {
	pkiDebug("krb5_pkinit_get_client_cert: no identity found!\n");
	pkiCssmErr("pkinit_search_ident", ortn);
	ourRtn = KRB5_PRINC_NOMATCH;
    }
    else {
	*client_cert = (krb5_pkinit_signing_cert_t)idRef;
    }
errOut:
    if(theDict) {
	CFRelease(theDict);
    }
    return ourRtn;
}

/* 
 * Determine if the specified client has a signing cert. Returns TRUE
 * if so, else returns FALSE.
 */
krb5_boolean krb5_pkinit_have_client_cert(
    const char			*principal)	/* full principal string */
{
    krb5_pkinit_signing_cert_t signing_cert = NULL;
    krb5_error_code krtn;
    
    krtn = krb5_pkinit_get_client_cert(principal, &signing_cert);
    if(krtn) {
	return FALSE;
    }
    if(signing_cert != NULL) {
	krb5_pkinit_release_cert(signing_cert);
	return TRUE;
    }
    else {
	return FALSE;
    }
}

/*
 * Store the specified certificate (or, more likely, some platform-dependent
 * reference to it) as the specified principal's signing certificate. Passing
 * in NULL for the client_cert has the effect of deleting the relevant entry
 * in the cert storage.
 */
krb5_error_code krb5_pkinit_set_client_cert_from_signing_cert(
    const char			*principal,     /* full principal string */
    krb5_pkinit_signing_cert_t	client_cert)
{
    SecIdentityRef idRef = (SecIdentityRef)client_cert;
    SecCertificateRef certRef = NULL;
    OSStatus ortn;
    krb5_error_code ourRtn = 0;

    if (NULL != idRef) {
	if (CFGetTypeID(idRef) != SecIdentityGetTypeID()) {
	    ourRtn = KRB5KRB_ERR_GENERIC;
	    goto fin;
	}
	/* Get the cert */
	ortn = SecIdentityCopyCertificate(idRef, &certRef);
	if (ortn) {
	    pkiCssmErr("SecIdentityCopyCertificate", ortn);
	    ourRtn = KRB5KRB_ERR_GENERIC;
	    goto fin;
	}
    }
    ourRtn = krb5_pkinit_set_client_cert(principal, (krb5_pkinit_cert_t)certRef);
fin:
    if (certRef)
	CFRelease(certRef);
    return ourRtn;
}


/*
 * Store the specified certificate (or, more likely, some platform-dependent
 * reference to it) as the specified principal's certificate. Passing
 * in NULL for the client_cert has the effect of deleting the relevant entry
 * in the cert storage.
 */
krb5_error_code krb5_pkinit_set_client_cert(
    const char			*principal,     /* full principal string */
    krb5_pkinit_cert_t		client_cert)
{
    SecCertificateRef certRef = (SecCertificateRef)client_cert;
    OSStatus ortn;
    CSSM_DATA issuerSerial = {0, NULL};
    CFDataRef cfIssuerSerial = NULL;
    CFDictionaryRef existDict = NULL;
    CFMutableDictionaryRef newDict = NULL;
    CFStringRef keyStr = NULL;
    krb5_error_code ourRtn = 0;
    
    if(certRef != NULL) {
	if(CFGetTypeID(certRef) != SecCertificateGetTypeID()) {
	    return KRB5KRB_ERR_GENERIC;
	}
    
	/* Cook up DER-encoded issuer/serial number */
	ortn = pkinit_get_cert_issuer_sn(certRef, &issuerSerial);
	if(ortn) {
	    ourRtn = KRB5KRB_ERR_GENERIC;
	    goto errOut;
	}
    }
    
    /* 
     * Obtain the existing pref for kPkinitClientCertKey as a CFDictionary, or
     * cook up a new one. 
     */
    ortn = pkinit_get_pref_dict(&existDict);
    if(ortn == noErr) {
	/* dup to a mutable dictionary */
	newDict = CFDictionaryCreateMutableCopy(NULL, 0, existDict);
    }
    else {
	if(certRef == NULL) {
	    /* no existing entry, nothing to delete, we're done */
	    return 0;
	}
	newDict = CFDictionaryCreateMutable(NULL, 0,
	    &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
    if(newDict == NULL) {
	ourRtn = ENOMEM;
	goto errOut;
    }

    /* issuer / serial number ==> that dictionary */
    keyStr = CFStringCreateWithCString(NULL, principal, kCFStringEncodingASCII);
    if(certRef == NULL) {
	CFDictionaryRemoveValue(newDict, keyStr);
    }
    else {
	cfIssuerSerial = CFDataCreate(NULL, issuerSerial.Data, issuerSerial.Length);
	CFDictionarySetValue(newDict, keyStr, cfIssuerSerial);
    }
    
    /* dictionary ==> prefs */
    CFPreferencesSetValue(CFSTR(kPkinitClientCertKey), newDict, 
	CFSTR(kPkinitClientCertApp), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if(CFPreferencesSynchronize(CFSTR(kPkinitClientCertApp), kCFPreferencesCurrentUser, 
	    kCFPreferencesAnyHost)) {
	ourRtn = 0;
    }
    else {
	ourRtn = EACCES;   /* any better ideas? */
    }
errOut:
    if(cfIssuerSerial) {
	CFRelease(cfIssuerSerial);
    }
    if(issuerSerial.Data) {
	free(issuerSerial.Data);
    }
    if(existDict) {
	CFRelease(existDict);
    }
    if(newDict) {
	CFRelease(newDict);
    }
    if(keyStr) {
	CFRelease(keyStr);
    }
    return ourRtn;
}

/* 
 * Obtain a reference to the client's cert database. Specify either principal
 * name or client_cert as obtained from krb5_pkinit_get_client_cert().
 */
krb5_error_code krb5_pkinit_get_client_cert_db(
    const char			*principal,     /* full principal string */
    krb5_pkinit_signing_cert_t	client_cert,    /* optional, from krb5_pkinit_get_client_cert() */
    krb5_pkinit_cert_db_t	*client_cert_db)/* RETURNED */
{
    krb5_error_code krtn;
    krb5_pkinit_signing_cert_t local_cert;
    
    assert((client_cert != NULL) || (principal != NULL));
    if(client_cert == NULL) {
	/* caller didn't provide, look it up */
	krtn = krb5_pkinit_get_client_cert(principal, &local_cert);
	if(krtn) {
	    return krtn;
	}
    }
    else {
	/* easy case */
	local_cert = client_cert;
    }
    krtn = pkinit_cert_to_db(local_cert, client_cert_db);
    if(client_cert == NULL) {
	krb5_pkinit_release_cert(local_cert);
    }
    return krtn;
}

#pragma mark --- Public server side functions ---

/*
 * Obtain the KDC signing cert, with optional CA and specific cert specifiers.
 * CAs and cert specifiers are in the form of DER-encoded issuerAndSerialNumbers.
 *
 * The client_spec argument is typically provided by the client as kdcPkId.
 */
krb5_error_code krb5_pkinit_get_kdc_cert(
    krb5_ui_4			num_trusted_CAs,    /* sizeof *trusted_CAs */
    krb5_data			*trusted_CAs,	    /* optional */
    krb5_data			*client_spec,	    /* optional */
    krb5_pkinit_signing_cert_t *kdc_cert)
{
    SecIdentityRef idRef = NULL;
    OSStatus ortn;
    krb5_error_code ourRtn = 0;
    
    /* OS X: trusted_CAs and client_spec ignored */
    
    ortn = SecIdentityCopySystemIdentity(kSecIdentityDomainKerberosKDC,
	&idRef, NULL);
    if(ortn) {
	pkiCssmErr("SecIdentityCopySystemIdentity", ortn);
	return KRB5_PRINC_NOMATCH;
    }
    *kdc_cert = (krb5_pkinit_signing_cert_t)idRef;
    return ourRtn;
}

/* 
 * Obtain a reference to the KDC's cert database.
 */
krb5_error_code krb5_pkinit_get_kdc_cert_db(
    krb5_pkinit_cert_db_t   *kdc_cert_db)
{
    krb5_pkinit_signing_cert_t kdcCert = NULL;
    krb5_error_code krtn;
    
    krtn = krb5_pkinit_get_kdc_cert(0, NULL, NULL, &kdcCert);
    if(krtn) {
	return krtn;
    }
    krtn = pkinit_cert_to_db(kdcCert, kdc_cert_db);
    krb5_pkinit_release_cert(kdcCert);
    return krtn;
}

/*
 * Release certificate references obtained via krb5_pkinit_get_client_cert() and
 * krb5_pkinit_get_kdc_cert().
 */
void krb5_pkinit_release_cert(
    krb5_pkinit_signing_cert_t   cert)
{
    if(cert == NULL) {
	return;
    }
    CFRelease((CFTypeRef)cert);
}

/*
 * Release database references obtained via krb5_pkinit_get_client_cert_db() and
 * krb5_pkinit_get_kdc_cert_db().
 */
extern void krb5_pkinit_release_cert_db(
    krb5_pkinit_cert_db_t	    cert_db)
{
    if(cert_db == NULL) {
	return;
    }
    CFRelease((CFTypeRef)cert_db);
}


/* 
 * Obtain a mallocd C-string representation of a certificate's SHA1 digest. 
 * Only error is a NULL return indicating memory failure. 
 * Caller must free the returned string.
 */
char *krb5_pkinit_cert_hash_str(
    const krb5_data *cert)
{
    CC_SHA1_CTX ctx;
    char *outstr;
    char *cpOut;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    unsigned dex;
    
    assert(cert != NULL);
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, cert->data, cert->length);
    CC_SHA1_Final(digest, &ctx);
    
    outstr = (char *)malloc((2 * CC_SHA1_DIGEST_LENGTH) + 1);
    if(outstr == NULL) {
	return NULL;
    }
    cpOut = outstr;
    for(dex=0; dex<CC_SHA1_DIGEST_LENGTH; dex++) {
	snprintf(cpOut, 3, "%02X", (unsigned)(digest[dex]));
	cpOut += 2;
    }
    *cpOut = '\0';
    return outstr;
}

/* 
 * Obtain a client's optional list of trusted KDC CA certs (trustedCertifiers)
 * and/or trusted KDC cert (kdcPkId) for a given client and server. 
 * All returned values are mallocd and must be freed by caller; the contents 
 * of the krb5_datas are DER-encoded certificates. 
 */
krb5_error_code krb5_pkinit_get_server_certs(
    const char *client_principal,
    const char *server_principal,
    krb5_data **trusted_CAs,	    /* RETURNED, though return value may be NULL */
    krb5_ui_4 *num_trusted_CAs,	    /* RETURNED */
    krb5_data *kdc_cert)	    /* RETURNED, though may be 0/NULL */
{
    /* nothing for now */
    *trusted_CAs = NULL;
    *num_trusted_CAs = 0;
    kdc_cert->data = NULL;
    kdc_cert->length = 0;
    return 0;
}

#endif /* APPLE_PKINIT */

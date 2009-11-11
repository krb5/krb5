/*
 * plugins/authdata/saml_server/saml_util.cpp
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 *
 *
 * SAML Kerberos helpers
 */

#include <string.h>
#include <errno.h>

#include "saml_kdc.h"

krb5_error_code
saml_krb_derive_key(krb5_context context,
                    const krb5_keyblock *basekey,
                    unsigned int usage,
                    XSECCryptoKey **pXMLKey)
{
    OpenSSLCryptoKeyHMAC *hmackey;
    krb5_error_code code;
    char constant[8] = "saml";
    krb5_data cdata;
    krb5_data dk;
    size_t dklen;

    *pXMLKey = NULL;

    cdata.data = constant;
    cdata.length = sizeof(constant);

    /*
     * Object to be signed:
     *
     *      0x00   SAML assertion
     */
    constant[4] = 0;
    /*
     * Signing key:
     *
     *      0x00   TGT session key
     *      0xFF   Long-term service key
     */
    switch (usage) {
    case SAML_KRB_USAGE_SESSION_KEY:
        constant[5] = 0x00;
        break;
    case SAML_KRB_USAGE_SERVER_KEY:
        constant[5] = 0xFF;
        break;
    default:
        return EINVAL;
    }
    /* Reserved */
    constant[6] = 0;
    constant[7] = 0;

    code = krb5_c_prf_length(context, basekey->enctype, &dklen);
    if (code != 0)
        return code;

    dk.data = (char *)k5alloc(dklen, &code);
    if (code != 0)
        return code;

    dk.length = dklen;

    code = krb5_c_prf(context, basekey, &cdata, &dk);
    if (code != 0)
        return code;

    try {
        hmackey = new OpenSSLCryptoKeyHMAC();
        hmackey->setKey((unsigned char *)dk.data, dk.length);
    } catch (XSECCryptoException &e) {
        code = KRB5_CRYPTO_INTERNAL;
    } catch (XSECException &e) {
        code = KRB5_CRYPTO_INTERNAL;
    }

    *pXMLKey = hmackey;

    krb5_free_data_contents(context, &dk);

    return code;
}

static char saml_krb_wk_string[]        = "WELLKNOWN";
static char saml_krb_null_string[]      = "NULL";
static char saml_krb_realm[]            = "WELLKNOWN:SAML";

krb5_boolean
saml_krb_is_saml_principal(krb5_context context,
                           krb5_const_principal principal)
{
    return principal->type == KRB5_NT_WELLKNOWN &&
        principal->length == 2 &&
        data_eq_string(principal->data[0], saml_krb_wk_string) &&
        data_eq_string(principal->data[1], saml_krb_null_string) &&
        data_eq_string(principal->realm, saml_krb_realm);
}

krb5_error_code
saml_krb_unparse_name_xmlch(krb5_context context,
                            krb5_const_principal name,
                            XMLCh **unicodePrincipal,
                            int flags)
{
    krb5_error_code code;
    char *utf8Name;

    code = krb5_unparse_name_flags(context, name, flags, &utf8Name);
    if (code != 0)
        return code;

    *unicodePrincipal = fromUTF8(utf8Name, false);

    if (*unicodePrincipal == NULL)
        code = ENOMEM;

    free(utf8Name);

    return code;
}

krb5_error_code
saml_krb_parse_name_xmlch(krb5_context context,
                          const XMLCh *unicodePrincipal,
                          krb5_principal *name,
                          int flags)
{
    krb5_error_code code;
    char *utf8Name;

    utf8Name = toUTF8(unicodePrincipal);
    if (utf8Name == NULL)
        return NULL;

    code = krb5_parse_name_flags(context, utf8Name, flags, name);

    delete utf8Name;

    return code;
}

krb5_error_code
saml_krb_build_nameid(krb5_context context,
                      krb5_const_principal principal,
                      NameID **pNameID)
{
    NameID *nameID;
    krb5_error_code code;
    XMLCh *unicodePrincipal = NULL;

    *pNameID = NULL;

    code = saml_krb_unparse_name_xmlch(context, principal, &unicodePrincipal);
    if (code != 0)
        return code;

    nameID = NameIDBuilder::buildNameID();
    nameID->setName(unicodePrincipal);
    nameID->setFormat(NameIDType::KERBEROS);

    *pNameID = nameID;

    delete unicodePrincipal;

    return 0;
}

krb5_boolean
saml_krb_compare_principal(krb5_context context,
                           const XMLCh *unicodePrincipal,
                           krb5_const_principal princ1)
{
    krb5_boolean ret;
    krb5_principal princ2;

    if (saml_krb_parse_name_xmlch(context, unicodePrincipal, &princ2) != 0)
        return FALSE;

    ret = krb5_principal_compare(context, princ1, princ2);

    krb5_free_principal(context, princ2);

    return ret;
}

krb5_error_code
saml_krb_map_subject(krb5_context context,
                     Subject *subject,
                     krb5_principal *pMappedPrincipal)
{
    krb5_error_code code;
    NameID *nameID = subject->getNameID();
    const XMLCh *format;
    const XMLCh *name;

    *pMappedPrincipal = NULL;

    if (nameID == NULL)
        return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;

    format = nameID->getFormat();
    name = nameID->getName();

    if (XMLString::equals(format, NameIDType::KERBEROS)) {
        code = saml_krb_parse_name_xmlch(context, name, pMappedPrincipal);
    } else {
        /* XXX make a NameIDMappingRequest to the IdP? */
        code = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
    }

    return code; 
}

krb5_boolean
saml_krb_compare_issuer(krb5_context context,
                        Issuer *asserted,
                        Issuer *actual)
{
    if (asserted == NULL)
        return TRUE;
    else if (asserted != NULL && actual == NULL)
        return FALSE;

    return (XMLString::equals(asserted->getFormat(), actual->getFormat()) &&
            XMLString::equals(asserted->getName(), actual->getName()));
}

krb5_boolean
saml_krb_compare_subject(krb5_context context,
                         Subject *asserted,
                         Subject *actual)
{
    NameID *assertedName;
    NameID *actualName;

    assert(asserted != NULL);

    if (actual == NULL)
        return FALSE;

    assertedName = asserted->getNameID();
    actualName = actual->getNameID();

    if (assertedName == NULL || actualName == NULL)
        return FALSE;

    return (XMLString::equals(assertedName->getFormat(), actualName->getFormat()) &&
            XMLString::equals(assertedName->getName(), actualName->getName()));
}

krb5_error_code
saml_krb_bind_subject_kdb(krb5_context context,
                          krb5_db_entry *entry,
                          Issuer *issuer,
                          Subject *subject)
{
    krb5_error_code code = KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
    krb5_tl_data *tlp;

    for (tlp = entry->tl_data; tlp != NULL; tlp = tlp->tl_data_next) {
        saml2::Assertion *assertion;

        if (tlp->tl_data_type != KRB5_TL_SAML_IDENTITY_BINDING)
            continue;

        try {
            string samlbuf((char *)tlp->tl_data_contents, tlp->tl_data_length);
            istringstream samlin(samlbuf);

            DOMDocument *doc = XMLToolingConfig::getConfig().getParser().parse(samlin);
            const XMLObjectBuilder *b = XMLObjectBuilder::getDefaultBuilder();
            DOMElement *elem = doc->getDocumentElement();
            XMLObject *xobj = b->buildOneFromElement(elem, true);
            assertion = (saml2::Assertion*)((void *)xobj);
            if (saml_krb_compare_issuer(context, issuer, assertion->getIssuer()) &&
                saml_krb_compare_subject(context, subject, assertion->getSubject())) {
                code = 0;
                delete assertion;
                break;
            }
            delete assertion;
        } catch (XMLToolingException &e) {
            continue;
        }
    }

    return code;
} 

krb5_timestamp
saml_krb_get_authtime(krb5_context context,
                      const saml2::Assertion *assertion)
{
    krb5_timestamp ktime = 0;
    const AuthnStatement *statement;

    if (assertion->getAuthnStatements().size() == 1) {
        statement = assertion->getAuthnStatements().front();
        ktime = statement->getAuthnInstant()->getEpoch(false);
    }

    return ktime;
}

krb5_error_code
saml_krb_build_principal_keyinfo(krb5_context context,
                                 krb5_const_principal principal,
                                 KeyInfo **pKeyInfo)
{
    krb5_error_code code;
    XMLCh *unicodePrincipal;
    KeyName *keyName;
    KeyInfo *keyInfo;

    *pKeyInfo = NULL;

    code = saml_krb_unparse_name_xmlch(context, principal, &unicodePrincipal);
    if (code != 0)
        return code;

    keyName = KeyNameBuilder::buildKeyName();
    keyName->setTextContent(unicodePrincipal);

    keyInfo = KeyInfoBuilder::buildKeyInfo();
    keyInfo->getKeyNames().push_back(keyName);

    *pKeyInfo = keyInfo;

    return 0;
}

krb5_error_code
saml_krb_confirm_keyinfo(krb5_context context,
                         const saml2::SubjectConfirmation *conf,
                         krb5_const_principal principal,
                         krb5_boolean *pConfirmed)
{
    const saml2::KeyInfoConfirmationDataType *keyConfData;

    *pConfirmed = FALSE;

    keyConfData = (KeyInfoConfirmationDataType *)((void *)conf->getSubjectConfirmationData());

    for (vector<KeyInfo *>::const_iterator ki = keyConfData->getKeyInfos().begin();
         ki != keyConfData->getKeyInfos().end();
         ki++)
    {
        KeyName *kn = (*ki)->getKeyNames().front();
        const XMLCh *knValue = kn->getTextContent();

        if (saml_krb_compare_principal(context, knValue, principal)) {
            *pConfirmed = TRUE;
            break;
        }
    }

    return 0;
}

krb5_error_code
saml_krb_confirm_subject(krb5_context context,
                         const saml2::Subject *subject,
                         krb5_const_principal principal,
                         krb5_timestamp authtime,
                         krb5_boolean *pConfirmed,
                         krb5_boolean *pBound)
{
    krb5_error_code code;
    const vector<SubjectConfirmation *>&confs = subject->getSubjectConfirmations();
    krb5_boolean confirmed = FALSE;
    krb5_boolean bound = FALSE;

    for (vector<SubjectConfirmation *>::const_iterator sc = confs.begin();
         sc != confs.end();
         sc++)
    {
         const SubjectConfirmationData *subjectConfirmationData;
         time_t ts;

         subjectConfirmationData = (SubjectConfirmationData *)((void *)(*sc)->getSubjectConfirmationData());

         ts = subjectConfirmationData->getNotBefore()->getEpoch(false);
         if (ts < authtime)
            continue;

#if 0
         ts = subjectConfirmationData->getNotOnOrAfter()->getEpoch(false);
         if (ts > endtime)
             continue;
#endif

        if (XMLString::equals((*sc)->getMethod(), SubjectConfirmation::HOLDER_KEY)) {
            code = saml_krb_confirm_keyinfo(context, *sc, principal, &confirmed);
            if (code != 0)
                break;

            bound = TRUE;
        } else {
            confirmed = saml_krb_is_saml_principal(context, principal);
        }
        if (confirmed)
            break;
    }

    *pConfirmed = confirmed;
    *pBound = bound;

    return 0;
}

krb5_error_code
saml_krb_verify_recipient(krb5_context context,
                          const saml2::Assertion *assertion,
                          krb5_const_principal spn,
                          krb5_boolean *pValid)
{
    const Subject *subject = assertion->getSubject();
    const vector<SubjectConfirmation *>&confs = subject->getSubjectConfirmations();
    krb5_boolean spnMatch = FALSE;
    krb5_boolean hasRecipient = FALSE;
    XMLCh *spnInstance = NULL;
    XMLCh *spnAll = NULL;
    krb5_error_code code;

    code = saml_krb_unparse_name_xmlch(context, spn, &spnAll);
    if (code != 0)
        return code;

    if (spn->type == KRB5_NT_SRV_HST && spn->length > 1) {
        spnInstance = new XMLCh[spn->data[1].length + 1];
        XMLString::transcode(spn->data[1].data, spnInstance, spn->data[1].length);
    }

    for (vector<SubjectConfirmation *>::const_iterator sc = confs.begin();
         sc != confs.end();
         sc++)
    {
#if 0
        const SubjectConfirmationDataType* data = dynamic_cast<const SubjectConfirmationDataType*>((*sc)->getSubjectConfirmationData());
#else
        const SubjectConfirmationDataType* data = (const SubjectConfirmationDataType *)((void *)(*sc)->getSubjectConfirmationData());
#endif

        if (data == NULL || data->getRecipient() == NULL)
            continue;

        hasRecipient = TRUE;

        if (spnInstance != NULL &&
            XMLString::equals((*sc)->getMethod(),
                              SubjectConfirmation::BEARER)) {
            XMLURL url(data->getRecipient());

            spnMatch = XMLString::equals(url.getHost(), spnInstance);
        } else if (XMLString::equals((*sc)->getMethod(),
                                     SubjectConfirmation::HOLDER_KEY)) {
            spnMatch = XMLString::equals(data->getRecipient(), spnAll);
        }
        if (spnMatch == TRUE)
            break;
    }

    *pValid = hasRecipient ? spnMatch : TRUE;

    delete spnInstance;
    delete spnAll;

    return 0;
}

krb5_error_code
saml_krb_verify_signature(krb5_context context,
                          Signature *signature,
                          const krb5_keyblock *key,
                          krb5_const_principal server,
                          unsigned int flags,
                          krb5_boolean bound,
                          krb5_boolean *pValid)
{
    krb5_error_code code = 0;
    krb5_boolean validSig;

    validSig = FALSE;

    try {
        SignatureValidator krbSigValidator;
        XSECCryptoKey *krbXmlKey;

        /* Only KDC-issued assertions can be natively bound */
        if (flags & SAML_KRB_VERIFY_SESSION_KEY) {
            code = saml_krb_derive_key(context, key,
                                       SAML_KRB_USAGE_SESSION_KEY, &krbXmlKey);
            if (code != 0)
                return code;

            krbSigValidator.setKey(krbXmlKey);

            try {
                krbSigValidator.validate(signature);
                validSig = TRUE;
            } catch (ValidationException &v) {
            }
        }
        if (validSig == FALSE &&
            (flags & SAML_KRB_VERIFY_TRUSTENGINE)) {
            /*
             * Note the verification policy may differ depending on whether
             * we also trust this signer to bind the name.
             */
            code = saml_krb_verify_trustengine(context, signature, key,
                                               server, flags, bound, pValid);
        }
    } catch (exception &e) {
        code = KRB5_CRYPTO_INTERNAL;
    }

    *pValid = validSig;

    return code;
}

krb5_error_code
saml_krb_bind_subject(krb5_context context,
                      Issuer *issuer,
                      Subject *subject,
                      krb5_const_principal client_princ,
                      krb5_db_entry *client,
                      krb5_boolean *pBound,
                      krb5_principal *pMappedPrincipal)
{
    krb5_error_code code;
    krb5_boolean bound = FALSE;
    krb5_principal mappedPrincipal;

    *pBound = FALSE;

    if (client != NULL) {
        code = saml_krb_bind_subject_kdb(context, client, issuer, subject);
        if (code == 0) {
            *pBound = TRUE;
            return code;
        }
    }

    /* Try forward mapping */
    code = saml_krb_map_subject(context, subject, &mappedPrincipal);
    if (code != 0)
        return code;
    if (!krb5_principal_compare(context, mappedPrincipal, client_princ)) {
        krb5_free_principal(context, mappedPrincipal);
        return KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
    }

    if (pMappedPrincipal != NULL)
        *pMappedPrincipal = mappedPrincipal;
    else
        krb5_free_principal(context, mappedPrincipal);

    bound = TRUE;

    return 0;
}

krb5_error_code
saml_krb_verify(krb5_context context,
                saml2::Assertion *assertion,
                const krb5_keyblock *key,
                krb5_const_principal client_princ,
                krb5_db_entry *client,
                krb5_const_principal server,
                krb5_timestamp authtime,
                unsigned int flags,
                krb5_boolean *pValid,
                krb5_principal *pMappedPrincipal)
{
    krb5_error_code code;
    krb5_boolean verified = FALSE;
    krb5_boolean bound = FALSE;
    Signature *signature;
    Subject *subject;

    *pValid = FALSE;

    if (pMappedPrincipal != NULL)
        *pMappedPrincipal = NULL;

    if (assertion == NULL)
        return EINVAL;

    subject = assertion->getSubject();
    if (subject == NULL)
        return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;

    signature = assertion->getSignature();
    if (signature == NULL)
        return 0;

    /*
     * Verify any signatures present on the assertion.
     */
    if ((flags & SAML_KRB_VERIFY_KDC_VOUCHED) == 0) {
        code = saml_krb_verify_signature(context, signature, key, server,
                                         flags, bound, &verified);
        if (code != 0 || verified == FALSE)
            return KRB5KRB_AP_ERR_MODIFIED;
    }

    if (saml_krb_get_authtime(context, assertion) < authtime)
        return KRB5KDC_ERR_CLIENT_NOTYET;

    /*
     * Verify the assertion is appropriately bound to the ticket client
     */
    code = saml_krb_confirm_subject(context, subject, client_princ,
                                    authtime, &verified, &bound);
    if (code != 0)
        return code;
    else if (verified == FALSE)
        return KRB5KDC_ERR_CLIENT_NOT_TRUSTED;

   /*
     * Verify that the Recipient in any bearer SubjectConfirmationData
     * matches the service principal.
     */
    code = saml_krb_verify_recipient(context, assertion, server, &verified);
    if (code != 0 || verified == FALSE)
        return KRB5KRB_AP_WRONG_PRINC;

    if (bound == FALSE) {
        code = saml_krb_bind_subject(context, assertion->getIssuer(), subject,
                                     client_princ, client,
                                     &bound, pMappedPrincipal);
        if (code != 0 || bound == FALSE)
            return KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
    }

    assert(bound && verified);

    *pValid = TRUE;

    return 0;
}

krb5_error_code
saml_krb_decode_assertion(krb5_context context,
                          krb5_data *data,
                          saml2::Assertion **pAssertion)
{
    krb5_error_code code;
    DOMDocument *doc;
    const XMLObjectBuilder *b;
    DOMElement *elem;
    XMLObject *xobj;

    *pAssertion = NULL;

    /*
     * Attempt to parse the assertion.
     */
    try {
        string samlbuf(data->data, data->length);
        istringstream samlin(samlbuf);

        doc = XMLToolingConfig::getConfig().getParser().parse(samlin);
        b = XMLObjectBuilder::getDefaultBuilder();
        elem = doc->getDocumentElement();
        xobj = b->buildOneFromElement(elem, true);
#if 0
        *pAssertion = dynamic_cast<saml2::Assertion*>(xobj);
        if (*pAssertion == NULL) {
            fprintf(stderr, "%s\n", typeid(xobj).name());
            delete xobj;
            code = ASN1_PARSE_ERROR;
        }
#else
        *pAssertion = (saml2::Assertion*)((void *)xobj);
        code = 0;
#endif
    } catch (exception &e) {
        code = ASN1_PARSE_ERROR; /* XXX */
    }

    return code;
}
 
krb5_error_code
saml_krb_decode_assertion(krb5_context context,
                          krb5_authdata *authdata,
                          saml2::Assertion **pAssertion)
{
    krb5_data data;

    if (authdata->ad_type != KRB5_AUTHDATA_SAML)
        return EINVAL;

    data.data = (char *)authdata->contents;
    data.length = authdata->length;

    return saml_krb_decode_assertion(context, &data, pAssertion);
}


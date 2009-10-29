/*
 * plugins/authdata/saml_server/saml_krb.h
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

#ifndef SAML_KRB_H_
#define SAML_KRB_H_ 1

extern "C" {
#include <k5-int.h>
#include <krb5/authdata_plugin.h>
}

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/signature/SignatureProfileValidator.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/SignatureTrustEngine.h>
#include <xmltooling/security/OpenSSLCredential.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/signature/SignatureValidator.h>
#include <xmltooling/util/XMLHelper.h>
#include <xsec/framework/XSECException.hpp>
#include <xsec/dsig/DSIGKeyInfoValue.hpp>
#include <xsec/dsig/DSIGKeyInfoName.hpp>
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyHMAC.hpp>
#include <xercesc/util/Base64.hpp>

using namespace xmlsignature;
using namespace xmlconstants;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace samlconstants;
using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xercesc;
using namespace std;

#define SAML_KRB_USAGE_SESSKEY          0x1 /* signed with session key */
#define SAML_KRB_USAGE_TGSKEY           0x2 /* signed with TGS key */
#define SAML_KRB_USAGE_TRUSTENGINE      0x4 /* signed with public key */

static inline krb5_error_code
saml_krb_derive_key(krb5_context context,
                    krb5_keyblock *basekey,
                    unsigned int flags,
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

    constant[4] = (flags & SAML_KRB_USAGE_TGSKEY) ? 0xFF : 0;
    constant[5] = 0;
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

static char saml_krb_wk_string[] = "WELLKNOWN";
static char saml_krb_null_string[] = "NULL";
static char saml_krb_realm[] = "WELLKNOWN:SAML";

static inline krb5_boolean
saml_krb_is_saml_principal(krb5_context context,
                           krb5_const_principal principal)
{
    return principal->type == KRB5_NT_WELLKNOWN &&
        principal->length == 2 &&
        data_eq_string(principal->data[0], saml_krb_wk_string) &&
        data_eq_string(principal->data[1], saml_krb_null_string) &&
        data_eq_string(principal->realm, saml_krb_realm);
}

static krb5_error_code
saml_krb_unparse_name_xmlch(krb5_context context,
                            krb5_const_principal name,
                            XMLCh **unicodePrincipal)
{
    krb5_error_code code;
    char *utf8Name;

    code = krb5_unparse_name(context, name, &utf8Name);
    if (code != 0)
        return code;

    *unicodePrincipal = fromUTF8(utf8Name, false);

    if (*unicodePrincipal == NULL)
        code = ENOMEM;

    free(utf8Name);

    return code;
}

static krb5_error_code
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

static inline krb5_boolean
saml_krb_compare_principal(krb5_context context,
                           const XMLCh *unicodePrincipal,
                           krb5_const_principal principal)
{
    char *name = NULL;
    krb5_boolean ret;
    krb5_principal p;

    name = toUTF8(unicodePrincipal);
    if (name == NULL)
        return FALSE;

    if (krb5_parse_name(context, name, &p) != 0) {
        delete name;
        return FALSE;
    }

    ret = krb5_principal_compare(context, p, principal);

    delete name;

    return ret;
}

static inline krb5_boolean
saml_krb_compare_nameid(krb5_context context,
                        const NameID *nameID,
                        krb5_const_principal principal)
{
    if (!XMLString::equals(nameID->getFormat(), NameIDType::KERBEROS))
        return FALSE;

    return saml_krb_compare_principal(context, nameID->getName(), principal);
}

#if 0
typedef enum _saml_krb_subject_type {
    SAML_KRB_NO_SUBJECT = 0,
    SAML_KRB_ANY_SUBJECT,
    SAML_KRB_NATIVE_SUBJECT,
    SAML_KRB_CONFIRMED_SUBJECT,
} saml_krb_subject_type;

static inline saml_krb_subject_type
saml_krb_validate_subject(krb5_context context,
                          const Subject *subject,
                          krb5_const_principal principal)
{
    const NameID *nameID = subject->getNameID();
    saml_krb_subject_type ret = SAML_KRB_NO_SUBJECT;

    if (nameID == NULL)
        ret = SAML_KRB_NO_SUBJECT;
    else if (saml_krb_is_saml_principal(context, principal))
        ret = SAML_KRB_ANY_SUBJECT;
    else if (saml_krb_compare_nameid(context, subject->getNameID(), principal))
        ret = SAML_KRB_NATIVE_SUBJECT;
    else {
        const vector<SubjectConfirmation *>&confs =
            subject->getSubjectConfirmations();

        for (vector<SubjectConfirmation *>::const_iterator sc = confs.begin();
             sc != confs.end();
             sc++) {
            if (XMLString::equals((*sc)->getMethod(), SubjectConfirmation::HOLDER_KEY) &&
                saml_krb_compare_nameid(context, (*sc)->getNameID(), principal)) {
                ret = SAML_KRB_CONFIRMED_SUBJECT;
                break;
            }
        }
    }

    return ret;
}
#endif

#if 0
static inline krb5_timestamp
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
#endif

static krb5_error_code
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

static inline krb5_error_code
saml_krb_confirm_keyinfo(krb5_context context,
                         const saml2::SubjectConfirmation *conf,
                         krb5_const_principal principal,
                         krb5_boolean *pConfirmed)
{
    krb5_error_code code;
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

static inline krb5_error_code
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

static inline krb5_error_code
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

static inline krb5_error_code
saml_krb_verify_signature(krb5_context context,
                          Signature *signature,
                          krb5_keyblock *key,
                          unsigned int flags,
                          krb5_boolean *pValid)
{
    krb5_error_code code = 0;
    krb5_boolean validSig;

    validSig = FALSE;

    try {
        SignatureValidator krbSigValidator;
        XSECCryptoKey *krbXmlKey;

        /* Only KDC-issued assertions can be natively bound */
        if (flags & SAML_KRB_USAGE_SESSKEY) {
            code = saml_krb_derive_key(context, key, flags, &krbXmlKey);
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
            (flags & SAML_KRB_USAGE_TRUSTENGINE)) {
        }
    } catch (exception &e) {
        code = KRB5_CRYPTO_INTERNAL;
    }

    *pValid = validSig;

    return code;
}

static inline krb5_error_code
saml_krb_verify(krb5_context context,
                saml2::Assertion *assertion,
                krb5_keyblock *key,
                krb5_const_principal client,
                krb5_const_principal server,
                krb5_timestamp authtime,
                unsigned int flags,
                krb5_boolean *pValid,
                krb5_principal *pMappedPrincipal = NULL)
{
    krb5_error_code code;
    krb5_boolean validSig = FALSE;
    krb5_boolean validNameBinding = FALSE;
    Signature *signature;
    Subject *subject;

    *pValid = FALSE;

    if (assertion == NULL)
        return EINVAL;

    subject = assertion->getSubject();
    if (subject == NULL)
        return KRB5KRB_AP_WRONG_PRINC;

    signature = assertion->getSignature();
    if (signature == NULL)
        return 0;

    /*
     * Verify the assertion is appropriately bound to the ticket client
     */
    code = saml_krb_confirm_subject(context, subject, client,
                                    authtime, &validSig, &validNameBinding);
    if (code != 0)
        return code;

    /*
     * Verify any signatures present on the assertion.
     */
    code = saml_krb_verify_signature(context, signature, key, flags, &validSig);
    if (code != 0 || validSig == FALSE)
        return code;

    /*
     * Verify that the Recipient in any bearer SubjectConfirmationData
     * matches the service principal.
     */
    code = saml_krb_verify_recipient(context, assertion, server, &validSig);
    if (code != 0 || validSig == FALSE)
        return code;

    if (validNameBinding) {
    }

    *pValid = TRUE;

    return 0;
}

/* Helper for transcoding krb5_data objects */
class auto_ptr_krb5_data {
    MAKE_NONCOPYABLE(auto_ptr_krb5_data);
    public:
        auto_ptr_krb5_data() : m_buf(NULL) {
        }
        auto_ptr_krb5_data(const krb5_data *src) {
            m_buf = new XMLCh[src->length + 1];
            XMLString::transcode(src->data, m_buf, src->length);
        }
        ~auto_ptr_krb5_data() {
            xercesc::XMLString::release(&m_buf);
        }
        const XMLCh* get() const {
            return m_buf;
        }
        XMLCh* release() {
            XMLCh *temp = m_buf; m_buf = NULL; return temp;
        }
    private:
        XMLCh *m_buf;
};

#endif /* SAML_KRB_H_ */


/*
 * plugins/authdata/saml_server/saml_kerb.h
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

static inline krb5_error_code
saml_krb_derive_key(krb5_context context,
                    krb5_keyblock *basekey,
                    XSECCryptoKey **pXMLKey)
{
    OpenSSLCryptoKeyHMAC *hmackey;
    krb5_error_code code;
    char constant[] = "saml";
    krb5_data cdata;
    krb5_data dk;
    size_t dklen;

    *pXMLKey = NULL;

    cdata.data = constant;
    cdata.length = sizeof(constant) - 1;

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

static inline krb5_boolean
saml_krb_compare_subject(krb5_context context,
                         Subject *subject,
                         krb5_const_principal principal)
{
    NameID *nameID = subject->getNameID();
    char *sname;
    krb5_error_code ret;
    krb5_principal sprinc;

    if (nameID == NULL)
        return FALSE;

    if (!XMLString::equals(nameID->getFormat(), NameIDType::KERBEROS))
        return FALSE;

    if (!nameID->getName())
        return FALSE;

    sname = toUTF8(nameID->getName());
    if (sname == NULL)
        return FALSE;

    if (krb5_parse_name(context, sname, &sprinc) == 0)
        ret = krb5_principal_compare(context, sprinc, principal);
    else
        ret = FALSE;

    delete sname;

    return ret;
}

static krb5_timestamp
saml_krb_get_authtime(krb5_context context,
                      saml2::Assertion *assertion)
{
    krb5_timestamp ktime = 0;
    const AuthnStatement *statement;

    if (assertion->getAuthnStatements().size() == 1) {
        statement = assertion->getAuthnStatements().front();
        ktime = statement->getAuthnInstant()->getEpoch(false);
    }

    return ktime;
}

static inline krb5_error_code
saml_krb_verify(krb5_context context,
                opensaml::saml2::Assertion *assertion,
                krb5_keyblock *basekey,
                krb5_const_principal client,
                krb5_timestamp authtime,
                krb5_boolean *pValid)
{
    krb5_error_code code;
    XSECCryptoKey *key;
    krb5_boolean validSig = FALSE;

    *pValid = FALSE;

    if (assertion == NULL)
        return EINVAL;

    code = saml_krb_derive_key(context, basekey, &key);
    if (code != 0)
        return code;

    try {
        Signature *signature = assertion->getSignature();
        DSIGSignature *dsig = signature->getXMLSignature();

        if (dsig != NULL) {
            dsig->setSigningKey(key);
            validSig = dsig->verify();
        }
    } catch (XSECException &e) {
        code = KRB5_CRYPTO_INTERNAL;
    } catch (XSECCryptoException &e) {
        code = KRB5_CRYPTO_INTERNAL;
    }

    if (validSig) {
        if (saml_krb_get_authtime(context, assertion) == authtime &&
            saml_krb_compare_subject(context, assertion->getSubject(), client))
            *pValid = TRUE;
    }

    return 0;
}

#endif /* SAML_KRB_H_ */


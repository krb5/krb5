/*
 * plugins/authdata/saml_server/saml_trust.cpp
 *
 * Copyright 2009, 2011 by the Massachusetts Institute of Technology.
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
 * SAML TrustEngine glue
 */

#include <string.h>
#include <errno.h>

#include <iostream>
#include <fstream>

#include "saml_krb.h"

static krb5_error_code
saml_krb_get_sp_document(krb5_context context,
                         krb5_const_principal server,
                         const char *key,
                         DOMDocument **pDocument)
{
    char *tmp, *path;
    const krb5_data *realm = krb5_princ_realm(context, server);
    krb5_error_code code;

    tmp = (char *)k5alloc(realm->length + 1, &code);
    if (code != 0)
        return code;

    memcpy(tmp, realm->data, realm->length);
    tmp[realm->length] = '\0';

    code = profile_get_string(context->profile, KRB5_CONF_REALMS,
                              tmp, key, NULL, &path);
    if (code != 0) {
        free(tmp);
        return code;
    }

    ifstream in(path);

    try {
        *pDocument = XMLToolingConfig::getConfig().getParser().parse(in);
        code = 0;
    } catch (XMLToolingException &e) {
        code = ASN1_PARSE_ERROR;
    }

    assert(*pDocument != NULL || code != 0);

    free(path);
    free(tmp);

    return code;
}

static krb5_error_code
saml_krb_get_sp_metadata_provider(krb5_context context,
                                  krb5_const_principal server,
                                  MetadataProvider **pMetadataProvider)
{
    krb5_error_code code;
    MetadataProvider *mp;
    DOMDocument *doc;

    *pMetadataProvider = NULL;

    code = saml_krb_get_sp_document(context, server,
                                    "saml_metadata_provider", &doc);
    if (code != 0)
        return code;

    mp = opensaml::SAMLConfig::getConfig().MetadataProviderManager.newPlugin(XML_METADATA_PROVIDER, doc->getDocumentElement());
    try {
        mp->init();
    } catch (XMLToolingException &e) {
        code = ASN1_PARSE_ERROR;
    }

    *pMetadataProvider = mp;

    delete doc;

    return code;
}

static krb5_error_code
saml_krb_get_sp_trustengine(krb5_context context,
                            krb5_const_principal server,
                            SignatureTrustEngine **pTrustEngine)
{
    krb5_error_code code;
    TrustEngine *te;
    DOMDocument *doc;

    *pTrustEngine = NULL;

    code = saml_krb_get_sp_document(context, server,
                                    "saml_trustengine", &doc);
    if (code != 0)
        return code;

    te = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(STATIC_PKIX_TRUSTENGINE, doc->getDocumentElement());

    *pTrustEngine = dynamic_cast<SignatureTrustEngine *>(te);
    if (*pTrustEngine == NULL)
        code = ASN1_PARSE_ERROR;

    delete doc;

    return code;
}

krb5_error_code
saml_krb_verify_trustengine(krb5_context context,
                            Signature *signature,
                            const krb5_keyblock *key,
                            krb5_const_principal server,
                            unsigned int flags,
                            krb5_boolean bound,
                            krb5_boolean *pValid)
{
    MetadataProvider *mp = NULL;
    SignatureTrustEngine *te = NULL;
    const EntityDescriptor *descriptor;
    RoleDescriptor *role;
    krb5_error_code code;

    assert(flags & SAML_KRB_VERIFY_TRUSTENGINE);

    code = saml_krb_get_sp_metadata_provider(context, server, &mp);
    if (code != 0)
        return code;

    code = saml_krb_get_sp_trustengine(context, server, &te);
    if (code != 0) {
        delete mp;
        return code;
    }

    Locker locker(mp);

#if 0
    /* XXX MetadataCredentialCriteria */
    descriptor = mp->getEntityDescriptor(MetadataProvider::Criteria("https://idp.example.org")).first;

    role = descriptor->getIDPSSODescriptors().front();
    if (role != NULL) {
        MetadataCredentialCriteria cc(*role);
        cc.setPeerName("https://idp.example.org");
        *pValid = te->validate(*signature, *mp, &cc);
    }
#else
    *pValid = te->validate(*signature, *mp, (CredentialCriteria *)NULL);
#endif

    delete mp;
    delete te;

    return code;
}


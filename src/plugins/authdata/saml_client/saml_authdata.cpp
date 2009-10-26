/*
 * plugins/authdata/saml_client/saml_authdata.cpp
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
 * Sample authorization data plugin
 */

#include <string.h>
#include <errno.h>

extern "C" {
#include "k5-int.h"
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
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyHMAC.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/framework/XSECException.hpp>

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

struct saml_context {
    saml2::Assertion *assertion;
    krb5_boolean verified;
};

extern "C" {
static krb5_error_code
saml_init(krb5_context kcontext, void **plugin_context);

static void
saml_flags(krb5_context kcontext,
           void *plugin_context,
           krb5_authdatatype ad_type,
           krb5_flags *flags);

static void
saml_fini(krb5_context kcontext, void *plugin_context);

static krb5_error_code
saml_request_init(krb5_context kcontext,
                  krb5_authdata_context context,
                  void *plugin_context,
                  void **request_context);

static krb5_error_code
saml_export_authdata(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     krb5_flags usage,
                     krb5_authdata ***out_authdata);

static krb5_error_code
saml_import_authdata(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     krb5_authdata **authdata,
                     krb5_boolean kdc_issued_flag,
                     krb5_const_principal issuer);

static void
saml_request_fini(krb5_context kcontext,
                  krb5_authdata_context context,
                  void *plugin_context,
                  void *request_context);

static krb5_error_code
saml_get_attribute_types(krb5_context kcontext,
                         krb5_authdata_context context,
                         void *plugin_context,
                         void *request_context,
                         krb5_data **out_attrs);

static krb5_error_code
saml_get_attribute(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void *request_context,
                   const krb5_data *attribute,
                   krb5_boolean *authenticated,
                   krb5_boolean *complete,
                   krb5_data *value,
                   krb5_data *display_value,
                   int *more);

static krb5_error_code
saml_delete_attribute(krb5_context kcontext,
                      krb5_authdata_context context,
                      void *plugin_context,
                      void *request_context,
                      const krb5_data *attribute);

static krb5_error_code
saml_size(krb5_context kcontext,
          krb5_authdata_context context,
          void *plugin_context,
          void *request_context,
          size_t *sizep);

static krb5_error_code
saml_externalize(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void *request_context,
                 krb5_octet **buffer,
                 size_t *lenremain);

static krb5_error_code
saml_internalize(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void *request_context,
                 krb5_octet **buffer,
                 size_t *lenremain);

static krb5_error_code
saml_verify_authdata(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     const krb5_auth_context *auth_context,
                     const krb5_keyblock *key,
                     const krb5_ap_req *req);

static krb5_error_code
saml_copy(krb5_context kcontext,
          krb5_authdata_context context,
          void *plugin_context,
          void *request_context,
          void *dst_plugin_context,
          void *dst_request_context);

static void saml_library_init(void) __attribute__((__constructor__));
static void saml_library_fini(void) __attribute__((__destructor__));
}

static void saml_library_init(void)
{
    SAMLConfig &config = SAMLConfig::getConfig();
    XMLToolingConfig& xmlconf = XMLToolingConfig::getConfig();

    if (getenv("SAML_DEBUG"))
        xmlconf.log_config("DEBUG");
    else
        xmlconf.log_config();

    config.init();
}

static void saml_library_fini(void)
{
    SAMLConfig &config = SAMLConfig::getConfig();
    config.term();
}

static krb5_error_code
saml_init(krb5_context kcontext, void **plugin_context)
{
    return 0;
}

static void
saml_flags(krb5_context kcontext,
           void *plugin_context,
           krb5_authdatatype ad_type,
           krb5_flags *flags)
{
    *flags = AD_USAGE_TGS_REQ;
}

static void
saml_fini(krb5_context kcontext, void *plugin_context)
{
}

static krb5_error_code
saml_request_init(krb5_context kcontext,
                  krb5_authdata_context context,
                  void *plugin_context,
                  void **request_context)
{
    struct saml_context *sc;

    sc = (struct saml_context *)calloc(1, sizeof(*sc));
    if (sc == NULL)
        return ENOMEM;

    sc->verified = FALSE;

    *request_context = sc;

    return 0;
}

static krb5_error_code
saml_export_authdata(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     krb5_flags usage,
                     krb5_authdata ***out_authdata)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    krb5_authdata *data[2];
    krb5_authdata datum;
    string buf;

    if (sc->assertion == NULL)
        return 0;

    try {
        XMLHelper::serialize(sc->assertion->marshall((DOMDocument *)NULL), buf);
    } catch (XMLToolingException &e) {
        return ASN1_PARSE_ERROR;
    }

    datum.ad_type = KRB5_AUTHDATA_SAML;
    datum.length = buf.length();
    datum.contents = (krb5_octet *)buf.c_str();

    data[0] = &datum;
    data[1] = NULL;

    return krb5_copy_authdata(kcontext, data, out_authdata);
}

static krb5_error_code
saml_import_authdata(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     krb5_authdata **authdata,
                     krb5_boolean kdc_issued_flag,
                     krb5_const_principal issuer)
{
    krb5_error_code code = 0;
    struct saml_context *sc = (struct saml_context *)request_context;
    string samlbuf((char *)authdata[0]->contents, authdata[0]->length);
    istringstream samlin(samlbuf);
    DOMDocument *doc = NULL;
    DOMElement *elem = NULL;
    const XMLObjectBuilder *b;
    XMLObject *xobj;

    assert(sc->verified == FALSE);

    try {
        doc = XMLToolingConfig::getConfig().getParser().parse(samlin);
        b = XMLObjectBuilder::getDefaultBuilder();
        elem = doc->getDocumentElement();
        xobj = b->buildOneFromElement(elem, true);
#if 0
        sc->assertion = dynamic_cast<saml2::Assertion*>(xobj);
        if (sc->assertion == NULL) {
            fprintf(stderr, "%s\n", typeid(xobj).name());
            delete xobj;
            code = ASN1_PARSE_ERROR;
        }
#else
        sc->assertion = (saml2::Assertion*)((void *)xobj);
#endif
    } catch (XMLToolingException &e) {
        code = ASN1_PARSE_ERROR; /* XXX */
    }

    return code;
}

static krb5_boolean
saml_compare_subject(krb5_context kcontext,
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

    if (krb5_parse_name(kcontext, sname, &sprinc) == 0)
        ret = krb5_principal_compare(kcontext, sprinc, principal);
    else
        ret = FALSE;

    delete sname;

    return ret;
}

static krb5_timestamp
saml_get_authtime(krb5_context kcontext,
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

static krb5_error_code
saml_verify_authdata(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     const krb5_auth_context *auth_context,
                     const krb5_keyblock *key,
                     const krb5_ap_req *req)
{
    krb5_error_code code;
    struct saml_context *sc = (struct saml_context *)request_context;
    krb5_keyblock *skey = req->ticket->enc_part2->session;

    if (sc->assertion == NULL)
        return EINVAL;

    try {
        OpenSSLCryptoKeyHMAC xkey;
        Signature *signature = sc->assertion->getSignature();
        DSIGSignature *dsig = signature->getXMLSignature();

        if (dsig == NULL)
            return KRB5KRB_AP_ERR_BAD_INTEGRITY;

        xkey.setKey(skey->contents, skey->length);

        dsig->setSigningKey(xkey.clone());
        if (dsig->verify())
            code = 0;
        else
            code = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    } catch (XSECException &e) {
        code = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    } catch (XSECCryptoException &e) {
        code = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }

    if (code == 0) {
        krb5_timestamp authtime;

        authtime = req->ticket->enc_part2->times.authtime;

        if (saml_get_authtime(kcontext, sc->assertion) != authtime ||
            saml_compare_subject(kcontext, sc->assertion->getSubject(),
                                 req->ticket->enc_part2->client) == FALSE)
            code = KRB5KRB_AP_WRONG_PRINC;
    }

    sc->verified = (code == 0);

    return 0;
}

static void
saml_request_fini(krb5_context kcontext,
                  krb5_authdata_context context,
                  void *plugin_context,
                  void *request_context)
{
    struct saml_context *sc = (struct saml_context *)request_context;

    if (sc != NULL) {
        delete sc->assertion;
        free(sc);
    }
}

static krb5_error_code
saml_get_attribute_types(krb5_context kcontext,
                         krb5_authdata_context context,
                         void *plugin_context,
                         void *request_context,
                         krb5_data **out_attrs)
{
    krb5_error_code code;
    struct saml_context *sc = (struct saml_context *)request_context;
    saml2::Assertion *token2 = sc->assertion;
    size_t nattrs, i = 0;
    krb5_data *attrs;

    if (token2 == NULL)
        return EINVAL;

    if (token2->getAttributeStatements().size() == 0)
        return ENOENT;

    nattrs = token2->getAttributeStatements().front()->getAttributes().size();

    attrs = (krb5_data *)k5alloc((nattrs + 1) * sizeof(krb5_data), &code);
    if (code != 0)
        return code;

    const vector<saml2::Attribute*>& attrs2 =
        const_cast<const saml2::AttributeStatement*>(token2->getAttributeStatements().front())->getAttributes();
    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin();
        a != attrs2.end();
        ++a)
    {
        krb5_data *d = &attrs[i++];

        d->magic = KV5M_DATA;
        d->data = toUTF8((*a)->getName(), true);
        d->length = strlen(d->data);
    }
    assert(i == nattrs);
    attrs[i].data = NULL;
    attrs[i].length = 0;

    *out_attrs = attrs;

    return 0;
}

static const saml2::Attribute *
saml_get_attribute_object(krb5_context context,
                          struct saml_context *sc,
                          const krb5_data *name)
{
    saml2::Assertion *token2 = sc->assertion;
    auto_ptr_XMLCh desiredName(name->data, name->length);

    if (token2->getAttributeStatements().size() == 0)
        return NULL;

    const vector<saml2::Attribute*>& attrs2 =
        const_cast<const saml2::AttributeStatement*>(token2->getAttributeStatements().front())->getAttributes();

    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin();
        a != attrs2.end();
        ++a) {
        if (XMLString::equals((*a)->getName(), desiredName.get()))
            return (*a);
    }

    return NULL;
}

static int
saml_get_attribute_index(krb5_context context,
                         AttributeStatement *statement,
                         const krb5_data *name)
{
    auto_ptr_XMLCh desiredName(name->data, name->length);
    int index = 0;

    const vector<saml2::Attribute*>& attrs2 =
        const_cast<const saml2::AttributeStatement*>(statement)->getAttributes();

    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin();
        a != attrs2.end();
        ++a) {
        if (XMLString::equals((*a)->getName(), desiredName.get()))
            return index;
        ++index;
    }

    return -1;
}

static krb5_error_code
saml_get_attribute_value(krb5_context context,
                         struct saml_context *sc,
                         const Attribute *attr,
                         krb5_boolean *authenticated,
                         krb5_boolean *complete,
                         krb5_data *value,
                         krb5_data *display_value,
                         int *more)
{
    const AttributeValue *av;
    int nvalues = attr->getAttributeValues().size();

    /*
     * On the first call, *more is -1. If there are more values,
     * it is set to the index of the next value to return. On
     * the last value, it is set to zero.
     */
    if (*more == -1)
        *more = 0;
    else if (*more >= nvalues) {
        *more = 0;
        return ENOENT;
    }

//    av = dynamic_cast<const AttributeValue *>(attr->getAttributeValues().at(*more));
    av = (const AttributeValue *)((void *)attr->getAttributeValues().at(*more));
    if (av == NULL) {
        *more = 0;
        return ENOENT;
    }

    *authenticated = sc->verified; /* XXX */
    *complete = TRUE; /* XXX */

    value->data = toUTF8(av->getTextContent(), true);
    value->length = strlen(value->data);

    display_value->data = toUTF8(av->getTextContent(), true);
    display_value->length = strlen(display_value->data);

    if (nvalues > *more + 1)
        (*more)++;
    else
        *more = 0;

    return 0;
}

static krb5_error_code
saml_get_attribute(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void *request_context,
                   const krb5_data *attribute,
                   krb5_boolean *authenticated,
                   krb5_boolean *complete,
                   krb5_data *value,
                   krb5_data *display_value,
                   int *more)
{
    krb5_error_code code;
    struct saml_context *sc = (struct saml_context *)request_context;
    const Attribute *attr;

    if (sc->assertion == NULL)
        return EINVAL;

    attr = saml_get_attribute_object(kcontext, sc, attribute);
    if (attr == NULL) {
        assert(0);
        return ENOENT;
    }

    code = saml_get_attribute_value(kcontext, sc, attr,
                                    authenticated, complete,
                                    value, display_value, more);

    return code;
}

static krb5_error_code
saml_set_attribute(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void *request_context,
                   krb5_boolean complete,
                   const krb5_data *attribute,
                   const krb5_data *value)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    Attribute *attr;
    AttributeValue *attrValue;
    auto_ptr_XMLCh canonicalName(attribute->data, attribute->length);
    auto_ptr_XMLCh valueString(value->data, value->length);

    attr = AttributeBuilder::buildAttribute();
    attr->setNameFormat(Attribute::URI_REFERENCE);
    attr->setName(canonicalName.get());

    attrValue = AttributeValueBuilder::buildAttributeValue();
    attrValue->setTextContent(valueString.get());

    attr->getAttributeValues().push_back(attrValue);

    if (sc->assertion == NULL) {
        /* XXX this is probably not what we want to be doing */
        AttributeStatement *attrStatement;

        attrStatement = AttributeStatementBuilder::buildAttributeStatement();
        attrStatement->getAttributes().push_back(attr);

        sc->assertion = AssertionBuilder::buildAssertion();
        sc->assertion->getAttributeStatements().push_back(attrStatement);
    }

    return 0;
}

static krb5_error_code
saml_delete_attribute(krb5_context kcontext,
                      krb5_authdata_context context,
                      void *plugin_context,
                      void *request_context,
                      const krb5_data *attribute)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    saml2::Assertion *token2 = sc->assertion;
    auto_ptr_XMLCh desiredName(attribute->data, attribute->length);
    saml2::AttributeStatement *attrStatement;
    int index;

    if (token2 == NULL)
        return ENOENT;

    if (token2->getAttributeStatements().size() == 0)
        return ENOENT;

    attrStatement = (saml2::AttributeStatement *)token2->getAttributeStatements().front();
    index = saml_get_attribute_index(kcontext, attrStatement, attribute);
    if (index == -1)
        return ENOENT;

    attrStatement->getAttributes().erase(
        attrStatement->getAttributes().begin() + index);

    sc->verified = FALSE;

    return 0;
}

static krb5_error_code
saml_size(krb5_context kcontext,
           krb5_authdata_context context,
           void *plugin_context,
           void *request_context,
           size_t *sizep)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    string buf;

    try {
        XMLHelper::serialize(sc->assertion->marshall((DOMDocument *)NULL), buf);
    } catch (XMLToolingException &e) {
        return ASN1_PARSE_ERROR;
    }

    *sizep += sizeof(krb5_int32) + buf.length() + sizeof(krb5_int32);

    return 0;
}

static krb5_error_code
saml_externalize(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void *request_context,
                 krb5_octet **buffer,
                 size_t *lenremain)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    string buf;

    try {
        XMLHelper::serialize(sc->assertion->marshall((DOMDocument *)NULL), buf);
    } catch (XMLToolingException &e) {
        return ASN1_PARSE_ERROR;
    }

    if (*lenremain < sizeof(krb5_int32) + buf.length() + sizeof(krb5_int32))
        return ENOMEM;

    krb5_ser_pack_int32(buf.length(), buffer, lenremain);
    krb5_ser_pack_bytes((krb5_octet *)buf.c_str(), buf.length(),
                        buffer, lenremain);
    krb5_ser_pack_int32((krb5_int32)sc->verified, buffer, lenremain);

    return 0;
}

static krb5_error_code
saml_internalize(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void *request_context,
                 krb5_octet **buffer,
                 size_t *lenremain)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    krb5_error_code code;
    krb5_int32 length;
    krb5_octet *contents = NULL;
    krb5_int32 verified;
    krb5_octet *bp;
    size_t remain;

    bp = *buffer;
    remain = *lenremain;

    code = krb5_ser_unpack_int32(&length, &bp, &remain);
    if (code != 0)
        return code;

    if (length != 0) {
        krb5_authdata ad_datum, *ad_data[2];

        ad_datum.contents = bp;
        ad_datum.length = length;

        ad_data[0] = &ad_datum;
        ad_data[1] = NULL;

        if (remain < (size_t)length)
            return ENOMEM;

        code = saml_import_authdata(kcontext, context,
                                    plugin_context, request_context,
                                    ad_data, FALSE, NULL);
        if (code != 0)
            return code;

        bp += length;
        remain -= length;
    }

    /* Verified */
    code = krb5_ser_unpack_int32(&verified, &bp, &remain);
    if (code != 0) {
        free(contents);
        return code;
    }

    sc->verified = (verified != 0);

    *buffer = bp;
    *lenremain = remain;

    return 0;
}

static krb5_error_code
saml_copy(krb5_context kcontext,
          krb5_authdata_context context,
          void *plugin_context,
          void *request_context,
          void *dst_plugin_context,
          void *dst_request_context)
{
    struct saml_context *src = (struct saml_context *)request_context;
    struct saml_context *dst = (struct saml_context *)dst_request_context;

    if (src->assertion != NULL)
        dst->assertion = (saml2::Assertion *)((void *)src->assertion->clone());
    dst->verified = src->verified;

    assert(dst->assertion != NULL);

    return 0;
}

static krb5_authdatatype saml_ad_types[] = { KRB5_AUTHDATA_SAML, 0 };

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    "saml",
    saml_ad_types,
    saml_init,
    saml_fini,
    saml_flags,
    saml_request_init,
    saml_request_fini,
    saml_get_attribute_types,
    saml_get_attribute,
    saml_set_attribute,
    saml_delete_attribute,
    saml_export_authdata,
    saml_import_authdata,
    NULL,
    NULL,
    saml_verify_authdata,
    saml_size,
    saml_externalize,
    saml_internalize,
    saml_copy
};

/*
 * Copyright (c) 2011, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Portions Copyright 2011 by JANET(UK).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * plugins/authdata/saml_client/saml_authdata.cpp
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
 * Sample authorization data plugin
 */

#include <string.h>
#include <errno.h>

#include "../saml_server/saml_krb.h"

#include <gssapi/gssapi_ext.h>

#include <shibsp/exceptions.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibresolver/resolver.h>

#include <sstream>

using namespace xmlsignature;
using namespace xmlconstants;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace samlconstants;
using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace shibresolver;
using namespace shibsp;
using namespace std;

struct saml_context {
    saml2::Assertion *assertion;
    std::vector<shibsp::Attribute *> attributes;
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
saml_unresolve(krb5_context kcontext,
               struct saml_context *sc);

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
saml_export_internal(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     krb5_boolean restrict_authenticated,
                     void **ptr);

void
saml_free_internal(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void *request_context,
                   void *ptr);

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

static krb5_boolean didShibInit;

static void saml_library_init(void)
{
    if (!didShibInit && SPConfig::getConfig().getFeatures() == 0) {
        ShibbolethResolver::init();
        didShibInit = TRUE;
    }
}

static void saml_library_fini(void)
{
    if (didShibInit) {
        ShibbolethResolver::term();
        didShibInit = FALSE;
    }
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

static krb5_boolean
saml_is_assertion_attr(const krb5_data *attr)
{
    return (attr->length == GSS_C_ATTR_SAML_ASSERTION->length &&
            memcmp(attr->data, GSS_C_ATTR_SAML_ASSERTION->value,
                   GSS_C_ATTR_SAML_ASSERTION->length) == 0);
}

static shibsp::Attribute *
saml_copy_attribute(const shibsp::Attribute *src)
{
    DDF obj = src->marshall();
    shibsp::Attribute *attribute = shibsp::Attribute::unmarshall(obj);
    obj.destroy();

    return attribute;
}

static vector <shibsp::Attribute *>
saml_copy_attributes(const vector <shibsp::Attribute *>src)
{
    vector <shibsp::Attribute *> dst;

    for (vector<shibsp::Attribute *>::const_iterator a = src.begin();
         a != src.end();
         ++a)
        dst.push_back(saml_copy_attribute(*a));

    return dst;
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
    } catch (exception &e) {
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
    struct saml_context *sc = (struct saml_context *)request_context;
    krb5_error_code code;
    saml2::Assertion *assertion;

    code = saml_krb_decode_assertion(kcontext, authdata[0], &assertion);
    if (code == 0) {
        saml_unresolve(kcontext, sc);
        sc->assertion = assertion;
    }

    return code;
}

static void
saml_unresolve(krb5_context kcontext,
               struct saml_context *sc)
{
    for_each(sc->attributes.begin(),
             sc->attributes.end(),
             xmltooling::cleanup<shibsp::Attribute>())
        ;
    sc->attributes.clear();

    delete sc->assertion;
    sc->assertion = NULL;
    sc->verified = FALSE;
}

static void
saml_request_fini(krb5_context kcontext,
                  krb5_authdata_context context,
                  void *plugin_context,
                  void *request_context)
{
    struct saml_context *sc = (struct saml_context *)request_context;

    if (sc != NULL) {
        saml_unresolve(kcontext, sc);
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
    size_t i = 0, nelems;
    krb5_data *attrs;

    nelems = 0;
    if (sc->assertion != NULL)
        nelems++;
    nelems += sc->attributes.size();

    attrs = (krb5_data *)k5alloc((nelems + 1) * sizeof(krb5_data), &code);
    if (code != 0)
        return code;

    if (sc->assertion != NULL) {
        krb5_data saml;

        saml.length = GSS_C_ATTR_SAML_ASSERTION->length;
        saml.data = (char *)GSS_C_ATTR_SAML_ASSERTION->value;

        code = krb5int_copy_data_contents_add0(kcontext, &saml, &attrs[i++]);
        if (code != 0) {
            free(attrs);
            return code;
        }
    }

    for (vector<shibsp::Attribute*>::const_iterator a = sc->attributes.begin();
        a != sc->attributes.end();
        ++a)
    {
        krb5_data s;

        s.data = (char *)(*a)->getId();
        s.length = strlen(s.data);

        code = krb5int_copy_data_contents_add0(kcontext, &s, &attrs[i++]);
        if (code != 0)
            break;
    }

    attrs[i].data = NULL;
    attrs[i].length = 0;

    *out_attrs = attrs;

    return code;
}

static const shibsp::Attribute *
saml_get_attribute_object(krb5_context context,
                          struct saml_context *sc,
                          const krb5_data *attr)
{
    const shibsp::Attribute *ret = NULL;

    for (vector<shibsp::Attribute *>::const_iterator a = sc->attributes.begin();
         a != sc->attributes.end();
         ++a)
    {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attr->length == (*s).length() &&
                memcmp((*s).c_str(), attr->data, attr->length) == 0) {
                ret = *a;
                break;
            }
        }
        if (ret != NULL)
            break;
    }

    return ret;
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
    const shibsp::Attribute *attr;
    int nvalues, i = *more;
    krb5_data data;

    *more = 0;

    if (saml_is_assertion_attr(attribute)) {
        string buf;

        if (sc->assertion == NULL)
            return ENOENT;

        try {
            XMLHelper::serialize(sc->assertion->marshall((DOMDocument *)NULL), buf);
            data.length = buf.length();
            data.data = (char *)buf.c_str();
            nvalues = 1;
            code = 0;
        } catch (exception &e) {
           return ASN1_PARSE_ERROR;
        }
    } else {
        attr = saml_get_attribute_object(kcontext, sc, attribute);
        if (attr == NULL)
            return ENOENT;

        nvalues = attr->valueCount();
        if (i == -1)
            i = 0;
        if (i >= nvalues)
            return ENOENT;

        data.data = (char *)attr->getSerializedValues()[*more].c_str();
        data.length = strlen(data.data);
    }

    if (data.length != 0) {
        if (value != NULL) {
            code = krb5int_copy_data_contents_add0(kcontext, &data, value);
            if (code != 0)
                return code;
        }
        if (display_value != NULL) {
            code = krb5int_copy_data_contents_add0(kcontext, &data, display_value);
            if (code != 0)
                return code;
        }
    }

    if (authenticated != NULL)
        *authenticated = sc->verified;
    if (complete != NULL)
        *complete = FALSE;

    if (nvalues > ++i)
        *more = i;

    return 0;
}

static ssize_t
saml_get_attribute_index(krb5_context kcontext,
                         struct saml_context *sc,
                         const krb5_data *attribute)
{
    int i = 0;

    for (vector<shibsp::Attribute *>::const_iterator a = sc->attributes.begin();
         a != sc->attributes.end();
         ++a)
    {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attribute->length == (*s).length() &&
                memcmp((*s).c_str(), attribute->data, attribute->length) == 0) {
                return i;
            }
        }
    }

    return -1;
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
    krb5_error_code code;

    if (saml_is_assertion_attr(attribute)) {
        saml2::Assertion *assertion;
        krb5_authdata ad_datum;

        ad_datum.ad_type = KRB5_AUTHDATA_SAML;
        ad_datum.length = value->length;
        ad_datum.contents = (krb5_octet *)value->data;

        code = saml_krb_decode_assertion(kcontext, &ad_datum, &assertion);
        if (code != 0)
            return code;

        saml_unresolve(kcontext, sc);
        sc->assertion = assertion;
    } else {
        string attrStr(attribute->data, attribute->length);
        vector <string> ids(1, attrStr);
        shibsp::SimpleAttribute *attr = new SimpleAttribute(ids);

        if (value->length != 0) {
            string valueStr(value->data, value->length);
            attr->getValues().push_back(valueStr);
        }

        sc->attributes.push_back(attr);
        sc->verified = FALSE;
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
    int i;

    if (saml_is_assertion_attr(attribute)) {
        saml_unresolve(kcontext, sc);
    } else {
        i = saml_get_attribute_index(kcontext, sc, attribute);
        if (i >= 0)
            sc->attributes.erase(sc->attributes.begin() + i);
        sc->verified = FALSE;
    }

    return 0;
}

static krb5_error_code
saml_export_internal(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context,
                     krb5_boolean restrict_authenticated,
                     void **ptr)
{
    struct saml_context *sc = (struct saml_context *)request_context;

    if (sc->assertion == NULL)
        return ENOENT;

    *ptr = (void *)(sc->assertion->clone());

    return 0;
}

void
saml_free_internal(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void *request_context,
                   void *ptr)
{
    delete (saml2::Assertion *)ptr;
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
    krb5_enc_tkt_part *enc_part = req->ticket->enc_part2;

    code = saml_krb_verify(kcontext,
                           sc->assertion,
                           enc_part->session,
                           enc_part->client,
                           NULL,
                           req->ticket->server,
                           enc_part->times.authtime,
                           SAML_KRB_VERIFY_SESSION_KEY | SAML_KRB_VERIFY_TRUSTENGINE,
                           &sc->verified);
    /* Squash KDC error codes */
    switch (code) {
    case KRB5KDC_ERR_CLIENT_NAME_MISMATCH:
    case KRB5KDC_ERR_CLIENT_NOT_TRUSTED:
    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
    case KRB5KDC_ERR_CLIENT_NOTYET:
        code = KRB5KRB_AP_WRONG_PRINC;
        break;
    }

    if (code == 0) {
        auto_ptr<ShibbolethResolver> resolver(ShibbolethResolver::create());

        try {
            resolver->addToken(sc->assertion);
            resolver->resolve();
            sc->attributes = resolver->getResolvedAttributes();
            resolver->getResolvedAttributes().clear();
        } catch (exception &e) {
        }
    }

    return code;
}

static krb5_error_code
saml_size(krb5_context kcontext,
           krb5_authdata_context context,
           void *plugin_context,
           void *request_context,
           size_t *sizep)
{
    struct saml_context *sc = (struct saml_context *)request_context;
    string assertion;
    ostringstream sink;
    DDF attrs(NULL);

    try {
        if (sc->assertion != NULL)
            XMLHelper::serialize(sc->assertion->marshall((DOMDocument *)NULL), assertion);
        for (vector<shibsp::Attribute *>::const_iterator a = sc->attributes.begin();
            a != sc->attributes.end(); ++a) {
            DDF attr = (*a)->marshall();
            attrs.add(attr);
        }
        sink << attrs;
    } catch (exception &e) {
        return ASN1_PARSE_ERROR;
    }

    sink << attrs;

    *sizep += sizeof(krb5_int32) + assertion.length() +
        sizeof(krb5_int32) + sink.str().length() +
        sizeof(krb5_int32);

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
    string assertion;
    DDF attrs(NULL);
    ostringstream sink;

    try {
        if (sc->assertion != NULL)
            XMLHelper::serialize(sc->assertion->marshall((DOMDocument *)NULL), assertion);
        if (sc->attributes.size()) {
            for (vector<shibsp::Attribute *>::const_iterator a = sc->attributes.begin();
                a != sc->attributes.end(); ++a) {
                DDF attr = (*a)->marshall();
                attrs.add(attr);
            }
            sink << attrs;
        }
    } catch (exception &e) {
        return ASN1_PARSE_ERROR;
    }

    string attributes(sink.str());

    if (*lenremain < sizeof(krb5_int32) + assertion.length() +
        sizeof(krb5_int32) + attributes.length() +
        sizeof(krb5_int32))
        return ENOMEM;

    krb5_ser_pack_int32(assertion.length(), buffer, lenremain);
    krb5_ser_pack_bytes((krb5_octet *)assertion.c_str(), assertion.length(),
                        buffer, lenremain);
    krb5_ser_pack_int32(attributes.length(), buffer, lenremain);
    krb5_ser_pack_bytes((krb5_octet *)attributes.c_str(), attributes.length(),
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

        ad_datum.ad_type = KRB5_AUTHDATA_SAML;
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

    code = krb5_ser_unpack_int32(&length, &bp, &remain);
    if (code != 0)
        return code;

    if (length != 0) {
        string str((char *)bp, length);
        istringstream source(str);
        DDF attrs(NULL);

        source >> attrs;

        DDF attr = attrs.first();
        while (!attr.isnull()) {
            shibsp::Attribute *attribute = shibsp::Attribute::unmarshall(attr);
            sc->attributes.push_back(attribute);
            attr = attrs.next();
        }
        attrs.destroy();

        bp += length;
        remain -= length;
    }

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

    if (src->attributes.size() != 0)
        dst->attributes = saml_copy_attributes(src->attributes);

    dst->verified = src->verified;

    return 0;
}

static krb5_authdatatype saml_ad_types[] = { KRB5_AUTHDATA_SAML, 0 };

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    (char *)"saml",
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
    saml_export_internal,
    saml_free_internal,
    saml_verify_authdata,
    saml_size,
    saml_externalize,
    saml_internalize,
    saml_copy
};

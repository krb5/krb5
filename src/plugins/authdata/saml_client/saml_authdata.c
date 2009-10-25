/*
 * plugins/authdata/saml_client/
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
#include "k5-int.h"
#include <krb5/authdata_plugin.h>
#include <assert.h>

struct saml_context {
    krb5_data data;
    krb5_boolean verified;
};

static krb5_data saml_attr = {
    KV5M_DATA, sizeof("urn:saml") - 1, "urn:saml" };

static krb5_error_code
saml_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = 0;
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
    return;
}

static krb5_error_code
saml_request_init(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void **request_context)
{
    struct saml_context *sc;

    sc = malloc(sizeof(*sc));
    if (sc == NULL)
        return ENOMEM;

    sc->data.data = NULL;
    sc->data.length = 0;
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
    krb5_error_code code;

    datum.ad_type = KRB5_AUTHDATA_SAML;
    datum.length = sc->data.length;
    datum.contents = (krb5_octet *)sc->data.data;

    data[0] = &datum;
    data[1] = NULL;

    code = krb5_copy_authdata(kcontext, data, out_authdata);

    return code;
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
    krb5_error_code code;
    struct saml_context *sc = (struct saml_context *)request_context;
    krb5_data data;

    krb5_free_data_contents(kcontext, &sc->data);
    sc->verified = FALSE;

    assert(authdata[0] != NULL);

    data.length = authdata[0]->length;
    data.data = (char *)authdata[0]->contents;

    code = krb5int_copy_data_contents_add0(kcontext, &data, &sc->data);
    if (code == 0)
        sc->verified = kdc_issued_flag;

    return code;
}

static void
saml_request_fini(krb5_context kcontext,
                   krb5_authdata_context context,
                   void *plugin_context,
                   void *request_context)
{
    struct saml_context *sc = (struct saml_context *)request_context;

    if (sc != NULL) {
        krb5_free_data_contents(kcontext, &sc->data);
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

    if (sc->data.length == 0)
        return ENOENT;

    *out_attrs = calloc(2, sizeof(krb5_data));
    if (*out_attrs == NULL)
        return ENOMEM;

    code = krb5int_copy_data_contents_add0(kcontext,
                                           &saml_attr,
                                           &(*out_attrs)[0]);
    if (code != 0) {
        free(*out_attrs);
        *out_attrs = NULL;
        return code;
    }

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
    struct saml_context *sc = (struct saml_context *)request_context;
    krb5_error_code code;

    if (!data_eq(*attribute, saml_attr) || sc->data.length == 0)
        return ENOENT;

    *authenticated = sc->verified;
    *complete = TRUE;
    *more = 0;

    code = krb5int_copy_data_contents_add0(kcontext, &sc->data, value);
    if (code == 0) {
        code = krb5int_copy_data_contents_add0(kcontext,
                                               &sc->data,
                                               display_value);
        if (code != 0)
            krb5_free_data_contents(kcontext, value);
    }

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
    krb5_data data;
    krb5_error_code code;

    if (sc->data.data != NULL)
        return EEXIST;

    code = krb5int_copy_data_contents_add0(kcontext, value, &data);
    if (code != 0)
        return code;

    krb5_free_data_contents(kcontext, &sc->data);
    sc->data = data;
    sc->verified = FALSE;

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

    krb5_free_data_contents(kcontext, &sc->data);
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

    *sizep += sizeof(krb5_int32) +
              sc->data.length +
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
    size_t required = 0;
    struct saml_context *sc = (struct saml_context *)request_context;

    saml_size(kcontext, context, plugin_context,
               request_context, &required);

    if (*lenremain < required)
        return ENOMEM;

    krb5_ser_pack_int32(sc->data.length, buffer, lenremain);
    krb5_ser_pack_bytes((krb5_octet *)sc->data.data,
                        (size_t)sc->data.length,
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
        contents = malloc(length);
        if (contents == NULL)
            return ENOMEM;

        code = krb5_ser_unpack_bytes(contents, (size_t)length, &bp, &remain);
        if (code != 0) {
            free(contents);
            return code;
        }
    }

    /* Verified */
    code = krb5_ser_unpack_int32(&verified, &bp, &remain);
    if (code != 0) {
        free(contents);
        return code;
    }

    krb5_free_data_contents(kcontext, &sc->data);
    sc->data.length = length;
    sc->data.data = (char *)contents;
    sc->verified = (verified != 0);

    *buffer = bp;
    *lenremain = remain;

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
    NULL,
    saml_size,
    saml_externalize,
    saml_internalize,
    NULL
};

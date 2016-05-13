/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/krb5/krb/ai_authdata.c - Auth indicator AD backend */
/*
 * Copyright (C) 2016 by the Massachusetts Institute of Technology.
 * Copyright (C) 2016 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Authdata backend for authentication indicators.
 */

#include "k5-int.h"
#include "authdata.h"
#include "auth_con.h"
#include "int-proto.h"

struct authind_context {
    krb5_data **indicators;      /* Decoded. */
    int count;
};

static krb5_error_code
authind_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
authind_flags(krb5_context kcontext, void *plugin_context,
              krb5_authdatatype ad_type, krb5_flags *flags)
{
    *flags = AD_CAMMAC_PROTECTED;
}

static krb5_error_code
authind_request_init(krb5_context kcontext, krb5_authdata_context context,
                     void *plugin_context, void **request_context)
{
    krb5_error_code ret = 0;
    struct authind_context *aictx;

    aictx = k5alloc(sizeof(*aictx), &ret);
    if (aictx == NULL)
        return ret;

    aictx->indicators = NULL;
    aictx->count = 0;

    *request_context = aictx;

    return ret;
}

static krb5_error_code
authind_import_authdata(krb5_context kcontext, krb5_authdata_context context,
                        void *plugin_context, void *request_context,
                        krb5_authdata **authdata, krb5_boolean kdc_issued,
                        krb5_const_principal kdc_issuer)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret = 0;
    krb5_data **indps;
    int count, i;

    /* Explicitly set to NULL for k5_authind_decode(). */
    indps = NULL;

    for (i = 0; authdata != NULL && authdata[i] != NULL; i++) {
        ret = k5_authind_decode(authdata[i], &indps);
        if (ret)
            goto cleanup;
    }

    for (count = 0; indps != NULL && indps[count] != NULL; count++);

    if (count != 0) {
        aictx->indicators = indps;
        aictx->count = count;
        indps = NULL;
    }

cleanup:
    k5_free_data_ptr_list(indps);
    return ret;
}

static void
authind_request_fini(krb5_context kcontext, krb5_authdata_context context,
                     void *plugin_context, void *request_context)
{
    struct authind_context *aictx = (struct authind_context *)request_context;

    if (aictx != NULL) {
        k5_free_data_ptr_list(aictx->indicators);
        free(aictx);
    }
}

/* This is a non-URI "local attribute" that is implementation defined. */
static krb5_data authind_attr = {
    KV5M_DATA,
    sizeof("auth-indicators") - 1,
    "auth-indicators"
};

static krb5_error_code
authind_get_attribute_types(krb5_context kcontext,
                            krb5_authdata_context context,
                            void *plugin_context, void *request_context,
                            krb5_data **out_attrs)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_data *attrs;

    *out_attrs = NULL;

    if (aictx->count == 0)
        return ENOENT;

    attrs = k5calloc(2, sizeof(*attrs), &ret);
    if (attrs == NULL)
        return ENOMEM;

    ret = krb5int_copy_data_contents(kcontext, &authind_attr, &attrs[0]);
    if (ret)
        goto cleanup;

    attrs[1].data = NULL;
    attrs[1].length = 0;

    *out_attrs = attrs;
    attrs = NULL;

cleanup:
    krb5int_free_data_list(kcontext, attrs);
    return ret;
}

static krb5_error_code
authind_get_attribute(krb5_context kcontext, krb5_authdata_context context,
                      void *plugin_context, void *request_context,
                      const krb5_data *attribute, krb5_boolean *authenticated,
                      krb5_boolean *complete, krb5_data *value,
                      krb5_data *display_value, int *more)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_data *value_out;
    int left;

    if (!data_eq(*attribute, authind_attr))
        return ENOENT;

    /* The caller should set more to -1 before the first call.  Successive
     * calls return the number of indicators left, ending at 0. */
    if (*more < 0)
        left = aictx->count;
    else
        left = *more;

    if (left <= 0)
        return ENOENT;
    else if (left > aictx->count)
        return EINVAL;

    ret = krb5_copy_data(kcontext, aictx->indicators[aictx->count - left],
                         &value_out);
    if (ret)
        return ret;

    *more = left - 1;
    *value = *value_out;
    /* Indicators are delivered in a CAMMAC verified outside of this module,
     * so these are authenticated values. */
    *authenticated = TRUE;
    *complete = TRUE;

    free(value_out);
    return ret;
}

static krb5_error_code
authind_set_attribute(krb5_context kcontext, krb5_authdata_context context,
                      void *plugin_context, void *request_context,
                      krb5_boolean complete, const krb5_data *attribute,
                      const krb5_data *value)
{
    /* Indicators are imported from ticket authdata, not set by this module. */
    if (!data_eq(*attribute, authind_attr))
        return ENOENT;

    return EPERM;
}

static krb5_error_code
authind_size(krb5_context kcontext, krb5_authdata_context context,
             void *plugin_context, void *request_context, size_t *sizep)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret = 0;
    int i;

    /* Indicator count. */
    *sizep += sizeof(krb5_int32);

    for (i = 0; i < aictx->count; i++) {
        /* Length + indicator size. */
        *sizep += sizeof(krb5_int32) + (size_t)aictx->indicators[i]->length;
    }

    return ret;
}

static krb5_error_code
authind_externalize(krb5_context kcontext, krb5_authdata_context context,
                    void *plugin_context, void *request_context,
                    krb5_octet **buffer, size_t *lenremain)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret = 0;
    size_t required = 0;
    uint8_t *bp;
    size_t remain;
    int i;

    bp = (uint8_t *)*buffer;
    remain = *lenremain;

    authind_size(kcontext, context, plugin_context, request_context,
                 &required);

    if (required > remain)
        return ENOMEM;

    /* Indicator count. */
    krb5_ser_pack_int32(aictx->count, &bp, &remain);

    for (i = 0; i < aictx->count; i++) {
        /* Length + indicator. */
        krb5_ser_pack_int32(aictx->indicators[i]->length, &bp, &remain);
        ret = krb5_ser_pack_bytes((krb5_octet *)aictx->indicators[i]->data,
                                  (size_t)aictx->indicators[i]->length,
                                  &bp, &remain);
        if (ret)
            return ret;
    }

    *buffer = bp;
    *lenremain = remain;

    return ret;
}


static krb5_error_code
authind_internalize(krb5_context kcontext, krb5_authdata_context context,
                    void *plugin_context, void *request_context,
                    krb5_octet **buffer, size_t *lenremain)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code ret;
    krb5_int32 count, len;
    uint8_t *bp;
    size_t remain;
    krb5_data **inds = NULL;
    int i;

    bp = (uint8_t *)*buffer;
    remain = *lenremain;

    /* Get the count. */
    ret = krb5_ser_unpack_int32(&count, &bp, &remain);
    if (ret)
        return ret;

    if (count > (krb5_int32)remain)
        return ERANGE;

    inds = k5calloc(count, sizeof(*inds), &ret);
    if (inds == NULL)
        return errno;

    for (i = 0; i < count; i++) {
        /* Get the length. */
        ret = krb5_ser_unpack_int32(&len, &bp, &remain);
        if (ret)
            goto cleanup;

        if (len > (krb5_int32)remain) {
            ret = ERANGE;
            goto cleanup;
        }

        inds[i] = k5alloc(sizeof(*(inds[i])), &ret);
        if (inds[i] == NULL)
            goto cleanup;

        ret = alloc_data(inds[i], len);
        if (ret)
            goto cleanup;

        /* Get the indicator. */
        ret = krb5_ser_unpack_bytes((krb5_octet *)inds[i]->data, (size_t)len,
                                    &bp, &remain);
        if (ret)
            goto cleanup;
    }

    k5_free_data_ptr_list(aictx->indicators);

    aictx->count = (int)count;
    aictx->indicators = inds;
    inds = NULL;

    *buffer = bp;
    *lenremain = remain;

cleanup:
    k5_free_data_ptr_list(inds);
    return ret;
}

static krb5_authdatatype authind_ad_types[] = {
    KRB5_AUTHDATA_AUTH_INDICATOR, 0
};

krb5plugin_authdata_client_ftable_v0 k5_authind_ad_client_ftable = {
    "authentication-indicators",
    authind_ad_types,
    authind_init,
    NULL, /* fini */
    authind_flags,
    authind_request_init,
    authind_request_fini,
    authind_get_attribute_types,
    authind_get_attribute,
    authind_set_attribute,
    NULL, /* delete_attribute_proc */
    NULL, /* export_authdata */
    authind_import_authdata,
    NULL, /* export_internal */
    NULL, /* free_internal */
    NULL, /* verify */
    authind_size,
    authind_externalize,
    authind_internalize,
    NULL /* authind_copy */
};

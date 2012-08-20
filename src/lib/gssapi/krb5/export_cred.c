/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/gssapi/krb5/export_cred.c - krb5 export_cred implementation */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
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

#include "k5-int.h"
#include "k5-json.h"
#include "gssapiP_krb5.h"

/* Add v to array and then release it.  Return -1 if v is NULL. */
static int
add(k5_json_array array, k5_json_value v)
{
    if (v == NULL || k5_json_array_add(array, v))
        return -1;
    k5_json_release(v);
    return 0;
}

/* Return a JSON null or string value representing str. */
static k5_json_value
json_optional_string(const char *str)
{
    return (str == NULL) ? (k5_json_value)k5_json_null_create() :
        (k5_json_value)k5_json_string_create(str);
}

/* Return a JSON null or array value representing princ. */
static k5_json_value
json_principal(krb5_context context, krb5_principal princ)
{
    char *princname;
    k5_json_string str;

    if (princ == NULL)
        return k5_json_null_create();
    if (krb5_unparse_name(context, princ, &princname))
        return NULL;
    str = k5_json_string_create(princname);
    krb5_free_unparsed_name(context, princname);
    return str;
}

/* Return a json null or array value representing etypes. */
static k5_json_value
json_etypes(krb5_enctype *etypes)
{
    k5_json_array array;

    if (etypes == NULL)
        return k5_json_null_create();
    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    for (; *etypes != 0; etypes++) {
        if (add(array, k5_json_number_create(*etypes)))
            goto oom;
    }
    return array;
oom:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON null or array value representing name. */
static k5_json_value
json_kgname(krb5_context context, krb5_gss_name_t name)
{
    k5_json_array array;

    if (name == NULL)
        return k5_json_null_create();
    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    if (add(array, json_principal(context, name->princ)))
        goto oom;
    if (add(array, json_optional_string(name->service)))
        goto oom;
    if (add(array, json_optional_string(name->host)))
        goto oom;
    return array;
oom:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON null or string value representing keytab. */
static k5_json_value
json_keytab(krb5_context context, krb5_keytab keytab)
{
    char name[1024];

    if (keytab == NULL)
        return k5_json_null_create();
    if (krb5_kt_get_name(context, keytab, name, sizeof(name)))
        return NULL;
    return k5_json_string_create(name);
}

/* Return a JSON null or string value representing rcache. */
static k5_json_value
json_rcache(krb5_context context, krb5_rcache rcache)
{
    char *name;
    k5_json_string str;

    if (rcache == NULL)
        return k5_json_null_create();
    if (asprintf(&name, "%s:%s", krb5_rc_get_type(context, rcache),
                 krb5_rc_get_name(context, rcache)) < 0)
        return NULL;
    str = k5_json_string_create(name);
    free(name);
    return str;
}

/* Return a JSON array value representing keyblock. */
static k5_json_value
json_keyblock(krb5_keyblock *keyblock)
{
    k5_json_array array;

    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    if (add(array, k5_json_number_create(keyblock->enctype)))
        goto oom;
    if (add(array, k5_json_string_create_base64(keyblock->contents,
                                                keyblock->length)))
        goto oom;
    return array;
oom:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON array value representing addr. */
static k5_json_value
json_address(krb5_address *addr)
{
    k5_json_array array;

    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    if (add(array, k5_json_number_create(addr->addrtype)))
        goto oom;
    if (add(array, k5_json_string_create_base64(addr->contents, addr->length)))
        goto oom;
    return array;
oom:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON null or array value representing addrs. */
static k5_json_value
json_addresses(krb5_address **addrs)
{
    k5_json_array array;

    if (addrs == NULL)
        return k5_json_null_create();
    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    for (; *addrs != NULL; addrs++) {
        if (add(array, json_address(*addrs))) {
            k5_json_release(array);
            return NULL;
        }
    }
    return array;
}

/* Return a JSON array value representing ad. */
static k5_json_value
json_authdata_element(krb5_authdata *ad)
{
    k5_json_array array;

    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    if (add(array, k5_json_number_create(ad->ad_type)))
        goto oom;
    if (add(array, k5_json_string_create_base64(ad->contents, ad->length)))
        goto oom;
    return array;
oom:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON null or array value representing authdata. */
static k5_json_value
json_authdata(krb5_authdata **authdata)
{
    k5_json_array array;

    if (authdata == NULL)
        return k5_json_null_create();
    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    for (; *authdata != NULL; authdata++) {
        if (add(array, json_authdata_element(*authdata))) {
            k5_json_release(array);
            return NULL;
        }
    }
    return array;
}

/* Return a JSON array value representing creds. */
static k5_json_value
json_creds(krb5_context context, krb5_creds *creds)
{
    k5_json_array array;

    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    if (add(array, json_principal(context, creds->client)))
        goto eom;
    if (add(array, json_principal(context, creds->server)))
        goto eom;
    if (add(array, json_keyblock(&creds->keyblock)))
        goto eom;
    if (add(array, k5_json_number_create(creds->times.authtime)))
        goto eom;
    if (add(array, k5_json_number_create(creds->times.starttime)))
        goto eom;
    if (add(array, k5_json_number_create(creds->times.endtime)))
        goto eom;
    if (add(array, k5_json_number_create(creds->times.renew_till)))
        goto eom;
    if (add(array, k5_json_bool_create(creds->is_skey)))
        goto eom;
    if (add(array, k5_json_number_create(creds->ticket_flags)))
        goto eom;
    if (add(array, json_addresses(creds->addresses)))
        goto eom;
    if (add(array, k5_json_string_create_base64(creds->ticket.data,
                                                creds->ticket.length)))
        goto eom;
    if (add(array, k5_json_string_create_base64(creds->second_ticket.data,
                                                creds->second_ticket.length)))
        goto eom;
    if (add(array, json_authdata(creds->authdata)))
        goto eom;
    return array;
eom:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON array value representing the contents of ccache. */
static k5_json_value
json_ccache_contents(krb5_context context, krb5_ccache ccache)
{
    krb5_error_code ret;
    krb5_principal princ;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    k5_json_array array;
    int st;

    array = k5_json_array_create();
    if (array == NULL)
        return NULL;

    /* Put the principal in the first array entry. */
    if (krb5_cc_get_principal(context, ccache, &princ))
        goto err;
    st = add(array, json_principal(context, princ));
    krb5_free_principal(context, princ);
    if (st)
        goto err;

    /* Put credentials in the remaining array entries. */
    if (krb5_cc_start_seq_get(context, ccache, &cursor))
        goto err;
    while ((ret = krb5_cc_next_cred(context, ccache, &cursor, &creds)) == 0) {
        if (add(array, json_creds(context, &creds))) {
            krb5_free_cred_contents(context, &creds);
            break;
        }
        krb5_free_cred_contents(context, &creds);
    }
    krb5_cc_end_seq_get(context, ccache, &cursor);
    if (ret != KRB5_CC_END)
        goto err;
    return array;

err:
    k5_json_release(array);
    return NULL;
}

/* Return a JSON null, string, or array value representing ccache. */
static k5_json_value
json_ccache(krb5_context context, krb5_ccache ccache)
{
    char *name;
    k5_json_string str;

    if (ccache == NULL)
        return k5_json_null_create();
    if (strcmp(krb5_cc_get_type(context, ccache), "MEMORY") == 0) {
        return json_ccache_contents(context, ccache);
    } else {
        if (krb5_cc_get_full_name(context, ccache, &name))
            return NULL;
        str = k5_json_string_create(name);
        free(name);
        return str;
    }
}

/* Return a JSON array value representing cred. */
static k5_json_value
json_kgcred(krb5_context context, krb5_gss_cred_id_t cred)
{
    k5_json_array array;

    array = k5_json_array_create();
    if (array == NULL)
        return NULL;
    if (add(array, k5_json_number_create(cred->usage)))
        goto oom;
    if (add(array, json_kgname(context, cred->name)))
        goto oom;
    if (add(array, json_principal(context, cred->impersonator)))
        goto oom;
    if (add(array, k5_json_bool_create(cred->default_identity)))
        goto oom;
    if (add(array, k5_json_bool_create(cred->iakerb_mech)))
        goto oom;
    /* Don't marshal cred->destroy_ccache. */
    if (add(array, json_keytab(context, cred->keytab)))
        goto oom;
    if (add(array, json_rcache(context, cred->rcache)))
        goto oom;
    if (add(array, json_ccache(context, cred->ccache)))
        goto oom;
    if (add(array, json_keytab(context, cred->client_keytab)))
        goto oom;
    if (add(array, k5_json_bool_create(cred->have_tgt)))
        goto oom;
    if (add(array, k5_json_number_create(cred->expire)))
        goto oom;
    if (add(array, k5_json_number_create(cred->refresh_time)))
        goto oom;
    if (add(array, json_etypes(cred->req_enctypes)))
        goto oom;
    if (add(array, json_optional_string(cred->password)))
        goto oom;
    return array;
oom:
    k5_json_release(array);
    return NULL;
}

OM_uint32 KRB5_CALLCONV
krb5_gss_export_cred(OM_uint32 *minor_status, gss_cred_id_t cred_handle,
                     gss_buffer_t token)
{
    OM_uint32 status = GSS_S_COMPLETE;
    krb5_context context;
    krb5_error_code ret;
    krb5_gss_cred_id_t cred;
    k5_json_array array = NULL;
    char *str = NULL;
    krb5_data d;

    ret = krb5_gss_init_context(&context);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }

    /* Validate and lock cred_handle. */
    status = krb5_gss_validate_cred_1(minor_status, cred_handle, context);
    if (status != GSS_S_COMPLETE)
        return status;
    cred = (krb5_gss_cred_id_t)cred_handle;

    array = k5_json_array_create();
    if (array == NULL)
        goto oom;
    if (add(array, k5_json_string_create(CRED_EXPORT_MAGIC)))
        goto oom;
    if (add(array, json_kgcred(context, cred)))
        goto oom;

    str = k5_json_encode(array);
    if (str == NULL)
        goto oom;
    d = string2data(str);
    if (data_to_gss(&d, token))
        goto oom;
    str = NULL;

cleanup:
    free(str);
    k5_mutex_unlock(&cred->lock);
    k5_json_release(array);
    krb5_free_context(context);
    return status;

oom:
    *minor_status = ENOMEM;
    status = GSS_S_FAILURE;
    goto cleanup;
}

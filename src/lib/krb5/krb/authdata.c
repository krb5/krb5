/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Copyright 2009 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
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
 */

#include "k5-int.h"
#include "authdata.h"
#include "auth_con.h"

/* Loosely based on preauth2.c */

static const char *objdirs[] = {
#if TARGET_OS_MAC
    KRB5_AUTHDATA_PLUGIN_BUNDLE_DIR,
#endif
    LIBDIR "/krb5/plugins/authdata",
    NULL
 }; /* should be a list */

/* Internal authdata systems */
static krb5plugin_authdata_client_ftable_v0 *authdata_systems[] = {
    &krb5int_mspac_authdata_client_ftable,
    NULL
};

static inline int
k5_ad_module_count(krb5plugin_authdata_client_ftable_v0 *table)
{
    int i;

    if (table->ad_type_list == NULL)
        return 0;

    for (i = 0; table->ad_type_list[i]; i++)
        ;

    return i;
}

static krb5_error_code
k5_ad_init_modules(krb5_context kcontext,
                   krb5_authdata_context context,
                   krb5plugin_authdata_client_ftable_v0 *table,
                   int *module_count)
{
    int j, k = *module_count;
    krb5_error_code code;
    void *plugin_context = NULL;
    void **rcpp;

    if (table->ad_type_list == NULL) {
#ifdef DEBUG
        fprintf(stderr, "warning: module \"%s\" does not advertise "
                "any AD types\n", table->name);
#endif
        return ENOENT;
    }

    if (table->init == NULL)
        return ENOSYS;

    code = (*table->init)(kcontext, &plugin_context);
    if (code != 0) {
#ifdef DEBUG
        fprintf(stderr, "warning: skipping module \"%s\" which "
                "failed to initialize\n", table->name);
#endif
        return code;
    }

    for (j = 0; table->ad_type_list[j] != 0; j++) {
        context->modules[k].ad_type = table->ad_type_list[j];
        context->modules[k].plugin_context = plugin_context;
        if (j == 0)
            context->modules[k].client_fini = table->fini;
        else
            context->modules[k].client_fini = NULL;
        context->modules[k].ftable = table;
        context->modules[k].name = table->name;
        if (table->flags != NULL) {
            (*table->flags)(kcontext, plugin_context,
                            context->modules[k].ad_type,
                            &context->modules[k].flags);
        } else {
            context->modules[k].flags = 0;
        }
        context->modules[k].request_context = NULL;
        if (j == 0) {
            context->modules[k].client_req_init = table->request_init;
            context->modules[k].client_req_fini = table->request_fini;
            rcpp = &context->modules[k].request_context;

            /* For now, single request per context. That may change */
            code = (*table->request_init)(kcontext,
                                          context,
                                          plugin_context,
                                          rcpp);
            if ((code != 0 && code != ENOMEM) &&
                (context->modules[k].flags & AD_INFORMATIONAL))
                code = 0;
            if (code != 0)
                break;
        } else {
            context->modules[k].client_req_init = NULL;
            context->modules[k].client_req_fini = NULL;
        }
        context->modules[k].request_context_pp = rcpp;

#ifdef DEBUG
        fprintf(stderr, "init module \"%s\", ad_type %d, flags %08x\n",
                context->modules[k].name,
                context->modules[k].ad_type,
                context->modules[k].flags);
#endif
        k++;
    }
    *module_count = k;

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_context_init(krb5_context kcontext,
                           krb5_authdata_context *pcontext)
{
    int n_modules, n_tables, i, k;
    void **tables = NULL;
    krb5plugin_authdata_client_ftable_v0 *table;
    krb5_authdata_context context = NULL;
    int internal_count = 0;
    struct plugin_dir_handle plugins;
    krb5_error_code code;

    *pcontext = NULL;
    memset(&plugins, 0, sizeof(plugins));

    n_modules = 0;
    for (n_tables = 0; authdata_systems[n_tables] != NULL; n_tables++) {
        n_modules += k5_ad_module_count(authdata_systems[n_tables]);
    }
    internal_count = n_tables;

    if (PLUGIN_DIR_OPEN(&plugins) == 0 &&
        krb5int_open_plugin_dirs(objdirs, NULL,
                                 &plugins,
                                 &kcontext->err) == 0 &&
        krb5int_get_plugin_dir_data(&plugins,
                                    "authdata_client_0",
                                    &tables,
                                    &kcontext->err) == 0 &&
        tables != NULL)
    {
        for (; tables[n_tables - internal_count] != NULL; n_tables++) {
            table = tables[n_tables - internal_count];
            n_modules += k5_ad_module_count(table);
        }
    }

    context = calloc(1, sizeof(*context));
    if (kcontext == NULL) {
        if (tables != NULL)
            krb5int_free_plugin_dir_data(tables);
        krb5int_close_plugin_dirs(&context->plugins);
        return ENOMEM;
    }
    context->modules = calloc(n_modules, sizeof(context->modules[0]));
    if (context->modules == NULL) {
        if (tables != NULL)
            krb5int_free_plugin_dir_data(tables);
        krb5int_close_plugin_dirs(&context->plugins);
        free(kcontext);
        return ENOMEM;
    }
    context->n_modules = n_modules;

    /* fill in the structure */
    for (i = 0, k = 0, code = 0; i < n_tables - internal_count; i++) {
        code = k5_ad_init_modules(kcontext, context, tables[i], &k);
        if (code != 0)
            break;
    }

    if (code == 0) {
        for (i = 0; i < internal_count; i++) {
            code = k5_ad_init_modules(kcontext, context, authdata_systems[i], &k);
            if (code != 0)
                break;
        }
    }

    if (tables != NULL)
        krb5int_free_plugin_dir_data(tables);

    context->plugins = plugins;

    if (code != 0)
        krb5_authdata_context_free(kcontext, context);
    else
        *pcontext = context;

    return code;
}

void KRB5_CALLCONV
krb5_authdata_context_free(krb5_context kcontext,
                           krb5_authdata_context context)
{
    int i;

    if (context == NULL)
        return;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];

        if (module->client_req_fini != NULL &&
            module->request_context != NULL)
            (*module->client_req_fini)(kcontext,
                                       context,
                                       module->plugin_context,
                                       module->request_context);

        if (module->client_fini != NULL)
            (*module->client_fini)(kcontext, module->plugin_context);

        memset(module, 0, sizeof(*module));
    }

    if (context->modules != NULL) {
        free(context->modules);
        context->modules = NULL;
    }
    krb5int_close_plugin_dirs(&context->plugins);
    memset(context, 0, sizeof(*context));
    free(context);
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_import_attributes(krb5_context kcontext,
                                krb5_authdata_context context,
                                krb5_flags usage,
                                krb5_authdata **authdata_to_import)
{
    int i;
    krb5_error_code code = 0;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];
        krb5_authdata **authdata;

        if ((module->flags & usage) == 0)
            continue;

        if (module->ftable->import_attributes == NULL)
            continue;

        code = krb5int_find_authdata(kcontext,
                                     authdata_to_import,
                                     NULL,
                                     module->ad_type,
                                     &authdata);
        if (code != 0 || authdata == NULL)
            continue;

        assert(authdata[0] != NULL);

        code = (*module->ftable->import_attributes)(kcontext,
                                                    context,
                                                    module->plugin_context,
                                                    *(module->request_context_pp),
                                                    authdata);
        if (code != 0 && (module->flags & AD_INFORMATIONAL))
            code = 0;
        krb5_free_authdata(kcontext, authdata);
        if (code != 0)
            break;
    }

    return code;
}

static krb5_error_code
k5_get_kdc_issued_authdata(krb5_context kcontext,
                           const krb5_ap_req *ap_req,
                           krb5_principal *kdc_issuer,
                           krb5_authdata ***kdc_issued_authdata)
{
    krb5_error_code code;
    krb5_authdata **authdata;
    krb5_authdata **ticket_authdata;

    *kdc_issuer = NULL;
    *kdc_issued_authdata = NULL;

    ticket_authdata = ap_req->ticket->enc_part2->authorization_data;

    code = krb5int_find_authdata(kcontext,
                                 ticket_authdata,
                                 NULL,
                                 KRB5_AUTHDATA_KDC_ISSUED,
                                 &authdata);
    if (code != 0)
        return code;

    /*
     * Note: a module must still implement a verify_authdata
     * method, even it is a NOOP that simply records the value
     8 of kdc_issued_flag.
     */
    code = krb5_verify_authdata_kdc_issued(kcontext,
                                           ap_req->ticket->enc_part2->session,
                                           authdata[0],
                                           kdc_issuer,
                                           kdc_issued_authdata);

    assert(code == 0 || *kdc_issued_authdata == NULL);

    krb5_free_authdata(kcontext, authdata);

    return code;
}

krb5_error_code
krb5int_authdata_verify(krb5_context kcontext,
                        krb5_authdata_context context,
                        krb5_flags usage,
                        const krb5_auth_context *auth_context,
                        const krb5_keyblock *key,
                        const krb5_ap_req *ap_req)
{
    int i;
    krb5_error_code code = 0;
    krb5_authdata **authen_authdata;
    krb5_authdata **ticket_authdata;
    krb5_principal kdc_issuer = NULL;
    krb5_authdata **kdc_issued_authdata = NULL;

    authen_authdata = (*auth_context)->authentp->authorization_data;
    ticket_authdata = ap_req->ticket->enc_part2->authorization_data;
    k5_get_kdc_issued_authdata(kcontext, ap_req,
                               &kdc_issuer, &kdc_issued_authdata);

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];
        krb5_authdata **authdata;
        krb5_boolean kdc_issued_flag = FALSE;

        if ((module->flags & usage) == 0)
            continue;

        if (module->ftable->import_attributes == NULL)
            continue;

        code = krb5int_find_authdata(kcontext,
                                     ticket_authdata,
                                     authen_authdata,
                                     module->ad_type,
                                     &authdata);
        if (code != 0)
            break;

        if (authdata == NULL && kdc_issued_authdata != NULL) {
            code = krb5int_find_authdata(kcontext,
                                         kdc_issued_authdata,
                                         NULL,
                                         module->ad_type,
                                         &authdata);
            if (code != 0)
                break;

            kdc_issued_flag = TRUE;
        }

        if (authdata == NULL)
            continue;

        assert(authdata[0] != NULL);

        code = (*module->ftable->import_attributes)(kcontext,
                                                    context,
                                                    module->plugin_context,
                                                    *(module->request_context_pp),
                                                    authdata);
        if (code == 0 && module->ftable->verify != NULL) {
            code = (*module->ftable->verify)(kcontext,
                                             context,
                                             module->plugin_context,
                                             *(module->request_context_pp),
                                             auth_context,
                                             key,
                                             ap_req,
                                             kdc_issued_flag,
                                             kdc_issuer);
        }
        if (code != 0 && (module->flags & AD_INFORMATIONAL))
            code = 0;
        krb5_free_authdata(kcontext, authdata);
        if (code != 0)
            break;
    }

    krb5_free_principal(kcontext, kdc_issuer);
    krb5_free_authdata(kcontext, kdc_issued_authdata);

    return code;
}

static krb5_error_code
k5_merge_data_list(krb5_data **dst, krb5_data *src, unsigned int *len)
{
    unsigned int i;
    krb5_data *d;

    if (src == NULL)
        return 0;

    for (i = 0; src[i].data != NULL; i++)
        ;

    d = realloc(*dst, (*len + i + 1) * sizeof(krb5_data));
    if (d == NULL)
        return ENOMEM;

    memcpy(&d[*len], src, i * sizeof(krb5_data));

    *len += i;

    d[*len].data = NULL;
    d[*len].length = 0;

    *dst = d;

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_get_attribute_types(krb5_context kcontext,
                                  krb5_authdata_context context,
                                  krb5_data **verified_attrs,
                                  krb5_data **asserted_attrs,
                                  krb5_data **all_attrs)
{
    int i;
    krb5_error_code code = 0;
    krb5_data *verified = NULL;
    krb5_data *asserted = NULL;
    krb5_data *all = NULL;
    unsigned int verified_len = 0;
    unsigned int asserted_len = 0;
    unsigned int all_len = 0;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];
        krb5_data *verified2 = NULL;
        krb5_data *asserted2 = NULL;
        krb5_data *all2 = NULL;

        if (module->ftable->get_attribute_types == NULL)
            continue;

        if ((*module->ftable->get_attribute_types)(kcontext,
                                                   context,
                                                   module->plugin_context,
                                                   *(module->request_context_pp),
                                                   verified_attrs ?
                                                       &verified2 : NULL,
                                                   asserted_attrs ?
                                                       &asserted2 : NULL,
                                                   all_attrs ?
                                                       &all2 : NULL))
            continue;

        if (verified_attrs != NULL) {
            code = k5_merge_data_list(&verified, verified2, &verified_len);
            if (code != 0)  {
                krb5int_free_data_list(kcontext, verified2);
                break;
            }
            if (verified2 != NULL)
                free(verified2);
        }

        if (asserted_attrs != NULL) {
            code = k5_merge_data_list(&asserted, asserted2, &asserted_len);
            if (code != 0) {
                krb5int_free_data_list(kcontext, asserted2);
                break;
            }
            if (asserted2 != NULL)
                free(asserted2);
        }

        if (all_attrs != NULL) {
            code = k5_merge_data_list(&all, all2, &all_len);
            if (code != 0)  {
                krb5int_free_data_list(kcontext, all2);
                break;
            }
            if (all2 != NULL)
                free(all2);
        }
    }

    if (code != 0) {
        krb5int_free_data_list(kcontext, verified);
        verified = NULL;

        krb5int_free_data_list(kcontext, asserted);
        asserted = NULL;

        krb5int_free_data_list(kcontext, all);
        all = NULL;
    }

    if (verified_attrs != NULL)
        *verified_attrs = verified;
    if (asserted_attrs != NULL)
        *asserted_attrs = asserted;
    if (all_attrs != NULL)
        *all_attrs = all;

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_get_attribute(krb5_context kcontext,
                            krb5_authdata_context context,
                            const krb5_data *attribute,
                            krb5_boolean *authenticated,
                            krb5_boolean *complete,
                            krb5_data *value,
                            krb5_data *display_value,
                            int *more)
{
    int i;
    krb5_error_code code = ENOENT;

    *authenticated = FALSE;
    *complete = FALSE;

    value->data = NULL;
    value->length = 0;

    display_value->data = NULL;
    display_value->length = 0;

    /*
     * NB at present a module is presumed to be authoritative for
     * an attribute; not sure how to federate "more" across module
     * yet
     */
    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];

        if (module->ftable->get_attribute == NULL)
            continue;

        code = (*module->ftable->get_attribute)(kcontext,
                                                context,
                                                module->plugin_context,
                                                *(module->request_context_pp),
                                                attribute,
                                                authenticated,
                                                complete,
                                                value,
                                                display_value,
                                                more);
        if (code == 0)
            break;
    }

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_set_attribute(krb5_context kcontext,
                            krb5_authdata_context context,
                            krb5_boolean complete,
                            const krb5_data *attribute,
                            const krb5_data *value)
{
    int i;
    krb5_error_code code = 0;
    int found = 0;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];

        if (module->ftable->set_attribute == NULL)
            continue;

        code = (*module->ftable->set_attribute)(kcontext,
                                                context,
                                                module->plugin_context,
                                                *(module->request_context_pp),
                                                complete,
                                                attribute,
                                                value);
        if (code == ENOENT)
            code = 0;
        else if (code == 0)
            found++;
        else
            break;
    }

    if (code == 0 && found == 0)
        code = ENOENT;

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_delete_attribute(krb5_context kcontext,
                               krb5_authdata_context context,
                               const krb5_data *attribute)
{
    int i;
    krb5_error_code code = ENOENT;
    int found = 0;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];

        if (module->ftable->set_attribute == NULL)
            continue;

        code = (*module->ftable->delete_attribute)(kcontext,
                                                   context,
                                                   module->plugin_context,
                                                   *(module->request_context_pp),
                                                   attribute);
        if (code == ENOENT)
            code = 0;
        else if (code == 0)
            found++;
        else
            break;
    }

    if (code == 0 && found == 0)
        code = ENOENT;

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_export_attributes(krb5_context kcontext,
                                krb5_authdata_context context,
                                krb5_flags flags,
                                krb5_authdata ***pauthdata)
{
    int i;
    krb5_error_code code = ENOENT;
    krb5_authdata **authdata = NULL;
    unsigned int len = 0;

    *pauthdata = NULL;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];
        krb5_authdata **authdata2 = NULL;
        int j;

        if ((module->flags & flags) == 0)
            continue;

        if (module->ftable->export_attributes == NULL)
            continue;

        code = (*module->ftable->export_attributes)(kcontext,
                                                    context,
                                                    module->plugin_context,
                                                    *(module->request_context_pp),
                                                    flags,
                                                    &authdata2);
        if (code == ENOENT)
            code = 0;
        else if (code != 0)
            break;

        if (authdata2 == NULL)
            continue;

        for (j = 0; authdata2[j] != NULL; j++)
            ;

        authdata = realloc(authdata, (len + j + 1) * sizeof(krb5_authdata *));
        if (authdata == NULL)
            return ENOMEM;

        memcpy(&authdata[len], authdata2, j * sizeof(krb5_authdata *));
        free(authdata2);

        len += j;
    }

    authdata[len] = NULL;

    *pauthdata = authdata;

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_export_internal(krb5_context kcontext,
                              krb5_authdata_context context,
                              krb5_boolean restrict_authenticated,
                              const char *module_name,
                              void **ptr)
{
    int i;
    krb5_error_code code = ENOENT;

    *ptr = NULL;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];

        if (strcmp(module_name, module->name) != 0)
            continue;

        if (module->ftable->export_internal == NULL)
            continue;

        code = (*module->ftable->export_internal)(kcontext,
                                                  context,
                                                  module->plugin_context,
                                                  *(module->request_context_pp),
                                                  restrict_authenticated,
                                                  ptr);

        break;
    }

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_free_internal(krb5_context kcontext,
                            krb5_authdata_context context,
                            const char *module_name,
                            void *ptr)
{
    int i;
    krb5_error_code code = ENOENT;

    for (i = 0; i < context->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &context->modules[i];

        if (strcmp(module_name, module->name) != 0)
            continue;

        if (module->ftable->free_internal == NULL)
            continue;

        (*module->ftable->free_internal)(kcontext,
                                         context,
                                         module->plugin_context,
                                         *(module->request_context_pp),
                                         ptr);

        break;
    }

    return code;
}

static krb5_error_code
k5_copy_ad_module_data(krb5_context kcontext,
                       krb5_authdata_context context,
                       struct _krb5_authdata_context_module *src_module,
                       krb5_authdata_context dst)
{
    int i;
    krb5_error_code code;
    struct _krb5_authdata_context_module *dst_module = NULL;

    for (i = 0; i < dst->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &dst->modules[i];

        if (module->ftable == src_module->ftable) {
            /* XXX is this safe to assume these pointers are interned? */
            dst_module = module;
            break;
        }
    }

    if (dst_module == NULL)
        return ENOENT;

    if (dst_module->client_req_init == NULL) {
        /* only copy the context for the head module */
        return 0;
    }

    assert(strcmp(dst_module->name, src_module->name) == 0);
    assert(src_module->request_context_pp == &src_module->request_context);
    assert(dst_module->request_context_pp == &dst_module->request_context);

    code = (*src_module->ftable->copy_context)(kcontext,
                                               context,
                                               src_module->plugin_context,
                                               src_module->request_context,
                                               dst_module->plugin_context,
                                               dst_module->request_context);

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_authdata_context_copy(krb5_context kcontext,
                           krb5_authdata_context src,
                           krb5_authdata_context *pdst)
{
    int i;
    krb5_error_code code;
    krb5_authdata_context dst;

    /* XXX we need to init a new context because we can't copy plugins */
    code = krb5_authdata_context_init(kcontext, &dst);
    if (code != 0)
        return code;

    for (i = 0; i < src->n_modules; i++) {
        struct _krb5_authdata_context_module *module = &src->modules[i];

        code = k5_copy_ad_module_data(kcontext, src, module, dst);
        if (code != 0)
            break;
    }

    if (code != 0) {
        krb5_authdata_context_free(kcontext, dst);
        return code;
    }

    *pdst = dst;

    return 0;
}


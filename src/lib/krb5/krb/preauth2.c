/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1995, 2003, 2008 by the Massachusetts Institute of Technology.  All
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

/*
 * This file contains routines for establishing, verifying, and any other
 * necessary functions, for utilizing the pre-authentication field of the
 * kerberos kdc request, with various hardware/software verification devices.
 */

#include "k5-int.h"
#if APPLE_PKINIT
#include "pkinit_client.h"
#include "pkinit_cert_store.h"
#endif /* APPLE_PKINIT */
#include "osconf.h"
#include <krb5/preauth_plugin.h>
#include "int-proto.h"
#include "fast.h"

#if !defined(_WIN32)
#include <unistd.h>
#endif

/* This structure lets us keep track of all of the modules which are loaded,
 * turning the list of modules and their lists of implemented preauth types
 * into a single list which we can walk easily. */
struct krb5_preauth_context_st {
    int n_modules;
    struct krb5_preauth_context_module_st {
        /* Which of the possibly more than one preauth types which the
         * module supports we're using at this point in the list. */
        krb5_preauthtype pa_type;
        /* Encryption types which the client claims to support -- we
         * copy them directly into the krb5_kdc_req structure during
         * krb5_preauth_prepare_request(). */
        krb5_enctype *enctypes;
        /* The plugin's module data and a function to clear it. */
        krb5_clpreauth_moddata moddata;
        krb5_clpreauth_fini_fn client_fini;
        /* The module's table, and some of its members, copied here for
         * convenience when we populated the list. */
        const char *name;
        int flags, use_count;
        krb5_clpreauth_process_fn client_process;
        krb5_clpreauth_tryagain_fn client_tryagain;
        krb5_clpreauth_supply_gic_opts_fn client_supply_gic_opts;
        krb5_clpreauth_request_init_fn client_req_init;
        krb5_clpreauth_request_fini_fn client_req_fini;
        /* The per-request context which the client_req_init() function
         * might allocate, which we'll need to clean up later by
         * calling the client_req_fini() function. */
        krb5_clpreauth_modreq modreq;
        /* A pointer to the request_context pointer.  All modules within
         * a plugin will point at the request_context of the first
         * module within the plugin. */
        krb5_clpreauth_modreq *modreq_p;
    } *modules;
};

typedef krb5_error_code (*pa_function)(krb5_context,
                                       krb5_kdc_req *request,
                                       krb5_pa_data *in_padata,
                                       krb5_pa_data **out_padata,
                                       krb5_data *salt, krb5_data *s2kparams,
                                       krb5_enctype *etype,
                                       krb5_keyblock *as_key,
                                       krb5_prompter_fct prompter_fct,
                                       void *prompter_data,
                                       krb5_gic_get_as_key_fct gak_fct,
                                       void *gak_data);

typedef struct _pa_types_t {
    krb5_preauthtype type;
    pa_function fct;
    int flags;
} pa_types_t;

/* Create the per-krb5_context context. This means loading the modules
 * if we haven't done that yet (applications which never obtain initial
 * credentials should never hit this routine), breaking up the module's
 * list of support pa_types so that we can iterate over the modules more
 * easily, and copying over the relevant parts of the module's table. */
void KRB5_CALLCONV
krb5_init_preauth_context(krb5_context kcontext)
{
    int n_tables, n_modules, i, count;
    krb5_plugin_initvt_fn *plugins = NULL, *pl;
    struct krb5_clpreauth_vtable_st *vtables = NULL, *vt;
    struct krb5_preauth_context_module_st *mod;
    krb5_preauth_context *context = NULL;
    krb5_clpreauth_moddata moddata;
    krb5_preauthtype pa_type, *pat;
    krb5_boolean first;
    krb5_clpreauth_modreq *rcpp;

    /* Only do this once for each krb5_context */
    if (kcontext->preauth_context != NULL)
        return;

    /* Auto-register built-in modules. */
    k5_plugin_register_dyn(kcontext, PLUGIN_INTERFACE_CLPREAUTH, "pkinit",
                           "preauth");
    k5_plugin_register(kcontext, PLUGIN_INTERFACE_CLPREAUTH,
                       "encrypted_challenge",
                       clpreauth_encrypted_challenge_initvt);
    k5_plugin_register(kcontext, PLUGIN_INTERFACE_CLPREAUTH,
                       "encrypted_timestamp",
                       clpreauth_encrypted_timestamp_initvt);

    /* Get all available clpreauth vtables. */
    if (k5_plugin_load_all(kcontext, PLUGIN_INTERFACE_CLPREAUTH, &plugins))
        return;
    for (count = 0; plugins[count] != NULL; count++);
    vtables = calloc(count, sizeof(*vtables));
    if (vtables == NULL)
        goto cleanup;
    for (pl = plugins, n_tables = 0; *pl != NULL; pl++) {
        if ((*pl)(kcontext, 1, 1, (krb5_plugin_vtable)&vtables[n_tables]) == 0)
            n_tables++;
    }

    /* Count how many modules we ended up loading, and how many preauth
     * types we may claim to support as a result. */
    n_modules = 0;
    for (i = 0; i < n_tables; i++) {
        for (count = 0; vtables[i].pa_type_list[count] > 0; count++);
        n_modules += count;
    }

    /* Allocate the space we need. */
    context = malloc(sizeof(*context));
    if (context == NULL)
        goto cleanup;
    context->modules = calloc(n_modules, sizeof(*context->modules));
    if (context->modules == NULL)
        goto cleanup;

    /* fill in the structure */
    n_modules = 0;
    for (i = 0; i < n_tables; i++) {
        vt = &vtables[i];
        if ((vt->pa_type_list != NULL) && (vt->process != NULL)) {
            moddata = NULL;
            if (vt->init != NULL && vt->init(kcontext, &moddata) != 0) {
#ifdef DEBUG
                fprintf(stderr, "init err, skipping module \"%s\"\n",
                        vt->name);
#endif
                continue;
            }

            rcpp = NULL;
            for (pat = vt->pa_type_list, first = TRUE; *pat > 0;
                 pat++, first = FALSE) {
                pa_type = *pat;
                mod = &context->modules[n_modules];
                mod->pa_type = pa_type;
                mod->enctypes = vt->enctype_list;
                mod->moddata = moddata;
                /* Only call client_fini once per plugin */
                if (first)
                    mod->client_fini = vt->fini;
                else
                    mod->client_fini = NULL;
                mod->name = vt->name;
                mod->flags = (*vt->flags)(kcontext, pa_type);
                mod->use_count = 0;
                mod->client_process = vt->process;
                mod->client_tryagain = vt->tryagain;
                mod->client_supply_gic_opts = first ? vt->gic_opts : NULL;
                mod->modreq = NULL;
                /*
                 * Only call request_init and request_fini once per plugin.
                 * Only the first module within each plugin will ever
                 * have request_context filled in.  Every module within
                 * the plugin will have its request_context_pp pointing
                 * to that entry's request_context.  That way all the
                 * modules within the plugin share the same request_context
                 */
                if (first) {
                    mod->client_req_init = vt->request_init;
                    mod->client_req_fini = vt->request_fini;
                    rcpp = &mod->modreq;
                } else {
                    mod->client_req_init = NULL;
                    mod->client_req_fini = NULL;
                }
                mod->modreq_p = rcpp;
#ifdef DEBUG
                fprintf(stderr, "init module \"%s\", pa_type %d, flag %d\n",
                        mod->name, mod->pa_type, mod->flags);
#endif
                n_modules++;
            }
        }
    }
    context->n_modules = n_modules;

    /* Place the constructed preauth context into the krb5 context. */
    kcontext->preauth_context = context;
    context = NULL;

cleanup:
    if (context)
        free(context->modules);
    free(context);
    k5_plugin_free_modules(kcontext, plugins);
    free(vtables);
}

/* Zero the use counts for the modules herein.  Usually used before we
 * start processing any data from the server, at which point every module
 * will again be able to take a crack at whatever the server sent. */
void KRB5_CALLCONV
krb5_clear_preauth_context_use_counts(krb5_context context)
{
    int i;
    if (context->preauth_context != NULL) {
        for (i = 0; i < context->preauth_context->n_modules; i++) {
            context->preauth_context->modules[i].use_count = 0;
        }
    }
}


/* Free the per-krb5_context preauth_context. This means clearing any
 * plugin-specific context which may have been created, and then
 * freeing the context itself. */
void KRB5_CALLCONV
krb5_free_preauth_context(krb5_context context)
{
    int i;
    struct krb5_preauth_context_module_st *mod;

    if (context == NULL || context->preauth_context == NULL)
        return;
    for (i = 0; i < context->preauth_context->n_modules; i++) {
        mod = &context->preauth_context->modules[i];
        if (mod->client_fini != NULL)
            mod->client_fini(context, mod->moddata);
        zap(mod, sizeof(*mod));
    }
    free(context->preauth_context->modules);
    free(context->preauth_context);
    context->preauth_context = NULL;
}

/* Initialize the per-AS-REQ context. This means calling the client_req_init
 * function to give the plugin a chance to allocate a per-request context. */
void KRB5_CALLCONV
krb5_preauth_request_context_init(krb5_context context)
{
    int i;
    struct krb5_preauth_context_module_st *mod;

    if (context->preauth_context == NULL)
        krb5_init_preauth_context(context);
    if (context->preauth_context == NULL)
        return;
    for (i = 0; i < context->preauth_context->n_modules; i++) {
        mod = &context->preauth_context->modules[i];
        if (mod->client_req_init != NULL)
            mod->client_req_init(context, mod->moddata, mod->modreq_p);
    }
}

/* Free the per-AS-REQ context. This means clearing any request-specific
 * context which the plugin may have created. */
void KRB5_CALLCONV
krb5_preauth_request_context_fini(krb5_context context)
{
    int i;
    struct krb5_preauth_context_module_st *mod;

    if (context->preauth_context == NULL)
        return;
    for (i = 0; i < context->preauth_context->n_modules; i++) {
        mod = &context->preauth_context->modules[i];
        if (mod->modreq != NULL) {
            if (mod->client_req_fini != NULL)
                mod->client_req_fini(context, mod->moddata, mod->modreq);
            mod->modreq = NULL;
        }
    }
}

/* Add the named encryption type to the existing list of ktypes. */
static void
grow_ktypes(krb5_enctype **out_ktypes, int *out_nktypes, krb5_enctype ktype)
{
    int i;
    krb5_enctype *ktypes;
    for (i = 0; i < *out_nktypes; i++) {
        if ((*out_ktypes)[i] == ktype)
            return;
    }
    ktypes = malloc((*out_nktypes + 2) * sizeof(ktype));
    if (ktypes) {
        for (i = 0; i < *out_nktypes; i++)
            ktypes[i] = (*out_ktypes)[i];
        ktypes[i++] = ktype;
        ktypes[i] = 0;
        free(*out_ktypes);
        *out_ktypes = ktypes;
        *out_nktypes = i;
    }
}

/*
 * Add the given list of pa_data items to the existing list of items.
 * Factored out here to make reading the do_preauth logic easier to read.
 */
static int
grow_pa_list(krb5_pa_data ***out_pa_list, int *out_pa_list_size,
             krb5_pa_data **addition, int num_addition)
{
    krb5_pa_data **pa_list;
    int i, j;

    if (out_pa_list == NULL || addition == NULL) {
        return EINVAL;
    }

    if (*out_pa_list == NULL) {
        /* Allocate room for the new additions and a NULL terminator. */
        pa_list = malloc((num_addition + 1) * sizeof(krb5_pa_data *));
        if (pa_list == NULL)
            return ENOMEM;
        for (i = 0; i < num_addition; i++)
            pa_list[i] = addition[i];
        pa_list[i] = NULL;
        *out_pa_list = pa_list;
        *out_pa_list_size = num_addition;
    } else {
        /*
         * Allocate room for the existing entries plus
         * the new additions and a NULL terminator.
         */
        pa_list = malloc((*out_pa_list_size + num_addition + 1)
                         * sizeof(krb5_pa_data *));
        if (pa_list == NULL)
            return ENOMEM;
        for (i = 0; i < *out_pa_list_size; i++)
            pa_list[i] = (*out_pa_list)[i];
        for (j = 0; j < num_addition;)
            pa_list[i++] = addition[j++];
        pa_list[i] = NULL;
        free(*out_pa_list);
        *out_pa_list = pa_list;
        *out_pa_list_size = i;
    }
    return 0;
}

static krb5_enctype
get_etype(krb5_context context, krb5_clpreauth_rock rock)
{
    return *rock->etype;
}

static krb5_keyblock *
fast_armor(krb5_context context, krb5_clpreauth_rock rock)
{
    return rock->fast_state->armor_key;
}

static krb5_error_code
get_as_key(krb5_context context, krb5_clpreauth_rock rock,
           krb5_keyblock **keyblock)
{
    krb5_error_code ret;

    if (rock->as_key->length == 0) {
        ret = (*rock->gak_fct)(context, rock->client, *rock->etype,
                               rock->prompter, rock->prompter_data, rock->salt,
                               rock->s2kparams, rock->as_key, *rock->gak_data);
        if (ret)
            return ret;
    }
    *keyblock = rock->as_key;
    return 0;
}

static krb5_error_code
set_as_key(krb5_context context, krb5_clpreauth_rock rock,
           const krb5_keyblock *keyblock)
{
    krb5_free_keyblock_contents(context, rock->as_key);
    return krb5_copy_keyblock_contents(context, keyblock, rock->as_key);
}

static struct krb5_clpreauth_callbacks_st callbacks = {
    1,
    get_etype,
    fast_armor,
    get_as_key,
    set_as_key
};

/* Tweak the request body, for now adding any enctypes which the module claims
 * to add support for to the list, but in the future perhaps doing more
 * involved things. */
void KRB5_CALLCONV
krb5_preauth_prepare_request(krb5_context kcontext,
                             krb5_gic_opt_ext *opte,
                             krb5_kdc_req *request)
{
    int i, j;

    if (kcontext->preauth_context == NULL) {
        return;
    }
    /* Add the module-specific enctype list to the request, but only if
     * it's something we can safely modify. */
    if (!(opte && (opte->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST))) {
        for (i = 0; i < kcontext->preauth_context->n_modules; i++) {
            if (kcontext->preauth_context->modules[i].enctypes == NULL)
                continue;
            for (j = 0; kcontext->preauth_context->modules[i].enctypes[j] != 0; j++) {
                grow_ktypes(&request->ktype, &request->nktypes,
                            kcontext->preauth_context->modules[i].enctypes[j]);
            }
        }
    }
}

/* Find the first module which provides for the named preauth type which also
 * hasn't had a chance to run yet (INFO modules don't count, because as a rule
 * they don't generate preauth data), and run it. */
static krb5_error_code
run_preauth_plugins(krb5_context kcontext,
                    int module_required_flags,
                    krb5_kdc_req *request,
                    krb5_data *encoded_request_body,
                    krb5_data *encoded_previous_request,
                    krb5_pa_data *in_padata,
                    krb5_prompter_fct prompter,
                    void *prompter_data,
                    krb5_clpreauth_rock preauth_rock,
                    krb5_pa_data ***out_pa_list,
                    int *out_pa_list_size,
                    int *module_ret,
                    int *module_flags,
                    krb5_gic_opt_ext *opte)
{
    int i;
    krb5_pa_data **out_pa_data;
    krb5_error_code ret;
    struct krb5_preauth_context_module_st *module;

    if (kcontext->preauth_context == NULL) {
        return ENOENT;
    }
    /* iterate over all loaded modules */
    for (i = 0; i < kcontext->preauth_context->n_modules; i++) {
        module = &kcontext->preauth_context->modules[i];
        /* skip over those which don't match the preauth type */
        if (module->pa_type != in_padata->pa_type)
            continue;
        /* skip over those which don't match the flags (INFO vs REAL, mainly) */
        if ((module->flags & module_required_flags) == 0)
            continue;
        /* if it's a REAL module, try to call it only once per library call */
        if (module_required_flags & PA_REAL) {
            if (module->use_count > 0) {
                TRACE_PREAUTH_SKIP(kcontext, module->name, module->pa_type);
                continue;
            }
            module->use_count++;
        }
        /* run the module's callback function */
        out_pa_data = NULL;
#ifdef DEBUG
        fprintf(stderr, "using module \"%s\" (%d), flags = %d\n",
                module->name, module->pa_type, module->flags);
#endif
        ret = module->client_process(kcontext, module->moddata,
                                     *module->modreq_p,
                                     (krb5_get_init_creds_opt *)opte,
                                     &callbacks, preauth_rock,
                                     request, encoded_request_body,
                                     encoded_previous_request, in_padata,
                                     prompter, prompter_data, &out_pa_data);
        TRACE_PREAUTH_PROCESS(kcontext, module->name, module->pa_type,
                              module->flags, ret);
        /* Make note of the module's flags and status. */
        *module_flags = module->flags;
        *module_ret = ret;
        /* Save the new preauth data item. */
        if (out_pa_data != NULL) {
            int j;
            for (j = 0; out_pa_data[j] != NULL; j++);
            ret = grow_pa_list(out_pa_list, out_pa_list_size, out_pa_data, j);
            free(out_pa_data);
            if (ret != 0)
                return ret;
        }
        break;
    }
    if (i >= kcontext->preauth_context->n_modules) {
        return ENOENT;
    }
    return 0;
}

static inline krb5_data
padata2data(krb5_pa_data p)
{
    krb5_data d;
    d.magic = KV5M_DATA;
    d.length = p.length;
    d.data = (char *) p.contents;
    return d;
}

static krb5_error_code
pa_salt(krb5_context context, krb5_kdc_req *request, krb5_pa_data *in_padata,
        krb5_pa_data **out_padata, krb5_data *salt, krb5_data *s2kparams,
        krb5_enctype *etype, krb5_keyblock *as_key, krb5_prompter_fct prompter,
        void *prompter_data, krb5_gic_get_as_key_fct gak_fct, void *gak_data)
{
    krb5_data tmp;
    krb5_error_code retval;

    tmp = padata2data(*in_padata);
    krb5_free_data_contents(context, salt);
    retval = krb5int_copy_data_contents(context, &tmp, salt);
    if (retval)
        return retval;

    TRACE_PREAUTH_SALT(context, salt, in_padata->pa_type);
    if (in_padata->pa_type == KRB5_PADATA_AFS3_SALT)
        salt->length = SALT_TYPE_AFS_LENGTH;

    return(0);
}

static krb5_error_code
pa_fx_cookie(krb5_context context, krb5_kdc_req *request,
             krb5_pa_data *in_padata, krb5_pa_data **out_padata,
             krb5_data *salt, krb5_data *s2kparams, krb5_enctype *etype,
             krb5_keyblock *as_key, krb5_prompter_fct prompter,
             void *prompter_data, krb5_gic_get_as_key_fct gak_fct,
             void *gak_data)
{
    krb5_pa_data *pa = calloc(1, sizeof(krb5_pa_data));
    krb5_octet *contents;

    TRACE_PREAUTH_COOKIE(context, in_padata->length, in_padata->contents);
    if (pa == NULL)
        return ENOMEM;
    contents = malloc(in_padata->length);
    if (contents == NULL) {
        free(pa);
        return ENOMEM;
    }
    *pa = *in_padata;
    pa->contents = contents;
    memcpy(contents, in_padata->contents, pa->length);
    *out_padata = pa;
    return 0;
}

#if APPLE_PKINIT
/*
 * PKINIT. One function to generate AS-REQ, one to parse AS-REP
 */
#define  PKINIT_DEBUG    0
#if     PKINIT_DEBUG
#define kdcPkinitDebug(args...)       printf(args)
#else
#define kdcPkinitDebug(args...)
#endif

static krb5_error_code
pa_pkinit_gen_req(krb5_context context,
                  krb5_kdc_req *request,
                  krb5_pa_data *in_padata,
                  krb5_pa_data **out_padata,
                  krb5_data *salt,
                  krb5_data *s2kparams,
                  krb5_enctype *etype,
                  krb5_keyblock *as_key,
                  krb5_prompter_fct prompter,
                  void *prompter_data,
                  krb5_gic_get_as_key_fct gak_fct,
                  void *gak_data)
{
    krb5_error_code             krtn;
    krb5_data                   out_data = {0, 0, NULL};
    krb5_timestamp              kctime = 0;
    krb5_int32                  cusec = 0;
    krb5_ui_4                   nonce = 0;
    krb5_checksum               cksum;
    krb5_pkinit_signing_cert_t  client_cert;
    krb5_data                   *der_req = NULL;
    char                        *client_principal = NULL;
    char                        *server_principal = NULL;
    unsigned char               nonce_bytes[4];
    krb5_data                   nonce_data = {0, 4, (char *)nonce_bytes};
    int                         dex;

    /*
     * Trusted CA list and specific KC cert optionally obtained via
     * krb5_pkinit_get_server_certs(). All are DER-encoded certs.
     */
    krb5_data *trusted_CAs = NULL;
    krb5_ui_4 num_trusted_CAs;
    krb5_data kdc_cert = {0};

    kdcPkinitDebug("pa_pkinit_gen_req\n");

    /* If we don't have a client cert, we're done */
    if(request->client == NULL) {
        kdcPkinitDebug("No request->client; aborting PKINIT\n");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    krtn = krb5_unparse_name(context, request->client, &client_principal);
    if(krtn) {
        return krtn;
    }
    krtn = krb5_pkinit_get_client_cert(client_principal, &client_cert);
    free(client_principal);
    if(krtn) {
        kdcPkinitDebug("No client cert; aborting PKINIT\n");
        return krtn;
    }

    /* optional platform-dependent CA list and KDC cert */
    krtn = krb5_unparse_name(context, request->server, &server_principal);
    if(krtn) {
        goto cleanup;
    }
    krtn = krb5_pkinit_get_server_certs(client_principal, server_principal,
                                        &trusted_CAs, &num_trusted_CAs, &kdc_cert);
    if(krtn) {
        goto cleanup;
    }

    /* checksum of the encoded KDC-REQ-BODY */
    krtn = encode_krb5_kdc_req_body(request, &der_req);
    if(krtn) {
        kdcPkinitDebug("encode_krb5_kdc_req_body returned %d\n", (int)krtn);
        goto cleanup;
    }
    krtn = krb5_c_make_checksum(context, CKSUMTYPE_NIST_SHA, NULL, 0, der_req, &cksum);
    if(krtn) {
        goto cleanup;
    }

    krtn = krb5_us_timeofday(context, &kctime, &cusec);
    if(krtn) {
        goto cleanup;
    }

    /* cook up a random 4-byte nonce */
    krtn = krb5_c_random_make_octets(context, &nonce_data);
    if(krtn) {
        goto cleanup;
    }
    for(dex=0; dex<4; dex++) {
        nonce <<= 8;
        nonce |= nonce_bytes[dex];
    }

    krtn = krb5int_pkinit_as_req_create(context,
                                        kctime, cusec, nonce, &cksum,
                                        client_cert,
                                        trusted_CAs, num_trusted_CAs,
                                        (kdc_cert.data ? &kdc_cert : NULL),
                                        &out_data);
    if(krtn) {
        kdcPkinitDebug("error %d on pkinit_as_req_create; aborting PKINIT\n", (int)krtn);
        goto cleanup;
    }
    *out_padata = (krb5_pa_data *)malloc(sizeof(krb5_pa_data));
    if(*out_padata == NULL) {
        krtn = ENOMEM;
        free(out_data.data);
        goto cleanup;
    }
    (*out_padata)->magic = KV5M_PA_DATA;
    (*out_padata)->pa_type = KRB5_PADATA_PK_AS_REQ;
    (*out_padata)->length = out_data.length;
    (*out_padata)->contents = (krb5_octet *)out_data.data;
    krtn = 0;
cleanup:
    if(client_cert) {
        krb5_pkinit_release_cert(client_cert);
    }
    if(cksum.contents) {
        free(cksum.contents);
    }
    if (der_req) {
        krb5_free_data(context, der_req);
    }
    if(server_principal) {
        free(server_principal);
    }
    /* free data mallocd by krb5_pkinit_get_server_certs() */
    if(trusted_CAs) {
        unsigned udex;
        for(udex=0; udex<num_trusted_CAs; udex++) {
            free(trusted_CAs[udex].data);
        }
        free(trusted_CAs);
    }
    if(kdc_cert.data) {
        free(kdc_cert.data);
    }
    return krtn;

}

/* If and only if the realm is that of a Local KDC, accept
 * the KDC certificate as valid if its hash matches the
 * realm.
 */
static krb5_boolean
local_kdc_cert_match(krb5_context context,
                     krb5_data *signer_cert,
                     krb5_principal client)
{
    static const char lkdcprefix[] = "LKDC:SHA1.";
    krb5_boolean match = FALSE;
    size_t cert_hash_len;
    char *cert_hash;
    const char *realm_hash;
    size_t realm_hash_len;

    if (client->realm.length <= sizeof(lkdcprefix) ||
        0 != memcmp(lkdcprefix, client->realm.data, sizeof(lkdcprefix)-1))
        return match;
    realm_hash = &client->realm.data[sizeof(lkdcprefix)-1];
    realm_hash_len = client->realm.length - sizeof(lkdcprefix) + 1;
    kdcPkinitDebug("checking realm versus certificate hash\n");
    if (NULL != (cert_hash = krb5_pkinit_cert_hash_str(signer_cert))) {
        kdcPkinitDebug("hash = %s\n", cert_hash);
        cert_hash_len = strlen(cert_hash);
        if (cert_hash_len == realm_hash_len &&
            0 == memcmp(cert_hash, realm_hash, cert_hash_len))
            match = TRUE;
        free(cert_hash);
    }
    kdcPkinitDebug("result: %s\n", match ? "matches" : "does not match");
    return match;
}

static krb5_error_code
pa_pkinit_parse_rep(krb5_context context,
                    krb5_kdc_req *request,
                    krb5_pa_data *in_padata,
                    krb5_pa_data **out_padata,
                    krb5_data *salt,
                    krb5_data *s2kparams,
                    krb5_enctype *etype,
                    krb5_keyblock *as_key,
                    krb5_prompter_fct prompter,
                    void *prompter_data,
                    krb5_gic_get_as_key_fct gak_fct,
                    void *gak_data)
{
    krb5int_cert_sig_status     sig_status = (krb5int_cert_sig_status)-999;
    krb5_error_code             krtn;
    krb5_data                   asRep;
    krb5_keyblock               local_key = {0};
    krb5_pkinit_signing_cert_t  client_cert;
    char                        *princ_name = NULL;
    krb5_checksum               as_req_checksum_rcd = {0};  /* received checksum */
    krb5_checksum               as_req_checksum_gen = {0};  /* calculated checksum */
    krb5_data                   *encoded_as_req = NULL;
    krb5_data                   signer_cert = {0};

    *out_padata = NULL;
    kdcPkinitDebug("pa_pkinit_parse_rep\n");
    if((in_padata == NULL) || (in_padata->length== 0)) {
        kdcPkinitDebug("pa_pkinit_parse_rep: no in_padata\n");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* If we don't have a client cert, we're done */
    if(request->client == NULL) {
        kdcPkinitDebug("No request->client; aborting PKINIT\n");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    krtn = krb5_unparse_name(context, request->client, &princ_name);
    if(krtn) {
        return krtn;
    }
    krtn = krb5_pkinit_get_client_cert(princ_name, &client_cert);
    free(princ_name);
    if(krtn) {
        kdcPkinitDebug("No client cert; aborting PKINIT\n");
        return krtn;
    }

    memset(&local_key, 0, sizeof(local_key));
    asRep.data = (char *)in_padata->contents;
    asRep.length = in_padata->length;
    krtn = krb5int_pkinit_as_rep_parse(context, &asRep, client_cert,
                                       &local_key, &as_req_checksum_rcd, &sig_status,
                                       &signer_cert, NULL, NULL);
    if(krtn) {
        kdcPkinitDebug("pkinit_as_rep_parse returned %d\n", (int)krtn);
        return krtn;
    }
    switch(sig_status) {
    case pki_cs_good:
        break;
    case pki_cs_unknown_root:
        if (local_kdc_cert_match(context, &signer_cert, request->client))
            break;
        /* FALLTHROUGH */
    default:
        kdcPkinitDebug("pa_pkinit_parse_rep: bad cert/sig status %d\n",
                       (int)sig_status);
        krtn = KRB5KDC_ERR_PREAUTH_FAILED;
        goto error_out;
    }

    /* calculate checksum of incoming AS-REQ using the decryption key
     * we just got from the ReplyKeyPack */
    krtn = encode_krb5_as_req(request, &encoded_as_req);
    if(krtn) {
        goto error_out;
    }
    krtn = krb5_c_make_checksum(context, context->kdc_req_sumtype,
                                &local_key, KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
                                encoded_as_req, &as_req_checksum_gen);
    if(krtn) {
        goto error_out;
    }
    if((as_req_checksum_gen.length != as_req_checksum_rcd.length) ||
       memcmp(as_req_checksum_gen.contents,
              as_req_checksum_rcd.contents,
              as_req_checksum_gen.length)) {
        kdcPkinitDebug("pa_pkinit_parse_rep: checksum miscompare\n");
        krtn = KRB5KDC_ERR_PREAUTH_FAILED;
        goto error_out;
    }

    /* We have the key; transfer to caller */
    if (as_key->length) {
        krb5_free_keyblock_contents(context, as_key);
    }
    *as_key = local_key;

#if PKINIT_DEBUG
    fprintf(stderr, "pa_pkinit_parse_rep: SUCCESS\n");
    fprintf(stderr, "enctype %d keylen %d keydata %02x %02x %02x %02x...\n",
            (int)as_key->enctype, (int)as_key->length,
            as_key->contents[0], as_key->contents[1],
            as_key->contents[2], as_key->contents[3]);
#endif

    krtn = 0;

error_out:
    if (signer_cert.data) {
        free(signer_cert.data);
    }
    if(as_req_checksum_rcd.contents) {
        free(as_req_checksum_rcd.contents);
    }
    if(as_req_checksum_gen.contents) {
        free(as_req_checksum_gen.contents);
    }
    if(encoded_as_req) {
        krb5_free_data(context, encoded_as_req);
    }
    if(krtn && (local_key.contents != NULL)) {
        krb5_free_keyblock_contents(context, &local_key);
    }
    return krtn;
}
#endif /* APPLE_PKINIT */

/* this macro expands to the int,ptr necessary for "%.*s" in an sprintf */

#define SAMDATA(kdata, str, maxsize)                                    \
    (int)((kdata.length)?                                               \
          ((((kdata.length)<=(maxsize))?(kdata.length):strlen(str))):   \
          strlen(str)),                                                 \
        (kdata.length)?                                                 \
        ((((kdata.length)<=(maxsize))?(kdata.data):(str))):(str)
static char *
sam_challenge_banner(krb5_int32 sam_type)
{
    char *label;

    switch (sam_type) {
    case PA_SAM_TYPE_ENIGMA:    /* Enigma Logic */
        label = _("Challenge for Enigma Logic mechanism");
        break;
    case PA_SAM_TYPE_DIGI_PATH: /*  Digital Pathways */
    case PA_SAM_TYPE_DIGI_PATH_HEX: /*  Digital Pathways */
        label = _("Challenge for Digital Pathways mechanism");
        break;
    case PA_SAM_TYPE_ACTIVCARD_DEC: /*  Digital Pathways */
    case PA_SAM_TYPE_ACTIVCARD_HEX: /*  Digital Pathways */
        label = _("Challenge for Activcard mechanism");
        break;
    case PA_SAM_TYPE_SKEY_K0:   /*  S/key where  KDC has key 0 */
        label = _("Challenge for Enhanced S/Key mechanism");
        break;
    case PA_SAM_TYPE_SKEY:      /*  Traditional S/Key */
        label = _("Challenge for Traditional S/Key mechanism");
        break;
    case PA_SAM_TYPE_SECURID:   /*  Security Dynamics */
        label = _("Challenge for Security Dynamics mechanism");
        break;
    case PA_SAM_TYPE_SECURID_PREDICT:   /* predictive Security Dynamics */
        label = _("Challenge for Security Dynamics mechanism");
        break;
    default:
        label = _("Challenge from authentication server");
        break;
    }

    return(label);
}

static krb5_error_code
pa_sam_2(krb5_context context, krb5_kdc_req *request, krb5_pa_data *in_padata,
         krb5_pa_data **out_padata, krb5_data *salt, krb5_data *s2kparams,
         krb5_enctype *etype, krb5_keyblock *as_key,
         krb5_prompter_fct prompter, void *prompter_data,
         krb5_gic_get_as_key_fct gak_fct, void *gak_data)
{
    krb5_error_code retval;
    krb5_sam_challenge_2 *sc2 = NULL;
    krb5_sam_challenge_2_body *sc2b = NULL;
    krb5_data tmp_data;
    krb5_data response_data;
    char name[100], banner[100], prompt[100], response[100];
    krb5_prompt kprompt;
    krb5_prompt_type prompt_type;
    krb5_data defsalt;
    krb5_checksum **cksum;
    krb5_data *scratch = NULL;
    krb5_boolean valid_cksum = 0;
    krb5_enc_sam_response_enc_2 enc_sam_response_enc_2;
    krb5_sam_response_2 sr2;
    size_t ciph_len;
    krb5_pa_data *sam_padata;

    if (prompter == NULL)
        return KRB5_LIBOS_CANTREADPWD;

    tmp_data.length = in_padata->length;
    tmp_data.data = (char *)in_padata->contents;

    if ((retval = decode_krb5_sam_challenge_2(&tmp_data, &sc2)))
        return(retval);

    retval = decode_krb5_sam_challenge_2_body(&sc2->sam_challenge_2_body, &sc2b);

    if (retval) {
        krb5_free_sam_challenge_2(context, sc2);
        return(retval);
    }

    if (!sc2->sam_cksum || ! *sc2->sam_cksum) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        return(KRB5_SAM_NO_CHECKSUM);
    }

    if (sc2b->sam_flags & KRB5_SAM_MUST_PK_ENCRYPT_SAD) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        return(KRB5_SAM_UNSUPPORTED);
    }

    if (!krb5_c_valid_enctype(sc2b->sam_etype)) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        return(KRB5_SAM_INVALID_ETYPE);
    }

    /* All of the above error checks are KDC-specific, that is, they     */
    /* assume a failure in the KDC reply.  By returning anything other   */
    /* than KRB5_KDC_UNREACH, KRB5_PREAUTH_FAILED,               */
    /* KRB5_LIBOS_PWDINTR, or KRB5_REALM_CANT_RESOLVE, the client will   */
    /* most likely go on to try the AS_REQ against master KDC            */

    if (!(sc2b->sam_flags & KRB5_SAM_USE_SAD_AS_KEY)) {
        /* We will need the password to obtain the key used for */
        /* the checksum, and encryption of the sam_response.    */
        /* Go ahead and get it now, preserving the ordering of  */
        /* prompts for the user.                                */

        retval = (gak_fct)(context, request->client,
                           sc2b->sam_etype, prompter,
                           prompter_data, salt, s2kparams, as_key, gak_data);
        if (retval) {
            krb5_free_sam_challenge_2(context, sc2);
            krb5_free_sam_challenge_2_body(context, sc2b);
            return(retval);
        }
    }

    snprintf(name, sizeof(name), "%.*s",
             SAMDATA(sc2b->sam_type_name, _("SAM Authentication"),
                     sizeof(name) - 1));

    snprintf(banner, sizeof(banner), "%.*s",
             SAMDATA(sc2b->sam_challenge_label,
                     sam_challenge_banner(sc2b->sam_type),
                     sizeof(banner)-1));

    snprintf(prompt, sizeof(prompt), "%s%.*s%s%.*s",
             sc2b->sam_challenge.length?"Challenge is [":"",
             SAMDATA(sc2b->sam_challenge, "", 20),
             sc2b->sam_challenge.length?"], ":"",
             SAMDATA(sc2b->sam_response_prompt, "passcode", 55));

    response_data.data = response;
    response_data.length = sizeof(response);
    kprompt.prompt = prompt;
    kprompt.hidden = 1;
    kprompt.reply = &response_data;

    prompt_type = KRB5_PROMPT_TYPE_PREAUTH;
    krb5int_set_prompt_types(context, &prompt_type);

    if ((retval = ((*prompter)(context, prompter_data, name,
                               banner, 1, &kprompt)))) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        krb5int_set_prompt_types(context, 0);
        return(retval);
    }

    krb5int_set_prompt_types(context, (krb5_prompt_type *)NULL);

    /* Generate salt used by string_to_key() */
    if (((int) salt->length == -1) && (salt->data == NULL)) {
        if ((retval =
             krb5_principal2salt(context, request->client, &defsalt))) {
            krb5_free_sam_challenge_2(context, sc2);
            krb5_free_sam_challenge_2_body(context, sc2b);
            return(retval);
        }
        salt = &defsalt;
    } else {
        defsalt.length = 0;
    }

    /* Get encryption key to be used for checksum and sam_response */
    if (!(sc2b->sam_flags & KRB5_SAM_USE_SAD_AS_KEY)) {
        /* as_key = string_to_key(password) */

        if (as_key->length) {
            krb5_free_keyblock_contents(context, as_key);
            as_key->length = 0;
        }

        /* generate a key using the supplied password */
        retval = krb5_c_string_to_key(context, sc2b->sam_etype,
                                      (krb5_data *)gak_data, salt, as_key);

        if (retval) {
            krb5_free_sam_challenge_2(context, sc2);
            krb5_free_sam_challenge_2_body(context, sc2b);
            if (defsalt.length) free(defsalt.data);
            return(retval);
        }

        if (!(sc2b->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD)) {
            /* as_key = combine_key (as_key, string_to_key(SAD)) */
            krb5_keyblock tmp_kb;

            retval = krb5_c_string_to_key(context, sc2b->sam_etype,
                                          &response_data, salt, &tmp_kb);

            if (retval) {
                krb5_free_sam_challenge_2(context, sc2);
                krb5_free_sam_challenge_2_body(context, sc2b);
                if (defsalt.length) free(defsalt.data);
                return(retval);
            }

            /* This should be a call to the crypto library some day */
            /* key types should already match the sam_etype */
            retval = krb5int_c_combine_keys(context, as_key, &tmp_kb, as_key);

            if (retval) {
                krb5_free_sam_challenge_2(context, sc2);
                krb5_free_sam_challenge_2_body(context, sc2b);
                if (defsalt.length) free(defsalt.data);
                return(retval);
            }
            krb5_free_keyblock_contents(context, &tmp_kb);
        }

        if (defsalt.length)
            free(defsalt.data);

    } else {
        /* as_key = string_to_key(SAD) */

        if (as_key->length) {
            krb5_free_keyblock_contents(context, as_key);
            as_key->length = 0;
        }

        /* generate a key using the supplied password */
        retval = krb5_c_string_to_key(context, sc2b->sam_etype,
                                      &response_data, salt, as_key);

        if (defsalt.length)
            free(defsalt.data);

        if (retval) {
            krb5_free_sam_challenge_2(context, sc2);
            krb5_free_sam_challenge_2_body(context, sc2b);
            return(retval);
        }
    }

    /* Now we have a key, verify the checksum on the sam_challenge */

    cksum = sc2->sam_cksum;

    for (; *cksum; cksum++) {
        if (!krb5_c_is_keyed_cksum((*cksum)->checksum_type))
            continue;
        /* Check this cksum */
        retval = krb5_c_verify_checksum(context, as_key,
                                        KRB5_KEYUSAGE_PA_SAM_CHALLENGE_CKSUM,
                                        &sc2->sam_challenge_2_body,
                                        *cksum, &valid_cksum);
        if (retval) {
            krb5_free_data(context, scratch);
            krb5_free_sam_challenge_2(context, sc2);
            krb5_free_sam_challenge_2_body(context, sc2b);
            return(retval);
        }
        if (valid_cksum)
            break;
    }

    if (!valid_cksum) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        /*
         * Note: We return AP_ERR_BAD_INTEGRITY so upper-level applications
         * can interpret that as "password incorrect", which is probably
         * the best error we can return in this situation.
         */
        return(KRB5KRB_AP_ERR_BAD_INTEGRITY);
    }

    /* fill in enc_sam_response_enc_2 */
    enc_sam_response_enc_2.magic = KV5M_ENC_SAM_RESPONSE_ENC_2;
    enc_sam_response_enc_2.sam_nonce = sc2b->sam_nonce;
    if (sc2b->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD) {
        enc_sam_response_enc_2.sam_sad = response_data;
    } else {
        enc_sam_response_enc_2.sam_sad.data = NULL;
        enc_sam_response_enc_2.sam_sad.length = 0;
    }

    /* encode and encrypt enc_sam_response_enc_2 with as_key */
    retval = encode_krb5_enc_sam_response_enc_2(&enc_sam_response_enc_2,
                                                &scratch);
    if (retval) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        return(retval);
    }

    /* Fill in sam_response_2 */
    memset(&sr2, 0, sizeof(sr2));
    sr2.sam_type = sc2b->sam_type;
    sr2.sam_flags = sc2b->sam_flags;
    sr2.sam_track_id = sc2b->sam_track_id;
    sr2.sam_nonce = sc2b->sam_nonce;

    /* Now take care of sr2.sam_enc_nonce_or_sad by encrypting encoded   */
    /* enc_sam_response_enc_2 from above */

    retval = krb5_c_encrypt_length(context, as_key->enctype, scratch->length,
                                   &ciph_len);
    if (retval) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        krb5_free_data(context, scratch);
        return(retval);
    }
    sr2.sam_enc_nonce_or_sad.ciphertext.length = ciph_len;

    sr2.sam_enc_nonce_or_sad.ciphertext.data =
        (char *)malloc(sr2.sam_enc_nonce_or_sad.ciphertext.length);

    if (!sr2.sam_enc_nonce_or_sad.ciphertext.data) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        krb5_free_data(context, scratch);
        return(ENOMEM);
    }

    retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_SAM_RESPONSE,
                            NULL, scratch, &sr2.sam_enc_nonce_or_sad);
    if (retval) {
        krb5_free_sam_challenge_2(context, sc2);
        krb5_free_sam_challenge_2_body(context, sc2b);
        krb5_free_data(context, scratch);
        krb5_free_data_contents(context, &sr2.sam_enc_nonce_or_sad.ciphertext);
        return(retval);
    }
    krb5_free_data(context, scratch);
    scratch = NULL;

    /* Encode the sam_response_2 */
    retval = encode_krb5_sam_response_2(&sr2, &scratch);
    krb5_free_sam_challenge_2(context, sc2);
    krb5_free_sam_challenge_2_body(context, sc2b);
    krb5_free_data_contents(context, &sr2.sam_enc_nonce_or_sad.ciphertext);

    if (retval) {
        return (retval);
    }

    /* Almost there, just need to make padata !  */
    sam_padata = malloc(sizeof(krb5_pa_data));
    if (sam_padata == NULL) {
        krb5_free_data(context, scratch);
        return(ENOMEM);
    }

    sam_padata->magic = KV5M_PA_DATA;
    sam_padata->pa_type = KRB5_PADATA_SAM_RESPONSE_2;
    sam_padata->length = scratch->length;
    sam_padata->contents = (krb5_octet *) scratch->data;
    free(scratch);

    *out_padata = sam_padata;

    return(0);
}

static krb5_error_code
pa_s4u_x509_user(krb5_context context, krb5_kdc_req *request,
                 krb5_pa_data *in_padata, krb5_pa_data **out_padata,
                 krb5_data *salt, krb5_data *s2kparams, krb5_enctype *etype,
                 krb5_keyblock *as_key, krb5_prompter_fct prompter,
                 void *prompter_data, krb5_gic_get_as_key_fct gak_fct,
                 void *gak_data)
{
    krb5_s4u_userid *userid = (krb5_s4u_userid *)gak_data; /* XXX private contract */
    krb5_pa_data *s4u_padata;
    krb5_error_code code;
    krb5_principal client;

    *out_padata = NULL;

    if (userid == NULL)
        return EINVAL;

    code = krb5_copy_principal(context, request->client, &client);
    if (code != 0)
        return code;

    if (userid->user != NULL)
        krb5_free_principal(context, userid->user);
    userid->user = client;

    if (userid->subject_cert.length != 0) {
        s4u_padata = malloc(sizeof(*s4u_padata));
        if (s4u_padata == NULL)
            return ENOMEM;

        s4u_padata->magic = KV5M_PA_DATA;
        s4u_padata->pa_type = KRB5_PADATA_S4U_X509_USER;
        s4u_padata->contents = malloc(userid->subject_cert.length);
        if (s4u_padata->contents == NULL) {
            free(s4u_padata);
            return ENOMEM;
        }
        memcpy(s4u_padata->contents, userid->subject_cert.data, userid->subject_cert.length);
        s4u_padata->length = userid->subject_cert.length;

        *out_padata = s4u_padata;
    }

    return 0;
}

/* FIXME - order significant? */
static const pa_types_t pa_types[] = {
    {
        KRB5_PADATA_PW_SALT,
        pa_salt,
        PA_INFO,
    },
    {
        KRB5_PADATA_AFS3_SALT,
        pa_salt,
        PA_INFO,
    },
#if APPLE_PKINIT
    {
        KRB5_PADATA_PK_AS_REQ,
        pa_pkinit_gen_req,
        PA_INFO,
    },
    {
        KRB5_PADATA_PK_AS_REP,
        pa_pkinit_parse_rep,
        PA_REAL,
    },
#endif /* APPLE_PKINIT */
    {
        KRB5_PADATA_SAM_CHALLENGE_2,
        pa_sam_2,
        PA_REAL,
    },
    {
        KRB5_PADATA_FX_COOKIE,
        pa_fx_cookie,
        PA_INFO,
    },
    {
        KRB5_PADATA_S4U_X509_USER,
        pa_s4u_x509_user,
        PA_INFO,
    },
    {
        -1,
        NULL,
        0,
    },
};

/*
 * If one of the modules can adjust its AS_REQ data using the contents of the
 * err_reply, return 0.  If it's the sort of correction which requires that we
 * ask the user another question, we let the calling application deal with it.
 */
krb5_error_code KRB5_CALLCONV
krb5_do_preauth_tryagain(krb5_context kcontext,
                         krb5_kdc_req *request,
                         krb5_data *encoded_request_body,
                         krb5_data *encoded_previous_request,
                         krb5_pa_data **padata,
                         krb5_pa_data ***return_padata,
                         krb5_error *err_reply,
                         krb5_pa_data **err_padata,
                         krb5_prompter_fct prompter, void *prompter_data,
                         krb5_clpreauth_rock preauth_rock,
                         krb5_gic_opt_ext *opte)
{
    krb5_error_code ret;
    krb5_pa_data **out_padata;
    krb5_preauth_context *context;
    struct krb5_preauth_context_module_st *module;
    int i, j;
    int out_pa_list_size = 0;

    ret = KRB5KRB_ERR_GENERIC;
    if (kcontext->preauth_context == NULL) {
        return KRB5KRB_ERR_GENERIC;
    }
    context = kcontext->preauth_context;
    if (context == NULL) {
        return KRB5KRB_ERR_GENERIC;
    }

    TRACE_PREAUTH_TRYAGAIN_INPUT(kcontext, padata);

    for (i = 0; padata[i] != NULL && padata[i]->pa_type != 0; i++) {
        out_padata = NULL;
        for (j = 0; j < context->n_modules; j++) {
            module = &context->modules[j];
            if (module->pa_type != padata[i]->pa_type) {
                continue;
            }
            if (module->client_tryagain == NULL) {
                continue;
            }
            if ((*module->client_tryagain)(kcontext, module->moddata,
                                           *module->modreq_p,
                                           (krb5_get_init_creds_opt *)opte,
                                           &callbacks, preauth_rock,
                                           request,
                                           encoded_request_body,
                                           encoded_previous_request,
                                           padata[i]->pa_type,
                                           err_reply, err_padata,
                                           prompter, prompter_data,
                                           &out_padata) == 0) {
                if (out_padata != NULL) {
                    int k;
                    for (k = 0; out_padata[k] != NULL; k++);
                    grow_pa_list(return_padata, &out_pa_list_size,
                                 out_padata, k);
                    free(out_padata);
                    TRACE_PREAUTH_TRYAGAIN_OUTPUT(kcontext, *return_padata);
                    return 0;
                }
            }
        }
    }
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_do_preauth(krb5_context context, krb5_kdc_req *request,
                krb5_data *encoded_request_body,
                krb5_data *encoded_previous_request,
                krb5_pa_data **in_padata, krb5_pa_data ***out_padata,
                krb5_prompter_fct prompter, void *prompter_data,
                krb5_clpreauth_rock rock, krb5_gic_opt_ext *opte,
                krb5_boolean *got_real_out)
{
    unsigned int h;
    int i, j, out_pa_list_size;
    int seen_etype_info2 = 0;
    krb5_pa_data *out_pa = NULL, **out_pa_list = NULL;
    krb5_data scratch;
    krb5_etype_info etype_info = NULL;
    krb5_error_code ret;
    static const int paorder[] = { PA_INFO, PA_REAL };
    int realdone;

    *got_real_out = FALSE;

    if (in_padata == NULL) {
        *out_padata = NULL;
        return(0);
    }

    TRACE_PREAUTH_INPUT(context, in_padata);

    out_pa_list = NULL;
    out_pa_list_size = 0;

    /* first do all the informational preauths, then the first real one */

    for (h=0; h<(sizeof(paorder)/sizeof(paorder[0])); h++) {
        realdone = 0;
        for (i=0; in_padata[i] && !realdone; i++) {
            int k, l, etype_found, valid_etype_found;
            /*
             * This is really gross, but is necessary to prevent
             * lossage when talking to a 1.0.x KDC, which returns an
             * erroneous PA-PW-SALT when it returns a KRB-ERROR
             * requiring additional preauth.
             */
            switch (in_padata[i]->pa_type) {
            case KRB5_PADATA_ETYPE_INFO:
            case KRB5_PADATA_ETYPE_INFO2:
            {
                krb5_preauthtype pa_type = in_padata[i]->pa_type;
                if (etype_info) {
                    if (seen_etype_info2 || pa_type != KRB5_PADATA_ETYPE_INFO2)
                        continue;
                    if (pa_type == KRB5_PADATA_ETYPE_INFO2) {
                        krb5_free_etype_info( context, etype_info);
                        etype_info = NULL;
                    }
                }

                scratch.length = in_padata[i]->length;
                scratch.data = (char *) in_padata[i]->contents;
                if (pa_type == KRB5_PADATA_ETYPE_INFO2) {
                    seen_etype_info2++;
                    ret = decode_krb5_etype_info2(&scratch, &etype_info);
                }
                else ret = decode_krb5_etype_info(&scratch, &etype_info);
                if (ret) {
                    ret = 0; /*Ignore error and etype_info element*/
                    if (etype_info)
                        krb5_free_etype_info( context, etype_info);
                    etype_info = NULL;
                    continue;
                }
                if (etype_info[0] == NULL) {
                    krb5_free_etype_info(context, etype_info);
                    etype_info = NULL;
                    break;
                }
                /*
                 * Select first etype in our request which is also in
                 * etype-info (preferring client request ktype order).
                 */
                for (etype_found = 0, valid_etype_found = 0, k = 0;
                     !etype_found && k < request->nktypes; k++) {
                    for (l = 0; etype_info[l]; l++) {
                        if (etype_info[l]->etype == request->ktype[k]) {
                            etype_found++;
                            break;
                        }
                        /* check if program has support for this etype for more
                         * precise error reporting.
                         */
                        if (krb5_c_valid_enctype(etype_info[l]->etype))
                            valid_etype_found++;
                    }
                }
                if (!etype_found) {
                    if (valid_etype_found) {
                        /* supported enctype but not requested */
                        ret =  KRB5_CONFIG_ETYPE_NOSUPP;
                        goto cleanup;
                    }
                    else {
                        /* unsupported enctype */
                        ret =  KRB5_PROG_ETYPE_NOSUPP;
                        goto cleanup;
                    }

                }
                scratch.data = (char *) etype_info[l]->salt;
                scratch.length = etype_info[l]->length;
                krb5_free_data_contents(context, rock->salt);
                if (scratch.length == KRB5_ETYPE_NO_SALT)
                    rock->salt->data = NULL;
                else {
                    ret = krb5int_copy_data_contents(context, &scratch,
                                                     rock->salt);
                    if (ret)
                        goto cleanup;
                }
                *rock->etype = etype_info[l]->etype;
                krb5_free_data_contents(context, rock->s2kparams);
                ret = krb5int_copy_data_contents(context,
                                                 &etype_info[l]->s2kparams,
                                                 rock->s2kparams);
                if (ret)
                    goto cleanup;
                TRACE_PREAUTH_ETYPE_INFO(context, *rock->etype, rock->salt,
                                         rock->s2kparams);
                break;
            }
            case KRB5_PADATA_PW_SALT:
            case KRB5_PADATA_AFS3_SALT:
                if (etype_info)
                    continue;
                break;
            default:
                ;
            }
            /* Try the internally-provided preauth type list. */
            if (!realdone) for (j=0; pa_types[j].type >= 0; j++) {
                    if ((in_padata[i]->pa_type == pa_types[j].type) &&
                        (pa_types[j].flags & paorder[h])) {
#ifdef DEBUG
                        fprintf (stderr, "calling internal function for pa_type "
                                 "%d, flag %d\n", pa_types[j].type, paorder[h]);
#endif
                        out_pa = NULL;

                        ret = pa_types[j].fct(context, request, in_padata[i],
                                              &out_pa, rock->salt,
                                              rock->s2kparams, rock->etype,
                                              rock->as_key, prompter,
                                              prompter_data, *rock->gak_fct,
                                              *rock->gak_data);
                        if (ret) {
                            if (paorder[h] == PA_INFO) {
                                TRACE_PREAUTH_INFO_FAIL(context,
                                                        in_padata[i]->pa_type,
                                                        ret);
                                ret = 0;
                                continue; /* PA_INFO type failed, ignore */
                            }

                            goto cleanup;
                        }

                        ret = grow_pa_list(&out_pa_list, &out_pa_list_size,
                                           &out_pa, 1);
                        if (ret != 0) {
                            goto cleanup;
                        }
                        if (paorder[h] == PA_REAL)
                            realdone = 1;
                    }
                }

            /* Try to use plugins now. */
            if (!realdone) {
                krb5_init_preauth_context(context);
                if (context->preauth_context != NULL) {
                    int module_ret = 0, module_flags;
#ifdef DEBUG
                    fprintf (stderr, "trying modules for pa_type %d, flag %d\n",
                             in_padata[i]->pa_type, paorder[h]);
#endif
                    ret = run_preauth_plugins(context,
                                              paorder[h],
                                              request,
                                              encoded_request_body,
                                              encoded_previous_request,
                                              in_padata[i],
                                              prompter,
                                              prompter_data,
                                              rock,
                                              &out_pa_list,
                                              &out_pa_list_size,
                                              &module_ret,
                                              &module_flags,
                                              opte);
                    if (ret == 0) {
                        if (module_ret == 0) {
                            if (paorder[h] == PA_REAL) {
                                realdone = 1;
                            }
                        }
                    }
                }
            }
        }
    }

    TRACE_PREAUTH_OUTPUT(context, out_pa_list);
    *out_padata = out_pa_list;
    if (etype_info)
        krb5_free_etype_info(context, etype_info);

    *got_real_out = realdone;
    return(0);
cleanup:
    if (out_pa_list) {
        out_pa_list[out_pa_list_size++] = NULL;
        krb5_free_pa_data(context, out_pa_list);
    }
    if (etype_info)
        krb5_free_etype_info(context, etype_info);
    return (ret);
}

/*
 * Give all the preauth plugins a look at the preauth option which
 * has just been set
 */
krb5_error_code
krb5_preauth_supply_preauth_data(krb5_context context, krb5_gic_opt_ext *opte,
                                 const char *attr, const char *value)
{
    krb5_error_code retval = 0;
    int i;
    struct krb5_preauth_context_module_st *mod;
    const char *emsg = NULL;

    if (context->preauth_context == NULL)
        krb5_init_preauth_context(context);
    if (context->preauth_context == NULL) {
        retval = EINVAL;
        krb5_set_error_message(context, retval,
                               _("Unable to initialize preauth context"));
        return retval;
    }

    /*
     * Go down the list of preauth modules, and supply them with the
     * attribute/value pair.
     */
    for (i = 0; i < context->preauth_context->n_modules; i++) {
        mod = &context->preauth_context->modules[i];
        if (mod->client_supply_gic_opts == NULL)
            continue;
        retval = mod->client_supply_gic_opts(context, mod->moddata,
                                             (krb5_get_init_creds_opt *)opte,
                                             attr, value);
        if (retval) {
            emsg = krb5_get_error_message(context, retval);
            krb5_set_error_message(context, retval, _("Preauth plugin %s: %s"),
                                   mod->name, emsg);
            krb5_free_error_message(context, emsg);
            break;
        }
    }
    return retval;
}

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1995, 2003, 2008, 2012 by the Massachusetts Institute of Technology.  All
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
#include "k5-json.h"
#include "osconf.h"
#include <krb5/preauth_plugin.h>
#include "int-proto.h"
#include "fast.h"
#include "init_creds_ctx.h"

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
        krb5_clpreauth_prep_questions_fn client_prep_questions;
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
    k5_plugin_register(kcontext, PLUGIN_INTERFACE_CLPREAUTH, "sam2",
                       clpreauth_sam2_initvt);
    k5_plugin_register(kcontext, PLUGIN_INTERFACE_CLPREAUTH, "otp",
                       clpreauth_otp_initvt);

    /* Get all available clpreauth vtables. */
    if (k5_plugin_load_all(kcontext, PLUGIN_INTERFACE_CLPREAUTH, &plugins))
        return;
    for (count = 0; plugins[count] != NULL; count++);
    vtables = calloc(count, sizeof(*vtables));
    if (vtables == NULL)
        goto cleanup;
    for (pl = plugins, n_tables = 0; *pl != NULL; pl++) {
        if ((*pl)(kcontext, 1, 2, (krb5_plugin_vtable)&vtables[n_tables]) == 0)
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
                mod->client_prep_questions = vt->prep_questions;
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
        context->preauth_context->modules[i].use_count = 0;
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
    ktypes = realloc(*out_ktypes, (*out_nktypes + 2) * sizeof(ktype));
    if (ktypes != NULL) {
        *out_ktypes = ktypes;
        ktypes[(*out_nktypes)++] = ktype;
        ktypes[*out_nktypes] = 0;
    }
}

/* Add a list of new pa_data items to an existing list. */
static int
grow_pa_list(krb5_pa_data ***out_pa_list, int *out_pa_list_size,
             krb5_pa_data **addition, int num_addition)
{
    krb5_pa_data **pa_list;
    int i;

    /* Allocate space for new entries and a null terminator. */
    pa_list = realloc(*out_pa_list, (*out_pa_list_size + num_addition + 1) *
                      sizeof(*pa_list));
    if (pa_list == NULL)
        return ENOMEM;
    *out_pa_list = pa_list;
    for (i = 0; i < num_addition; i++)
        pa_list[(*out_pa_list_size)++] = addition[i];
    pa_list[*out_pa_list_size] = NULL;
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
    krb5_data *salt;

    if (rock->as_key->length == 0) {
        salt = (*rock->default_salt) ? NULL : rock->salt;
        ret = (*rock->gak_fct)(context, rock->client, *rock->etype,
                               rock->prompter, rock->prompter_data, salt,
                               rock->s2kparams, rock->as_key, *rock->gak_data,
                               rock->rctx.items);
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

static krb5_error_code
get_preauth_time(krb5_context context, krb5_clpreauth_rock rock,
                 krb5_boolean allow_unauth_time, krb5_timestamp *time_out,
                 krb5_int32 *usec_out)
{
    if (rock->pa_offset_state != NO_OFFSET &&
        (allow_unauth_time || rock->pa_offset_state == AUTH_OFFSET) &&
        (context->library_options & KRB5_LIBOPT_SYNC_KDCTIME)) {
        /* Use the offset we got from the preauth-required error. */
        return k5_time_with_offset(rock->pa_offset, rock->pa_offset_usec,
                                   time_out, usec_out);

    } else {
        /* Use the time offset from the context, or no offset. */
        return krb5_us_timeofday(context, time_out, usec_out);
    }
}

static krb5_error_code
responder_ask_question(krb5_context context, krb5_clpreauth_rock rock,
                       const char *question, const char *challenge)
{
    /* Force plugins to use need_as_key(). */
    if (strcmp(KRB5_RESPONDER_QUESTION_PASSWORD, question) == 0)
        return EINVAL;
    return k5_response_items_ask_question(rock->rctx.items, question,
                                          challenge);
}

static const char *
responder_get_answer(krb5_context context, krb5_clpreauth_rock rock,
                     const char *question)
{
    /* Don't let plugins get the raw password. */
    if (question && strcmp(KRB5_RESPONDER_QUESTION_PASSWORD, question) == 0)
        return NULL;
    return k5_response_items_get_answer(rock->rctx.items, question);
}

static void
need_as_key(krb5_context context, krb5_clpreauth_rock rock)
{
    /* Calling gac_fct() with NULL as_key indicates desire for the AS key. */
    (*rock->gak_fct)(context, rock->client, *rock->etype, NULL, NULL, NULL,
                     NULL, NULL, *rock->gak_data, rock->rctx.items);
}

static const char *
get_cc_config(krb5_context context, krb5_clpreauth_rock rock, const char *key)
{
    k5_json_value value;

    if (rock->cc_config_in == NULL || *rock->cc_config_in == NULL)
        return NULL;

    value = k5_json_object_get(*rock->cc_config_in, key);
    if (value == NULL)
        return NULL;

    if (k5_json_get_tid(value) != K5_JSON_TID_STRING)
        return NULL;

    return k5_json_string_utf8(value);
}

static krb5_error_code
set_cc_config(krb5_context context, krb5_clpreauth_rock rock,
              const char *key, const char *data)
{
    k5_json_value value;
    int i;

    if (rock->cc_config_out == NULL || *rock->cc_config_out == NULL)
        return ENOENT;

    value = k5_json_string_create(data);
    if (value == NULL)
        return ENOMEM;

    i = k5_json_object_set(*rock->cc_config_out, key, value);
    k5_json_release(value);
    if (i < 0)
        return ENOMEM;

    return 0;
}

static struct krb5_clpreauth_callbacks_st callbacks = {
    2,
    get_etype,
    fast_armor,
    get_as_key,
    set_as_key,
    get_preauth_time,
    responder_ask_question,
    responder_get_answer,
    need_as_key,
    get_cc_config,
    set_cc_config
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

const char * const * KRB5_CALLCONV
krb5_responder_list_questions(krb5_context ctx, krb5_responder_context rctx)
{
    return k5_response_items_list_questions(rctx->items);
}

const char * KRB5_CALLCONV
krb5_responder_get_challenge(krb5_context ctx, krb5_responder_context rctx,
                             const char *question)
{
    if (rctx == NULL)
        return NULL;

    return k5_response_items_get_challenge(rctx->items, question);
}

krb5_error_code KRB5_CALLCONV
krb5_responder_set_answer(krb5_context ctx, krb5_responder_context rctx,
                          const char *question, const char *answer)
{
    if (rctx == NULL)
        return EINVAL;

    return k5_response_items_set_answer(rctx->items, question, answer);
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
                    krb5_error_code *module_ret,
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
        if ((module->flags & PA_REAL) &&
            *preauth_rock->allowed_preauth_type != KRB5_PADATA_NONE &&
            in_padata->pa_type != *preauth_rock->allowed_preauth_type)
            continue;
        /* if it's a REAL module, try to call it only once per library call */
        if (module_required_flags & PA_REAL) {
            if (module->use_count > 0) {
                TRACE_PREAUTH_SKIP(kcontext, module->name, module->pa_type);
                continue;
            }
            if (module->pa_type != KRB5_PADATA_SAM_CHALLENGE_2)
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

/* Set salt in rock based on pw-salt or afs3-salt elements in padata. */
static krb5_error_code
get_salt(krb5_context context, krb5_pa_data **padata,
         krb5_kdc_req *request, krb5_clpreauth_rock rock)
{
    krb5_error_code ret;
    krb5_pa_data *pa;
    krb5_data d;
    const char *p;

    /* Look for a pw-salt or afs3-salt element. */
    pa = krb5int_find_pa_data(context, padata, KRB5_PADATA_PW_SALT);
    if (pa == NULL)
        pa = krb5int_find_pa_data(context, padata, KRB5_PADATA_AFS3_SALT);
    if (pa == NULL)
        return 0;

    /* Set rock->salt based on the element we found. */
    krb5_free_data_contents(context, rock->salt);
    d = padata2data(*pa);
    ret = krb5int_copy_data_contents(context, &d, rock->salt);
    if (ret)
        return ret;

    /* Adjust the salt if we got it from an afs3-salt element. */
    if (pa->pa_type == KRB5_PADATA_AFS3_SALT) {
        /* Work around a (possible) old Heimdal KDC foible. */
        p = memchr(rock->salt->data, '@', rock->salt->length);
        if (p != NULL)
            rock->salt->length = p - rock->salt->data;
        /* Tolerate extra null in MIT KDC afs3-salt value. */
        if (rock->salt->length > 0 &&
            rock->salt->data[rock->salt->length - 1] == '\0')
            rock->salt->length--;
        /* Set an s2kparams value to indicate AFS string-to-key. */
        krb5_free_data_contents(context, rock->s2kparams);
        ret = alloc_data(rock->s2kparams, 1);
        if (ret)
            return ret;
        rock->s2kparams->data[0] = '\1';
    }

    *rock->default_salt = FALSE;
    TRACE_PREAUTH_SALT(context, rock->salt, pa->pa_type);
    return 0;
}

/* Set etype info parameters in rock based on padata. */
static krb5_error_code
get_etype_info(krb5_context context, krb5_pa_data **padata,
               krb5_kdc_req *request, krb5_clpreauth_rock rock)
{
    krb5_error_code ret = 0;
    krb5_pa_data *pa;
    krb5_data d;
    krb5_etype_info etype_info = NULL, e;
    krb5_etype_info_entry *entry;
    krb5_boolean valid_found;
    int i;

    /* Find an etype-info2 or etype-info element in padata. */
    pa = krb5int_find_pa_data(context, padata, KRB5_PADATA_ETYPE_INFO2);
    if (pa != NULL) {
        d = padata2data(*pa);
        (void)decode_krb5_etype_info2(&d, &etype_info);
    } else {
        pa = krb5int_find_pa_data(context, padata, KRB5_PADATA_ETYPE_INFO);
        if (pa != NULL) {
            d = padata2data(*pa);
            (void)decode_krb5_etype_info(&d, &etype_info);
        }
    }

    /* Fall back to pw-salt/afs3-salt if no etype-info element is present. */
    if (etype_info == NULL)
        return get_salt(context, padata, request, rock);

    /* Search entries in order of the request's enctype preference. */
    entry = NULL;
    valid_found = FALSE;
    for (i = 0; i < request->nktypes && entry == NULL; i++) {
        for (e = etype_info; *e != NULL && entry == NULL; e++) {
            if ((*e)->etype == request->ktype[i])
                entry = *e;
            if (krb5_c_valid_enctype((*e)->etype))
                valid_found = TRUE;
        }
    }
    if (entry == NULL) {
        ret = (valid_found) ? KRB5_CONFIG_ETYPE_NOSUPP :
            KRB5_PROG_ETYPE_NOSUPP;
        goto cleanup;
    }

    /* Set rock fields based on the entry we selected. */
    *rock->etype = entry->etype;
    krb5_free_data_contents(context, rock->salt);
    if (entry->length != KRB5_ETYPE_NO_SALT) {
        *rock->salt = make_data(entry->salt, entry->length);
        entry->salt = NULL;
        *rock->default_salt = FALSE;
    } else {
        *rock->salt = empty_data();
        *rock->default_salt = TRUE;
    }
    krb5_free_data_contents(context, rock->s2kparams);
    *rock->s2kparams = entry->s2kparams;
    entry->s2kparams = empty_data();
    TRACE_PREAUTH_ETYPE_INFO(context, *rock->etype, rock->salt,
                             rock->s2kparams);

cleanup:
    krb5_free_etype_info(context, etype_info);
    return ret;
}

/* Look for an fx-cookie element in in_padata and add it to out_pa_list. */
static krb5_error_code
copy_cookie(krb5_context context, krb5_pa_data **in_padata,
            krb5_pa_data ***out_pa_list, int *out_pa_list_size)
{
    krb5_error_code ret;
    krb5_pa_data *cookie, *pa = NULL;

    cookie = krb5int_find_pa_data(context, in_padata, KRB5_PADATA_FX_COOKIE);
    if (cookie == NULL)
        return 0;
    TRACE_PREAUTH_COOKIE(context, cookie->length, cookie->contents);
    pa = k5alloc(sizeof(*pa), &ret);
    if (pa == NULL)
        return ret;
    *pa = *cookie;
    pa->contents = k5alloc(cookie->length, &ret);
    if (pa->contents == NULL)
        goto error;
    memcpy(pa->contents, cookie->contents, cookie->length);
    ret = grow_pa_list(out_pa_list, out_pa_list_size, &pa, 1);
    if (ret)
        goto error;
    return 0;

error:
    free(pa->contents);
    free(pa);
    return ENOMEM;
}

static krb5_error_code
add_s4u_x509_user_padata(krb5_context context, krb5_s4u_userid *userid,
                         krb5_principal client, krb5_pa_data ***out_pa_list,
                         int *out_pa_list_size)
{
    krb5_pa_data *s4u_padata;
    krb5_error_code code;
    krb5_principal client_copy;

    if (userid == NULL)
        return EINVAL;
    code = krb5_copy_principal(context, client, &client_copy);
    if (code != 0)
        return code;
    krb5_free_principal(context, userid->user);
    userid->user = client_copy;

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

        code = grow_pa_list(out_pa_list, out_pa_list_size, &s4u_padata, 1);
        if (code) {
            free(s4u_padata->contents);
            free(s4u_padata);
            return code;
        }
    }

    return 0;
}

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
            if ((module->flags & PA_REAL) &&
                *preauth_rock->allowed_preauth_type != KRB5_PADATA_NONE &&
                padata[i]->pa_type != *preauth_rock->allowed_preauth_type) {
                /* It's unlikely that we'll get here. */
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

/* Compile the set of response items for in_padata by invoke each module's
 * prep_questions method. */
static krb5_error_code
fill_response_items(krb5_context context, krb5_kdc_req *request,
                    krb5_data *encoded_request_body,
                    krb5_data *encoded_previous_request,
                    krb5_pa_data **in_padata, krb5_clpreauth_rock rock,
                    krb5_gic_opt_ext *opte)
{
    krb5_error_code ret;
    krb5_pa_data *pa;
    struct krb5_preauth_context_module_st *module;
    krb5_clpreauth_prep_questions_fn prep_questions;
    int i, j;

    k5_response_items_reset(rock->rctx.items);
    for (i = 0; in_padata[i] != NULL; i++) {
        pa = in_padata[i];
        for (j = 0; j < context->preauth_context->n_modules; j++) {
            module = &context->preauth_context->modules[j];
            prep_questions = module->client_prep_questions;
            if (module->pa_type != pa->pa_type || prep_questions == NULL)
                continue;
            if ((module->flags & PA_REAL) &&
                *rock->allowed_preauth_type != KRB5_PADATA_NONE &&
                pa->pa_type != *rock->allowed_preauth_type)
                continue;
            ret = (*prep_questions)(context, module->moddata,
                                    *module->modreq_p,
                                    (krb5_get_init_creds_opt *)opte,
                                    &callbacks, rock, request,
                                    encoded_request_body,
                                    encoded_previous_request, pa);
            if (ret)
                return ret;
        }
    }
    return 0;
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
    size_t i, h;
    int out_pa_list_size = 0;
    krb5_pa_data **out_pa_list = NULL;
    krb5_error_code ret, module_ret;
    krb5_responder_fn responder = opte->opt_private->responder;
    static const int paorder[] = { PA_INFO, PA_REAL };

    *out_padata = NULL;
    *got_real_out = FALSE;

    if (in_padata == NULL)
        return 0;

    TRACE_PREAUTH_INPUT(context, in_padata);

    /* Scan the padata list and process etype-info or salt elements. */
    ret = get_etype_info(context, in_padata, request, rock);
    if (ret)
        return ret;

    /* Copy the cookie if there is one. */
    ret = copy_cookie(context, in_padata, &out_pa_list, &out_pa_list_size);
    if (ret)
        goto error;

    if (krb5int_find_pa_data(context, in_padata,
                             KRB5_PADATA_S4U_X509_USER) != NULL) {
        /* Fulfill a private contract with krb5_get_credentials_for_user. */
        ret = add_s4u_x509_user_padata(context, *rock->gak_data,
                                       request->client, &out_pa_list,
                                       &out_pa_list_size);
        if (ret)
            goto error;
    }

    /* If we can't initialize the preauth context, stop with what we have. */
    krb5_init_preauth_context(context);
    if (context->preauth_context == NULL) {
        *out_padata = out_pa_list;
        goto error;
    }

    /* Get a list of response items for in_padata from the preauth modules. */
    ret = fill_response_items(context, request, encoded_request_body,
                              encoded_previous_request, in_padata, rock, opte);
    if (ret)
        goto error;

    /* Call the responder to answer response items. */
    if (responder != NULL && !k5_response_items_empty(rock->rctx.items)) {
        ret = (*responder)(context, opte->opt_private->responder_data,
                           &rock->rctx);
        if (ret)
            goto error;
    }

    /* Produce output padata, first from all the informational preauths, then
     * the from first real one. */
    for (h = 0; h < sizeof(paorder) / sizeof(paorder[0]); h++) {
        for (i = 0; in_padata[i] != NULL; i++) {
#ifdef DEBUG
            fprintf (stderr, "trying modules for pa_type %d, flag %d\n",
                     in_padata[i]->pa_type, paorder[h]);
#endif
            ret = run_preauth_plugins(context, paorder[h], request,
                                      encoded_request_body,
                                      encoded_previous_request, in_padata[i],
                                      prompter, prompter_data, rock,
                                      &out_pa_list, &out_pa_list_size,
                                      &module_ret, opte);
            if (ret == 0 && module_ret == 0 && paorder[h] == PA_REAL) {
                /* Record which real padata type we answered. */
                if (rock->selected_preauth_type != NULL)
                    *rock->selected_preauth_type = in_padata[i]->pa_type;
                *got_real_out = TRUE;
                break;
            }
        }
    }

    TRACE_PREAUTH_OUTPUT(context, out_pa_list);
    *out_padata = out_pa_list;
    return 0;

error:
    krb5_free_pa_data(context, out_pa_list);
    return ret;
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

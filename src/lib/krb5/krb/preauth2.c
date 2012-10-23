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
#include <krb5/clpreauth_plugin.h>
#include "int-proto.h"
#include "fast.h"
#include "init_creds_ctx.h"

#if !defined(_WIN32)
#include <unistd.h>
#endif

typedef struct {
    struct krb5_clpreauth_vtable_st vt;
    krb5_clpreauth_moddata data;
    krb5_clpreauth_modreq req;
} *clpreauth_handle;

struct krb5_preauth_context_st {
    krb5_preauthtype *tried;
    clpreauth_handle *handles;
};

/* Release the memory used by a list of handles. */
static void
free_handles(krb5_context context, clpreauth_handle *handles)
{
    clpreauth_handle *hp, h;

    if (handles == NULL)
        return;
    for (hp = handles; *hp != NULL; hp++) {
        h = *hp;
        if (h->vt.fini != NULL)
            h->vt.fini(context, h->data);
        free(h);
    }
    free(handles);
}

/* Find the handle in handles which can process pa_type. */
static clpreauth_handle
find_module(clpreauth_handle *handles, krb5_preauthtype pa_type)
{
    clpreauth_handle *hp, h;
    krb5_preauthtype *tp;

    for (hp = handles; *hp != NULL; hp++) {
        h = *hp;
        for (tp = h->vt.pa_type_list; *tp != 0; tp++) {
            if (*tp == pa_type)
                return h;
        }
    }
    return FALSE;
}

/* Initialize the preauth state for a krb5 context. */
void KRB5_CALLCONV
krb5_init_preauth_context(krb5_context kcontext)
{
    krb5_plugin_initvt_fn *modules = NULL, *mod;
    clpreauth_handle *list = NULL, h, h2;
    size_t count;
    krb5_preauthtype *tp;

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
    if (k5_plugin_load_all(kcontext, PLUGIN_INTERFACE_CLPREAUTH, &modules))
        return;

    /* Allocate a large enough list of handles. */
    for (count = 0; modules[count] != NULL; count++);
    list = calloc(count + 1, sizeof(*list));
    if (list == NULL)
        goto cleanup;

    /* Create a handle for each module we can successfully initialize. */
    count = 0;
    for (mod = modules; *mod != NULL; mod++) {
        h = calloc(1, sizeof(*h));
        if (h == NULL)
            goto cleanup;

        /* Initialize the handle vtable. */
        if ((*mod)(kcontext, 1, 1, (krb5_plugin_vtable)&h->vt) != 0) {
            free(h);
            continue;
        }

        /* Check for a preauth type conflict with an existing module. */
        for (tp = h->vt.pa_type_list; *tp != 0; tp++) {
            h2 = find_module(list, *tp);
            if (h2 != NULL) {
                TRACE_PREAUTH_CONFLICT(kcontext, h->vt.name, h2->vt.name, *tp);
                break;
            }
        }
        if (*tp != 0)
            continue;

        /* Initialize the module data. */
        h->data = NULL;
        if (h->vt.init != NULL && h->vt.init(kcontext, &h->data) != 0) {
            free(h);
            continue;
        }
        list[count++] = h;
        list[count] = NULL;
    }
    list[count] = NULL;

    /* Place the constructed preauth context into the krb5 context. */
    kcontext->preauth_context = malloc(sizeof(struct krb5_preauth_context_st));
    if (kcontext->preauth_context == NULL)
        goto cleanup;
    kcontext->preauth_context->tried = NULL;
    kcontext->preauth_context->handles = list;
    list = NULL;

cleanup:
    k5_plugin_free_modules(kcontext, modules);
    free_handles(kcontext, list);
}

/* Zero the use counts for the modules herein.  Usually used before we
 * start processing any data from the server, at which point every module
 * will again be able to take a crack at whatever the server sent. */
void KRB5_CALLCONV
krb5_clear_preauth_context_use_counts(krb5_context context)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;

    if (pctx == NULL)
        return;
    free(pctx->tried);
    pctx->tried = NULL;
}


/* Free the per-krb5_context preauth_context. This means clearing any
 * plugin-specific context which may have been created, and then
 * freeing the context itself. */
void KRB5_CALLCONV
krb5_free_preauth_context(krb5_context context)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;

    if (pctx == NULL)
        return;
    free(pctx->tried);
    free_handles(context, pctx->handles);
    free(pctx);
    context->preauth_context = NULL;
}

/* Initialize the per-AS-REQ context. This means calling the client_req_init
 * function to give the plugin a chance to allocate a per-request context. */
void KRB5_CALLCONV
krb5_preauth_request_context_init(krb5_context context)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    clpreauth_handle *hp, h;

    if (pctx == NULL) {
        krb5_init_preauth_context(context);
        pctx = context->preauth_context;
        if (pctx == NULL)
            return;
    }
    krb5_clear_preauth_context_use_counts(context);
    for (hp = pctx->handles; *hp != NULL; hp++) {
        h = *hp;
        if (h->vt.request_init != NULL)
            h->vt.request_init(context, h->data, &h->req);
    }
}

/* Free the per-AS-REQ context. This means clearing any request-specific
 * context which the plugin may have created. */
void KRB5_CALLCONV
krb5_preauth_request_context_fini(krb5_context context)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    clpreauth_handle *hp, h;

    if (pctx == NULL)
        return;
    for (hp = pctx->handles; *hp != NULL; hp++) {
        h = *hp;
        if (h->req != NULL && h->vt.request_fini != NULL)
            h->vt.request_fini(context, h->data, h->req);
        h->req = NULL;
    }
}

/* Return 1 if pa_type is a real preauthentication mechanism according to the
 * module h.  Return 0 if it is not. */
static int
clpreauth_is_real(krb5_context context, clpreauth_handle h,
                  krb5_preauthtype pa_type)
{
    return (h->vt.flags(context, pa_type) & PA_REAL) != 0;
}

static krb5_error_code
clpreauth_prep_questions(krb5_context context, clpreauth_handle h,
                         krb5_get_init_creds_opt *opt,
                         krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
                         krb5_kdc_req *req, krb5_data *req_body,
                         krb5_data *prev_req, krb5_pa_data *pa_data)
{
    if (h->vt.prep_questions == NULL)
        return 0;
    return h->vt.prep_questions(context, h->data, h->req, opt, cb, rock, req,
                                req_body, prev_req, pa_data);
}

static krb5_error_code
clpreauth_process(krb5_context context, clpreauth_handle h,
                  krb5_get_init_creds_opt *opt, krb5_clpreauth_callbacks cb,
                  krb5_clpreauth_rock rock, krb5_kdc_req *req,
                  krb5_data *req_body, krb5_data *prev_req,
                  krb5_pa_data *pa_data, krb5_prompter_fct prompter,
                  void *prompter_data, krb5_pa_data ***pa_data_out)
{
    return h->vt.process(context, h->data, h->req, opt, cb, rock, req,
                         req_body, prev_req, pa_data, prompter, prompter_data,
                         pa_data_out);
}

static krb5_error_code
clpreauth_tryagain(krb5_context context, clpreauth_handle h,
                   krb5_get_init_creds_opt *opt, krb5_clpreauth_callbacks cb,
                   krb5_clpreauth_rock rock, krb5_kdc_req *req,
                   krb5_data *req_body, krb5_data *prev_req,
                   krb5_preauthtype pa_type, krb5_error *error,
                   krb5_pa_data **error_padata, krb5_prompter_fct prompter,
                   void *prompter_data, krb5_pa_data ***pa_data_out)
{
    if (h->vt.tryagain == NULL)
        return 0;
    return h->vt.tryagain(context, h->data, h->req, opt, cb, rock, req,
                          req_body, prev_req, pa_type, error, error_padata,
                          prompter, prompter_data, pa_data_out);
}

static krb5_error_code
clpreauth_gic_opts(krb5_context context, clpreauth_handle h,
                   krb5_get_init_creds_opt *opt, const char *attr,
                   const char *value)
{
    if (h->vt.gic_opts == NULL)
        return 0;
    return h->vt.gic_opts(context, h->data, opt, attr, value);
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
    struct krb5_preauth_context_st *pctx = kcontext->preauth_context;
    clpreauth_handle *hp, h;
    krb5_enctype *ep;

    if (pctx == NULL)
        return;
    /* Don't modify the enctype list if it's specified in the gic opts. */
    if (opte != NULL && (opte->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST))
        return;
    for (hp = pctx->handles; *hp != NULL; hp++) {
        h = *hp;
        if (h->vt.enctype_list == NULL)
            continue;
        for (ep = h->vt.enctype_list; *ep != ENCTYPE_NULL; ep++)
            grow_ktypes(&request->ktype, &request->nktypes, *ep);
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

/* Return true if pa_type matches the specific preauth type allowed for this
 * authentication, or if there is no specific allowed type. */
static inline krb5_boolean
pa_type_allowed(krb5_clpreauth_rock rock, krb5_preauthtype pa_type)
{
    return *rock->allowed_preauth_type == KRB5_PADATA_NONE ||
        pa_type == *rock->allowed_preauth_type;
}

/*
 * If pa_type has already been tried as a real preauth type for this
 * authentication, return true.  Otherwise ass pa_type to the list of tried
 * types and return false.
 */
static krb5_boolean
already_tried(krb5_context context, krb5_preauthtype pa_type)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    size_t count;
    krb5_preauthtype *newptr;

    for (count = 0; pctx->tried != NULL && pctx->tried[count] != 0; count++) {
        if (pctx->tried[count] == pa_type)
            return TRUE;
    }
    newptr = realloc(pctx->tried, (count + 2) * sizeof(*newptr));
    if (newptr == NULL)
        return FALSE;
    pctx->tried = newptr;
    pctx->tried[count] = pa_type;
    pctx->tried[count + 1] = ENCTYPE_NULL;
    return FALSE;
}

/* Allow clpreauth modules to process in_pa_list and produce output padata.
 * Set *preauthed to true if we succeeded on a real preauth type. */
static krb5_error_code
process_pa_data(krb5_context context, krb5_get_init_creds_opt *opt,
                krb5_clpreauth_rock rock, krb5_kdc_req *req,
                krb5_data *req_body, krb5_data *prev_req,
                krb5_pa_data **in_pa_list, krb5_prompter_fct prompter,
                void *prompter_data, krb5_pa_data ***out_pa_list,
                int *out_pa_list_size, krb5_boolean *got_real_out)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    krb5_pa_data *pa, **pa_ptr, **mod_pa;
    krb5_error_code ret;
    clpreauth_handle h;
    int real, i;

    if (pctx == NULL)
        return ENOENT;

    /* Process all informational padata types, then the first real preauth type
     * we succeed on. */
    for (real = 0; real <= 1; real++) {
        for (pa_ptr = in_pa_list; *pa_ptr != NULL; pa_ptr++) {
            pa = *pa_ptr;
            /* Restrict real mechanisms to the chosen one if we have one. */
            if (real && !pa_type_allowed(rock, pa->pa_type))
                continue;
            h = find_module(pctx->handles, pa->pa_type);
            if (h == NULL)
                continue;
            /* Make sure this type is for the current pass. */
            if (clpreauth_is_real(context, h, pa->pa_type) != real)
                continue;
            /* Only try a real mechanism once per authentication. */
            if (real && already_tried(context, pa->pa_type))
                continue;
            mod_pa = NULL;
            ret = clpreauth_process(context, h, opt, &callbacks, rock, req,
                                    req_body, prev_req, pa, prompter,
                                    prompter_data, &mod_pa);
            TRACE_PREAUTH_PROCESS(context, h->vt.name, pa->pa_type, real,
                                  ret);
            if (mod_pa != NULL) {
                for (i = 0; mod_pa[i] != NULL; i++);
                ret = grow_pa_list(out_pa_list, out_pa_list_size, mod_pa, i);
                if (ret) {
                    krb5_free_pa_data(context, mod_pa);
                    return ret;
                }
                free(mod_pa);
            }
            if (ret == 0 && real) {
                /* Record which real padata type we answered. */
                if (rock->selected_preauth_type != NULL)
                    *rock->selected_preauth_type = pa->pa_type;
                *got_real_out = TRUE;
                break;
            }
        }
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
krb5_do_preauth_tryagain(krb5_context context, krb5_kdc_req *req,
                         krb5_data *req_body, krb5_data *prev_req,
                         krb5_pa_data **in_padata, krb5_pa_data ***out_padata,
                         krb5_error *err_reply, krb5_pa_data **err_padata,
                         krb5_prompter_fct prompter, void *prompter_data,
                         krb5_clpreauth_rock rock, krb5_gic_opt_ext *opte)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    krb5_error_code ret;
    krb5_pa_data **mod_pa;
    krb5_get_init_creds_opt *opt = (krb5_get_init_creds_opt *)opte;
    clpreauth_handle h;
    int i;

    *out_padata = NULL;
    if (pctx == NULL)
        return KRB5KRB_ERR_GENERIC;

    TRACE_PREAUTH_TRYAGAIN_INPUT(context, in_padata);

    for (i = 0; in_padata[i] != NULL; i++) {
        out_padata = NULL;
        h = find_module(pctx->handles, in_padata[i]->pa_type);
        if (h == NULL)
            continue;
        mod_pa = NULL;
        ret = clpreauth_tryagain(context, h, opt, &callbacks, rock, req,
                                 req_body, prev_req, in_padata[i]->pa_type,
                                 err_reply, err_padata, prompter,
                                 prompter_data, &mod_pa);
        if (ret == 0 && mod_pa != NULL) {
            TRACE_PREAUTH_TRYAGAIN_OUTPUT(context, mod_pa);
            *out_padata = mod_pa;
            return 0;
        }
    }
    return KRB5KRB_ERR_GENERIC;
}

/* Compile the set of response items for in_padata by invoke each module's
 * prep_questions method. */
static krb5_error_code
fill_response_items(krb5_context context, krb5_get_init_creds_opt *opt,
                    krb5_clpreauth_rock rock, krb5_kdc_req *req,
                    krb5_data *req_body, krb5_data *prev_req,
                    krb5_pa_data **in_padata)
{
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    krb5_error_code ret;
    krb5_pa_data *pa;
    clpreauth_handle h;
    int i;

    k5_response_items_reset(rock->rctx.items);
    for (i = 0; in_padata[i] != NULL; i++) {
        pa = in_padata[i];
        if (!pa_type_allowed(rock, pa->pa_type))
            continue;
        h = find_module(pctx->handles, pa->pa_type);
        if (h == NULL)
            continue;
        ret = clpreauth_prep_questions(context, h, opt, &callbacks, rock, req,
                                       req_body, prev_req, pa);
        if (ret)
            return ret;
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_do_preauth(krb5_context context, krb5_kdc_req *req, krb5_data *req_body,
                krb5_data *prev_req, krb5_pa_data **in_padata,
                krb5_pa_data ***out_padata, krb5_prompter_fct prompter,
                void *prompter_data, krb5_clpreauth_rock rock,
                krb5_gic_opt_ext *opte, krb5_boolean *got_real_out)
{
    int out_pa_list_size = 0;
    krb5_pa_data **out_pa_list = NULL;
    krb5_error_code ret;
    krb5_responder_fn responder = opte->opt_private->responder;
    krb5_get_init_creds_opt *opt = (krb5_get_init_creds_opt *)opte;

    *out_padata = NULL;
    *got_real_out = FALSE;

    if (in_padata == NULL)
        return 0;

    TRACE_PREAUTH_INPUT(context, in_padata);

    /* Scan the padata list and process etype-info or salt elements. */
    ret = get_etype_info(context, in_padata, req, rock);
    if (ret)
        return ret;

    /* Copy the cookie if there is one. */
    ret = copy_cookie(context, in_padata, &out_pa_list, &out_pa_list_size);
    if (ret)
        goto error;

    if (krb5int_find_pa_data(context, in_padata,
                             KRB5_PADATA_S4U_X509_USER) != NULL) {
        /* Fulfill a private contract with krb5_get_credentials_for_user. */
        ret = add_s4u_x509_user_padata(context, *rock->gak_data, req->client,
                                       &out_pa_list, &out_pa_list_size);
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
    ret = fill_response_items(context, opt, rock, req, req_body, prev_req,
                              in_padata);
    if (ret)
        goto error;

    /* Call the responder to answer response items. */
    if (responder != NULL && !k5_response_items_empty(rock->rctx.items)) {
        ret = (*responder)(context, opte->opt_private->responder_data,
                           &rock->rctx);
        if (ret)
            goto error;
    }

    ret = process_pa_data(context, opt, rock, req, req_body, prev_req,
                          in_padata, prompter, prompter_data, &out_pa_list,
                          &out_pa_list_size, got_real_out);
    if (ret)
        goto error;

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
    struct krb5_preauth_context_st *pctx = context->preauth_context;
    krb5_get_init_creds_opt *opt = (krb5_get_init_creds_opt *)opte;
    clpreauth_handle *hp, h;
    krb5_error_code ret;
    const char *emsg = NULL;

    if (pctx == NULL) {
        krb5_init_preauth_context(context);
        pctx = context->preauth_context;
        if (pctx == NULL) {
            krb5_set_error_message(context, EINVAL,
                                   _("Unable to initialize preauth context"));
            return EINVAL;
        }
    }

    /*
     * Go down the list of preauth modules, and supply them with the
     * attribute/value pair.
     */
    for (hp = pctx->handles; *hp != NULL; hp++) {
        h = *hp;
        ret = clpreauth_gic_opts(context, h, opt, attr, value);
        if (ret) {
            emsg = krb5_get_error_message(context, ret);
            krb5_set_error_message(context, ret, _("Preauth module %s: %s"),
                                   h->vt.name, emsg);
            krb5_free_error_message(context, emsg);
            return ret;
        }
    }
    return 0;
}

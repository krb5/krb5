/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * kdc/kdc_preauth.c
 *
 * Copyright 1995, 2003, 2007, 2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Preauthentication routines for the KDC.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>
#include "adm_proto.h"
#if APPLE_PKINIT
#include "pkinit_server.h"
#include "pkinit_cert_store.h"
#endif /* APPLE_PKINIT */

#include <syslog.h>

#include <assert.h>
#include "../include/krb5/preauth_plugin.h"

#if TARGET_OS_MAC
static const char *objdirs[] = { KRB5_PLUGIN_BUNDLE_DIR,
                                 LIBDIR "/krb5/plugins/preauth",
                                 NULL }; /* should be a list */
#else
static const char *objdirs[] = { LIBDIR "/krb5/plugins/preauth", NULL };
#endif

/* XXX This is ugly and should be in a header file somewhere */
#ifndef KRB5INT_DES_TYPES_DEFINED
#define KRB5INT_DES_TYPES_DEFINED
typedef unsigned char des_cblock[8];    /* crypto-block size */
#endif
typedef des_cblock mit_des_cblock;
extern void mit_des_fixup_key_parity (mit_des_cblock );
extern int mit_des_is_weak_key (mit_des_cblock );

typedef struct _krb5_preauth_systems {
    const char *name;
    int         type;
    int         flags;
    void       *plugin_context;
    preauth_server_init_proc    init;
    preauth_server_fini_proc    fini;
    preauth_server_edata_proc   get_edata;
    preauth_server_verify_proc  verify_padata;
    preauth_server_return_proc  return_padata;
    preauth_server_free_reqcontext_proc free_pa_reqctx;
} krb5_preauth_systems;

static krb5_error_code
verify_enc_timestamp (krb5_context, krb5_db_entry *client,
                      krb5_data *req_pkt,
                      krb5_kdc_req *request,
                      krb5_enc_tkt_part * enc_tkt_reply, krb5_pa_data *data,
                      preauth_get_entry_data_proc get_entry_data,
                      void *pa_system_context,
                      void **pa_request_context,
                      krb5_data **e_data,
                      krb5_authdata ***authz_data);

static krb5_error_code
get_enc_ts(krb5_context, krb5_kdc_req *request,
           krb5_db_entry *client, krb5_db_entry *server,
           preauth_get_entry_data_proc get_entry_data,
           void *pa_system_context,
           krb5_pa_data *data);

static krb5_error_code
get_etype_info(krb5_context, krb5_kdc_req *request,
               krb5_db_entry *client, krb5_db_entry *server,
               preauth_get_entry_data_proc get_entry_data,
               void *pa_system_context,
               krb5_pa_data *data);

static krb5_error_code
get_etype_info2(krb5_context context, krb5_kdc_req *request,
                krb5_db_entry *client, krb5_db_entry *server,
                preauth_get_entry_data_proc get_entry_data,
                void *pa_system_context,
                krb5_pa_data *pa_data);

static krb5_error_code
etype_info_as_rep_helper(krb5_context context, krb5_pa_data * padata,
                         krb5_db_entry *client,
                         krb5_kdc_req *request, krb5_kdc_rep *reply,
                         krb5_key_data *client_key,
                         krb5_keyblock *encrypting_key,
                         krb5_pa_data **send_pa,
                         int etype_info2);

static krb5_error_code
return_etype_info(krb5_context, krb5_pa_data * padata,
                  krb5_db_entry *client,
                  krb5_data *req_pkt,
                  krb5_kdc_req *request, krb5_kdc_rep *reply,
                  krb5_key_data *client_key,
                  krb5_keyblock *encrypting_key,
                  krb5_pa_data **send_pa,
                  preauth_get_entry_data_proc get_entry_data,
                  void *pa_system_context,
                  void **pa_request_context);

static krb5_error_code
return_etype_info2(krb5_context, krb5_pa_data * padata,
                   krb5_db_entry *client,
                   krb5_data *req_pkt,
                   krb5_kdc_req *request, krb5_kdc_rep *reply,
                   krb5_key_data *client_key,
                   krb5_keyblock *encrypting_key,
                   krb5_pa_data **send_pa,
                   preauth_get_entry_data_proc get_entry_data,
                   void *pa_system_context,
                   void **pa_request_context);

static krb5_error_code
return_pw_salt(krb5_context, krb5_pa_data * padata,
               krb5_db_entry *client,
               krb5_data *req_pkt,
               krb5_kdc_req *request, krb5_kdc_rep *reply,
               krb5_key_data *client_key,
               krb5_keyblock *encrypting_key,
               krb5_pa_data **send_pa,
               preauth_get_entry_data_proc get_entry_data,
               void *pa_system_context,
               void **pa_request_context);


#if APPLE_PKINIT
/* PKINIT preauth support */
static krb5_error_code get_pkinit_edata(
    krb5_context context,
    krb5_kdc_req *request,
    krb5_db_entry *client,
    krb5_db_entry *server,
    preauth_get_entry_data_proc get_entry_data,
    void *pa_module_context,
    krb5_pa_data *pa_data);
static krb5_error_code verify_pkinit_request(
    krb5_context context,
    krb5_db_entry *client,
    krb5_data *req_pkt,
    krb5_kdc_req *request,
    krb5_enc_tkt_part *enc_tkt_reply,
    krb5_pa_data *data,
    preauth_get_entry_data_proc get_entry_data,
    void *pa_module_context,
    void **pa_request_context,
    krb5_data **e_data,
    krb5_authdata ***authz_data);
static krb5_error_code return_pkinit_response(
    krb5_context context,
    krb5_pa_data * padata,
    krb5_db_entry *client,
    krb5_data *req_pkt,
    krb5_kdc_req *request,
    krb5_kdc_rep *reply,
    krb5_key_data *client_key,
    krb5_keyblock *encrypting_key,
    krb5_pa_data **send_pa,
    preauth_get_entry_data_proc get_entry_data,
    void *pa_module_context,
    void **pa_request_context);
#endif /* APPLE_PKINIT */

static krb5_preauth_systems static_preauth_systems[] = {
#if APPLE_PKINIT
    {
        "pkinit",
        KRB5_PADATA_PK_AS_REQ,
        PA_SUFFICIENT,
        NULL,                   /* pa_sys_context */
        NULL,                   /* init */
        NULL,                   /* fini */
        get_pkinit_edata,
        verify_pkinit_request,
        return_pkinit_response,
        NULL                    /* free_pa_request_context */
    },
#endif /* APPLE_PKINIT */
    {
        "timestamp",
        KRB5_PADATA_ENC_TIMESTAMP,
        0,
        NULL,
        NULL,
        NULL,
        get_enc_ts,
        verify_enc_timestamp,
        0
    },
    {
        "FAST",
        KRB5_PADATA_FX_FAST,
        PA_HARDWARE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        0
    },
    {
        "etype-info",
        KRB5_PADATA_ETYPE_INFO,
        0,
        NULL,
        NULL,
        NULL,
        get_etype_info,
        0,
        return_etype_info
    },
    {
        "etype-info2",
        KRB5_PADATA_ETYPE_INFO2,
        0,
        NULL,
        NULL,
        NULL,
        get_etype_info2,
        0,
        return_etype_info2
    },
    {
        "pw-salt",
        KRB5_PADATA_PW_SALT,
        PA_PSEUDO,              /* Don't include this in the error list */
        NULL,
        NULL,
        NULL,
        0,
        0,
        return_pw_salt
    },
    {
        "pac-request",
        KRB5_PADATA_PAC_REQUEST,
        PA_PSEUDO,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    },
#if 0
    {
        "server-referral",
        KRB5_PADATA_SERVER_REFERRAL,
        PA_PSEUDO,
        0,
        0,
        return_server_referral
    },
#endif
    { "[end]", -1,}
};

static krb5_preauth_systems *preauth_systems;
static int n_preauth_systems;
static struct plugin_dir_handle preauth_plugins;

/* Open plugin directories for preauth modules. */
static krb5_error_code
open_preauth_plugin_dirs(krb5_context ctx)
{
    static const char *path[] = {
        KRB5_CONF_LIBDEFAULTS, KRB5_CONF_PREAUTH_MODULE_DIR, NULL,
    };
    char **profpath = NULL;
    const char **dirs;
    krb5_error_code ret;

    ret = profile_get_values(ctx->profile, path, &profpath);
    if (ret != 0 && ret != PROF_NO_RELATION)
        return ret;
    dirs = (profpath != NULL) ? (const char **) profpath : objdirs;
    ret = krb5int_open_plugin_dirs(dirs, NULL, &preauth_plugins, &ctx->err);
    profile_free_list(profpath);
    return ret;
}

krb5_error_code
load_preauth_plugins(krb5_context context)
{
    void **preauth_plugins_ftables;
    struct krb5plugin_preauth_server_ftable_v1 *ftable;
    size_t module_count, i, j, k;
    void *plugin_context;
    preauth_server_init_proc server_init_proc = NULL;
    char **kdc_realm_names = NULL;

    /* Attempt to load all of the preauth plugins we can find. */
    PLUGIN_DIR_INIT(&preauth_plugins);
    if (PLUGIN_DIR_OPEN(&preauth_plugins) == 0) {
        if (open_preauth_plugin_dirs(context) != 0)
            return KRB5_PLUGIN_NO_HANDLE;
    }

    /* Get the method tables provided by the loaded plugins. */
    preauth_plugins_ftables = NULL;
    if (krb5int_get_plugin_dir_data(&preauth_plugins,
                                    "preauthentication_server_1",
                                    &preauth_plugins_ftables, &context->err) != 0) {
        return KRB5_PLUGIN_NO_HANDLE;
    }

    /* Count the valid modules. */
    module_count = sizeof(static_preauth_systems)
        / sizeof(static_preauth_systems[0]);
    if (preauth_plugins_ftables != NULL) {
        for (i = 0; preauth_plugins_ftables[i] != NULL; i++) {
            ftable = preauth_plugins_ftables[i];
            if ((ftable->flags_proc == NULL) &&
                (ftable->edata_proc == NULL) &&
                (ftable->verify_proc == NULL) &&
                (ftable->return_proc == NULL)) {
                continue;
            }
            for (j = 0;
                 ftable->pa_type_list != NULL &&
                     ftable->pa_type_list[j] > 0;
                 j++) {
                module_count++;
            }
        }
    }

    /* Build the complete list of supported preauthentication options, and
     * leave room for a terminator entry. */
    preauth_systems = malloc(sizeof(krb5_preauth_systems) * (module_count + 1));
    if (preauth_systems == NULL) {
        krb5int_free_plugin_dir_data(preauth_plugins_ftables);
        return ENOMEM;
    }

    /* Build a list of the names of the supported realms for this KDC.
     * The list of names is terminated with a NULL. */
    kdc_realm_names = malloc(sizeof(char *) * (kdc_numrealms + 1));
    if (kdc_realm_names == NULL) {
        krb5int_free_plugin_dir_data(preauth_plugins_ftables);
        return ENOMEM;
    }
    for (i = 0; i < (size_t)kdc_numrealms; i++) {
        kdc_realm_names[i] = kdc_realmlist[i]->realm_name;
    }
    kdc_realm_names[i] = NULL;

    /* Add the locally-supplied mechanisms to the dynamic list first. */
    for (i = 0, k = 0;
         i < sizeof(static_preauth_systems) / sizeof(static_preauth_systems[0]);
         i++) {
        if (static_preauth_systems[i].type == -1)
            break;
        preauth_systems[k] = static_preauth_systems[i];
        /* Try to initialize the preauth system.  If it fails, we'll remove it
         * from the list of systems we'll be using. */
        plugin_context = NULL;
        server_init_proc = static_preauth_systems[i].init;
        if ((server_init_proc != NULL) &&
            ((*server_init_proc)(context, &plugin_context,
                                 (const char **)kdc_realm_names) != 0)) {
            memset(&preauth_systems[k], 0, sizeof(preauth_systems[k]));
            continue;
        }
        preauth_systems[k].plugin_context = plugin_context;
        k++;
    }

    /* Now add the dynamically-loaded mechanisms to the list. */
    if (preauth_plugins_ftables != NULL) {
        for (i = 0; preauth_plugins_ftables[i] != NULL; i++) {
            ftable = preauth_plugins_ftables[i];
            if ((ftable->flags_proc == NULL) &&
                (ftable->edata_proc == NULL) &&
                (ftable->verify_proc == NULL) &&
                (ftable->return_proc == NULL)) {
                continue;
            }
            plugin_context = NULL;
            for (j = 0;
                 ftable->pa_type_list != NULL &&
                     ftable->pa_type_list[j] > 0;
                 j++) {
                /* Try to initialize the plugin.  If it fails, we'll remove it
                 * from the list of modules we'll be using. */
                if (j == 0) {
                    server_init_proc = ftable->init_proc;
                    if (server_init_proc != NULL) {
                        krb5_error_code initerr;
                        initerr = (*server_init_proc)(context, &plugin_context,
                                                      (const char **)kdc_realm_names);
                        if (initerr) {
                            const char *emsg;
                            emsg = krb5_get_error_message(context, initerr);
                            if (emsg) {
                                krb5_klog_syslog(LOG_ERR,
                                                 "preauth %s failed to initialize: %s",
                                                 ftable->name, emsg);
                                krb5_free_error_message(context, emsg);
                            }
                            memset(&preauth_systems[k], 0,
                                   sizeof(preauth_systems[k]));

                            break;      /* skip all modules in this plugin */
                        }
                    }
                }
                preauth_systems[k].name = ftable->name;
                preauth_systems[k].type = ftable->pa_type_list[j];
                if (ftable->flags_proc != NULL)
                    preauth_systems[k].flags = ftable->flags_proc(context,
                                                                  preauth_systems[k].type);
                else
                    preauth_systems[k].flags = 0;
                preauth_systems[k].plugin_context = plugin_context;
                preauth_systems[k].init = server_init_proc;
                /* Only call fini once for each plugin */
                if (j == 0)
                    preauth_systems[k].fini = ftable->fini_proc;
                else
                    preauth_systems[k].fini = NULL;
                preauth_systems[k].get_edata = ftable->edata_proc;
                preauth_systems[k].verify_padata = ftable->verify_proc;
                preauth_systems[k].return_padata = ftable->return_proc;
                preauth_systems[k].free_pa_reqctx =
                    ftable->freepa_reqcontext_proc;
                k++;
            }
        }
        krb5int_free_plugin_dir_data(preauth_plugins_ftables);
    }
    free(kdc_realm_names);
    n_preauth_systems = k;
    /* Add the end-of-list marker. */
    preauth_systems[k].name = "[end]";
    preauth_systems[k].type = -1;
    return 0;
}

krb5_error_code
unload_preauth_plugins(krb5_context context)
{
    int i;
    if (preauth_systems != NULL) {
        for (i = 0; i < n_preauth_systems; i++) {
            if (preauth_systems[i].fini != NULL) {
                (*preauth_systems[i].fini)(context,
                                           preauth_systems[i].plugin_context);
            }
            memset(&preauth_systems[i], 0, sizeof(preauth_systems[i]));
        }
        free(preauth_systems);
        preauth_systems = NULL;
        n_preauth_systems = 0;
        krb5int_close_plugin_dirs(&preauth_plugins);
    }
    return 0;
}

/*
 * The make_padata_context() function creates a space for storing any context
 * information which will be needed by return_padata() later.  Each preauth
 * type gets a context storage location of its own.
 */
struct request_pa_context {
    int n_contexts;
    struct {
        krb5_preauth_systems *pa_system;
        void *pa_context;
    } *contexts;
};

static krb5_error_code
make_padata_context(krb5_context context, void **padata_context)
{
    int i;
    struct request_pa_context *ret;

    ret = malloc(sizeof(*ret));
    if (ret == NULL) {
        return ENOMEM;
    }

    ret->n_contexts = n_preauth_systems;
    ret->contexts = malloc(sizeof(ret->contexts[0]) * ret->n_contexts);
    if (ret->contexts == NULL) {
        free(ret);
        return ENOMEM;
    }

    memset(ret->contexts, 0, sizeof(ret->contexts[0]) * ret->n_contexts);

    for (i = 0; i < ret->n_contexts; i++) {
        ret->contexts[i].pa_system = &preauth_systems[i];
        ret->contexts[i].pa_context = NULL;
    }

    *padata_context = ret;

    return 0;
}

/*
 * The free_padata_context function frees any context information pointers
 * which the check_padata() function created but which weren't already cleaned
 * up by return_padata().
 */
krb5_error_code
free_padata_context(krb5_context kcontext, void **padata_context)
{
    struct request_pa_context *context;
    krb5_preauth_systems *preauth_system;
    void **pctx, *mctx;
    int i;

    if (padata_context == NULL)
        return 0;

    context = *padata_context;

    for (i = 0; i < context->n_contexts; i++) {
        if (context->contexts[i].pa_context != NULL) {
            preauth_system = context->contexts[i].pa_system;
            mctx = preauth_system->plugin_context;
            if (preauth_system->free_pa_reqctx != NULL) {
                pctx = &context->contexts[i].pa_context;
                (*preauth_system->free_pa_reqctx)(kcontext, mctx, pctx);
            }
            context->contexts[i].pa_context = NULL;
        }
    }

    free(context->contexts);
    free(context);

    return 0;
}

/* Retrieve a specified tl_data item from the given entry, and return its
 * contents in a new krb5_data, which must be freed by the caller.
 */
static krb5_error_code
get_entry_tl_data(krb5_context context, krb5_db_entry *entry,
                  krb5_int16 tl_data_type, krb5_data **result)
{
    krb5_tl_data *tl;
    for (tl = entry->tl_data; tl != NULL; tl = tl->tl_data_next) {
        if (tl->tl_data_type == tl_data_type) {
            *result = malloc(sizeof(krb5_data));
            if (*result == NULL) {
                return ENOMEM;
            }
            (*result)->magic = KV5M_DATA;
            (*result)->data = malloc(tl->tl_data_length);
            if ((*result)->data == NULL) {
                free(*result);
                *result = NULL;
                return ENOMEM;
            }
            memcpy((*result)->data, tl->tl_data_contents, tl->tl_data_length);
            return 0;
        }
    }
    return ENOENT;
}

/*
 * Retrieve a specific piece of information pertaining to the entry or the
 * request and return it in a new krb5_data item which the caller must free.
 *
 * This may require massaging data into a contrived format, but it will
 * hopefully keep us from having to reveal library-internal functions to
 * modules.
 */
static krb5_error_code
get_entry_data(krb5_context context,
               krb5_kdc_req *request, krb5_db_entry *entry,
               krb5_int32  type,
               krb5_data **result)
{
    int i, k;
    krb5_data *ret;
    krb5_deltat *delta;
    krb5_keyblock *keys;
    krb5_key_data *entry_key;
    krb5_error_code error;
    struct kdc_request_state *state = request->kdc_state;

    switch (type) {
    case krb5plugin_preauth_entry_request_certificate:
        return get_entry_tl_data(context, entry,
                                 KRB5_TL_USER_CERTIFICATE, result);
        break;
    case krb5plugin_preauth_entry_max_time_skew:
        ret = malloc(sizeof(krb5_data));
        if (ret == NULL)
            return ENOMEM;
        delta = malloc(sizeof(krb5_deltat));
        if (delta == NULL) {
            free(ret);
            return ENOMEM;
        }
        *delta = context->clockskew;
        ret->data = (char *) delta;
        ret->length = sizeof(*delta);
        *result = ret;
        return 0;
        break;
    case krb5plugin_preauth_keys:
        ret = malloc(sizeof(krb5_data));
        if (ret == NULL)
            return ENOMEM;
        keys = malloc(sizeof(krb5_keyblock) * (request->nktypes + 1));
        if (keys == NULL) {
            free(ret);
            return ENOMEM;
        }
        ret->data = (char *) keys;
        ret->length = sizeof(krb5_keyblock) * (request->nktypes + 1);
        memset(ret->data, 0, ret->length);
        k = 0;
        for (i = 0; i < request->nktypes; i++) {
            entry_key = NULL;
            if (krb5_dbe_find_enctype(context, entry, request->ktype[i],
                                      -1, 0, &entry_key) != 0)
                continue;
            if (krb5_dbe_decrypt_key_data(context, NULL, entry_key,
                                          &keys[k], NULL) != 0) {
                if (keys[k].contents != NULL)
                    krb5_free_keyblock_contents(context, &keys[k]);
                memset(&keys[k], 0, sizeof(keys[k]));
                continue;
            }
            k++;
        }
        if (k > 0) {
            *result = ret;
            return 0;
        } else {
            free(keys);
            free(ret);
        }
        break;
    case krb5plugin_preauth_request_body:
        ret = NULL;
        encode_krb5_kdc_req_body(request, &ret);
        if (ret != NULL) {
            *result = ret;
            return 0;
        }
        return ASN1_PARSE_ERROR;
        break;
    case krb5plugin_preauth_fast_armor:
        ret = calloc(1, sizeof(krb5_data));
        if (ret == NULL)
            return ENOMEM;
        if (state->armor_key == NULL) {
            *result = ret;
            return 0;
        }
        error = krb5_copy_keyblock(context, state->armor_key, &keys);
        if (error == 0) {
            ret->data = (char *) keys;
            ret->length = sizeof(krb5_keyblock);
            *result = ret;
            return 0;
        }
        free(ret);
        return error;
    case krb5plugin_preauth_free_fast_armor:
        if ((*result)->data) {
            keys = (krb5_keyblock *) (*result)->data;
            krb5_free_keyblock(context, keys);
        }
        free(*result);
        return 0;
    default:
        break;
    }
    return ENOENT;
}

static krb5_error_code
find_pa_system(int type, krb5_preauth_systems **preauth)
{
    krb5_preauth_systems *ap;

    ap = preauth_systems ? preauth_systems : static_preauth_systems;
    while ((ap->type != -1) && (ap->type != type))
        ap++;
    if (ap->type == -1)
        return(KRB5_PREAUTH_BAD_TYPE);
    *preauth = ap;
    return 0;
}

static krb5_error_code
find_pa_context(krb5_preauth_systems *pa_sys,
                struct request_pa_context *context,
                void ***pa_context)
{
    int i;

    *pa_context = 0;

    if (context == NULL)
        return KRB5KRB_ERR_GENERIC;

    for (i = 0; i < context->n_contexts; i++) {
        if (context->contexts[i].pa_system == pa_sys) {
            *pa_context = &context->contexts[i].pa_context;
            return 0;
        }
    }

    return KRB5KRB_ERR_GENERIC;
}

/*
 * Create a list of indices into the preauth_systems array, sorted by order of
 * preference.
 */
static krb5_boolean
pa_list_includes(krb5_pa_data **pa_data, krb5_preauthtype pa_type)
{
    while (*pa_data != NULL) {
        if ((*pa_data)->pa_type == pa_type)
            return TRUE;
        pa_data++;
    }
    return FALSE;
}
static void
sort_pa_order(krb5_context context, krb5_kdc_req *request, int *pa_order)
{
    int i, j, k, n_repliers, n_key_replacers;

    /* First, set up the default order. */
    i = 0;
    for (j = 0; j < n_preauth_systems; j++) {
        if (preauth_systems[j].return_padata != NULL)
            pa_order[i++] = j;
    }
    n_repliers = i;
    pa_order[n_repliers] = -1;

    /* Reorder so that PA_REPLACES_KEY modules are listed first. */
    for (i = 0; i < n_repliers; i++) {
        /* If this module replaces the key, then it's okay to leave it where it
         * is in the order. */
        if (preauth_systems[pa_order[i]].flags & PA_REPLACES_KEY)
            continue;
        /* If not, search for a module which does, and swap in the first one we
         * find. */
        for (j = i + 1; j < n_repliers; j++) {
            if (preauth_systems[pa_order[j]].flags & PA_REPLACES_KEY) {
                k = pa_order[j];
                pa_order[j] = pa_order[i];
                pa_order[i] = k;
                break;
            }
        }
    }

    if (request->padata != NULL) {
        /* Now reorder the subset of modules which replace the key,
         * bubbling those which handle pa_data types provided by the
         * client ahead of the others.
         */
        for (i = 0; preauth_systems[pa_order[i]].flags & PA_REPLACES_KEY; i++) {
            continue;
        }
        n_key_replacers = i;
        for (i = 0; i < n_key_replacers; i++) {
            if (pa_list_includes(request->padata,
                                 preauth_systems[pa_order[i]].type))
                continue;
            for (j = i + 1; j < n_key_replacers; j++) {
                if (pa_list_includes(request->padata,
                                     preauth_systems[pa_order[j]].type)) {
                    k = pa_order[j];
                    pa_order[j] = pa_order[i];
                    pa_order[i] = k;
                    break;
                }
            }
        }
    }
#ifdef DEBUG
    krb5_klog_syslog(LOG_DEBUG, "original preauth mechanism list:");
    for (i = 0; i < n_preauth_systems; i++) {
        if (preauth_systems[i].return_padata != NULL)
            krb5_klog_syslog(LOG_DEBUG, "... %s(%d)", preauth_systems[i].name,
                             preauth_systems[i].type);
    }
    krb5_klog_syslog(LOG_DEBUG, "sorted preauth mechanism list:");
    for (i = 0; pa_order[i] != -1; i++) {
        krb5_klog_syslog(LOG_DEBUG, "... %s(%d)",
                         preauth_systems[pa_order[i]].name,
                         preauth_systems[pa_order[i]].type);
    }
#endif
}

const char *missing_required_preauth(krb5_db_entry *client,
                                     krb5_db_entry *server,
                                     krb5_enc_tkt_part *enc_tkt_reply)
{
#if 0
    /*
     * If this is the pwchange service, and the pre-auth bit is set,
     * allow it even if the HW preauth would normally be required.
     *
     * Sandia national labs wanted this for some strange reason... we
     * leave it disabled normally.
     */
    if (isflagset(server->attributes, KRB5_KDB_PWCHANGE_SERVICE) &&
        isflagset(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH))
        return 0;
#endif

#ifdef DEBUG
    krb5_klog_syslog (
        LOG_DEBUG,
        "client needs %spreauth, %shw preauth; request has %spreauth, %shw preauth",
        isflagset (client->attributes, KRB5_KDB_REQUIRES_PRE_AUTH) ? "" : "no ",
        isflagset (client->attributes, KRB5_KDB_REQUIRES_HW_AUTH) ? "" : "no ",
        isflagset (enc_tkt_reply->flags, TKT_FLG_PRE_AUTH) ? "" : "no ",
        isflagset (enc_tkt_reply->flags, TKT_FLG_HW_AUTH) ? "" : "no ");
#endif

    if (isflagset(client->attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
        !isflagset(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH))
        return "NEEDED_PREAUTH";

    if (isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH) &&
        !isflagset(enc_tkt_reply->flags, TKT_FLG_HW_AUTH))
        return "NEEDED_HW_PREAUTH";

    return 0;
}

void
get_preauth_hint_list(krb5_kdc_req *request, krb5_db_entry *client,
                      krb5_db_entry *server, krb5_data *e_data)
{
    int hw_only;
    krb5_preauth_systems *ap;
    krb5_pa_data **pa_data, **pa;
    krb5_data *edat;
    krb5_error_code retval;

    /* Zero these out in case we need to abort */
    e_data->length = 0;
    e_data->data = 0;

    hw_only = isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH);
    /* Allocate two extra entries for the cookie and the terminator. */
    pa_data = calloc(n_preauth_systems + 2, sizeof(krb5_pa_data *));
    if (pa_data == 0)
        return;
    pa = pa_data;

    for (ap = preauth_systems; ap->type != -1; ap++) {
        if (hw_only && !(ap->flags & PA_HARDWARE))
            continue;
        if (ap->flags & PA_PSEUDO)
            continue;
        *pa = malloc(sizeof(krb5_pa_data));
        if (*pa == 0)
            goto errout;
        memset(*pa, 0, sizeof(krb5_pa_data));
        (*pa)->magic = KV5M_PA_DATA;
        (*pa)->pa_type = ap->type;
        if (ap->get_edata) {
            retval = (ap->get_edata)(kdc_context, request, client, server,
                                     get_entry_data, ap->plugin_context, *pa);
            if (retval) {
                /* just failed on this type, continue */
                free(*pa);
                *pa = 0;
                continue;
            }
        }
        pa++;
    }
    if (pa_data[0] == 0) {
        krb5_klog_syslog (LOG_INFO,
                          "%spreauth required but hint list is empty",
                          hw_only ? "hw" : "");
    }
    /*
     * If we fail to get the cookie it is probably
     * still reasonable to continue with the response
     */
    kdc_preauth_get_cookie(request->kdc_state, pa);
    retval = encode_krb5_padata_sequence(pa_data, &edat);
    if (retval)
        goto errout;
    *e_data = *edat;
    free(edat);

errout:
    krb5_free_pa_data(kdc_context, pa_data);
    return;
}

/*
 * Add authorization data returned from preauth modules to the ticket
 * It is assumed that ad is a "null-terminated" array of krb5_authdata ptrs
 */
static krb5_error_code
add_authorization_data(krb5_enc_tkt_part *enc_tkt_part, krb5_authdata **ad)
{
    krb5_authdata **newad;
    int oldones, newones;
    int i;

    if (enc_tkt_part == NULL || ad == NULL)
        return EINVAL;

    for (newones = 0; ad[newones] != NULL; newones++);
    if (newones == 0)
        return 0;   /* nothing to add */

    if (enc_tkt_part->authorization_data == NULL)
        oldones = 0;
    else
        for (oldones = 0;
             enc_tkt_part->authorization_data[oldones] != NULL; oldones++);

    newad = malloc((oldones + newones + 1) * sizeof(krb5_authdata *));
    if (newad == NULL)
        return ENOMEM;

    /* Copy any existing pointers */
    for (i = 0; i < oldones; i++)
        newad[i] = enc_tkt_part->authorization_data[i];

    /* Add the new ones */
    for (i = 0; i < newones; i++)
        newad[oldones+i] = ad[i];

    /* Terminate the new list */
    newad[oldones+i] = NULL;

    /* Free any existing list */
    if (enc_tkt_part->authorization_data != NULL)
        free(enc_tkt_part->authorization_data);

    /* Install our new list */
    enc_tkt_part->authorization_data = newad;

    return 0;
}

/*
 * This routine is called to verify the preauthentication information
 * for a V5 request.
 *
 * Returns 0 if the pre-authentication is valid, non-zero to indicate
 * an error code of some sort.
 */

krb5_error_code
check_padata (krb5_context context, krb5_db_entry *client, krb5_data *req_pkt,
              krb5_kdc_req *request, krb5_enc_tkt_part *enc_tkt_reply,
              void **padata_context, krb5_data *e_data)
{
    krb5_error_code retval = 0;
    krb5_pa_data **padata;
    krb5_preauth_systems *pa_sys;
    void **pa_context;
    krb5_data *pa_e_data = NULL, *tmp_e_data = NULL;
    int pa_ok = 0, pa_found = 0;
    krb5_error_code saved_retval = 0;
    int use_saved_retval = 0;
    const char *emsg;
    krb5_authdata **tmp_authz_data = NULL;

    if (request->padata == 0)
        return 0;

    if (make_padata_context(context, padata_context) != 0) {
        return KRB5KRB_ERR_GENERIC;
    }

#ifdef DEBUG
    krb5_klog_syslog (LOG_DEBUG, "checking padata");
#endif
    for (padata = request->padata; *padata; padata++) {
#ifdef DEBUG
        krb5_klog_syslog (LOG_DEBUG, ".. pa_type 0x%x", (*padata)->pa_type);
#endif
        if (find_pa_system((*padata)->pa_type, &pa_sys))
            continue;
        if (find_pa_context(pa_sys, *padata_context, &pa_context))
            continue;
#ifdef DEBUG
        krb5_klog_syslog (LOG_DEBUG, ".. pa_type %s", pa_sys->name);
#endif
        if (pa_sys->verify_padata == 0)
            continue;
        pa_found++;
        retval = pa_sys->verify_padata(context, client, req_pkt, request,
                                       enc_tkt_reply, *padata,
                                       get_entry_data, pa_sys->plugin_context,
                                       pa_context, &tmp_e_data, &tmp_authz_data);
        if (retval) {
            emsg = krb5_get_error_message (context, retval);
            krb5_klog_syslog (LOG_INFO, "preauth (%s) verify failure: %s",
                              pa_sys->name, emsg);
            krb5_free_error_message (context, emsg);
            /* Ignore authorization data returned from modules that fail */
            if (tmp_authz_data != NULL) {
                krb5_free_authdata(context, tmp_authz_data);
                tmp_authz_data = NULL;
            }
            if (pa_sys->flags & PA_REQUIRED) {
                /* free up any previous edata we might have been saving */
                if (pa_e_data != NULL)
                    krb5_free_data(context, pa_e_data);
                pa_e_data = tmp_e_data;
                tmp_e_data = NULL;
                use_saved_retval = 0; /* Make sure we use the current retval */
                pa_ok = 0;
                break;
            }
            /*
             * We'll return edata from either the first PA_REQUIRED module
             * that fails, or the first non-PA_REQUIRED module that fails.
             * Hang on to edata from the first non-PA_REQUIRED module.
             * If we've already got one saved, simply discard this one.
             */
            if (tmp_e_data != NULL) {
                if (pa_e_data == NULL) {
                    /* save the first error code and e-data */
                    pa_e_data = tmp_e_data;
                    tmp_e_data = NULL;
                    saved_retval = retval;
                    use_saved_retval = 1;
                } else {
                    /* discard this extra e-data from non-PA_REQUIRED module */
                    krb5_free_data(context, tmp_e_data);
                    tmp_e_data = NULL;
                }
            }
        } else {
#ifdef DEBUG
            krb5_klog_syslog (LOG_DEBUG, ".. .. ok");
#endif
            /* Ignore any edata returned on success */
            if (tmp_e_data != NULL) {
                krb5_free_data(context, tmp_e_data);
                tmp_e_data = NULL;
            }
            /* Add any authorization data to the ticket */
            if (tmp_authz_data != NULL) {
                add_authorization_data(enc_tkt_reply, tmp_authz_data);
                free(tmp_authz_data);
                tmp_authz_data = NULL;
            }
            pa_ok = 1;
            if (pa_sys->flags & PA_SUFFICIENT)
                break;
        }
    }

    /* Don't bother copying and returning e-data on success */
    if (pa_ok && pa_e_data != NULL) {
        krb5_free_data(context, pa_e_data);
        pa_e_data = NULL;
    }
    /* Return any e-data from the preauth that caused us to exit the loop */
    if (pa_e_data != NULL) {
        e_data->data = malloc(pa_e_data->length);
        if (e_data->data == NULL) {
            krb5_free_data(context, pa_e_data);
            return KRB5KRB_ERR_GENERIC;
        }
        memcpy(e_data->data, pa_e_data->data, pa_e_data->length);
        e_data->length = pa_e_data->length;
        krb5_free_data(context, pa_e_data);
        pa_e_data = NULL;
        if (use_saved_retval != 0)
            retval = saved_retval;
    }

    if (pa_ok)
        return 0;

    /* pa system was not found; we may return PREAUTH_REQUIRED later,
       but we did not actually fail to verify the pre-auth. */
    if (!pa_found)
        return 0;


    /* The following switch statement allows us
     * to return some preauth system errors back to the client.
     */
    switch(retval) {
    case 0: /* in case of PA-PAC-REQUEST with no PA-ENC-TIMESTAMP */
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KRB_AP_ERR_SKEW:
    case KRB5KDC_ERR_PREAUTH_REQUIRED:
    case KRB5KDC_ERR_ETYPE_NOSUPP:
        /* rfc 4556 */
    case KRB5KDC_ERR_CLIENT_NOT_TRUSTED:
    case KRB5KDC_ERR_INVALID_SIG:
    case KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:
    case KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE:
    case KRB5KDC_ERR_INVALID_CERTIFICATE:
    case KRB5KDC_ERR_REVOKED_CERTIFICATE:
    case KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN:
    case KRB5KDC_ERR_CLIENT_NAME_MISMATCH:
    case KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE:
    case KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED:
    case KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED:
    case KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED:
    case KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED:
        /* earlier drafts of what became rfc 4556 */
    case KRB5KDC_ERR_CERTIFICATE_MISMATCH:
    case KRB5KDC_ERR_KDC_NOT_TRUSTED:
    case KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE:
        /* This value is shared with KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED. */
        /* case KRB5KDC_ERR_KEY_TOO_WEAK: */
    case KRB5KDC_ERR_DISCARD:
        return retval;
    default:
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }
}

/*
 * return_padata creates any necessary preauthentication
 * structures which should be returned by the KDC to the client
 */
krb5_error_code
return_padata(krb5_context context, krb5_db_entry *client, krb5_data *req_pkt,
              krb5_kdc_req *request, krb5_kdc_rep *reply,
              krb5_key_data *client_key, krb5_keyblock *encrypting_key,
              void **padata_context)
{
    krb5_error_code             retval;
    krb5_pa_data **             padata;
    krb5_pa_data **             send_pa_list;
    krb5_pa_data **             send_pa;
    krb5_pa_data *              pa = 0;
    krb5_pa_data null_item;
    krb5_preauth_systems *      ap;
    int *                       pa_order;
    int *                       pa_type;
    int                         size = 0;
    void **                     pa_context;
    krb5_boolean                key_modified;
    krb5_keyblock               original_key;
    if ((!*padata_context) &&
        (make_padata_context(context, padata_context) != 0)) {
        return KRB5KRB_ERR_GENERIC;
    }

    for (ap = preauth_systems; ap->type != -1; ap++) {
        if (ap->return_padata)
            size++;
    }

    if ((send_pa_list = malloc((size+1) * sizeof(krb5_pa_data *))) == NULL)
        return ENOMEM;
    if ((pa_order = malloc((size+1) * sizeof(int))) == NULL) {
        free(send_pa_list);
        return ENOMEM;
    }
    sort_pa_order(context, request, pa_order);

    retval = krb5_copy_keyblock_contents(context, encrypting_key,
                                         &original_key);
    if (retval) {
        free(send_pa_list);
        free(pa_order);
        return retval;
    }
    key_modified = FALSE;
    null_item.contents = NULL;
    null_item.length = 0;
    send_pa = send_pa_list;
    *send_pa = 0;

    for (pa_type = pa_order; *pa_type != -1; pa_type++) {
        ap = &preauth_systems[*pa_type];
        if (!key_modified)
            if (original_key.enctype != encrypting_key->enctype)
                key_modified = TRUE;
        if (!key_modified)
            if (original_key.length != encrypting_key->length)
                key_modified = TRUE;
        if (!key_modified)
            if (memcmp(original_key.contents, encrypting_key->contents,
                       original_key.length) != 0)
                key_modified = TRUE;
        if (key_modified && (ap->flags & PA_REPLACES_KEY))
            continue;
        if (ap->return_padata == 0)
            continue;
        if (find_pa_context(ap, *padata_context, &pa_context))
            continue;
        pa = &null_item;
        null_item.pa_type = ap->type;
        if (request->padata) {
            for (padata = request->padata; *padata; padata++) {
                if ((*padata)->pa_type == ap->type) {
                    pa = *padata;
                    break;
                }
            }
        }
        if ((retval = ap->return_padata(context, pa, client, req_pkt,
                                        request, reply,
                                        client_key, encrypting_key, send_pa,
                                        get_entry_data, ap->plugin_context,
                                        pa_context))) {
            goto cleanup;
        }

        if (*send_pa)
            send_pa++;
        *send_pa = 0;
    }

    retval = 0;

    if (send_pa_list[0]) {
        reply->padata = send_pa_list;
        send_pa_list = 0;
    }

cleanup:
    krb5_free_keyblock_contents(context, &original_key);
    free(pa_order);
    if (send_pa_list)
        krb5_free_pa_data(context, send_pa_list);

    return (retval);
}

static krb5_boolean
request_contains_enctype(krb5_context context,  const krb5_kdc_req *request,
                         krb5_enctype enctype)
{
    int i;
    for (i =0; i < request->nktypes; i++)
        if (request->ktype[i] == enctype)
            return 1;
    return 0;
}

static krb5_error_code
get_enc_ts(krb5_context context, krb5_kdc_req *request,
           krb5_db_entry *client, krb5_db_entry *server,
           preauth_get_entry_data_proc get_entry_data_proc,
           void *pa_system_context,
           krb5_pa_data *data)
{
    struct kdc_request_state *state = request->kdc_state;
    if (state->armor_key)
        return ENOENT;
    return 0;
}


static krb5_error_code
verify_enc_timestamp(krb5_context context, krb5_db_entry *client,
                     krb5_data *req_pkt,
                     krb5_kdc_req *request, krb5_enc_tkt_part *enc_tkt_reply,
                     krb5_pa_data *pa,
                     preauth_get_entry_data_proc ets_get_entry_data,
                     void *pa_system_context,
                     void **pa_request_context,
                     krb5_data **e_data,
                     krb5_authdata ***authz_data)
{
    krb5_pa_enc_ts *            pa_enc = 0;
    krb5_error_code             retval;
    krb5_data                   scratch;
    krb5_data                   enc_ts_data;
    krb5_enc_data               *enc_data = 0;
    krb5_keyblock               key;
    krb5_key_data *             client_key;
    krb5_int32                  start;
    krb5_timestamp              timenow;
    krb5_error_code             decrypt_err = 0;

    scratch.data = (char *)pa->contents;
    scratch.length = pa->length;

    enc_ts_data.data = 0;

    if ((retval = decode_krb5_enc_data(&scratch, &enc_data)) != 0)
        goto cleanup;

    enc_ts_data.length = enc_data->ciphertext.length;
    if ((enc_ts_data.data = (char *) malloc(enc_ts_data.length)) == NULL)
        goto cleanup;

    start = 0;
    decrypt_err = 0;
    while (1) {
        if ((retval = krb5_dbe_search_enctype(context, client,
                                              &start, enc_data->enctype,
                                              -1, 0, &client_key)))
            goto cleanup;

        if ((retval = krb5_dbe_decrypt_key_data(context, NULL, client_key,
                                                &key, NULL)))
            goto cleanup;

        key.enctype = enc_data->enctype;

        retval = krb5_c_decrypt(context, &key, KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS,
                                0, enc_data, &enc_ts_data);
        krb5_free_keyblock_contents(context, &key);
        if (retval == 0)
            break;
        else
            decrypt_err = retval;
    }

    if ((retval = decode_krb5_pa_enc_ts(&enc_ts_data, &pa_enc)) != 0)
        goto cleanup;

    if ((retval = krb5_timeofday(context, &timenow)) != 0)
        goto cleanup;

    if (labs(timenow - pa_enc->patimestamp) > context->clockskew) {
        retval = KRB5KRB_AP_ERR_SKEW;
        goto cleanup;
    }

    setflag(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH);

    retval = 0;

cleanup:
    if (enc_data) {
        krb5_free_data_contents(context, &enc_data->ciphertext);
        free(enc_data);
    }
    krb5_free_data_contents(context, &enc_ts_data);
    if (pa_enc)
        free(pa_enc);
    /*
     * If we get NO_MATCHING_KEY and decryption previously failed, and
     * we failed to find any other keys of the correct enctype after
     * that failed decryption, it probably means that the password was
     * incorrect.
     */
    if (retval == KRB5_KDB_NO_MATCHING_KEY && decrypt_err != 0)
        retval = decrypt_err;

    return retval;
}

static krb5_error_code
_make_etype_info_entry(krb5_context context,
                       krb5_principal client_princ, krb5_key_data *client_key,
                       krb5_enctype etype, krb5_etype_info_entry **entry,
                       int etype_info2)
{
    krb5_data                   salt;
    krb5_etype_info_entry *     tmp_entry;
    krb5_error_code             retval;

    if ((tmp_entry = malloc(sizeof(krb5_etype_info_entry))) == NULL)
        return ENOMEM;

    salt.data = 0;

    tmp_entry->magic = KV5M_ETYPE_INFO_ENTRY;
    tmp_entry->etype = etype;
    tmp_entry->length = KRB5_ETYPE_NO_SALT;
    tmp_entry->salt = 0;
    tmp_entry->s2kparams.data = NULL;
    tmp_entry->s2kparams.length = 0;
    retval = get_salt_from_key(context, client_princ, client_key, &salt);
    if (retval)
        goto fail;
    if (etype_info2 && client_key->key_data_ver > 1 &&
        client_key->key_data_type[1] == KRB5_KDB_SALTTYPE_AFS3) {
        switch (etype) {
        case ENCTYPE_DES_CBC_CRC:
        case ENCTYPE_DES_CBC_MD4:
        case ENCTYPE_DES_CBC_MD5:
            tmp_entry->s2kparams.data = malloc(1);
            if (tmp_entry->s2kparams.data == NULL) {
                retval = ENOMEM;
                goto fail;
            }
            tmp_entry->s2kparams.length = 1;
            tmp_entry->s2kparams.data[0] = 1;
            break;
        default:
            break;
        }
    }

    if (salt.length >= 0) {
        tmp_entry->length = salt.length;
        tmp_entry->salt = (unsigned char *) salt.data;
        salt.data = 0;
    }
    *entry = tmp_entry;
    return 0;

fail:
    if (tmp_entry) {
        if (tmp_entry->s2kparams.data)
            free(tmp_entry->s2kparams.data);
        free(tmp_entry);
    }
    if (salt.data)
        free(salt.data);
    return retval;
}
/*
 * This function returns the etype information for a particular
 * client, to be passed back in the preauth list in the KRB_ERROR
 * message.  It supports generating both etype_info  and etype_info2
 *  as most of the work is the same.
 */
static krb5_error_code
etype_info_helper(krb5_context context, krb5_kdc_req *request,
                  krb5_db_entry *client, krb5_db_entry *server,
                  krb5_pa_data *pa_data, int etype_info2)
{
    krb5_etype_info_entry **    entry = 0;
    krb5_key_data               *client_key;
    krb5_error_code             retval;
    krb5_data *                 scratch;
    krb5_enctype                db_etype;
    int                         i = 0;
    int                         start = 0;
    int                         seen_des = 0;

    entry = malloc((client->n_key_data * 2 + 1) * sizeof(krb5_etype_info_entry *));
    if (entry == NULL)
        return ENOMEM;
    entry[0] = NULL;

    while (1) {
        retval = krb5_dbe_search_enctype(context, client, &start, -1,
                                         -1, 0, &client_key);
        if (retval == KRB5_KDB_NO_MATCHING_KEY)
            break;
        if (retval)
            goto cleanup;
        db_etype = client_key->key_data_type[0];
        if (db_etype == ENCTYPE_DES_CBC_MD4)
            db_etype = ENCTYPE_DES_CBC_MD5;

        if (request_contains_enctype(context, request, db_etype)) {
            assert(etype_info2 ||
                   !enctype_requires_etype_info_2(db_etype));
            retval = _make_etype_info_entry(context, client->princ, client_key,
                                            db_etype, &entry[i], etype_info2);
            if (retval != 0)
                goto cleanup;
            entry[i+1] = 0;
            i++;
        }

        /*
         * If there is a des key in the kdb, try the "similar" enctypes,
         * avoid duplicate entries.
         */
        if (!seen_des) {
            switch (db_etype) {
            case ENCTYPE_DES_CBC_MD5:
                db_etype = ENCTYPE_DES_CBC_CRC;
                break;
            case ENCTYPE_DES_CBC_CRC:
                db_etype = ENCTYPE_DES_CBC_MD5;
                break;
            default:
                continue;

            }
            if (request_contains_enctype(context, request, db_etype)) {
                retval = _make_etype_info_entry(context, client->princ,
                                                client_key, db_etype,
                                                &entry[i], etype_info2);
                if (retval != 0)
                    goto cleanup;
                entry[i+1] = 0;
                i++;
            }
            seen_des++;
        }
    }
    if (etype_info2)
        retval = encode_krb5_etype_info2(entry, &scratch);
    else
        retval = encode_krb5_etype_info(entry, &scratch);
    if (retval)
        goto cleanup;
    pa_data->contents = (unsigned char *)scratch->data;
    pa_data->length = scratch->length;
    free(scratch);

    retval = 0;

cleanup:
    if (entry)
        krb5_free_etype_info(context, entry);
    return retval;
}

static krb5_error_code
get_etype_info(krb5_context context, krb5_kdc_req *request,
               krb5_db_entry *client, krb5_db_entry *server,
               preauth_get_entry_data_proc etype_get_entry_data,
               void *pa_system_context,
               krb5_pa_data *pa_data)
{
    int i;
    for (i=0;  i < request->nktypes; i++) {
        if (enctype_requires_etype_info_2(request->ktype[i]))
            return KRB5KDC_ERR_PADATA_TYPE_NOSUPP ;;;; /*Caller will
                                                        * skip this
                                                        * type*/
    }
    return etype_info_helper(context, request, client, server, pa_data, 0);
}

static krb5_error_code
get_etype_info2(krb5_context context, krb5_kdc_req *request,
                krb5_db_entry *client, krb5_db_entry *server,
                preauth_get_entry_data_proc etype_get_entry_data,
                void *pa_system_context,
                krb5_pa_data *pa_data)
{
    return etype_info_helper( context, request, client, server, pa_data, 1);
}

static krb5_error_code
etype_info_as_rep_helper(krb5_context context, krb5_pa_data * padata,
                         krb5_db_entry *client,
                         krb5_kdc_req *request, krb5_kdc_rep *reply,
                         krb5_key_data *client_key,
                         krb5_keyblock *encrypting_key,
                         krb5_pa_data **send_pa,
                         int etype_info2)
{
    int i;
    krb5_error_code retval;
    krb5_pa_data *tmp_padata;
    krb5_etype_info_entry **entry = NULL;
    krb5_data *scratch = NULL;

    /*
     * Skip PA-ETYPE-INFO completely if AS-REQ lists any "newer"
     * enctypes.
     */
    if (!etype_info2) {
        for (i = 0; i < request->nktypes; i++) {
            if (enctype_requires_etype_info_2(request->ktype[i])) {
                *send_pa = NULL;
                return 0;
            }
        }
    }

    tmp_padata = malloc( sizeof(krb5_pa_data));
    if (tmp_padata == NULL)
        return ENOMEM;
    if (etype_info2)
        tmp_padata->pa_type = KRB5_PADATA_ETYPE_INFO2;
    else
        tmp_padata->pa_type = KRB5_PADATA_ETYPE_INFO;

    entry = malloc(2 * sizeof(krb5_etype_info_entry *));
    if (entry == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }
    entry[0] = NULL;
    entry[1] = NULL;
    retval = _make_etype_info_entry(context, client->princ, client_key,
                                    encrypting_key->enctype, entry,
                                    etype_info2);
    if (retval)
        goto cleanup;

    if (etype_info2)
        retval = encode_krb5_etype_info2(entry, &scratch);
    else
        retval = encode_krb5_etype_info(entry, &scratch);

    if (retval)
        goto cleanup;
    tmp_padata->contents = (krb5_octet *)scratch->data;
    tmp_padata->length = scratch->length;
    *send_pa = tmp_padata;

    /* For cleanup - we no longer own the contents of the krb5_data
     * only to pointer to the krb5_data
     */
    scratch->data = 0;

cleanup:
    if (entry)
        krb5_free_etype_info(context, entry);
    if (retval) {
        if (tmp_padata)
            free(tmp_padata);
    }
    if (scratch)
        krb5_free_data(context, scratch);
    return retval;
}

static krb5_error_code
return_etype_info2(krb5_context context, krb5_pa_data * padata,
                   krb5_db_entry *client,
                   krb5_data *req_pkt,
                   krb5_kdc_req *request, krb5_kdc_rep *reply,
                   krb5_key_data *client_key,
                   krb5_keyblock *encrypting_key,
                   krb5_pa_data **send_pa,
                   preauth_get_entry_data_proc etype_get_entry_data,
                   void *pa_system_context,
                   void **pa_request_context)
{
    return etype_info_as_rep_helper(context, padata, client, request, reply,
                                    client_key, encrypting_key, send_pa, 1);
}


static krb5_error_code
return_etype_info(krb5_context context, krb5_pa_data * padata,
                  krb5_db_entry *client,
                  krb5_data *req_pkt,
                  krb5_kdc_req *request, krb5_kdc_rep *reply,
                  krb5_key_data *client_key,
                  krb5_keyblock *encrypting_key,
                  krb5_pa_data **send_pa,
                  preauth_get_entry_data_proc etypeget_entry_data,
                  void *pa_system_context,
                  void **pa_request_context)
{
    return etype_info_as_rep_helper(context, padata, client, request, reply,
                                    client_key, encrypting_key, send_pa, 0);
}

static krb5_error_code
return_pw_salt(krb5_context context, krb5_pa_data *in_padata,
               krb5_db_entry *client, krb5_data *req_pkt, krb5_kdc_req *request,
               krb5_kdc_rep *reply, krb5_key_data *client_key,
               krb5_keyblock *encrypting_key, krb5_pa_data **send_pa,
               preauth_get_entry_data_proc etype_get_entry_data,
               void *pa_system_context,
               void **pa_request_context)
{
    krb5_error_code     retval;
    krb5_pa_data *      padata;
    krb5_data *         scratch;
    krb5_data           salt_data;
    int i;

    for (i = 0; i < request->nktypes; i++) {
        if (enctype_requires_etype_info_2(request->ktype[i]))
            return 0;
    }
    if (client_key->key_data_ver == 1 ||
        client_key->key_data_type[1] == KRB5_KDB_SALTTYPE_NORMAL)
        return 0;

    if ((padata = malloc(sizeof(krb5_pa_data))) == NULL)
        return ENOMEM;
    padata->magic = KV5M_PA_DATA;
    padata->pa_type = KRB5_PADATA_PW_SALT;

    switch (client_key->key_data_type[1]) {
    case KRB5_KDB_SALTTYPE_V4:
        /* send an empty (V4) salt */
        padata->contents = 0;
        padata->length = 0;
        break;
    case KRB5_KDB_SALTTYPE_NOREALM:
        if ((retval = krb5_principal2salt_norealm(kdc_context,
                                                  request->client,
                                                  &salt_data)))
            goto cleanup;
        padata->contents = (krb5_octet *)salt_data.data;
        padata->length = salt_data.length;
        break;
    case KRB5_KDB_SALTTYPE_AFS3:
        /* send an AFS style realm-based salt */
        /* for now, just pass the realm back and let the client
           do the work. In the future, add a kdc configuration
           variable that specifies the old cell name. */
        padata->pa_type = KRB5_PADATA_AFS3_SALT;
        /* it would be just like ONLYREALM, but we need to pass the 0 */
        scratch = krb5_princ_realm(kdc_context, request->client);
        if ((padata->contents = malloc(scratch->length+1)) == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        memcpy(padata->contents, scratch->data, scratch->length);
        padata->length = scratch->length+1;
        padata->contents[scratch->length] = 0;
        break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
        scratch = krb5_princ_realm(kdc_context, request->client);
        if ((padata->contents = malloc(scratch->length)) == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        memcpy(padata->contents, scratch->data, scratch->length);
        padata->length = scratch->length;
        break;
    case KRB5_KDB_SALTTYPE_SPECIAL:
        if ((padata->contents = malloc(client_key->key_data_length[1]))
            == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        memcpy(padata->contents, client_key->key_data_contents[1],
               client_key->key_data_length[1]);
        padata->length = client_key->key_data_length[1];
        break;
    default:
        free(padata);
        return 0;
    }

    *send_pa = padata;
    return 0;

cleanup:
    free(padata);
    return retval;
}



#if APPLE_PKINIT
/* PKINIT preauth support */
#define  PKINIT_DEBUG    0
#if     PKINIT_DEBUG
#define kdcPkinitDebug(args...)       printf(args)
#else
#define kdcPkinitDebug(args...)
#endif

/*
 * get_edata() - our only job is to determine whether this KDC is capable of
 * performing PKINIT. We infer that from the presence or absence of any
 * KDC signing cert.
 */
static krb5_error_code get_pkinit_edata(
    krb5_context context,
    krb5_kdc_req *request,
    krb5_db_entry *client,
    krb5_db_entry *server,
    preauth_get_entry_data_proc pkinit_get_entry_data,
    void *pa_module_context,
    krb5_pa_data *pa_data)
{
    krb5_pkinit_signing_cert_t cert = NULL;
    krb5_error_code err = krb5_pkinit_get_kdc_cert(0, NULL, NULL, &cert);

    kdcPkinitDebug("get_pkinit_edata: kdc cert %s\n", err ? "NOT FOUND" : "FOUND");
    if(cert) {
        krb5_pkinit_release_cert(cert);
    }
    return err;
}

/*
 * This is 0 only for testing until the KDC DB contains
 * the hash of the client cert
 */
#define REQUIRE_CLIENT_CERT_MATCH   1

static krb5_error_code verify_pkinit_request(
    krb5_context context,
    krb5_db_entry *client,
    krb5_data *req_pkt,
    krb5_kdc_req *request,
    krb5_enc_tkt_part *enc_tkt_reply,
    krb5_pa_data *data,
    preauth_get_entry_data_proc pkinit_get_entry_data,
    void *pa_module_context,
    void **pa_request_context,
    krb5_data **e_data,
    krb5_authdata ***authz_data)
{
    krb5_error_code         krtn;
    krb5_data               pa_data;
    krb5_data               *der_req = NULL;
    krb5_boolean            valid_cksum;
    char                    *cert_hash = NULL;
    unsigned                cert_hash_len;
    unsigned                key_dex;
    unsigned                cert_match = 0;
    krb5_keyblock           decrypted_key, *mkey_ptr;

    /* the data we get from the AS-REQ */
    krb5_timestamp          client_ctime = 0;
    krb5_ui_4               client_cusec = 0;
    krb5_timestamp          kdc_ctime = 0;
    krb5_int32              kdc_cusec = 0;
    krb5_ui_4               nonce = 0;
    krb5_checksum           pa_cksum;
    krb5int_cert_sig_status cert_sig_status;
    krb5_data               client_cert = {0, 0, NULL};

    krb5_kdc_req *tmp_as_req = NULL;

    kdcPkinitDebug("verify_pkinit_request\n");

    decrypted_key.contents = NULL;
    pa_data.data = (char *)data->contents;
    pa_data.length = data->length;
    krtn = krb5int_pkinit_as_req_parse(context, &pa_data,
                                       &client_ctime, &client_cusec,
                                       &nonce, &pa_cksum,
                                       &cert_sig_status,
                                       NULL, NULL,/* num_cms_types, cms_types */
                                       &client_cert,       /* signer_cert */
                                       /* remaining fields unused (for now) */
                                       NULL, NULL,/* num_all_certs, all_certs */
                                       NULL, NULL,/* num_trusted_CAs, trusted_CAs */
                                       NULL);     /* kdc_cert */
    if(krtn) {
        kdcPkinitDebug("pa_pk_as_req_parse returned %d; PKINIT aborting.\n",
                       (int)krtn);
        return krtn;
    }
#if     PKINIT_DEBUG
    if(cert_sig_status != pki_cs_good) {
        kdcPkinitDebug("verify_pkinit_request: cert_sig_status %d\n",
                       (int)cert_sig_status);
    }
#endif  /* PKINIT_DEBUG */

    /*
     * Verify signature and cert.
     * FIXME: The spec calls for an e-data with error-specific type to be
     * returned on error here. TD_TRUSTED_CERTIFIERS
     * to be returned to the client here. There is no way for a preauth
     * module to pass back e-data to process_as_req at this time. We
     * might want to add such capability via an out param to check_padata
     * and to its callees.
     */
    switch(cert_sig_status) {
    case pki_cs_good:
        break;
    case pki_cs_sig_verify_fail:
        /* no e-data */
        krtn = KDC_ERR_INVALID_SIG;
        goto cleanup;
    case pki_cs_no_root:
    case pki_cs_unknown_root:
    case pki_cs_untrusted:
        /*
         * Can't verify to known root.
         * e-data TD_TRUSTED_CERTIFIERS
         */
        kdcPkinitDebug("verify_pkinit_request: KDC_ERR_CANT_VERIFY_CERTIFICATE\n");
        krtn = KDC_ERR_CANT_VERIFY_CERTIFICATE;
        goto cleanup;
    case pki_cs_bad_leaf:
    case pki_cs_expired:
    case pki_cs_not_valid_yet:
        /*
         * Problems with client cert itself.
         * e-data type TD_INVALID_CERTIFICATES
         */
        krtn = KDC_ERR_INVALID_CERTIFICATE;
        goto cleanup;
    case pki_cs_revoked:
        /* e-data type TD-INVALID-CERTIFICATES */
        krtn = KDC_ERR_REVOKED_CERTIFICATE;
        goto cleanup;
    case pki_bad_key_use:
        krtn = KDC_ERR_INCONSISTENT_KEY_PURPOSE;
        /* no e-data */
        goto cleanup;
    case pki_bad_digest:
        /* undefined (explicitly!) e-data */
        krtn = KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED;
        goto cleanup;
    case pki_bad_cms:
    case pki_cs_other_err:
    default:
        krtn = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }

    krtn = krb5_us_timeofday(context, &kdc_ctime, &kdc_cusec);
    if(krtn) {
        goto cleanup;
    }
    if (labs(kdc_ctime - client_ctime) > context->clockskew) {
        kdcPkinitDebug("verify_pkinit_request: clock skew violation client %d svr %d\n",
                       (int)client_ctime, (int)kdc_ctime);
        krtn = KRB5KRB_AP_ERR_SKEW;
        goto cleanup;
    }

    /*
     * The KDC may have modified the request after decoding it.
     * We need to compute the checksum on the data that
     * came from the client.  Therefore, we use the original
     * packet contents.
     */
    krtn = decode_krb5_as_req(req_pkt, &tmp_as_req);
    if(krtn) {
        kdcPkinitDebug("decode_krb5_as_req returned %d\n", (int)krtn);
        goto cleanup;
    }

    /* calculate and compare checksum */
    krtn = encode_krb5_kdc_req_body(tmp_as_req, &der_req);
    if(krtn) {
        kdcPkinitDebug("encode_krb5_kdc_req_body returned %d\n", (int)krtn);
        goto cleanup;
    }
    krtn = krb5_c_verify_checksum(context, NULL, 0, der_req,
                                  &pa_cksum, &valid_cksum);
    if(krtn) {
        kdcPkinitDebug("krb5_c_verify_checksum returned %d\n", (int)krtn);
        goto cleanup;
    }
    if(!valid_cksum) {
        kdcPkinitDebug("verify_pkinit_request: checksum error\n");
        krtn = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        goto cleanup;
    }

#if REQUIRE_CLIENT_CERT_MATCH
    /* look up in the KDB to ensure correct client/cert binding */
    cert_hash = krb5_pkinit_cert_hash_str(&client_cert);
    if(cert_hash == NULL) {
        krtn = ENOMEM;
        goto cleanup;
    }
    cert_hash_len = strlen(cert_hash);
    for(key_dex=0; key_dex<client->n_key_data; key_dex++) {
        krb5_key_data *key_data = &client->key_data[key_dex];
        kdcPkinitDebug("--- key %u type[0] %u length[0] %u type[1] %u length[1] %u\n",
                       key_dex,
                       key_data->key_data_type[0], key_data->key_data_length[0],
                       key_data->key_data_type[1], key_data->key_data_length[1]);
        if(key_data->key_data_type[1] != KRB5_KDB_SALTTYPE_CERTHASH) {
            continue;
        }

        /*
         * Unfortunately this key is stored encrypted even though it's
         * not sensitive...
         */
        krtn = krb5_dbe_decrypt_key_data(context, NULL, key_data,
                                         &decrypted_key, NULL);
        if(krtn) {
            kdcPkinitDebug("verify_pkinit_request: error decrypting cert hash block\n");
            break;
        }
        if((decrypted_key.contents != NULL) &&
           (cert_hash_len == decrypted_key.length) &&
           !memcmp(decrypted_key.contents, cert_hash, cert_hash_len)) {
            cert_match = 1;
            break;
        }
    }
    if(decrypted_key.contents) {
        krb5_free_keyblock_contents(context, &decrypted_key);
    }
    if(!cert_match) {
        kdcPkinitDebug("verify_pkinit_request: client cert does not match\n");
        krtn = KDC_ERR_CLIENT_NOT_TRUSTED;
        goto cleanup;
    }
#endif   /* REQUIRE_CLIENT_CERT_MATCH */
    krtn = 0;
    setflag(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH);

cleanup:
    if(pa_cksum.contents) {
        free(pa_cksum.contents);
    }
    if (tmp_as_req) {
        krb5_free_kdc_req(context, tmp_as_req);
    }
    if (der_req) {
        krb5_free_data(context, der_req);
    }
    if(cert_hash) {
        free(cert_hash);
    }
    if(client_cert.data) {
        free(client_cert.data);
    }
    kdcPkinitDebug("verify_pkinit_request: returning %d\n", (int)krtn);
    return krtn;
}

static krb5_error_code return_pkinit_response(
    krb5_context context,
    krb5_pa_data * padata,
    krb5_db_entry *client,
    krb5_data *req_pkt,
    krb5_kdc_req *request,
    krb5_kdc_rep *reply,
    krb5_key_data *client_key,
    krb5_keyblock *encrypting_key,
    krb5_pa_data **send_pa,
    preauth_get_entry_data_proc pkinit_get_entry_data,
    void *pa_module_context,
    void **pa_request_context)
{
    krb5_error_code             krtn;
    krb5_data                   pa_data;
    krb5_pkinit_signing_cert_t  signing_cert = NULL;
    krb5_checksum               as_req_checksum = {0};
    krb5_data                   *encoded_as_req = NULL;
    krb5int_algorithm_id        *cms_types = NULL;
    krb5_ui_4                   num_cms_types = 0;

    /* the data we get from the AS-REQ */
    krb5_ui_4                   nonce = 0;
    krb5_data                   client_cert = {0};

    /*
     * Trusted CA list and specific KC cert optionally obtained via
     * krb5int_pkinit_as_req_parse(). All are DER-encoded
     * issuerAndSerialNumbers.
     */
    krb5_data                   *trusted_CAs = NULL;
    krb5_ui_4                   num_trusted_CAs;
    krb5_data                   kdc_cert = {0};

    if (padata == NULL) {
        /* Client has to send us something */
        return 0;
    }

    kdcPkinitDebug("return_pkinit_response\n");
    pa_data.data = (char *)padata->contents;
    pa_data.length = padata->length;

    /*
     * We've already verified; just obtain the fields we need to create a response
     */
    krtn = krb5int_pkinit_as_req_parse(context,
                                       &pa_data,
                                       NULL, NULL, &nonce,     /* ctime, cusec, nonce */
                                       NULL, NULL,             /* pa_cksum, cert_status */
                                       &num_cms_types, &cms_types,
                                       &client_cert,   /* signer_cert: we encrypt for this */
                                       /* remaining fields unused (for now) */
                                       NULL, NULL,     /* num_all_certs, all_certs */
                                       &num_trusted_CAs, &trusted_CAs,
                                       &kdc_cert);
    if(krtn) {
        kdcPkinitDebug("pa_pk_as_req_parse returned %d; PKINIT aborting.\n",
                       (int)krtn);
        goto cleanup;
    }
    if(client_cert.data == NULL) {
        kdcPkinitDebug("pa_pk_as_req_parse failed to give a client_cert; aborting.\n");
        krtn = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }

    if(krb5_pkinit_get_kdc_cert(num_trusted_CAs, trusted_CAs,
                                (kdc_cert.data ? &kdc_cert : NULL),
                                &signing_cert)) {
        /*
         * Since get_pkinit_edata was able to obtain *some* KDC cert,
         * this means that we can't satisfy the client's requirement.
         * FIXME - particular error status for this?
         */
        kdcPkinitDebug("return_pkinit_response: NO appropriate signing cert!\n");
        krtn = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }

    /*
     * Cook up keyblock for caller and for outgoing AS-REP.
     * FIXME how much is known to be valid about encrypting_key?
     * Will encrypting_key->enctype always be valid here? Seems that
     * if we allow for clients without a shared secret (i.e. preauth
     * by PKINIT only) there won't be a valid encrypting_key set up
     * here for us.
     */
    krb5_free_keyblock_contents(context, encrypting_key);
    krb5_c_make_random_key(context, encrypting_key->enctype, encrypting_key);

    /* calculate checksum of incoming AS-REQ */
    krtn = encode_krb5_as_req(request, &encoded_as_req);
    if(krtn) {
        kdcPkinitDebug("encode_krb5_as_req returned %d; PKINIT aborting.\n", (int)krtn);
        goto cleanup;
    }
    krtn = krb5_c_make_checksum(context, context->kdc_req_sumtype,
                                encrypting_key, KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
                                encoded_as_req, &as_req_checksum);
    if(krtn) {
        goto cleanup;
    }

    /*
     * FIXME: here we assume that the client has one cert - the one that
     * signed the AuthPack in the request (and that we therefore obtained from
     * krb5int_pkinit_as_req_parse()), and the one we're using to encrypt the
     * ReplyKeyPack with here. This may need rethinking.
     */
    krtn = krb5int_pkinit_as_rep_create(context,
                                        encrypting_key, &as_req_checksum,
                                        signing_cert, TRUE,
                                        &client_cert,
                                        num_cms_types, cms_types,
                                        num_trusted_CAs, trusted_CAs,
                                        (kdc_cert.data ? &kdc_cert : NULL),
                                        &pa_data);
    if(krtn) {
        kdcPkinitDebug("pa_pk_as_rep_create returned %d; PKINIT aborting.\n",
                       (int)krtn);
        goto cleanup;
    }

    *send_pa = (krb5_pa_data *)malloc(sizeof(krb5_pa_data));
    if(*send_pa == NULL) {
        krtn = ENOMEM;
        free(pa_data.data);
        goto cleanup;
    }
    (*send_pa)->magic = KV5M_PA_DATA;
    (*send_pa)->pa_type = KRB5_PADATA_PK_AS_REP;
    (*send_pa)->length = pa_data.length;
    (*send_pa)->contents = (krb5_octet *)pa_data.data;
    krtn = 0;

#if PKINIT_DEBUG
    fprintf(stderr, "return_pkinit_response: SUCCESS\n");
    fprintf(stderr, "nonce 0x%x enctype %d keydata %02x %02x %02x %02x...\n",
            (int)nonce, (int)encrypting_key->enctype,
            encrypting_key->contents[0], encrypting_key->contents[1],
            encrypting_key->contents[2], encrypting_key->contents[3]);
#endif

cleanup:
    /* all of this was allocd by krb5int_pkinit_as_req_parse() */
    if(signing_cert) {
        krb5_pkinit_release_cert(signing_cert);
    }
    if(cms_types) {
        unsigned dex;
        krb5int_algorithm_id *alg_id;

        for(dex=0; dex<num_cms_types; dex++) {
            alg_id = &cms_types[dex];
            if(alg_id->algorithm.data) {
                free(alg_id->algorithm.data);
            }
            if(alg_id->parameters.data) {
                free(alg_id->parameters.data);
            }
        }
        free(cms_types);
    }
    if(trusted_CAs) {
        unsigned dex;
        for(dex=0; dex<num_trusted_CAs; dex++) {
            free(trusted_CAs[dex].data);
        }
        free(trusted_CAs);
    }
    if(kdc_cert.data) {
        free(kdc_cert.data);
    }
    if(client_cert.data) {
        free(client_cert.data);
    }
    if(encoded_as_req) {
        krb5_free_data(context, encoded_as_req);
    }
    return krtn;
}

#endif /* APPLE_PKINIT */

/*
 * Returns TRUE if the PAC should be included
 */
krb5_boolean
include_pac_p(krb5_context context, krb5_kdc_req *request)
{
    krb5_error_code             code;
    krb5_pa_data                **padata;
    krb5_boolean                retval = TRUE; /* default is to return PAC */
    krb5_data                   data;
    krb5_pa_pac_req             *req = NULL;

    if (request->padata == NULL) {
        return retval;
    }

    for (padata = request->padata; *padata != NULL; padata++) {
        if ((*padata)->pa_type == KRB5_PADATA_PAC_REQUEST) {
            data.data = (char *)(*padata)->contents;
            data.length = (*padata)->length;

            code = decode_krb5_pa_pac_req(&data, &req);
            if (code == 0) {
                retval = req->include_pac;
                krb5_free_pa_pac_req(context, req);
                req = NULL;
            }
            break;
        }
    }

    return retval;
}

static krb5_error_code
return_referral_enc_padata( krb5_context context,
                            krb5_enc_kdc_rep_part *reply,
                            krb5_db_entry *server)
{
    krb5_error_code             code;
    krb5_tl_data                tl_data;
    krb5_pa_data                pa_data;

    tl_data.tl_data_type = KRB5_TL_SVR_REFERRAL_DATA;
    code = krb5_dbe_lookup_tl_data(context, server, &tl_data);
    if (code || tl_data.tl_data_length == 0)
        return 0;

    pa_data.magic = KV5M_PA_DATA;
    pa_data.pa_type = KRB5_PADATA_SVR_REFERRAL_INFO;
    pa_data.length = tl_data.tl_data_length;
    pa_data.contents = tl_data.tl_data_contents;
    return add_pa_data_element(context, &pa_data, &reply->enc_padata, TRUE);
}

krb5_error_code
return_enc_padata(krb5_context context, krb5_data *req_pkt,
                  krb5_kdc_req *request, krb5_keyblock *reply_key,
                  krb5_db_entry *server, krb5_enc_kdc_rep_part *reply_encpart,
                  krb5_boolean is_referral)
{
    krb5_error_code code = 0;
    /* This should be initialized and only used for Win2K compat and other
     * specific standardized uses such as FAST negotiation. */
    assert(reply_encpart->enc_padata == NULL);
    if (is_referral) {
        code = return_referral_enc_padata(context, reply_encpart, server);
        if (code)
            return code;
    }
    code = kdc_handle_protected_negotiation(req_pkt, request, reply_key,
                                            &reply_encpart->enc_padata);
    if (code)
        goto cleanup;
    /*Add potentially other enc_padata providers*/
cleanup:
    return code;
}


#if 0
static krb5_error_code return_server_referral(krb5_context context,
                                              krb5_pa_data * padata,
                                              krb5_db_entry *client,
                                              krb5_db_entry *server,
                                              krb5_kdc_req *request,
                                              krb5_kdc_rep *reply,
                                              krb5_key_data *client_key,
                                              krb5_keyblock *encrypting_key,
                                              krb5_pa_data **send_pa)
{
    krb5_error_code             code;
    krb5_tl_data                tl_data;
    krb5_pa_data                *pa_data;
    krb5_enc_data               enc_data;
    krb5_data                   plain;
    krb5_data                   *enc_pa_data;

    *send_pa = NULL;

    tl_data.tl_data_type = KRB5_TL_SERVER_REFERRAL;

    code = krb5_dbe_lookup_tl_data(context, server, &tl_data);
    if (code || tl_data.tl_data_length == 0)
        return 0; /* no server referrals to return */

    plain.length = tl_data.tl_data_length;
    plain.data = tl_data.tl_data_contents;

    /* Encrypt ServerReferralData */
    code = krb5_encrypt_helper(context, encrypting_key,
                               KRB5_KEYUSAGE_PA_SERVER_REFERRAL_DATA,
                               &plain, &enc_data);
    if (code)
        return code;

    /* Encode ServerReferralData into PA-SERVER-REFERRAL-DATA */
    code = encode_krb5_enc_data(&enc_data, &enc_pa_data);
    if (code) {
        krb5_free_data_contents(context, &enc_data.ciphertext);
        return code;
    }

    krb5_free_data_contents(context, &enc_data.ciphertext);

    /* Return PA-SERVER-REFERRAL-DATA */
    pa_data = (krb5_pa_data *)malloc(sizeof(*pa_data));
    if (pa_data == NULL) {
        krb5_free_data(context, enc_pa_data);
        return ENOMEM;
    }

    pa_data->magic = KV5M_PA_DATA;
    pa_data->pa_type = KRB5_PADATA_SVR_REFERRAL_INFO;
    pa_data->length = enc_pa_data->length;
    pa_data->contents = enc_pa_data->data;

    free(enc_pa_data); /* don't free contents */

    *send_pa = pa_data;

    return 0;
}
#endif

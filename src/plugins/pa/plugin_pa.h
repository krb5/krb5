/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/pa/plugin_pa.h
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * Implement Encrypted Challenge fast factor from
 * draft-ietf-krb-wg-preauth-framework
 */

#ifndef PLUGIN_PA_H_
#define PLUGIN_PA_H_

#include <plugin_manager.h>
#include <k5-int.h>

/* PREAUTH API */
typedef struct {
        int version;
        krb5_error_code (*server_init)(krb5_context, void**, const char**);
        void (*server_fini)(krb5_context, void*);
        int (*preauth_flags)(krb5_context context, krb5_preauthtype pa_type);
        krb5_error_code (*process_preauth)(krb5_context, void*, void*,
                                           krb5_get_init_creds_opt*,
                                           preauth_get_client_data_proc,
                                           struct _krb5_preauth_client_rock*,
                                           krb5_kdc_req*,
                                           krb5_data*, krb5_data*, krb5_pa_data*,
                                           krb5_prompter_fct prompter, void*,
                                           preauth_get_as_key_proc, void*,
                                           krb5_data*, krb5_data*, krb5_keyblock*,
                                           krb5_pa_data***);
        krb5_error_code (*kdc_include_padata)(krb5_context, krb5_kdc_req*,
                                          struct _krb5_db_entry_new*,
                                          struct _krb5_db_entry_new*,
                                          preauth_get_entry_data_proc,
                                          void*, krb5_pa_data*);
        krb5_error_code (*kdc_verify_preauth)(krb5_context, struct _krb5_db_entry_new*,
                                          krb5_data*, krb5_kdc_req*,
                                          krb5_enc_tkt_part*, krb5_pa_data*,
                                          preauth_get_entry_data_proc,
                                          void*, void**,
                                          krb5_data**, krb5_authdata***);
        krb5_error_code (*kdc_return_preauth)(krb5_context, krb5_pa_data*,
                                          struct _krb5_db_entry_new*, krb5_data*,
                                          krb5_kdc_req*, krb5_kdc_rep*,
                                          struct _krb5_key_data*,
                                          krb5_keyblock*, krb5_pa_data**,
                                          preauth_get_entry_data_proc,
                                          void*, void**);
        krb5_error_code (*server_free_reqctx)(krb5_context, void*, void**);
} plugin_pa;

int plugin_preauth_flags(plhandle handle, krb5_context context, krb5_preauthtype pa_type);
krb5_error_code plugin_process_preauth(plhandle handle, krb5_context context, void *plugin_context,
                                       void *request_context, krb5_get_init_creds_opt *opt,
                                       preauth_get_client_data_proc get_data_proc,
                                       struct _krb5_preauth_client_rock *rock, krb5_kdc_req *request,
                                       krb5_data *encoded_request_body,
                                       krb5_data *encoded_previous_request, krb5_pa_data *padata,
                                       krb5_prompter_fct prompter, void *prompter_data,
                                       preauth_get_as_key_proc gak_fct, void *gak_data,
                                       krb5_data *salt, krb5_data *s2kparams, krb5_keyblock *as_key,
                                       krb5_pa_data ***out_padata);
krb5_error_code plugin_kdc_include_padata(plhandle handle, krb5_context context, krb5_kdc_req *request,
                                          struct _krb5_db_entry_new *client,
                                          struct _krb5_db_entry_new *server,
                                          preauth_get_entry_data_proc get_entry_proc,
                                          void *pa_module_context, krb5_pa_data *data);
krb5_error_code plugin_kdc_verify_preauth(plhandle handle, krb5_context context, struct _krb5_db_entry_new *client,
                                          krb5_data *req_pkt, krb5_kdc_req *request,
                                          krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *data,
                                          preauth_get_entry_data_proc get_entry_proc,
                                          void *pa_module_context, void **pa_request_context,
                                          krb5_data **e_data, krb5_authdata ***authz_data);
krb5_error_code plugin_kdc_return_preauth(plhandle handle, krb5_context context, krb5_pa_data *padata,
                                          struct _krb5_db_entry_new *client, krb5_data *req_pkt,
                                          krb5_kdc_req *request, krb5_kdc_rep *reply,
                                          struct _krb5_key_data *client_keys,
                                          krb5_keyblock *encrypting_key, krb5_pa_data **send_pa,
                                          preauth_get_entry_data_proc get_entry_proc,
                                          void *pa_module_context, void **pa_request_context);
krb5_error_code plugin_server_free_reqctx(plhandle handle, krb5_context kcontext,
                                          void *pa_module_context,
                                          void **pa_request_context);
krb5_error_code plugin_server_init(plhandle handle, krb5_context kcontext, void **module_context, const char **realmnames);
void plugin_server_fini(plhandle handle, krb5_context kcontext, void *module_context);

#if 0
krb5_preauthtype supported_pa_types[] = {KRB5_PADATA_ENCRYPTED_CHALLENGE, 0};

struct krb5plugin_preauth_server_ftable_v1 preauthentication_server_1 = {
    "Encrypted challenge",
    &supported_pa_types[0],
    NULL,
    NULL,
    kdc_preauth_flags,
    kdc_include_padata,
    kdc_verify_preauth,
    kdc_return_preauth,
    NULL
};

struct krb5plugin_preauth_client_ftable_v1 preauthentication_client_1 = {
    "Encrypted Challenge",                /* name */
    &supported_pa_types[0],        /* pa_type_list */
    NULL,                    /* enctype_list */
    NULL,                    /* plugin init function */
    NULL,                    /* plugin fini function */
    preauth_flags,                /* get flags function */
    NULL,                    /* request init function */
    NULL,                    /* request fini function */
    process_preauth,                /* process function */
    NULL,                    /* try_again function */
    NULL                /* get init creds opt function */
};
#endif

#endif /* PLUGIN_PA_H_ */

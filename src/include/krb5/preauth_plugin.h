/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (c) 2006 Red Hat, Inc.
 * Portions copyright (c) 2006, 2011 Massachusetts Institute of Technology
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Red Hat, Inc., nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Declarations for preauth plugin module implementors.
 *
 * This header defines two preauth interfaces, clpreauth and kdcpreauth.  A
 * shared object can implement both interfaces or it can implement just one.
 *
 *
 * The clpreauth interface has a single supported major version, which is
 * 1.  Major version 1 has a current minor version of 1.  clpreauth modules
 * should define a function named clpreauth_<modulename>_initvt, matching
 * the signature:
 *
 *   krb5_error_code
 *   clpreauth_modname_initvt(krb5_context context, int maj_ver,
 *                            int min_ver, krb5_plugin_vtable vtable);
 *
 * The kdcpreauth interface has a single supported major version, which is 1.
 * Major version 1 has a current minor version of 1.  kdcpreauth modules should
 * define a function named kdcpreauth_<modulename>_initvt, matching the
 * signature:
 *
 *   krb5_error_code
 *   kdcpreauth_modname_initvt(krb5_context context, int maj_ver, int min_ver,
 *                             krb5_plugin_vtable vtable);
 *
 * For both interfaces, the initvt function should:
 *
 * - Check that the supplied maj_ver number is supported by the module, or
 *   return KRB5_PLUGIN_VER_NOTSUPP if it is not.
 *
 * - Cast the vtable pointer as appropriate for the interface and maj_ver:
 *     clpreauth, maj_ver == 1:  Cast to krb5_clpreauth_vtable
 *     kdcpreauth, maj_ver == 1: Cast to krb5_kdcpreauth_vtable
 *
 * - Initialize the methods of the vtable, stopping as appropriate for the
 *   supplied min_ver.  Optional methods may be left uninitialized.
 *
 * Memory for the vtable is allocated by the caller, not by the module.
 */

#ifndef KRB5_PREAUTH_PLUGIN_H_INCLUDED
#define KRB5_PREAUTH_PLUGIN_H_INCLUDED
#include <krb5/krb5.h>
#include <krb5/plugin.h>

/*
 * Preauth mechanism property flags, unified from previous definitions in the
 * KDC and libkrb5 sources.
 */

/* Provides a real answer which we can send back to the KDC (client-only).  The
 * client assumes that one real answer will be enough. */
#define PA_REAL         0x00000001

/* Doesn't provide a real answer, but must be given a chance to run before any
 * REAL mechanism callbacks (client-only). */
#define PA_INFO         0x00000002

/*
 * Causes the KDC to include this mechanism in a list of supported preauth
 * types if the user's DB entry flags the user as requiring hardware-based
 * preauthentication (KDC-only).
 */
#define PA_HARDWARE     0x00000004

/*
 * Causes the KDC to include this mechanism in a list of supported preauth
 * types if the user's DB entry flags the user as requiring preauthentication,
 * and to fail preauthentication if we can't verify the client data.  The
 * flipside of PA_SUFFICIENT (KDC-only).
 */
#define PA_REQUIRED     0x00000008

/*
 * Causes the KDC to include this mechanism in a list of supported preauth
 * types if the user's DB entry flags the user as requiring preauthentication,
 * and to mark preauthentication as successful if we can verify the client
 * data.  The flipside of PA_REQUIRED (KDC-only).
 */
#define PA_SUFFICIENT   0x00000010

/*
 * Marks this preauthentication mechanism as one which changes the key which is
 * used for encrypting the response to the client.  Modules which have this
 * flag have their server_return_fn called before modules which do not, and are
 * passed over if a previously-called module has modified the encrypting key
 * (KDC-only).
 */
#define PA_REPLACES_KEY 0x00000020

/*
 * Not really a padata type, so don't include it in any list of preauth types
 * which gets sent over the wire.
 */
#define PA_PSEUDO       0x00000080


/*
 * clpreauth plugin interface definition.
 */

/* Abstract type for a client request information handle. */
typedef struct krb5_clpreauth_rock_st *krb5_clpreauth_rock;

/* Abstract types for module data and per-request module data. */
typedef struct krb5_clpreauth_moddata_st *krb5_clpreauth_moddata;
typedef struct krb5_clpreauth_modreq_st *krb5_clpreauth_modreq;

/*
 * Provided by krb5: a callback which will obtain the user's long-term AS key
 * by prompting the user for the password, then salting it properly, and so on.
 * For the moment, it's identical to the get_as_key callback used inside of
 * libkrb5, but we define a new typedef here instead of making the existing one
 * public to isolate ourselves from potential future changes.
 */
typedef krb5_error_code
(*krb5_clpreauth_get_as_key_fn)(krb5_context context,
                                krb5_principal princ,
                                krb5_enctype enctype,
                                krb5_prompter_fct prompter,
                                void *prompter_data,
                                krb5_data *salt,
                                krb5_data *s2kparams,
                                krb5_keyblock *as_key,
                                void *gak_data);

/*
 * Provided by krb5: a client module's callback functions are allowed to
 * request various information to enable it to process a request.
 */
enum krb5_clpreauth_request_type {
    /*
     * The returned krb5_data item holds the enctype expected to be used to
     * encrypt the encrypted portion of the AS_REP packet. When handling a
     * PREAUTH_REQUIRED error, this typically comes from etype-info2.  When
     * handling an AS reply, it is initialized from the AS reply itself.
     */
    krb5_clpreauth_get_etype = 1,

    /* Free the data returned from krb5plugin_clpreauth_req_get_etype */
    krb5_clpreauth_free_etype = 2,

    /*
     * The returned krb5_data contains the FAST armor key in a krb5_keyblock.
     * Returns success with a NULL data item in the krb5_data if the client
     * library supports FAST but is not using it.
     */
    krb5_clpreauth_fast_armor = 3,

    /*
     * Frees return from KRB5PLUGIN_CLPREAUTH_FAST_ARMOR.  It is
     * acceptable to set data->data to NULL and free the keyblock using
     * krb5_free_keyblock; in that case, this frees the krb5_data only.
     */
    krb5_clpreauth_free_fast_armor = 4
};
typedef krb5_error_code
(*krb5_clpreauth_get_data_fn)(krb5_context context,
                              krb5_clpreauth_rock rock,
                              krb5_int32 request_type, krb5_data **data);

/*
 * Optional: per-plugin initialization/cleanup.  The init function is called by
 * libkrb5 when the plugin is loaded, and the fini function is called before
 * the plugin is unloaded.  These may be called multiple times in case the
 * plugin is used in multiple contexts.  The returned context lives the
 * lifetime of the krb5_context.
 */
typedef krb5_error_code
(*krb5_clpreauth_init_fn)(krb5_context context,
                          krb5_clpreauth_moddata *moddata_out);
typedef void
(*krb5_clpreauth_fini_fn)(krb5_context context,
                          krb5_clpreauth_moddata moddata);

/*
 * Mandatory: Return flags indicating if the module is a "real" or an "info"
 * mechanism, and so on.  This function is called for each entry in the
 * client_pa_type_list.
 */
typedef int
(*krb5_clpreauth_get_flags_fn)(krb5_context context, krb5_preauthtype pa_type);

/*
 * Optional: per-request initialization/cleanup.  The request_init function is
 * called when beginning to process a get_init_creds request and the
 * request_fini function is called when processing of the request is complete.
 * This is optional.  It may be called multiple times in the lifetime of a
 * krb5_context.
 */
typedef void
(*krb5_clpreauth_request_init_fn)(krb5_context context,
                                  krb5_clpreauth_moddata moddata,
                                  krb5_clpreauth_modreq *modreq_out);
typedef void
(*krb5_clpreauth_request_fini_fn)(krb5_context context,
                                  krb5_clpreauth_moddata moddata,
                                  krb5_clpreauth_modreq modreq);

/*
 * Mandatory: process server-supplied data in pa_data and returns created data
 * in out_pa_data.  It is also called after the AS-REP is received if the
 * AS-REP includes preauthentication data of the associated type.  NOTE: the
 * encoded_previous_request will be NULL the first time this function is
 * called, because it is expected to only ever contain the data obtained from a
 * previous call to this function.
 */
typedef krb5_error_code
(*krb5_clpreauth_process_fn)(krb5_context context,
                             krb5_clpreauth_moddata moddata,
                             krb5_clpreauth_modreq modreq,
                             krb5_get_init_creds_opt *opt,
                             krb5_clpreauth_get_data_fn get_data,
                             krb5_clpreauth_rock rock,
                             krb5_kdc_req *request,
                             krb5_data *encoded_request_body,
                             krb5_data *encoded_previous_request,
                             krb5_pa_data *pa_data,
                             krb5_prompter_fct prompter, void *prompter_data,
                             krb5_clpreauth_get_as_key_fn gak_fct,
                             void *gak_data,
                             krb5_data *salt, krb5_data *s2kparams,
                             krb5_keyblock *as_key,
                             krb5_pa_data ***out_pa_data);

/*
 * Optional: Attempt to use e-data in the error response to try to recover from
 * the given error.  If this function is provided, and it stores data in
 * out_pa_data which is different data from the contents of in_pa_data, then
 * the client library will retransmit the request.
 */
typedef krb5_error_code
(*krb5_clpreauth_tryagain_fn)(krb5_context context,
                              krb5_clpreauth_moddata moddata,
                              krb5_clpreauth_modreq modreq,
                              krb5_get_init_creds_opt *opt,
                              krb5_clpreauth_get_data_fn get_data,
                              krb5_clpreauth_rock rock,
                              krb5_kdc_req *request,
                              krb5_data *encoded_request_body,
                              krb5_data *encoded_previous_request,
                              krb5_pa_data *in_pa_data,
                              krb5_error *error,
                              krb5_prompter_fct prompter, void *prompter_data,
                              krb5_clpreauth_get_as_key_fn gak_fct,
                              void *gak_data,
                              krb5_data *salt, krb5_data *s2kparams,
                              krb5_keyblock *as_key,
                              krb5_pa_data ***out_pa_data);

/*
 * Optional: receive krb5_get_init_creds_opt information.  The attr and value
 * information supplied should be copied into moddata by the module if it
 * wishes to reference it after returning from this call.
 */
typedef krb5_error_code
(*krb5_clpreauth_supply_gic_opts_fn)(krb5_context context,
                                     krb5_clpreauth_moddata moddata,
                                     krb5_get_init_creds_opt *opt,
                                     const char *attr, const char *value);

typedef struct krb5_clpreauth_vtable_st {
    /* Mandatory: name of module. */
    char *name;

    /* Mandatory: pointer to zero-terminated list of pa_types which this module
     * can provide services for. */
    krb5_preauthtype *pa_type_list;

    /* Optional: pointer to zero-terminated list of enc_types which this module
     * claims to add support for. */
    krb5_enctype *enctype_list;

    krb5_clpreauth_init_fn init;
    krb5_clpreauth_fini_fn fini;
    krb5_clpreauth_get_flags_fn flags;
    krb5_clpreauth_request_init_fn request_init;
    krb5_clpreauth_request_fini_fn request_fini;
    krb5_clpreauth_process_fn process;
    krb5_clpreauth_tryagain_fn tryagain;
    krb5_clpreauth_supply_gic_opts_fn gic_opts;
    /* Minor version 1 ends here. */
} *krb5_clpreauth_vtable;


/*
 * kdcpreauth plugin interface definition.
 */

/* While arguments of these types are passed in, they are opaque to kdcpreauth
 * modules. */
struct _krb5_db_entry_new;
struct _krb5_key_data;

/* Abstract type for module data and per-request module data. */
typedef struct krb5_kdcpreauth_moddata_st *krb5_kdcpreauth_moddata;
typedef struct krb5_kdcpreauth_modreq_st *krb5_kdcpreauth_modreq;

/*
 * Provided by krb5: a kdcpreauth module's callback functions are allowed to
 * request specific types of information about the given client or server
 * record or request, even though the database records themselves are opaque to
 * the module.
 */
enum krb5_kdcpreauth_request_type {
    /* The returned krb5_data item holds a DER-encoded X.509 certificate. */
    krb5_kdcpreauth_request_certificate = 1,
    /* The returned krb5_data_item holds a krb5_deltat. */
    krb5_kdcpreauth_max_time_skew = 2,
    /*
     * The returned krb5_data_item holds an array of krb5_keyblock structures,
     * terminated by an entry with key type = 0.  Each keyblock should have its
     * contents freed in turn, and then the data item itself should be freed.
     */
    krb5_kdcpreauth_keys = 3,
    /*
     * The returned krb5_data_item holds the request structure, re-encoded
     * using DER.  Unless the client implementation is the same as the server
     * implementation, there's a good chance that the result will not match
     * what the client sent, so don't create any fatal errors if it doesn't
     * match up.
     */
    krb5_kdcpreauth_request_body = 4,
    /*
     * The returned krb5_data contains a krb5_keyblock with the FAST armor key.
     * The data member is NULL if this method is not part of a FAST tunnel.
     */
    krb5_kdcpreauth_fast_armor = 5,
    /*
     * Frees a fast armor key. It is acceptable to set data to NULL and free
     * the keyblock using krb5_free_keyblock; in that case, this function
     * simply frees the data.
     */
    krb5_kdcpreauth_free_fast_armor = 6
};
typedef krb5_error_code
(*krb5_kdcpreauth_get_data_fn)(krb5_context context, krb5_kdc_req *request,
                               struct _krb5_db_entry_new *entry,
                               krb5_int32 request_type,
                               krb5_data **);

/* Optional: preauth plugin initialization function. */
typedef krb5_error_code
(*krb5_kdcpreauth_init_fn)(krb5_context context,
                           krb5_kdcpreauth_moddata *moddata_out,
                           const char **realmnames);

/* Optional: preauth plugin cleanup function. */
typedef void
(*krb5_kdcpreauth_fini_fn)(krb5_context context,
                           krb5_kdcpreauth_moddata moddata);

/*
 * Optional: return the flags which the KDC should use for this module.  This
 * is a callback instead of a static value because the module may or may not
 * wish to count itself as a hardware preauthentication module (in other words,
 * the flags may be affected by the configuration, for example if a site
 * administrator can force a particular preauthentication type to be supported
 * using only hardware).  This function is called for each entry entry in the
 * server_pa_type_list.
 */
typedef int
(*krb5_kdcpreauth_flags_fn)(krb5_context context, krb5_preauthtype patype);

/*
 * Optional: fill in pa_out->length and pa_out->contents with data to send to
 * the client as part of the "you need to use preauthentication" error.  If
 * this function returns non-zero, the padata type will not be included in the
 * list; if this function is not provided or returns zero without changing
 * pa_out, the padata type will be included in the list with an empty value.
 * This function not allowed to create a context because we have no guarantee
 * that the client will ever call again (or that it will hit this server if it
 * does), in which case a context might otherwise hang around forever.
 */
typedef krb5_error_code
(*krb5_kdcpreauth_edata_fn)(krb5_context context, krb5_kdc_req *request,
                            struct _krb5_db_entry_new *client,
                            struct _krb5_db_entry_new *server,
                            krb5_kdcpreauth_get_data_fn get_data,
                            krb5_kdcpreauth_moddata moddata,
                            krb5_pa_data *pa_out);

/*
 * Optional: verify preauthentication data sent by the client, setting the
 * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
 * field as appropriate, and returning nonzero on failure.  Can create
 * per-request module data for consumption by the return_fn or free_modreq_fn
 * below.
 */
typedef krb5_error_code
(*krb5_kdcpreauth_verify_fn)(krb5_context context,
                             struct _krb5_db_entry_new *client,
                             krb5_data *req_pkt, krb5_kdc_req *request,
                             krb5_enc_tkt_part *enc_tkt_reply,
                             krb5_pa_data *data,
                             krb5_kdcpreauth_get_data_fn get_data,
                             krb5_kdcpreauth_moddata moddata,
                             krb5_kdcpreauth_modreq *modreq_out,
                             krb5_data **e_data_out,
                             krb5_authdata ***authz_data_out);

/*
 * Optional: generate preauthentication response data to send to the client as
 * part of the AS-REP.  If it needs to override the key which is used to
 * encrypt the response, it can do so.
 */
typedef krb5_error_code
(*krb5_kdcpreauth_return_fn)(krb5_context context,
                             krb5_pa_data *padata,
                             struct _krb5_db_entry_new *client,
                             krb5_data *req_pkt,
                             krb5_kdc_req *request,
                             krb5_kdc_rep *reply,
                             struct _krb5_key_data *client_keys,
                             krb5_keyblock *encrypting_key,
                             krb5_pa_data **send_pa_out,
                             krb5_kdcpreauth_get_data_fn,
                             krb5_kdcpreauth_moddata moddata,
                             krb5_kdcpreauth_modreq modreq);

/* Optional: free a per-request context. */
typedef void
(*krb5_kdcpreauth_free_modreq_fn)(krb5_context,
                                  krb5_kdcpreauth_moddata moddata,
                                  krb5_kdcpreauth_modreq modreq);

typedef struct krb5_kdcpreauth_vtable_st {
    /* Mandatory: name of module. */
    char *name;

    /* Mandatory: pointer to zero-terminated list of pa_types which this module
     * can provide services for. */
    krb5_preauthtype *pa_type_list;

    krb5_kdcpreauth_init_fn init;
    krb5_kdcpreauth_fini_fn fini;
    krb5_kdcpreauth_flags_fn flags;
    krb5_kdcpreauth_edata_fn edata;
    krb5_kdcpreauth_verify_fn verify;
    krb5_kdcpreauth_return_fn return_padata;
    krb5_kdcpreauth_free_modreq_fn free_modreq;
} *krb5_kdcpreauth_vtable;

/*
 * This function allows a preauth plugin to obtain preauth
 * options.  The preauth_data returned from this function
 * should be freed by calling krb5_get_init_creds_opt_free_pa().
 *
 * The 'opt' pointer supplied to this function must have been
 * obtained using krb5_get_init_creds_opt_alloc().
 */
krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_get_pa(krb5_context context,
                               krb5_get_init_creds_opt *opt,
                               int *num_preauth_data,
                               krb5_gic_opt_pa_data **preauth_data);

/*
 * This function frees the preauth_data that was returned by
 * krb5_get_init_creds_opt_get_pa().
 */
void KRB5_CALLCONV
krb5_get_init_creds_opt_free_pa(krb5_context context,
                                int num_preauth_data,
                                krb5_gic_opt_pa_data *preauth_data);

#endif /* KRB5_PREAUTH_PLUGIN_H_INCLUDED */

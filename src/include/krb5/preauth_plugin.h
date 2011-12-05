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
 * For kdcpreauth mechanisms, indicates that e_data in non-FAST errors should
 * be encoded as typed data instead of padata.
 */
#define PA_TYPED_E_DATA 0x00000100

/*
 * clpreauth plugin interface definition.
 */

/* Abstract type for a client request information handle. */
typedef struct krb5_clpreauth_rock_st *krb5_clpreauth_rock;

/* Abstract types for module data and per-request module data. */
typedef struct krb5_clpreauth_moddata_st *krb5_clpreauth_moddata;
typedef struct krb5_clpreauth_modreq_st *krb5_clpreauth_modreq;

/* Before using a callback after version 1, modules must check the vers
 * field of the callback structure. */
typedef struct krb5_clpreauth_callbacks_st {
    int vers;

    /*
     * Get the enctype expected to be used to encrypt the encrypted portion of
     * the AS_REP packet.  When handling a PREAUTH_REQUIRED error, this
     * typically comes from etype-info2.  When handling an AS reply, it is
     * initialized from the AS reply itself.
     */
    krb5_enctype (*get_etype)(krb5_context context, krb5_clpreauth_rock rock);

    /* Get a pointer to the FAST armor key, or NULL if the client is not using
     * FAST.  The returned pointer is an alias and should not be freed. */
    krb5_keyblock *(*fast_armor)(krb5_context context,
                                 krb5_clpreauth_rock rock);

    /*
     * Get a pointer to the client-supplied reply key, possibly invoking the
     * prompter to ask for a password if this has not already been done.  The
     * returned pointer is an alias and should not be freed.
     */
    krb5_error_code (*get_as_key)(krb5_context context,
                                  krb5_clpreauth_rock rock,
                                  krb5_keyblock **keyblock);

    /* Replace the reply key to be used to decrypt the AS response. */
    krb5_error_code (*set_as_key)(krb5_context context,
                                  krb5_clpreauth_rock rock,
                                  const krb5_keyblock *keyblock);

    /* End of version 1 clpreauth callbacks. */
} *krb5_clpreauth_callbacks;

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
 * Mandatory: process server-supplied data in pa_data and return created data
 * in pa_data_out.  Also called after the AS-REP is received if the AS-REP
 * includes preauthentication data of the associated type.
 *
 * as_key contains the client-supplied key if known, or an empty keyblock if
 * not.  If it is empty, the module may use gak_fct to fill it in.
 *
 * encoded_previous_request may be NULL if there has been no previous request
 * in the AS exchange.
 */
typedef krb5_error_code
(*krb5_clpreauth_process_fn)(krb5_context context,
                             krb5_clpreauth_moddata moddata,
                             krb5_clpreauth_modreq modreq,
                             krb5_get_init_creds_opt *opt,
                             krb5_clpreauth_callbacks cb,
                             krb5_clpreauth_rock rock,
                             krb5_kdc_req *request,
                             krb5_data *encoded_request_body,
                             krb5_data *encoded_previous_request,
                             krb5_pa_data *pa_data,
                             krb5_prompter_fct prompter, void *prompter_data,
                             krb5_pa_data ***pa_data_out);

/*
 * Optional: Attempt to use error and error_padata to try to recover from the
 * given error.  To work with both FAST and non-FAST errors, an implementation
 * should generally consult error_padata rather than decoding error->e_data.
 * For non-FAST errors, it contains the e_data decoded as either pa-data or
 * typed-data.
 *
 * If this function is provided, and it returns 0 and stores data in
 * pa_data_out, then the client library will retransmit the request.
 */
typedef krb5_error_code
(*krb5_clpreauth_tryagain_fn)(krb5_context context,
                              krb5_clpreauth_moddata moddata,
                              krb5_clpreauth_modreq modreq,
                              krb5_get_init_creds_opt *opt,
                              krb5_clpreauth_callbacks cb,
                              krb5_clpreauth_rock rock,
                              krb5_kdc_req *request,
                              krb5_data *encoded_request_body,
                              krb5_data *encoded_previous_request,
                              krb5_preauthtype pa_type,
                              krb5_error *error,
                              krb5_pa_data **error_padata,
                              krb5_prompter_fct prompter, void *prompter_data,
                              krb5_pa_data ***pa_data_out);

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
 * This function allows a clpreauth plugin to obtain preauth options.  The
 * preauth_data returned from this function should be freed by calling
 * krb5_get_init_creds_opt_free_pa().
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


/*
 * kdcpreauth plugin interface definition.
 */

/* Abstract type for a KDC callback data handle. */
typedef struct krb5_kdcpreauth_rock_st *krb5_kdcpreauth_rock;

/* Abstract type for module data and per-request module data. */
typedef struct krb5_kdcpreauth_moddata_st *krb5_kdcpreauth_moddata;
typedef struct krb5_kdcpreauth_modreq_st *krb5_kdcpreauth_modreq;

/* The verto context structure type (typedef is in verto.h; we want to avoid a
 * header dependency for the moment). */
struct verto_context;

/* Before using a callback after version 1, modules must check the vers
 * field of the callback structure. */
typedef struct krb5_kdcpreauth_callbacks_st {
    int vers;

    krb5_deltat (*max_time_skew)(krb5_context context,
                                 krb5_kdcpreauth_rock rock);

    /*
     * Get an array of krb5_keyblock structures containing the client keys
     * matching the request enctypes, terminated by an entry with key type = 0.
     * Returns ENOENT if no keys are available for the request enctypes.  Free
     * the resulting object with the free_keys callback.
     */
    krb5_error_code (*client_keys)(krb5_context context,
                                   krb5_kdcpreauth_rock rock,
                                   krb5_keyblock **keys_out);

    /* Free the result of client_keys. */
    void (*free_keys)(krb5_context context, krb5_kdcpreauth_rock rock,
                      krb5_keyblock *keys);

    /*
     * Get the encoded request body, which is sometimes needed for checksums.
     * For a FAST request this is the encoded inner request body.  The returned
     * pointer is an alias and should not be freed.
     */
    krb5_data *(*request_body)(krb5_context context,
                               krb5_kdcpreauth_rock rock);

    /* Get a pointer to the FAST armor key, or NULL if the request did not use
     * FAST.  The returned pointer is an alias and should not be freed. */
    krb5_keyblock *(*fast_armor)(krb5_context context,
                                 krb5_kdcpreauth_rock rock);

    /* Retrieve a string attribute from the client DB entry, or NULL if no such
     * attribute is set.  Free the result with the free_string callback. */
    krb5_error_code (*get_string)(krb5_context context,
                                  krb5_kdcpreauth_rock rock, const char *key,
                                  char **value_out);

    /* Free the result of get_string. */
    void (*free_string)(krb5_context context, krb5_kdcpreauth_rock rock,
                        char *string);

    /* Get a pointer to the client DB entry (returned as a void pointer to
     * avoid a dependency on a libkdb5 type). */
    void *(*client_entry)(krb5_context context, krb5_kdcpreauth_rock rock);

    /* Get a pointer to the verto context which should be used by an
     * asynchronous edata or verify method. */
    struct verto_ctx *(*event_context)(krb5_context context,
                                       krb5_kdcpreauth_rock rock);

    /* End of version 1 kdcpreauth callbacks. */
} *krb5_kdcpreauth_callbacks;

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
(*krb5_kdcpreauth_flags_fn)(krb5_context context, krb5_preauthtype pa_type);

/*
 * Responder for krb5_kdcpreauth_edata_fn.  If invoked with a non-zero code, pa
 * will be ignored and the padata type will not be included in the hint list.
 * If invoked with a zero code and a null pa value, the padata type will be
 * included in the list with an empty value.  If invoked with a zero code and a
 * non-null pa value, pa will be included in the hint list and will later be
 * freed by the KDC.
 */
typedef void
(*krb5_kdcpreauth_edata_respond_fn)(void *arg, krb5_error_code code,
                                    krb5_pa_data *pa);

/*
 * Optional: provide pa_data to send to the client as part of the "you need to
 * use preauthentication" error.  The implementation must invoke the respond
 * when complete, whether successful or not, either before returning or
 * asynchronously using the verto context returned by cb->event_context().
 *
 * This function is not allowed to create a modreq object because we have no
 * guarantee that the client will ever make a follow-up request, or that it
 * will hit this KDC if it does.
 */
typedef void
(*krb5_kdcpreauth_edata_fn)(krb5_context context, krb5_kdc_req *request,
                            krb5_kdcpreauth_callbacks cb,
                            krb5_kdcpreauth_rock rock,
                            krb5_kdcpreauth_moddata moddata,
                            krb5_preauthtype pa_type,
                            krb5_kdcpreauth_edata_respond_fn respond,
                            void *arg);

/*
 * Responder for krb5_kdcpreauth_verify_fn.  Invoke with the arg parameter
 * supplied to verify, the error code (0 for success), an optional module
 * request state object to be consumed by return_fn or free_modreq_fn, optional
 * e_data to be passed to the caller if code is nonzero, and optional
 * authorization data to be included in the ticket.  In non-FAST replies,
 * e_data will be encoded as typed-data if the module sets the PA_TYPED_E_DATA
 * flag, and as pa-data otherwise.  e_data and authz_data will be freed by the
 * KDC.
 */
typedef void
(*krb5_kdcpreauth_verify_respond_fn)(void *arg, krb5_error_code code,
                                     krb5_kdcpreauth_modreq modreq,
                                     krb5_pa_data **e_data,
                                     krb5_authdata **authz_data);

/*
 * Optional: verify preauthentication data sent by the client, setting the
 * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
 * field as appropriate.  The implementation must invoke the respond function
 * when complete, whether successful or not, either before returning or
 * asynchronously using the verto context returned by cb->event_context().
 */
typedef void
(*krb5_kdcpreauth_verify_fn)(krb5_context context,
                             krb5_data *req_pkt, krb5_kdc_req *request,
                             krb5_enc_tkt_part *enc_tkt_reply,
                             krb5_pa_data *data,
                             krb5_kdcpreauth_callbacks cb,
                             krb5_kdcpreauth_rock rock,
                             krb5_kdcpreauth_moddata moddata,
                             krb5_kdcpreauth_verify_respond_fn respond,
                             void *arg);

/*
 * Optional: generate preauthentication response data to send to the client as
 * part of the AS-REP.  If it needs to override the key which is used to
 * encrypt the response, it can do so.
 */
typedef krb5_error_code
(*krb5_kdcpreauth_return_fn)(krb5_context context,
                             krb5_pa_data *padata,
                             krb5_data *req_pkt,
                             krb5_kdc_req *request,
                             krb5_kdc_rep *reply,
                             krb5_keyblock *encrypting_key,
                             krb5_pa_data **send_pa_out,
                             krb5_kdcpreauth_callbacks cb,
                             krb5_kdcpreauth_rock rock,
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

#endif /* KRB5_PREAUTH_PLUGIN_H_INCLUDED */

/*
 * $Header$
 *
 * Copyright 2006-2008 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 */

#include <krb5.h>
#include "kim_private.h"

struct kim_credential_iterator_opaque {
    krb5_context context;
    krb5_ccache ccache;
    krb5_cc_cursor cursor;
    krb5_flags old_flags;
};

struct kim_credential_iterator_opaque kim_credential_iterator_initializer = { NULL, NULL, NULL };

/* ------------------------------------------------------------------------ */

kim_error kim_credential_iterator_create (kim_credential_iterator *out_credential_iterator,
                                          kim_ccache               in_ccache)
{
    kim_error err = kim_library_init ();
    kim_credential_iterator credential_iterator = NULL;

    if (!err && !out_credential_iterator) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_ccache              ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        credential_iterator = malloc (sizeof (*credential_iterator));
        if (credential_iterator) {
            *credential_iterator = kim_credential_iterator_initializer;
        } else {
            err = KIM_OUT_OF_MEMORY_ERR;
        }
    }

    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential_iterator->context));
    }

    if (!err) {
        err = kim_ccache_get_krb5_ccache (in_ccache,
                                          credential_iterator->context,
                                          &credential_iterator->ccache);
    }

    if (!err) {
        /* Turn off OPENCLOSE mode */
        err = krb5_error (credential_iterator->context,
                          krb5_cc_get_flags (credential_iterator->context,
                                             credential_iterator->ccache,
                                             &credential_iterator->old_flags));

        if (!err && credential_iterator->old_flags & KRB5_TC_OPENCLOSE) {
            krb5_flags new_flags = credential_iterator->old_flags & ~KRB5_TC_OPENCLOSE;

            err = krb5_error (credential_iterator->context,
                              krb5_cc_set_flags (credential_iterator->context,
                                                 credential_iterator->ccache,
                                                 new_flags));
            if (err == KRB5_FCC_NOFILE) { err = KIM_NO_ERROR; }
        }
    }

    if (!err) {
        err = krb5_error (credential_iterator->context,
                          krb5_cc_start_seq_get (credential_iterator->context,
                                                 credential_iterator->ccache,
                                                 &credential_iterator->cursor));
    }

    if (!err) {
        *out_credential_iterator = credential_iterator;
        credential_iterator = NULL;
    }

    kim_credential_iterator_free (&credential_iterator);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_iterator_next (kim_credential_iterator  in_credential_iterator,
                                        kim_credential          *out_credential)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential_iterator) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_credential        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        krb5_creds creds;

        krb5_error_code terr = krb5_cc_next_cred (in_credential_iterator->context,
                                                  in_credential_iterator->ccache,
                                                  &in_credential_iterator->cursor,
                                                  &creds);

        if (!terr) {
            err = kim_credential_create_from_krb5_creds (out_credential,
                                                         in_credential_iterator->context,
                                                         &creds);

            krb5_free_cred_contents (in_credential_iterator->context, &creds);

        } else if (terr == KRB5_CC_END) {
            *out_credential = NULL; /* no more ccaches */

        } else {
            err = krb5_error (in_credential_iterator->context, terr);
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_credential_iterator_free (kim_credential_iterator *io_credential_iterator)
{
    if (io_credential_iterator && *io_credential_iterator) {
        if ((*io_credential_iterator)->context) {
            if ((*io_credential_iterator)->ccache) {
                if ((*io_credential_iterator)->cursor) {
                    krb5_cc_end_seq_get ((*io_credential_iterator)->context,
                                         (*io_credential_iterator)->ccache,
                                         &(*io_credential_iterator)->cursor);

                    krb5_cc_set_flags ((*io_credential_iterator)->context,
                                       (*io_credential_iterator)->ccache,
                                       (*io_credential_iterator)->old_flags);
                }
                krb5_cc_close ((*io_credential_iterator)->context,
                               (*io_credential_iterator)->ccache);
            }
            krb5_free_context ((*io_credential_iterator)->context);
        }
        free (*io_credential_iterator);
        *io_credential_iterator = NULL;
    }
}

#pragma mark -

/* ------------------------------------------------------------------------ */

struct kim_credential_opaque {
    krb5_context context;
    krb5_creds *creds;
};

struct kim_credential_opaque kim_credential_initializer = { NULL, NULL };

/* ------------------------------------------------------------------------ */

static inline kim_error kim_credential_allocate (kim_credential *out_credential)
{
    kim_error err = kim_library_init ();
    kim_credential credential = NULL;

    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        credential = malloc (sizeof (*credential));
        if (!credential) { err = KIM_OUT_OF_MEMORY_ERR; }
    }

    if (!err) {
        *credential = kim_credential_initializer;
        *out_credential = credential;
        credential = NULL;
    }

    kim_credential_free (&credential);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_new (kim_credential *out_credential,
                                     kim_identity    in_identity,
                                     kim_options     in_options)
{
    return check_error (kim_credential_create_new_with_password (out_credential,
                                                                 in_identity,
                                                                 in_options,
                                                                 NULL));
}

/* ------------------------------------------------------------------------ */

static void kim_credential_remember_prefs (kim_identity in_identity,
                                           kim_options  in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences prefs = NULL;
    kim_boolean remember_identity = 0;
    kim_boolean remember_options = 0;

    err = kim_preferences_create (&prefs);

    if (!err && in_options) {
        err = kim_preferences_get_remember_options (prefs,
                                                    &remember_options);
    }

    if (!err && in_identity) {
        err = kim_preferences_get_remember_client_identity (prefs,
                                                            &remember_identity);
    }

    if (!err && remember_options) {
        err = kim_preferences_set_options (prefs, in_options);
    }

    if (!err && remember_identity) {
        err = kim_preferences_set_client_identity (prefs, in_identity);

    }

    if (!err && (remember_options || remember_identity)) {
        err = kim_preferences_synchronize (prefs);
    }

    kim_preferences_free (&prefs);

    check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_new_with_password (kim_credential *out_credential,
                                                   kim_identity    in_identity,
                                                   kim_options     in_options,
                                                   kim_string      in_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    kim_options options = NULL;
    kim_ui_context context;
    kim_boolean ui_inited = 0;
    kim_boolean done_with_identity = 0;

    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_allocate (&credential);
    }

    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }

    if (!err) {
        if (in_options) {
            options = in_options;
        } else {
            err = kim_options_create (&options);
        }
    }

    if (!err) {
        err = kim_ui_init (&context);
        if (!err) { ui_inited = 1; }
    }

    while (!err && !done_with_identity) {
        kim_identity identity = in_identity;
        kim_boolean done_with_credentials = 0;

        if (identity) {
            done_with_identity = 1;

        } else while (!err && !identity) {
            kim_boolean user_wants_change_password = 0;

            err = kim_ui_enter_identity (&context, options,
                                         &identity,
                                         &user_wants_change_password);

            if (!err && user_wants_change_password) {
                err = kim_identity_change_password_common (identity, 0,
                                                           &context,
                                                           NULL);

                /* reenter enter_identity so just forget this identity
                 * even if we got an error */
                if (err == KIM_USER_CANCELED_ERR ||
                    err == KIM_DUPLICATE_UI_REQUEST_ERR) {
                    err = KIM_NO_ERROR;
                }

                kim_identity_free (&identity);
            }

        }

        if (!err) {
            context.identity = identity; /* used by kim_ui_prompter */
        }

        while (!err && !done_with_credentials) {
            krb5_creds creds;
            kim_boolean free_creds = 0;
            kim_count prompt_count;
            krb5_principal principal = kim_identity_krb5_principal (identity);
            krb5_get_init_creds_opt *opts = kim_options_init_cred_options (options);
            char *service = kim_options_service_name (options);
            kim_time start_time = kim_options_start_time (options);

            /* set counter to zero so we can tell if we got prompted */
            context.prompt_count = 0;
            context.password_to_save = NULL;

            err = krb5_error (credential->context,
                              krb5_get_init_creds_password (credential->context,
                                                            &creds,
                                                            principal,
                                                            (char *) in_password,
                                                            kim_ui_prompter,
                                                            &context,
                                                            start_time,
                                                            service,
                                                            opts));

            prompt_count = context.prompt_count; /* remember if we got prompts */
            if (!err) { free_creds = 1; }

            if (!err) {
                err = krb5_error (credential->context,
                                  krb5_copy_creds (credential->context,
                                                   &creds,
                                                   &credential->creds));
            }

            if (!err && context.password_to_save) {
                /* If we were successful, save any password we got */
                err = kim_os_identity_set_saved_password (identity,
                                                          context.password_to_save);


            }

            if (err == KRB5KDC_ERR_KEY_EXP) {
                kim_string new_password = NULL;

                err = kim_identity_change_password_common (identity, 1,
                                                           &context,
                                                           &new_password);

                if (!err) {
                    /* set counter to zero so we can tell if we got prompted */
                    context.prompt_count = 0;

                    err = krb5_error (credential->context,
                                      krb5_get_init_creds_password (credential->context,
                                                                    &creds,
                                                                    principal,
                                                                    (char *) new_password,
                                                                    kim_ui_prompter,
                                                                    &context,
                                                                    start_time,
                                                                    service,
                                                                    opts));

                    prompt_count = context.prompt_count; /* remember if we got prompts */
                    if (!err) { free_creds = 1; }

                    if (!err) {
                        err = krb5_error (credential->context,
                                          krb5_copy_creds (credential->context,
                                                           &creds,
                                                           &credential->creds));
                    }
                }

                kim_string_free (&new_password);
            }

            if (!err || err == KIM_USER_CANCELED_ERR ||
                        err == KIM_DUPLICATE_UI_REQUEST_ERR) {
                /* new creds obtained or the user gave up */
                done_with_credentials = 1;

                if (!err) {
                    /* remember identity and options if the user wanted to */
                    kim_credential_remember_prefs (identity, options);
                }

                if (err == KIM_DUPLICATE_UI_REQUEST_ERR) {
                    kim_ccache ccache = NULL;
                    /* credential for this identity was obtained, but via a different
                     * dialog.  Find it.  */

                    err = kim_ccache_create_from_client_identity (&ccache,
                                                                  identity);

                    if (!err) {
                        err = kim_ccache_get_valid_credential (ccache,
                                                               &credential);
                    }

                    kim_ccache_free (&ccache);
                }

            } else if (prompt_count) {
                /* User was prompted and might have entered bad info
                 * so report error and try again. */

                err = kim_ui_handle_kim_error (&context, identity,
                                               kim_ui_error_type_authentication,
                                               err);
            }

            if (err == KRB5KRB_AP_ERR_BAD_INTEGRITY ||
                err == KRB5KDC_ERR_PREAUTH_FAILED ||
                err == KIM_BAD_PASSWORD_ERR || err == KIM_PREAUTH_FAILED_ERR) {
                /* if the password could have failed, remove any saved ones
                 * or the user will get stuck. */
                kim_os_identity_remove_saved_password (identity);
            }

            if (free_creds) { krb5_free_cred_contents (credential->context, &creds); }
        }

        if (!err || err == KIM_USER_CANCELED_ERR) {
            /* identity obtained or the user gave up */
            done_with_identity = 1;

        } else if (!in_identity) {
            /* User entered an identity so report error and try again */
            err = kim_ui_handle_kim_error (&context, identity,
                                           kim_ui_error_type_authentication,
                                           err);
        }

        if (identity != in_identity) { kim_identity_free (&identity); }
    }

    if (ui_inited) {
        kim_error fini_err = kim_ui_fini (&context);
        if (!err) { err = check_error (fini_err); }
    }

    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }

    if (options != in_options) { kim_options_free (&options); }
    kim_credential_free (&credential);

    return check_error (err);
}

#ifndef LEAN_CLIENT

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_from_keytab (kim_credential *out_credential,
                                             kim_identity    in_identity,
                                             kim_options     in_options,
                                             kim_string      in_keytab)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    krb5_keytab keytab = NULL;
    krb5_creds creds;
    kim_boolean free_creds = FALSE;
    krb5_principal principal = NULL;
    kim_options options = in_options;

    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_allocate (&credential);
    }

    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }

    if (!err && !options) {
        err = kim_options_create (&options);
    }

    if (!err) {
        if (in_keytab) {
            err = krb5_error (credential->context,
                              krb5_kt_resolve (credential->context,
                                               in_keytab, &keytab));
        } else {
            err = krb5_error (credential->context,
                              krb5_kt_default (credential->context, &keytab));
        }
    }

    if (!err) {
        if (in_identity) {
            err = kim_identity_get_krb5_principal (in_identity,
                                                   credential->context,
                                                   &principal);
        } else {
            krb5_kt_cursor cursor = NULL;
            krb5_keytab_entry entry;
            kim_boolean entry_allocated = FALSE;

            err = krb5_error (credential->context,
                              krb5_kt_start_seq_get (credential->context,
                                                     keytab,
                                                     &cursor));

            if (!err) {
                err = krb5_error (credential->context,
                                  krb5_kt_next_entry (credential->context,
                                                      keytab,
                                                      &entry,
                                                      &cursor));
                entry_allocated = (err == KIM_NO_ERROR); /* remember to free later */
            }

            if (!err) {
                err = krb5_error (credential->context,
                                  krb5_copy_principal (credential->context,
                                                       entry.principal,
                                                       &principal));
            }

            if (entry_allocated) { krb5_free_keytab_entry_contents (credential->context, &entry); }
            if (cursor         ) { krb5_kt_end_seq_get (credential->context, keytab, &cursor); }
        }
    }

    if (!err) {
        krb5_get_init_creds_opt *opts = kim_options_init_cred_options (options);
        char *service = kim_options_service_name (options);
        kim_time start_time = kim_options_start_time (options);

        err = krb5_error (credential->context,
                          krb5_get_init_creds_keytab (credential->context,
                                                      &creds,
                                                      principal,
                                                      keytab,
                                                      start_time,
                                                      service,
                                                      opts));
        if (!err) { free_creds = TRUE; }
    }

    if (!err) {
        err = krb5_error (credential->context,
                          krb5_copy_creds (credential->context,
                                           &creds,
                                           &credential->creds));
    }

    if (principal ) { krb5_free_principal (credential->context, principal); }
    if (free_creds) { krb5_free_cred_contents (credential->context, &creds); }

    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }

    if (options != in_options) { kim_options_free (&options); }
    kim_credential_free (&credential);

    return check_error (err);
}

#endif /* LEAN_CLIENT */

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_from_krb5_creds (kim_credential *out_credential,
                                                 krb5_context    in_krb5_context,
                                                 krb5_creds     *in_krb5_creds)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;

    if (!err && !out_credential ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_creds  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_allocate (&credential);
    }

    if (!err) {
        err = krb5_error (in_krb5_context,
                          krb5_copy_context (in_krb5_context,
                                             &credential->context));
    }

    if (!err) {
        err = krb5_error (credential->context,
                          krb5_copy_creds (credential->context,
                                           in_krb5_creds,
                                           &credential->creds));
    }

    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }

    return check_error (err);
}
/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_for_change_password (kim_credential  *out_credential,
                                                     kim_identity     in_identity,
                                                     kim_string       in_old_password,
                                                     kim_ui_context  *in_ui_context,
                                                     kim_boolean     *out_user_was_prompted)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    kim_string realm = NULL;
    kim_string service = NULL;
    kim_string service_format = "kadmin/changepw@%s";

    if (!err && !out_credential       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_old_password      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_user_was_prompted) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_allocate (&credential);
    }

    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }

    if (!err) {
        err = kim_identity_get_realm (in_identity, &realm);
    }

    if (!err) {
        err = kim_string_create_from_format (&service, service_format, realm);
    }

    if (!err) {
        krb5_creds creds;
        kim_boolean free_creds = 0;
        krb5_principal principal = kim_identity_krb5_principal (in_identity);
        krb5_get_init_creds_opt	opts;

        krb5_get_init_creds_opt_init (&opts);
        krb5_get_init_creds_opt_set_tkt_life (&opts, 5*60);
        krb5_get_init_creds_opt_set_renew_life (&opts, 0);
        krb5_get_init_creds_opt_set_forwardable (&opts, 0);
        krb5_get_init_creds_opt_set_proxiable (&opts, 0);

        /* set counter to zero so we can tell if we got prompted */
        in_ui_context->prompt_count = 0;
        in_ui_context->identity = in_identity;

        err = krb5_error (credential->context,
                          krb5_get_init_creds_password (credential->context,
                                                        &creds,
                                                        principal,
                                                        (char *) in_old_password,
                                                        kim_ui_prompter,
                                                        in_ui_context, 0,
                                                        (char *) service,
                                                        &opts));

       if (!err) { free_creds = 1; }

        if (!err) {
            err = krb5_error (credential->context,
                              krb5_copy_creds (credential->context,
                                               &creds,
                                               &credential->creds));
        }

        if (free_creds) { krb5_free_cred_contents (credential->context, &creds); }
    }

    if (!err) {
        *out_user_was_prompted = (in_ui_context->prompt_count > 0);
        *out_credential = credential;
        credential = NULL;
    }

    kim_string_free (&realm);
    kim_string_free (&service);
    kim_credential_free (&credential);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_copy (kim_credential *out_credential,
                               kim_credential  in_credential)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;

    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_credential ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_allocate (&credential);
    }

    if (!err) {
        err = krb5_error (in_credential->context,
                          krb5_copy_context (in_credential->context,
                                             &credential->context));
    }

    if (!err) {
        err = krb5_error (credential->context,
                          krb5_copy_creds (credential->context,
                                           in_credential->creds,
                                           &credential->creds));
    }

    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_krb5_creds (kim_credential   in_credential,
                                         krb5_context     in_krb5_context,
                                         krb5_creds     **out_krb5_creds)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_krb5_creds ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = krb5_error (in_krb5_context,
                          krb5_copy_creds (in_krb5_context,
                                           in_credential->creds,
                                           out_krb5_creds));
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_client_identity (kim_credential  in_credential,
                                              kim_identity   *out_client_identity)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_client_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_identity_create_from_krb5_principal (out_client_identity,
                                                       in_credential->context,
                                                       in_credential->creds->client);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_service_identity (kim_credential  in_credential,
                                               kim_identity   *out_service_identity)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_service_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_identity_create_from_krb5_principal (out_service_identity,
                                                       in_credential->context,
                                                       in_credential->creds->server);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_is_tgt (kim_credential  in_credential,
                                 kim_boolean     *out_is_tgt)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity service = NULL;

    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_is_tgt   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_get_service_identity (in_credential, &service);
    }

    if (!err) {
        err = kim_identity_is_tgt_service (service, out_is_tgt);
    }

    kim_identity_free (&service);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_state (kim_credential           in_credential,
                                    kim_credential_state    *out_state)
{
    kim_error err = KIM_NO_ERROR;
    kim_time expiration_time = 0;
    kim_time start_time = 0;
    krb5_timestamp now = 0;

    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_state    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_credential_get_expiration_time (in_credential, &expiration_time);
    }

    if (!err) {
        err = kim_credential_get_start_time (in_credential, &start_time);
    }

    if (!err) {
        krb5_int32 usec;

        err = krb5_error (in_credential->context,
                          krb5_us_timeofday (in_credential->context,
                                             &now, &usec));
    }

    if (!err) {
        *out_state = kim_credentials_state_valid;

        if (expiration_time <= now) {
            *out_state = kim_credentials_state_expired;

        } else if ((in_credential->creds->ticket_flags & TKT_FLG_POSTDATED) &&
                   (in_credential->creds->ticket_flags & TKT_FLG_INVALID)) {
            if (start_time > now) {
                *out_state = kim_credentials_state_not_yet_valid;
            } else {
                *out_state = kim_credentials_state_needs_validation;
            }

        } else if (in_credential->creds->addresses) { /* ticket contains addresses */
            krb5_address **laddresses = NULL;

            krb5_error_code code = krb5_os_localaddr (in_credential->context,
                                                      &laddresses);
            if (!code) { laddresses = NULL; }

            if (laddresses) { /* assume valid if the local host has no addresses */
                kim_boolean found_match = FALSE;
                kim_count i = 0;

                for (i = 0; in_credential->creds->addresses[i]; i++) {
                    if (!krb5_address_search (in_credential->context,
                                              in_credential->creds->addresses[i],
                                              laddresses)) {
                        found_match = TRUE;
                        break;
                    }
                }

                if (!found_match) {
                    *out_state = kim_credentials_state_address_mismatch;
                }
            }

            if (laddresses) { krb5_free_addresses (in_credential->context,
                                                   laddresses); }
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_start_time (kim_credential  in_credential,
                                         kim_time       *out_start_time)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_start_time) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_start_time = (in_credential->creds->times.starttime ?
                           in_credential->creds->times.starttime :
                           in_credential->creds->times.authtime);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_expiration_time (kim_credential  in_credential,
                                              kim_time       *out_expiration_time)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_expiration_time = in_credential->creds->times.endtime;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_renewal_expiration_time (kim_credential  in_credential,
                                                      kim_time       *out_renewal_expiration_time)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_credential              ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_renewal_expiration_time) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (in_credential->creds->ticket_flags & TKT_FLG_RENEWABLE) {
            *out_renewal_expiration_time = in_credential->creds->times.renew_till;
        } else {
            *out_renewal_expiration_time = 0;
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_options (kim_credential  in_credential,
                                      kim_options    *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;
    krb5_creds *creds = NULL;

    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_options  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        creds = in_credential->creds;

        err = kim_options_create (&options);
    }

    if (!err) {
        err = kim_options_set_start_time (options, creds->times.starttime);
    }

    if (!err) {
        kim_lifetime lifetime = (creds->times.endtime -
                                 (creds->times.starttime ?
                                  creds->times.starttime :
                                  creds->times.authtime));

        err = kim_options_set_lifetime (options, lifetime);
    }

    if (!err) {
        kim_boolean renewable = (creds->ticket_flags & TKT_FLG_RENEWABLE);

        err = kim_options_set_renewable (options, renewable);
    }

    if (!err) {
        kim_lifetime rlifetime = (creds->ticket_flags & TKT_FLG_RENEWABLE ?
                                  creds->times.renew_till -
                                  (creds->times.starttime ?
                                   creds->times.starttime :
                                   creds->times.authtime) : 0);

        err = kim_options_set_renewal_lifetime (options, rlifetime);
    }

    if (!err) {
        kim_boolean forwardable = (creds->ticket_flags & TKT_FLG_FORWARDABLE);

        err = kim_options_set_forwardable (options, forwardable);
    }

    if (!err) {
        kim_boolean proxiable = (creds->ticket_flags & TKT_FLG_PROXIABLE);

        err = kim_options_set_proxiable (options, proxiable);
    }

    if (!err) {
        kim_boolean addressless = (!creds->addresses || !creds->addresses[0]);

        err = kim_options_set_addressless (options, addressless);
    }

    if (!err) {
        kim_boolean is_tgt = 0;
        kim_string service = NULL; /* tgt service */

        err = kim_credential_is_tgt (in_credential, &is_tgt);

        if (!err && !is_tgt) {
            kim_identity identity = NULL;

            err = kim_credential_get_service_identity (in_credential, &identity);

            if (!err) {
                err = kim_identity_get_string (identity, &service);
            }

            kim_identity_free (&identity);
        }

        if (!err) {
            err = kim_options_set_service_name (options, service);
        }

        kim_string_free (&service);
    }

    if (!err) {
        *out_options = options;
        options = NULL;
    }

    kim_options_free (&options);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_store (kim_credential  in_credential,
                                kim_identity    in_identity,
                                kim_ccache     *out_ccache)
{
    kim_error err = KIM_NO_ERROR;
    krb5_ccache k5ccache = NULL;
    kim_boolean destroy_ccache_on_error = FALSE;

    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        char *environment_ccache = getenv ("KRB5CCNAME");

        if (environment_ccache) {
            err = krb5_error (in_credential->context,
                              krb5_cc_resolve (in_credential->context,
                                               environment_ccache,
                                               &k5ccache));

        } else {
            kim_ccache ccache = NULL;

            err = kim_ccache_create_from_client_identity (&ccache,
                                                          in_identity);

            if (!err) {
                err = kim_ccache_get_krb5_ccache (ccache,
                                                  in_credential->context,
                                                  &k5ccache);

            } else if (err == KIM_NO_SUCH_PRINCIPAL_ERR) {
                /* Nothing to replace, create a new ccache */
                err = krb5_error (in_credential->context,
                                  krb5_cc_new_unique (in_credential->context,
                                                      "API", NULL, &k5ccache));
                if (!err) { destroy_ccache_on_error = TRUE; }
            }

            kim_ccache_free (&ccache);
        }
    }

    if (!err) {
        krb5_principal principal = kim_identity_krb5_principal (in_identity);

	err = krb5_error (in_credential->context,
                          krb5_cc_initialize (in_credential->context,
                                              k5ccache, principal));
    }

    if (!err) {
	err = krb5_error (in_credential->context,
                          krb5_cc_store_cred (in_credential->context,
                                              k5ccache, in_credential->creds));
    }

    if (!err && out_ccache) {
        err = kim_ccache_create_from_krb5_ccache (out_ccache,
                                                  in_credential->context,
                                                  k5ccache);
    }

    if (k5ccache) {
        if (err && destroy_ccache_on_error) {
            krb5_cc_destroy (in_credential->context, k5ccache);
        } else {
            krb5_cc_close (in_credential->context, k5ccache);
        }
    }

    return check_error (err);
}

#ifndef LEAN_CLIENT

/* ------------------------------------------------------------------------ */

kim_error kim_credential_verify (kim_credential in_credential,
                                 kim_identity   in_service_identity,
                                 kim_string     in_keytab,
                                 kim_boolean    in_fail_if_no_service_key)
{
    kim_error err = KIM_NO_ERROR;
    krb5_context scontext = NULL;
    krb5_keytab keytab = NULL;

    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
	err = krb5_error (NULL, krb5_init_secure_context (&scontext));
    }

    if (in_keytab) {
	err = krb5_error (scontext,
                          krb5_kt_resolve (scontext, in_keytab, &keytab));
    }

    if (!err) {
        krb5_principal sprincipal = NULL;
	krb5_verify_init_creds_opt options;

	/* That's "no key == fail" not "no fail" >.< */
        krb5_verify_init_creds_opt_init (&options);
        krb5_verify_init_creds_opt_set_ap_req_nofail (&options, in_fail_if_no_service_key);

        if (in_service_identity) {
            sprincipal = kim_identity_krb5_principal (in_service_identity);
        }

	err = krb5_error (scontext,
                          krb5_verify_init_creds (scontext,
                                                  in_credential->creds,
						  sprincipal,
						  keytab,
						  NULL /* don't store creds in ccache */,
						  &options));

	if (err && !in_service_identity && in_fail_if_no_service_key) {
	    /* If the service principal wasn't specified but we are supposed to
             * fail without a key we should walk the keytab trying to find one
             * that succeeds. */
            krb5_error_code terr = 0;
            kim_boolean verified = 0;
	    krb5_kt_cursor cursor = NULL;
	    krb5_keytab_entry entry;


	    if (!keytab) {
                terr = krb5_kt_default (scontext, &keytab);
	    }

	    if (!terr) {
		terr = krb5_kt_start_seq_get (scontext, keytab, &cursor);
	    }

	    while (!terr && !verified) {
                kim_boolean free_entry = 0;

		terr = krb5_kt_next_entry (scontext, keytab, &entry, &cursor);
		free_entry = !terr; /* remember to free */

                if (!terr) {
                    terr = krb5_verify_init_creds (scontext, in_credential->creds,
                                                   entry.principal /* get principal for the 1st entry */,
                                                   keytab,
                                                   NULL /* don't store creds in ccache */,
                                                   &options);
                }

                if (!terr) {
                    verified = 1;
                }

                if (free_entry) { krb5_free_keytab_entry_contents (scontext, &entry); }
	    }

            if (!terr && verified) {
                /* We found a key that verified! */
                err = KIM_NO_ERROR;
            }

	    if (cursor) { krb5_kt_end_seq_get (scontext, keytab, &cursor); }
	}
    }

    if (keytab  ) { krb5_kt_close (scontext, keytab); }
    if (scontext) { krb5_free_context (scontext); }

    return check_error (err);
}

#endif /* LEAN_CLIENT */

/* ------------------------------------------------------------------------ */

kim_error kim_credential_renew (kim_credential *io_credential,
                                kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_string service_name = NULL;
    krb5_ccache ccache = NULL;

    if (!err && !io_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        kim_options options = in_options;

        if (!options) {
            err = kim_options_create (&options);
        }

	if (!err) {
	    err = kim_options_get_service_name (options, &service_name);
	}

        if (options != in_options) { kim_options_free (&options); }
    }

    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_new_unique ((*io_credential)->context,
					      "MEMORY", NULL,
					      &ccache));
    }

    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_initialize ((*io_credential)->context, ccache,
					      (*io_credential)->creds->client));
    }

    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_store_cred ((*io_credential)->context, ccache,
					      (*io_credential)->creds));
    }

    if (!err) {
	krb5_creds creds;
	krb5_creds *renewed_creds = NULL;
	kim_boolean free_creds = 0;

	err = krb5_error ((*io_credential)->context,
                          krb5_get_renewed_creds ((*io_credential)->context,
						  &creds, (*io_credential)->creds->client,
						  ccache, (char *) service_name));
	if (!err) { free_creds = 1; }

	if (!err) {
	    err = krb5_error ((*io_credential)->context,
                              krb5_copy_creds ((*io_credential)->context,
                                               &creds, &renewed_creds));
	}

	if (!err) {
	    /* replace the credentials */
	    krb5_free_creds ((*io_credential)->context, (*io_credential)->creds);
	    (*io_credential)->creds = renewed_creds;
	}

	if (free_creds) { krb5_free_cred_contents ((*io_credential)->context, &creds); }
    }

    if (ccache) { krb5_cc_destroy ((*io_credential)->context, ccache); }
    kim_string_free (&service_name);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_validate (kim_credential *io_credential,
                                   kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_string service_name = NULL;
    krb5_ccache ccache = NULL;

    if (!err && !io_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        kim_options options = in_options;

        if (!options) {
            err = kim_options_create (&options);
        }

	if (!err) {
	    err = kim_options_get_service_name (options, &service_name);
	}

        if (options != in_options) { kim_options_free (&options); }
    }

    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_new_unique ((*io_credential)->context,
					      "MEMORY", NULL,
					      &ccache));
    }

    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_initialize ((*io_credential)->context, ccache,
					      (*io_credential)->creds->client));
    }

    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_store_cred ((*io_credential)->context, ccache,
					      (*io_credential)->creds));
    }

    if (!err) {
	krb5_creds creds;
	krb5_creds *validated_creds = NULL;
	kim_boolean free_creds = 0;

        err = krb5_error ((*io_credential)->context,
                          krb5_get_validated_creds ((*io_credential)->context,
						    &creds,
                                                    (*io_credential)->creds->client,
						    ccache,
                                                    (char *) service_name));
	if (!err) { free_creds = 1; }

	if (!err) {
	    err = krb5_error ((*io_credential)->context,
                              krb5_copy_creds ((*io_credential)->context,
                                               &creds, &validated_creds));
	}

	if (!err) {
	    /* replace the credentials */
	    krb5_free_creds ((*io_credential)->context, (*io_credential)->creds);
	    (*io_credential)->creds = validated_creds;
	}

	if (free_creds) { krb5_free_cred_contents ((*io_credential)->context, &creds); }
    }

    if (ccache) { krb5_cc_destroy ((*io_credential)->context, ccache); }
    kim_string_free (&service_name);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_credential_free (kim_credential *io_credential)
{
    if (io_credential && *io_credential) {
        if ((*io_credential)->context) {
            if ((*io_credential)->creds) {
                krb5_free_creds ((*io_credential)->context, (*io_credential)->creds);
            }
            krb5_free_context ((*io_credential)->context);
        }
        free (*io_credential);
        *io_credential = NULL;
    }
}

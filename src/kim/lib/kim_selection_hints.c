/*
 * Copyright 2005-2006 Massachusetts Institute of Technology.
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

#include "kim_private.h"

/* ------------------------------------------------------------------------ */

struct kim_selection_hints_opaque {
    kim_string application_identifier;
    kim_string explanation;
    kim_options options;
    kim_boolean allow_user_interaction;
    kim_boolean use_cached_results;
    kim_string service_identity;
    kim_string client_realm;
    kim_string user;
    kim_string service_realm;
    kim_string service;
    kim_string server;
};

struct kim_selection_hints_opaque kim_selection_hints_initializer = {
    NULL,
    kim_empty_string,
    KIM_OPTIONS_DEFAULT,
    TRUE,
    TRUE,
    kim_empty_string,
    kim_empty_string,
    kim_empty_string,
    kim_empty_string,
    kim_empty_string,
    kim_empty_string
};

/* ------------------------------------------------------------------------ */

static inline kim_error kim_selection_hints_allocate (kim_selection_hints *out_selection_hints)
{
    kim_error err = kim_library_init ();
    kim_selection_hints selection_hints = NULL;

    if (!err && !out_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        selection_hints = malloc (sizeof (*selection_hints));
        if (!selection_hints) { err = KIM_OUT_OF_MEMORY_ERR; }
    }

    if (!err) {
        *selection_hints = kim_selection_hints_initializer;
        *out_selection_hints = selection_hints;
        selection_hints = NULL;
    }

    kim_selection_hints_free (&selection_hints);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_create (kim_selection_hints *out_selection_hints,
                                      kim_string           in_application_identifier)
{
    kim_error err = KIM_NO_ERROR;
    kim_selection_hints selection_hints = NULL;

    if (!err && !out_selection_hints      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_application_identifier) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_selection_hints_allocate (&selection_hints);
    }

    if (!err) {
        err = kim_string_copy (&selection_hints->application_identifier,
                               in_application_identifier);
    }

    if (!err) {
        *out_selection_hints = selection_hints;
        selection_hints = NULL;
    }

    kim_selection_hints_free (&selection_hints);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_copy (kim_selection_hints *out_selection_hints,
                                    kim_selection_hints  in_selection_hints)
{
    kim_error err = KIM_NO_ERROR;
    kim_selection_hints selection_hints = NULL;

    if (!err && !out_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_selection_hints ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_selection_hints_allocate (&selection_hints);
    }

    if (!err) {
        err = kim_string_copy (&selection_hints->application_identifier,
                               in_selection_hints->application_identifier);
    }

    if (!err && in_selection_hints->explanation) {
        err = kim_string_copy (&selection_hints->explanation,
                               in_selection_hints->explanation);
    }

    if (!err && in_selection_hints->options) {
        err = kim_options_copy (&selection_hints->options,
                                in_selection_hints->options);
    }

    if (!err && in_selection_hints->service_identity) {
        err = kim_string_copy (&selection_hints->service_identity,
                               in_selection_hints->service_identity);
    }

    if (!err && in_selection_hints->client_realm) {
        err = kim_string_copy (&selection_hints->client_realm,
                               in_selection_hints->client_realm);
    }

    if (!err && in_selection_hints->user) {
        err = kim_string_copy (&selection_hints->user,
                               in_selection_hints->user);
    }

    if (!err && in_selection_hints->service_realm) {
        err = kim_string_copy (&selection_hints->service_realm,
                               in_selection_hints->service_realm);
    }

    if (!err && in_selection_hints->service) {
        err = kim_string_copy (&selection_hints->service,
                               in_selection_hints->service);
    }

    if (!err && in_selection_hints->server) {
        err = kim_string_copy (&selection_hints->server,
                               in_selection_hints->server);
    }

    if (!err) {
        selection_hints->allow_user_interaction = in_selection_hints->allow_user_interaction;
        selection_hints->use_cached_results = in_selection_hints->use_cached_results;

        *out_selection_hints = selection_hints;
        selection_hints = NULL;
    }

    kim_selection_hints_free (&selection_hints);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_set_hint (kim_selection_hints io_selection_hints,
                                        kim_string          in_hint_key,
                                        kim_string          in_hint_string)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_hint_key       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_hint_string    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (!strcmp (in_hint_key, kim_hint_key_client_realm)) {
            kim_string_free (&io_selection_hints->client_realm);
            err = kim_string_copy (&io_selection_hints->client_realm,
                                   in_hint_string);

        } else if (!strcmp (in_hint_key, kim_hint_key_user)) {
            kim_string_free (&io_selection_hints->user);
            err = kim_string_copy (&io_selection_hints->user,
                                   in_hint_string);

        } else if (!strcmp (in_hint_key, kim_hint_key_service_realm)) {
            kim_string_free (&io_selection_hints->service_realm);
            err = kim_string_copy (&io_selection_hints->service_realm,
                                   in_hint_string);

        } else if (!strcmp (in_hint_key, kim_hint_key_service)) {
            kim_string_free (&io_selection_hints->service);
            err = kim_string_copy (&io_selection_hints->service,
                                   in_hint_string);

        } else if (!strcmp (in_hint_key, kim_hint_key_server)) {
            kim_string_free (&io_selection_hints->server);
            err = kim_string_copy (&io_selection_hints->server,
                                   in_hint_string);

        } else if (!strcmp (in_hint_key, kim_hint_key_service_identity)) {
            kim_string_free (&io_selection_hints->service_identity);
            err = kim_string_copy (&io_selection_hints->service_identity,
                                   in_hint_string);

        } else {
            err = kim_error_set_message_for_code (KIM_UNSUPPORTED_HINT_ERR,
                                                  in_hint_key);
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_hint (kim_selection_hints  in_selection_hints,
                                        kim_string           in_hint_key,
                                        kim_string          *out_hint_string)
{
    kim_error err = KIM_NO_ERROR;
    kim_string hint = NULL;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_hint_key       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_hint_string   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (!strcmp (in_hint_key, kim_hint_key_client_realm)) {
            hint = in_selection_hints->client_realm;

        } else if (!strcmp (in_hint_key, kim_hint_key_user)) {
            hint = in_selection_hints->user;

        } else if (!strcmp (in_hint_key, kim_hint_key_service_realm)) {
            hint = in_selection_hints->service_realm;

        } else if (!strcmp (in_hint_key, kim_hint_key_service)) {
            hint = in_selection_hints->service;

        } else if (!strcmp (in_hint_key, kim_hint_key_server)) {
            hint = in_selection_hints->server;

        } else if (!strcmp (in_hint_key, kim_hint_key_service_identity)) {
            hint = in_selection_hints->service_identity;

        } else {
            err = kim_error_set_message_for_code (KIM_UNSUPPORTED_HINT_ERR,
                                                  in_hint_key);
        }
    }

    if (!err) {
        if (hint && hint != kim_empty_string) {
            err = kim_string_copy (out_hint_string, hint);
        } else {
            *out_hint_string = NULL;
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_set_explanation (kim_selection_hints io_selection_hints,
                                               kim_string          in_explanation)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_explanation    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_string_copy (&io_selection_hints->explanation, in_explanation);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_explanation (kim_selection_hints  in_selection_hints,
                                               kim_string          *out_explanation)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_explanation   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (in_selection_hints->explanation &&
            in_selection_hints->explanation != kim_empty_string) {
            err = kim_string_copy (out_explanation, in_selection_hints->explanation);
        } else {
            *out_explanation = NULL;
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_application_id (kim_selection_hints  in_selection_hints,
                                                  kim_string          *out_application_id)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_application_id) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (in_selection_hints->application_identifier) {
            err = kim_string_copy (out_application_id,
                                   in_selection_hints->application_identifier);
        } else {
            *out_application_id = NULL;
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_set_options (kim_selection_hints io_selection_hints,
                                           kim_options         in_options)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_options        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_options_copy (&io_selection_hints->options, in_options);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_options (kim_selection_hints  in_selection_hints,
                                           kim_options         *out_options)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_options       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_options_copy (out_options, in_selection_hints->options);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_set_allow_user_interaction (kim_selection_hints io_selection_hints,
                                                          kim_boolean         in_allow_user_interaction)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_selection_hints ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_selection_hints->allow_user_interaction = in_allow_user_interaction;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_allow_user_interaction (kim_selection_hints  in_selection_hints,
                                                          kim_boolean         *out_allow_user_interaction)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_allow_user_interaction) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_allow_user_interaction = in_selection_hints->allow_user_interaction;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_set_remember_identity (kim_selection_hints io_selection_hints,
                                                     kim_boolean         in_use_cached_results)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_selection_hints ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_selection_hints->use_cached_results = in_use_cached_results;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_remember_identity (kim_selection_hints  in_selection_hints,
                                                     kim_boolean         *out_use_cached_results)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_use_cached_results) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_use_cached_results = in_selection_hints->use_cached_results;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_identity (kim_selection_hints  in_selection_hints,
                                            kim_identity        *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    kim_ccache ccache = NULL;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && in_selection_hints->use_cached_results) {
        err = kim_os_selection_hints_lookup_identity (in_selection_hints, &identity);
    }

    if (!err && !identity && in_selection_hints->allow_user_interaction) {
        kim_ui_context context;

        err = kim_ui_init (&context);

        while (!err && !identity) {
            kim_boolean user_wants_change_password = 0;

            err = kim_ui_select_identity (&context,
                                          in_selection_hints,
                                          &identity,
                                          &user_wants_change_password);

            if (!err && user_wants_change_password) {
                err = kim_identity_change_password_common (identity, 0,
                                                           &context,
                                                           NULL);

                /* reenter select_identity so just forget this identity
                 * even if we got an error */
                if (err == KIM_USER_CANCELED_ERR ||
                    err == KIM_DUPLICATE_UI_REQUEST_ERR) { err = KIM_NO_ERROR; }
                kim_identity_free (&identity);
            }

        }

        if (context.initialized) {
            kim_error terr = KIM_NO_ERROR;
            terr = kim_ui_fini (&context);
            err = (terr != KIM_NO_ERROR) ? terr : err;
        }
    }

    if (!err) {
        *out_identity = identity;
        identity = NULL;
    }

    kim_identity_free (&identity);
    kim_ccache_free (&ccache);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_remember_identity (kim_selection_hints in_selection_hints,
                                                 kim_identity        in_identity)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_selection_hints_remember_identity (in_selection_hints,
                                                        in_identity);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_forget_identity (kim_selection_hints in_selection_hints)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_os_selection_hints_forget_identity (in_selection_hints);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_get_preference_strings (kim_selection_hints                   in_selection_hints,
                                                      kim_selection_hints_preference_strings *io_preference_strings)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_preference_strings) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_preference_strings->application_identifier = in_selection_hints->application_identifier;
        io_preference_strings->service_identity       = in_selection_hints->service_identity;
        io_preference_strings->client_realm           = in_selection_hints->client_realm;
        io_preference_strings->user                   = in_selection_hints->user;
        io_preference_strings->service_realm          = in_selection_hints->service_realm;
        io_preference_strings->service                = in_selection_hints->service;
        io_preference_strings->server                 = in_selection_hints->server;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_selection_hints_free (kim_selection_hints *io_selection_hints)
{
    if (io_selection_hints && *io_selection_hints) {
        kim_string_free  (&(*io_selection_hints)->application_identifier);
        kim_string_free  (&(*io_selection_hints)->explanation);
        kim_options_free (&(*io_selection_hints)->options);
        kim_string_free  (&(*io_selection_hints)->service_identity);
        kim_string_free  (&(*io_selection_hints)->client_realm);
        kim_string_free  (&(*io_selection_hints)->user);
        kim_string_free  (&(*io_selection_hints)->service_realm);
        kim_string_free  (&(*io_selection_hints)->service);
        kim_string_free  (&(*io_selection_hints)->server);
        free (*io_selection_hints);
        *io_selection_hints = NULL;
    }
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_write_to_stream (kim_selection_hints in_selection_hints,
                                               k5_ipc_stream       io_stream)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_stream         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->application_identifier);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->explanation);
    }

    if (!err) {
        err = kim_options_write_to_stream (in_selection_hints->options,
                                           io_stream);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->service_identity);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->client_realm);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->user);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->service_realm);
    }

    if (!err) {
       err = krb5int_ipc_stream_write_string (io_stream,
					      in_selection_hints->service);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,
					       in_selection_hints->server);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_read_from_stream (kim_selection_hints io_selection_hints,
                                                k5_ipc_stream       io_stream)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_stream         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        char *application_identifier = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &application_identifier);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->application_identifier,
                                   application_identifier);
        }

        krb5int_ipc_stream_free_string (application_identifier);
    }

    if (!err) {
        char *explanation = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &explanation);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->explanation,
                                   explanation);
        }

        krb5int_ipc_stream_free_string (explanation);
    }

    if (!err) {
        if (io_selection_hints->options) {
            err = kim_options_read_from_stream (io_selection_hints->options,
                                                io_stream);
        } else {
            err = kim_options_create_from_stream (&io_selection_hints->options,
                                                  io_stream);
        }
    }

    if (!err) {
        char *service_identity = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &service_identity);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->service_identity,
                                   service_identity);
        }

        krb5int_ipc_stream_free_string (service_identity);
    }

    if (!err) {
        char *client_realm = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &client_realm);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->client_realm,
                                   client_realm);
        }

        krb5int_ipc_stream_free_string (client_realm);
    }

    if (!err) {
        char *user = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &user);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->user, user);
        }

        krb5int_ipc_stream_free_string (user);
    }

    if (!err) {
        char *service_realm = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &service_realm);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->service_realm,
                                   service_realm);
        }

        krb5int_ipc_stream_free_string (service_realm);
    }

    if (!err) {
        char *service = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &service);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->service, service);
        }

        krb5int_ipc_stream_free_string (service);
    }

    if (!err) {
        char *server = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &server);

        if (!err) {
            err = kim_string_copy (&io_selection_hints->server, server);
        }

        krb5int_ipc_stream_free_string (server);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_selection_hints_create_from_stream (kim_selection_hints *out_selection_hints,
                                                  k5_ipc_stream        io_stream)
{
    kim_error err = KIM_NO_ERROR;
    kim_selection_hints selection_hints = NULL;

    if (!err && !out_selection_hints) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_stream          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_selection_hints_allocate (&selection_hints);
    }

    if (!err) {
        err = kim_selection_hints_read_from_stream (selection_hints, io_stream);
    }

    if (!err) {
        *out_selection_hints = selection_hints;
        selection_hints = NULL;
    }

    kim_selection_hints_free (&selection_hints);

    return check_error (err);
}

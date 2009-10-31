/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
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

struct kim_options_opaque {
    kim_time start_time;
    kim_lifetime lifetime;
    kim_boolean renewable;
    kim_lifetime renewal_lifetime;
    kim_boolean forwardable;
    kim_boolean proxiable;
    kim_boolean addressless;
    kim_string service_name;
    krb5_context init_cred_context;
    krb5_get_init_creds_opt *init_cred_options;
};

struct kim_options_opaque kim_options_initializer = {
0,
kim_default_lifetime,
kim_default_renewable,
kim_default_renewal_lifetime,
kim_default_forwardable,
kim_default_proxiable,
kim_default_addressless,
kim_empty_string,
NULL,
NULL };

/* ------------------------------------------------------------------------ */

static inline kim_error kim_options_allocate (kim_options *out_options)
{
    kim_error err = kim_library_init ();
    kim_options options = NULL;

    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        options = malloc (sizeof (*options));
        if (!options) { err = KIM_OUT_OF_MEMORY_ERR; }
    }

    if (!err) {
        *options = kim_options_initializer;
        *out_options = options;
        options = NULL;
    }

    kim_options_free (&options);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_create_empty (kim_options *out_options)
{
    return check_error (kim_options_allocate (out_options));
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_create (kim_options *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    kim_options options = KIM_OPTIONS_DEFAULT;

    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_preferences_create (&preferences);
    }

    if (!err) {
        err = kim_preferences_get_options (preferences, &options);
    }

    if (!err && !options) {
        err = kim_options_allocate (&options);
    }

    if (!err) {
        *out_options = options;
        options = NULL; /* caller takes ownership */
    }

    kim_options_free (&options);
    kim_preferences_free (&preferences);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_copy (kim_options *out_options,
                            kim_options  in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = KIM_OPTIONS_DEFAULT;

    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && in_options != KIM_OPTIONS_DEFAULT) {
        err = kim_options_allocate (&options);

        if (!err) {
            options->start_time = in_options->start_time;
            options->lifetime = in_options->lifetime;
            options->renewable = in_options->renewable;
            options->renewal_lifetime = in_options->renewal_lifetime;
            options->forwardable = in_options->forwardable;
            options->proxiable = in_options->proxiable;
            options->addressless = in_options->addressless;

            if (in_options->service_name) {
                err = kim_string_copy (&options->service_name,
                                       in_options->service_name);
            }
        }
    }

    if (!err) {
        *out_options = options;
        options = NULL;
    }

    kim_options_free (&options);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_start_time (kim_options io_options,
                                      kim_time    in_start_time)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->start_time = in_start_time;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_start_time (kim_options  in_options,
                                      kim_time    *out_start_time)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_start_time) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_start_time = in_options->start_time;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_lifetime (kim_options  io_options,
                                    kim_lifetime in_lifetime)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->lifetime = in_lifetime;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_lifetime (kim_options   in_options,
                                    kim_lifetime *out_lifetime)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_lifetime = in_options->lifetime;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_renewable (kim_options io_options,
                                     kim_boolean in_renewable)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->renewable = in_renewable;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_renewable (kim_options  in_options,
                                     kim_boolean *out_renewable)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_renewable) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_renewable = in_options->renewable;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_renewal_lifetime (kim_options  io_options,
                                            kim_lifetime in_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->renewal_lifetime = in_renewal_lifetime;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_renewal_lifetime (kim_options   in_options,
                                            kim_lifetime *out_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_renewal_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_renewal_lifetime = in_options->renewal_lifetime;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_forwardable (kim_options io_options,
                                       kim_boolean in_forwardable)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->forwardable = in_forwardable;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_forwardable (kim_options  in_options,
                                       kim_boolean *out_forwardable)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_forwardable) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_forwardable = in_options->forwardable;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_proxiable (kim_options io_options,
                                     kim_boolean in_proxiable)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->proxiable = in_proxiable;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_proxiable (kim_options  in_options,
                                     kim_boolean *out_proxiable)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_proxiable) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_proxiable = in_options->proxiable;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_addressless (kim_options io_options,
                                       kim_boolean in_addressless)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        io_options->addressless = in_addressless;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_addressless (kim_options  in_options,
                                       kim_boolean *out_addressless)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_addressless) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        *out_addressless = in_options->addressless;
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_service_name (kim_options  io_options,
                                        kim_string   in_service_name)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
	kim_string_free (&io_options->service_name);
        if (in_service_name) {
            err = kim_string_copy (&io_options->service_name, in_service_name);
        } else {
            io_options->service_name = kim_empty_string;
        }
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_service_name (kim_options  in_options,
                                        kim_string  *out_service_name)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !in_options      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_service_name) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (in_options->service_name &&
            in_options->service_name != kim_empty_string) {
            err = kim_string_copy (out_service_name, in_options->service_name);
        } else {
            *out_service_name = NULL;
        }
    }

    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

char *kim_options_service_name (kim_options in_options)
{
    if (in_options) {
        if (in_options->service_name == kim_empty_string) {
            return NULL;
        } else {
            return (char *) in_options->service_name;
        }
    }
    check_error (KIM_NULL_PARAMETER_ERR);  /* log bad options input */
    return NULL;
}

/* ------------------------------------------------------------------------ */

kim_time kim_options_start_time (kim_options in_options)
{
    if (in_options) {
        return in_options->start_time;
    }
    check_error (KIM_NULL_PARAMETER_ERR);  /* log bad options input */
    return 0;
}

/* ------------------------------------------------------------------------ */

krb5_get_init_creds_opt *kim_options_init_cred_options (kim_options in_options)
{
    kim_error err = KIM_NO_ERROR;
    krb5_address **addresses = NULL;

    if (!err && !in_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && !in_options->init_cred_context) {
        err = krb5_error (NULL,
                          krb5_init_context (&in_options->init_cred_context));
    }

    if (!err && !in_options->addressless) {
        err = krb5_error (in_options->init_cred_context,
                          krb5_os_localaddr (in_options->init_cred_context,
                                             &addresses));
    }

    if (!err && !in_options->init_cred_options) {
        err = krb5_error (in_options->init_cred_context,
                          krb5_get_init_creds_opt_alloc (in_options->init_cred_context,
                                                         &in_options->init_cred_options));
    }

    if (!err) {
        krb5_get_init_creds_opt_set_tkt_life (in_options->init_cred_options,
                                              in_options->lifetime);
        krb5_get_init_creds_opt_set_renew_life (in_options->init_cred_options,
                                                in_options->renewable ? in_options->renewal_lifetime : 0);
        krb5_get_init_creds_opt_set_forwardable (in_options->init_cred_options,
                                                 in_options->forwardable);
        krb5_get_init_creds_opt_set_proxiable (in_options->init_cred_options,
                                               in_options->proxiable);
        krb5_get_init_creds_opt_set_address_list (in_options->init_cred_options,
                                                  addresses);
        addresses = NULL;
    }

    if (addresses) { krb5_free_addresses (in_options->init_cred_context,
                                          addresses); }

    return !check_error (err) ? in_options->init_cred_options : NULL;
}

/* ------------------------------------------------------------------------ */

void kim_options_free (kim_options *io_options)
{
    if (io_options && *io_options) {
        kim_string_free (&(*io_options)->service_name);
        if ((*io_options)->init_cred_context) {
            if ((*io_options)->init_cred_options) {
                if ((*io_options)->init_cred_options->address_list) {
                    krb5_free_addresses ((*io_options)->init_cred_context,
                                         (*io_options)->init_cred_options->address_list);
                }
                krb5_get_init_creds_opt_free ((*io_options)->init_cred_context,
                                              (*io_options)->init_cred_options);
            }
            krb5_free_context ((*io_options)->init_cred_context);
        }

        free (*io_options);
        *io_options = NULL;
    }
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_options_write_to_stream (kim_options   in_options,
                                       k5_ipc_stream io_stream)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = in_options;

    if (!err && !io_stream ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && !in_options) {
        err = kim_options_create (&options);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int64 (io_stream, options->start_time);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int64 (io_stream, options->lifetime);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int32 (io_stream, options->renewable);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int64 (io_stream,
                                         options->renewal_lifetime);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int32 (io_stream, options->forwardable);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int32 (io_stream, options->proxiable);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_int32 (io_stream, options->addressless);
    }

    if (!err) {
        err = krb5int_ipc_stream_write_string (io_stream,  options->service_name);
    }

    if (options != in_options) { kim_options_free (&options); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_read_from_stream (kim_options    io_options,
                                        k5_ipc_stream  io_stream)
{
    kim_error err = KIM_NO_ERROR;

    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_stream ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = krb5int_ipc_stream_read_int64 (io_stream, &io_options->start_time);
    }

    if (!err) {
        err = krb5int_ipc_stream_read_int64 (io_stream, &io_options->lifetime);
    }

    if (!err) {
        err = krb5int_ipc_stream_read_int32 (io_stream, &io_options->renewable);
    }

    if (!err) {
        err = krb5int_ipc_stream_read_int64 (io_stream,
                                        &io_options->renewal_lifetime);
    }

    if (!err) {
        err = krb5int_ipc_stream_read_int32 (io_stream, &io_options->forwardable);
    }

    if (!err) {
        err = krb5int_ipc_stream_read_int32 (io_stream, &io_options->proxiable);
    }

    if (!err) {
        err = krb5int_ipc_stream_read_int32 (io_stream, &io_options->addressless);
    }

    if (!err) {
        char *service_name = NULL;
        err = krb5int_ipc_stream_read_string (io_stream, &service_name);

        if (!err) {
            kim_string_free (&io_options->service_name);
            if (service_name[0]) {
                err = kim_string_copy (&io_options->service_name, service_name);
            } else {
                io_options->service_name = kim_empty_string;
            }
        }

        krb5int_ipc_stream_free_string (service_name);
    }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_create_from_stream (kim_options   *out_options,
                                          k5_ipc_stream  io_stream)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;

    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !io_stream  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_options_allocate (&options);
    }

    if (!err) {
        kim_options_read_from_stream (options, io_stream);
    }

    if (!err) {
        *out_options = options;
        options = NULL;
    }

    kim_options_free (&options);

    return check_error (err);
}

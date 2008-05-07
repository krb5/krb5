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
    kim_prompt_callback_t prompt_callback;
    const void *prompt_callback_data;
#warning add prompt responses here
    kim_time_t start_time;
    kim_lifetime_t lifetime;
    kim_boolean_t renewable;
    kim_lifetime_t renewal_lifetime;
    kim_boolean_t forwardable;
    kim_boolean_t proxiable;
    kim_boolean_t addressless;
    kim_string_t service_name;
};

struct kim_options_opaque kim_options_initializer = { 
    NULL, NULL, 
    0, 
    kim_default_lifetime, 
    kim_default_renewable, 
    kim_default_renewal_lifetime,
    kim_default_forwardable,
    kim_default_proxiable,
    kim_default_addressless,
    NULL };

/* ------------------------------------------------------------------------ */

static inline kim_error_t kim_options_allocate (kim_options_t *out_options)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_options_t options = NULL;
    
    if (!err && !out_options) { err = param_error (1, "out_options", "NULL"); }
    
    if (!err) {
        options = malloc (sizeof (*options));
        if (!options) { err = os_error (errno); }
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

kim_error_t kim_options_create_from_defaults (kim_options_t *out_options)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_options_t options = NULL;
    
    if (!err && !out_options) { err = param_error (1, "out_options", "NULL"); }
    
    if (!err) {
        err = kim_options_allocate (&options);
    }
        
    if (!err) {
        *out_options = options;
        options = NULL;
    }
    
    kim_options_free (&options);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_create (kim_options_t *out_options)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_preferences_t preferences = NULL;
    
    if (!err && !out_options) { err = param_error (1, "out_options", "NULL"); }
    
    if (!err) {
        err = kim_preferences_create (&preferences);
    }
    
    if (!err) {
        err = kim_preferences_get_options (preferences, out_options);
    }
    
    kim_preferences_free (&preferences);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_copy (kim_options_t *out_options,
                              kim_options_t  in_options)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_options_t options = NULL;
    
    if (!err && !out_options) { err = param_error (1, "out_options", "NULL"); }
    if (!err && !in_options ) { err = param_error (2, "in_options", "NULL"); }

    if (!err) {
        err = kim_options_allocate (&options);
    }
    
    if (!err) {
        options->prompt_callback = in_options->prompt_callback;
        options->prompt_callback_data = in_options->prompt_callback_data;
#warning copy prompt responses here
    }
    
    if (!err) {
        options->start_time = in_options->start_time;
        options->lifetime = in_options->lifetime;
        options->renewable = in_options->renewable;
        options->renewal_lifetime = in_options->renewal_lifetime;
        options->forwardable = in_options->forwardable;
        options->proxiable = in_options->proxiable;
        options->addressless = in_options->addressless;
        
        if (in_options->service_name) {
            err = kim_string_copy (&options->service_name, in_options->service_name);
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

kim_error_t kim_options_set_prompt_callback (kim_options_t         io_options,
                                             kim_prompt_callback_t in_prompt_callback)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->prompt_callback = in_prompt_callback;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_prompt_callback (kim_options_t          in_options,
                                             kim_prompt_callback_t *out_prompt_callback)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options         ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_prompt_callback) { err = param_error (2, "out_prompt_callback", "NULL"); }
    
    if (!err) {
        *out_prompt_callback = in_options->prompt_callback;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_data (kim_options_t  io_options,
                                  const void    *in_data)

{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->prompt_callback_data = in_data;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_data (kim_options_t   in_options,
                                  const void    **out_data)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_data  ) { err = param_error (2, "out_data", "NULL"); }
    
    if (!err) {
        *out_data = in_options->prompt_callback_data;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_prompt_response (kim_options_t     io_options,
                                             kim_prompt_type_t in_prompt_type,
                                             void             *in_response)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options ) { err = param_error (1, "io_options", "NULL"); }
    if (!err && !in_response) { err = param_error (2, "in_response", "NULL"); }
    
    if (!err) {
#warning kim_options_set_prompt_response unimplemented
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_prompt_response (kim_options_t       in_options,
                                             kim_prompt_type_t   in_prompt_type,
                                             void              **out_response)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options  ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_response) { err = param_error (2, "out_response", "NULL"); }
    
    if (!err) {
#warning kim_options_get_prompt_response unimplemented
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_start_time (kim_options_t io_options,
                                        kim_time_t    in_start_time)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->start_time = in_start_time;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_start_time (kim_options_t  in_options,
                                        kim_time_t    *out_start_time)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options    ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_start_time) { err = param_error (2, "out_start_time", "NULL"); }
    
    if (!err) {
        *out_start_time = in_options->start_time;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_lifetime (kim_options_t  io_options,
                                      kim_lifetime_t in_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->lifetime = in_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_lifetime (kim_options_t   in_options,
                                      kim_lifetime_t *out_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options  ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_lifetime) { err = param_error (2, "out_lifetime", "NULL"); }
    
    if (!err) {
        *out_lifetime = in_options->lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_renewable (kim_options_t io_options,
                                       kim_boolean_t in_renewable)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->renewable = in_renewable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_renewable (kim_options_t  in_options,
                                       kim_boolean_t *out_renewable)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options   ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_renewable) { err = param_error (2, "out_renewable", "NULL"); }
    
    if (!err) {
        *out_renewable = in_options->renewable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_renewal_lifetime (kim_options_t  io_options,
                                              kim_lifetime_t in_renewal_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->renewal_lifetime = in_renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_renewal_lifetime (kim_options_t   in_options,
                                              kim_lifetime_t *out_renewal_lifetime)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options          ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_renewal_lifetime) { err = param_error (2, "out_renewal_lifetime", "NULL"); }
    
    if (!err) {
        *out_renewal_lifetime = in_options->renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_forwardable (kim_options_t io_options,
                                         kim_boolean_t in_forwardable)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->forwardable = in_forwardable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_forwardable (kim_options_t  in_options,
                                         kim_boolean_t *out_forwardable)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options     ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_forwardable) { err = param_error (2, "out_forwardable", "NULL"); }
    
    if (!err) {
        *out_forwardable = in_options->forwardable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_proxiable (kim_options_t io_options,
                                       kim_boolean_t in_proxiable)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->proxiable = in_proxiable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_proxiable (kim_options_t  in_options,
                                       kim_boolean_t *out_proxiable)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options   ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_proxiable) { err = param_error (2, "out_proxiable", "NULL"); }
    
    if (!err) {
        *out_proxiable = in_options->proxiable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_addressless (kim_options_t io_options,
                                         kim_boolean_t in_addressless)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    
    if (!err) {
        io_options->addressless = in_addressless;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_addressless (kim_options_t  in_options,
                                         kim_boolean_t *out_addressless)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options     ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_addressless) { err = param_error (2, "out_addressless", "NULL"); }
    
    if (!err) {
        *out_addressless = in_options->addressless;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_set_service_name (kim_options_t  io_options,
					  kim_string_t   in_service_name)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_string_t service_name = NULL;
    
    if (!err && !io_options     ) { err = param_error (1, "io_options", "NULL"); }
    if (!err && !in_service_name) { err = param_error (2, "in_service_name", "NULL"); }
    
    if (!err) {
        err = kim_string_copy (&service_name, in_service_name);
    }
    
    if (!err) {
	kim_string_free (&io_options->service_name);
	io_options->service_name = service_name;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_service_name (kim_options_t  in_options,
					  kim_string_t  *out_service_name)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_options      ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !out_service_name) { err = param_error (2, "out_service_name", "NULL"); }
    
    if (!err) {
        err = kim_string_copy (out_service_name, in_options->service_name);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_get_init_cred_options (kim_options_t              in_options, 
                                               krb5_context               in_context,
					       krb5_get_init_creds_opt  **out_init_cred_options)
{
    kim_error_t err = KIM_NO_ERROR;
    krb5_get_init_creds_opt *init_cred_options;
    krb5_address **addresses = NULL;
    
    if (!err && !in_options           ) { err = param_error (1, "in_options", "NULL"); }
    if (!err && !in_context           ) { err = param_error (2, "in_context", "NULL"); }
    if (!err && !out_init_cred_options) { err = param_error (3, "out_init_cred_options", "NULL"); }
    
    if (!err && !in_options->addressless) {
        err = krb5_error (krb5_os_localaddr (in_context, &addresses));
    }

    if (!err) {
        krb5_get_init_creds_opt_alloc (in_context, &init_cred_options);
        krb5_get_init_creds_opt_set_tkt_life (init_cred_options, in_options->lifetime);
        krb5_get_init_creds_opt_set_renew_life (init_cred_options, in_options->renewable ? in_options->renewal_lifetime : 0);
        krb5_get_init_creds_opt_set_forwardable (init_cred_options, in_options->forwardable);
        krb5_get_init_creds_opt_set_proxiable (init_cred_options, in_options->proxiable);
        krb5_get_init_creds_opt_set_address_list (init_cred_options, addresses);

	*out_init_cred_options = init_cred_options;
	init_cred_options = NULL;
	addresses = NULL;
    }
    
    if (init_cred_options) { krb5_get_init_creds_opt_free (in_context, init_cred_options); }
    if (addresses        ) { krb5_free_addresses (in_context, addresses); }
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error_t kim_options_free_init_cred_options (krb5_context               in_context,
                                                krb5_get_init_creds_opt  **io_init_cred_options)
{
    kim_error_t err = KIM_NO_ERROR;
    
    if (!err && !in_context) { err = param_error (1, "in_context", "NULL"); }
    
    if (!err && io_init_cred_options && *io_init_cred_options) {
	if ((*io_init_cred_options)->address_list) {
	    krb5_free_addresses (in_context, (*io_init_cred_options)->address_list);
	}
	krb5_get_init_creds_opt_free (in_context, *io_init_cred_options);
	*io_init_cred_options = NULL;
    }
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

void kim_options_free (kim_options_t *io_options)
{
    if (io_options && *io_options) { 
        kim_string_free (&(*io_options)->service_name); 
        free (*io_options);
        *io_options = NULL;
    }
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error_code_t kim_prompt_callback_default (kim_options_t       *io_options, 
                                              kim_prompt_type_t    in_type,
                                              kim_string_t         in_title,
                                              kim_string_t         in_message,
                                              kim_string_t         in_description,
                                              void               **out_reply)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_error_code_t code = KIM_NO_ERROR_ECODE;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    if (!err && !out_reply ) { err = param_error (6, "out_reply", "NULL"); }
    
    if (!err) {
    }
    
    code = kim_error_get_code (check_error (err));
    kim_error_free (&err);
    return code;
}

/* ------------------------------------------------------------------------ */

kim_error_code_t kim_prompt_callback_gui (kim_options_t       *io_options, 
                                          kim_prompt_type_t    in_type,
                                          kim_string_t         in_title,
                                          kim_string_t         in_message,
                                          kim_string_t         in_description,
                                          void               **out_reply)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_error_code_t code = KIM_NO_ERROR_ECODE;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    if (!err && !out_reply ) { err = param_error (6, "out_reply", "NULL"); }
    
    if (!err) {
    }
    
    code = kim_error_get_code (check_error (err));
    kim_error_free (&err);
    return code;
}

/* ------------------------------------------------------------------------ */

kim_error_code_t kim_prompt_callback_cli (kim_options_t       *io_options, 
                                          kim_prompt_type_t    in_type,
                                          kim_string_t         in_title,
                                          kim_string_t         in_message,
                                          kim_string_t         in_description,
                                          void               **out_reply)
{
    kim_error_t err = KIM_NO_ERROR;
    kim_error_code_t code = KIM_NO_ERROR_ECODE;
    
    if (!err && !io_options) { err = param_error (1, "io_options", "NULL"); }
    if (!err && !out_reply ) { err = param_error (6, "out_reply", "NULL"); }
    
    if (!err) {
    }
    
    code = kim_error_get_code (check_error (err));
    kim_error_free (&err);
    return code;
}

/* ------------------------------------------------------------------------ */

kim_error_code_t kim_prompt_callback_none (kim_options_t       *io_options, 
                                           kim_prompt_type_t    in_type,
                                           kim_string_t         in_title,
                                           kim_string_t         in_message,
                                           kim_string_t         in_description,
                                           void               **out_reply)
{
    return KIM_USER_CANCELED_ECODE;
}

/*
 * $Header$
 *
 * Copyright 2008 Massachusetts Institute of Technology.
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

#ifndef LEAN_CLIENT

#include "kim_os_private.h"
#include "kim_mig_types.h"
#include "kim_mig.h"

#define kKerberosAgentBundleID "edu.mit.Kerberos.KerberosAgent"
#define kKerberosAgentPath "/System/Library/CoreServices/KerberosAgent.app/Contents/MacOS/KerberosAgent"

#include <Kerberos/kipc_client.h>
#include <mach/mach.h>
#include <mach/mach_error.h>

struct kim_ui_gui_context {
    mach_port_t port;
};

/* ------------------------------------------------------------------------ */

static void kim_os_ui_gui_context_free (kim_ui_gui_context *io_context)
{
    if (io_context && *io_context) { 
        free (*io_context);
        *io_context = NULL;
    }
}

/* ------------------------------------------------------------------------ */

static kim_error kim_os_ui_gui_context_allocate (kim_ui_gui_context *out_context)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_gui_context context = NULL;
    
    if (!err && !out_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        context = malloc (sizeof (*context));
        if (!context) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        context->port = MACH_PORT_NULL;
        
        *out_context = context;
        context = NULL;
    }
    
    kim_os_ui_gui_context_free (&context);
    
    return check_error (err);    
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_init (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_gui_context context = NULL;
    kim_string name = NULL;
    kim_string path = NULL;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_os_ui_gui_context_allocate (&context);
    }
    
    if (!err) {
        err = kim_library_get_application_name (&name);
    }
    
    if (!err) {
        err = kim_os_library_get_application_path (&path);
    }

    if (!err) {
        err = kipc_client_lookup_server (kim_os_agent_bundle_id, 
                                         1 /* launch */, 
                                         0 /* don't use cached port */, 
                                         &context->port);
    }
    
    if (!err) {
        kim_mipc_error result = 0;
        
        err = kim_mipc_cli_init (context->port,
                                 mach_task_self (),
                                 name, kim_string_buflen (name),
                                 path, kim_string_buflen (path),
                                 &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        io_context->tcontext = context;
        context = NULL;
    }
    
    kim_string_free (&name);
    kim_string_free (&path);
    kim_os_ui_gui_context_free (&context);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_enter_identity (kim_ui_context *in_context,
                                        kim_identity   *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_mipc_out_string identity = NULL;
    mach_msg_type_number_t identity_len = 0;
    
    if (!err && !in_context  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_gui_context context = (kim_ui_gui_context) in_context->tcontext;
        kim_mipc_error result = 0;

        err = kim_mipc_cli_enter_identity (context->port,
                                           &identity,
                                           &identity_len,
                                           &result);        
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err = kim_identity_create_from_string (out_identity, identity);
    }
    
    if (identity) { vm_deallocate (mach_task_self (), 
                                   (vm_address_t) identity, identity_len); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_select_identity (kim_ui_context      *in_context,
                                         kim_selection_hints  in_hints,
                                         kim_identity        *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;
    kim_time start_time = 0;
    kim_lifetime lifetime;
    kim_boolean renewable;
    kim_lifetime renewal_lifetime;
    kim_boolean forwardable;
    kim_boolean proxiable;
    kim_boolean addressless;
    kim_string service_name = NULL;
    kim_string application_id = NULL;
    kim_string explanation = NULL;
    kim_string service_identity_hint = NULL;
    kim_string client_realm_hint = NULL;
    kim_string user_hint = NULL;
    kim_string service_realm_hint = NULL;
    kim_string service_hint = NULL;
    kim_string server_hint = NULL;
    kim_mipc_out_string identity = NULL;
    mach_msg_type_number_t identity_len = 0;    
   
    if (!err && !in_context  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_hints    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_selection_hints_get_options (in_hints, &options);
        
        if (!err && !options) {
            err = kim_options_create (&options);
        }
    }
    
    if (!err) {
        err = kim_options_get_start_time (options, &start_time);
    }
    
    if (!err) {
        err = kim_options_get_lifetime (options, &lifetime);
    }
    
    if (!err) {
        err = kim_options_get_renewable (options, &renewable);
    }
    
    if (!err) {
        err = kim_options_get_renewal_lifetime (options, &renewal_lifetime);
    }
    
    if (!err) {
        err = kim_options_get_forwardable (options, &forwardable);
    }
    
    if (!err) {
        err = kim_options_get_proxiable (options, &proxiable);
    }
    
    if (!err) {
        err = kim_options_get_addressless (options, &addressless);
    }
    
    if (!err) {
        err = kim_options_get_service_name (options, &service_name);
    }
    
    if (!err) {
        err = kim_selection_hints_get_explanation (in_hints, &explanation);
    }

    if (!err) {
        err = kim_selection_hints_get_application_id (in_hints, &application_id);
    }
    
    if (!err) {
        err = kim_selection_hints_get_hint (in_hints, 
                                            kim_hint_key_service_identity,
                                            &service_identity_hint);
    }
    
    if (!err) {
        err = kim_selection_hints_get_hint (in_hints, 
                                            kim_hint_key_client_realm,
                                            &client_realm_hint);
    }
    
    if (!err) {
        err = kim_selection_hints_get_hint (in_hints, 
                                            kim_hint_key_user,
                                            &user_hint);
    }
    
    if (!err) {
        err = kim_selection_hints_get_hint (in_hints, 
                                            kim_hint_key_service_realm,
                                            &service_realm_hint);
    }
    
    if (!err) {
        err = kim_selection_hints_get_hint (in_hints, 
                                            kim_hint_key_service,
                                            &service_hint);
    }
    
    if (!err) {
        err = kim_selection_hints_get_hint (in_hints, 
                                            kim_hint_key_server,
                                            &server_hint);
    }
    
    if (!err) {
        kim_ui_gui_context context = (kim_ui_gui_context) in_context->tcontext;
        kim_mipc_error result = 0;
        
        err = kim_mipc_cli_select_identity (context->port,
                                            application_id,
                                            kim_string_buflen (application_id),
                                            explanation,
                                            kim_string_buflen (explanation),
                                            
                                            start_time,
                                            lifetime,
                                            renewable,
                                            renewal_lifetime,
                                            forwardable,
                                            proxiable,
                                            addressless,
                                            service_name, 
                                            kim_string_buflen (service_name),
                                            
                                            service_identity_hint, 
                                            kim_string_buflen (service_identity_hint),
                                            
                                            client_realm_hint, 
                                            kim_string_buflen (client_realm_hint),
                                            
                                            user_hint, 
                                            kim_string_buflen (user_hint),
                                            
                                            service_realm_hint, 
                                            kim_string_buflen (service_realm_hint),
                                           
                                            service_hint, 
                                            kim_string_buflen (service_hint),
                                            
                                            server_hint, 
                                            kim_string_buflen (server_hint),
                                            
                                            &identity,
                                            &identity_len,
                                            &result);        
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err = kim_identity_create_from_string (out_identity, identity);
    }
    
    if (identity) { vm_deallocate (mach_task_self (), 
                                   (vm_address_t) identity, identity_len); }
    
    kim_string_free (&application_id);
    kim_string_free (&explanation);
    kim_string_free (&service_name);
    kim_string_free (&service_identity_hint);
    kim_string_free (&client_realm_hint);
    kim_string_free (&user_hint);
    kim_string_free (&service_realm_hint);
    kim_string_free (&service_hint);
    kim_string_free (&server_hint);
    kim_options_free (&options);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_auth_prompt (kim_ui_context     *in_context,
                                     kim_identity        in_identity,
                                     kim_prompt_type     in_type,
                                     kim_boolean         in_hide_reply, 
                                     kim_string          in_title,
                                     kim_string          in_message,
                                     kim_string          in_description,
                                     char              **out_reply)
{
    kim_error err = KIM_NO_ERROR;
    kim_string identity_string = NULL;
    kim_mipc_out_string reply = NULL;
    mach_msg_type_number_t reply_len = 0;    
    
    if (!err && !in_context ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_reply  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_title, in_message or in_description may be NULL */
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        kim_ui_gui_context context = (kim_ui_gui_context) in_context->tcontext;
        kim_mipc_error result = 0;

        err = kim_mipc_cli_auth_prompt (context->port,
                                        identity_string, 
                                        kim_string_buflen (identity_string),
                                        in_type,
                                        in_hide_reply,
                                        in_title, 
                                        kim_string_buflen (in_title),
                                        in_message, 
                                        kim_string_buflen (in_message),
                                        in_description, 
                                        kim_string_buflen (in_description),
                                        &reply,
                                        &reply_len,
                                        &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err = kim_string_copy ((kim_string *) out_reply, reply);
    }
    
    if (reply) { vm_deallocate (mach_task_self (), (vm_address_t) reply, reply_len); }
    kim_string_free (&identity_string);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_change_password (kim_ui_context      *in_context,
                                         kim_identity         in_identity,
                                         kim_boolean          in_old_password_expired,
                                         char               **out_old_password,
                                         char               **out_new_password,
                                         char               **out_verify_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_string identity_string = NULL;
    
    kim_mipc_out_string old_password_buf = NULL;
    mach_msg_type_number_t old_password_len = 0;    
    kim_mipc_out_string new_password_buf = NULL;
    mach_msg_type_number_t new_password_len = 0;    
    kim_mipc_out_string verify_password_buf = NULL;
    mach_msg_type_number_t verify_password_len = 0;  
    
    kim_string old_password = NULL;
    kim_string new_password = NULL;
    kim_string verify_password = NULL;
   
    if (!err && !in_context         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_old_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_new_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_verify_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        kim_ui_gui_context context = (kim_ui_gui_context) in_context->tcontext;
        kim_mipc_error result = 0;
        
        err = kim_mipc_cli_change_password (context->port,
                                            identity_string, 
                                            kim_string_buflen (identity_string),
                                            in_old_password_expired,
                                            &old_password_buf,
                                            &old_password_len,
                                            &new_password_buf,
                                            &new_password_len,
                                            &verify_password_buf,
                                            &verify_password_len,
                                            &result);
        if (!err) { err = check_error (result); }        
    }
    
    if (!err) {
        err = kim_string_copy (&old_password, old_password_buf);
    }
    
    if (!err) {
        err = kim_string_copy (&new_password, new_password_buf);
    }
    
    if (!err) {
        err = kim_string_copy (&verify_password, verify_password_buf);
    }
    
    if (!err) {
        *out_old_password = (char *) old_password;
        old_password = NULL;
        *out_new_password = (char *) new_password;
        new_password = NULL;
        *out_verify_password = (char *) verify_password;
        verify_password = NULL;
    }
    
    if (old_password_buf) { vm_deallocate (mach_task_self (), 
                                           (vm_address_t) old_password_buf, 
                                           old_password_len); }
    if (new_password_buf) { vm_deallocate (mach_task_self (), 
                                           (vm_address_t) new_password_buf, 
                                           new_password_len); }
    if (verify_password_buf) { vm_deallocate (mach_task_self (), 
                                              (vm_address_t) verify_password_buf, 
                                              verify_password_len); }
    kim_string_free (&identity_string);    
    kim_string_free (&old_password);    
    kim_string_free (&new_password);    
    kim_string_free (&verify_password);    
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_handle_error (kim_ui_context    *in_context,
                                      kim_identity       in_identity,
                                      kim_error          in_error,
                                      kim_string         in_error_message,
                                      kim_string         in_error_description)
{
    kim_error err = KIM_NO_ERROR;
    kim_string identity_string = NULL;
    
    if (!err && !in_context          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_message    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_description) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        kim_ui_gui_context context = (kim_ui_gui_context) in_context->tcontext;
        kim_mipc_error result = 0;
        
        err = kim_mipc_cli_handle_error (context->port,
                                         identity_string, 
                                         kim_string_buflen (identity_string),
                                         in_error,
                                         in_error_message, 
                                         kim_string_buflen (in_error_message),
                                         in_error_description, 
                                         kim_string_buflen (in_error_description),
                                         &result);
        if (!err) { err = check_error (result); }        
    }
    
    kim_string_free (&identity_string);    

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_os_ui_gui_free_string (kim_ui_context      *in_context,
                                char               **io_string)
{
    kim_string_free ((kim_string *) io_string);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_fini (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_ui_gui_context context = (kim_ui_gui_context) io_context->tcontext;
        kim_mipc_error result = 0;
        
        err = kim_mipc_cli_fini (context->port, &result);
        if (!err) { err = check_error (result); }
        
        
        if (!err) {
            kim_os_ui_gui_context_free (&context);
            io_context->tcontext = NULL;
        }
    }    
    
    return check_error (err);
}

#endif /* LEAN_CLIENT */

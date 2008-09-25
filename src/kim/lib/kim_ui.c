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

#include "kim_private.h"


/* ------------------------------------------------------------------------ */

static kim_prompt_type kim_ui_ptype2ktype (krb5_prompt_type type)
{
    if (type == KRB5_PROMPT_TYPE_PASSWORD) {
        return kim_prompt_type_password;
        
    } else if (type == KRB5_PROMPT_TYPE_PREAUTH) {
        return kim_prompt_type_preauth;
    }
    return kim_prompt_type_preauth;
}


#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_ui_init (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
#ifndef LEAN_CLIENT
        kim_ui_environment environment = kim_library_ui_environment ();
        
        if (environment == KIM_UI_ENVIRONMENT_GUI) {
#endif /* LEAN_CLIENT */
            io_context->type = kim_ui_type_gui_plugin;
            
            err = kim_ui_plugin_init (io_context);
#ifndef LEAN_CLIENT        
            if (err) { 
                io_context->type = kim_ui_type_gui_builtin;
                
                err = kim_os_ui_gui_init (io_context);
            }
            
        } else if (environment == KIM_UI_ENVIRONMENT_CLI) {
            io_context->type = kim_ui_type_cli;
            
            err = kim_ui_cli_init (io_context);  
            
        } else {
            io_context->type = kim_ui_type_none;
            
            err = check_error (KIM_NO_UI_ERR);
        }
#endif /* LEAN_CLIENT */
    }
    
    if (!err) {
        io_context->identity = NULL;
        io_context->prompt_count = 0;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_enter_identity (kim_ui_context      *in_context,
                                 kim_identity        *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (in_context->type == kim_ui_type_gui_plugin) {
            err = kim_ui_plugin_enter_identity (in_context, 
                                                out_identity);
            
#ifndef LEAN_CLIENT
        } else if (in_context->type == kim_ui_type_gui_builtin) {
            err = kim_os_ui_gui_enter_identity (in_context, 
                                                out_identity);
            
        } else if (in_context->type == kim_ui_type_cli) {
            err = kim_ui_cli_enter_identity (in_context, 
                                             out_identity);
            
#endif /* LEAN_CLIENT */
            
        } else {
            err = check_error (KIM_NO_UI_ERR);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_select_identity (kim_ui_context      *in_context,
                                  kim_selection_hints  in_hints,
                                  kim_identity        *out_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_hints    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (in_context->type == kim_ui_type_gui_plugin) {
            err = kim_ui_plugin_select_identity (in_context, 
                                                 in_hints,
                                                 out_identity);
            
#ifndef LEAN_CLIENT
        } else if (in_context->type == kim_ui_type_gui_builtin) {
            err = kim_os_ui_gui_select_identity (in_context, 
                                                 in_hints,
                                                 out_identity);
            
        } else if (in_context->type == kim_ui_type_cli) {
            err = kim_ui_cli_select_identity (in_context, 
                                              in_hints,
                                              out_identity);
            
#endif /* LEAN_CLIENT */
            
        } else {
            err = check_error (KIM_NO_UI_ERR);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */
/* Set the identity field in your context and pass the context as the data */

krb5_error_code kim_ui_prompter (krb5_context  in_krb5_context,
                                 void         *in_context,
                                 const char   *in_name,
                                 const char   *in_banner,
                                 int           in_num_prompts,
                                 krb5_prompt   in_prompts[])
{
    kim_error err = KIM_NO_ERROR;
    krb5_prompt_type *types = NULL;
    kim_ui_context *context = (kim_ui_context *) in_context;
    int i;
    
    if (!err && !in_krb5_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_context     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_prompts     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        types = krb5_get_prompt_types (in_krb5_context);
        if (!types) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    }
    
    for (i = 0; !err && i < in_num_prompts; i++) {
        char *reply = NULL;
        kim_prompt_type type = kim_ui_ptype2ktype (types[i]);
        kim_boolean got_saved_password = 0;
                
        if (type == kim_prompt_type_password) {
            /* Check for saved password on OSes that support it */
            kim_error terr = KIM_NO_ERROR;
            
            terr = kim_os_identity_get_saved_password (context->identity, 
                                                       (kim_string *) &reply);
            if (!terr) { got_saved_password = 1; }
        }
        
        if (!got_saved_password) {
            context->prompt_count++;
            
            if (context->type == kim_ui_type_gui_plugin) {
                err = kim_ui_plugin_auth_prompt (context, 
                                                 context->identity, 
                                                 type,
                                                 in_prompts[i].hidden,
                                                 in_name,
                                                 in_banner,
                                                 in_prompts[i].prompt,
                                                 &reply);
                
#ifndef LEAN_CLIENT
            } else if (context->type == kim_ui_type_gui_builtin) {
                err = kim_os_ui_gui_auth_prompt (context, 
                                                 context->identity, 
                                                 type,
                                                 in_prompts[i].hidden,
                                                 in_name,
                                                 in_banner,
                                                 in_prompts[i].prompt,
                                                 &reply);
                
            } else if (context->type == kim_ui_type_cli) {
                err = kim_ui_cli_auth_prompt (context, 
                                              context->identity, 
                                              type,
                                              in_prompts[i].hidden,
                                              in_name,
                                              in_banner,
                                              in_prompts[i].prompt,
                                              &reply);
#endif /* LEAN_CLIENT */
                
            } else {
                err = check_error (KIM_NO_UI_ERR);
            }
        }

        if (!err) {
            uint32_t reply_len = strlen (reply);
            
            if ((reply_len + 1) > in_prompts[i].reply->length) {
                kim_debug_printf ("%s(): reply %d is too long (is %d, should be %d)\n",
                                  __FUNCTION__, i, 
                                  reply_len, in_prompts[i].reply->length);
                reply_len = in_prompts[i].reply->length;
            }
            
            memmove (in_prompts[i].reply->data, reply, reply_len + 1);
            in_prompts[i].reply->length = reply_len;
        }
        
        /* Clean up reply buffer.  Saved passwords are allocated by KIM. */
        if (reply) {
            memset (reply, '\0', strlen (reply));
            if (got_saved_password) {
                kim_string_free ((kim_string *) &reply);
             } else {
                kim_ui_free_string (context, &reply);
            }
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_change_password (kim_ui_context  *in_context,
                                  kim_identity     in_identity,
                                  kim_boolean      in_old_password_expired,
                                  char           **out_old_password,
                                  char           **out_new_password,
                                  char           **out_verify_password)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_identity        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_old_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_new_password   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_verify_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (in_context->type == kim_ui_type_gui_plugin) {
            err = kim_ui_plugin_change_password (in_context, 
                                                 in_identity, 
                                                 in_old_password_expired,
                                                 out_old_password,
                                                 out_new_password,
                                                 out_verify_password);
            
#ifndef LEAN_CLIENT
        } else if (in_context->type == kim_ui_type_gui_builtin) {
            err = kim_os_ui_gui_change_password (in_context, 
                                                 in_identity, 
                                                 in_old_password_expired,
                                                 out_old_password,
                                                 out_new_password,
                                                 out_verify_password);
            
        } else if (in_context->type == kim_ui_type_cli) {
            err = kim_ui_cli_change_password (in_context,
                                              in_identity, 
                                              in_old_password_expired,
                                              out_old_password,
                                              out_new_password,
                                              out_verify_password);
#endif /* LEAN_CLIENT */
            
        } else {
            err = check_error (KIM_NO_UI_ERR);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */
/* Helper function */

kim_error kim_ui_handle_kim_error (kim_ui_context         *in_context,
                                   kim_identity            in_identity,
                                   enum kim_ui_error_type  in_type,
                                   kim_error               in_error)
{
    kim_error err = KIM_NO_ERROR;
    kim_string message = NULL;
    kim_string description = NULL;
    
    if (!err) {
        /* Do this first so last error doesn't get overwritten */
        err = kim_string_create_for_last_error (&description, in_error);
    }
    
    if (!err && !in_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_string key = NULL;
        
        switch (in_type) {
            case kim_ui_error_type_authentication:
                key = "KLStringLoginFailed";
                break;
                
            case kim_ui_error_type_change_password:
                key = "KLStringChangePasswordFailed";
                break;
                
            case kim_ui_error_type_selection:
            case kim_ui_error_type_generic:
            default:
                key = "KLStringKerberosOperationFailed";
                break;
        }
        
        err = kim_os_string_create_localized (&message, key);
    }
    
    if (!err) {
        err = kim_ui_handle_error (in_context, in_identity,
                                   in_error, message, description);        
    }
    
    kim_string_free (&description);
    kim_string_free (&message);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_handle_error (kim_ui_context *in_context,
                               kim_identity    in_identity,
                               kim_error       in_error,
                               kim_string      in_error_message,
                               kim_string      in_error_description)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_message    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_description) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (in_context->type == kim_ui_type_gui_plugin) {
            err = kim_ui_plugin_handle_error (in_context, 
                                              in_identity, 
                                              in_error,
                                              in_error_message,
                                              in_error_description);
            
#ifndef LEAN_CLIENT
        } else if (in_context->type == kim_ui_type_gui_builtin) {
            err = kim_os_ui_gui_handle_error (in_context, 
                                              in_identity, 
                                              in_error,
                                              in_error_message,
                                              in_error_description);
            
        } else if (in_context->type == kim_ui_type_cli) {
            err = kim_ui_cli_handle_error (in_context, 
                                           in_identity, 
                                           in_error,
                                           in_error_message,
                                           in_error_description);
#endif /* LEAN_CLIENT */  
            
        } else {
            err = check_error (KIM_NO_UI_ERR);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_ui_free_string (kim_ui_context  *in_context,
                         char           **io_string)
{
    if (in_context && io_string && *io_string) {
        if (in_context->type == kim_ui_type_gui_plugin) {
            kim_ui_plugin_free_string (in_context, 
                                       io_string);
            
#ifndef LEAN_CLIENT
        } else if (in_context->type == kim_ui_type_gui_builtin) {
            kim_os_ui_gui_free_string (in_context, 
                                       io_string);
            
        } else if (in_context->type == kim_ui_type_cli) {
            kim_ui_cli_free_string (in_context, 
                                    io_string);
#endif /* LEAN_CLIENT */    
            
        }
    }
}

/* ------------------------------------------------------------------------ */

kim_error kim_ui_fini (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (io_context->type == kim_ui_type_gui_plugin) {
            err = kim_ui_plugin_fini (io_context);
            
#ifndef LEAN_CLIENT
        } else if (io_context->type == kim_ui_type_gui_builtin) {
            err = kim_os_ui_gui_fini (io_context);
            
        } else if (io_context->type == kim_ui_type_cli) {
            err = kim_ui_cli_fini (io_context);
#endif /* LEAN_CLIENT */
            
        } else {
            err = check_error (KIM_NO_UI_ERR);
        }
    }
    
    return check_error (err);
}

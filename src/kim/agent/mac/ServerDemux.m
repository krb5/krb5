/*
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

#import "kim_migServer.h"
#import "ServerThread.h"

// ---------------------------------------------------------------------------

static kim_boolean caller_is_front_process (task_t    in_task, 
                                            NSString *in_path)
{
    kim_error err = KIM_NO_ERROR;
    Boolean is_front_process;
    pid_t task_pid;
    ProcessSerialNumber task_psn, front_psn;
    
    NSBundle *bundle = [NSBundle bundleWithPath: in_path];
    if (bundle) {
        NSString *identifier = [bundle bundleIdentifier];
        if (identifier && 
            ([identifier compare: @"edu.mit.Kerberos.KerberosMenu"] == NSOrderedSame ||
             [identifier compare: @"com.apple.systemuiserver"]      == NSOrderedSame)) {
            return TRUE;
        }
    }
    
    if (!err) {
        err = pid_for_task (in_task, &task_pid);
    }
    
    if (!err) {
        err = GetProcessForPID (task_pid, &task_psn);
    }
    
    if (!err) {
        err = GetFrontProcess (&front_psn);
    }
    
    if (!err) {
        err = SameProcess (&task_psn, &front_psn, &is_front_process);
    }
    
    return !err ? is_front_process : FALSE;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_init (mach_port_t             in_server_port,
                                 task_t                  in_application_task,
                                 kim_mipc_in_string      in_application_name,
                                 mach_msg_type_number_t  in_application_nameCnt,
                                 kim_mipc_in_string      in_application_path,
                                 mach_msg_type_number_t  in_application_pathCnt,
                                 kim_mipc_error         *out_error)
{
    kern_return_t err = 0;
    ServerThread *sthread = NULL;
    
    if (!err) {
        sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        kim_mipc_error result = KIM_NO_ERROR;
        NSString *name = NULL;
        NSString *path = NULL;

        if (in_application_name) {
            name = [NSString stringWithUTF8String: in_application_name];
        }

        if (in_application_path) {
            path = [NSString stringWithUTF8String: in_application_path];
        }
        
        [sthread addConnectionWithPort: in_server_port
                                  name: name
                                  path: path
                          frontProcess: caller_is_front_process (in_application_task, 
                                                                 path)];
        *out_error = result;
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_enter_identity (mach_port_t             in_server_port,
                                           kim_mipc_out_string    *out_identity,
                                           mach_msg_type_number_t *out_identityCnt,
                                           kim_mipc_error         *out_error)
{
    kern_return_t err = 0;
    kim_error result = KIM_NO_ERROR;
    ClientConnection *client = NULL;
    kim_identity identity = NULL;
    kim_string identity_string = NULL;
    mach_msg_type_number_t identity_len = 0;
    kim_mipc_out_string identity_buf = NULL;
    
    if (!err) {
        ServerThread *sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }

        if (!err) {
            client = [sthread connectionForPort: in_server_port];
            if (!client) { err = KIM_OUT_OF_MEMORY_ERR; }
        }
    }
    
    if (!err) {
        identity = [client enterIdentityWithError: &result];
    }
    
    if (!err && !result) {
        err = kim_identity_get_string (identity, &identity_string);
    }
    
    if (!err && !result && identity_string) {
        identity_len = strlen (identity_string) + 1;
        err = vm_allocate (mach_task_self (), 
                           (vm_address_t *) &identity_buf, identity_len, TRUE);
        
    }
    
    if (!err && !result) {
        memmove (identity_buf, identity_string, identity_len);
        *out_identity = identity_buf;
        *out_identityCnt = identity_len;
        identity_buf = NULL;
    }
    
    if (!err) {
        *out_error = result;
    }
    
    if (identity_buf) { vm_deallocate (mach_task_self (), (vm_address_t) identity_buf, identity_len); }
    kim_string_free (&identity_string);
    kim_identity_free (&identity);
    
    return err;
}

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_select_identity (mach_port_t             in_server_port,
                                            kim_mipc_in_string      in_application_id,
                                            mach_msg_type_number_t  in_application_idCnt,
                                            kim_mipc_in_string      in_explanation,
                                            mach_msg_type_number_t  in_explanationCnt,
                                            kim_mipc_time           in_start_time,
                                            kim_mipc_lifetime       in_lifetime,
                                            kim_mipc_boolean        in_renewable,
                                            kim_mipc_lifetime       in_renewal_lifetime,
                                            kim_mipc_boolean        in_forwardable,
                                            kim_mipc_boolean        in_proxiable,
                                            kim_mipc_boolean        in_addressless,
                                            kim_mipc_in_string      in_service_name,
                                            mach_msg_type_number_t  in_service_nameCnt,
                                            kim_mipc_in_string      in_service_identity_hint,
                                            mach_msg_type_number_t  in_service_identity_hintCnt,
                                            kim_mipc_in_string      in_client_realm_hint,
                                            mach_msg_type_number_t  in_client_realm_hintCnt,
                                            kim_mipc_in_string      in_user_hint,
                                            mach_msg_type_number_t  in_user_hintCnt,
                                            kim_mipc_in_string      in_service_realm_hint,
                                            mach_msg_type_number_t  in_service_realm_hintCnt,
                                            kim_mipc_in_string      in_service_hint,
                                            mach_msg_type_number_t  in_service_hintCnt,
                                            kim_mipc_in_string      in_server_hint,
                                            mach_msg_type_number_t  in_server_hintCnt,
                                            kim_mipc_out_string    *out_identity,
                                            mach_msg_type_number_t *out_identityCnt,
                                            kim_mipc_error         *out_error)
{
    kern_return_t err = 0;
    kim_error result = KIM_NO_ERROR;
    ClientConnection *client = NULL;
    kim_selection_hints hints = NULL;
    kim_identity identity = NULL;
    kim_string identity_string = NULL;
    mach_msg_type_number_t identity_len = 0;
    kim_mipc_out_string identity_buf = NULL;
    
    if (!err) {
        err = kim_selection_hints_create (&hints, in_application_id);
    }
    
    if (!err) {
        kim_options options = NULL;
        
        err = kim_options_create (&options);
        
        if (!err) {
            err = kim_options_set_start_time (options, in_start_time);
        }
        
        if (!err) {
            err = kim_options_set_lifetime (options, in_lifetime);
        }
        
        if (!err) {
            err = kim_options_set_renewable (options, in_renewable);
        }
        
        if (!err) {
            err = kim_options_set_renewal_lifetime (options, in_renewal_lifetime);
        }
        
        if (!err) {
            err = kim_options_set_forwardable (options, in_forwardable);
        }
        
        if (!err) {
            err = kim_options_set_proxiable (options, in_proxiable);
        }
        
        if (!err) {
            err = kim_options_set_addressless (options, in_addressless);
        }
        
        if (!err) {
            err = kim_options_set_service_name (options, in_service_name);
        }
        
        if (!err) {
            err = kim_selection_hints_set_options (hints, options);
        }
        
        kim_options_free (&options);
    }
    
    if (!err) {
        err = kim_selection_hints_set_explanation (hints, in_explanation);
    }
    
    if (!err && in_service_identity_hint) {
        err = kim_selection_hints_set_hint (hints, 
                                            kim_hint_key_service_identity,
                                            in_service_identity_hint);
    }
    
    if (!err && in_client_realm_hint) {
        err = kim_selection_hints_set_hint (hints, 
                                            kim_hint_key_client_realm,
                                            in_client_realm_hint);
    }
    
    if (!err && in_user_hint) {
        err = kim_selection_hints_set_hint (hints, 
                                            kim_hint_key_user,
                                            in_user_hint);
    }
    
    if (!err && in_service_realm_hint) {
        err = kim_selection_hints_set_hint (hints, 
                                            kim_hint_key_service_realm,
                                            in_service_realm_hint);
    }
    
    if (!err && in_service_hint) {
        err = kim_selection_hints_set_hint (hints, 
                                            kim_hint_key_service,
                                            in_service_hint);
    }
    
    if (!err && in_server_hint) {
        err = kim_selection_hints_set_hint (hints, 
                                            kim_hint_key_server,
                                            in_server_hint);
    }
    
    if (!err) {
        ServerThread *sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err) {
            client = [sthread connectionForPort: in_server_port];
            if (!client) { err = KIM_OUT_OF_MEMORY_ERR; }
        }
    }
    
    if (!err) {
        identity = [client selectIdentityWithHints: hints
                                             error: &result];
    }
    
    if (!err && !result) {
        err = kim_identity_get_string (identity, &identity_string);
    }

    if (!err && !result && identity_string) {
        identity_len = strlen (identity_string) + 1;
        err = vm_allocate (mach_task_self (), 
                           (vm_address_t *) &identity_buf, identity_len, TRUE);
    }
    
    if (!err && !result) {
        memmove (identity_buf, identity_string, identity_len);
        *out_identity = identity_buf;
        *out_identityCnt = identity_len;
        identity_buf = NULL;
    }
        
    if (!err) {
        *out_error = result;
    }
    
    if (identity_buf) { vm_deallocate (mach_task_self (), 
                                       (vm_address_t) identity_buf, 
                                       identity_len); }
    kim_string_free (&identity_string);
    kim_identity_free (&identity);
    kim_selection_hints_free (&hints);

    return err;
}

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_auth_prompt (mach_port_t             in_server_port,
                                        kim_mipc_in_string      in_identity,
                                        mach_msg_type_number_t  in_identityCnt,
                                        kim_mipc_prompt_type    in_prompt_type,
                                        kim_mipc_boolean        in_hide_reply,
                                        kim_mipc_in_string      in_title,
                                        mach_msg_type_number_t  in_titleCnt,
                                        kim_mipc_in_string      in_message,
                                        mach_msg_type_number_t  in_messageCnt,
                                        kim_mipc_in_string      in_description,
                                        mach_msg_type_number_t  in_descriptionCnt,
                                        kim_mipc_out_string    *out_response,
                                        mach_msg_type_number_t *out_responseCnt,
                                        kim_mipc_error         *out_error)
{
    kern_return_t err = 0;
    kim_error result = KIM_NO_ERROR;
    ClientConnection *client = NULL;
    kim_identity identity = NULL;
    const char *response_string = NULL;
    mach_msg_type_number_t response_len = 0;
    kim_mipc_out_string response_buf = NULL;
    
    if (!err) {
        ServerThread *sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err) {
            client = [sthread connectionForPort: in_server_port];
            if (!client) { err = KIM_OUT_OF_MEMORY_ERR; }
        }
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity, in_identity);
    }
    
    if (!err) {
        NSString *title = NULL;
        NSString *message = NULL;
        NSString *description = NULL;
        
        if (in_title) {
            title = [NSString stringWithUTF8String: in_title];
        }
        
        if (in_message) {
            message = [NSString stringWithUTF8String: in_message];
        }
        
        if (in_description) {
            description = [NSString stringWithUTF8String: in_description];
        }
        
        response_string = [[client authPromptWithIdentity: identity
                                                     type: in_prompt_type
                                                hideReply: in_hide_reply
                                                    title: title
                                                  message: message
                                              description: description
                                                    error: &result] UTF8String];
    }
    
    if (!err && !result && response_string) {
        response_len = strlen (response_string) + 1;
        err = vm_allocate (mach_task_self (), 
                           (vm_address_t *) &response_buf, response_len, TRUE);
        
    }
    
    if (!err && !result) {
        memmove (response_buf, response_string, response_len);
        *out_response = response_buf;
        *out_responseCnt = response_len;
        response_buf = NULL;
    }
    
    if (!err) {
        *out_error = result;
    }
    
    if (response_buf) { vm_deallocate (mach_task_self (), 
                                       (vm_address_t) response_buf, 
                                       response_len); }
    kim_identity_free (&identity);
    
    return err;
}

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_change_password (mach_port_t             in_server_port,
                                            kim_mipc_in_string      in_identity,
                                            mach_msg_type_number_t  in_identityCnt,
                                            kim_mipc_boolean        in_old_password_expired,
                                            kim_mipc_out_string    *out_old_password,
                                            mach_msg_type_number_t *out_old_passwordCnt,
                                            kim_mipc_out_string    *out_new_password,
                                            mach_msg_type_number_t *out_new_passwordCnt,
                                            kim_mipc_out_string    *out_vfy_password,
                                            mach_msg_type_number_t *out_vfy_passwordCnt,
                                            kim_mipc_error         *out_error)
{
    kern_return_t err = 0;
    kim_error result = KIM_NO_ERROR;
    ClientConnection *client = NULL;
    kim_identity identity = NULL;
    NSArray *passwords = NULL;
    const char *old_password_string = NULL;
    const char *new_password_string = NULL;
    const char *vfy_password_string = NULL;
    mach_msg_type_number_t old_password_len = 0;
    mach_msg_type_number_t new_password_len = 0;
    mach_msg_type_number_t vfy_password_len = 0;
    kim_mipc_out_string old_password_buf = NULL;
    kim_mipc_out_string new_password_buf = NULL;
    kim_mipc_out_string vfy_password_buf = NULL;
    
    if (!err) {
        ServerThread *sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err) {
            client = [sthread connectionForPort: in_server_port];
            if (!client) { err = KIM_OUT_OF_MEMORY_ERR; }
        }
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity, in_identity);
    }
    
    if (!err) {
        passwords = [client changePasswordWithIdentity: identity
                                   oldPasswordIsExpired: in_old_password_expired
                                                  error: &result];
    }
    
    if (!err && !result) {
        if (passwords && [passwords count] == 3) {
            old_password_string = [[passwords objectAtIndex: 1] UTF8String];
            new_password_string = [[passwords objectAtIndex: 2] UTF8String];
            vfy_password_string = [[passwords objectAtIndex: 3] UTF8String];
        } else {
            err = KIM_OUT_OF_MEMORY_ERR;
        }
    }
        
    if (!err && !result && old_password_string) {
        old_password_len = strlen (old_password_string) + 1;
        err = vm_allocate (mach_task_self (), (vm_address_t *) &old_password_buf, old_password_len, TRUE);
        
    }

    if (!err && !result && new_password_string) {
        new_password_len = strlen (new_password_string) + 1;
        err = vm_allocate (mach_task_self (), (vm_address_t *) &new_password_buf, new_password_len, TRUE);
        
    }
    
    if (!err && !result && vfy_password_string) {
        vfy_password_len = strlen (vfy_password_string) + 1;
        err = vm_allocate (mach_task_self (), (vm_address_t *) &vfy_password_buf, vfy_password_len, TRUE);
    }
    
    if (!err && !result) {
        memmove (old_password_buf, old_password_string, old_password_len);
        memmove (new_password_buf, new_password_string, new_password_len);
        memmove (vfy_password_buf, vfy_password_string, vfy_password_len);
        *out_old_password = old_password_buf;
        *out_new_password = new_password_buf;
        *out_vfy_password = vfy_password_buf;
        *out_old_passwordCnt = old_password_len;
        *out_new_passwordCnt = new_password_len;
        *out_vfy_passwordCnt = vfy_password_len;
        old_password_buf = NULL;
        new_password_buf = NULL;
        vfy_password_buf = NULL;
    }
    
    if (!err) {
        *out_error = result;
    }
    
    if (old_password_buf) { vm_deallocate (mach_task_self (), (vm_address_t) old_password_buf, old_password_len); }
    if (new_password_buf) { vm_deallocate (mach_task_self (), (vm_address_t) new_password_buf, new_password_len); }
    if (vfy_password_buf) { vm_deallocate (mach_task_self (), (vm_address_t) vfy_password_buf, vfy_password_len); }
    kim_identity_free (&identity);
    
    return err;
}

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_handle_error (mach_port_t             in_server_port,
                                         kim_mipc_in_string      in_identity,
                                         mach_msg_type_number_t  in_identityCnt,
                                         kim_mipc_error          in_error,
                                         kim_mipc_in_string      in_message,
                                         mach_msg_type_number_t  in_messageCnt,
                                         kim_mipc_in_string      in_description,
                                         mach_msg_type_number_t  in_descriptionCnt,
                                         kim_mipc_error         *out_error)
{
    kern_return_t err = 0;
    kim_error result = KIM_NO_ERROR;
    ClientConnection *client = NULL;
    kim_identity identity = NULL;
    
    if (!err) {
        ServerThread *sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }
        
        if (!err) {
            client = [sthread connectionForPort: in_server_port];
            if (!client) { err = KIM_OUT_OF_MEMORY_ERR; }
        }
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity, in_identity);
    }
    
    if (!err) {
        NSString *message = NULL;
        NSString *description = NULL;
        
        if (in_message) {
            message = [NSString stringWithUTF8String: in_message];
        }
        
        if (in_description) {
            description = [NSString stringWithUTF8String: in_description];
        }
        
        result = [client handleError: in_error
                            identity: identity
                             message: message
                         description: description];
    }
    
    if (!err) {
        *out_error = result;
    }
    
    kim_identity_free (&identity);
    
    return err;
}

/* ------------------------------------------------------------------------ */

kern_return_t kim_mipc_srv_fini (mach_port_t     in_server_port,
                                 kim_mipc_error *out_error)
{
    kern_return_t err = 0;
    ServerThread *sthread = NULL;
    
    if (!err) {
        sthread = [ServerThread sharedServerThread];
        if (!sthread) { err = KIM_OUT_OF_MEMORY_ERR; }
    }

    if (!err) {
        [sthread removeConnectionWithPort: in_server_port];
    }
    
    if (!err) {
        *out_error = KIM_NO_ERROR;
    }
    
    return err;
}

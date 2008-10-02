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

#import "ServerDemux.h"
#import "kim_selection_hints_private.h"
#import "kim_options_private.h"
#import "KerberosAgentListener.h"
#import "KIMUtilities.h"

// ---------------------------------------------------------------------------

static kim_boolean caller_is_front_process (pid_t    in_pid, 
                                            NSString *in_path)
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean is_front_process = FALSE;
    NSNumber *active_pid = NULL;
    
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
        NSDictionary *activeApplication = [[NSWorkspace sharedWorkspace] activeApplication];
        if (activeApplication) {
            active_pid = [activeApplication objectForKey: @"NSApplicationProcessIdentifier"];
        }
    }
    
    if (!err && active_pid) {
        is_front_process = ([active_pid intValue] == in_pid);
    }
    
    return is_front_process;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_init (mach_port_t   in_client_port, 
                                        mach_port_t   in_reply_port, 
                                        k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    int32_t pid = 0;
    char *name = NULL;
    char *path = NULL;
    bool isFrontProcess = 0;

    if (!err) {
        err = k5_ipc_stream_read_int32 (in_request_stream, &pid);
    }
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &name);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &path);
    } 
    
    
    if (!err) {
        isFrontProcess = caller_is_front_process (pid, 
                                                  [NSString stringWithUTF8String: path]);
    }
    
    if (!err) {
        // performs selector on main thread
        [KerberosAgentListener addClientWithPort:in_client_port 
                                       replyPort:in_reply_port 
                                            name:name 
                                            path:path];
    }
    
    k5_ipc_stream_free_string (name);    
    k5_ipc_stream_free_string (path);

    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_init (mach_port_t   in_reply_port, 
                               int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }
    
    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_enter_identity (mach_port_t   in_client_port, 
                                                  mach_port_t   in_reply_port, 
                                                  k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    kim_options options = NULL;
    
    if (!err) {
        err = kim_options_create_from_stream (&options, in_request_stream);
    }
    
    if (!err) {
        // performs selector on main thread
        [KerberosAgentListener enterIdentityWithClientPort:in_client_port 
                                                 replyPort:in_reply_port
                                                   options:options];
    }
    
    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_enter_identity (mach_port_t   in_reply_port, 
                                         kim_identity  in_identity,
                                         kim_options   in_options,
                                         kim_boolean   in_change_password,
                                         int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    kim_string identity_string = NULL;
    
    if (!err && !in_error) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_string (reply, identity_string);
    }

    if (!err && !in_error) {
        err = k5_ipc_stream_write_uint32 (reply, in_change_password);
    }
    
    if (!err && !in_error) {
        err = kim_options_write_to_stream (in_options, reply);
    }
    
    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    kim_string_free (&identity_string);
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_select_identity (mach_port_t   in_client_port, 
                                                   mach_port_t   in_reply_port, 
                                                   k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    kim_selection_hints hints = NULL;

    if (!err) {
        err = kim_selection_hints_create_from_stream (&hints, 
                                                      in_request_stream);
    }    
    
    if (!err) {
        // performs selector on main thread
        [KerberosAgentListener selectIdentityWithClientPort:in_client_port 
                                                  replyPort:in_reply_port
                                                      hints:hints];
    }
    
    kim_selection_hints_free (&hints);
    
    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_select_identity (mach_port_t   in_reply_port, 
                                          kim_identity  in_identity,
                                          kim_options   in_options,
                                          kim_boolean   in_change_password,
                                          int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    kim_string identity_string = NULL;
    
    if (!err && !in_error) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_string (reply, identity_string);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_uint32 (reply, in_change_password);
    }

    if (!err && !in_error) {
        err = kim_options_write_to_stream (in_options, reply);
    }

    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    kim_string_free (&identity_string);
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_auth_prompt (mach_port_t   in_client_port, 
                                               mach_port_t   in_reply_port, 
                                               k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    char *identity_string = NULL;
    int32_t type = 0;
    int32_t allow_save_reply = 0;
    int32_t hide_reply = 0;
    char *title = NULL;
    char *message = NULL;
    char *description = NULL;
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &identity_string);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_int32 (in_request_stream, &type);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_int32 (in_request_stream, &allow_save_reply);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_int32 (in_request_stream, &hide_reply);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &title);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &message);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &description);
    }    
    
    if (!err) {
        // performs selector on main thread
        [KerberosAgentListener promptForAuthWithClientPort:in_client_port
                                                 replyPort:in_reply_port 
                                                  identity:identity_string 
                                                promptType:type 
                                                 allowSave:allow_save_reply
                                                 hideReply:hide_reply
                                                     title:title
                                                   message:message
                                               description:description];
    }
    
    k5_ipc_stream_free_string (identity_string);    
    k5_ipc_stream_free_string (title);    
    k5_ipc_stream_free_string (message);    
    k5_ipc_stream_free_string (description);    
    
    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_auth_prompt (mach_port_t   in_reply_port, 
                                      kim_string    in_prompt_response,
                                      kim_boolean   in_allow_save_response,
                                      int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_string (reply, in_prompt_response);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_int32 (reply, in_allow_save_response);
    }
    
    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_change_password (mach_port_t   in_client_port, 
                                                   mach_port_t   in_reply_port, 
                                                   k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    char *identity_string = NULL;
    int32_t old_password_expired = 0;
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &identity_string);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_int32 (in_request_stream, 
                                        &old_password_expired);
    }    
    
    if (!err) {
        // performs selector on main thread
        [KerberosAgentListener changePasswordWithClientPort:in_client_port
                                                 replyPort:in_reply_port 
                                                  identity:identity_string 
                                                    expired:old_password_expired];
    }
    
    k5_ipc_stream_free_string (identity_string);   
    
    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_change_password (mach_port_t   in_reply_port, 
                                          kim_string    in_old_password,
                                          kim_string    in_new_password,
                                          kim_string    in_vfy_password,
                                          int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_string (reply, in_old_password);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_string (reply, in_new_password);
    }
    
    if (!err && !in_error) {
        err = k5_ipc_stream_write_string (reply, in_vfy_password);
    }
    
    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_handle_error (mach_port_t   in_client_port, 
                                                mach_port_t   in_reply_port, 
                                                k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    char *identity_string = NULL;
    int32_t error = 0;
    char *message = NULL;
    char *description = NULL;
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &identity_string);
        /* Can be empty string "" if there is no identity */
        if (!err && !identity_string[0]) {
            k5_ipc_stream_free_string (identity_string);   
            identity_string = NULL;
        }
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_int32 (in_request_stream, &error);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &message);
    }    
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &description);
    }    
    
    if (!err) {
        // performs selector on main thread
        [KerberosAgentListener handleErrorWithClientPort:in_client_port
                                               replyPort:in_reply_port 
                                                identity:identity_string 
                                                   error:error
                                                 message:message
                                             description:description];
    }
    
    k5_ipc_stream_free_string (identity_string);   
    k5_ipc_stream_free_string (message);   
    k5_ipc_stream_free_string (description);   
    
    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_handle_error (mach_port_t   in_reply_port, 
                                       int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }

    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static int32_t kim_handle_request_fini (mach_port_t   in_client_port, 
                                        mach_port_t   in_reply_port, 
                                        k5_ipc_stream in_request_stream)
{
    int32_t err = 0;

    [KerberosAgentListener removeClientMatchingPort:in_client_port replyPort:in_reply_port];
    
    return err;   
}

/* ------------------------------------------------------------------------ */

int32_t kim_handle_reply_fini (mach_port_t   in_reply_port, 
                               int32_t       in_error)
{
    int32_t err = 0;
    k5_ipc_stream reply = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (reply, in_error);
    }
    
    if (!err) {
        err = k5_ipc_server_send_reply (in_reply_port, reply);
    }
    
    k5_ipc_stream_release (reply);
    
    return err;   
}

#pragma mark -

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_add_client (mach_port_t in_client_port)
{
    int32_t err = 0;
    
    if (!err) {
        /* Don't need to do anything here since we have an init message */
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_remove_client (mach_port_t in_client_port)
{
    int32_t err = 0;    
    
    if (!err) {
        /* Client exited.  Main thread should check for windows belonging to
         * in_client_port and close any it finds. */
        [KerberosAgentListener removeClientMatchingPort:in_client_port replyPort:0];
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_handle_request (mach_port_t   in_client_port, 
                                      mach_port_t   in_reply_port, 
                                      k5_ipc_stream in_request_stream)
{
    int32_t err = 0;
    char *message_type = NULL;
    
    if (!err) {
        err = k5_ipc_stream_read_string (in_request_stream, &message_type);
    }
    
    if (!err) {
        if (!strcmp (message_type, "init")) {
            err = kim_handle_request_init (in_client_port,
                                           in_reply_port,
                                           in_request_stream);
            
        } else if (!strcmp (message_type, "enter_identity")) {
            err = kim_handle_request_enter_identity (in_client_port,
                                                     in_reply_port,
                                                     in_request_stream);
            
        } else if (!strcmp (message_type, "select_identity")) {
            err = kim_handle_request_select_identity (in_client_port,
                                                      in_reply_port,
                                                      in_request_stream);
            
        } else if (!strcmp (message_type, "auth_prompt")) {
            err = kim_handle_request_auth_prompt (in_client_port,
                                                  in_reply_port,
                                                  in_request_stream);
            
        } else if (!strcmp (message_type, "change_password")) {
            err = kim_handle_request_change_password (in_client_port,
                                                      in_reply_port,
                                                      in_request_stream);
            
        } else if (!strcmp (message_type, "handle_error")) {
            err = kim_handle_request_handle_error (in_client_port,
                                                   in_reply_port,
                                                   in_request_stream);
            
        } else if (!strcmp (message_type, "fini")) {
            err = kim_handle_request_fini (in_client_port,
                                           in_reply_port,
                                           in_request_stream);
            
        } else {
            err = EINVAL;
        }
    }
    
    k5_ipc_stream_free_string (message_type);
    
    return err;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

int32_t kim_agent_listen_loop (void)
{
    return k5_ipc_server_listen_loop ();
}

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

#ifdef KIM_BUILTIN_UI

#include "kim_os_private.h"

#include "k5_mig_client.h"

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ */

static inline int32_t kim_os_ui_gui_send_request (int32_t        in_launch_server,
                                                  k5_ipc_stream  in_request_stream,
                                                  k5_ipc_stream *out_reply_stream)
{
    return k5_ipc_send_request (kim_os_agent_bundle_id,
                                in_launch_server,
                                in_request_stream,
                                out_reply_stream);
}


/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_init (kim_ui_context *io_context)
{
    kim_error err = KIM_NO_ERROR;
    kim_string name = NULL;
    kim_string path = NULL;
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    
    if (!err && !io_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_library_get_application_name (&name);
    }
    
    if (!err) {
        err = kim_os_library_get_application_path (&path);
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "init");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (request, getpid());
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, name ? name : "");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, path ? path : "");
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (1 /* launch server */,
                                          request,
                                          &reply);
    }
    
    if (!err) {
        int32_t result = 0;

        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        io_context->tcontext = NULL;
    }
    
    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);
    kim_string_free (&name);
    kim_string_free (&path);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_enter_identity (kim_ui_context *in_context,
                                        kim_options     io_options,
                                        kim_identity   *out_identity,
                                        kim_boolean    *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    char *identity_string = NULL;
    kim_identity identity = NULL;
    uint32_t change_password = 0;
    
    if (!err && !io_options         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_change_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "enter_identity");
    }

    if (!err) {
        err = kim_options_write_to_stream (io_options, request);
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (0 /* don't launch server */,
                                          request,
                                          &reply);
        if (!reply) { err = check_error (KIM_NO_SERVER_ERR); }
    }
    
    if (!err) {
        int32_t result = 0;
        
        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err  = k5_ipc_stream_read_string (reply, &identity_string);
    }

    if (!err) {
        err  = k5_ipc_stream_read_uint32 (reply, &change_password);
    }
    
    if (!err) {
        err  = kim_options_read_from_stream (io_options, reply);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity, identity_string);
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
        *out_change_password = change_password;
    }
    
    kim_identity_free (&identity);
    k5_ipc_stream_free_string (identity_string);
    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_select_identity (kim_ui_context      *in_context,
                                         kim_selection_hints  io_hints,
                                         kim_identity        *out_identity,
                                         kim_boolean         *out_change_password)
{
    kim_error err = KIM_NO_ERROR;
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    char *identity_string = NULL;
    kim_options options = NULL;
    kim_identity identity = NULL;
    uint32_t change_password = 0;
    
    if (!err && !io_hints           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_change_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "select_identity");
    }
    
    if (!err) {
        err = kim_selection_hints_write_to_stream (io_hints, request);
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (0 /* don't launch server */,
                                          request,
                                          &reply);
        if (!reply) { err = check_error (KIM_NO_SERVER_ERR); }
    }
    
    if (!err) {
        int32_t result = 0;
        
        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err  = k5_ipc_stream_read_string (reply, &identity_string);
    }
    
    if (!err) {
        err = kim_identity_create_from_string (&identity, identity_string);
    }
    
    if (!err) {
        err  = k5_ipc_stream_read_uint32 (reply, &change_password);
    }

    if (!err) {
        err = kim_options_create_from_stream (&options, reply);
    }
    
    if (!err) {
        err = kim_selection_hints_set_options (io_hints, options);
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
        *out_change_password = change_password;
    }
    
    kim_identity_free (&identity);    
    kim_options_free (&options);
    k5_ipc_stream_free_string (identity_string);    
    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_auth_prompt (kim_ui_context      *in_context,
                                     kim_identity         in_identity,
                                     kim_prompt_type      in_type,
                                     kim_boolean          in_allow_save_reply, 
                                     kim_boolean          in_hide_reply, 
                                     kim_string           in_title,
                                     kim_string           in_message,
                                     kim_string           in_description,
                                     char               **out_reply,
                                     kim_boolean         *out_save_reply)
{
    kim_error err = KIM_NO_ERROR;
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    kim_string identity_string = NULL;
    
    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_reply  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* in_title, in_message or in_description may be NULL */
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "auth_prompt");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (request, in_type);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (request, in_allow_save_reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (request, in_hide_reply);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, 
                                          in_title ? in_title : "");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, 
                                          in_message ? in_message : "");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, 
                                          in_description ? in_description : "");
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (0 /* don't launch server */,
                                          request,
                                          &reply);
        if (!reply) { err = check_error (KIM_NO_SERVER_ERR); }
    }
    
    if (!err) {
        int32_t result = 0;
        
        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err  = k5_ipc_stream_read_string (reply, out_reply);
    } 
    
    if (!err) {
        err  = k5_ipc_stream_read_int32 (reply, out_save_reply);
    } 
    
    kim_string_free (&identity_string);

    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_ui_gui_change_password (kim_ui_context      *in_context,
                                         kim_identity         in_identity,
                                         kim_boolean          in_old_password_expired,
                                         char               **out_old_password,
                                         char               **out_new_password,
                                         char               **out_vfy_password)
{
    kim_error err = KIM_NO_ERROR;
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    kim_string identity_string = NULL;
    
    char *old_password = NULL;
    char *new_password = NULL;
    char *vfy_password = NULL;
   
    if (!err && !in_identity     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_old_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_new_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_vfy_password) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "change_password");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (request, in_old_password_expired);
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (0 /* don't launch server */,
                                          request,
                                          &reply);
        if (!reply) { err = check_error (KIM_NO_SERVER_ERR); }
    }
    
    if (!err) {
        int32_t result = 0;
        
        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }
    
    if (!err) {
        err  = k5_ipc_stream_read_string (reply, &old_password);
    }     
    
    if (!err) {
        err  = k5_ipc_stream_read_string (reply, &new_password);
    }     
    
    if (!err) {
        err  = k5_ipc_stream_read_string (reply, &vfy_password);
    }     
    
    if (!err) {
        *out_old_password = (char *) old_password;
        old_password = NULL;
        *out_new_password = (char *) new_password;
        new_password = NULL;
        *out_vfy_password = (char *) vfy_password;
        vfy_password = NULL;
    }
    
    kim_string_free (&identity_string);    
    k5_ipc_stream_free_string (old_password);    
    k5_ipc_stream_free_string (new_password);    
    k5_ipc_stream_free_string (vfy_password);    
    
    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);

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
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    kim_string identity_string = NULL;
    
    if (!err && !in_error_message    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_error_description) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "handle_error");
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, identity_string);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_int32 (request, in_error);
    }

    if (!err) {
        err = k5_ipc_stream_write_string (request, in_error_message);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, in_error_description);
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (0 /* don't launch server */,
                                          request,
                                          &reply);
        if (!reply) { err = check_error (KIM_NO_SERVER_ERR); }
    }
    
    if (!err) {
        int32_t result = 0;
        
        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }
    
    kim_string_free (&identity_string);    

    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);

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
    k5_ipc_stream request = NULL;
    k5_ipc_stream reply = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&request);
    }
    
    if (!err) {
        err = k5_ipc_stream_write_string (request, "fini");
    }
    
    if (!err) {
        err = kim_os_ui_gui_send_request (0 /* don't launch server */,
                                          request,
                                          &reply);
        if (!reply) { err = check_error (KIM_NO_SERVER_ERR); }
    }
    
    if (!err) {
        int32_t result = 0;
        
        err = k5_ipc_stream_read_int32 (reply, &result);
        if (!err) { err = check_error (result); }
    }    
    
    k5_ipc_stream_release (request);
    k5_ipc_stream_release (reply);

    return check_error (err);
}

#endif /* KIM_BUILTIN_UI */

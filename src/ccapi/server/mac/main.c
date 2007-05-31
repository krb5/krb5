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

#include "ccs_common.h"

#include <syslog.h>
#include <Kerberos/kipc_server.h>
#include "cci_mig_requestServer.h"
#include "cci_mig_reply.h"
#include "ccs_os_server.h"

/* ------------------------------------------------------------------------ */

static boolean_t ccs_server_demux (mach_msg_header_t *request, 
                                   mach_msg_header_t *reply) 
{
    boolean_t handled = false;
    
    if (!handled) {
        handled = ccs_server (request, reply);
    }
    
    if (!handled && request->msgh_id == MACH_NOTIFY_NO_SENDERS) {
        kern_return_t err = KERN_SUCCESS;

        err = ccs_server_remove_client (request->msgh_local_port);
        
        if (!err) {
            /* Check here for a client in our table and free rights associated with it */
            err = mach_port_mod_refs (mach_task_self (), request->msgh_local_port, 
                                      MACH_PORT_RIGHT_RECEIVE, -1);
        }
        
        if (!err) {
            handled = 1;  /* was a port we are tracking */
        }

        cci_check_error (err);
    }
    
    return handled;    
}

/* ------------------------------------------------------------------------ */

int main (int argc, const char *argv[])
{
    cc_int32 err = 0;
    
    openlog (argv[0], LOG_CONS | LOG_PID, LOG_AUTH);
    syslog (LOG_INFO, "Starting up.");   
    
    if (!err) {
        err = ccs_server_initialize ();
    }
    
    if (!err) {
        err = kipc_server_run_server (ccs_server_demux);
    }
    
    /* cleanup ccs resources */
    ccs_server_cleanup ();
    
    syslog (LOG_NOTICE, "Exiting: %s (%d)", kipc_error_string (err), err);
    
    /* exit */
    return err ? 1 : 0;
}

/* ------------------------------------------------------------------------ */

kern_return_t ccs_mipc_create_client_connection (mach_port_t    in_server_port,
                                                 mach_port_t   *out_connection_port)
{
    kern_return_t err = KERN_SUCCESS;
    mach_port_t connection_port = MACH_PORT_NULL;
    mach_port_t old_notification_target = MACH_PORT_NULL;
    
    if (!err) {
        err = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &connection_port);
    }
    
    if (!err) {
        err = mach_port_move_member (mach_task_self (), connection_port, kipc_server_get_listen_portset ());
    }
    
    if (!err) {
        /* request no-senders notification so we can tell when client quits/crashes */
        err = mach_port_request_notification (mach_task_self (), connection_port, 
                                              MACH_NOTIFY_NO_SENDERS, 1, connection_port, 
                                              MACH_MSG_TYPE_MAKE_SEND_ONCE, &old_notification_target );
    }
    
    if (!err) {
        err = ccs_server_add_client (connection_port);
    }
    
    if (!err) {
        *out_connection_port = connection_port;
        connection_port = MACH_PORT_NULL;
    }
    
    if (MACH_PORT_VALID (connection_port)) { mach_port_deallocate (mach_task_self (), connection_port); }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_os_server_send_reply (ccs_pipe_t   in_reply_pipe,
                                   cci_stream_t in_reply_stream)
{
    kern_return_t err = KERN_SUCCESS;
    cci_mipc_inl_reply_t inl_reply;
    mach_msg_type_number_t inl_reply_length = 0;
    cci_mipc_ool_reply_t ool_reply = NULL;
    mach_msg_type_number_t ool_reply_length = 0;
    
    if (!ccs_pipe_valid (in_reply_pipe)) { err = cci_check_error (ccErrBadParam); }
    if (!in_reply_stream               ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        /* depending on how big the message is, use the fast inline buffer or  
        * the slow dynamically allocated buffer */
        mach_msg_type_number_t reply_length = cci_stream_size (in_reply_stream);
        
        if (reply_length > kCCAPIMaxILMsgSize) {            
            cci_debug_printf ("%s choosing out of line buffer (size is %d)", 
                              __FUNCTION__, reply_length);
            
            err = vm_read (mach_task_self (), 
                           (vm_address_t) cci_stream_data (in_reply_stream), reply_length, 
                           (vm_address_t *) &ool_reply, &ool_reply_length);
            
        } else {
            //cci_debug_printf ("%s choosing in line buffer (size is %d)",
            //                  __FUNCTION__, reply_length);
            
            inl_reply_length = reply_length;
            memcpy (inl_reply, cci_stream_data (in_reply_stream), reply_length);
        }
    }
    
    if (!err) {
        err = ccs_mipc_reply (ccs_pipe_os (in_reply_pipe), 
                              inl_reply, inl_reply_length,
                              ool_reply, ool_reply_length);
    }
    
    if (!err) {
        /* Because we use ",dealloc" ool_reply will be freed by mach. Don't double free it. */
        ool_reply = NULL;
        ool_reply_length = 0;
    }
    
    if (ool_reply_length) { vm_deallocate (mach_task_self (), (vm_address_t) ool_reply, ool_reply_length); }
    
    return cci_check_error (err);
}
                                     

/* ------------------------------------------------------------------------ */

kern_return_t ccs_mipc_request (mach_port_t             in_connection_port,
                                mach_port_t             in_reply_port,
                                cci_mipc_inl_request_t  in_inl_request,
                                mach_msg_type_number_t  in_inl_requestCnt,
                                cci_mipc_ool_request_t  in_ool_request,
                                mach_msg_type_number_t  in_ool_requestCnt)
{
    kern_return_t err = KERN_SUCCESS;
    cci_stream_t request_stream = NULL;
    ccs_pipe_t connection_pipe = NULL;
    ccs_pipe_t reply_pipe = NULL;
    
    if (!err) {
        err = cci_stream_new (&request_stream);
    }
    
    if (!err) {
        if (in_inl_requestCnt) {
            err = cci_stream_write (request_stream, in_inl_request, in_inl_requestCnt);
            
        } else if (in_ool_requestCnt) {
            err = cci_stream_write (request_stream, in_ool_request, in_ool_requestCnt);
            
        } else {
            err = cci_check_error (ccErrBadInternalMessage);
        }
    }
    
    if (!err) {
        err = ccs_pipe_new (&connection_pipe, in_connection_port);
    }
    
    if (!err) {
        err = ccs_pipe_new (&reply_pipe, in_reply_port);
    }
    
    if (!err) {
        err = ccs_server_handle_request (connection_pipe, reply_pipe, request_stream);
    }
    
    ccs_pipe_release (connection_pipe);
    ccs_pipe_release (reply_pipe);
    cci_stream_release (request_stream);
    if (in_ool_requestCnt) { vm_deallocate (mach_task_self (), (vm_address_t) in_ool_request, in_ool_requestCnt); }
    
    return cci_check_error (err);
}

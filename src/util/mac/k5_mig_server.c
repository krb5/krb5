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

#include "k5_mig_server.h"

#include <syslog.h>
#include <Kerberos/kipc_server.h>
#include "k5_mig_requestServer.h"
#include "k5_mig_reply.h"


/* ------------------------------------------------------------------------ */

static boolean_t k5_ipc_request_demux (mach_msg_header_t *request, 
                                       mach_msg_header_t *reply) 
{
    boolean_t handled = false;
    
    if (!handled) {
        handled = k5_ipc_request_server (request, reply);
    }
    
    if (!handled && request->msgh_id == MACH_NOTIFY_NO_SENDERS) {
        kern_return_t err = KERN_SUCCESS;
        
        err = k5_ipc_server_remove_client (request->msgh_local_port);
        
        if (!err) {
            /* Check here for a client in our table and free rights associated with it */
            err = mach_port_mod_refs (mach_task_self (), request->msgh_local_port, 
                                      MACH_PORT_RIGHT_RECEIVE, -1);
        }
        
        if (!err) {
            handled = 1;  /* was a port we are tracking */
        }
    }
    
    return handled;    
}

/* ------------------------------------------------------------------------ */

kern_return_t k5_ipc_server_create_client_connection (mach_port_t    in_server_port,
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
        err = k5_ipc_server_add_client (connection_port);
    }
    
    if (!err) {
        *out_connection_port = connection_port;
        connection_port = MACH_PORT_NULL;
    }
    
    if (MACH_PORT_VALID (connection_port)) { mach_port_deallocate (mach_task_self (), connection_port); }
    
    return err;    
}

/* ------------------------------------------------------------------------ */

kern_return_t k5_ipc_server_request (mach_port_t             in_connection_port,
                                     mach_port_t             in_reply_port,
                                     k5_ipc_inl_request_t    in_inl_request,
                                     mach_msg_type_number_t  in_inl_requestCnt,
                                     k5_ipc_ool_request_t    in_ool_request,
                                     mach_msg_type_number_t  in_ool_requestCnt)
{
    kern_return_t err = KERN_SUCCESS;
    k5_ipc_stream request_stream = NULL;
    
    if (!err) {
        err = k5_ipc_stream_new (&request_stream);
    }
    
    if (!err) {
        if (in_inl_requestCnt) {
            err = k5_ipc_stream_write (request_stream, in_inl_request, in_inl_requestCnt);
            
        } else if (in_ool_requestCnt) {
            err = k5_ipc_stream_write (request_stream, in_ool_request, in_ool_requestCnt);
            
        } else {
            err = EINVAL;
        }
    }
    
    if (!err) {
        err = k5_ipc_server_handle_request (in_connection_port, in_reply_port, request_stream);
    }
    
    k5_ipc_stream_release (request_stream);
    if (in_ool_requestCnt) { vm_deallocate (mach_task_self (), (vm_address_t) in_ool_request, in_ool_requestCnt); }
    
    return err;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_initialize (int argc, const char *argv[])
{
    int32_t err = 0;
    
    openlog (argv[0], LOG_CONS | LOG_PID, LOG_AUTH);
    syslog (LOG_INFO, "Starting up.");   
    
    syslog (LOG_NOTICE, "Exiting: %s (%d)", kipc_error_string (err), err);
    
    return err;
}

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_cleanup (int argc, const char *argv[])
{
    int32_t err = 0;
    
    openlog (argv[0], LOG_CONS | LOG_PID, LOG_AUTH);
    syslog (LOG_INFO, "Starting up.");   
    
    syslog (LOG_NOTICE, "Exiting: %s (%d)", kipc_error_string (err), err);
    
    return err;
}

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_listen_loop (void)
{
    /* Run the Mach IPC listen loop.  
     * This will call k5_ipc_server_create_client_connection for new clients
     * and k5_ipc_server_request for existing clients */
    
    return kipc_server_run_server (k5_ipc_request_demux);
}

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_server_send_reply (mach_port_t   in_reply_port,
                                  k5_ipc_stream in_reply_stream)
{
    kern_return_t err = KERN_SUCCESS;
    k5_ipc_inl_reply_t inl_reply;
    mach_msg_type_number_t inl_reply_length = 0;
    k5_ipc_ool_reply_t ool_reply = NULL;
    mach_msg_type_number_t ool_reply_length = 0;
    
    if (!MACH_PORT_VALID (in_reply_port)) { err = EINVAL; }
    if (!in_reply_stream                ) { err = EINVAL; }
    
    if (!err) {
        /* depending on how big the message is, use the fast inline buffer or  
         * the slow dynamically allocated buffer */
        mach_msg_type_number_t reply_length = k5_ipc_stream_size (in_reply_stream);
        
        if (reply_length > K5_IPC_MAX_MSG_SIZE) {            
            //dprintf ("%s choosing out of line buffer (size is %d)", 
            //                  __FUNCTION__, reply_length);
            
            err = vm_read (mach_task_self (), 
                           (vm_address_t) k5_ipc_stream_data (in_reply_stream), reply_length, 
                           (vm_address_t *) &ool_reply, &ool_reply_length);
            
        } else {
            //cci_debug_printf ("%s choosing in line buffer (size is %d)",
            //                  __FUNCTION__, reply_length);
            
            inl_reply_length = reply_length;
            memcpy (inl_reply, k5_ipc_stream_data (in_reply_stream), reply_length);
        }
    }
    
    if (!err) {
        err = k5_ipc_server_reply (in_reply_port, 
                                   inl_reply, inl_reply_length,
                                   ool_reply, ool_reply_length);
    }
    
    if (!err) {
        /* Because we use ",dealloc" ool_reply will be freed by mach. Don't double free it. */
        ool_reply = NULL;
        ool_reply_length = 0;
    }
    
    if (ool_reply_length) { vm_deallocate (mach_task_self (), (vm_address_t) ool_reply, ool_reply_length); }
    
    return err;
}

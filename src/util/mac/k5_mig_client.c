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

#include "k5_mig_client.h"

#include <Kerberos/kipc_client.h>
#include "k5_mig_request.h"
#include "k5_mig_replyServer.h"
#include "k5-thread.h"

MAKE_INIT_FUNCTION(k5_cli_ipc_thread_init);
MAKE_FINI_FUNCTION(k5_cli_ipc_thread_fini);

/* ------------------------------------------------------------------------ */

static int k5_cli_ipc_thread_init (void)
{
    int err = 0;

    err = k5_key_register (K5_KEY_IPC_REQUEST_PORT, free);
    
    if (!err) {
        err = k5_key_register (K5_KEY_IPC_REPLY_STREAM, NULL);
    }
    
    if (!err) {
        err = k5_key_register (K5_KEY_IPC_SERVER_DIED, NULL);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static void k5_cli_ipc_thread_fini (void)
{    
    k5_key_delete (K5_KEY_IPC_REQUEST_PORT);
    k5_key_delete (K5_KEY_IPC_REPLY_STREAM);
    k5_key_delete (K5_KEY_IPC_SERVER_DIED);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static boolean_t k5_ipc_reply_demux (mach_msg_header_t *request, 
                                     mach_msg_header_t *reply) 
{
    boolean_t handled = 0;
    
    if (CALL_INIT_FUNCTION (k5_cli_ipc_thread_init) != 0) {
        return 0;
    }    
    
    if (!handled && request->msgh_id == MACH_NOTIFY_NO_SENDERS) {
        int32_t *server_died = k5_getspecific (K5_KEY_IPC_SERVER_DIED);
        if (!server_died) { 
            *server_died = 1;
        }
        
        handled = 1; /* server died */
    }
    
    if (!handled) {
        handled = k5_ipc_reply_server (request, reply);
    }
    
    return handled;    
}

/* ------------------------------------------------------------------------ */

kern_return_t k5_ipc_client_reply (mach_port_t             in_reply_port,
                                   k5_ipc_inl_reply_t      in_inl_reply,
                                   mach_msg_type_number_t  in_inl_replyCnt,
                                   k5_ipc_ool_reply_t      in_ool_reply,
                                   mach_msg_type_number_t  in_ool_replyCnt)
{
    kern_return_t err = KERN_SUCCESS;
    k5_ipc_stream reply_stream = NULL;
    
    if (!err) {
        err = CALL_INIT_FUNCTION (k5_cli_ipc_thread_init);
    }
    
    if (!err) {
        reply_stream = k5_getspecific (K5_KEY_IPC_REPLY_STREAM);
        if (!reply_stream) { err = EINVAL; }
    }
    
    if (!err) {
        if (in_inl_replyCnt) {
            err = k5_ipc_stream_write (reply_stream, in_inl_reply, in_inl_replyCnt);
            
        } else if (in_ool_replyCnt) {
            err = k5_ipc_stream_write (reply_stream, in_ool_reply, in_ool_replyCnt);
            
        } else {
            err = EINVAL;
        }
    }
    
    if (in_ool_replyCnt) { vm_deallocate (mach_task_self (), (vm_address_t) in_ool_reply, in_ool_replyCnt); }
    
    return err;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

int32_t k5_ipc_send_request (int32_t        in_launch_server,
                             k5_ipc_stream  in_request_stream,
                             k5_ipc_stream *out_reply_stream)
{
    int err = 0;
    int32_t done = 0;
    int32_t try_count = 0;
    int32_t server_died = 0;
    mach_port_t server_port = MACH_PORT_NULL;
    mach_port_t *request_port = NULL;
    mach_port_t reply_port = MACH_PORT_NULL;
    const char *inl_request = NULL; /* char * so we can pass the buffer in directly */
    mach_msg_type_number_t inl_request_length = 0;
    k5_ipc_ool_request_t ool_request = NULL;
    mach_msg_type_number_t ool_request_length = 0;
    k5_ipc_stream reply_stream = NULL;
    
    if (!in_request_stream) { err = EINVAL; }
    if (!out_reply_stream ) { err = EINVAL; }
    
    if (!err) {
        err = CALL_INIT_FUNCTION (k5_cli_ipc_thread_init);
    }    
    
    if (!err) {
        /* depending on how big the message is, use the fast inline buffer or  
         * the slow dynamically allocated buffer */
        mach_msg_type_number_t request_length = k5_ipc_stream_size (in_request_stream);
        
        if (request_length > K5_IPC_MAX_MSG_SIZE) {
            //dprintf ("%s choosing out of line buffer (size is %d)", 
            //                  __FUNCTION__, request_length);
            
            err = vm_read (mach_task_self (), 
                           (vm_address_t) k5_ipc_stream_data (in_request_stream), request_length, 
                           (vm_address_t *) &ool_request, &ool_request_length);        
        } else {
            //dprintf ("%s choosing in line buffer (size is %d)",
            //                  __FUNCTION__, request_length);
            
            inl_request_length = request_length;
            inl_request = k5_ipc_stream_data (in_request_stream);
        }
    }

    if (!err) {
        request_port = k5_getspecific (K5_KEY_IPC_REQUEST_PORT);
        
        if (!request_port) {
            request_port = malloc (sizeof (mach_port_t));
            if (!request_port) { err = ENOMEM; }
            
            if (!err) {
                *request_port = MACH_PORT_NULL;
                err = k5_setspecific (K5_KEY_IPC_REQUEST_PORT, request_port);
            }
        }
    }
    
    if (!err) {
        err = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &reply_port);
    }

    if (!err) {
        err = kipc_client_lookup_server (K5_IPC_SERVER_ID, 
                                         in_launch_server, TRUE, &server_port);
    }
    
    while (!err && !done) {
        if (!err && !MACH_PORT_VALID (*request_port)) {
            err = k5_ipc_client_create_client_connection (server_port, request_port);
        }
        
        if (!err) {
            err = k5_ipc_client_request (*request_port, reply_port,
                                         inl_request, inl_request_length,
                                         ool_request, ool_request_length);
            
        }
        
        if (err == MACH_SEND_INVALID_DEST) {
            if (try_count < 2) { 
                try_count++;
                err = 0;
            }

            if (request_port && MACH_PORT_VALID (*request_port)) {
                mach_port_mod_refs (mach_task_self(), *request_port, MACH_PORT_RIGHT_SEND, -1 );
                *request_port = MACH_PORT_NULL;
            }    
            
            /* Look up server name again without using the cached copy */
            err = kipc_client_lookup_server (K5_IPC_SERVER_ID,  
                                             in_launch_server, FALSE, &server_port);
            
        } else {
            /* Talked to server, though we may have gotten an error */
            done = 1;
            
            /* Because we use ",dealloc" ool_request will be freed by mach. 
            * Don't double free it. */
            ool_request = NULL; 
            ool_request_length = 0;                
        }            
    }
    
    if (!err) {
        err = k5_ipc_stream_new (&reply_stream);
    }
    
    if (!err) {
        err = k5_setspecific (K5_KEY_IPC_REPLY_STREAM, reply_stream);
    }
    
    if (!err) {
        err = k5_setspecific (K5_KEY_IPC_SERVER_DIED, &server_died);
    }
    
    if (!err) {
        mach_port_t old_notification_target = MACH_PORT_NULL;

        /* request no-senders notification so we can get a message when server dies */
        err = mach_port_request_notification (mach_task_self (), reply_port, 
                                              MACH_NOTIFY_NO_SENDERS, 1, reply_port, 
                                              MACH_MSG_TYPE_MAKE_SEND_ONCE, 
                                              &old_notification_target);
        
        if (!err && old_notification_target != MACH_PORT_NULL) {
            mach_port_deallocate (mach_task_self (), old_notification_target);
        }
    }
    
    if (!err) {
        err = mach_msg_server_once (k5_ipc_reply_demux, kkipc_max_message_size, 
                                    reply_port, MACH_MSG_TIMEOUT_NONE);
    }
    
    if (!err && server_died) {
        err = ENOTCONN;
    }
    
    if (err == BOOTSTRAP_UNKNOWN_SERVICE && !in_launch_server) {
        err = 0;  /* If the server is not running just return an empty stream. */
    }
    
    if (!err) {
        *out_reply_stream = reply_stream;
        reply_stream = NULL;
    }
    
    k5_setspecific (K5_KEY_IPC_REPLY_STREAM, NULL);
    k5_setspecific (K5_KEY_IPC_SERVER_DIED, NULL);
    if (reply_port != MACH_PORT_NULL) { mach_port_destroy (mach_task_self (), reply_port); }
    if (ool_request_length          ) { vm_deallocate (mach_task_self (), (vm_address_t) ool_request, ool_request_length); }
    if (reply_stream                ) { k5_ipc_stream_release (reply_stream); }
    
    return err;    
}

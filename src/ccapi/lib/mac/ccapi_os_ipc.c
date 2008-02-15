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

#include "ccapi_os_ipc.h"

#include <Kerberos/kipc_client.h>
#include "cci_mig_request.h"
#include "cci_mig_replyServer.h"
#include "k5-thread.h"

#define cci_server_bundle_id "edu.mit.Kerberos.CCacheServer"
#define cci_server_path "/System/Library/CoreServices/CCacheServer.app/Contents/MacOS/CCacheServer"

static pthread_key_t g_request_port_key = 0;
static pthread_key_t g_reply_stream_key = 0;
static pthread_key_t g_server_died_key = 0;

/* ------------------------------------------------------------------------ */

cc_int32 cci_os_ipc_thread_init (void)
{
    cc_int32 err = ccNoError;

    err = pthread_key_create (&g_request_port_key, free);
    
    if (!err) {
        err = pthread_key_create (&g_reply_stream_key, NULL);
    }
    
    if (!err) {
        err = pthread_key_create (&g_server_died_key, NULL);
    }
    
    return err;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

static boolean_t cci_server_demux (mach_msg_header_t *request, 
                                   mach_msg_header_t *reply) 
{
    boolean_t handled = false;
    
    if (!handled && request->msgh_id == MACH_NOTIFY_NO_SENDERS) {
        cc_int32 *server_died = pthread_getspecific (g_server_died_key);
        if (!server_died) { 
            *server_died = 1;
        }
        
        handled = 1; /* server died */
    }
    
    if (!handled) {
        handled = cci_server (request, reply);
    }
    
    return handled;    
}

/* ------------------------------------------------------------------------ */

kern_return_t cci_mipc_reply (mach_port_t             in_reply_port,
                              cci_mipc_inl_reply_t    in_inl_reply,
                              mach_msg_type_number_t  in_inl_replyCnt,
                              cci_mipc_ool_reply_t    in_ool_reply,
                              mach_msg_type_number_t  in_ool_replyCnt)
{
    kern_return_t err = KERN_SUCCESS;
    cci_stream_t reply_stream = NULL;
    
    if (!err) {
        reply_stream = pthread_getspecific (g_reply_stream_key);
        if (!reply_stream) { err = cci_check_error (ccErrBadInternalMessage); }
    }
    
    if (!err) {
        if (in_inl_replyCnt) {
            err = cci_stream_write (reply_stream, in_inl_reply, in_inl_replyCnt);
            
        } else if (in_ool_replyCnt) {
            err = cci_stream_write (reply_stream, in_ool_reply, in_ool_replyCnt);
            
        } else {
            err = cci_check_error (ccErrBadInternalMessage);
        }
    }
    
    if (in_ool_replyCnt) { vm_deallocate (mach_task_self (), (vm_address_t) in_ool_reply, in_ool_replyCnt); }
    
    return cci_check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

cc_int32 cci_os_ipc (cc_int32      in_launch_server,
                     cci_stream_t  in_request_stream,
                     cci_stream_t *out_reply_stream)
{
    cc_int32 err = ccNoError;
    cc_int32 done = 0;
    cc_int32 try_count = 0;
    cc_int32 server_died = 0;
    mach_port_t server_port = MACH_PORT_NULL;
    mach_port_t *request_port = NULL;
    mach_port_t reply_port = MACH_PORT_NULL;
    const char *inl_request = NULL; /* char * so we can pass the buffer in directly */
    mach_msg_type_number_t inl_request_length = 0;
    cci_mipc_ool_request_t ool_request = NULL;
    mach_msg_type_number_t ool_request_length = 0;
    cci_stream_t reply_stream = NULL;
    
    if (!in_request_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_reply_stream ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        /* depending on how big the message is, use the fast inline buffer or  
         * the slow dynamically allocated buffer */
        mach_msg_type_number_t request_length = cci_stream_size (in_request_stream);
        
        if (request_length > kCCAPIMaxILMsgSize) {
            cci_debug_printf ("%s choosing out of line buffer (size is %d)", 
                              __FUNCTION__, request_length);
            
            err = vm_read (mach_task_self (), 
                           (vm_address_t) cci_stream_data (in_request_stream), request_length, 
                           (vm_address_t *) &ool_request, &ool_request_length);        
        } else {
            //cci_debug_printf ("%s choosing in line buffer (size is %d)",
            //                  __FUNCTION__, request_length);
            
            inl_request_length = request_length;
            inl_request = cci_stream_data (in_request_stream);
        }
    }

    if (!err) {
        request_port = pthread_getspecific (g_request_port_key);
        
        if (!request_port) {
            request_port = malloc (sizeof (mach_port_t));
            if (!request_port) { err = cci_check_error (ccErrNoMem); }
            
            if (!err) {
                *request_port = MACH_PORT_NULL;
                err = pthread_setspecific (g_request_port_key, request_port);
            }
        }
    }
    
    if (!err) {
        err = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &reply_port);
    }

    if (!err) {
        err = kipc_client_lookup_server (cci_server_bundle_id, cci_server_path, 
                                         in_launch_server, TRUE, &server_port);
    }
    
    while (!err && !done) {
        if (!err && !MACH_PORT_VALID (*request_port)) {
            err = cci_mipc_create_client_connection (server_port, request_port);
        }
        
        if (!err) {
            err = cci_mipc_request (*request_port, reply_port,
                                    inl_request, inl_request_length,
                                    ool_request, ool_request_length);
            
        }
        
        if (err == MACH_SEND_INVALID_DEST) {
            if (try_count < 2) { 
                try_count++;
                err = ccNoError;
            }

            if (request_port && MACH_PORT_VALID (*request_port)) {
                mach_port_mod_refs (mach_task_self(), *request_port, MACH_PORT_RIGHT_SEND, -1 );
                *request_port = MACH_PORT_NULL;
            }    
            
            /* Look up server name again without using the cached copy */
            err = kipc_client_lookup_server (cci_server_bundle_id, cci_server_path, 
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
        err = cci_stream_new (&reply_stream);
    }
    
    if (!err) {
        err = pthread_setspecific (g_reply_stream_key, reply_stream);
    }
    
    if (!err) {
        err = pthread_setspecific (g_server_died_key, &server_died);
    }
    
    if (!err) {
        mach_port_t old_notification_target = MACH_PORT_NULL;

        /* request no-senders notification so we can get a message when server dies */
        err = mach_port_request_notification (mach_task_self (), reply_port, 
                                              MACH_NOTIFY_NO_SENDERS, 1, reply_port, 
                                              MACH_MSG_TYPE_MAKE_SEND_ONCE, 
                                              &old_notification_target );
    }
    
    if (!err) {
        err = mach_msg_server_once (cci_server_demux, kkipc_max_message_size, 
                                    reply_port, MACH_MSG_TIMEOUT_NONE);
    }
    
    if (!err && server_died) {
        err = cci_check_error (ccErrServerUnavailable);
    }
    
    if (err == BOOTSTRAP_UNKNOWN_SERVICE && !in_launch_server) {
        err = ccNoError;  /* If the server is not running just return an empty stream. */
    }
    
    if (!err) {
        *out_reply_stream = reply_stream;
        reply_stream = NULL;
    }
    
    pthread_setspecific (g_reply_stream_key, NULL);
    pthread_setspecific (g_server_died_key, NULL);
    if (MACH_PORT_VALID (reply_port)) { mach_port_deallocate (mach_task_self (), reply_port); }
    if (ool_request_length          ) { vm_deallocate (mach_task_self (), (vm_address_t) ool_request, ool_request_length); }
    if (reply_stream                ) { cci_stream_release (reply_stream); }
    
    return cci_check_error (err);    
}

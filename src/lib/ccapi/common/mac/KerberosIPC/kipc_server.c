/*
 * kipc_server.c
 *
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

#include <Kerberos/kipc_server.h>
#include <Kerberos/kipc_session.h>
#include "notifyServer.h"

// Global variables for servers (used by demux)
static mach_port_t       g_service_port = MACH_PORT_NULL;
static kipc_boolean_t    g_ready_to_quit = FALSE;
static kipc_demux_proc   g_demux_proc = NULL;

#pragma mark -

// ---------------------------------------------------------------------------

mach_port_t
kipc_server_get_service_port ()
{
    return g_service_port;
}

#pragma mark -

// ---------------------------------------------------------------------------

kipc_boolean_t
kipc_server_quit (void)
{
    // Do not unregister our port because then we won't get automatically launched again.
    dprintf ("mach_server_quit_self(): quitting...");
    g_ready_to_quit = true;
    return g_ready_to_quit;
}

#pragma mark -

// ---------------------------------------------------------------------------

static kipc_boolean_t 
kipc_server_demux (mach_msg_header_t *request, mach_msg_header_t *reply) 
{
    if (mach_notify_server (request, reply) != false) {
        return true;
    } else {
        return g_demux_proc (request, reply);
    }
    return false;
}

#pragma mark -

// ---------------------------------------------------------------------------

static kipc_err_t
kipc_get_server_id (char **out_server_id)
{
    kern_return_t err = KERN_SUCCESS;
    CFBundleRef   bundle = NULL;
    CFStringRef   id_string = NULL;
    CFIndex       id_length = 0;
    char         *server_id = NULL;
    
    if (out_server_id == NULL) { err = kipc_err (EINVAL); }
    
    if (!err) {
        bundle = CFBundleGetMainBundle ();
        if (bundle == NULL) { err = ENOENT; }
    }
    
    if (!err) {
        id_string = CFBundleGetIdentifier (bundle);
        if (id_string == NULL) { err = ENOMEM; }
    }
    
    if (!err) {
        id_length = CFStringGetMaximumSizeForEncoding (CFStringGetLength (id_string), 
                                                       CFStringGetSystemEncoding ()) + 1;
        server_id = calloc (id_length, sizeof (char));
        if (server_id == NULL) { err = errno; }
    }
    
    if (!err) {
        if (!CFStringGetCString (id_string, server_id, id_length, CFStringGetSystemEncoding ())) { 
            err = ENOMEM; 
        }
    }
    
    if (!err) {
        *out_server_id = server_id;
        server_id = NULL;
    }
    
    if (server_id != NULL) { kipc_free_string (server_id); }
    
    return kipc_err (err);
}

// ---------------------------------------------------------------------------

kipc_err_t
kipc_server_run_server (kipc_demux_proc in_demux_proc)
{
    kern_return_t  err = KERN_SUCCESS;
    char          *server_id = NULL;
    char          *service_name = NULL;
    char          *lookup_name = NULL;
    mach_port_t    boot_port = MACH_PORT_NULL;
    mach_port_t    lookup_port = MACH_PORT_NULL;
    mach_port_t    notify_port = MACH_PORT_NULL;
    mach_port_t    previous_notify_port = MACH_PORT_NULL;
    mach_port_t    listen_port_set = MACH_PORT_NULL;
    
    if (in_demux_proc == NULL) { err = kipc_err (EINVAL); }
    
    // Shed root privileges if any
    if (!err && (geteuid () == 0)) {
        uid_t new_uid = kipc_session_get_server_uid ();
        if (setuid (new_uid) < 0) {
            dprintf ("%s(): setuid(%d) failed (euid is %d)", __FUNCTION__, new_uid, geteuid ());
        }
    }
    
    if (!err) {
        // Set up the globals so the demux can find them
        g_demux_proc = in_demux_proc;
    }
    
    if (!err) {
        err = kipc_get_server_id (&server_id);
    }
    
    if (!err) {
        err = kipc_get_service_name (&service_name, server_id);
    }
    
    if (!err) {
        err = kipc_get_lookup_name (&lookup_name, server_id);
    }
    
    if (!err) {
        // Get the bootstrap port
        err = task_get_bootstrap_port (mach_task_self (), &boot_port);
        dprintf ("%s(): task_get_bootstrap_port(): port is %x (err = %d '%s')", 
                 __FUNCTION__, boot_port, err, mach_error_string (err));
    }
    
    if (!err) {
        // Create the lookup port:
        err = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &lookup_port);
    }
    
    if (!err) {
        err = mach_port_insert_right (mach_task_self (), lookup_port, lookup_port, MACH_MSG_TYPE_MAKE_SEND);
    }
    
    if (!err) {
        // Register the lookup port so others can tell whether or not we are running
        err = bootstrap_register (boot_port, lookup_name, lookup_port);
        dprintf ("%s(): bootstrap_register('%s', %x): (err = %d '%s')", 
                 __FUNCTION__, lookup_name, lookup_port, err, mach_error_string (err));
    }
    
    if (!err) {
        // We are an on-demand server so our port already exists.  Just ask for it.
        err = bootstrap_check_in (boot_port, (char *) service_name, &g_service_port);
        dprintf ("%s(): bootstrap_check_in('%s'): port is %d (err = %d '%s')", 
                 __FUNCTION__, service_name, g_service_port, err, mach_error_string (err));
    }      
    
    if (!err) {
        // Create the notification port:
        err = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &notify_port);
    }    
    
    if (!err) {
        // Ask for notification when the server port has no more senders
        // A send-once right != a send right so our send-once right will not interfere with the notification
        err = mach_port_request_notification (mach_task_self (), g_service_port, MACH_NOTIFY_NO_SENDERS, true, 
                                              notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous_notify_port);
        dprintf ("%s(): requesting notification for no senders of %x returned '%s', err = %d\n",
                 __FUNCTION__, g_service_port, mach_error_string (err), err);
    }
    
    if (!err) {
        // Create the port set that the server will listen on
        err = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_PORT_SET, &listen_port_set);
    }    
    
    if (!err) {
        // Add the service port to the port set
        err = mach_port_move_member (mach_task_self (), g_service_port, listen_port_set);
    }    
    
    if (!err) {
        // Add the notify port to the port set
        err = mach_port_move_member (mach_task_self (), notify_port, listen_port_set);
    }
    
    if (!err) {
        dprintf ("%s(): \"%s\": starting up. service port = %x, bootstrap port = %x\n", 
                 __FUNCTION__, service_name, g_service_port, boot_port);
    }
    
    while (!err && !g_ready_to_quit) {
        // Handle one message at a time so we can check to see if the server wants to quit
        err = mach_msg_server_once (kipc_server_demux, kkipc_max_message_size, listen_port_set, MACH_MSG_OPTION_NONE);
    }
    
    // Regardless of whether there was an error, unregister ourselves from no senders notifications 
    // so we don't get launched again by the notification message when we quit
    // A send-once right != a send right so our send-once right will not interfere with the notification
    if (g_service_port != MACH_PORT_NULL) {
        err = mach_port_request_notification (mach_task_self (), g_service_port, MACH_NOTIFY_NO_SENDERS, 
                                              true, MACH_PORT_NULL, MACH_MSG_TYPE_MAKE_SEND_ONCE, 
                                              &previous_notify_port);
        dprintf ("%s(): removing notification for no senders of %x returned '%s', err = %d\n", 
                 __FUNCTION__, previous_notify_port, mach_error_string (err), err);
    }
    
    // Clean up the ports and strings
    if (lookup_port != MACH_PORT_NULL) { 
        kipc_err_t terr = bootstrap_register (boot_port, lookup_name, MACH_PORT_NULL);
        dprintf ("%s(): bootstrap_register('%s', MACH_PORT_NULL): (err = %d '%s')", 
                 __FUNCTION__, lookup_name, terr, mach_error_string (terr));
        mach_port_deallocate (mach_task_self (), lookup_port); 
    }
    if (notify_port     != MACH_PORT_NULL) { mach_port_deallocate (mach_task_self (), notify_port); }
    if (listen_port_set != MACH_PORT_NULL) { mach_port_deallocate (mach_task_self (), listen_port_set); }
    if (boot_port       != MACH_PORT_NULL) { mach_port_deallocate (mach_task_self (), boot_port); }
    if (lookup_name     != NULL          ) { kipc_free_string (lookup_name); }
    if (service_name    != NULL          ) { kipc_free_string (service_name); }
    if (server_id       != NULL          ) { kipc_free_string (server_id); }
    
    return kipc_err (err);    
}

#pragma mark -

// ---------------------------------------------------------------------------

kern_return_t 
do_mach_notify_port_deleted (mach_port_t notify, mach_port_name_t name)
{
    dprintf ("Received MACH_NOTIFY_PORT_DELETED... quitting self");
    kipc_server_quit ();
    return KERN_SUCCESS;
}

// ---------------------------------------------------------------------------

kern_return_t 
do_mach_notify_port_destroyed (mach_port_t notify, mach_port_t rights)
{
    dprintf ("Received MACH_NOTIFY_PORT_DESTROYED... quitting self");
    kipc_server_quit ();
    return KERN_SUCCESS;
}

// ---------------------------------------------------------------------------

kern_return_t 
do_mach_notify_no_senders (mach_port_t notify, mach_port_mscount_t mscount)
{
    dprintf ("Received MACH_NOTIFY_NO_SENDERS... quitting self");
    kipc_server_quit ();
    return KERN_SUCCESS;
}

// ---------------------------------------------------------------------------

kern_return_t 
do_mach_notify_send_once (mach_port_t notify)
{
    dprintf ("Received MACH_NOTIFY_SEND_ONCE");
    return KERN_SUCCESS;
}

// ---------------------------------------------------------------------------

kern_return_t 
do_mach_notify_dead_name (mach_port_t notify, mach_port_name_t name)
{
    dprintf ("Received MACH_NOTIFY_DEAD_NAME... quitting self");
    kipc_server_quit ();
    return KERN_SUCCESS;
}


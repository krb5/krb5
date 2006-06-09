/*
 * kipc_client.c
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

#include <Kerberos/kipc_client.h>

// ---------------------------------------------------------------------------

kipc_err_t
kipc_client_lookup_server (const char  *in_service_id,
                           boolean_t    in_launch_if_necessary,
                           mach_port_t *out_service_port) 
{
    kipc_err_t  err = 0;
    mach_port_t boot_port = MACH_PORT_NULL;
    char *service_name = NULL;
    
    if (in_service_id    == NULL) { err = kipc_err (EINVAL); }
    if (out_service_port == NULL) { err = kipc_err (EINVAL); }
    
    if (!err) {
        // Get our bootstrap port
        err = task_get_bootstrap_port (mach_task_self (), &boot_port);
    }
    
    if (!err && !in_launch_if_necessary) {
        char *lookup_name = NULL;
        mach_port_t lookup_port = MACH_PORT_NULL;
        
        err = kipc_get_lookup_name (&lookup_name, in_service_id);
        
        if (!err) {
            // Use the lookup name because the service name will return 
            // a valid port even if the server isn't running
            err = bootstrap_look_up (boot_port, lookup_name, &lookup_port);
            //dprintf ("%s(): bootstrap_look_up('%s'): port is %x (err = %d '%s')", 
            //         __FUNCTION__, lookup_name, lookup_port, err, mach_error_string (err));
        }
        
        if (lookup_name != NULL          ) { kipc_free_string (lookup_name); }
        if (lookup_port != MACH_PORT_NULL) { mach_port_deallocate (mach_task_self (), lookup_port); }
    }
    
    if (!err) {
        err = kipc_get_service_name (&service_name, in_service_id);
    }
    
    if (!err) {
        err = bootstrap_look_up (boot_port, service_name, out_service_port);
        //dprintf ("%s(): bootstrap_look_up('%s'): port is %x (err = %d '%s')", 
        //         __FUNCTION__, service_name, *out_service_port, err, mach_error_string (err));
    }
    
    if (service_name != NULL       ) { kipc_free_string (service_name); }
    if (boot_port != MACH_PORT_NULL) { mach_port_deallocate (mach_task_self (), boot_port); }
    
    if (err == BOOTSTRAP_UNKNOWN_SERVICE) {
        return err;  // Avoid spewing to the log file
    } else {
        return kipc_err (err);
    }
}

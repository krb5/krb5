/*
 * kipc_common.c
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

#include <Kerberos/kipc_common.h>
#include <Kerberos/kipc_session.h>


// ---------------------------------------------------------------------------

kipc_err_t __kipc_err (kipc_err_t in_error, const char *in_function, const char *in_file, int in_line)
{
    if (in_error && (ddebuglevel () > 0)) {
        dprintf ("%s() got %d ('%s') at %s: %d", 
                 in_function, in_error, mach_error_string (in_error), in_file, in_line);
        dprintsession ();
        //dprintbootstrap (mach_task_self ());
    }    
    return in_error;
}
// ---------------------------------------------------------------------------


const char *kipc_error_string (kipc_err_t in_error)
{
    return mach_error_string (in_error);
}

// ---------------------------------------------------------------------------

kipc_err_t kipc_get_service_name (char **out_service_name, const char *in_service_id)
{
    kipc_err_t err = 0;
    
    if (out_service_name == NULL) { err = EINVAL; }
    if (in_service_id    == NULL) { err = EINVAL; }
    
    if (!err) {
        int wrote = asprintf (out_service_name, "%s%s", in_service_id, ".ipcService");
        if (wrote < 0) { err = ENOMEM; }
    }
    
    return kipc_err (err);
}

// ---------------------------------------------------------------------------

kipc_err_t kipc_get_lookup_name (char **out_lookup_name, const char *in_service_id)
{
    kipc_err_t err = 0;
    
    if (out_lookup_name == NULL) { err = EINVAL; }
    if (in_service_id   == NULL) { err = EINVAL; }
    
    if (!err) {
        int wrote = asprintf (out_lookup_name, "%s%s", in_service_id, ".ipcLookup");
        if (wrote < 0) { err = ENOMEM; }
    }
    
    return kipc_err (err);    
}

// ---------------------------------------------------------------------------

void kipc_free_string (char *io_string)
{
    free (io_string);
}


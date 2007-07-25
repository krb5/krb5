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

struct ccs_client_d {
    ccs_pipe_t client_pipe;
    ccs_callbackref_array_t callbacks; /* references, not owner */
};

struct ccs_client_d ccs_client_initializer = { CCS_PIPE_NULL, NULL };

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_new (ccs_client_t *out_client,
                         ccs_pipe_t    in_client_pipe)
{
    cc_int32 err = ccNoError;
    ccs_client_t client = NULL;
    
    if (!out_client                     ) { err = cci_check_error (ccErrBadParam); }
    if (!ccs_pipe_valid (in_client_pipe)) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        client = malloc (sizeof (*client));
        if (client) { 
            *client = ccs_client_initializer;
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    if (!err) {
        err = ccs_callbackref_array_new (&client->callbacks);
    }
    
    if (!err) {
	err = ccs_pipe_copy (&client->client_pipe, in_client_pipe);
    }
        
    if (!err) {
        *out_client = client;
        client = NULL;
    }
    
    ccs_client_release (client);
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_release (ccs_client_t io_client)
{
    cc_int32 err = ccNoError;
    
    if (!err && io_client) {
	cc_uint64 i;
	cc_uint64 lock_count = ccs_callbackref_array_count (io_client->callbacks);
	
	for (i = 0; !err && i < lock_count; i++) {
	    ccs_callback_t callback = ccs_callbackref_array_object_at_index (io_client->callbacks, i);
	    
	    cci_debug_printf ("%s: Invalidating callback reference %p.", __FUNCTION__, callback);
	    ccs_callback_invalidate (callback);
	}
	
	ccs_callbackref_array_release (io_client->callbacks);
	ccs_pipe_release (io_client->client_pipe);
	free (io_client);
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_add_callback (ccs_client_t   io_client,
				  ccs_callback_t in_callback)
{
    cc_int32 err = ccNoError;
    
    if (!io_client  ) { err = cci_check_error (ccErrBadParam); }
    if (!in_callback) { err = cci_check_error (ccErrBadParam); }
    
     if (!err) {
        err = ccs_callbackref_array_insert (io_client->callbacks, in_callback,
					    ccs_callback_array_count (io_client->callbacks));
     }
    
    return cci_check_error (err);    
}


/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_remove_callback (ccs_client_t   io_client,
				     ccs_callback_t in_callback)
{
    cc_int32 err = ccNoError;
    cc_uint32 found_lock = 0;
    
    if (!io_client) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        cc_uint64 i;
        cc_uint64 lock_count = ccs_callbackref_array_count (io_client->callbacks);
        
        for (i = 0; !err && i < lock_count; i++) {
            ccs_callback_t callback = ccs_callbackref_array_object_at_index (io_client->callbacks, i);
            
            if (callback == in_callback) {
		cci_debug_printf ("%s: Removing callback reference %p.", __FUNCTION__, callback);
		err = ccs_callbackref_array_remove (io_client->callbacks, i);
		break;
            }
        }
    }
    
    if (!err && !found_lock) {
        cci_debug_printf ("%s: WARNING! callback not found.", __FUNCTION__);
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_client_uses_pipe (ccs_client_t  in_client,
                               ccs_pipe_t    in_pipe,
                               cc_uint32    *out_uses_pipe)
{
    cc_int32 err = ccNoError;
    
    if (!in_client    ) { err = cci_check_error (ccErrBadParam); }
    if (!in_pipe      ) { err = cci_check_error (ccErrBadParam); }
    if (!out_uses_pipe) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        *out_uses_pipe = (in_client->client_pipe == in_pipe);
    }
    
    return cci_check_error (err);    
}

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

struct ccs_lockref_d {
    ccs_client_t client_owner;
    ccs_lock_t lock;
};

struct ccs_lockref_d ccs_lockref_initializer = { NULL, NULL };

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_new (ccs_lockref_t *out_lockref,
                          ccs_client_t   in_client_owner,
                          ccs_lock_t     in_lock)
{
    cc_int32 err = ccNoError;
    ccs_lockref_t lockref = NULL;
    
    if (!out_lockref    ) { err = cci_check_error (ccErrBadParam); }
    if (!in_client_owner) { err = cci_check_error (ccErrBadParam); }
    if (!in_lock        ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        lockref = malloc (sizeof (*lockref));
        if (lockref) { 
            *lockref = ccs_lockref_initializer;
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    if (!err) {
        lockref->client_owner = in_client_owner;
        lockref->lock = in_lock;
        
        *out_lockref = lockref;
        lockref = NULL;
    }
    
    ccs_lockref_release (lockref);
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_release (ccs_lockref_t io_lockref)
{
    cc_int32 err = ccNoError;
    
    if (!io_lockref) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        if (io_lockref->lock) {
            ccs_lock_invalidate (io_lockref->lock);
        }
        free (io_lockref);
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_invalidate (ccs_lockref_t io_lockref)
{
    cc_int32 err = ccNoError;
    
    if (!io_lockref) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        io_lockref->lock = NULL; /* so we don't loop */
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_lockref_is_for_lock (ccs_lockref_t in_lockref,
                                  ccs_lock_t    in_lock,
                                  cc_uint32    *out_is_for_lock)
{
    cc_int32 err = ccNoError;
    
    if (!in_lockref     ) { err = cci_check_error (ccErrBadParam); }
    if (!in_lock        ) { err = cci_check_error (ccErrBadParam); }
    if (!out_is_for_lock) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        *out_is_for_lock = (in_lockref->lock == in_lock);
    }
    
    return cci_check_error (err);    
}

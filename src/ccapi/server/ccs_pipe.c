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
#include "ccs_os_pipe.h"

struct ccs_pipe_d {
    ccs_os_pipe_t os_pipe;
};

struct ccs_pipe_d ccs_pipe_initializer = { CCS_OS_PIPE_NULL };

/* ------------------------------------------------------------------------ */

cc_int32 ccs_pipe_new (ccs_pipe_t    *out_pipe,
                       ccs_os_pipe_t  in_os_pipe)
{
    cc_int32 err = ccNoError;
    ccs_pipe_t new_pipe = NULL;
    
    if (!out_pipe                      ) { err = cci_check_error (ccErrBadParam); }
    if (!ccs_os_pipe_valid (in_os_pipe)) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        new_pipe = malloc (sizeof (*new_pipe));
        if (new_pipe) { 
            *new_pipe = ccs_pipe_initializer;
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    if (!err) {
        err = ccs_os_pipe_copy (&new_pipe->os_pipe, in_os_pipe);
    }
    
    if (!err) {
        *out_pipe = new_pipe;
        new_pipe = NULL;
    }
    
    ccs_pipe_release (new_pipe);
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

inline cc_int32 ccs_pipe_release (ccs_pipe_t io_pipe)
{
    cc_int32 err = ccNoError;
    
    if (!io_pipe) { err = ccErrBadParam; }
    
    if (!err) {
        ccs_os_pipe_release (io_pipe->os_pipe);
        free (io_pipe);
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_pipe_copy (ccs_pipe_t *out_pipe,
                        ccs_pipe_t  in_pipe)
{
    cc_int32 err = ccNoError;
    
    if (!out_pipe) { err = cci_check_error (ccErrBadParam); }
    if (!in_pipe ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = ccs_pipe_new (out_pipe, in_pipe->os_pipe);
     }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_pipe_compare (ccs_pipe_t  in_pipe,
                           ccs_pipe_t  in_compare_to_pipe,
                           cc_uint32  *out_equal)
{
    cc_int32 err = ccNoError;
    
    if (!in_pipe           ) { err = cci_check_error (ccErrBadParam); }
    if (!in_compare_to_pipe) { err = cci_check_error (ccErrBadParam); }
    if (!out_equal         ) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = ccs_os_pipe_compare (in_pipe->os_pipe,
                                   in_compare_to_pipe->os_pipe,
                                   out_equal);
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_pipe_compare_to_os_pipe (ccs_pipe_t     in_pipe,
                                      ccs_os_pipe_t  in_compare_to_os_pipe,
                                      cc_uint32      *out_equal)
{
    cc_int32 err = ccNoError;
    
    if (in_pipe) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = ccs_os_pipe_compare (in_pipe->os_pipe,
                                   in_compare_to_os_pipe,
                                   out_equal);
    }
    
    return cci_check_error (err);    
}

/* ------------------------------------------------------------------------ */

cc_int32 ccs_pipe_valid (ccs_pipe_t in_pipe)
{
    if (in_pipe) {
        return ccs_os_pipe_valid (in_pipe->os_pipe);
    } else {
        return 0;
    }
}


/* ------------------------------------------------------------------------ */

ccs_os_pipe_t ccs_pipe_os (ccs_pipe_t in_pipe)
{
    if (in_pipe) {
        return in_pipe->os_pipe;
    } else {
        return CCS_OS_PIPE_NULL;
    }
}

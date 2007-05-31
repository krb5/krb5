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

#include "cci_common.h"
#include <CredentialsCache2.h>

/* ------------------------------------------------------------------------ */

cc_result cc_shutdown (apiCB **io_context) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_get_NC_info (apiCB    *in_context,
                          infoNC ***out_info)
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_get_change_time (apiCB     *in_context,
                              cc_time_t *out_change_time) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_int32 cc_open (apiCB       *in_context,
                  const char  *in_name,
                  cc_int32     in_version,
                  cc_uint32    in_flags,
                  ccache_p   **out_ccache) 
{    
    return CC_NOT_SUPP;
}    

/* ------------------------------------------------------------------------ */

cc_result cc_create (apiCB       *in_context,
                     const char  *in_name,
                     const char  *in_principal,
                     cc_int32     in_version,
                     cc_uint32    in_flags,
                     ccache_p   **out_ccache) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_close (apiCB     *in_context,
                    ccache_p **io_ccache) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_destroy (apiCB     *in_context,
                      ccache_p **io_ccache) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_seq_fetch_NCs_begin (apiCB       *in_context,
                                  ccache_cit **out_iterator) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

// CCache iterators need to return some ccaches twice (when v3 ccache has
// two kinds of credentials). To do that, we use a single v3 iterator, but
// sometimes don't advance it.

cc_result cc_seq_fetch_NCs_next (apiCB       *in_context,
                                 ccache_p   **out_ccache,
                                 ccache_cit  *in_iterator) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_seq_fetch_NCs_end (apiCB       *in_context,
                                ccache_cit **io_iterator) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_get_name (apiCB     *in_context,
                       ccache_p  *in_ccache,
                       char     **out_name) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_get_cred_version (apiCB    *in_context,
                               ccache_p *in_ccache,
                               cc_int32 *out_version) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_set_principal (apiCB    *in_context,
                            ccache_p *io_ccache,
                            cc_int32  in_version,
                            char     *in_principal) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_get_principal (apiCB      *in_context,
                            ccache_p   *in_ccache,
                            char      **out_principal) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_store (apiCB      *in_context,
                    ccache_p   *io_ccache,
                    cred_union  in_credentials) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_remove_cred (apiCB      *in_context,
                          ccache_p   *in_ccache,
                          cred_union  in_credentials) 
{
    return CC_NOT_SUPP;
}	

/* ------------------------------------------------------------------------ */

cc_result cc_seq_fetch_creds_begin (apiCB           *in_context,
                                    const ccache_p  *in_ccache,
                                    ccache_cit     **out_iterator) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_seq_fetch_creds_next (apiCB       *in_context,
                                   cred_union **out_creds,
                                   ccache_cit  *in_iterator) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_seq_fetch_creds_end (apiCB       *in_context,
                                  ccache_cit **io_iterator) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_free_principal (apiCB  *in_context,
                             char  **io_principal) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_free_name (apiCB  *in_context,
                        char  **io_name) 
{    
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_free_creds (apiCB       *in_context,
                         cred_union **io_credentials) 
{
    return CC_NOT_SUPP;
}

/* ------------------------------------------------------------------------ */

cc_result cc_free_NC_info (apiCB    *in_context,
                           infoNC ***io_info) 
{    
    return CC_NOT_SUPP;
}

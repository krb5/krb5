/*
 * lib/gssapi/krb5/set_ccache.c
 *
 * Copyright 1999, 2003 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
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
 *
 * Set ccache name used by gssapi, and optionally obtain old ccache
 * name.  Caller should not free returned name.
 */

#include <string.h>
#include "gssapiP_krb5.h"

OM_uint32 KRB5_CALLCONV 
gss_krb5_ccache_name(minor_status, name, out_name)
	OM_uint32 *minor_status;
	const char *name;
	const char **out_name;
{
    static char *gss_out_name = NULL;
    
    char *old_name = NULL;
    OM_uint32 err = 0;
    OM_uint32 minor = 0;

    if (out_name) {
        const char *tmp_name = NULL;

        if (!err) {
            if (GSS_ERROR(kg_get_ccache_name (&minor, &tmp_name))) {
                err = minor;
            }
        }
        
        if (!err) {
            old_name = malloc(strlen(tmp_name) + 1);
            if (old_name == NULL) {
                err = ENOMEM;
            } else {
                strcpy(old_name, tmp_name);
            }
        }
        
        if (!err) {
            char *swap = NULL;
            
            swap = gss_out_name;
            gss_out_name = old_name;
            old_name = swap;
        }            
    }
    
    if (!err) {
        if (GSS_ERROR(kg_set_ccache_name (&minor, name))) {
            err = minor;
        }
    }
    
    if (!err) {
        if (out_name) {
            *out_name = gss_out_name;
        }
    }
    
    if (old_name != NULL) {
        free (old_name);
    }
    
    *minor_status = err;
    return (*minor_status == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

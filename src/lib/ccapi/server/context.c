/* $Copyright:
 *
 * Copyright 2004 by the Massachusetts Institute of Technology.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require a
 * specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and distribute
 * this software and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of M.I.T. not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  Furthermore if you
 * modify this software you must label your software as modified software
 * and not distribute it in such a fashion that it might be confused with
 * the original MIT software. M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Individual source code files are copyright MIT, Cygnus Support,
 * OpenVision, Oracle, Sun Soft, FundsXpress, and others.
 * 
 * Project Athena, Athena, Athena MUSE, Discuss, Hesiod, Kerberos, Moira,
 * and Zephyr are trademarks of the Massachusetts Institute of Technology
 * (MIT).  No commercial use of these trademarks may be made without prior
 * written permission of MIT.
 * 
 * "Commercial use" means use of a name in a product or other for-profit
 * manner.  It does NOT prevent a commercial firm from referring to the MIT
 * trademarks in order to convey information (although in doing so,
 * recognition of their trademark status should be given).
 * $
 */

/*
 * Functions to manipulate datastore layer contexts.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "CredentialsCache.h"
#include "datastore.h"

int cc_myversion = 5;
char cc_vendor[] = "MIT C lang CCache V5";
char cc_default_ccache_name[] = "krb5cc";


cc_int32
cci_context_new( int api_version, cc_auth_info_t* auth_info, 
                 cc_session_info_t* session_info, cc_server_context_t** outContextpp )
{
    cc_server_context_t* ctx;
	
    if ( outContextpp == NULL )
        return ccErrBadParam;

	ctx = (cc_server_context_t*)malloc(sizeof(cc_server_context_t));
    if (ctx == NULL)
        return ccErrNoMem;
		
    cci_ccache_list_new(&ctx->ccaches);
    cci_generic_list_new(&ctx->active_iterators);	
    ctx->api_version = api_version;
    ctx->auth_info = auth_info;
    ctx->session_info = session_info;
    ctx->changed = time(NULL);

    *outContextpp = ctx;
    return ccNoError;
}

cc_int32
cci_context_get_default_ccache_name(cc_server_context_t* ctx, char ** outNamepp) 
{
    cc_server_ccache_t* default_ccache;

    if (outNamepp == NULL)
        return ccErrBadParam;
    
    if (ctx == NULL)
        return ccErrInvalidContext;

    if (ctx->ccaches->head != NULL) {
        default_ccache = (cc_server_ccache_t*)ctx->ccaches->head->data;
        *outNamepp = default_ccache->name;
    } else {
        *outNamepp = cc_default_ccache_name;
    }
    return ccNoError;
}


cc_int32
cci_context_find_ccache( cc_server_context_t* ctx, char *name, 
                         cc_server_ccache_t** outCcachepp )
{
    cc_ccache_iterate_t* ccache_iterator;
    cc_ccache_list_node_t* ccache_node;
    cc_server_ccache_t* ccache;
	cc_int32 code;

    if (ctx == NULL) 
        return ccErrInvalidContext;
    
    if (name == NULL)
        return ccErrInvalidString;

    if (outCcachepp == NULL)
        return ccErrBadParam;

    code = cci_ccache_list_iterator(ctx->ccaches, &ccache_iterator);
    while (cci_ccache_iterate_has_next(ccache_iterator)) {
        code = cci_ccache_iterate_next(ccache_iterator, &ccache_node);
        ccache = (cc_server_ccache_t *)ccache_node->data;
        if (strcmp(ccache->name, name) == 0)  {
            free(ccache_iterator);
            *outCcachepp = ccache;
            return ccNoError;
        }
    }
    free(ccache_iterator);
    return ccErrCCacheNotFound;
}       

cc_int32
cci_context_open_ccache( cc_server_context_t* ctx, char *name, 
                         cc_server_ccache_t** outCcachepp )
{
    return cci_context_find_ccache(ctx, name, outCcachepp);
}


cc_int32
cci_context_create_ccache( cc_server_context_t* ctx, char *name, int creds_version, 
                           char *principal, cc_server_ccache_t** outCcachepp )
{
    cc_server_ccache_t* ccache;
    cc_int32 code;

    if (ctx == NULL) 
        return ccErrInvalidContext;
    
    if (outCcachepp == NULL)
        return ccErrBadParam;

    if (name == NULL || principal == NULL)
        return ccErrInvalidString;

    if (creds_version != cc_credentials_v4 && creds_version != cc_credentials_v5 && 
         creds_version != cc_credentials_v4_v5)
        return ccErrBadCredentialsVersion;
	
    code = cci_context_find_ccache(ctx, name, &ccache);
    if (code == ccNoError) {
        code = cci_ccache_set_principal(ccache, creds_version, principal);
    } else {
        code = cci_ccache_new(name, principal, creds_version, &ccache);
        if (code != ccNoError)
            return code;	/*let caller deal with error*/

        ccache->mycontext = ctx;
        ctx->changed = time(NULL);
        cci_ccache_list_append(ctx->ccaches, ccache, NULL);

        if (ctx->ccaches->head->data == (cc_uint8 *)ccache) {
            ccache->is_default = 1;
        }
    }
    *outCcachepp = ccache;
    return ccNoError;
}

cc_int32
cci_context_create_default_ccache( cc_server_context_t* ctx, int creds_version, 
                                   char *principal, cc_server_ccache_t** outCcachepp )
{
    cc_server_ccache_t* ccache, *old_default;
    cc_int32 code;

    if (ctx == NULL) 
        return ccErrInvalidContext;
    
    if (outCcachepp == NULL)
        return ccErrBadParam;

    if (principal == NULL)
        return ccErrInvalidString;

    if (creds_version != cc_credentials_v4 && creds_version != cc_credentials_v5 && 
         creds_version != cc_credentials_v4_v5)
        return ccErrBadCredentialsVersion;
	
    code = cci_context_find_ccache(ctx, cc_default_ccache_name, &ccache);
    if (code == ccNoError) {
        cci_ccache_set_principal(ccache, creds_version, principal);
    } else {
        code = cci_ccache_new(cc_default_ccache_name, principal, creds_version, &ccache);
        if (code != ccNoError)
            return code;	/*let caller deal with error*/

        ccache->mycontext = ctx;
        ccache->is_default = 1;
        ctx->changed = time(NULL);
	
        if (ctx->ccaches->head != NULL) {
            old_default = (cc_server_ccache_t *)ctx->ccaches->head->data;
            old_default->is_default = 0;
            old_default->last_default = time(NULL);
        }

        cci_ccache_list_prepend(ctx->ccaches, ccache, NULL);
    }
    *outCcachepp = ccache;
    return ccNoError;
}

cc_int32
cci_context_ccache_iterator(cc_server_context_t* ctx, cc_ccache_iterate_t** iterpp) 
{
    cc_ccache_iterate_t* ccache_iterator;
    cc_int32 code;

    if (ctx == NULL) 
        return ccErrInvalidContext;
    
    if (iterpp == NULL)
        return ccErrBadParam;

    code = cci_ccache_list_iterator(ctx->ccaches, &ccache_iterator);
    if (code != ccNoError)
        return code;
    cci_generic_list_prepend(ctx->active_iterators, ccache_iterator, sizeof(cc_ccache_iterate_t), NULL);

    *iterpp = ccache_iterator;
    return ccNoError;
}

cc_int32 
cci_context_compare(cc_server_context_t* a, cc_server_context_t* b) 
{
    if (a == b)
        return 1;
    else
        return 0;
}

cc_int32 
cci_context_destroy(cc_server_context_t* ctx) 
{
    cc_ccache_iterate_t* ccache_iterator;
    cc_ccache_list_node_t* ccache_node;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    if (ctx == NULL) 
        return ccErrInvalidContext;

    cci_generic_list_destroy(ctx->active_iterators);
	
    code = cci_ccache_list_iterator(ctx->ccaches, &ccache_iterator);
    while (cci_ccache_iterate_has_next(ccache_iterator)) {
        code = cci_ccache_iterate_next(ccache_iterator, &ccache_node);
        ccache = (cc_server_ccache_t *)ccache_node->data;
        ccache_node->data = NULL;
        cci_ccache_destroy(ccache);
    }
    cci_ccache_list_destroy(ctx->ccaches);

    return ccNoError;
}

cc_int32 
cci_context_rem_ccache(cc_server_context_t* ctx, cc_server_ccache_t* ccache) 
{
    cc_ccache_iterate_t* ccache_iterator;
    cc_ccache_iterate_t* active_ccache_iterator;
    cc_ccache_list_node_t* ccache_node;
    cc_server_ccache_t* list_ccache;
    cc_generic_list_node_t* gen_node;
    cc_generic_iterate_t* gen_iterator;
    cc_int32 code;

    if (ctx == NULL) 
        return ccErrInvalidContext;

    if (ccache == NULL) 
        return ccErrInvalidCCache;

    code = cci_ccache_list_iterator(ctx->ccaches, &ccache_iterator);
    while (cci_ccache_iterate_has_next(ccache_iterator)) {
        code = cci_ccache_iterate_next(ccache_iterator, &ccache_node);
        list_ccache = (cc_server_ccache_t *)ccache_node->data;

        if (list_ccache == ccache) {
            code = cci_generic_list_iterator(ctx->active_iterators, &gen_iterator);
            while (cci_generic_iterate_has_next(gen_iterator)) {
                code = cci_generic_iterate_next(gen_iterator, &gen_node);
                active_ccache_iterator = (cc_server_ccache_t *)gen_node->data;
                if (active_ccache_iterator->next == ccache_node) {
                    active_ccache_iterator->next = active_ccache_iterator->next->next;
                }
            }
            free(gen_iterator);
            code = cci_ccache_list_remove_element(ctx->ccaches, ccache_node);
            break;
        }
    }
    free(ccache_iterator);
    return ccNoError;
}


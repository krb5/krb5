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

/* context.c */                                                 

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "context.h"
#include "msg.h"
#include "msg_headers.h"

cc_int32
cc_int_context_new( cc_context_t * pcontext, cc_handle handle, cc_uint32 version )
{
    cc_int_context_t context = (cc_int_context_t)malloc(sizeof(cc_int_context_d));
    if (context == NULL)
        return ccErrNoMem;

    context->functions = (cc_context_f*)malloc(sizeof(cc_context_f));
    if (context->functions == NULL) {
        free(context);
        return ccErrNoMem;
    }

    context->functions->release = cc_int_context_release;
    context->functions->get_change_time = cc_int_context_get_change_time;
    context->functions->get_default_ccache_name = cc_int_context_get_default_ccache_name;
    context->functions->open_ccache = cc_int_context_open_ccache;
    context->functions->open_default_ccache = cc_int_context_open_default_ccache;
    context->functions->create_ccache = cc_int_context_create_ccache;
    context->functions->create_default_ccache = cc_int_context_create_default_ccache;
    context->functions->create_new_ccache = cc_int_context_create_new_ccache;
    context->functions->new_ccache_iterator = cc_int_context_new_ccache_iterator;
    context->functions->lock = cc_int_context_lock;
    context->functions->unlock = cc_int_context_unlock;
    context->functions->compare = cc_int_context_compare;

    context->magic = CC_CONTEXT_MAGIC;
    context->handle = handle;
    context->api_version = version;

    *pcontext = (cc_context_t)context;
    return ccNoError;
}

cc_int32    
cc_int_context_release( cc_context_t context )
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ctx_release_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( context == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_release_t*)malloc(sizeof(ccmsg_ctx_release_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_context->handle;

    code = cci_msg_new(ccmsg_CTX_RELEASE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_release_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    free(int_context->functions);
    free(int_context);
    return code;
}

cc_int32
cc_int_context_get_change_time( cc_context_t context,
                                cc_time_t* time)
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ctx_get_change_time_t *request_header;
    cc_msg_t        *response;
    ccmsg_ctx_get_change_time_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || time == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_get_change_time_t*)malloc(sizeof(ccmsg_ctx_get_change_time_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_context->handle;

    code = cci_msg_new(ccmsg_CTX_GET_CHANGE_TIME, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_get_change_time_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ctx_get_change_time_resp_t*)response->header;
        *time = response_header->time;
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_get_default_ccache_name( cc_context_t context,
                                        cc_string_t* name )
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ctx_get_default_ccache_name_t *request_header;
    cc_msg_t        *response;
    ccmsg_ctx_get_default_ccache_name_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || name == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_get_default_ccache_name_t*)malloc(sizeof(ccmsg_ctx_get_default_ccache_name_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_context->handle;

    code = cci_msg_new(ccmsg_CTX_GET_DEFAULT_CCACHE_NAME, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_get_default_ccache_name_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        char * string;
        response_header = (ccmsg_ctx_get_default_ccache_name_resp_t*)response->header;
        code = cci_msg_retrieve_blob(response, response_header->name_offset, 
                                     response_header->name_len, &string);
        if (code == ccNoError) {
            code = cc_string_new(&name, string);
            free(string);
        }
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_compare( cc_context_t context,
                        cc_context_t compare_to,
                        cc_uint32* equal )
{
    cc_int_context_t int_context, int_compare_to;
    cc_msg_t        *request;
    ccmsg_ctx_compare_t *request_header;
    cc_msg_t        *response;
    ccmsg_ctx_compare_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || compare_to == NULL || 
         equal == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;
    int_compare_to = (cc_int_context_t)compare_to;

    if ( int_context->magic != CC_CONTEXT_MAGIC ||
         int_compare_to->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_compare_t*)malloc(sizeof(ccmsg_ctx_compare_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx1 = int_context->handle;
    request_header->ctx2 = int_compare_to->handle;

    code = cci_msg_new(ccmsg_CTX_COMPARE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_compare_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ctx_compare_resp_t*)response->header;
        *equal = response_header->is_equal;
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}


cc_int32
cc_int_context_new_ccache_iterator( cc_context_t context,
                                    cc_ccache_iterator_t* iterator )
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ctx_new_ccache_iterator_t *request_header;
    cc_msg_t        *response;
    ccmsg_ctx_new_ccache_iterator_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || iterator == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_new_ccache_iterator_t*)malloc(sizeof(ccmsg_ctx_new_ccache_iterator_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_context->handle;

    code = cci_msg_new(ccmsg_CTX_NEW_CCACHE_ITERATOR, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_new_ccache_iterator_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ctx_new_ccache_iterator_resp_t*)response->header;
        code = cc_int_ccache_iterator_new(iterator, int_context->handle, response_header->iterator);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_open_ccache( cc_context_t context,
                            const char* name,
                            cc_ccache_t* ccache )
{
    cc_uint32 blob_pos;
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ccache_open_t *request_header;
    cc_msg_t        *response;
    ccmsg_ccache_open_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || name == NULL || ccache == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ccache_open_t*)malloc(sizeof(ccmsg_ccache_open_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_OPEN, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_data_blob(request, (void *)name, strlen(name) + 1, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    
    request_header->ctx = int_context->handle;
    request_header->name_offset = blob_pos;
    request_header->name_len = strlen(name) + 1;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_open_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ccache_open_resp_t*)response->header;
        code = cc_cache_new(ccache, response_header->ccache);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_open_default_ccache( cc_context_t context,
                                    cc_ccache_t* ccache)
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ccache_open_default_t *request_header;
    cc_msg_t        *response;
    ccmsg_ccache_open_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || ccache == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ccache_open_default_t*)malloc(sizeof(ccmsg_ccache_open_default_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_OPEN_DEFAULT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_context->handle;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_open_default_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ccache_open_resp_t*)response->header;
        code = cc_cache_new(ccache, response_header->ccache);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_create_ccache( cc_context_t context,
                              const char* name,
                              cc_uint32 cred_vers,
                              const char* principal, 
                              cc_ccache_t* ccache )
{
    cc_uint32 blob_pos;
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ccache_create_t *request_header;
    cc_msg_t        *response;
    ccmsg_ccache_create_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL || name == NULL || 
         cred_vers == 0 || cred_vers > cc_credentials_v4_v5 ||
         principal == NULL || ccache == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ccache_create_t*)malloc(sizeof(ccmsg_ccache_create_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_CREATE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_data_blob(request, (void *)name, strlen(name) + 1, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    
    request_header->ctx = int_context->handle;
    request_header->version = cred_vers;
    request_header->name_offset = blob_pos;
    request_header->name_len = strlen(name) + 1;

    code = cci_msg_add_data_blob(request, (void *)principal, strlen(principal) + 1, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    request_header->principal_offset = blob_pos;
    request_header->principal_len = strlen(principal) + 1;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_create_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ccache_create_resp_t*)response->header;
        code = cc_cache_new(ccache, response_header->ccache);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_create_default_ccache( cc_context_t context,
                                      cc_uint32 cred_vers,
                                      const char* principal, 
                                      cc_ccache_t* ccache )
{
    cc_uint32 blob_pos;
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ccache_create_default_t *request_header;
    cc_msg_t        *response;
    ccmsg_ccache_create_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL ||
         cred_vers == 0 || cred_vers > cc_credentials_v4_v5 ||
         principal == NULL || ccache == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ccache_create_default_t*)malloc(sizeof(ccmsg_ccache_create_default_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_CREATE_DEFAULT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_context->handle;
    request_header->version = cred_vers;

    code = cci_msg_add_data_blob(request, (void *)principal, strlen(principal) + 1, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    request_header->principal_offset = blob_pos;
    request_header->principal_len = strlen(principal) + 1;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_create_default_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ccache_create_resp_t*)response->header;
        code = cc_cache_new(ccache, response_header->ccache);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_create_new_ccache( cc_context_t context,
                                  cc_uint32 cred_vers,
                                  const char* principal, 
                                  cc_ccache_t* ccache )
{
    cc_uint32 blob_pos;
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ccache_create_unique_t *request_header;
    cc_msg_t        *response;
    ccmsg_ccache_create_resp_t *response_header;
    cc_int32 code;

    if ( context == NULL ||
         cred_vers == 0 || cred_vers > cc_credentials_v4_v5 ||
         principal == NULL || ccache == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ccache_create_unique_t*)malloc(sizeof(ccmsg_ccache_create_unique_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_CREATE_UNIQUE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_context->handle;
    request_header->version = cred_vers;

    code = cci_msg_add_data_blob(request, (void *)principal, strlen(principal) + 1, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    request_header->principal_offset = blob_pos;
    request_header->principal_len = strlen(principal) + 1;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_create_unique_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_ccache_create_resp_t*)response-> header;
        code = cc_cache_new(ccache, response_header->ccache);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}
 
cc_int32
cc_int_context_lock( cc_context_t context,
                     cc_uint32 lock_type,
                     cc_uint32 block )
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ctx_lock_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( context == NULL || 
         (lock_type != cc_lock_read && lock_type != cc_lock_write) ||
         (block != cc_lock_block && block != cc_lock_noblock) )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_lock_t*)malloc(sizeof(ccmsg_ctx_lock_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CTX_LOCK, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_context->handle;
    request_header->lock_type;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_lock_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;

        // TODO: if (block == cc_lock_block) .....
    } else if (response->type == ccmsg_ACK) {
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_unlock( cc_context_t context )
{
    cc_int_context_t int_context;
    cc_msg_t        *request;
    ccmsg_ctx_unlock_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( context == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    request_header = (ccmsg_ctx_unlock_t*)malloc(sizeof(ccmsg_ctx_unlock_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CTX_UNLOCK, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_context->handle;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ctx_unlock_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_clone( cc_context_t      inContext,
                      cc_context_t*     outContext,
                      cc_int32          requestedVersion,
                      cc_int32*         supportedVersion,
                      char const**      vendor )
{
    cc_int_context_t int_context, new_context;
    static char vendor_st[128] = "";
    cc_msg_t     *request;
    ccmsg_clone_t *request_header;
    cc_msg_t     *response;
    ccmsg_clone_resp_t *response_header;
    cc_int32 code;

    if ( inContext == NULL ||
         outContext == NULL ||
         supportedVersion == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    if ((requestedVersion != ccapi_version_2) &&
         (requestedVersion != ccapi_version_3) &&
         (requestedVersion != ccapi_version_4) &&
         (requestedVersion != ccapi_version_5)) {

        if (supportedVersion != NULL) {
            *supportedVersion = ccapi_version_5;
        }
        return ccErrBadAPIVersion;
    }   

    request_header = (ccmsg_clone_t*)malloc(sizeof(ccmsg_clone_t));
    if (request_header == NULL)
        return ccErrNoMem;

    request_header->ctx = int_context->handle;
    request_header->in_version = requestedVersion;

    code = cci_msg_new(ccmsg_INIT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_init_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        response_header = (ccmsg_clone_resp_t *)response->header;
        *supportedVersion = response_header->out_version;
        code = cc_int_context_new(outContext, response_header->out_ctx, response_header->out_version);

        if (!vendor_st[0]) {
            char * string;
            code = cci_msg_retrieve_blob(response, response_header->vendor_offset, response_header->vendor_length, &string);
            strncpy(vendor_st, string, sizeof(vendor_st)-1);
            vendor_st[sizeof(vendor_st)-1] = '\0';
            free(string);
        } 
        *vendor = vendor_st;

        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_context_get_version( cc_context_t        context,
                            cc_int32*           version )
{
    cc_int_context_t int_context;
    cc_int32 code;

    if ( context == NULL ||
         version == NULL )
        return ccErrBadParam;

    int_context = (cc_int_context_t)context;

    if ( int_context->magic != CC_CONTEXT_MAGIC )
        return ccErrInvalidContext;

    *version = int_context->api_version;
    return ccNoError;
}



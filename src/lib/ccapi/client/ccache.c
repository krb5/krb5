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


/* ccache.c */

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "credentials.h"
#include "ccache.h"
#include "msg.h"
#include "msg_headers.h"

cc_int32
cc_int_ccache_new( cc_ccache_t * pccache, cc_handle hctx, cc_handle hccache )
{
    cc_int_ccache_t ccache = (cc_int_ccache_t)malloc(sizeof(cc_int_ccache_d));
    if ( ccache == NULL )
        return ccErrNoMem;

    ccache->functions = (cc_ccache_f*)malloc(sizeof(cc_ccache_f));
    if ( ccache->functions == NULL ) {
        free(ccache);
        return ccErrNoMem;
    }

    ccache->functions->release = cc_int_ccache_release;
    ccache->functions->destroy = cc_int_ccache_destroy;
    ccache->functions->set_default = cc_int_ccache_set_default;
    ccache->functions->get_credentials_version = cc_int_ccache_get_credentials_version;
    ccache->functions->get_name = cc_int_ccache_get_name;
    ccache->functions->get_principal = cc_int_ccache_get_principal;
    ccache->functions->set_principal = cc_int_ccache_set_principal;
    ccache->functions->store_credentials = cc_int_ccache_store_credentials;
    ccache->functions->remove_credentials = cc_int_ccache_remove_credentials;
    ccache->functions->new_credentials_iterator = cc_int_ccache_new_credentials_iterator;
    ccache->functions->move = cc_int_ccache_move;
    ccache->functions->lock = cc_int_ccache_lock;
    ccache->functions->unlock = cc_int_ccache_unlock;
    ccache->functions->get_last_default_time = cc_int_ccache_get_last_default_time;
    ccache->functions->get_change_time = cc_int_ccache_get_change_time;
    ccache->functions->compare = cc_int_ccache_compare;
    ccache->functions->get_kdc_time_offset = cc_int_ccache_get_kdc_time_offset;
    ccache->functions->set_kdc_time_offset = cc_int_ccache_set_kdc_time_offset;
    ccache->functions->clear_kdc_time_offset = cc_int_ccache_clear_kdc_time_offset;

    ccache->magic = CC_CCACHE_MAGIC;
    ccache->ctx = hctx;
    ccache->handle = hccache;

    *pccache = (cc_ccache_t)ccache;

    return ccNoError;
}

cc_int32    
cc_int_ccache_release( cc_ccache_t ccache )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_release_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_release_t*)malloc(sizeof(ccmsg_ccache_release_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_RELEASE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_release_t));

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
    free(int_ccache->functions);
    free(int_ccache);
    return code;
}


cc_int32    
cc_int_ccache_destroy( cc_ccache_t ccache )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_destroy_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_destroy_t*)malloc(sizeof(ccmsg_ccache_destroy_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_DESTROY, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_destroy_t));

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
    free(ccache);
    return code;
}


cc_int32
cc_int_ccache_set_default( cc_ccache_t ccache )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_set_default_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_set_default_t*)malloc(sizeof(ccmsg_ccache_set_default_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_SET_DEFAULT, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_set_default_t));

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
cc_int_ccache_get_credentials_version( cc_ccache_t ccache,
                                   cc_uint32* credentials_version)
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_get_creds_version_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_get_creds_version_t*)malloc(sizeof(ccmsg_ccache_get_creds_version_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_GET_CREDS_VERSION, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_get_creds_version_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        ccmsg_ccache_get_creds_version_resp_t * response_header = (ccmsg_ccache_get_creds_version_resp_t*)response->header;
        *credentials_version = response_header->version;
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_ccache_get_name( cc_ccache_t ccache,
                    cc_string_t* name )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_get_name_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_get_name_t*)malloc(sizeof(ccmsg_ccache_get_name_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_GET_NAME, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_get_name_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        char * string;
        ccmsg_ccache_get_name_resp_t * response_header = (ccmsg_ccache_get_name_resp_t*)response->header;
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
cc_int_ccache_get_principal( cc_ccache_t ccache,
                        cc_uint32 credentials_version,
                        cc_string_t* principal )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_get_principal_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_get_principal_t*)malloc(sizeof(ccmsg_ccache_get_principal_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->version = credentials_version;

    code = cci_msg_new(ccmsg_CCACHE_GET_PRINCIPAL, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_get_principal_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        char * string;
        ccmsg_ccache_get_principal_resp_t * response_header = (ccmsg_ccache_get_principal_resp_t*)response->header;
        code = cci_msg_retrieve_blob(response, response_header->principal_offset, 
                                      response_header->principal_len, &string);
        if (code == ccNoError) {
            code = cc_string_new(&principal, string);
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
cc_int_ccache_set_principal( cc_ccache_t ccache,
                         cc_uint32 credentials_version,
                         const char* principal )
{
    cc_uint32   blob_pos;
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_set_principal_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_set_principal_t*)malloc(sizeof(ccmsg_ccache_set_principal_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->version = credentials_version;

    code = cci_msg_new(ccmsg_CCACHE_GET_PRINCIPAL, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_data_blob(request, (void*)principal, strlen(principal) + 1, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    
    request_header->principal_offset = blob_pos;
    request_header->principal_len = strlen(principal) + 1;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_set_principal_t));

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
cc_int_ccache_new_credentials_iterator( cc_ccache_t ccache,
                                        cc_credentials_iterator_t* iterator )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_creds_iterator_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_creds_iterator_t*)malloc(sizeof(ccmsg_ccache_creds_iterator_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_CREDS_ITERATOR, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_creds_iterator_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        ccmsg_ccache_creds_iterator_resp_t * response_header = (ccmsg_ccache_creds_iterator_resp_t*)response->header;
        code = cc_int_credentials_iterator_new(iterator, response_header->iterator);
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_ccache_store_credentials( cc_ccache_t ccache,
                             const cc_credentials_union* credentials )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_store_creds_t *request_header;
    cc_msg_t        *response;
    char            *flat_cred = 0;
    cc_uint32       flat_cred_len = 0;
    cc_uint32       blob_pos;
    cc_int32 code;

    if ( ccache == NULL || credentials == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_store_creds_t*)malloc(sizeof(ccmsg_ccache_store_creds_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_STORE_CREDS, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    switch ( credentials->version ) {
    case cc_credentials_v4:
        code = cci_creds_v4_marshall(credentials->credentials.credentials_v4, &flat_cred, &flat_cred_len);
        break;
    case cc_credentials_v5:
        code = cci_creds_v5_marshall(credentials->credentials.credentials_v5, &flat_cred, &flat_cred_len);
        break;
    default:
        cci_msg_destroy(request);
        free(request_header);
        return ccErrBadCredentialsVersion;
    }
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }

    code = cci_msg_add_data_blob(request, (void*)flat_cred, flat_cred_len, &blob_pos);
    if (code != ccNoError) {
        cci_msg_destroy(request);
        free(request_header);
        return code;
    }
    
    request_header->creds_version = credentials->version;
    request_header->creds_offset = blob_pos;
    request_header->creds_len = flat_cred_len;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_store_creds_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    free(flat_cred);
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_ccache_remove_credentials( cc_ccache_t ccache,
                              cc_credentials_t credentials )
{
    cc_int_ccache_t int_ccache;
    cc_int_credentials_t  int_creds;
    cc_msg_t        *request;
    ccmsg_ccache_rem_creds_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL || credentials == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;
    int_creds  = (cc_int_credentials_t)credentials;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    if ( int_creds->magic != CC_CREDS_MAGIC )
        return ccErrInvalidCredentials;

    request_header = (ccmsg_ccache_rem_creds_t*)malloc(sizeof(ccmsg_ccache_rem_creds_t));
    if (request_header == NULL)
        return ccErrNoMem;
    
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->creds  = int_creds->handle;

    code = cci_msg_new(ccmsg_CCACHE_REM_CREDS, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_rem_creds_t));

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
cc_int_ccache_move( cc_ccache_t source,
                    cc_ccache_t destination )
{
    cc_int_ccache_t int_ccache_source;
    cc_int_ccache_t int_ccache_dest;
    cc_msg_t        *request;
    ccmsg_ccache_move_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( source == NULL || destination == NULL )
        return ccErrBadParam;

    int_ccache_source = (cc_int_ccache_t)source;
    int_ccache_dest = (cc_int_ccache_t)destination;

    if ( int_ccache_source->magic != CC_CCACHE_MAGIC ||
         int_ccache_dest->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    if ( int_ccache_source->ctx != int_ccache_dest->ctx )
        return ccErrInvalidContext;

    request_header = (ccmsg_ccache_move_t*)malloc(sizeof(ccmsg_ccache_move_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_MOVE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_ccache_source->ctx;
    request_header->ccache_source = int_ccache_source->handle;
    request_header->ccache_dest = int_ccache_dest->handle;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_move_t));

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

cc_int_ccache_lock( cc_ccache_t ccache,
                cc_uint32 lock_type,
                cc_uint32 block )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_lock_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL || 
         (lock_type != cc_lock_read && lock_type != cc_lock_write) ||
         (block != cc_lock_block && block != cc_lock_noblock) )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_lock_t*)malloc(sizeof(ccmsg_ccache_lock_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_LOCK, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->lock_type;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_lock_t));

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
cc_int_ccache_unlock( cc_ccache_t ccache )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_unlock_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_unlock_t*)malloc(sizeof(ccmsg_ccache_unlock_t));
    if (request_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_CCACHE_UNLOCK, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_unlock_t));

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
cc_int_ccache_get_last_default_time( cc_ccache_t ccache,
                                     cc_time_t* time_offset )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_get_last_default_time_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_get_last_default_time_t*)malloc(sizeof(ccmsg_ccache_get_last_default_time_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_GET_LAST_DEFAULT_TIME, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_get_last_default_time_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        ccmsg_ccache_get_last_default_time_resp_t * response_header = (ccmsg_ccache_get_last_default_time_resp_t*)response->header;
        *time_offset = response_header->last_default_time;
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_ccache_get_change_time( cc_ccache_t ccache,
                           cc_time_t* time )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_get_change_time_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_get_change_time_t*)malloc(sizeof(ccmsg_ccache_get_change_time_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;

    code = cci_msg_new(ccmsg_CCACHE_GET_CHANGE_TIME, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_get_change_time_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        ccmsg_ccache_get_change_time_resp_t * response_header = (ccmsg_ccache_get_change_time_resp_t*)response->header;
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
cc_int_ccache_compare( cc_ccache_t ccache,
                   cc_ccache_t compare_to,
                   cc_uint32* equal )
{
    cc_int_ccache_t int_ccache;
    cc_int_ccache_t int_compare_to;
    cc_msg_t        *request;
    ccmsg_ccache_compare_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;
    int_compare_to = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC ||
         int_compare_to->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_compare_t*)malloc(sizeof(ccmsg_ccache_compare_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache1 = int_ccache->handle;
    request_header->ccache2 = int_compare_to->handle;

    code = cci_msg_new(ccmsg_CCACHE_COMPARE, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_compare_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        ccmsg_ccache_compare_resp_t * response_header = (ccmsg_ccache_compare_resp_t*)response->header;
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
cc_int_ccache_get_kdc_time_offset( cc_ccache_t ccache,
                               cc_int32	credentials_version,
                               cc_time_t*	time_offset )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_get_kdc_time_offset_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_get_kdc_time_offset_t*)malloc(sizeof(ccmsg_ccache_get_kdc_time_offset_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->creds_version = credentials_version;

    code = cci_msg_new(ccmsg_CCACHE_GET_KDC_TIME_OFFSET, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_get_kdc_time_offset_t));

    code = cci_perform_rpc(request, &response);

    if (response->type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = nack_header->err_code;
    } else if (response->type == ccmsg_ACK) {
        ccmsg_ccache_get_kdc_time_offset_resp_t * response_header = (ccmsg_ccache_get_kdc_time_offset_resp_t*)response->header;
        *time_offset = response_header->offset;
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }
    cci_msg_destroy(request);
    cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_ccache_set_kdc_time_offset( cc_ccache_t ccache,
                               cc_int32	credentials_version,
                               cc_time_t	time_offset )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_set_kdc_time_offset_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_set_kdc_time_offset_t*)malloc(sizeof(ccmsg_ccache_set_kdc_time_offset_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->creds_version = credentials_version;

    code = cci_msg_new(ccmsg_CCACHE_SET_KDC_TIME_OFFSET, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_set_kdc_time_offset_t));

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
cc_int_ccache_clear_kdc_time_offset( cc_ccache_t	ccache,
                                 cc_int32	credentials_version )
{
    cc_int_ccache_t int_ccache;
    cc_msg_t        *request;
    ccmsg_ccache_clear_kdc_time_offset_t *request_header;
    cc_msg_t        *response;
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrBadParam;

    int_ccache = (cc_int_ccache_t)ccache;

    if ( int_ccache->magic != CC_CCACHE_MAGIC )
        return ccErrInvalidCCache;

    request_header = (ccmsg_ccache_clear_kdc_time_offset_t*)malloc(sizeof(ccmsg_ccache_clear_kdc_time_offset_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = int_ccache->ctx;
    request_header->ccache = int_ccache->handle;
    request_header->creds_version = credentials_version;

    code = cci_msg_new(ccmsg_CCACHE_CLEAR_KDC_TIME_OFFSET, &request);
    if (code != ccNoError) {
        free(request_header);
        return code;
    }

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_ccache_clear_kdc_time_offset_t));

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



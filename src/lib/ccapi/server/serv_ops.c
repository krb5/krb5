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
 * Server side implementation of each API function.
 */

#include "CredentialsCache.h"
#include "serv_ops.h"
#include "datastore.h"
#include "rpc_auth.h"
#include "msg_headers.h"

#include <stdlib.h>
#include <string.h>

cc_context_list_head_t* AllContexts = NULL;
type_to_op_mapping_t* TypeToOpMapping = NULL;

extern int cc_err_code;
extern int cc_myversion;
extern char cc_vendor[];

cc_int32 
cci_serv_initialize(void) 
{
    cc_int32 code;

    code = cci_context_list_new(&AllContexts);
    if ( code != ccNoError )
        return code;
    TypeToOpMapping = (type_to_op_mapping_t*)malloc(sizeof(type_to_op_mapping_t));
    if (TypeToOpMapping == NULL) {
        cci_context_list_destroy(AllContexts);
        return ccErrNoMem;
    }

    TypeToOpMapping->operations[ccmsg_INIT] = ccop_INIT;
    TypeToOpMapping->operations[ccmsg_CTX_RELEASE] = ccop_CTX_RELEASE;
    TypeToOpMapping->operations[ccmsg_CTX_GET_CHANGE_TIME] = ccop_CTX_GET_CHANGE_TIME;
    TypeToOpMapping->operations[ccmsg_CTX_GET_DEFAULT_CCACHE_NAME] = ccop_CTX_GET_DEFAULT_CCACHE_NAME;
    TypeToOpMapping->operations[ccmsg_CTX_COMPARE] = ccop_CTX_COMPARE;
    TypeToOpMapping->operations[ccmsg_CTX_NEW_CCACHE_ITERATOR] = ccop_CTX_NEW_CCACHE_ITERATOR;
    TypeToOpMapping->operations[ccmsg_CTX_LOCK] = ccop_CTX_LOCK;
    TypeToOpMapping->operations[ccmsg_CTX_UNLOCK] = ccop_CTX_UNLOCK;
    TypeToOpMapping->operations[ccmsg_CTX_CLONE] = ccop_CTX_CLONE;
    TypeToOpMapping->operations[ccmsg_CCACHE_OPEN] = ccop_CCACHE_OPEN;
    TypeToOpMapping->operations[ccmsg_CCACHE_OPEN_DEFAULT] = ccop_CCACHE_OPEN_DEFAULT;
    TypeToOpMapping->operations[ccmsg_CCACHE_CREATE] = ccop_CCACHE_CREATE;
    TypeToOpMapping->operations[ccmsg_CCACHE_CREATE_DEFAULT] = ccop_CCACHE_CREATE_DEFAULT;
    TypeToOpMapping->operations[ccmsg_CCACHE_CREATE_UNIQUE] = ccop_CCACHE_CREATE_UNIQUE;
    TypeToOpMapping->operations[ccmsg_CCACHE_RELEASE] = ccop_CCACHE_RELEASE;
    TypeToOpMapping->operations[ccmsg_CCACHE_DESTROY] = ccop_CCACHE_DESTROY;
    TypeToOpMapping->operations[ccmsg_CCACHE_SET_DEFAULT] = ccop_CCACHE_SET_DEFAULT;
    TypeToOpMapping->operations[ccmsg_CCACHE_GET_CREDS_VERSION] = ccop_CCACHE_GET_CREDS_VERSION;
    TypeToOpMapping->operations[ccmsg_CCACHE_GET_NAME] = ccop_CCACHE_GET_NAME;
    TypeToOpMapping->operations[ccmsg_CCACHE_GET_PRINCIPAL] = ccop_CCACHE_GET_PRINCIPAL;
    TypeToOpMapping->operations[ccmsg_CCACHE_SET_PRINCIPAL] = ccop_CCACHE_SET_PRINCIPAL;
    TypeToOpMapping->operations[ccmsg_CCACHE_CREDS_ITERATOR] = ccop_CCACHE_CREDS_ITERATOR;
    TypeToOpMapping->operations[ccmsg_CCACHE_STORE_CREDS] = ccop_CCACHE_STORE_CREDS;
    TypeToOpMapping->operations[ccmsg_CCACHE_REM_CREDS] = ccop_CCACHE_REM_CREDS;
    TypeToOpMapping->operations[ccmsg_CCACHE_GET_LAST_DEFAULT_TIME] = ccop_CCACHE_GET_LAST_DEFAULT_TIME;
    TypeToOpMapping->operations[ccmsg_CCACHE_GET_CHANGE_TIME] = ccop_CCACHE_GET_CHANGE_TIME;
    TypeToOpMapping->operations[ccmsg_CCACHE_COMPARE] = ccop_CCACHE_COMPARE;
    TypeToOpMapping->operations[ccmsg_CCACHE_GET_KDC_TIME_OFFSET] = ccop_CCACHE_GET_KDC_TIME_OFFSET;
    TypeToOpMapping->operations[ccmsg_CCACHE_SET_KDC_TIME_OFFSET] = ccop_CCACHE_SET_KDC_TIME_OFFSET;
    TypeToOpMapping->operations[ccmsg_CCACHE_CLEAR_KDC_TIME_OFFSET] = ccop_CCACHE_CLEAR_KDC_TIME_OFFSET;
    TypeToOpMapping->operations[ccmsg_CCACHE_ITERATOR_RELEASE] = ccop_CCACHE_ITERATOR_RELEASE;
    TypeToOpMapping->operations[ccmsg_CCACHE_ITERATOR_NEXT] = ccop_CCACHE_ITERATOR_NEXT;
    TypeToOpMapping->operations[ccmsg_CREDS_ITERATOR_RELEASE] = ccop_CREDS_ITERATOR_RELEASE;
    TypeToOpMapping->operations[ccmsg_CREDS_ITERATOR_NEXT] = ccop_CREDS_ITERATOR_NEXT;
    TypeToOpMapping->operations[ccmsg_CREDS_RELEASE] = ccop_CREDS_RELEASE;

    return ccNoError;
};

cc_int32 
cci_serv_process_msg(cc_msg_t * msg, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_msg_t** resp_msg) 
{
    cc_server_context_t* ctx;
    ccmsg_ctx_only_t* header = (ccmsg_ctx_only_t *)msg->header;
    cc_int32 code;

    if (msg == NULL || msg->header == NULL || auth_info == NULL || session_info == NULL)
        return ccErrBadParam;

    if (AllContexts == NULL) {
        code = cci_serv_initialize();
        if ( code != ccNoError )
            return code;
    }
	
    if (msg->type == ccmsg_INIT) {
        return TypeToOpMapping->operations[msg->type] (NULL, auth_info, session_info, msg, resp_msg);
    } else {
        if (msg->header_len < sizeof(ccmsg_ctx_only_t)) {
            return ccErrBadParam;
        }

        code = cci_serv_find_ctx_by_handle(header->ctx, auth_info, session_info, &ctx);
        if (code != ccNoError) {
            cci_serv_make_nack(ccErrContextNotFound, auth_info, session_info, resp_msg);
            return code;
        }
        return TypeToOpMapping->operations[msg->type] (ctx, auth_info, session_info, msg, resp_msg);
    }
}

/*deprecated*/
cc_int32
cci_serv_find_ctx(cc_auth_info_t* auth_info, cc_session_info_t* session_info,
                  cc_server_context_t** ctxpp)
{
    cc_context_iterate_t* ctx_iterator;
    cc_context_list_node_t* ctx_node;
    cc_server_context_t* ctx;
    cc_int32 code;
    cc_uint32 authorized;

    code = cci_context_list_iterator(AllContexts, &ctx_iterator);
    if (code != ccNoError)
        return code;

    while (cci_context_iterate_has_next(ctx_iterator)) {
        code = cci_context_iterate_next(ctx_iterator, &ctx_node);
        if (code != ccNoError) {
            cci_context_free_iterator(ctx_iterator);
            return code;
        }
        ctx = (cc_server_context_t *)ctx_node->data;
        code = cci_rpc_is_authorized(auth_info, session_info, ctx->auth_info, ctx->session_info, &authorized);
        if (code != ccNoError) {
            cci_context_free_iterator(ctx_iterator);
            return code;
        }

        if (authorized) {
            cci_context_free_iterator(ctx_iterator);
            *ctxpp = ctx;
            return ccNoError;
        }
    }
    cci_context_free_iterator(ctx_iterator);
    return ccIteratorEnd;
}

cc_int32
cci_serv_find_ctx_by_handle(cc_handle ctx_num, cc_auth_info_t* auth, cc_session_info_t* session, cc_server_context_t** ctxpp) 
{
    cc_server_context_t* input_ctx = (cc_server_context_t*)ctx_num;
    cc_context_iterate_t* ctx_iterator;
    cc_context_list_node_t* ctx_node;
    cc_server_context_t* ctx;
    cc_uint32 authorized;
    cc_int32 code;

    code = cci_context_list_iterator(AllContexts, &ctx_iterator);
    if (code != ccNoError)
        return code;

    while (cci_context_iterate_has_next(ctx_iterator)) {
        code = cci_context_iterate_next(ctx_iterator, &ctx_node);
        ctx = (cc_server_context_t *)ctx_node->data;
        if (code != ccNoError) {
            cci_context_free_iterator(ctx_iterator);
            return code;
        }

        code = cci_rpc_is_authorized(auth, session, ctx->auth_info, ctx->session_info, &authorized);
        if (code != ccNoError) {
            cci_context_free_iterator(ctx_iterator);
            return code;
        }

        if (ctx == input_ctx && authorized) {
            cci_context_free_iterator(ctx_iterator);
            *ctxpp = ctx;
            return ccNoError;
        }
    }
    cci_context_free_iterator(ctx_iterator);
    return ccIteratorEnd;
}

cc_int32
cci_serv_find_ccache_by_handle(cc_server_context_t* ctx, cc_handle ccache, cc_server_ccache_t** ccachepp ) 
{
    cc_ccache_iterate_t* ccache_iterator;
    cc_ccache_list_node_t* ccache_node;
    cc_server_ccache_t* stored_ccache;
    cc_server_ccache_t* target_ccache = (cc_server_ccache_t*)ccache;
    cc_int32 code;

    code = cci_ccache_list_iterator(ctx->ccaches, &ccache_iterator);
    if (code != ccNoError)
        return code;

    while (cci_ccache_iterate_has_next(ccache_iterator)) {
        code = cci_ccache_iterate_next(ccache_iterator, &ccache_node);
        if (code != ccNoError) {
            cci_ccache_free_iterator(ccache_iterator);
            return code;
        }

        stored_ccache = (cc_server_ccache_t *)ccache_node->data;
	
        if (stored_ccache == target_ccache) {
            cci_ccache_free_iterator(ccache_iterator);
            *ccachepp = stored_ccache;
            return ccNoError;
        }
    }
    cci_ccache_free_iterator(ccache_iterator);
    return ccIteratorEnd;
}

cc_int32
cci_serv_find_ccache_iterator_by_handle(cc_server_context_t* ctx, cc_handle iterator, cc_generic_list_node_t** nodepp ) 
{
    cc_generic_iterate_t* gen_iterator;
    cc_generic_list_node_t* gen_node;
    cc_ccache_iterate_t* stored_iterator;
    cc_ccache_iterate_t* target_iterator = (cc_ccache_iterate_t*)iterator;
    cc_int32 code;

    code = cci_generic_list_iterator(ctx->active_iterators, &gen_iterator);
    if (code != ccNoError) 
        return code;

    while (cci_generic_iterate_has_next(gen_iterator)) {
        code = cci_generic_iterate_next(gen_iterator, &gen_node);
        if (code != ccNoError) {
            cci_generic_free_iterator(gen_iterator);
            return code;
        }

        stored_iterator = (cc_ccache_iterate_t *)gen_node->data;
        if (stored_iterator == target_iterator) {
            cci_generic_free_iterator(gen_iterator);
            *nodepp = gen_node;
            return ccNoError;
        }
    }
    cci_generic_free_iterator(gen_iterator);
    return ccIteratorEnd;
}

cc_int32
cci_serv_find_creds_iterator_by_handle(cc_server_ccache_t* ccache, cc_handle iterator, cc_generic_list_node_t** nodepp) 
{
    cc_generic_iterate_t* gen_iterator;
    cc_generic_list_node_t* gen_node;
    cc_ccache_iterate_t* stored_iterator;
    cc_ccache_iterate_t* target_iterator = (cc_ccache_iterate_t*)iterator;
    cc_int32 code;

    code = cci_generic_list_iterator(ccache->active_iterators, &gen_iterator);
    if (code != ccNoError)
        return code;

    while (cci_generic_iterate_has_next(gen_iterator)) {
        code = cci_generic_iterate_next(gen_iterator, &gen_node);
        if (code != ccNoError) {
            cci_generic_free_iterator(gen_iterator);
            return code;
        }

        stored_iterator = (cc_ccache_iterate_t *)gen_node->data;
        if (stored_iterator == target_iterator) {
            cci_generic_free_iterator(gen_iterator);
            *nodepp = gen_node;
            return ccNoError;
        }
    }
    cci_generic_free_iterator(gen_iterator);
    return ccIteratorEnd;
}       

cc_int32 
cci_serv_make_nack(cc_int32 err_code, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_msg_t** resp_msg) 
{
    ccmsg_nack_t* nack_header;
    cc_int32 code;

    code = cci_msg_new(ccmsg_NACK, resp_msg);
    if (code != ccNoError) 
        return code;

    nack_header = (ccmsg_nack_t*)malloc(sizeof(ccmsg_nack_t));
    if (nack_header == NULL) {
        cci_msg_destroy(*resp_msg);
        *resp_msg = 0;
        return ccErrNoMem;
    }

    nack_header->err_code = err_code;;
    code = cci_msg_add_header(*resp_msg, nack_header, sizeof(ccmsg_nack_t));
    if (code != ccNoError) {
        cci_msg_destroy(*resp_msg);
        *resp_msg = 0;
        return code;
    }

    return ccNoError;
}

cc_int32 
cci_serv_make_ack(void * header, cc_int32 header_len, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_msg_t** resp_msg) 
{
    cc_int32 code;

    code = cci_msg_new(ccmsg_ACK, resp_msg);
    if (code != ccNoError)
        return code;

    if (header != NULL) {
        code = cci_msg_add_header(*resp_msg, header, header_len);
        if (code != ccNoError) {
            cci_msg_destroy(*resp_msg);
            resp_msg = 0;
            return code;
        }
    }
    return ccNoError;
}

cc_int32 
ccop_INIT( cc_server_context_t* ctx,            /* not used */
           cc_auth_info_t* auth_info,
           cc_session_info_t* session_info,
           cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_uint32 blob_pos;
    cc_server_context_t *new_ctx;
    ccmsg_init_resp_t *resp_header;
    ccmsg_init_t *header = (ccmsg_init_t *)msg->header;
    cc_context_list_node_t* ctx_node;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_init_t)) {
        return ccErrBadParam;
    }

    code = cci_context_new(header->in_version, auth_info, session_info, &new_ctx);
    if (code != ccNoError) {
        return code;
    }

    code = cci_context_list_append(AllContexts, ctx, &ctx_node);
    if (code != ccNoError) {
        cci_context_destroy(new_ctx);
        return code;
    }

    resp_header = (ccmsg_init_resp_t*)malloc(sizeof(ccmsg_init_resp_t));
    if (resp_header == NULL) {
        cci_context_destroy(new_ctx);
        return ccErrNoMem;
    }

    code = cci_msg_new(ccmsg_ACK, resp_msg);
    if (code != ccNoError) {
        free(resp_header);
        cci_context_destroy(new_ctx);
        return code;
    }
    code = cci_msg_add_data_blob(*resp_msg, cc_vendor, strlen(cc_vendor) + 1, &blob_pos);
    if (code != ccNoError) {
        free(resp_header);
        cci_context_destroy(new_ctx);
        cci_msg_destroy(*resp_msg);
        *resp_msg = 0;
        return code;
    }

    resp_header->out_ctx = new_ctx;
    resp_header->out_version = cc_myversion;
    resp_header->vendor_offset = blob_pos;
    resp_header->vendor_length = strlen(cc_vendor) + 1;
    code = cci_msg_add_header(*resp_msg, resp_header, sizeof(ccmsg_init_resp_t));
    if (code != ccNoError) {
        free(resp_header);
        cci_context_destroy(new_ctx);
        cci_msg_destroy(*resp_msg);
        *resp_msg = 0;
        return code;
    }

    return ccNoError;
}       

cc_int32 
ccop_CTX_RELEASE( cc_server_context_t* ctx,
                  cc_auth_info_t* auth_info,
                  cc_session_info_t* session_info,
                  cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ctx_release_t* header = (ccmsg_ctx_release_t *)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ctx_release_t)) {
        return ccErrBadParam;
    }

    code = cci_context_destroy(header->ctx);
    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CTX_GET_CHANGE_TIME( cc_server_context_t* ctx,
                          cc_auth_info_t* auth_info,
                          cc_session_info_t* session_info,
                          cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ctx_get_change_time_resp_t* resp_header;
    ccmsg_ctx_get_change_time_t *header = (ccmsg_ctx_get_change_time_t *)msg->header;

    *resp_msg = 0;
	
    if (msg->header_len != sizeof(ccmsg_ctx_get_change_time_t)) {
        return ccErrBadParam;
    }

    resp_header = (ccmsg_ctx_get_change_time_resp_t*)malloc(sizeof(ccmsg_ctx_get_change_time_resp_t));
    if (resp_header == NULL) {
        return ccErrNoMem;
    }

    resp_header->time = ctx->changed;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ctx_get_change_time_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CTX_GET_DEFAULT_CCACHE_NAME( cc_server_context_t* ctx,
                                  cc_auth_info_t* auth_info,
                                  cc_session_info_t* session_info,
                                  cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    char * name;
    ccmsg_ctx_get_default_ccache_name_resp_t* resp_header;
    ccmsg_ctx_get_default_ccache_name_t* header = (ccmsg_ctx_get_default_ccache_name_t *)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ctx_get_default_ccache_name_t)) {
        return ccErrBadParam;
    }
	
    code = cci_context_get_default_ccache_name(ctx, &name);
    if (code != ccNoError)
        return code;

    code = cci_msg_new(ccmsg_ACK, resp_msg);
    if (code != ccNoError) 
        return code;
	
    resp_header = (ccmsg_ctx_get_default_ccache_name_resp_t*)malloc(sizeof(ccmsg_ctx_get_default_ccache_name_resp_t));	
    if (resp_header == NULL) {
        cci_msg_destroy(*resp_msg);
        *resp_msg = 0;
        return ccErrNoMem;
    }

    code = cci_msg_add_data_blob(*resp_msg, name, strlen(name) + 1, &resp_header->name_offset);
    resp_header->name_len = strlen(name) + 1;
    return ccNoError;
}

cc_int32 
ccop_CTX_COMPARE(cc_server_context_t* ctx,
                  cc_auth_info_t* auth_info,
                  cc_session_info_t* session_info,
                  cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_server_context_t *ctx2;
    ccmsg_ctx_compare_resp_t* resp_header;
    ccmsg_ctx_compare_t* header = (ccmsg_ctx_compare_t *)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ctx_compare_t))
        return ccErrBadParam;

    code = cci_serv_find_ctx_by_handle(header->ctx2, auth_info, session_info, &ctx2);

    resp_header = (ccmsg_ctx_compare_resp_t*)malloc(sizeof(ccmsg_ctx_compare_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->is_equal = cci_context_compare(ctx, ctx2);
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ctx_compare_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CTX_NEW_CCACHE_ITERATOR(cc_server_context_t* ctx,
                              cc_auth_info_t* auth_info,
                              cc_session_info_t* session_info,
                              cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_ccache_iterate_t* ccache_iterator;
    ccmsg_ctx_new_ccache_iterator_resp_t* resp_header;
    ccmsg_ctx_new_ccache_iterator_t* header = (ccmsg_ctx_new_ccache_iterator_t*)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ctx_new_ccache_iterator_t))
        return ccErrBadParam;

    code = cci_context_ccache_iterator(ctx,&ccache_iterator);

    resp_header = (ccmsg_ctx_new_ccache_iterator_resp_t*)malloc(sizeof(ccmsg_ctx_new_ccache_iterator_resp_t));
    if (resp_header == NULL) 
        return ccErrNoMem;

    resp_header->iterator = ccache_iterator;

    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ctx_new_ccache_iterator_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32
ccop_CTX_LOCK( cc_server_context_t* ctx,
               cc_auth_info_t* auth_info,
               cc_session_info_t* session_info,
               cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO
    return cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
}

cc_int32
ccop_CTX_UNLOCK( cc_server_context_t* ctx,
                 cc_auth_info_t* auth_info,
                 cc_session_info_t* session_info,
                 cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO
    return cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
}

cc_int32
ccop_CTX_CLONE( cc_server_context_t* ctx,
                cc_auth_info_t* auth_info,
                cc_session_info_t* session_info,
                cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO
    return cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
}

cc_int32 
ccop_CCACHE_OPEN(cc_server_context_t* ctx,
                  cc_auth_info_t* auth_info,
                  cc_session_info_t* session_info,
                  cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    char *name;
    cc_server_ccache_t* ccache;
    ccmsg_ccache_open_resp_t* resp_header;
    ccmsg_ccache_open_t* header = (ccmsg_ccache_open_t*)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_open_t))
        return ccErrBadParam;

    code = cci_msg_retrieve_blob(msg, header->name_offset, header->name_len, &name);
    code = cci_context_find_ccache(ctx, name, &ccache);

    free(name);

    if (ccache == NULL)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    resp_header = (ccmsg_ccache_open_resp_t*)malloc(sizeof(ccmsg_ccache_open_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->ccache = ccache;
    cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_open_resp_t), auth_info, session_info, resp_msg);
    return ccNoError;
}       

cc_int32 
ccop_CCACHE_OPEN_DEFAULT(cc_server_context_t* ctx,
                          cc_auth_info_t* auth_info,
                          cc_session_info_t* session_info,
                          cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_open_default_t* header = (ccmsg_ccache_open_default_t*)msg->header;
    ccmsg_ccache_open_resp_t* resp_header;
    cc_server_ccache_t* ccache;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_open_default_t)) 
        return ccErrBadParam;

    if (ctx->ccaches->head->data == NULL)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);
    
    ccache = (cc_server_ccache_t*) ctx->ccaches->head->data;

    resp_header = (ccmsg_ccache_open_resp_t*)malloc(sizeof(ccmsg_ccache_open_resp_t));
    if (resp_header == NULL) 
        return ccErrNoMem;

    resp_header->ccache = ccache;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_open_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_CREATE(cc_server_context_t* ctx,
                    cc_auth_info_t* auth_info,
                    cc_session_info_t* session_info,
                    cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_create_resp_t* resp_header;
    ccmsg_ccache_create_t* header = (ccmsg_ccache_create_t*)msg->header;
    cc_server_ccache_t* ccache;
    char* principal;
    char* name;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_create_t)) 
        return ccErrBadParam;

    code = cci_msg_retrieve_blob(msg, header->principal_offset, header->principal_len, &principal);
    if (code != ccNoError) 
        return code;
    principal[header->principal_len] = '\0'; /*Ensure null termination*/

    code = cci_msg_retrieve_blob(msg, header->name_offset, header->name_len, &name);
    if (code != ccNoError) 
        return code;
    name[header->name_len] = '\0'; /*Ensure null termination*/

    code = cci_context_create_ccache(ctx, name, header->version, principal, &ccache);
    if (code != ccNoError)
        return code;

    resp_header = (ccmsg_ccache_create_resp_t*)malloc(sizeof(ccmsg_ccache_create_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->ccache = ccache;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_create_resp_t), auth_info, session_info, resp_msg);
}

cc_int32 
ccop_CCACHE_CREATE_DEFAULT( cc_server_context_t* ctx,
                            cc_auth_info_t* auth_info,
                            cc_session_info_t* session_info,
                            cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_create_resp_t* resp_header;
    ccmsg_ccache_create_t* header = (ccmsg_ccache_create_t*)msg->header;
    cc_server_ccache_t* ccache;
    char* principal;
    char* name;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_create_t)) 
        return ccErrBadParam;

    code = cci_msg_retrieve_blob(msg, header->principal_offset, header->principal_len, &principal);
    if (code != ccNoError) 
        return code;
    principal[header->principal_len] = '\0'; /*Ensure null termination*/

    code = cci_context_get_default_ccache_name(ctx, &name);
    if (code != ccNoError)
        return code;

    code = cci_context_create_ccache(ctx, name, header->version, principal, &ccache);
    if (code != ccNoError)
        return code;

    resp_header = (ccmsg_ccache_create_resp_t*)malloc(sizeof(ccmsg_ccache_create_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->ccache = ccache;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_create_resp_t), auth_info, session_info, resp_msg);
}

cc_int32 
ccop_CCACHE_CREATE_UNIQUE( cc_server_context_t* ctx,
                           cc_auth_info_t* auth_info,
                           cc_session_info_t* session_info,
                           cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_create_resp_t* resp_header;
    ccmsg_ccache_create_t* header = (ccmsg_ccache_create_t*)msg->header;
    cc_server_ccache_t* ccache;
    char* principal;
    char* name;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_create_t)) 
        return ccErrBadParam;

    code = cci_msg_retrieve_blob(msg, header->principal_offset, header->principal_len, &principal);
    if (code != ccNoError) 
        return code;
    principal[header->principal_len] = '\0'; /*Ensure null termination*/

    // TODO: Generate a unique ccache name 

    code = cci_context_create_ccache(ctx, name, header->version, principal, &ccache);
    if (code != ccNoError)
        return code;

    resp_header = (ccmsg_ccache_create_resp_t*)malloc(sizeof(ccmsg_ccache_create_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->ccache = ccache;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_create_resp_t), auth_info, session_info, resp_msg);
}

cc_int32 
ccop_CCACHE_RELEASE( cc_server_context_t* ctx,
                     cc_auth_info_t* auth_info,
                     cc_session_info_t* session_info,
                     cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO: This is probably wrong.  
    return ccop_CCACHE_DESTROY(ctx, auth_info, session_info, msg, resp_msg);
}       

cc_int32 
ccop_CCACHE_DESTROY( cc_server_context_t* ctx,
                     cc_auth_info_t* auth_info,
                     cc_session_info_t* session_info,
                     cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_release_t* header = (ccmsg_ccache_release_t*)msg->header;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_release_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    cci_ccache_destroy(ccache);

    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}

cc_int32 
ccop_CCACHE_SET_DEFAULT(cc_server_context_t* ctx,
                         cc_auth_info_t* auth_info,
                         cc_session_info_t* session_info,
                         cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_server_ccache_t* ccache, *stored_ccache, *old_default;
    ccmsg_ccache_set_default_t* header = (ccmsg_ccache_set_default_t*)msg->header;
    cc_ccache_iterate_t* ccache_iterator;
    cc_ccache_list_node_t* ccache_node;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_set_default_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    if (ccache == (cc_server_ccache_t*)ctx->ccaches->head->data) /*already default*/
        return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);

    old_default = (cc_server_ccache_t*)ctx->ccaches->head->data;
    old_default->last_default = time(NULL);

    code = cci_ccache_list_iterator(ctx->ccaches, &ccache_iterator);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    while (cci_ccache_iterate_has_next(ccache_iterator)) {
        code = cci_ccache_iterate_next(ccache_iterator,&ccache_node);
        stored_ccache = (cc_server_ccache_t*)ccache_node->data;

        if (stored_ccache == ccache) {
            ccache_node->data = NULL; /*don't want list removal code free()ing ccache*/
            cci_ccache_list_remove_element(ctx->ccaches, ccache_node);
            cci_ccache_list_prepend(ctx->ccaches, ccache, NULL);
            break;
        }
    }       
    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_GET_CREDS_VERSION(cc_server_context_t* ctx,
                               cc_auth_info_t* auth_info,
                               cc_session_info_t* session_info,
                               cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_get_creds_version_t* header = (ccmsg_ccache_get_creds_version_t*)msg->header;
    ccmsg_ccache_get_creds_version_resp_t* resp_header;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_get_creds_version_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    resp_header = (ccmsg_ccache_get_creds_version_resp_t*)malloc(sizeof(ccmsg_ccache_get_creds_version_resp_t));	
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->version = ccache->versions;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_get_creds_version_resp_t), auth_info, session_info, resp_msg);
}

cc_int32 
ccop_CCACHE_GET_NAME(cc_server_context_t* ctx,
                      cc_auth_info_t* auth_info,
                      cc_session_info_t* session_info,
                      cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_get_name_t* header = (ccmsg_ccache_get_name_t*)msg->header;
    ccmsg_ccache_get_name_resp_t* resp_header;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_get_name_resp_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (ccache == NULL)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    resp_header = (ccmsg_ccache_get_name_resp_t*)malloc(sizeof(ccmsg_ccache_get_name_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    code = cci_msg_new(ccmsg_ACK, resp_msg);
    if (code != ccNoError)
        return code;

    code = cci_msg_add_data_blob(*resp_msg, ccache->name, strlen(ccache->name) + 1, &resp_header->name_offset);
    resp_header->name_len = strlen(ccache->name) + 1;
    cci_msg_add_header(*resp_msg, resp_header, sizeof(ccmsg_ccache_get_name_resp_t));

    return ccNoError;
}       

cc_int32 
ccop_CCACHE_GET_PRINCIPAL(cc_server_context_t* ctx,
                           cc_auth_info_t* auth_info,
                           cc_session_info_t* session_info,
                           cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_get_principal_t* header = (ccmsg_ccache_get_principal_t*)msg->header;
    ccmsg_ccache_get_principal_resp_t* resp_header;
    cc_server_ccache_t* ccache;
    char * principal;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_get_principal_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_ccache_get_principal(ccache, header->version, &principal);
    if (code != ccNoError)
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    code = cci_msg_new(ccmsg_ACK, resp_msg);
    if (code != ccNoError) 
        return code;

    resp_header = (ccmsg_ccache_get_principal_resp_t*)malloc(sizeof(ccmsg_ccache_get_principal_resp_t));
    if (resp_header == NULL) 
        return ccErrNoMem;

    code = cci_msg_add_data_blob(*resp_msg, principal, strlen(principal) + 1, &resp_header->principal_offset);
    cci_msg_add_header(*resp_msg, resp_header, sizeof(ccmsg_ccache_get_principal_resp_t));

    return ccNoError;
}       

cc_int32 
ccop_CCACHE_SET_PRINCIPAL(cc_server_context_t* ctx,
                           cc_auth_info_t* auth_info,
                           cc_session_info_t* session_info,
                           cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_set_principal_t* header = (ccmsg_ccache_set_principal_t*)msg->header;
    cc_server_ccache_t* ccache;
    char *principal;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_set_principal_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_msg_retrieve_blob(msg, header->principal_offset, header->principal_len, &principal);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrBadParam, auth_info, session_info, resp_msg);

    code = cci_ccache_set_principal(ccache, header->version, principal);
    if (code != ccNoError)
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_CREDS_ITERATOR(cc_server_context_t* ctx,
                            cc_auth_info_t* auth_info,
                            cc_session_info_t* session_info,
                            cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_server_ccache_t* ccache;
    cc_credentials_iterate_t* creds_iterator;
    ccmsg_ccache_creds_iterator_t* header = (ccmsg_ccache_creds_iterator_t*)msg->header;
    ccmsg_ccache_creds_iterator_resp_t* resp_header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_creds_iterator_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_ccache_new_iterator(ccache, &creds_iterator);
    if (code != ccNoError)
        return code;

    resp_header = (ccmsg_ccache_creds_iterator_resp_t*)malloc(sizeof(ccmsg_ccache_creds_iterator_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->iterator = creds_iterator;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_creds_iterator_resp_t), auth_info, session_info, resp_msg);
}       


static cc_int32
cci_credentials_union_release( cc_credentials_union * creds )
{
    int i;

    switch (creds->version) {
    case cc_credentials_v4:
        free(creds->credentials.credentials_v4);
        break;
    case cc_credentials_v5:
        if ( creds->credentials.credentials_v5->client )
            free(creds->credentials.credentials_v5->client);
        if ( creds->credentials.credentials_v5->server )
            free(creds->credentials.credentials_v5->server );
        if ( creds->credentials.credentials_v5->keyblock.data )
            free(creds->credentials.credentials_v5->keyblock.data);
        if ( creds->credentials.credentials_v5->ticket.data )
            free(creds->credentials.credentials_v5->ticket.data);
        if ( creds->credentials.credentials_v5->second_ticket.data )
            free(creds->credentials.credentials_v5->second_ticket.data);
        if ( creds->credentials.credentials_v5->addresses ) {
            for ( i=0; creds->credentials.credentials_v5->addresses[i]; i++) {
                if (creds->credentials.credentials_v5->addresses[i]->data)
                    free(creds->credentials.credentials_v5->addresses[i]->data);
            }
            free(creds->credentials.credentials_v5->addresses);
        }
        if ( creds->credentials.credentials_v5->authdata ) {
            for ( i=0; creds->credentials.credentials_v5->authdata[i]; i++) {
                if ( creds->credentials.credentials_v5->authdata[i]->data )
                    free(creds->credentials.credentials_v5->authdata[i]->data);
            }
            free(creds->credentials.credentials_v5->authdata);
        }
        break;
    default:
        return ccErrBadCredentialsVersion;
    }        
    return ccNoError;
}

cc_int32 
ccop_CCACHE_STORE_CREDS(cc_server_context_t* ctx,
                         cc_auth_info_t* auth_info,
                         cc_session_info_t* session_info,
                         cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_store_creds_t* header = (ccmsg_ccache_store_creds_t*)msg->header;
    cc_server_ccache_t* ccache;
    char                 *flat_creds;
    cc_credentials_union *creds;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_store_creds_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    // TODO: This code is too simplistic.  cc_credential_unions are not flat
    // structures and must be flattened.  That means that although we can 
    // store a flat blob in the message we will need to decode the blob
    // into the actual object.  
    code = cci_msg_retrieve_blob(msg, header->creds_offset, header->creds_len, &flat_creds);
    if (code != ccNoError) 
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    creds = (cc_credentials_union *)malloc(sizeof(cc_credentials_union));
    if ( creds == NULL )
        return ccErrNoMem;

    switch ( creds->version ) {        
    case cc_credentials_v4:
        code = cci_creds_v4_unmarshall(flat_creds, header->creds_len, creds);
        break;                                 
    case cc_credentials_v5:
        code = cci_creds_v5_unmarshall(flat_creds, header->creds_len, creds);
        break;
    default:
        return cci_serv_make_nack(ccErrBadCredentialsVersion, auth_info, session_info, resp_msg);
    }
    if (code != ccNoError)
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    code = cci_ccache_store_creds(ccache, creds);
    cci_credentials_union_release(creds);
    if (code != ccNoError) {
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);
    }

    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_REM_CREDS(cc_server_context_t* ctx,
                       cc_auth_info_t* auth_info,
                       cc_session_info_t* session_info,
                       cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_rem_creds_t* header = (ccmsg_ccache_rem_creds_t*)msg->header;
    cc_server_ccache_t* ccache;
    cc_credentials_union *creds;
    cc_int32 code;

    *resp_msg = 0;
    if (msg->header_len != sizeof(ccmsg_ccache_rem_creds_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_ccache_rem_creds(ccache, header->creds);
    if (code != ccNoError)
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}               

cc_int32
ccop_CCACHE_LOCK( cc_server_context_t* ctx,
                  cc_auth_info_t* auth_info,
                  cc_session_info_t* session_info,
                  cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO
    return cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
}

cc_int32
ccop_CCACHE_UNLOCK( cc_server_context_t* ctx,
                    cc_auth_info_t* auth_info,
                    cc_session_info_t* session_info,
                    cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO
    return cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
}

cc_int32
ccop_CCACHE_MOVE( cc_server_context_t* ctx,
                  cc_auth_info_t* auth_info,
                  cc_session_info_t* session_info,
                  cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    // TODO
    return cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
}


cc_int32 
ccop_CCACHE_GET_LAST_DEFAULT_TIME(cc_server_context_t* ctx,
                                   cc_auth_info_t* auth_info,
                                   cc_session_info_t* session_info,
                                   cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_get_last_default_time_t* header = (ccmsg_ccache_get_last_default_time_t*)msg->header;
    ccmsg_ccache_get_last_default_time_resp_t* resp_header;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_get_last_default_time_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    resp_header = (ccmsg_ccache_get_last_default_time_resp_t*)malloc(sizeof(ccmsg_ccache_get_last_default_time_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->last_default_time = ccache->last_default;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_get_last_default_time_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_GET_CHANGE_TIME( cc_server_context_t* ctx,
                          cc_auth_info_t* auth_info,
                          cc_session_info_t* session_info,
                          cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_get_change_time_resp_t* resp_header;
    ccmsg_ccache_get_change_time_t *header = (ccmsg_ccache_get_change_time_t *)msg->header;
    cc_server_ccache_t* ccache = (cc_server_ccache_t *)header->ccache;

    *resp_msg = 0;
	
    if (msg->header_len != sizeof(ccmsg_ccache_get_change_time_t)) {
        return ccErrBadParam;
    }

    resp_header = (ccmsg_ccache_get_change_time_resp_t*)malloc(sizeof(ccmsg_ccache_get_change_time_resp_t));
    if (resp_header == NULL) {
        return ccErrNoMem;
    }

    resp_header->time = ccache->changed;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_get_change_time_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_COMPARE(cc_server_context_t* ctx,
                     cc_auth_info_t* auth_info,
                     cc_session_info_t* session_info,
                     cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_compare_t* header = (ccmsg_ccache_compare_t*)msg->header;
    ccmsg_ccache_compare_resp_t* resp_header;
    cc_server_ccache_t* ccache1, *ccache2;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_compare_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache1, &ccache1);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache2, &ccache2);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    resp_header = (ccmsg_ccache_compare_resp_t*)malloc(sizeof(ccmsg_ccache_compare_resp_t));	
    if (resp_header == NULL)
        return ccErrNoMem;

    cci_ccache_compare(ccache1, ccache2, &resp_header->is_equal);
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_compare_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_GET_KDC_TIME_OFFSET(cc_server_context_t* ctx,
                                 cc_auth_info_t* auth_info,
                                 cc_session_info_t* session_info,
                                 cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_get_kdc_time_offset_t* header = (ccmsg_ccache_get_kdc_time_offset_t*)msg->header;
    ccmsg_ccache_get_kdc_time_offset_resp_t* resp_header;
    cc_server_ccache_t* ccache;
    cc_time_t offset;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_get_kdc_time_offset_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    // TODO How is the header->creds_version supposed to be used?

    code = cci_ccache_get_kdc_time_offset(ccache, &offset);
    if (code != ccNoError)
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    resp_header = (ccmsg_ccache_get_kdc_time_offset_resp_t*)malloc(sizeof(ccmsg_ccache_get_kdc_time_offset_resp_t));
    if (resp_header == NULL)
        return ccErrNoMem;

    resp_header->offset = offset;
    return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_get_kdc_time_offset_resp_t), auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_SET_KDC_TIME_OFFSET(cc_server_context_t* ctx,
                                 cc_auth_info_t* auth_info,
                                 cc_session_info_t* session_info,
                                 cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_set_kdc_time_offset_t* header = (ccmsg_ccache_set_kdc_time_offset_t*)msg->header;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_set_kdc_time_offset_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    // TODO How is the header->creds_version supposed to be used?

    cci_ccache_set_kdc_time_offset(ccache, header->offset);
    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_CLEAR_KDC_TIME_OFFSET(cc_server_context_t* ctx,
                                   cc_auth_info_t* auth_info,
                                   cc_session_info_t* session_info,
                                   cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_clear_kdc_time_offset_t* header = (ccmsg_ccache_clear_kdc_time_offset_t*)msg->header;
    cc_server_ccache_t* ccache;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_clear_kdc_time_offset_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    // TODO How is the header->creds_version supposed to be used?

    cci_ccache_clear_kdc_time_offset(ccache);
    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}               

cc_int32 
ccop_CCACHE_ITERATOR_RELEASE(cc_server_context_t* ctx,
                              cc_auth_info_t* auth_info,
                              cc_session_info_t* session_info,
                              cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_generic_list_node_t* gen_node;
    ccmsg_ccache_iterator_release_t* header = (ccmsg_ccache_iterator_release_t*)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_iterator_release_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_iterator_by_handle(ctx, header->iterator, &gen_node);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrBadParam, auth_info, session_info, resp_msg);

    code = cci_generic_list_remove_element(ctx->active_iterators, gen_node);
    if (code != ccNoError) 
        return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CCACHE_ITERATOR_NEXT(cc_server_context_t* ctx,
                           cc_auth_info_t* auth_info,
                           cc_session_info_t* session_info,
                           cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_ccache_iterator_release_t* header = (ccmsg_ccache_iterator_release_t*)msg->header;
    ccmsg_ccache_iterator_next_resp_t* resp_header;
    cc_generic_list_node_t* gen_node;
    cc_ccache_iterate_t* ccache_iterator;
	cc_ccache_list_node_t *ccache_node;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_ccache_iterator_next_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_iterator_by_handle(ctx, header->iterator, &gen_node);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrBadParam, auth_info, session_info, resp_msg);

    ccache_iterator = (cc_ccache_iterate_t*)gen_node->data;
    if (cci_ccache_iterate_has_next(ccache_iterator)) {
        resp_header = (ccmsg_ccache_iterator_next_resp_t*)malloc(sizeof(ccmsg_ccache_iterator_next_resp_t));
        if (resp_header == NULL)
            return ccErrNoMem;

        code = cci_ccache_iterate_next(ccache_iterator, &ccache_node);
        if (code != ccNoError) 
            return cci_serv_make_nack(code, auth_info, session_info, resp_msg);

		resp_header->ccache = ccache_node;
        return cci_serv_make_ack(resp_header, sizeof(ccmsg_ccache_iterator_next_resp_t), auth_info, session_info, resp_msg);
    } else {
        return cci_serv_make_nack(ccIteratorEnd, auth_info, session_info, resp_msg);
    }
}       

cc_int32 
ccop_CREDS_ITERATOR_RELEASE(cc_server_context_t* ctx,
                             cc_auth_info_t* auth_info,
                             cc_session_info_t* session_info,
                             cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    cc_generic_list_node_t* gen_node;
    cc_server_ccache_t* ccache;
    ccmsg_creds_iterator_release_t* header = (ccmsg_creds_iterator_release_t*)msg->header;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_creds_iterator_release_t)) 
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_serv_find_creds_iterator_by_handle(ccache, header->iterator, &gen_node);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrBadParam, auth_info, session_info, resp_msg);

    code = cci_generic_list_remove_element(ccache->active_iterators, gen_node);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrBadParam, auth_info, session_info, resp_msg);

    return cci_serv_make_ack(NULL, 0, auth_info, session_info, resp_msg);
}       

cc_int32 
ccop_CREDS_ITERATOR_NEXT(cc_server_context_t* ctx,
                          cc_auth_info_t* auth_info,
                          cc_session_info_t* session_info,
                          cc_msg_t *msg, cc_msg_t **resp_msg) 
{
    ccmsg_creds_iterator_next_t* header = (ccmsg_creds_iterator_next_t*)msg->header;
    ccmsg_creds_iterator_next_resp_t* resp_header;
    cc_credentials_iterate_t* creds_iterator;
    cc_generic_list_node_t* gen_node;
    cc_credentials_list_node_t* creds_node;
    cc_server_ccache_t* ccache;
    cc_server_credentials_t* stored_creds;
    cc_credentials_union *creds_union;
    cc_int32 code;

    *resp_msg = 0;

    if (msg->header_len != sizeof(ccmsg_creds_iterator_next_t))
        return ccErrBadParam;

    code = cci_serv_find_ccache_by_handle(ctx, header->ccache, &ccache);
    if (code != ccNoError)
        return cci_serv_make_nack(ccErrCCacheNotFound, auth_info, session_info, resp_msg);

    code = cci_serv_find_creds_iterator_by_handle(ccache, header->iterator, &gen_node);
    if (code != ccNoError) 
        return cci_serv_make_nack(ccErrBadParam, auth_info, session_info, resp_msg);

    creds_iterator = (cc_credentials_iterate_t*)gen_node->data;
    if (cci_credentials_iterate_has_next(creds_iterator)) {
        code = cci_msg_new(ccmsg_ACK, resp_msg);
        if (code != ccNoError)
            return code;

        resp_header = (ccmsg_creds_iterator_next_resp_t*)malloc(sizeof(ccmsg_creds_iterator_next_resp_t));
        if (resp_header == NULL)
            return ccErrNoMem;

        code = cci_credentials_iterate_next(creds_iterator, &creds_node);
        stored_creds = (cc_server_credentials_t*)creds_node->data;
        creds_union = &stored_creds->creds;

        code = cci_msg_add_data_blob(*resp_msg, creds_union, sizeof(cc_credentials_union), &resp_header->creds_offset);
        code = cci_msg_add_header(*resp_msg, resp_header, sizeof(ccmsg_creds_iterator_next_resp_t));
    } else {
        cci_serv_make_nack(ccIteratorEnd, auth_info, session_info, resp_msg);
    }
    return ccNoError;
}       

cc_int32 
ccop_CREDS_RELEASE( cc_server_context_t* ctx,
                    cc_auth_info_t* auth_info,
                    cc_session_info_t* session_info,
                    cc_msg_t *msg, cc_msg_t **resp_msg) 
{       
        
    cci_serv_make_nack(ccErrNotImplemented, auth_info, session_info, resp_msg);
    return ccNoError;
}       

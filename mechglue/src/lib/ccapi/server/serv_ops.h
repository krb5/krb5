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
 * Prototypes for serv_ops.c
 */

#ifndef __SERV_OPS_H__
#define __SERV_OPS_H__

#include "CredentialsCache.h"
#include "rpc_auth.h"
#include "msg.h"
#include "datastore.h"

struct type_to_op_mapping_t {
    cc_int32 (*operations[CC_MSG_MAX_TYPE]) (
                        cc_server_context_t* ctx,
			cc_auth_info_t* auth_info,
			cc_session_info_t* session_info,
			cc_msg_t *msg,
                        cc_msg_t **resp_msg);
};
typedef struct type_to_op_mapping_t type_to_op_mapping_t;

cc_int32 cci_serv_initialize(void);
cc_int32 cci_serv_process_msg(cc_msg_t * msg, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_msg_t** resp_msg);
cc_int32 cci_serv_find_ctx(cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_server_context_t** contextp);
cc_int32 cci_serv_find_ctx_by_handle(cc_handle ctx_handle, cc_auth_info_t *auth, cc_session_info_t* session, cc_server_context_t** contextp);
cc_int32 cci_serv_find_ccache_by_handle(cc_server_context_t* ctx, cc_handle ccache_handle, cc_server_ccache_t** ccachep) ;
cc_int32 cci_serv_find_ccache_iterator_by_handle(cc_server_context_t* ctx, cc_handle iterator, cc_generic_list_node_t** nodep);
cc_int32 cci_serv_find_creds_iterator_by_handle(cc_server_ccache_t* ccache, cc_handle iterator, cc_generic_list_node_t** nodep);
cc_int32 cci_serv_make_nack(cc_int32 err_code, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_msg_t** msgp);
cc_int32 cci_serv_make_ack(void * header, cc_int32 header_len, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_msg_t** msgp);

cc_int32 ccop_INIT( 
        cc_server_context_t* ctx,
        cc_auth_info_t* auth_info,
        cc_session_info_t* session_info,
        cc_msg_t *msg,
        cc_msg_t **resp_msg);

cc_int32 ccop_CTX_RELEASE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CTX_GET_CHANGE_TIME(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CTX_GET_DEFAULT_CCACHE_NAME(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CTX_COMPARE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CTX_NEW_CCACHE_ITERATOR(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32
ccop_CTX_LOCK( cc_server_context_t* ctx,
               cc_auth_info_t* auth_info,
               cc_session_info_t* session_info,
               cc_msg_t *msg, 
               cc_msg_t **resp_msg);

cc_int32
ccop_CTX_UNLOCK( cc_server_context_t* ctx,
                 cc_auth_info_t* auth_info,
                 cc_session_info_t* session_info,
                 cc_msg_t *msg, 
                 cc_msg_t **resp_msg);

cc_int32
ccop_CTX_CLONE( cc_server_context_t* ctx,
                cc_auth_info_t* auth_info,
                cc_session_info_t* session_info,
                cc_msg_t *msg, 
                cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_OPEN(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_OPEN_DEFAULT(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_CREATE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 
ccop_CCACHE_CREATE_DEFAULT( cc_server_context_t* ctx,
                            cc_auth_info_t* auth_info,
                            cc_session_info_t* session_info,
                            cc_msg_t *msg, 
                            cc_msg_t **resp_msg);

cc_int32 
ccop_CCACHE_CREATE_UNIQUE( cc_server_context_t* ctx,
                           cc_auth_info_t* auth_info,
                           cc_session_info_t* session_info,
                           cc_msg_t *msg, 
                           cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_RELEASE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_DESTROY(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_SET_DEFAULT(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_GET_CREDS_VERSION(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_GET_NAME(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_GET_PRINCIPAL(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_SET_PRINCIPAL(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_CREDS_ITERATOR(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_STORE_CREDS(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_REM_CREDS(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_GET_LAST_DEFAULT_TIME(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 
ccop_CCACHE_GET_CHANGE_TIME( 
        cc_server_context_t* ctx,
        cc_auth_info_t* auth_info,
        cc_session_info_t* session_info,
        cc_msg_t *msg, 
        cc_msg_t **resp_msg) ;

cc_int32 ccop_CCACHE_COMPARE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_GET_KDC_TIME_OFFSET(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_SET_KDC_TIME_OFFSET(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_CLEAR_KDC_TIME_OFFSET(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_ITERATOR_RELEASE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CCACHE_ITERATOR_NEXT(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CREDS_ITERATOR_RELEASE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CREDS_ITERATOR_NEXT(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);

cc_int32 ccop_CREDS_RELEASE(
	cc_server_context_t* ctx,
	cc_auth_info_t* auth_info,
	cc_session_info_t* session_info,
	cc_msg_t *msg,
	cc_msg_t **resp_msg);
#endif /*__SERV_OPS_H__*/

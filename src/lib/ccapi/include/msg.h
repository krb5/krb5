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
 * Verifiable, extensible message format.
 *
 * Format:
 * <size of header block (header_len)>
 * <size of *entire* message, including previous field (flat_len)>
 * <message type (type)>
 * <type specific header (header)>
 * <magic number (magic)>
 * <data blob 1 length>
 * <data blob 1>
 * <data blob 2 length>
 * <data blob 2>
 * ...
 * <magic number (magic)>
 *
 * If the header has variable length data it is included in the data blobs. 
 * The header field has the offset from the beginning of the message of the 1st 
 * byte of the data and the length of the data.
 *
 */

#ifndef __CC_MSG_H__
#define __CC_MSG_H__

#include "CredentialsCache.h"

struct  cc_msg_t {
    cc_uint32 type;			/*type of message*/
    cc_uint8 *flat;			/*flattened representation of this message*/
    cc_uint8 *header;			/*fixed length header determined by message type*/
    cc_uint32 flat_len;			/*length of flat rep*/
    cc_uint32 header_len;		/*length of header*/
    cc_uint32 magic;			/*magic number for verification purposes*/
    cc_generic_list_head_t* data_blobs;	/*variable length data*/
};      
typedef struct cc_msg_t cc_msg_t;

/*Types of messages*/
enum {
    ccmsg_ACK,
    ccmsg_NACK,
    ccmsg_INIT,
    ccmsg_CTX_RELEASE,
    ccmsg_CTX_GET_CHANGE_TIME,
    ccmsg_CTX_GET_DEFAULT_CCACHE_NAME,
    ccmsg_CTX_COMPARE,
    ccmsg_CTX_NEW_CCACHE_ITERATOR,
    ccmsg_CTX_LOCK,
    ccmsg_CTX_UNLOCK,
    ccmsg_CTX_CLONE,
    ccmsg_CCACHE_OPEN,
    ccmsg_CCACHE_OPEN_DEFAULT,
    ccmsg_CCACHE_CREATE,
    ccmsg_CCACHE_CREATE_DEFAULT,
    ccmsg_CCACHE_CREATE_UNIQUE,
    ccmsg_CCACHE_RELEASE,
    ccmsg_CCACHE_DESTROY,
    ccmsg_CCACHE_SET_DEFAULT,
    ccmsg_CCACHE_GET_CREDS_VERSION,
    ccmsg_CCACHE_GET_NAME,
    ccmsg_CCACHE_GET_PRINCIPAL,
    ccmsg_CCACHE_SET_PRINCIPAL,
    ccmsg_CCACHE_CREDS_ITERATOR,
    ccmsg_CCACHE_STORE_CREDS,
    ccmsg_CCACHE_REM_CREDS,
    ccmsg_CCACHE_GET_LAST_DEFAULT_TIME,
    ccmsg_CCACHE_GET_CHANGE_TIME,
    ccmsg_CCACHE_MOVE,
    ccmsg_CCACHE_COMPARE,
    ccmsg_CCACHE_GET_KDC_TIME_OFFSET,
    ccmsg_CCACHE_SET_KDC_TIME_OFFSET,
    ccmsg_CCACHE_CLEAR_KDC_TIME_OFFSET,
    ccmsg_CCACHE_ITERATOR_RELEASE,
    ccmsg_CCACHE_ITERATOR_NEXT,
    ccmsg_CCACHE_LOCK,
    ccmsg_CCACHE_UNLOCK,
    ccmsg_CREDS_ITERATOR_RELEASE,
    ccmsg_CREDS_ITERATOR_NEXT,
    ccmsg_CREDS_RELEASE,
    ccmsg_CREDS_V4,
    ccmsg_CREDS_V5
};      

#define CC_MSG_MAX_SIZE	1073741824 /*2^30*/
#define CC_MSG_MAX_TYPE ccmsg_CREDS_V5
#define BLOB_LEN (sizeof(cc_uint32))
#define MAGIC_DATA_LEN (sizeof(cc_uint32))
#define MAGIC_HEAD_LEN (sizeof(cc_uint32))

cc_int32 cci_msg_new(cc_uint32 type, cc_msg_t** msgpp);
cc_int32 cci_msg_calc_size(cc_msg_t* msg, cc_uint32 * sizep);
cc_int32 cci_msg_calc_header_size(cc_msg_t* msg, cc_uint32 * sizep);
cc_int32 cci_msg_add_data_blob(cc_msg_t* msg, void *data, cc_uint32 len, cc_uint32 * sizep);
cc_int32 cci_msg_add_header(cc_msg_t* msg, void *header, cc_uint32 header_len);
cc_int32 cci_msg_calc_blob_pos(cc_msg_t* msg, void *data, cc_uint32 len, cc_uint32 * sizep);
cc_int32 cci_msg_flatten(cc_msg_t* msg, void **);
cc_int32 cci_msg_calc_magic(void *flat, int flat_len, cc_uint32 * sizep);
cc_int32 cci_msg_verify(void* flat, int flat_len, cc_uint32 * sizep);
cc_int32 cci_msg_unflatten(void *flat, int flat_len, cc_msg_t** msgpp);
cc_int32 cci_msg_retrieve_blob(cc_msg_t* msg, cc_uint32 blob_offset, cc_uint32 blob_len, void **);
cc_int32 cci_msg_destroy(cc_msg_t* msg);
#endif /*__CC_MSG_H__*/

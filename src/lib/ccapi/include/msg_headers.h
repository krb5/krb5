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
 * Message type specific header structures.
 *
 */

#ifndef __MSG_HEADERS_H__
#define __MSG_HEADERS_H__

#include "CredentialsCache.h"

/*
 * All header structs must have sizes divisible by 4, and
 * all individual fields within the structs must also have
 * size divisible by 4. This is to ensure correct alignment
 * and stop different compilers from inserting padding bytes in
 * different places.
 */

struct ccmsg_ctx_only_t {
    cc_handle ctx;
};
typedef struct ccmsg_ctx_only_t ccmsg_ctx_only_t;

struct ccmsg_nack_t {
    cc_uint32	err_code;	/*error code that caused failure*/
};
typedef struct ccmsg_nack_t ccmsg_nack_t;

struct ccmsg_init_t {
    cc_uint32	in_version;		/*client API version*/
};
struct ccmsg_init_resp_t {
    cc_handle	out_ctx;		/*handle on this ctx*/
    cc_uint32	out_version;		/*server API version*/
    cc_uint32	vendor_offset;		/*offset of vendor blob*/
    cc_uint32	vendor_length;		/*length of vendor blob*/
};      
typedef struct ccmsg_init_t ccmsg_init_t;
typedef struct ccmsg_init_resp_t ccmsg_init_resp_t;

struct ccmsg_clone_t {
    cc_handle   ctx;
    cc_uint32	in_version;		/*client API version*/
};
struct ccmsg_clone_resp_t {
    cc_handle	out_ctx;		/*handle on this ctx*/
    cc_uint32	out_version;		/*server API version*/
    cc_uint32	vendor_offset;		/*offset of vendor blob*/
    cc_uint32	vendor_length;		/*length of vendor blob*/
};      
typedef struct ccmsg_clone_t ccmsg_clone_t;
typedef struct ccmsg_clone_resp_t ccmsg_clone_resp_t;

struct ccmsg_ctx_release_t {
    cc_handle 	ctx;	/*# of ctx to release*/
};
typedef struct ccmsg_ctx_release_t ccmsg_ctx_release_t;

struct ccmsg_ctx_get_change_time_t {
    cc_handle	ctx;
};
struct ccmsg_ctx_get_change_time_resp_t {
    cc_time_t	time;
};
typedef struct ccmsg_ctx_get_change_time_t ccmsg_ctx_get_change_time_t;
typedef struct ccmsg_ctx_get_change_time_resp_t ccmsg_ctx_get_change_time_resp_t;

struct ccmsg_ctx_get_default_ccache_name_t {
    cc_handle	ctx;
};
struct ccmsg_ctx_get_default_ccache_name_resp_t {
    cc_uint32	name_offset;
    cc_uint32	name_len;
};
typedef struct ccmsg_ctx_get_default_ccache_name_t ccmsg_ctx_get_default_ccache_name_t;
typedef struct ccmsg_ctx_get_default_ccache_name_resp_t ccmsg_ctx_get_default_ccache_name_resp_t;

struct ccmsg_ctx_compare_t {
    cc_handle	ctx1;
    cc_handle	ctx2;
};
struct ccmsg_ctx_compare_resp_t {
    cc_uint32	is_equal;	
};
typedef struct ccmsg_ctx_compare_t ccmsg_ctx_compare_t;
typedef struct ccmsg_ctx_compare_resp_t ccmsg_ctx_compare_resp_t;

struct ccmsg_ctx_new_ccache_iterator_t {
    cc_handle	ctx;
};
struct ccmsg_ctx_new_ccache_iterator_resp_t {
    cc_handle	iterator;
};
typedef struct ccmsg_ctx_new_ccache_iterator_t ccmsg_ctx_new_ccache_iterator_t;
typedef struct ccmsg_ctx_new_ccache_iterator_resp_t ccmsg_ctx_new_ccache_iterator_resp_t;

struct ccmsg_ctx_lock_t {
    cc_handle   ctx;
    cc_uint32   lock_type;
};
typedef struct ccmsg_ctx_lock_t ccmsg_ctx_lock_t;

struct ccmsg_ctx_unlock_t {
    cc_handle   ctx;
};
typedef struct ccmsg_ctx_unlock_t ccmsg_ctx_unlock_t;

struct ccmsg_ccache_open_t {
    cc_handle	ctx;
    cc_uint32	name_offset;
    cc_uint32	name_len;
};      
struct ccmsg_ccache_open_resp_t {
    cc_handle	ccache;
};
typedef struct ccmsg_ccache_open_t ccmsg_ccache_open_t;
typedef struct ccmsg_ccache_open_resp_t ccmsg_ccache_open_resp_t;

struct ccmsg_ccache_open_default_t {
    cc_handle	ctx;
};
typedef struct ccmsg_ccache_open_default_t ccmsg_ccache_open_default_t;

struct ccmsg_ccache_create_t {
    cc_handle	ctx;
    cc_uint32	version;
    cc_uint32	principal_offset;
    cc_uint32	principal_len;
    cc_uint32	name_offset;
    cc_uint32	name_len;
};
struct ccmsg_ccache_create_default_t {
    cc_handle	ctx;
    cc_uint32	version;
    cc_uint32	principal_offset;
    cc_uint32	principal_len;
};
struct ccmsg_ccache_create_unique_t {
    cc_handle	ctx;
    cc_uint32	version;
    cc_uint32	principal_offset;
    cc_uint32	principal_len;
};

struct ccmsg_ccache_create_resp_t {
    cc_handle	ccache;
};
typedef struct ccmsg_ccache_create_t ccmsg_ccache_create_t;
typedef struct ccmsg_ccache_create_default_t ccmsg_ccache_create_default_t;
typedef struct ccmsg_ccache_create_unique_t ccmsg_ccache_create_unique_t;
typedef struct ccmsg_ccache_create_resp_t ccmsg_ccache_create_resp_t;

struct ccmsg_ccache_release_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
typedef struct ccmsg_ccache_release_t ccmsg_ccache_release_t;

struct ccmsg_ccache_destroy_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
typedef struct ccmsg_ccache_destroy_t ccmsg_ccache_destroy_t;

struct ccmsg_ccache_set_default_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
typedef struct ccmsg_ccache_set_default_t ccmsg_ccache_set_default_t;

struct ccmsg_ccache_get_creds_version_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
struct ccmsg_ccache_get_creds_version_resp_t {
    cc_uint32	version;
};
typedef struct ccmsg_ccache_get_creds_version_t ccmsg_ccache_get_creds_version_t;
typedef struct ccmsg_ccache_get_creds_version_resp_t ccmsg_ccache_get_creds_version_resp_t;

struct ccmsg_ccache_get_name_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
struct ccmsg_ccache_get_name_resp_t {
    cc_uint32	name_offset;
    cc_uint32	name_len;
};      
typedef struct ccmsg_ccache_get_name_t ccmsg_ccache_get_name_t;
typedef struct ccmsg_ccache_get_name_resp_t ccmsg_ccache_get_name_resp_t;

struct ccmsg_ccache_get_principal_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_uint32	version;
};
struct ccmsg_ccache_get_principal_resp_t {
    cc_uint32	principal_offset;
    cc_uint32	principal_len;
};
typedef struct ccmsg_ccache_get_principal_t ccmsg_ccache_get_principal_t;
typedef struct ccmsg_ccache_get_principal_resp_t ccmsg_ccache_get_principal_resp_t;

struct ccmsg_ccache_set_principal_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_uint32	version;	
    cc_uint32	principal_offset;
    cc_uint32	principal_len;
};
typedef struct ccmsg_ccache_set_principal_t ccmsg_ccache_set_principal_t;

struct ccmsg_ccache_creds_iterator_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
struct ccmsg_ccache_creds_iterator_resp_t {
    cc_handle	iterator;
};
typedef struct ccmsg_ccache_creds_iterator_t ccmsg_ccache_creds_iterator_t;
typedef struct ccmsg_ccache_creds_iterator_resp_t ccmsg_ccache_creds_iterator_resp_t;

struct ccmsg_ccache_store_creds_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_uint32   creds_version;
    cc_uint32	creds_offset;
    cc_uint32	creds_len;
};
typedef struct ccmsg_ccache_store_creds_t ccmsg_ccache_store_creds_t;

struct ccmsg_ccache_rem_creds_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_handle   creds;
};
typedef struct ccmsg_ccache_rem_creds_t ccmsg_ccache_rem_creds_t;

struct ccmsg_ccache_lock_t {
    cc_handle	ctx;
    cc_handle   ccache;
    cc_uint32   lock_type;
};
typedef struct ccmsg_ccache_lock_t ccmsg_ccache_lock_t;

struct ccmsg_ccache_unlock_t {
    cc_handle	ctx;
    cc_handle   ccache;
};
typedef struct ccmsg_ccache_unlock_t ccmsg_ccache_unlock_t;

struct ccmsg_ccache_move_t {
    cc_handle	ctx;
    cc_handle	ccache_source;
    cc_handle   ccache_dest;
};
typedef struct ccmsg_ccache_move_t ccmsg_ccache_move_t;

struct ccmsg_ccache_get_last_default_time_t {
    cc_handle	ctx;
    cc_handle	ccache;
};
struct ccmsg_ccache_get_last_default_time_resp_t {
    cc_time_t	last_default_time;
};
typedef struct ccmsg_ccache_get_last_default_time_t ccmsg_ccache_get_last_default_time_t;
typedef struct ccmsg_ccache_get_last_default_time_resp_t ccmsg_ccache_get_last_default_time_resp_t;

struct ccmsg_ccache_get_change_time_t {
    cc_handle   ctx;
    cc_handle	ccache;
};
struct ccmsg_ccache_get_change_time_resp_t {
    cc_time_t	time;
};
typedef struct ccmsg_ccache_get_change_time_t ccmsg_ccache_get_change_time_t;
typedef struct ccmsg_ccache_get_change_time_resp_t ccmsg_ccache_get_change_time_resp_t;

struct ccmsg_ccache_compare_t {
    cc_handle	ctx;
    cc_handle	ccache1;
    cc_handle	ccache2;
};
struct ccmsg_ccache_compare_resp_t {
    cc_uint32	is_equal;
};
typedef struct ccmsg_ccache_compare_t ccmsg_ccache_compare_t;
typedef struct ccmsg_ccache_compare_resp_t ccmsg_ccache_compare_resp_t;

struct ccmsg_ccache_get_kdc_time_offset_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_int32    creds_version;
};      
struct ccmsg_ccache_get_kdc_time_offset_resp_t {
    cc_time_t	offset;
};
typedef struct ccmsg_ccache_get_kdc_time_offset_t ccmsg_ccache_get_kdc_time_offset_t;
typedef struct ccmsg_ccache_get_kdc_time_offset_resp_t ccmsg_ccache_get_kdc_time_offset_resp_t;

struct ccmsg_ccache_set_kdc_time_offset_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_time_t	offset;
    cc_int32    creds_version;
};
typedef struct ccmsg_ccache_set_kdc_time_offset_t ccmsg_ccache_set_kdc_time_offset_t;

struct ccmsg_ccache_clear_kdc_time_offset_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_int32    creds_version;
};
typedef struct ccmsg_ccache_clear_kdc_time_offset_t ccmsg_ccache_clear_kdc_time_offset_t;

struct ccmsg_ccache_iterator_release_t {
    cc_handle	ctx;
    cc_handle	iterator;
};
typedef struct ccmsg_ccache_iterator_release_t ccmsg_ccache_iterator_release_t;

struct ccmsg_ccache_iterator_next_t {
    cc_handle	ctx;
    cc_handle	iterator;
};
struct ccmsg_ccache_iterator_next_resp_t {
    cc_handle	ccache;
};
typedef struct ccmsg_ccache_iterator_next_t ccmsg_ccache_iterator_next_t;
typedef struct ccmsg_ccache_iterator_next_resp_t ccmsg_ccache_iterator_next_resp_t;

struct ccmsg_creds_iterator_release_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_handle	iterator;
};
typedef struct ccmsg_creds_iterator_release_t ccmsg_creds_iterator_release_t;

struct ccmsg_creds_iterator_next_t {
    cc_handle	ctx;
    cc_handle	ccache;
    cc_handle	iterator;
};
struct ccmsg_creds_iterator_next_resp_t {
    cc_uint32	version;
    cc_handle   creds_handle;
    cc_uint32	creds_offset;
    cc_uint32	creds_len;
};
typedef struct ccmsg_creds_iterator_next_t ccmsg_creds_iterator_next_t;
typedef struct ccmsg_creds_iterator_next_resp_t ccmsg_creds_iterator_next_resp_t;

struct ccmsg_creds_v4_t {
    cc_uint32 offset;
    cc_uint32 len;
};
typedef struct ccmsg_creds_v4_t ccmsg_creds_v4_t;

struct ccmsg_creds_v5_t {
    cc_uint32 client_offset;
    cc_uint32 client_len;
    cc_uint32 server_offset;
    cc_uint32 server_len;
    cc_uint32 keyblock_offset;
    cc_uint32 keyblock_len;
    cc_time_t authtime;
    cc_time_t starttime;
    cc_time_t endtime;
    cc_time_t renewtime;
    cc_uint32 is_skey;
    cc_uint32 ticket_flags;
    cc_uint32 address_count;
    cc_uint32 address_offset;
    cc_uint32 address_len;
    cc_uint32 ticket_offset;
    cc_uint32 ticket_len;
    cc_uint32 ticket2_offset;
    cc_uint32 ticket2_len;
    cc_uint32 authdata_count;
    cc_uint32 authdata_offset;
    cc_uint32 authdata_len;
};
typedef struct ccmsg_creds_v5_t ccmsg_creds_v5_t;


#endif /*__MSG_HEADERS_H__*/

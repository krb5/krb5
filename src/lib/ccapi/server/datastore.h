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
 * Prototypes and data structures for datastore.
 *
 */


#ifndef __CCDATASTOREH__
#define __CCDATASTOREH__

#include "CredentialsCache.h"
#include "rpc_auth.h"

enum cc_list_type {
    generic = 0,
    context,
    cache,
    credentials
};

struct cc_generic_list_node_t {
    cc_uint8* 				data;
    cc_uint32 	        		len;
    struct cc_generic_list_node_t*	next;
    struct cc_generic_list_node_t*	prev;
};
typedef struct cc_generic_list_node_t cc_generic_list_node_t;

struct cc_generic_list_head_t {
    enum cc_list_type                   type;
    cc_generic_list_node_t*		head;
    cc_generic_list_node_t*		tail; 
};      
typedef struct cc_generic_list_head_t cc_generic_list_head_t;


struct cc_generic_iterate_t {
    cc_generic_list_node_t*     	next;
};
typedef struct cc_generic_iterate_t cc_generic_iterate_t;

typedef cc_generic_list_head_t cc_context_list_head_t;
typedef cc_generic_list_node_t cc_context_list_node_t;

typedef cc_generic_list_head_t cc_ccache_list_head_t;
typedef cc_generic_list_node_t cc_ccache_list_node_t;

typedef cc_generic_list_head_t cc_credentials_list_head_t;
typedef cc_generic_list_node_t cc_credentials_list_node_t;

struct cc_context_iterate_t {
    cc_context_list_node_t*	next;
};
typedef struct cc_context_iterate_t cc_context_iterate_t;

struct cc_ccache_iterate_t {
    cc_ccache_list_node_t*	next;
};
typedef struct cc_ccache_iterate_t cc_ccache_iterate_t;

struct cc_credentials_iterate_t {
    cc_credentials_list_node_t*	next;
};
typedef struct cc_credentials_iterate_t cc_credentials_iterate_t;

struct cc_lock_t {
    cc_uint32                           read_locks;             /* count of read locks (>= 0) */
    cc_uint32                           write_locks;            /* count of write locks (0 or 1) */
    void *                              platform_data;          /* platform specific implementation data */
};
typedef struct cc_lock cc_lock_t;


struct cc_server_context_t {
    cc_ccache_list_head_t*		ccaches;		/*our ccaches*/
    cc_generic_list_head_t*		active_iterators;	/*active ccache iterators*/
    cc_int32			        api_version;		/*Version our client passed in on init (ccapi_version_X) */
    cc_auth_info_t*			auth_info;		/*auth info passed in from RPC*/
    cc_session_info_t*		        session_info;		/*session info passed in from RPC*/
    cc_time_t			        changed;		/*date of last change to this context*/
    cc_int32                            error;                  /*last error code*/
    cc_lock_t                           locks;                  /*are we locked?*/
};                                                              
typedef struct cc_server_context_t cc_server_context_t;

struct cc_server_ccache_t {
    char*				name;			/*name of this ccache*/
    char*				principal_v4;		/*v4 principal associated with this cache*/
    char*				principal_v5;		/*v5 principal associated with this cache*/
    cc_uint32			        versions;		/*versions of creds supported (from cc_credentials enum in CredentialsCache.h)*/
    cc_time_t			        changed;		/*date of last change to ccache*/
    cc_int32			        kdc_set;		/*is the KDC time offset initialized?*/
    cc_time_t		        	kdc_offset;		/*offset of our clock relative kdc*/
    cc_time_t			        last_default;		/*the last date when we were default*/
    cc_int32			        is_default;		/*is this the default cred on this ccache?*/
    cc_generic_list_head_t*		active_iterators;	/*iterators which clients have opened on this cache*/
    cc_credentials_list_head_t*	creds;				/*list of creds stored in this ccache*/
    cc_server_context_t*		mycontext;		/*context to which I belong*/
    cc_lock_t                           locks;                  /*are we locked?*/
};
typedef struct cc_server_ccache_t cc_server_ccache_t;

struct cc_server_credentials_t {
    cc_int32			        is_default;		/*Are we the default cred? (first in list)*/
    cc_credentials_union		creds;
};
typedef struct cc_server_credentials_t cc_server_credentials_t;


/*Note: cci means Credential Cache Internal, to differentiate from exported API macros*/

cc_int32 cci_generic_iterate_has_next(cc_generic_iterate_t *iterate);
cc_int32 cci_generic_iterate_next(cc_generic_iterate_t *iterate, cc_generic_list_node_t**);

cc_int32 cci_generic_list_new(cc_generic_list_head_t **);
cc_int32 cci_generic_list_append(cc_generic_list_head_t *head, void *data, cc_uint32 len, cc_generic_list_node_t**);
cc_int32 cci_generic_list_prepend(cc_generic_list_head_t *head, void *data, cc_uint32 len, cc_generic_list_node_t**);
cc_int32 cci_generic_list_remove_element(cc_generic_list_head_t* head, cc_generic_list_node_t* rem);
cc_int32 cci_generic_free_element(cc_generic_list_node_t* node);
cc_int32 cci_generic_list_destroy(cc_generic_list_head_t* head);
cc_int32 cci_generic_list_copy(cc_generic_list_head_t* head, cc_generic_list_head_t**);
cc_int32 cci_generic_list_iterator(cc_generic_list_head_t *head, cc_generic_iterate_t**);
cc_int32 cci_generic_free_iterator(cc_generic_iterate_t* iterator);

cc_int32 cci_context_iterate_has_next(struct cc_context_iterate_t *iterate);
cc_int32 cci_context_iterate_next(struct cc_context_iterate_t *iterate, cc_context_list_node_t**);

cc_int32 cci_ccache_iterate_has_next(struct cc_ccache_iterate_t *iterate);
cc_int32 cci_ccache_iterate_next(struct cc_ccache_iterate_t *iterate, cc_ccache_list_node_t**);

cc_int32 cci_credentials_iterate_has_next(cc_credentials_iterate_t *iterate);
cc_int32 cci_credentials_iterate_next(cc_credentials_iterate_t *iterate, cc_credentials_list_node_t **);

cc_int32 cci_context_list_new(cc_context_list_head_t**);
cc_int32 cci_context_list_append(cc_context_list_head_t *head, cc_server_context_t *data, cc_context_list_node_t**);
cc_int32 cci_context_list_prepend(cc_context_list_head_t *head, cc_server_context_t *data, cc_context_list_node_t**);
cc_int32 cci_context_list_remove_element(cc_context_list_head_t* head, cc_context_list_node_t* rem);
cc_int32 cci_context_list_iterator(cc_context_list_head_t *head, struct cc_context_iterate_t**);
cc_int32 cci_context_free_iterator(struct cc_context_iterate_t *iterator);
cc_int32 cci_context_list_destroy(cc_context_list_head_t* head) ;
cc_int32 cci_context_list_copy(cc_context_list_head_t* head, cc_context_list_head_t**);

cc_int32 cci_ccache_list_new(cc_ccache_list_head_t**);
cc_int32 cci_ccache_list_append(cc_ccache_list_head_t *head, cc_server_ccache_t *data, cc_ccache_list_node_t**);
cc_int32 cci_ccache_list_prepend(cc_ccache_list_head_t *head, cc_server_ccache_t *data, cc_ccache_list_node_t**);
cc_int32 cci_ccache_list_remove_element(cc_ccache_list_head_t* head, cc_ccache_list_node_t* rem);
cc_int32 cci_ccache_list_iterator(cc_ccache_list_head_t *head, struct cc_ccache_iterate_t**);
cc_int32 cci_ccache_free_iterator(struct cc_ccache_iterate_t *iterator);
cc_int32 cci_ccache_list_destroy(cc_ccache_list_head_t* head) ;
cc_int32 cci_ccache_list_copy(cc_ccache_list_head_t* head, cc_ccache_list_head_t**);


cc_int32 cci_credentials_list_new(cc_credentials_list_head_t**);
cc_int32 cci_credentials_list_append(cc_credentials_list_head_t *head, cc_server_credentials_t *data, cc_credentials_list_node_t**);
cc_int32 cci_credentials_list_prepend(cc_credentials_list_head_t *head, cc_server_credentials_t *data, cc_credentials_list_node_t**);
cc_int32 cci_credentials_list_remove_element(cc_credentials_list_head_t* head, cc_credentials_list_node_t* rem);
cc_int32 cci_credentials_list_iterator(cc_credentials_list_head_t *head, cc_credentials_iterate_t**);
cc_int32 cci_credentials_free_iterator(cc_credentials_iterate_t* iterator);
cc_int32 cci_credentials_list_destroy(cc_credentials_list_head_t* head) ;
cc_int32 cci_credentials_list_copy(cc_credentials_list_head_t* head, cc_credentials_list_head_t**) ;


cc_int32 cci_context_new(int api_version, cc_auth_info_t* auth_info, cc_session_info_t* session_info, cc_server_context_t** ) ;
cc_int32 cci_context_get_default_ccache_name(cc_server_context_t* ctx, char **);
cc_int32 cci_context_find_ccache(cc_server_context_t* ctx, char *name, cc_server_ccache_t**);
cc_int32 cci_context_open_ccache(cc_server_context_t* ctx, char *name, cc_server_ccache_t** );
cc_int32 cci_context_create_ccache(cc_server_context_t* ctx, char *name, int creds_version, char *principal, cc_server_ccache_t**);
cc_int32 cci_context_create_default_ccache(cc_server_context_t* ctx, int creds_version, char *principal, cc_server_ccache_t**);
cc_int32 cci_context_ccache_iterator(cc_server_context_t* ctx, cc_ccache_iterate_t**);
cc_int32 cci_context_compare(cc_server_context_t* a, cc_server_context_t* b);
cc_int32 cci_context_destroy(cc_server_context_t* ctx);
cc_int32 cci_context_rem_ccache(cc_server_context_t* ctx, cc_server_ccache_t* ccache);

cc_int32 cci_ccache_new(char *name, char *principal, int cred_vers, cc_server_ccache_t**);
cc_int32 cci_ccache_check_version(const cc_server_ccache_t *ccache, const cc_credentials_union* creds, cc_uint32* compat);
cc_int32 cci_ccache_check_principal(const cc_server_ccache_t *ccache, const cc_credentials_union* creds, cc_uint32* compat);
cc_int32 cci_ccache_store_creds(cc_server_ccache_t *ccache, const cc_credentials_union* credentials);
cc_int32 cci_ccache_rem_creds(cc_server_ccache_t *ccache, const cc_credentials_union* credentials);
cc_int32 cci_ccache_move(cc_server_ccache_t *source, cc_server_ccache_t* destination);
cc_int32 cci_ccache_get_kdc_time_offset(cc_server_ccache_t* ccache, cc_time_t* offset);
cc_int32 cci_ccache_set_kdc_time_offset(cc_server_ccache_t* ccache, cc_time_t offset);
cc_int32 cci_ccache_clear_kdc_time_offset(cc_server_ccache_t* ccache);
cc_int32 cci_ccache_new_iterator(cc_server_ccache_t* ccache, cc_credentials_iterate_t** iterator);
cc_int32 cci_ccache_get_principal(cc_server_ccache_t* ccache, cc_int32 version, char ** principal);
cc_int32 cci_ccache_set_principal(cc_server_ccache_t* ccache, cc_int32 version, char * principal);
cc_int32 cci_ccache_free_principal(char * principal);
cc_int32 cci_ccache_destroy(cc_server_ccache_t* ccache);
void	 cci_ccache_changed(cc_server_ccache_t* ccache);
cc_int32 cci_ccache_compare(cc_server_ccache_t* ccache1, cc_server_ccache_t* ccache2, cc_uint32 *result);
#endif /*__CCDATASTOREH__*/

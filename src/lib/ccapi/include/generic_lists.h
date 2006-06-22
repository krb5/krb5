/* $Copyright:
 *
 * Copyright 2004-2006 by the Massachusetts Institute of Technology.
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


#ifndef __CC_GENERIC_LISTS_H_
#define __CC_GENERIC_LISTS_H_

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

#endif /* __CC_GENERIC_LISTS_H_ */

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
 * Lists implementation.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "CredentialsCache.h"
#include "datastore.h"

/**
 * ccs_context_iterate_has_next()
 *
 * Purpose: Determine if a context iterator has a next element
 *
 * Return:  1 if another element exists
 *          0 if no additional elements exist
 */
cc_int32 
ccs_context_iterate_has_next(cc_context_iterate_t *iterate) 
{
    if ( iterate == NULL )
        return 0;
    
    return cci_generic_iterate_has_next((cc_generic_iterate_t*)iterate);
}

/**
 * ccs_context_iterate_next()
 *
 * Purpose: Retrieve the next element from a context iterator and advance
 *          the iterator
 *
 * Return:  non-NULL, the next element in the iterator
 *          NULL, the iterator list is empty or iterator is invalid
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_context_iterate_next(cc_context_iterate_t *iterate, cc_context_list_node_t ** nodepp)
{
    if ( iterate == NULL || nodepp == NULL)
        return ccErrBadParam;
    
    return cci_generic_iterate_next((cc_generic_iterate_t*)iterate,(cc_context_list_node_t**)nodepp);
}

/**
 * ccs_ccache_iterate_has_next()
 *
 * Purpose: Determine if a cache iterator has a next element
 *
 * Return:  1 if another element exists
 *          0 if no additional elements exist
 *         -1 if error
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32 
ccs_ccache_iterate_has_next(cc_ccache_iterate_t *iterate) 
{
    if ( iterate == NULL )
        return 0;
    return cci_generic_iterate_has_next((cc_generic_iterate_t*)iterate);
}

/**
 * ccs_ccache_iterate_next()
 * 
 * Purpose: Retrieve the next element from a ccache iterator and advance
 *          the iterator
 *
 * Return:  non-NULL, the next element in the iterator
 *          NULL, the iterator list is empty or iterator is invalid
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_ccache_iterate_next(cc_ccache_iterate_t *iterate, cc_ccache_list_node_t ** nodepp)
{
    if ( iterate == NULL || nodepp == NULL)
        return ccErrBadParam;
    
    return cci_generic_iterate_next((cc_generic_iterate_t*)iterate, (cc_ccache_list_node_t**)nodepp);
}

/**
 * ccs_credentials_iterate_has_next()
 *
 * Purpose: Determine if a credentials iterator has a next element
 *
 * Return:  1 if another element exists
 *          0 if no additional elements exist
 *         -1 if error
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32 
ccs_credentials_iterate_has_next(cc_credentials_iterate_t *iterate) 
{
    if ( iterate == NULL )
        return 0;
    
    return cci_generic_iterate_has_next((cc_generic_iterate_t*)iterate);
}

/**
 * ccs_credentials_iterate_next()
 * 
 * Purpose: Retrieve the next element from a credentials iterator and advance
 *          the iterator
 *
 * Return:  non-NULL, the next element in the iterator
 *          NULL, the iterator list is empty or iterator is invalid
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_credentials_iterate_next(cc_credentials_iterate_t *iterate, cc_credentials_list_node_t** nodepp) 
{
    if ( iterate == NULL || nodepp == NULL )
        return ccErrBadParam;
    return cci_generic_iterate_next((cc_generic_iterate_t*)iterate, (cc_credentials_list_node_t**)nodepp);
}

/**
 * ccs_context_list_destroy()
 *
 * Purpose: Deallocate a list and all of its contents
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 */
cc_int32
ccs_context_list_destroy(cc_context_list_head_t* head) 
{
    return cci_generic_list_destroy((cc_generic_list_head_t*)head);
}

/**
 * ccs_ccache_list_destroy()
 *
 * Purpose: Deallocate a list and all of its contents
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 */
cc_int32
ccs_ccache_list_destroy(cc_ccache_list_head_t* head) 
{
    return cci_generic_list_destroy((cc_generic_list_head_t*)head);
}

/**
 * ccs_credentials_list_destroy()
 *
 * Purpose: Deallocate a list and all of its contents
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 */
cc_int32
ccs_credentials_list_destroy(cc_credentials_list_head_t* head) 
{
    return cci_generic_list_destroy((cc_generic_list_head_t*)head);
}

/**
 * ccs_context_list_copy()
 *
 * Purpose: Copy a list
 *
 * Return:  non-NULL, a new list
 *          NULL, failure
 *
 * Errors:  ccErrBadParam, ccErrNoMem
 *
 */
cc_int32
ccs_context_list_copy(cc_context_list_head_t* head, cc_context_list_head_t** headpp ) 
{
    return cci_generic_list_copy((cc_generic_list_head_t*)head, (cc_context_list_head_t **)headpp);
}

/**
 * ccs_ccache_list_copy()
 *
 * Purpose: Copy a list
 *
 * Return:  non-NULL, a new list
 *          NULL, failure
 *
 * Errors:  ccErrBadParam, ccErrNoMem
 */
cc_int32
ccs_ccache_list_copy(cc_ccache_list_head_t* head, cc_ccache_list_head_t** headpp)
{
    return cci_generic_list_copy((cc_generic_list_head_t*)head, (cc_ccache_list_head_t **)headpp);
}

/**
 * ccs_credentials_list_copy()
 *
 * Purpose: Copy a list
 *
 * Return:  non-NULL, a new list
 *          NULL, failure
 *
 * Errors:  ccErrBadParam, ccErrNoMem
 *
 */
cc_int32
ccs_credentials_list_copy(cc_credentials_list_head_t* head, cc_credentials_list_head_t** headpp) 
{
    return cci_generic_list_copy((cc_generic_list_head_t*)head, (cc_credentials_list_head_t **)headpp);
}


/**
 * ccs_context_list_new()
 *
 * Purpose: Allocate a new context list
 *
 * Return:  non-NULL, a new list
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 *
 */
cc_int32
ccs_context_list_new(cc_context_list_head_t ** headpp) 
{
    cc_context_list_head_t *ret;
    
    if ( headpp == NULL )
        return ccErrBadParam;

    ret = (cc_context_list_head_t *)malloc(sizeof(cc_context_list_head_t));
    if (ret == NULL)
        return ccErrNoMem;
    ret->head = ret->tail = NULL;
    *headpp = ret;
    return ccNoError;
}

/**
 * ccs_context_list_append()
 *
 * Purpose: Appends a new node containing a copy of 'len' bytes of 'data' 
 *
 * Return:  non-NULL, a pointer to the newly allocated node
 *          NULL, failure
 *
 * Errors:  ccErrNoMem,ccErrBadParam
 *
 */
cc_int32
ccs_context_list_append(cc_context_list_head_t *head, cc_server_context_t *data, cc_context_list_node_t** nodepp) 
{
    return cci_generic_list_append((cc_generic_list_head_t *)head, (void *)data, sizeof(cc_server_context_t), (cc_context_list_node_t**)nodepp);
}

/**
 * ccs_context_list_prepend()
 *
 * Purpose: Prepends a new node containing a copy of 'len' bytes of 'data' 
 *
 * Return:  non-NULL, a pointer to the newly allocated node
 *          NULL, failure
 *
 * Errors:  ccErrNoMem,ccErrBadParam
 *
 */
cc_int32
ccs_context_list_prepend(cc_context_list_head_t *head, cc_server_context_t *data, cc_context_list_node_t** nodepp ) 
{
    return cci_generic_list_prepend((cc_generic_list_head_t *)head, (void *)data, sizeof(cc_server_context_t), (cc_context_list_node_t**)nodepp);
}

/**
 * ccs_context_list_remove_element
 *
 * Purpose: Remove a node from the list
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 */
cc_int32
ccs_context_list_remove_element(cc_context_list_head_t* head, cc_context_list_node_t* rem) 
{
    return cci_generic_list_remove_element((cc_generic_list_head_t*)head, (cc_generic_list_node_t*)rem);
}

/**
 * ccs_context_list_iterator()
 *
 * Purpose: Allocate an iterator for the specified list
 *
 * Return:  non-NULL, an iterator
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 *
 */
cc_int32
ccs_context_list_iterator(cc_context_list_head_t *head, cc_context_iterate_t** iterpp) 
{
    cc_context_iterate_t* iterator;
    
    if ( head == NULL || iterpp == NULL )
        return ccErrBadParam;

    iterator = (cc_context_iterate_t*)malloc(sizeof(cc_context_iterate_t));
    if (iterator == NULL)
        return ccErrNoMem;

    iterator->next = head->head;
    *iterpp = iterator;
    return ccNoError;
}

/**
 * ccs_context_free_iterator()
 *
 * Purpose: Deallocate memory associated with an iterator
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_context_free_iterator(cc_context_iterate_t* iterator)
{
    if ( iterator == NULL )
        return ccErrBadParam;

    iterator->next = NULL;
    free(iterator);
    return ccNoError;
}

/**
 * ccs_ccache_list_new()
 *
 * Purpose: Allocate a new ccache list
 *
 * Return:  non-NULL, a new list
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 */
cc_int32
ccs_ccache_list_new(cc_ccache_list_head_t ** listpp)
{
    cc_ccache_list_head_t *ret;
    
    if ( listpp == NULL )
        return ccErrBadParam;

    ret = (cc_ccache_list_head_t *)malloc(sizeof(cc_ccache_list_head_t));
    if (ret == NULL)
        return ccErrNoMem;

    ret->head = ret->tail = NULL;
    *listpp = ret;
    return ccNoError;
}

/**
 * ccs_ccache_list_append()
 *
 * Purpose: Appends a new node containing a copy of 'len' bytes of 'data' 
 *
 * Return:  non-NULL, a pointer to the newly allocated node
 *          NULL, failure
 *
 * Errors:  ccErrNoMem,ccErrBadParam
 *
 */
cc_int32
ccs_ccache_list_append(cc_ccache_list_head_t *head, cc_server_ccache_t *data, cc_ccache_list_node_t** nodepp) 
{
    return cci_generic_list_append((cc_generic_list_head_t *)head, (void *)data, sizeof(cc_server_ccache_t), (cc_ccache_list_node_t**)nodepp);
}

/**
 * ccs_ccache_list_prepend()
 *
 * Purpose: Prepends a new node containing a copy of 'len' bytes of 'data' 
 *
 * Return:  non-NULL, a pointer to the newly allocated node
 *          NULL, failure
 *
 * Errors:  ccErrNoMem,ccErrBadParam
 *
 */
cc_int32
ccs_ccache_list_prepend(cc_ccache_list_head_t *head, cc_server_ccache_t *data, cc_ccache_list_node_t** nodepp) 
{
    return cci_generic_list_prepend((cc_generic_list_head_t *)head, (void *)data, sizeof(cc_server_ccache_t), (cc_ccache_list_node_t**)nodepp);
}

/**
 * ccs_ccache_list_remove_element()
 *
 * Purpose: Remove a node from the list
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_ccache_list_remove_element(cc_ccache_list_head_t* head, cc_ccache_list_node_t* rem) 
{
    return cci_generic_list_remove_element((cc_generic_list_head_t*)head, (cc_generic_list_node_t*)rem);
}

/**
 * ccs_ccache_list_iterator()
 *
 * Purpose: Allocate an iterator for the specified list
 *
 * Return:  non-NULL, an iterator
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 *
 */
cc_int32
ccs_ccache_list_iterator(cc_ccache_list_head_t *head, cc_ccache_iterate_t** iterpp) 
{
    cc_ccache_iterate_t* iterator;
    
    if ( head == NULL || iterpp == NULL )
        return ccErrBadParam;

    iterator = (cc_ccache_iterate_t*)malloc(sizeof(cc_ccache_iterate_t));
    if (iterator == NULL)
        return ccErrNoMem;

    iterator->next = head->head;
    *iterpp = iterator;
    return ccNoError;
}

/**
 * ccs_ccache_free_iterator()
 *
 * Purpose: Deallocate memory associated with an iterator
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_ccache_free_iterator(cc_ccache_iterate_t* iterator)
{
    if ( iterator == NULL )
        return ccErrBadParam;

    iterator->next = NULL;
    free(iterator);
    return ccNoError;
}

/**
 * ccs_credentials_list_new()
 *
 * Purpose: Allocate a new ccache list
 *
 * Return:  non-NULL, a new list
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 *
 */
cc_int32
ccs_credentials_list_new(cc_credentials_list_head_t ** list) 
{
    if ( list == NULL )
        return ccErrBadParam;

    *list = (cc_credentials_list_head_t *)malloc(sizeof(cc_credentials_list_head_t));
    if (*list == NULL)
        return ccErrNoMem;

    (*list)->head = (*list)->tail = NULL;
    return ccNoError;
}

/**
 * ccs_credentials_list_append()
 *
 * Purpose: Appends a new node containing a copy of 'len' bytes of 'data' 
 *
 * Return:  non-NULL, a pointer to the newly allocated node
 *          NULL, failure
 *
 * Errors:  ccErrNoMem,ccErrBadParam
 *
 */
cc_int32
ccs_credentials_list_append(cc_credentials_list_head_t *head, cc_server_credentials_t *data, cc_credentials_list_node_t** nodepp ) 
{
    return cci_generic_list_append((cc_generic_list_head_t *)head, (void *)data, sizeof(cc_server_credentials_t), (cc_credentials_list_node_t**)nodepp);
}

/**
 * ccs_credentials_list_prepend()
 *
 * Purpose: Prepends a new node containing a copy of 'len' bytes of 'data' 
 *
 * Return:  non-NULL, a pointer to the newly allocated node
 *          NULL, failure
 *
 * Errors:  ccErrNoMem,ccErrBadParam
 *
 */
cc_int32
ccs_credentials_list_prepend(cc_credentials_list_head_t *head, cc_server_credentials_t *data, cc_credentials_list_node_t** nodepp) 
{
    return cci_generic_list_prepend((cc_generic_list_head_t *)head, (void *)data, sizeof(cc_server_credentials_t), (cc_credentials_list_node_t**)nodepp);
}

/**
 * ccs_credentials_list_remove_element()
 *
 * Purpose: Remove a node from the list
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32 
ccs_credentials_list_remove_element(cc_credentials_list_head_t* head, cc_credentials_list_node_t* rem) 
{
    return cci_generic_list_remove_element((cc_generic_list_head_t*)head, (cc_generic_list_node_t*)rem);
}

/**
 * ccs_credentials_list_iterator()
 *
 * Purpose: Allocate an iterator for the specified list
 *
 * Return:  non-NULL, an iterator
 *          NULL, failure
 *
 * Errors:  ccErrNoMem
 *
 */
cc_int32
ccs_credentials_list_iterator(cc_credentials_list_head_t *head, cc_credentials_iterate_t** iterpp) 
{
    cc_credentials_iterate_t* iterator;
    
    if ( head == NULL || iterpp == NULL )
        return ccErrBadParam;

    iterator = (cc_credentials_iterate_t*)malloc(sizeof(cc_credentials_iterate_t));
    if (iterator == NULL)
        return ccErrNoMem;

    iterator->next = head->head;
    *iterpp = iterator;
    return ccNoError;
}

/**
 * ccs_credentials_free_iterator()
 *
 * Purpose: Deallocate memory associated with an iterator
 *
 * Return:  0, success
 *         -1, failure
 *
 * Errors:  ccErrBadParam
 *
 */
cc_int32
ccs_credentials_free_iterator(cc_credentials_iterate_t* iterator)
{
    if ( iterator == NULL )
        return ccErrBadParam;

    iterator->next = NULL;
    free(iterator);
    return ccNoError;
}


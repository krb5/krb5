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
 * Manages ccache objects.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "CredentialsCache.h"
#include "datastore.h"

/**
 * ccache_new()
 * 
 * Purpose: Allocate and initialize new credentials cache for the specified principal
 *          and version
 * 
 * Return:  ccNoError - success
 *          ccErrInvalidString - name or principal is NULL
 *          ccErrBadCredentialsVersion - unsupported creds type
 *          ccErrBadParam - outCcachepp is NULL
 *          ccErrNoMem - malloc failed
 */
cc_int32
cci_ccache_new( char *name, char *principal, int cred_vers, 
                cc_server_ccache_t** outCCachepp)
{
    cc_server_ccache_t* ccache;

    if (name == NULL || principal == NULL)
        return ccErrInvalidString;

    if (cred_vers != cc_credentials_v4 && cred_vers != cc_credentials_v5 && 
         cred_vers != cc_credentials_v4_v5)
        return ccErrBadCredentialsVersion;

    if (outCCachepp == NULL)
        return ccErrBadParam;

    ccache = (cc_server_ccache_t*)malloc(sizeof(cc_server_ccache_t));
    if (ccache == NULL)
        return ccErrNoMem;

    ccache->name = name;
    ccache->principal_v4 = NULL;
    ccache->principal_v5 = NULL;
    ccache->changed = time(NULL);
    ccache->kdc_offset = 0;
    ccache->last_default = 0;
    cci_generic_list_new(&ccache->active_iterators);
    cci_credentials_list_new(&ccache->creds);
    ccache->is_default = 0;
    ccache->kdc_set = 0;
    ccache->versions = cred_vers;
    ccache->mycontext = NULL;

    cci_ccache_set_principal(ccache, cred_vers, principal);
    *outCCachepp = ccache;
    return ccNoError;
}

/**
 * cci_ccache_check_version()
 * 
 * Purpose: Check to see if the ccache and the creds have compatible versions. 
 * 
 * Return:  ccNoError and compat = 1 if they are compatible 
 *          ccNoError and compat = 0 if they are not compatible
 * 
 * Errors:  ccErrInvalidCCache - ccache is NULL
 *          ccErrBadParam - either creds or compat are NULL
 */
cc_int32 
cci_ccache_check_version( const cc_server_ccache_t *ccache,
                          const cc_credentials_union* creds,
                          cc_uint32* compat)
{
    if (ccache == NULL)
        return ccErrInvalidCCache;

    if (creds == NULL || compat == NULL)
        return ccErrBadParam;

    if (ccache->versions == cc_credentials_v4_v5)
        *compat = 1;
    else if (ccache->versions == creds->version)
        *compat = 1;
    else
        *compat = 0;

    return ccNoError;
}

/** 
cci_ccache_check_principal()

Check to see if the client principal from the credentials matches
the principal associated with the cache.

* Return:  ccNoError and compat = 1 if they are compatible 
*          ccNoError and compat = 0 if they are not compatible
* 
* Errors:  ccErrInvalidCCache - ccache is NULL
*          ccErrBadParam - either creds or compat are NULL
*          ccErrBadCredentialVersion - unsupported credential type
*/
cc_int32 
cci_ccache_check_principal( const cc_server_ccache_t *ccache,
                            const cc_credentials_union* creds,
                            cc_uint32* compat)
{
    if (ccache == NULL)
        return ccErrInvalidCCache;

    if (creds == NULL || compat == NULL)
        return ccErrBadParam;

    if (creds->version == cc_credentials_v4) {
        if (strcmp(creds->credentials.credentials_v4->principal, ccache->principal_v4) == 0) 
            *compat = 1;
        else 
            *compat = 0;
    } else if (creds->version == cc_credentials_v5) {
        if (strcmp(creds->credentials.credentials_v5->client, ccache->principal_v5) == 0)
            *compat = 1;
        else 
            *compat = 0;
    } else {        
        return ccErrBadCredentialsVersion;
    }
    return ccNoError;
}


/** 
 * cci_ccache_store_creds()
 *
 * Purpose: Stores the provided credentials into the provided cache.  Validates the
 *          ability of the cache to store credentials of the given version and client
 *          principal.
 *
 * Return:  0 on success
 *         -1 on error
 *
 * Errors: ccErrNoMem
 *         ccErrBadCredentialsVersion
 *         ccErrBadInvalidCredentials
 *         ccErrInvalidCache
 *         ccErrBadParam
 */
cc_int32 
cci_ccache_store_creds(cc_server_ccache_t *ccache, const cc_credentials_union* credentials) 
{
    cc_server_credentials_t* stored_cred=NULL;
    cc_uint32 valid_version, valid_principal;
    cc_int32 code;

    if (ccache == NULL)
        return ccErrInvalidCCache;
    
    if (credentials == NULL)
        return ccErrBadParam;

    code = cci_ccache_check_version(ccache, credentials, &valid_version);
    if (code != ccNoError) {
        /* pass error on to caller */
        goto bad;
    }
    code = cci_ccache_check_principal(ccache, credentials, &valid_principal);
    if (code != ccNoError) {
        /* pass error on to caller */
        goto bad;
    }
    if (valid_version && valid_principal) {
        stored_cred = (cc_server_credentials_t*)malloc(sizeof(cc_server_credentials_t));
        if (stored_cred == NULL) {
            code = ccErrNoMem;
            goto bad;
        }
        memcpy(&stored_cred->creds, credentials, sizeof(cc_credentials_union));

        if (credentials->version == cc_credentials_v4) {
            stored_cred->creds.credentials.credentials_v4 = (cc_credentials_v4_t*)malloc(sizeof(cc_credentials_v4_t));
            if (stored_cred->creds.credentials.credentials_v4 == NULL) {
                code = ccErrNoMem;
                goto bad;
            }

            memcpy(stored_cred->creds.credentials.credentials_v4, credentials->credentials.credentials_v4, sizeof(cc_credentials_v4_t));
        } else if (credentials->version == cc_credentials_v5) {
            stored_cred->creds.credentials.credentials_v5 = (cc_credentials_v5_t*)malloc(sizeof(cc_credentials_v5_t));
            if (stored_cred->creds.credentials.credentials_v5 == NULL) {
                code = ccErrNoMem;
                goto bad;
            }

            memcpy(stored_cred->creds.credentials.credentials_v5, credentials->credentials.credentials_v5, sizeof(cc_credentials_v5_t));
        } else {
            code = ccErrBadCredentialsVersion;
            goto bad;
        }

        code = cci_credentials_list_append(ccache->creds, stored_cred, NULL);
        if ( code != ccNoError ) {
            /* pass error on to caller */
            goto bad;
        }
        if (ccache->creds->head->data == (cc_uint8 *)stored_cred) 
            stored_cred->is_default = 1; /*we're first on the list, so we're default*/

        cci_ccache_changed(ccache);
        return ccNoError;
    } else {
#ifdef DEBUG
        printf("vers: %d\tprincipal: %d\n",
                valid_version, valid_principal);
#endif /* DEBUG */
        code = ccErrInvalidCredentials;
        goto bad;
    }

  bad:
    if (stored_cred)
        free(stored_cred);
    return code;      /* error */
}

/**
 * cci_ccache_changed()
 *
 * Purpose: Updates the last update time for the ccache and its associated context.
 *          Provides a location from which interested parties should be notified
 *          of cache updates.
 *
 * Return:  none
 *
 * Errors:  none
 */
void 
cci_ccache_changed(cc_server_ccache_t* ccache) 
{
    ccache->changed = time(NULL);
    if (ccache->mycontext != NULL)
        ccache->mycontext->changed = time(NULL);

    /* XXX - notify registered listeners when implemented */
}

/**
 * cci_ccache_rem_creds()
 *
 * Purpose: Removes the specified credential object from the specified cache if
 *          it exists
 *
 * Return:  0 on success (credential is not in the cache)
 *         -1 on error
 *
 * Errors: ccErrBadParam, ccErrNoMem (from cc_credentials_list_iterator)
 *
 * Verify: does the memory associated with stored_cred->creds need to be freed?
 *
 */
cc_int32 
cci_ccache_rem_creds(cc_server_ccache_t *ccache, const cc_credentials_union* credentials) 
{
    cc_credentials_iterate_t* credentials_iterator=NULL, *active;
    cc_generic_iterate_t* generic_iterator=NULL;
    cc_credentials_list_node_t* credentials_node;
    cc_generic_list_node_t* generic_node;
    cc_server_credentials_t* stored_cred;
    cc_int8 changed = 0;
    cc_int32 code = 0;

    if (ccache == NULL)
        return ccErrInvalidCCache;

    if (credentials == NULL)
        return ccErrBadParam;

    code = cci_credentials_list_iterator(ccache->creds, &credentials_iterator);
    if (code != ccNoError) {
        /* pass error to caller */
        goto cleanup;
    }

    while (cci_credentials_iterate_has_next(credentials_iterator)) {
        code = cci_credentials_iterate_next(credentials_iterator, &credentials_node);
        stored_cred = (cc_server_credentials_t*)credentials_node->data;
        if (memcmp(&stored_cred->creds,credentials,sizeof(cc_credentials_union)) == 0) {
            /* XXX - do we need to free(stored_cred->creds) ? */
            free(credentials_node->data);
            changed = 1;
		
            /*If any iterator's next points to the deleted node, make it point to the next node*/
            code = cci_generic_list_iterator(ccache->active_iterators, &generic_iterator);
            while (cci_generic_iterate_has_next(generic_iterator)) {
                code = cci_generic_iterate_next(generic_iterator, &generic_node);			
                active = (cc_credentials_iterate_t*)generic_node->data;
                if (active->next == credentials_node) 
                    active->next = active->next->next;
            }
            code = cci_generic_free_iterator(generic_iterator);
            generic_iterator = NULL;

            if (credentials_node == ccache->creds->head) { /*removing the default, must make next cred default*/
                code = cci_credentials_list_remove_element(ccache->creds, credentials_node);

                if (ccache->creds->head != NULL)
                    ((cc_server_credentials_t*)ccache->creds->head->data)->is_default = 1;
            } else {
                code = cci_credentials_list_remove_element(ccache->creds, credentials_node);
            }
            break;
        }
    }

  cleanup:
    if (changed)
        cci_ccache_changed(ccache);
    if (credentials_iterator)
        cci_credentials_free_iterator(credentials_iterator);
    if (generic_iterator)
        cci_generic_free_iterator(generic_iterator);
    return code;
}

/**
 * cci_ccache_move()
 * 
 * Purpose: Destroys the existing contents of the destination and copies
 *          all credentials from the source to the destination
 *
 * Return:  0 on success
 *         -1 on error
 *
 * Errors:  ccBadNoMem
 *
 */

cc_int32 
cci_ccache_move(cc_server_ccache_t *source, cc_server_ccache_t* destination) 
{
    cc_generic_list_node_t* node;
    cc_generic_iterate_t* iterator;
    cc_credentials_iterate_t* cur;
    cc_int32 code;

    if (source == NULL || destination == NULL)
        return ccErrBadParam;
	
    code = cci_credentials_list_destroy(destination->creds);
    if ( code != ccNoError )
        return code;

    code = cci_credentials_list_copy(source->creds, &destination->creds);
    if ( code != ccNoError ) 
        return code;

    destination->versions = source->versions;
    destination->kdc_offset = source->kdc_offset;
    destination->last_default = 0;

    /*reset all active iterators to point to the head of the new creds list*/
    if (destination->active_iterators->head != NULL) {
        code = cci_generic_list_iterator(destination->active_iterators, &iterator);
        while (cci_generic_iterate_has_next(iterator)) {
            code = cci_generic_iterate_next(iterator, &node);
            cur = (cc_credentials_iterate_t*)node->data;
            cur->next = destination->creds->head;
        }
        code = cci_generic_free_iterator(iterator);
    }

    cci_ccache_changed(destination);
    return code;
}

/**
 * cci_ccache_get_kdc_time_offset()
 * 
 * Purpose: Retrieves the kdc_time_offset from the ccache if set
 *
 * Return:  0 on success
 *         -1 on error
 *
 * Errors:  ccErrBadParam, ccErrTimeOffsetNotSet
 *
 */
cc_int32 
cci_ccache_get_kdc_time_offset(cc_server_ccache_t* ccache, cc_time_t* offset) 
{
    if (ccache == NULL)
        return ccErrInvalidCCache;
    
    if (offset == NULL)
        return ccErrBadParam;

    if (!ccache->kdc_set)
        return ccErrTimeOffsetNotSet;

    *offset = ccache->kdc_offset;
    return ccNoError;
}

/**
 * cci_ccache_set_kdc_time_offset()
 *
 * Purpose: Sets the kdc time offset in the designated ccache
 * 
 * Return:  0 on success
 *         -1 on error
 * 
 * Errors: ccErrBadParam
 *
 */
cc_int32 
cci_ccache_set_kdc_time_offset(cc_server_ccache_t* ccache, cc_time_t offset) 
{
    if (ccache == NULL)
        return ccErrInvalidCCache;

    ccache->kdc_offset = offset;
    ccache->kdc_set = 1;
    cci_ccache_changed(ccache);

    return ccNoError;
}

/**
 * cci_ccache_clear_kdc_time_offset()
 *
 * Purpose: Clear the kdc time offset in the designated ccache
 *
 * Return:  0 on success
 *         -1 on error
 *
 * Errors: ccErrBadParam
 */
cc_int32 
cci_ccache_clear_kdc_time_offset(cc_server_ccache_t* ccache) 
{
    if (ccache == NULL)
        return ccErrInvalidCCache;

    ccache->kdc_offset = 0;
    ccache->kdc_set = 0;
    cci_ccache_changed(ccache);

    return ccNoError;
}

/**
 * cci_ccache_new_iterator()
 *
 * Purpose: Retrieve an iterator for the designated cache
 *
 * Return:  0 on success
 *         -1 on error
 *
 * Errors: ccErrBadParam, ccBadNoMem
 */
cc_int32 
cci_ccache_new_iterator(cc_server_ccache_t* ccache, cc_credentials_iterate_t** iterator)
{
    cc_int32 code;

    if (ccache == NULL)
        return ccErrInvalidCCache;

    if (iterator == NULL)
        return ccErrBadParam;

    code = cci_credentials_list_iterator(ccache->creds, iterator);
    if (code != ccNoError)
        return code;

    code = cci_generic_list_prepend(ccache->active_iterators, *iterator, sizeof(cc_credentials_iterate_t), NULL);
    if (code != ccNoError)
        return code;

    return ccNoError;
}

/**
 * cci_ccache_get_principal()
 * 
 * Purpose: Retrieves the client principal associated with the designated cache.
 *          The value is returned 
 * Return:
 *
 * Errors:
 */
cc_int32 
cci_ccache_get_principal(cc_server_ccache_t* ccache, cc_int32 version, char ** principal) 
{
    char *p = NULL;
    
    switch ( version ) {
    case cc_credentials_v4:
        p = ccache->principal_v4;
        break;
    case cc_credentials_v5:
        p = ccache->principal_v5;
        break;
    default:
        return ccErrBadCredentialsVersion;
    }

    *principal = (char *)malloc(strlen(p)+1);
    if ( *principal == NULL )
        return ccErrNoMem;

    strcpy(*principal, p);
    return ccNoError;
}

/**
 * Purpose: Releases the memory associated with a ccache principal
 * 
 * Return:
 *
 * Errors:
 *
 */
cc_int32
cci_ccache_free_principal(char * principal)
{
    if ( principal == NULL )
        return ccErrBadParam;

    free(principal);
    return ccNoError;
}

/**
 * ccache_set_principal()
 *
 * Purpose: Assigns a principal to the designated ccache and credential version.
 *          If the api version is 2, the cache is cleared of all existing
 *          credentials.
 *
 * Return:  0 on success
 *         -1 on error
 *
 * Errors: ccErrNoMem, ccErrBadCredentialsVersion
 */
cc_int32 
cci_ccache_set_principal( cc_server_ccache_t* ccache, cc_int32 cred_version, 
                          char* principal)
{
    cc_generic_iterate_t* generic_iterator;
    cc_generic_list_node_t* generic_node;
    cc_ccache_iterate_t* ccache_iterator;
    cc_int32 code = ccNoError;

    if (ccache == NULL)
        return ccErrInvalidCCache;
    
    if (principal == NULL)
        return ccErrInvalidString;

    switch (cred_version) {
    case cc_credentials_v4:
    case cc_credentials_v4_v5:
        ccache->principal_v4 = (char *)malloc(strlen(principal) + 1);
        if (ccache->principal_v4 == NULL)
            return ccErrNoMem;
        strcpy(ccache->principal_v4, principal);
        if (cred_version != cc_credentials_v4_v5)
            break;
        /* fall-through if we are v4_v5 */
    case cc_credentials_v5:
        ccache->principal_v5 = (char *)malloc(strlen(principal) + 1);
        if (ccache->principal_v5 == NULL) {
            if (cred_version == cc_credentials_v4_v5) {
                free(ccache->principal_v4);
                ccache->principal_v4 = NULL;
            }
            return ccErrNoMem;
        }
        strcpy(ccache->principal_v5, principal);
        break;
    default:
        return ccErrBadCredentialsVersion;
    }

    /*For API version 2 clients set_principal implies a flush of all creds*/
    if (ccache->mycontext != NULL && ccache->mycontext->api_version == ccapi_version_2) {
        cci_credentials_list_destroy(ccache->creds);
        cci_credentials_list_new(&ccache->creds);

        /*clean up active_iterators*/
        code = cci_generic_list_iterator(ccache->active_iterators, &generic_iterator);
        if (code == ccNoError) {
            while (cci_generic_iterate_has_next(generic_iterator)) {
                code = cci_generic_iterate_next(generic_iterator, &generic_node);
                ccache_iterator = (cc_ccache_iterate_t*)generic_node->data;
                ccache_iterator->next = NULL;
            }
        }
    }

    cci_ccache_changed(ccache);

    return code;
}

/**
 * cci_ccache_destroy()
 *
 * Purpose: Destroys an existing ccache 
 *
 * Return:  0 on success
 *         -1 on errors
 *
 * Errors:  ccErrBadParam
 */
cc_int32 
cci_ccache_destroy(cc_server_ccache_t* ccache) 
{
    cc_int32 code;

    if ( ccache == NULL )
        return ccErrInvalidCCache;

    code = cci_generic_list_destroy(ccache->active_iterators);
    code = cci_credentials_list_destroy(ccache->creds);

    if (ccache->mycontext != NULL)
        code = cci_context_rem_ccache(ccache->mycontext, ccache);

    return code;
}

/**
 * cci_ccache_compare()
 *
 * Purpose: Returns a boolean value indicating if two caches are identical
 *          Implemented as pointer equivalence.
 *
 * Return:  1 if TRUE
 *          0 if FALSE
 *
 * Errors:  No errors
 */
cc_int32 
cci_ccache_compare(cc_server_ccache_t* ccache1, cc_server_ccache_t* ccache2, cc_uint32 *result) 
{
    if ( ccache1 == NULL || ccache2 == NULL )
        return ccErrInvalidCCache;

    if (ccache1 == ccache2)
        *result = 1;
    else 
        *result = 0;

    return ccNoError;
}


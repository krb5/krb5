/*
 * lib/krb5/ccache/cc_memory.c
 *
 * Copyright 1990,1991,2000 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * implementation of memory-based credentials cache
 */
/*
 * mcc_store.c had:
 * Copyright 1995 Locus Computing Corporation
 *
 */
#include "k5-int.h"
#include <errno.h>

krb5_error_code KRB5_CALLCONV krb5_mcc_close
	(krb5_context, krb5_ccache id );

krb5_error_code KRB5_CALLCONV krb5_mcc_destroy 
	(krb5_context, krb5_ccache id );

krb5_error_code KRB5_CALLCONV krb5_mcc_end_seq_get 
	(krb5_context, krb5_ccache id , krb5_cc_cursor *cursor );

krb5_error_code KRB5_CALLCONV krb5_mcc_generate_new 
	(krb5_context, krb5_ccache *id );

const char * KRB5_CALLCONV krb5_mcc_get_name 
	(krb5_context, krb5_ccache id );

krb5_error_code KRB5_CALLCONV krb5_mcc_get_principal 
	(krb5_context, krb5_ccache id , krb5_principal *princ );

krb5_error_code KRB5_CALLCONV krb5_mcc_initialize 
	(krb5_context, krb5_ccache id , krb5_principal princ );

krb5_error_code KRB5_CALLCONV krb5_mcc_next_cred 
	(krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds );

krb5_error_code KRB5_CALLCONV krb5_mcc_resolve 
	(krb5_context, krb5_ccache *id , const char *residual );

krb5_error_code KRB5_CALLCONV krb5_mcc_retrieve 
	(krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds );

krb5_error_code KRB5_CALLCONV krb5_mcc_start_seq_get 
	(krb5_context, krb5_ccache id , krb5_cc_cursor *cursor );

krb5_error_code KRB5_CALLCONV krb5_mcc_store 
	(krb5_context, krb5_ccache id , krb5_creds *creds );

krb5_error_code KRB5_CALLCONV krb5_mcc_set_flags 
	(krb5_context, krb5_ccache id , krb5_flags flags );

extern const krb5_cc_ops krb5_mcc_ops;
krb5_error_code krb5_change_cache (void);

#define KRB5_OK 0

typedef struct _krb5_mcc_link {
     struct _krb5_mcc_link *next;
     krb5_creds *creds;
} krb5_mcc_link, *krb5_mcc_cursor;

typedef struct _krb5_mcc_data {
     struct _krb5_mcc_data *next;
     char *name;
     krb5_principal prin;
     krb5_mcc_cursor link;
} krb5_mcc_data;

static krb5_mcc_data *mcc_head = 0;

/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents are destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
void krb5_mcc_free (krb5_context context, krb5_ccache id);

krb5_error_code KRB5_CALLCONV
krb5_mcc_initialize(krb5_context context, krb5_ccache id, krb5_principal princ)
{
    krb5_error_code ret; 

    krb5_mcc_free(context, id);
    ret = krb5_copy_principal(context, princ,
        &((krb5_mcc_data *)id->data)->prin);
    if (ret == KRB5_OK)
        krb5_change_cache();
    return ret;
}

/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_close(krb5_context context, krb5_ccache id)
{
     krb5_xfree(id);

     return KRB5_OK;
}

void
krb5_mcc_free(krb5_context context, krb5_ccache id)
{
	krb5_mcc_cursor curr,next;
     
     for (curr = ((krb5_mcc_data *)id->data)->link; curr;)
     {
	krb5_free_creds(context, curr->creds);
	next = curr->next;
	krb5_xfree(curr);
	curr = next;
     }
     ((krb5_mcc_data *)id->data)->link = NULL;
     krb5_free_principal(context, ((krb5_mcc_data *)id->data)->prin);
}

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * none
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_destroy(krb5_context context, krb5_ccache id)
{
     krb5_mcc_data *curr;

     if (mcc_head && ((krb5_mcc_data *)id->data) == mcc_head)
	mcc_head = mcc_head->next;
     else {
	for (curr=mcc_head; curr; curr=curr->next)
		if (curr->next == ((krb5_mcc_data *)id->data)) {
			curr->next = curr->next->next;
			break;
		}
     }
     
     krb5_mcc_free(context, id);

     krb5_xfree(((krb5_mcc_data *)id->data)->name);
     krb5_xfree(id->data); 
     krb5_xfree(id);
#if 0
     --krb5_cache_sessions;
#endif

     krb5_change_cache ();
     return KRB5_OK;
}

/*
 * Requires:
 * residual is a legal path name, and a null-terminated string
 *
 * Modifies:
 * id
 * 
 * Effects:
 * creates a file-based cred cache that will reside in the file
 * residual.  The cache is not opened, but the filename is reserved.
 * 
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 *              krb5_ccache.  id is undefined.
 * permission errors
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_resolve (krb5_context context, krb5_ccache *id, const char *residual)
{
     krb5_ccache lid;
     krb5_mcc_data *ptr;

     
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_mcc_ops;
     
     for (ptr = mcc_head; ptr; ptr=ptr->next)
	if (!strcmp(ptr->name, residual))
	    break;
     if (ptr) {
     lid->data = ptr;
     } else {
     lid->data = (krb5_pointer) malloc(sizeof(krb5_mcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_mcc_data *) lid->data)->name = (char *)
	malloc(strlen(residual) + 1);
     if (((krb5_mcc_data *)lid->data)->name == NULL) {
	krb5_xfree(((krb5_mcc_data *)lid->data));
	krb5_xfree(lid);
	return KRB5_CC_NOMEM;
     }
     strcpy(((krb5_mcc_data *)lid->data)->name, residual);
     ((krb5_mcc_data *)lid->data)->link = 0L;
     ((krb5_mcc_data *)lid->data)->prin = 0L;


     ((krb5_mcc_data *)lid->data)->next = mcc_head;
     mcc_head = (krb5_mcc_data *)lid->data;
#if 0
     ++krb5_cache_sessions;
#endif
     }
     *id = lid; 
     return KRB5_OK;
}

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns a krb5_cc_cursor to be used with krb5_mcc_next_cred and
 * krb5_mcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_mcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_start_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
     krb5_mcc_cursor mcursor;
     
     mcursor = ((krb5_mcc_data *)id->data)->link;
     *cursor = (krb5_cc_cursor) mcursor;
     return KRB5_OK;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_mcc_start_seq_get.
 *
 * Modifes:
 * cursor, creds
 * 
 * Effects:
 * Fills in creds with the "next" credentals structure from the cache
 * id.  The actual order the creds are returned in is arbitrary.
 * Space is allocated for the variable length fields in the
 * credentials structure, so the object returned must be passed to
 * krb5_destroy_credential.
 *
 * The cursor is updated for the next call to krb5_mcc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_next_cred(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor, krb5_creds *creds)
{
     krb5_mcc_cursor mcursor;
     krb5_error_code retval;
     krb5_data *scratch;

     mcursor = (krb5_mcc_cursor) *cursor;
     if (mcursor == NULL)
	return KRB5_CC_END;
     memset(creds, 0, sizeof(krb5_creds));     
     if (mcursor->creds) {
	*creds = *mcursor->creds;
	retval = krb5_copy_principal(context, mcursor->creds->client, &creds->client);
	if (retval)
		return retval;
	retval = krb5_copy_principal(context, mcursor->creds->server,
		&creds->server);
	if (retval)
		goto cleanclient;
	retval = krb5_copy_keyblock_contents(context, &mcursor->creds->keyblock,
		&creds->keyblock);
	if (retval)
		goto cleanserver;
	retval = krb5_copy_addresses(context, mcursor->creds->addresses,
		&creds->addresses);
	if (retval)
		goto cleanblock;
	retval = krb5_copy_data(context, &mcursor->creds->ticket, &scratch);
	if (retval)
		goto cleanaddrs;
	creds->ticket = *scratch;
	krb5_xfree(scratch);
	retval = krb5_copy_data(context, &mcursor->creds->second_ticket, &scratch);
	if (retval)
		goto cleanticket;
	creds->second_ticket = *scratch;
	krb5_xfree(scratch);
	retval = krb5_copy_authdata(context, mcursor->creds->authdata,
		&creds->authdata);
	if (retval)
		goto clearticket;
     }
     *cursor = (krb5_cc_cursor)mcursor->next;
     return KRB5_OK;

clearticket:
	memset(creds->ticket.data,0, (unsigned) creds->ticket.length);
cleanticket:
	krb5_xfree(creds->ticket.data);
cleanaddrs:
	krb5_free_addresses(context, creds->addresses);
cleanblock:
	krb5_xfree(creds->keyblock.contents);
cleanserver:
	krb5_free_principal(context, creds->server);
cleanclient:
	krb5_free_principal(context, creds->client);
	return retval;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_mcc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the file credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
krb5_error_code KRB5_CALLCONV
krb5_mcc_end_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
     *cursor = 0L;
     return KRB5_OK;
}

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from mcc.h).
 * The cache is not opened, but the new filename is reserved.
 *  
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 *              krb5_ccache.  id is undefined.
 * system errors (from open)
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_generate_new (krb5_context context, krb5_ccache *id)
{
     krb5_ccache lid;
     char scratch[6+1]; /* 6 for the scratch part, +1 for NUL */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_mcc_ops;

     (void) strcpy(scratch, "XXXXXX");
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_mcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_mcc_data *) lid->data)->name = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_mcc_data *) lid->data)->name == NULL) {
	  krb5_xfree(((krb5_mcc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }
     ((krb5_mcc_data *) lid->data)->link = NULL;
     ((krb5_mcc_data *) lid->data)->prin = NULL;

     /* Set up the filename */
     strcpy(((krb5_mcc_data *) lid->data)->name, scratch);

     *id = lid;
#if 0
     ++krb5_cache_sessions;
#endif
     ((krb5_mcc_data *)lid->data)->next = mcc_head;
     mcc_head = (krb5_mcc_data *)lid->data;

     krb5_change_cache ();
     return KRB5_OK;
}

/*
 * Requires:
 * id is a file credential cache
 * 
 * Returns:
 * The name of the file cred cache id.
 */
const char * KRB5_CALLCONV
krb5_mcc_get_name (krb5_context context, krb5_ccache id)
{
     return (char *) ((krb5_mcc_data *) id->data)->name;
}

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_mcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_get_principal(krb5_context context, krb5_ccache id, krb5_principal *princ)
{
     krb5_mcc_data *ptr = (krb5_mcc_data *)id->data;
     if (!ptr->prin)
     {
        *princ = 0L;
        return KRB5_FCC_NOFILE;
     }
     return krb5_copy_principal(context, ptr->prin, princ);
}

krb5_error_code KRB5_CALLCONV
krb5_mcc_retrieve(krb5_context context, krb5_ccache id, krb5_flags whichfields, krb5_creds *mcreds, krb5_creds *creds)
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Modifies:
 * the memory cache
 *
 * Effects:
 * stores creds in the memory cred cache
 *
 * Errors:
 * system errors
 * storage failure errors
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_store(krb5_context context, krb5_ccache id, krb5_creds *creds)
{
     krb5_error_code ret;
     krb5_mcc_cursor mcursor;

     mcursor = (krb5_mcc_cursor)malloc(sizeof(krb5_mcc_link));
     if (mcursor == NULL)
	return KRB5_CC_NOMEM;
     ret = krb5_copy_creds(context, creds, &mcursor->creds);
     if (ret == KRB5_OK) {
	mcursor->next = ((krb5_mcc_data *)id->data)->link;
	((krb5_mcc_data *)id->data)->link = mcursor;
	krb5_change_cache();
     }
     return ret;
}

/*
 * Requires:
 * id is a cred cache returned by krb5_mcc_resolve or
 * krb5_mcc_generate_new, but has not been opened by krb5_mcc_initialize.
 *
 * Modifies:
 * id
 * 
 * Effects:
 * Sets the operational flags of id to flags.
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_set_flags(krb5_context context, krb5_ccache id, krb5_flags flags)
{
    return KRB5_OK;
}

#define NEED_WINDOWS

const krb5_cc_ops krb5_mcc_ops = {
     0,
     "MEMORY",
     krb5_mcc_get_name,
     krb5_mcc_resolve,
     krb5_mcc_generate_new,
     krb5_mcc_initialize,
     krb5_mcc_destroy,
     krb5_mcc_close,
     krb5_mcc_store,
     krb5_mcc_retrieve,
     krb5_mcc_get_principal,
     krb5_mcc_start_seq_get,
     krb5_mcc_next_cred,
     krb5_mcc_end_seq_get,
     NULL, /* XXX krb5_mcc_remove, */
     krb5_mcc_set_flags,
};

/* cc_memory.c - memory ccache implementation
 * Copyright 2000 MIT blah blah...
 */
#include "k5-int.h"
#include <errno.h>

/* start of former memory/mcc-proto.h */
/*
 * lib/krb5/ccache/memory/mcc-proto.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Prototypes for Memory-based credentials cache
 */


#ifndef KRB5_MCC_PROTO__
#define KRB5_MCC_PROTO__

/* mcc_close.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_close
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* mcc_destry.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_destroy 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* mcc_eseq.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_end_seq_get 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* mcc_gennew.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_generate_new 
	PROTOTYPE((krb5_context, krb5_ccache *id ));

/* mcc_getnam.c */
char * KRB5_CALLCONV krb5_mcc_get_name 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* mcc_gprin.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_get_principal 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));

/* mcc_init.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_initialize 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));

/* mcc_nseq.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_next_cred 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

/* mcc_reslv.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_resolve 
	PROTOTYPE((krb5_context, krb5_ccache *id , const char *residual ));

/* mcc_retrv.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_retrieve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

/* mcc_sseq.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_start_seq_get 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* mcc_store.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_store 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_creds *creds ));

/* mcc_sflags.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_set_flags 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags ));

/* mcc_ops.c */
extern krb5_cc_ops krb5_mcc_ops;
krb5_error_code krb5_change_cache
   PROTOTYPE(());
#endif /* KRB5_MCC_PROTO__ */
/* end of former memory/mcc-proto.h */
/* start of former memory/mcc.h */
/*
 * lib/krb5/ccache/memory/mcc.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains constant and function declarations used in the
 * memory-based credential cache routines.
 */

#ifndef __KRB5_MEMORY_CCACHE__
#define __KRB5_MEMORY_CCACHE__


#define KRB5_OK 0

typedef struct _krb5_mcc_link {
     struct _krb5_mcc_link *next;
     krb5_creds *creds;
} krb5_mcc_link, FAR *krb5_mcc_cursor;

typedef struct _krb5_mcc_data {
     struct _krb5_mcc_data *next;
     char *name;
     krb5_principal prin;
     krb5_mcc_cursor link;
} krb5_mcc_data;

#define mcc_head krb5int_mcc_head
extern krb5_mcc_data FAR *mcc_head;
#if 0
extern int krb5_cache_sessions;
#endif

#endif /* __KRB5_MEMORY_CCACHE__ */
/* end of former memory/mcc.h */
/* start of former memory/mcc_init.c */
/*
 * lib/krb5/ccache/memory/mcc_init.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_initialize.
 */


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
void krb5_mcc_free KRB5_PROTOTYPE((krb5_context context, krb5_ccache id));

krb5_error_code KRB5_CALLCONV
krb5_mcc_initialize(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_error_code ret; 

    krb5_mcc_free(context, id);
    ret = krb5_copy_principal(context, princ,
        &((krb5_mcc_data *)id->data)->prin);
    if (ret == KRB5_OK)
        krb5_change_cache();
    return ret;
}
/* end of former memory/mcc_init.c */
/* start of former memory/mcc_close.c */
/*
 * lib/krb5/ccache/file/mcc_close.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_close.
 */



/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_close(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_xfree(id);

     return KRB5_OK;
}
/* end of former memory/mcc_close.c */
/* start of former memory/mcc_destry.c */
/*
 * lib/krb5/ccache/memory/mcc_destry.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_destroy.
 */

void
krb5_mcc_free(context, id)
	krb5_context context;
	krb5_ccache id;
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
krb5_mcc_destroy(context, id)
   krb5_context context;
   krb5_ccache id;
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
/* end of former memory/mcc_destry.c */
/* start of former memory/mcc_reslv.c */
/*
 * lib/krb5/ccache/file/mcc_reslv.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_resolve.
 */




extern krb5_cc_ops krb5_mcc_ops;

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
krb5_mcc_resolve (context, id, residual)
   krb5_context context;
   krb5_ccache *id;
   const char *residual;
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
/* end of former memory/mcc_reslv.c */
/* start of former memory/mcc_sseq.c */
/*
 * lib/krb5/ccache/file/mcc_sseq.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_start_seq_get.
 */



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
krb5_mcc_start_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_mcc_cursor mcursor;
     
     mcursor = ((krb5_mcc_data *)id->data)->link;
     *cursor = (krb5_cc_cursor) mcursor;
     return KRB5_OK;
}
/* end of former memory/mcc_sseq.c */
/* start of former memory/mcc_nseq.c */
/*
 * lib/krb5/ccache/file/mcc_nseq.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_next_cred.
 */


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
krb5_mcc_next_cred(context, id, cursor, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
   krb5_creds *creds;
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
	memset(creds->ticket.data,0,creds->ticket.length);
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
/* end of former memory/mcc_nseq.c */
/* start of former memory/mcc_eseq.c */
/*
 * lib/krb5/ccache/memory/mcc_eseq.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_end_seq_get.
 */



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
krb5_mcc_end_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     *cursor = 0L;
     return KRB5_OK;
}


/* end of former memory/mcc_eseq.c */
/* start of former memory/mcc_gennew.c */
/*
 * lib/krb5/ccache/memory/mcc_gennew.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_generate_new.
 */


extern krb5_cc_ops krb5_mcc_ops;

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
krb5_mcc_generate_new (context, id)
   krb5_context context;
   krb5_ccache *id;
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
/* end of former memory/mcc_gennew.c */
/* start of former memory/mcc_getnam.c */
/*
 * lib/krb5/ccache/file/mcc_getnam.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_get_name.
 */




/*
 * Requires:
 * id is a file credential cache
 * 
 * Returns:
 * The name of the file cred cache id.
 */
char * KRB5_CALLCONV
krb5_mcc_get_name (context, id)
   krb5_context context;
   krb5_ccache id;
{
     return (char *) ((krb5_mcc_data *) id->data)->name;
}
/* end of former memory/mcc_getnam.c */
/* start of former memory/mcc_gprin.c */
/*
 * lib/krb5/ccache/file/mcc_gprin.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_get_principal.
 */



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
krb5_mcc_get_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_mcc_data *ptr = (krb5_mcc_data *)id->data;
     if (!ptr->prin)
     {
        *princ = 0L;
        return KRB5_FCC_NOFILE;
     }
     return krb5_copy_principal(context, ptr->prin, princ);
}

     
/* end of former memory/mcc_gprin.c */
/* start of former memory/mcc_retrv.c */
/*
 * lib/krb5/ccache/file/mcc_retrv.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_retrieve.
 */

#if 0


#define set(bits) (whichfields & bits)
#define flags_match(a,b) (((a) & (b)) == (a))
#define times_match_exact(t1,t2) (memcmp((char *)(t1), (char *)(t2), sizeof(*(t1))) == 0)

static krb5_boolean times_match PROTOTYPE((const krb5_ticket_times *,
					   const krb5_ticket_times *));
static krb5_boolean standard_fields_match
    PROTOTYPE((krb5_context,
		   const krb5_creds *,
	       const krb5_creds *));

static krb5_boolean srvname_match
    PROTOTYPE((krb5_context,
		   const krb5_creds *,
	       const krb5_creds *));

static krb5_boolean authdata_match
    PROTOTYPE ((krb5_authdata * const *, krb5_authdata * const *));


static krb5_boolean
data_match(data1, data2)
register const krb5_data *data1, *data2;
{
    if (!data1) {
	if (!data2)
	    return TRUE;
	else
	    return FALSE;
    }
    if (!data2) return FALSE;

    if (data1->length != data2->length)
	return FALSE;
    else
	return memcmp(data1->data, data2->data, data1->length) ? FALSE : TRUE;
}



/*
 * Effects:
 * Searches the file cred cache for a credential matching mcreds,
 * with the fields specified by whichfields.  If one if found, it is
 * returned in creds, which should be freed by the caller with
 * krb5_free_credentials().
 * 
 * The fields are interpreted in the following way (all constants are
 * preceded by KRB5_TC_).  MATCH_IS_SKEY requires the is_skey field to
 * match exactly.  MATCH_TIMES requires the requested lifetime to be
 * at least as great as that specified; MATCH_TIMES_EXACT requires the
 * requested lifetime to be exactly that specified.  MATCH_FLAGS
 * requires only the set bits in mcreds be set in creds;
 * MATCH_FLAGS_EXACT requires all bits to match.
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_CC_NOMEM
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
     /* This function could be considerably faster if it kept indexing */
     /* information.. sounds like a "next version" idea to me. :-) */

     krb5_cc_cursor cursor;
     krb5_error_code kret;
     krb5_creds fetchcreds;

     kret = krb5_mcc_start_seq_get(context, id, &cursor);
     if (kret != KRB5_OK)
	  return kret;

     while ((kret = krb5_mcc_next_cred(context, id, &cursor, &fetchcreds)) == KRB5_OK) {
	  if (((set(KRB5_TC_MATCH_SRV_NAMEONLY) &&
		   srvname_match(context, mcreds, &fetchcreds)) ||
	       standard_fields_match(context, mcreds, &fetchcreds))
	      &&
	      (! set(KRB5_TC_MATCH_IS_SKEY) ||
	       mcreds->is_skey == fetchcreds.is_skey)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS_EXACT) ||
	       mcreds->ticket_flags == fetchcreds.ticket_flags)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS) ||
	       flags_match(mcreds->ticket_flags, fetchcreds.ticket_flags))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES_EXACT) ||
	       times_match_exact(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES) ||
	       times_match(&mcreds->times, &fetchcreds.times))
	      &&
	      ( ! set(KRB5_TC_MATCH_AUTHDATA) ||
	       authdata_match(mcreds->authdata, fetchcreds.authdata))
	      &&
	      (! set(KRB5_TC_MATCH_2ND_TKT) ||
	       data_match (&mcreds->second_ticket, &fetchcreds.second_ticket))
	      &&
	      ((! set(KRB5_TC_MATCH_KTYPE))||
	       (mcreds->keyblock.enctype == fetchcreds.keyblock.enctype))
	      )
	  {
	       krb5_mcc_end_seq_get(context, id, &cursor);
	       *creds = fetchcreds;
	       return KRB5_OK;
	  }

	  /* This one doesn't match */
	  krb5_free_cred_contents(context, &fetchcreds);
     }

     /* If we get here, a match wasn't found */
     krb5_mcc_end_seq_get(context, id, &cursor);
     return KRB5_CC_NOTFOUND;
}

static krb5_boolean
times_match(t1, t2)
register const krb5_ticket_times *t1;
register const krb5_ticket_times *t2;
{
    if (t1->renew_till) {
	if (t1->renew_till > t2->renew_till)
	    return FALSE;               /* this one expires too late */
    }
    if (t1->endtime) {
	if (t1->endtime > t2->endtime)
	    return FALSE;               /* this one expires too late */
    }
    /* only care about expiration on a times_match */
    return TRUE;
}

static krb5_boolean
standard_fields_match(context, mcreds, creds)
   krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    return (krb5_principal_compare(context, mcreds->client,creds->client) &&
	    krb5_principal_compare(context, mcreds->server,creds->server));
}

/* only match the server name portion, not the server realm portion */

static krb5_boolean
srvname_match(context, mcreds, creds)
   krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    krb5_boolean retval;
    krb5_principal_data p1, p2;
    
    retval = krb5_principal_compare(context, mcreds->client,creds->client);
    if (retval != TRUE)
	return retval;
    /*
     * Hack to ignore the server realm for the purposes of the compare.
     */
    p1 = *mcreds->server;
    p2 = *creds->server;
    p1.realm = p2.realm;
    return krb5_principal_compare(context, &p1, &p2);
}

static krb5_boolean
authdata_match(mdata, data)
    register krb5_authdata * const *mdata, * const *data;
{
    register const krb5_authdata *mdatap, *datap;

    if (mdata == data)
      return TRUE;

    if (mdata == NULL)
	return *data == NULL;
	
    if (data == NULL)
	return *mdata == NULL;
    
    while ((mdatap = *mdata) && (datap = *data)) {
      if ((mdatap->ad_type != datap->ad_type) ||
	  (mdatap->length != datap->length) ||
	  (memcmp ((char *)mdatap->contents,
		 (char *)datap->contents, mdatap->length) != 0))
	  return FALSE;
      mdata++;
      data++;
    }
    return (*mdata == NULL) && (*data == NULL);
}

#else


krb5_error_code KRB5_CALLCONV
krb5_mcc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}

#endif
/* end of former memory/mcc_retrv.c */
/* start of former memory/mcc_store.c */
/*
 * lib/ccache/memory/mcc_store.c
 *
 * Copyright 1995 Locus Computing Corporation
 *
 * This file contains the source code for krb5_mcc_store.
 */

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
krb5_mcc_store(context, id, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_creds *creds;
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

/* end of former memory/mcc_store.c */
/* start of former memory/mcc_sflags.c */
/*
 * lib/krb5/ccache/file/mcc_sflags.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_set_flags.
 */




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
krb5_mcc_set_flags(context, id, flags)
   krb5_context context;
   krb5_ccache id;
   krb5_flags flags;
{
    return KRB5_OK;
}

/* end of former memory/mcc_sflags.c */
/* start of former memory/mcc_ops.c */
/*
 * lib/krb5/ccache/file/mcc_ops.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the structure krb5_mcc_ops.
 */

#define NEED_WINDOWS

krb5_cc_ops krb5_mcc_ops = {
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

krb5_mcc_data *mcc_head=0L;

/* end of former memory/mcc_ops.c */

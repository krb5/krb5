/*
 * kdc/fast_util.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 */

#include <k5-int.h>

#include "kdc_util.h"
#include "extern.h"


/*
 * This function will find the fast and cookie padata and if fast is
 * successfully processed, will throw away (and free) the outer
 * request and update the pointer to point to the inner request.  The
 * checksummed_data points to the data that is in the
 * armored_fast_request checksum; either the pa-tgs-req or the
 * kdc-req-body.
 */

krb5_error_code  kdc_find_fast
(krb5_kdc_req **requestptr,  krb5_data *checksummed_data,
 krb5_keyblock *tgs_subkey,
 struct kdc_request_state *state)
{
    krb5_error_code retval = 0;
    krb5_pa_data *fast_padata, *cookie_padata;
    krb5_data scratch;
    krb5_fast_req * fast_req = NULL;
    krb5_kdc_req *request = *requestptr;

    scratch.data = NULL;
    fast_padata = find_pa_data(request->padata,
			       KRB5_PADATA_FX_FAST);
    cookie_padata = find_pa_data(request->padata, KRB5_PADATA_FX_COOKIE);
        if (fast_padata == NULL)
	return 0; /*no fast*/
    
    scratch.length = fast_padata->length;
    scratch.data = (char *) fast_padata->contents;
    retval = decode_krb5_fast_req(&scratch, &fast_req);
    if (retval == 0) {
	if ((fast_req->fast_options & UNSUPPORTED_CRITICAL_FAST_OPTIONS) !=0)
	    retval = KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION;
    }
    if (retval == 0 && cookie_padata != NULL) {
	krb5_pa_data *new_padata = malloc(sizeof (krb5_pa_data));
	if (new_padata != NULL) {
	    retval = ENOMEM;
	} else {
	    new_padata->pa_type = KRB5_PADATA_FX_COOKIE;
	    new_padata->length = cookie_padata->length;
	    new_padata->contents = malloc(new_padata->length);
	    if (new_padata->contents == NULL) {
		retval = ENOMEM;
		free(new_padata);
	    } else {
		memcpy(new_padata->contents, cookie_padata->contents, new_padata->length);
		state->cookie = new_padata;
	    }
	}
    }
    if (retval == 0) {
	state->fast_options = fast_req->fast_options;
	if (request->kdc_state == state)
	    request->kdc_state = NULL;
	krb5_free_kdc_req( kdc_context, request);
	*requestptr = fast_req->req_body;
	fast_req->req_body = NULL;
	
    }
    if (fast_req)
	krb5_free_fast_req( kdc_context, fast_req);
    return retval;
}


krb5_error_code kdc_make_rstate(struct kdc_request_state **out)
{
    struct kdc_request_state *state = malloc( sizeof(struct kdc_request_state));
    if (state == NULL)
	return ENOMEM;
    memset( state, 0, sizeof(struct kdc_request_state));
    *out = state;
    return 0;
}

void kdc_free_rstate
(struct kdc_request_state *s)
{
  if (s == NULL)
    return;
    if (s->armor_key)
	krb5_free_keyblock(kdc_context, s->armor_key);
    if (s->cookie) {
	free(s->cookie->contents);
	free(s->cookie);
    }
    free(s);
}

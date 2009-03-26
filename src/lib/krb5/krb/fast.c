/*
 * lib/krb5/krb/fast.c
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

/*
 * It is possible to support sending a request that includes both a
 * FAST and normal version.  This would complicate the
 * pre-authentication logic significantly.  You would need to maintain
 * two contexts, one for FAST and one for normal use.  In adition, you
 * would need to manage the security issues surrounding downgrades.
 * However trying FAST at all requires an armor key.  Generally in
 * obtaining the armor key, the client learns enough to know that FAST
 * is supported.  If not, the client can see FAST in the
 * preauth_required error's padata and retry with FAST.  So, this
 * implementation does not support FAST+normal.
 *
 * We store the outer version of the request to use .  The caller
 * stores the inner version.  We handle the encoding of the request
 * body (and request) and provide encoded request bodies for the
 * caller to use as these may be used for checksums.  In the AS case
 * we also evaluate whether to continue a conversation as one of the
 * important questions there is the presence of a cookie.
 */
#include "fast.h"



krb5_error_code
krb5int_fast_prep_req_body(krb5_context context, struct krb5int_fast_request_state *state,
			   krb5_kdc_req *request, krb5_data **encoded_request_body)
{
    krb5_error_code retval = 0;
    krb5_data *local_encoded_request_body = NULL;
    assert(state != NULL);
    *encoded_request_body = NULL;
    if (state->armor_key == NULL) {
	return   encode_krb5_kdc_req_body(request, encoded_request_body);
    }
    state->fast_outer_request = *request;
    state->fast_outer_request.padata = NULL;
    if (retval == 0)
	retval = encode_krb5_kdc_req_body(&state->fast_outer_request,
					  &local_encoded_request_body);
    if (retval == 0) {
	*encoded_request_body = local_encoded_request_body;
	local_encoded_request_body = NULL;
    }
    if (local_encoded_request_body != NULL)
	krb5_free_data(context, local_encoded_request_body);
    return retval;
}


krb5_error_code 
krb5int_fast_prep_req (krb5_context context, struct krb5int_fast_request_state *state,
		       const krb5_kdc_req *request,
		       const krb5_data *to_be_checksummed, kdc_req_encoder_proc encoder,
		       krb5_data **encoded_request)
{
    krb5_error_code retval = 0;
    krb5_pa_data *pa_array[3];
    krb5_pa_data pa[2];
    krb5_fast_req fast_req;
    krb5_data *encoded_fast_req = NULL;
    krb5_data *local_encoded_result = NULL;

    assert(state != NULL);
        assert(state->fast_outer_request.padata == NULL);
    memset(pa_array, 0, sizeof pa_array);
    if (state->armor_key == NULL) {
	return encoder(request, encoded_request);
    }
    fast_req.req_body =  request;
    if (fast_req.req_body->padata == NULL) {
      fast_req.req_body->padata = calloc(1, sizeof(krb5_pa_data *));
      if (fast_req.req_body->padata == NULL)
	retval = ENOMEM;
    }
    fast_req.fast_options = state->fast_options;
    if (retval == 0)
	retval = encode_krb5_fast_req(&fast_req, &encoded_fast_req);
    if (retval==0) {
	pa[0].pa_type = KRB5_PADATA_FX_FAST;
	pa[0].contents = (unsigned char *) encoded_fast_req->data;
	pa[0].length = encoded_fast_req->length;
	pa_array[0] = &pa[0];
    }
    if (state->cookie_contents.data) {
	pa[1].contents = (unsigned char *) state->cookie_contents.data;
	pa[1].length = state->cookie_contents.length;
	pa[1].pa_type = KRB5_PADATA_FX_COOKIE;
	pa_array[1] = &pa[1];
    }
    state->fast_outer_request.padata = pa_array;
    if(retval == 0)
	retval = encoder(&state->fast_outer_request, &local_encoded_result);
    if (retval == 0) {
	*encoded_request = local_encoded_result;
	local_encoded_result = NULL;
    }
    if (encoded_fast_req)
	krb5_free_data(context, encoded_fast_req);
    if (local_encoded_result)
	krb5_free_data(context, local_encoded_result);
    state->fast_outer_request.padata = NULL;
    return retval;
}

/*
 * FAST separates two concepts: the set of padata we're using to
 * decide what pre-auth mechanisms to use and the set of padata we're
 * making available to mechanisms in order for them to respond to an
 * error.  The plugin interface in March 2009 does not permit
 * separating these concepts for the plugins.  This function makes
 * both available for future revisions to the plugin interface.  It
 * also re-encodes the padata from the current error as a encoded
 * typed-data and puts that in the e_data field.  That will allow
 * existing plugins with the old interface to find the error data.
 * The output parameter out_padata contains the padata from the error
 * whenever padata  is available (all the time with fast).
 */
krb5_error_code
krb5int_fast_process_error(krb5_context context, struct krb5int_fast_request_state *state,
			   krb5_error **err_replyptr			   , krb5_pa_data ***out_padata,
			   krb5_boolean *retry)
{
    krb5_error_code retval = 0;
    krb5_error *err_reply = *err_replyptr;
    *retry = (err_reply->e_data.length > 0);
    *out_padata = NULL;
    if ((err_reply->error == KDC_ERR_PREAUTH_REQUIRED
	 ||err_reply->error == KDC_ERR_PREAUTH_FAILED) && err_reply->e_data.length) {
	krb5_pa_data **result = NULL;
	retval = decode_krb5_padata_sequence(&err_reply->e_data, &result);
	if (retval == 0)
	if (retval == 0) {
	    *out_padata = result;

	    return 0;
	}
	krb5_free_pa_data(context, result);
	krb5_set_error_message(context, retval,
			       "Error decoding padata in error reply");
	return retval;
    }
    return 0;
}

krb5_error_code
krb5int_fast_make_state( krb5_context context, struct krb5int_fast_request_state **state)
{
    krb5_error_code retval = 0;
    struct krb5int_fast_request_state *local_state ;
    local_state = malloc(sizeof *local_state);
    if (local_state == NULL)
	return ENOMEM;
    memset(local_state, 0, sizeof(*local_state));
    *state = local_state;
    return 0;
}

void
krb5int_fast_free_state( krb5_context context, struct krb5int_fast_request_state *state)
{
    /*We are responsible for none of the store in the fast_outer_req*/
    krb5_free_keyblock(context, state->armor_key);
    krb5_free_fast_armor(context, state->armor);
    krb5_free_data_contents(context, &state->cookie_contents);
}

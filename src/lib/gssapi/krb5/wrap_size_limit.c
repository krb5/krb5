/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "gssapiP_krb5.h"

/*
 * $Id$
 */

/* V2 interface */
OM_uint32
krb5_gss_wrap_size_limit(minor_status, context_handle, conf_req_flag,
			 qop_req, req_output_size, max_input_size)
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    OM_uint32		req_output_size;
    OM_uint32		*max_input_size;
{
    krb5_context	context;
    krb5_gss_ctx_id_rec	*ctx;
    krb5_error_code code;

    if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return(GSS_S_FAILURE);

    /* only default qop is allowed */
    if (qop_req != GSS_C_QOP_DEFAULT) {
	*minor_status = (OM_uint32) G_UNKNOWN_QOP;
	return(GSS_S_FAILURE);
    }
    
    /* validate the context handle */
    if (! kg_validate_ctx_id(context_handle)) {
	*minor_status = (OM_uint32) G_VALIDATE_FAILED;
	return(GSS_S_NO_CONTEXT);
    }
    
    ctx = (krb5_gss_ctx_id_rec *) context_handle;
    if (! ctx->established) {
	*minor_status = KG_CTX_INCOMPLETE;
	return(GSS_S_NO_CONTEXT);
    }

    if (ctx->gsskrb5_version == 2000) {
	if (conf_req_flag) {
	    /* this is pretty gross.  take the max output, and call
	       krb5_c_encrypt_length to see how much overhead is added
	       on.  subtract that much, and see if it fits in the
	       requested space.  If not, start subtracting 1 until it
	       does.  This doesn't necessarily give us the optimal
	       packing, but I think that's ok (I could start adding 1
	       until I went over, but that seems like it's not worth
	       the effort).  This is probably O(blocksize), but that's
	       never going to be large. */

	    OM_uint32 headerlen, plainlen;
	    size_t enclen;

	    headerlen = g_token_size((gss_OID) ctx->mech_used, 2);
	    plainlen = req_output_size - headerlen;

	    if (code = krb5_c_encrypt_length(context, ctx->enc->enctype,
					     plainlen, &enclen)) {
		*minor_status = code;
		return(GSS_S_FAILURE);
	    }

	    plainlen -= plainlen - (enclen - plainlen);

	    if (code = krb5_c_encrypt_length(context, ctx->enc->enctype,
					     plainlen, &enclen)) {
		*minor_status = code;
		return(GSS_S_FAILURE);
	    }

	    while (headerlen + enclen > req_output_size) {
		plainlen--;

		if (code = krb5_c_encrypt_length(context, ctx->enc->enctype,
						 plainlen, &enclen)) {
		    *minor_status = code;
		    return(GSS_S_FAILURE);
		}
	    }

	    /* subtract off the fixed size inside the encrypted part */

	    plainlen -= 7;

	    *max_input_size = plainlen;
	} else {
	    size_t cksumlen;
	    OM_uint32 headerlen;

	    if (code = krb5_c_checksum_length(context, ctx->ctypes[0],
					      &cksumlen)) {
		*minor_status = code;
		return(GSS_S_FAILURE);
	    }

	    headerlen = g_token_size((gss_OID) ctx->mech_used, 13 + cksumlen);

	    *max_input_size = req_output_size - headerlen;
	}
    } else {
	OM_uint32		data_size, conflen;
	OM_uint32		ohlen;
	int			overhead;

	/* Calculate the token size and subtract that from the output size */
	overhead = 7 + ctx->mech_used->length;
	data_size = req_output_size;
	if (conf_req_flag) {
		conflen = kg_confounder_size(context, ctx->enc);
		data_size = (conflen + data_size + 8) & (~7);
	}
	ohlen = g_token_size((gss_OID) ctx->mech_used,
			     (unsigned int) (data_size + ctx->cksum_size + 14))
		- req_output_size;

	if (ohlen+overhead < req_output_size)
	    /*
	     * Cannot have trailer length that will cause us to pad over
	     * our length
	     */
	    *max_input_size = (req_output_size - ohlen - overhead) & (~7);
	else
	    *max_input_size = 0;
    }

    *minor_status = 0;
    return(GSS_S_COMPLETE);
}

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

#include "gssapiP_krb5.h"

OM_uint32
krb5_gss_seal(ctx, minor_status, context_handle, conf_req_flag,
	      qop_req, input_message_buffer, conf_state,
	      output_message_buffer)
     void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     int conf_req_flag;
     int qop_req;
     gss_buffer_t input_message_buffer;
     int *conf_state;
     gss_buffer_t output_message_buffer;
{
   krb5_context context = ctx;
   return(kg_seal(context, minor_status, context_handle, conf_req_flag,
		  qop_req, input_message_buffer, conf_state,
		  output_message_buffer, KG_TOK_SEAL_MSG));
}

/* V2 interface */
OM_uint32
krb5_gss_wrap(ctx, minor_status, context_handle, conf_req_flag,
	      qop_req, input_message_buffer, conf_state,
	      output_message_buffer)
    void *ctx;
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    gss_buffer_t	input_message_buffer;
    int			*conf_state;
    gss_buffer_t	output_message_buffer;
{
    krb5_context	context = ctx;
    
    return(kg_seal(context, minor_status, context_handle, conf_req_flag,
		   (int) qop_req, input_message_buffer, conf_state,
		   output_message_buffer, KG_TOK_WRAP_MSG));
}

/* V2 interface */
OM_uint32
krb5_gss_wrap_size_limit(ctx, minor_status, context_handle, conf_req_flag,
			 qop_req, req_output_size, max_input_size)
    void *ctx;
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    OM_uint32		req_output_size;
    OM_uint32		*max_input_size;
{
    krb5_context	context = ctx;
    
    /* XXX - should just put this in k5seal.c */
    return(kg_seal_size(context, minor_status, context_handle, conf_req_flag,
			qop_req, req_output_size, max_input_size));
}

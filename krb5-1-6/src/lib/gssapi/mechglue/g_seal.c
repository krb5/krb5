/* #pragma ident	"@(#)g_seal.c	1.19	98/04/21 SMI" */

/*
 * Copyright 1996 by Sun Microsystems, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *  glue routine for gss_seal
 */

#include "mglueP.h"

static OM_uint32
val_seal_args(
    OM_uint32 *minor_status,
    gss_ctx_id_t context_handle,
    int conf_req_flag,
    int qop_req,
    gss_buffer_t input_message_buffer,
    int *conf_state,
    gss_buffer_t output_message_buffer)
{

    /* Initialize outputs. */

    if (minor_status != NULL)
	*minor_status = 0;

    if (output_message_buffer != GSS_C_NO_BUFFER) {
	output_message_buffer->length = 0;
	output_message_buffer->value = NULL;
    }

    /* Validate arguments. */

    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (context_handle == GSS_C_NO_CONTEXT)
	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

    if (input_message_buffer == GSS_C_NO_BUFFER)
	return (GSS_S_CALL_INACCESSIBLE_READ);

    if (output_message_buffer == GSS_C_NO_BUFFER)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    return (GSS_S_COMPLETE);
}


OM_uint32 KRB5_CALLCONV
gss_seal (minor_status,
          context_handle,
          conf_req_flag,
          qop_req,
          input_message_buffer,
          conf_state,
          output_message_buffer)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
int			conf_req_flag;
int			qop_req;
gss_buffer_t		input_message_buffer;
int *			conf_state;
gss_buffer_t		output_message_buffer;
{
 /* EXPORT DELETE START */

    OM_uint32		status;
    gss_union_ctx_id_t	ctx;
    gss_mechanism	mech;

    status = val_seal_args(minor_status, context_handle,
			   conf_req_flag, qop_req,
			   input_message_buffer, conf_state,
			   output_message_buffer);
    if (status != GSS_S_COMPLETE)
	return (status);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    ctx = (gss_union_ctx_id_t) context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);
    
    if (mech) {
	if (mech->gss_seal)
	    status = mech->gss_seal(
				    mech->context,
				    minor_status,
				    ctx->internal_ctx_id,
				    conf_req_flag,
				    qop_req,
				    input_message_buffer,
				    conf_state,
				    output_message_buffer);
	else
	    status = GSS_S_UNAVAILABLE;
	
	return(status);
    }
 /* EXPORT DELETE END */
 
    return (GSS_S_BAD_MECH);
}

OM_uint32 KRB5_CALLCONV
gss_wrap (minor_status,
          context_handle,
          conf_req_flag,
          qop_req,
          input_message_buffer,
          conf_state,
          output_message_buffer)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
int			conf_req_flag;
gss_qop_t		qop_req;
gss_buffer_t		input_message_buffer;
int *			conf_state;
gss_buffer_t		output_message_buffer;

{
    return gss_seal(minor_status, (gss_ctx_id_t)context_handle,
		    conf_req_flag, (int) qop_req,
		    (gss_buffer_t)input_message_buffer, conf_state,
		    output_message_buffer);
}

/*
 * New for V2
 */
OM_uint32 KRB5_CALLCONV
gss_wrap_size_limit(minor_status, context_handle, conf_req_flag,
		    qop_req, req_output_size, max_input_size)
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    OM_uint32		req_output_size;
    OM_uint32		*max_input_size;
{
    gss_union_ctx_id_t	ctx;
    gss_mechanism	mech;

    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);
    *minor_status = 0;
    
    if (context_handle == GSS_C_NO_CONTEXT)
	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

    if (max_input_size == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    ctx = (gss_union_ctx_id_t) context_handle;
    mech = gssint_get_mechanism (ctx->mech_type);

    if (!mech)
	return (GSS_S_BAD_MECH);

    if (!mech->gss_wrap_size_limit)
	return (GSS_S_UNAVAILABLE);
    
    return (mech->gss_wrap_size_limit(mech->context, minor_status,
				      ctx->internal_ctx_id, conf_req_flag, qop_req,
				      req_output_size, max_input_size));
}

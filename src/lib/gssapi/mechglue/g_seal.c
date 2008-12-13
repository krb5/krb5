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

static OM_uint32
gssint_seal_iov_shim(OM_uint32 *minor_status,
		     gss_ctx_id_t context_handle,
		     int conf_req_flag,
		     int qop_req,
		     gss_buffer_t input_message_buffer,
		     int *conf_state,
		     gss_buffer_t output_message_buffer)
{
    gss_iov_buffer_desc	iov[4];
    OM_uint32		status;
    size_t		offset;

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].flags = 0;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].flags = 0;
    iov[1].buffer = *input_message_buffer;

    iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
    iov[2].flags = 0;
    iov[2].buffer.value = NULL;
    iov[2].buffer.length = 0;

    iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[3].flags = 0;
    iov[3].buffer.value = NULL;
    iov[3].buffer.length = 0;

    status = gss_wrap_iov_length(minor_status, context_handle,
				 conf_req_flag, qop_req,
				 NULL, iov,
				 sizeof(iov)/sizeof(iov[0]));
    if (status != GSS_S_COMPLETE)
	return status;

    output_message_buffer->length = iov[0].buffer.length +
				    iov[1].buffer.length +
				    iov[2].buffer.length +
				    iov[3].buffer.length;
    output_message_buffer->value = malloc(output_message_buffer->length);
    if (output_message_buffer->value == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    offset = 0;

    iov[0].buffer.value = (unsigned char *)output_message_buffer->value + offset;
    offset += iov[0].buffer.length;

    iov[1].buffer.value = (unsigned char *)output_message_buffer->value + offset;
    offset += iov[1].buffer.length;

    iov[2].buffer.value = (unsigned char *)output_message_buffer->value + offset;
    offset += iov[2].buffer.length;

    iov[3].buffer.value = (unsigned char *)output_message_buffer->value + offset;

    status = gss_wrap_iov(minor_status, context_handle,
			  conf_req_flag, qop_req, conf_state,
			  iov, sizeof(iov)/sizeof(iov[0]));
    if (status != GSS_S_COMPLETE) {
	OM_uint32 minor;

	gss_release_buffer(&minor, output_message_buffer);
    }

    return status;
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
	if (mech->gss_seal) {
	    status = mech->gss_seal(
				    minor_status,
				    ctx->internal_ctx_id,
				    conf_req_flag,
				    qop_req,
				    input_message_buffer,
				    conf_state,
				    output_message_buffer);
	    if (status != GSS_S_COMPLETE)
		map_error(minor_status, mech);
	} else if (mech->gss_wrap_iov) {
	    status = gssint_seal_iov_shim(minor_status,
					  ctx,
					  conf_req_flag,
					  qop_req,
					  input_message_buffer,
					  conf_state,
					  output_message_buffer);
	} else
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

#if 0
static OM_uint32
gssint_wrap_size_limit_iov_shim(OM_uint32 *minor_status,
				gss_ctx_id_t context_handle,
				int conf_req_flag,
				gss_qop_t qop_req,
				OM_uint32 req_output_size,
				OM_uint32 *max_input_size)
{
    gss_iov_buffer_desc	iov[4];
    OM_uint32		status;
    OM_uint32		ohlen;

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].flags = 0;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].flags = 0;
    iov[1].buffer.length = req_output_size;
    iov[1].buffer.value = NULL;

    iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
    iov[2].flags = 0;
    iov[2].buffer.value = NULL;
    iov[2].buffer.length = 0;

    iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[3].flags = 0;
    iov[3].buffer.value = NULL;
    iov[3].buffer.length = 0;

    status = gss_wrap_iov_length(minor_status, context_handle,
				 conf_req_flag, qop_req,
				 NULL, iov,
				 sizeof(iov)/sizeof(iov[0]));
    if (status != GSS_S_COMPLETE)
	return status;

    ohlen = iov[3].buffer.length - iov[2].buffer.length - iov[0].buffer.length;

    if (ohlen < req_output_size)
	*max_input_size = req_output_size - ohlen;
    else
	*max_input_size = 0;

    return GSS_S_COMPLETE;
}
#endif

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
    OM_uint32		major_status;

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

    if (mech->gss_wrap_size_limit)
	major_status = mech->gss_wrap_size_limit(minor_status,
						 ctx->internal_ctx_id,
						 conf_req_flag, qop_req,
						 req_output_size, max_input_size);
#if 0
    else if (mech->gss_wrap_iov_length)
	major_status = gssint_wrap_size_limit_iov_shim(minor_status, ctx,
						       conf_req_flag, qop_req,
						       req_output_size, max_input_size);
#endif
    else
	major_status = GSS_S_UNAVAILABLE;
    if (major_status != GSS_S_COMPLETE)
	map_error(minor_status, mech);
    return major_status;
}

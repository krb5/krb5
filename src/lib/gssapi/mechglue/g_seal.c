#ident  "@(#)gss_seal.c 1.10     95/08/07 SMI"
/*
 *  glue routine for gss_seal
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
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
    OM_uint32		status;
    gss_union_ctx_id_t	ctx;
    gss_mechanism	mech;

    gss_initialize();
    
    if (context_handle == GSS_C_NO_CONTEXT)
	return GSS_S_NO_CONTEXT;

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    ctx = (gss_union_ctx_id_t) context_handle;
    mech = get_mechanism (ctx->mech_type);
    
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
	    status = GSS_S_BAD_BINDINGS;
	
	return(status);
    }

    return(GSS_S_NO_CONTEXT);
}

OM_uint32
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
	return gss_seal(minor_status, context_handle, conf_req_flag,
			(int) qop_req, input_message_buffer, conf_state,
			output_message_buffer);
}

#ident  "@(#)gss_unseal.c 1.10     95/08/07 SMI"
/*
 *  glue routine gss_unseal
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
gss_unseal (minor_status,
            context_handle,
            input_message_buffer,
            output_message_buffer,
            conf_state,
            qop_state)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		input_message_buffer;
gss_buffer_t		output_message_buffer;
int *			conf_state;
int *			qop_state;

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
	if (mech->gss_unseal) 
	    status = mech->gss_unseal(
				      mech->context,
				      minor_status,
				      ctx->internal_ctx_id,
				      input_message_buffer,
				      output_message_buffer,
				      conf_state,
				      qop_state);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }

    return(GSS_S_NO_CONTEXT);
}

OM_uint32
gss_unwrap (minor_status,
            context_handle,
            input_message_buffer,
            output_message_buffer,
            conf_state,
            qop_state)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		input_message_buffer;
gss_buffer_t		output_message_buffer;
int *			conf_state;
gss_qop_t *		qop_state;

{
	return (gss_unseal(minor_status, context_handle,
			   input_message_buffer,
			   output_message_buffer,
			   conf_state, (int *) qop_state));
}

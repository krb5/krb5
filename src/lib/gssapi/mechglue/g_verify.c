#ident  "@(#)gss_verify.c 1.9     95/08/07 SMI"
/*
 *  glue routine for gss_verify
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
gss_verify (minor_status,
            context_handle,
            message_buffer,
            token_buffer,
            qop_state)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		message_buffer;
gss_buffer_t		token_buffer;
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
	if (mech->gss_verify)
	    status = mech->gss_verify(
				      mech->context,
				      minor_status,
				      ctx->internal_ctx_id,
				      message_buffer,
				      token_buffer,
				      qop_state);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }

    return(GSS_S_NO_CONTEXT);
}

OM_uint32
gss_verify_mic (minor_status,
            context_handle,
            message_buffer,
            token_buffer,
            qop_state)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		message_buffer;
gss_buffer_t		token_buffer;
gss_qop_t *		qop_state;

{
	return (gss_verify(minor_status, context_handle,
			   message_buffer, token_buffer, (int *) qop_state));
}

#ident  "@(#)gss_process_context.c 1.9     95/08/07 SMI"
/*
 *  glue routine gss_process_context
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
gss_process_context_token (minor_status,
                           context_handle,
                           token_buffer)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		token_buffer;

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

	if (mech->gss_process_context_token)
	    status = mech->gss_process_context_token(
						    mech->context,
						    minor_status,
						    ctx->internal_ctx_id,
						    token_buffer);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }
    
    return(GSS_S_NO_CONTEXT);
}

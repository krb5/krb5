#ident  "@(#)gss_delete_sec_context.c 1.10     95/08/07 SMI"
/*
 *  glue routine for gss_delete_sec_context
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

OM_uint32
gss_delete_sec_context (minor_status,
                        context_handle,
                        output_token)

OM_uint32 *		minor_status;
gss_ctx_id_t *		context_handle;
gss_buffer_t		output_token;

{
    OM_uint32		status;
    gss_union_ctx_id_t	ctx;
    gss_mechanism	mech;
    
    gss_initialize();

    /* if the context_handle is Null, return NO_CONTEXT error */
    
    if(context_handle == NULL || *context_handle == GSS_C_NO_CONTEXT)
	return(GSS_S_NO_CONTEXT);
    
    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    ctx = (gss_union_ctx_id_t) *context_handle;
    mech = get_mechanism (ctx->mech_type);
    
    if (mech) {

	if (mech->gss_delete_sec_context)
	    status = mech->gss_delete_sec_context(
						  mech->context,
						  minor_status,
						  &ctx->internal_ctx_id,
						  output_token);
	else
	    status = GSS_S_BAD_BINDINGS;

	/* now free up the space for the union context structure */
	
	free(ctx->mech_type->elements);
	free(ctx->mech_type);
	free(*context_handle);
	*context_handle = NULL;

	return(status);
    }
    
    return(GSS_S_NO_CONTEXT);
}

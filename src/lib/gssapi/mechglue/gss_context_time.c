#ident  "@(#)gss_context_time.c 1.8     95/08/07 SMI"
/*
 *  glue routines for gss_context_time
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mechglueP.h"

OM_uint32
gss_context_time (minor_status,
                  context_handle,
                  time_rec)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
OM_uint32 *		time_rec;

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

	if (mech->gss_context_time)
	    status = mech->gss_context_time(
					    mech->context,
					    minor_status,
					    ctx->internal_ctx_id,
					    time_rec);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }
    
    return(GSS_S_NO_CONTEXT);
}

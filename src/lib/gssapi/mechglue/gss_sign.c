#ident  "@(#)gss_sign.c 1.10     95/08/07 SMI"
/*
 *  glue routine gss_sign
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mechglueP.h"

OM_uint32
gss_sign (minor_status,
          context_handle,
          qop_req,
          message_buffer,
          msg_token)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
int			qop_req;
gss_buffer_t		message_buffer;
gss_buffer_t		msg_token;

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
	if (mech->gss_sign)
	    status = mech->gss_sign(
				    mech->context,
				    minor_status,
				    ctx->internal_ctx_id,
				    qop_req,
				    message_buffer,
				    msg_token);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }

    return(GSS_S_NO_CONTEXT);
}

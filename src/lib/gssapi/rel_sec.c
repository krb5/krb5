/*
 * rel_buffer.c --- release a security context
 *
 * $Source$
 * $Author$
 * $Header$
 * 
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#include <gssapi.h>

OM_uint32 gss_release_security_context(minor_status, context)
	OM_uint32	*minor_status;
	gss_ctx_id_t	context;
{
	*minor_status = 0;

	krb5_free_principal(context->me);
	krb5_free_principal(context->him);
	
	context->state = GSS_KRB5_STATE_DOWN;
	return(GSS_S_COMPLETE);
}
	
			     

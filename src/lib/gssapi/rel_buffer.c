/*
 * rel_buffer.c --- release a gss_buffer_t
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

OM_uint32 gss_release_buffer(minor_status, buffer)
	OM_uint32	*minor_status;
	gss_buffer_t	buffer;
{
	*minor_status = 0;

	free(buffer->value);
	return(GSS_S_COMPLETE);
}
	
			     

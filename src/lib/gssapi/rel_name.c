/*
 * rel_name.c --- release a gss_name_t
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

OM_uint32 gss_release_name(minor_status, name)
	OM_uint32	*minor_status;
	gss_name_t	*name;
{
	*minor_status = 0;

	krb5_free_principal(*name);
	return(GSS_S_COMPLETE);
}
	
			     

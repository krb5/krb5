/*
 * rel_cred.c --- release a gss_cred_id_t
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

OM_uint32 gss_release_cred(minor_status, cred_handle)
	OM_uint32	*minor_status;
	gss_cred_id_t	*cred_handle;
{
	krb5_free_principal(cred_handle->principal);
	if (*minor_status = krb5_cc_close(cred_handle->ccache))
		return(GSS_S_FAILURE);
	xfree(cred_handle->srvtab.contents);
	return(GSS_S_COMPLETE);
}
	
			     

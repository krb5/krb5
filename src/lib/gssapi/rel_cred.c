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
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
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
	
			     

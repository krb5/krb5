/*
 * rel_oidset.c --- release a fgss_oid_set
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

OM_uint32 gss_release_oid_set(minor_status, set)
	OM_uint32	*minor_status;
	gss_OID_set	set;
{
	*minor_status = 0;

	/*
	 * We don't free the OID parts themselves, since they will all
	 * be constant structures in this version
	 */
	free((char *)set);
	return(GSS_S_COMPLETE);
}
	
			     

/*
 * ind_mechs.c --- Indicate mechanisms  (also where the OID's are declared)
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

struct gss_OID_desc gss_OID_krb5 = { 15, "KRB5.OSI.SUCKS"};
struct gss_OID_desc gss_OID_krb5_name = { 20, "KRB5.NAME.OSI.SUCKS" };

OM_uint32 gss_indicate_mechs(minor_status, mech_set)
	OM_uint32	*minor_status;
	gss_OID_set	*mech_set;
{
	gss_OID_set	set;
	
	*minor_status = 0;
	if (!(set = (gss_OID_set) malloc (sizeof(struct gss_OID_set_desc)))) {
		*minor_status = ENOMEM;
		return(GSS_S_FAILURE);
	}
	set->count = 1;
	set->elements = &gss_OID_krb5;
	*mech_set = set;
	return(GSS_S_COMPLETE);
}
	
			     

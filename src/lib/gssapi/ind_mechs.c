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
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
	
			     

/*
 * imp_name.c --- import_name
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

OM_uint32 gss_compare_name(minor_status, name1, name2, name_equal)
	OM_uint32	*minor_status;
	gss_name_t	name1, name2;
	int		*name_equal;
{
	*minor_status = 0;

	*name_equal = krb5_principal_compare(name1, name2);
	return(GSS_S_COMPLETE);
}


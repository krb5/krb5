/*
 * comp_oid.c --- compare OID's
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

int gss_compare_OID(oid1, oid2)
	gss_OID	oid1, oid2;
{
	if (oid1->length != oid2->length)
		return(0);
	return (!memcmp(oid1->elements, oid2->elements, oid1->length));
}

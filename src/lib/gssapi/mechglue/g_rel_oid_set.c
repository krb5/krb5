#ident  "@(#)gss_release_oid_set.c 1.12     95/08/23 SMI"
/*
 *  glue routine for gss_release_oid_set
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
gss_release_oid_set (minor_status,
		     set)

OM_uint32 *		minor_status;
gss_OID_set *		set;
{
   size_t index;
   OM_uint32	status;

    if (minor_status)
	*minor_status = 0;

    if (set ==NULL)
	return GSS_S_COMPLETE;

    if (*set == GSS_C_NULL_OID_SET)
	return(GSS_S_COMPLETE);

    for (index=0; index<(*set)->count; index++)
      free((*set)->elements[index].elements);
    free((*set)->elements);
    free(*set);

    *set = GSS_C_NULL_OID_SET;
    
    return(GSS_S_COMPLETE);
}

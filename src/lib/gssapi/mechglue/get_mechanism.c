#ident  "@(#)get_mechanism.c 1.10     95/08/04 SMI"
/*
 *  given the mechs_array and a mechanism OID, return the 
 *  pointer to the mechanism, or NULL if that mechanism is
 *  not supported.  If the requested OID is NULL, then return
 *  the first mechanism.
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

extern gss_mechanism *mechs_array;

gss_mechanism get_mechanism (gss_OID type)
{
    int	i;

    if (type == GSS_C_NULL_OID)
	return (mechs_array[0]);

    for (i=0; mechs_array[i]->mech_type.length != 0; i++) {
	if ((mechs_array[i]->mech_type.length == type->length) &&
	    (memcmp (mechs_array[i]->mech_type.elements, type->elements,
		     type->length) == 0)) {

	    return (mechs_array[i]);
	}
    }
    return NULL;
}

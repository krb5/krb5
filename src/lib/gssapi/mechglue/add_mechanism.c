#ident	"@(#)add_mechanism.c	1.5	95/08/04 SMI"
/*
 * This function will add a new mechanism to the mechs_array
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mechglueP.h"
#include <errno.h>

static struct gss_config null_mech = {
  {0,NULL}};

gss_mechanism *mechs_array = NULL;

OM_uint32 add_mechanism (gss_mechanism mech, int replace)
{
    gss_mechanism *temp_array;
    int i;

    if (mech == NULL)
	return GSS_S_COMPLETE;

    /* initialize the mechs_array if it hasn't already been initialized */
    if (mechs_array == NULL) {
	mechs_array = (gss_mechanism *) malloc (sizeof(gss_mechanism));

	if (mechs_array == NULL)
	    return ENOMEM;

	mechs_array[0] = &null_mech;
    }

    /* 
     * Find the length of mechs_array, and look for an existing
     * entry for this OID
     */
    for (i=0; mechs_array[i]->mech_type.length != 0; i++) {
	if ((mechs_array[i]->mech_type.length == mech->mech_type.length) &&
	    (memcmp (mechs_array[i]->mech_type.elements, 
		     mech->mech_type.elements,
		     mech->mech_type.length) == 0)) {

	    /* We found a match.  Replace it? */
	    if (!replace)
		return GSS_S_FAILURE;

	    mechs_array[i] = mech;
	    return GSS_S_COMPLETE;
	}
    }

    /* we didn't find it -- add it to the end of the mechs_array */
    temp_array = (gss_mechanism *) realloc(mechs_array,
					   (i+2)*sizeof(gss_mechanism));

    if (temp_array == NULL)
	return ENOMEM;

    temp_array[i++] = mech;
    temp_array[i] = &null_mech;

    mechs_array = temp_array;

    return GSS_S_COMPLETE;
}

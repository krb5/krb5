#ident  "@(#)gss_indicate_mechs.c 1.13     95/08/04 SMI"
/*
 *  glue routine for gss_indicate_mechs
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

extern gss_mechanism *mechs_array;

static gss_OID_set_desc	supported_mechs_desc; 
static gss_OID_set supported_mechs = NULL;

OM_uint32
gss_indicate_mechs (minor_status,
                    mech_set)

OM_uint32 *		minor_status;
gss_OID_set *		mech_set;

{
    int i;
    
    gss_initialize();

    if (minor_status)
	*minor_status = 0;

    /*
     * If we have already computed the mechanisms supported, return
     * a pointer to it. Otherwise, compute them and return the pointer.
     */
    
    if(supported_mechs == NULL) {

	supported_mechs = &supported_mechs_desc;
	supported_mechs->count = 0;

	/* Build the mech_set from the OIDs in mechs_array. */

	for(i=0; mechs_array[i]->mech_type.length != 0; i++) 
	    supported_mechs->count++;

	supported_mechs->elements =
	    (void *) malloc(supported_mechs->count *
			    sizeof(gss_OID_desc));

	for(i=0; i < supported_mechs->count; i++) {
	    supported_mechs->elements[i].length =
		mechs_array[i]->mech_type.length;
	    supported_mechs->elements[i].elements = (void *)
		malloc(mechs_array[i]->mech_type.length);
	    memcpy(supported_mechs->elements[i].elements,
		   mechs_array[i]->mech_type.elements,
		   mechs_array[i]->mech_type.length);
	}
    }
    
    if(mech_set != NULL)
	*mech_set = supported_mechs;
    
    return(GSS_S_COMPLETE);
}

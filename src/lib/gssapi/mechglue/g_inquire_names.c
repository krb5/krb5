
#ident	"@(#)g_inquire_names.c 1.1     95/12/19 SMI"

/*
 *  glue routine for gss_inquire_context
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

/* Last argument new for V2 */
OM_uint32 gss_inquire_names_for_mech(
	    minor_status,
	    mechanism,
	    name_types)

OM_uint32 *	minor_status;
gss_OID 	mechanism;
gss_OID_set *	name_types;

{
    OM_uint32		status;
    gss_mechanism	mech;
    
    gss_initialize();
    
    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    mech = get_mechanism (mechanism);
    
    if (mech) {

	if (mech->gss_inquire_names_for_mech)
	    status = mech->gss_inquire_names_for_mech(
				mech->context,
				minor_status,
				mechanism,
				name_types);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }
    
    return(GSS_S_NO_CONTEXT);
}

#ident  "@(#)gssd_pname_to_uid.c 1.5     95/08/02 SMI"
/*
 *  glue routines that test the mech id either passed in to
 *  gss_init_sec_contex() or gss_accept_sec_context() or within the glue
 *  routine supported version of the security context and then call
 *  the appropriate underlying mechanism library procedure. 
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

int gssd_pname_to_uid(pname, name_type, mech_type, uid)

char * pname;
gss_OID name_type;
gss_OID mech_type;
uid_t * uid;
{
    int status;
    gss_mechanism	mech;

    gss_initialize();

    /*
     * find the appropriate mechanism specific pname_to_uid procedure and
     * call it.
     */

    mech = get_mechanism (mech_type);

    if (mech) {
	if (mech_type == GSS_C_NULL_OID)
	    mech_type = &mech->mech_type;

	if (mech->pname_to_uid)
	    status = mech->pname_to_uid(pname, name_type, mech_type, uid);
	else
	    status = GSS_S_BAD_MECH;
    } else
	status = GSS_S_BAD_MECH;

    return(status);
}

#ident  "@(#)gss_display_status.c 1.8     95/08/07 SMI"
/*
 *  glue routine gss_display_status
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
gss_display_status (minor_status,
                    status_value,
                    status_type,
                    req_mech_type,
                    message_context,
                    status_string)

OM_uint32 *		minor_status;
OM_uint32		status_value;
int			status_type;
gss_OID			req_mech_type;
OM_uint32 *		message_context;
gss_buffer_t		status_string;

{
    OM_uint32		status;
    gss_OID		mech_type = (gss_OID) req_mech_type;
    gss_mechanism	mech;

    gss_initialize();

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    mech = get_mechanism (mech_type);

    if (mech == NULL) 
	return (GSS_S_BAD_MECH);

    if (mech_type == GSS_C_NULL_OID)
	mech_type = &mech->mech_type;

    if (mech->gss_display_status)
	status = mech->gss_display_status(
					  mech->context,
					  minor_status,
					  status_value,
					  status_type,
					  mech_type,
					  message_context,
					  status_string);
    else
	status = GSS_S_BAD_BINDINGS;

    return(status);
}

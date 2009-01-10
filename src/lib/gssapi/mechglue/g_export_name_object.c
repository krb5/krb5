/*
 * Copyright (c) 1996,1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* #pragma ident	"@(#)g_export_name.c	1.11	00/07/17 SMI" */

/*
 * glue routine gss_export_name_object_object_object_object
 *
 * Will either call the mechanism defined gss_export_name, or if one is
 * not defined will call a generic_gss_export_name routine.
 */

#include <mglueP.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

OM_uint32 KRB5_CALLCONV
gss_export_name_object(minor_status,
		       input_name,
		       desired_name_type,
		       output_name)
OM_uint32 *		minor_status;
const gss_name_t	input_name;
gss_OID			desired_name_type;
void **			output_name;
{
    gss_union_name_t		union_name;
    gss_mechanism		mech;
    OM_uint32			major_status;

    if (minor_status != NULL)
	*minor_status = 0;

    if (output_name != NULL)
	*output_name = NULL;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (input_name == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;

    if (desired_name_type == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAMETYPE;

    if (output_name == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    union_name = (gss_union_name_t)input_name;

    if (union_name->mech_type == GSS_C_NO_OID)
	return GSS_S_NAME_NOT_MN;

    mech = gssint_get_mechanism(union_name->mech_type);
    if (mech == NULL)
	return GSS_S_BAD_MECH;

    if (mech->gss_export_name_object == NULL)
	return GSS_S_UNAVAILABLE;

    major_status = mech->gss_export_name_object(minor_status,
						input_name,
						desired_name_type,
						output_name);
    if (major_status != GSS_S_COMPLETE)
	map_error(minor_status, mech);

    return major_status;
}

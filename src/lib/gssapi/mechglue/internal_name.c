#ident  "@(#)internal_name.c 1.5     95/08/07 SMI"
/*
 *  Internal routines to get and release an internal mechanism name
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mechglueP.h"

OM_uint32 import_internal_name (minor_status, mech_type, union_name, 
				internal_name)
OM_uint32	*minor_status;
gss_OID		mech_type;
gss_union_name_t	union_name;
gss_name_t	*internal_name;
{
    OM_uint32		status;
    gss_mechanism	mech;

    mech = get_mechanism (mech_type);
    if (mech) {
	if (mech->gss_import_name)
	    status = mech->gss_import_name (
					    mech->context,
					    minor_status,
					    union_name->external_name,
					    union_name->name_type,
					    internal_name);
	else
	    status = GSS_S_BAD_BINDINGS;

	return (status);
    }

    return (GSS_S_BAD_MECH);
}

OM_uint32 display_internal_name (minor_status, mech_type, internal_name, 
				 external_name, name_type)
OM_uint32	*minor_status;
gss_OID		mech_type;
gss_name_t	internal_name;
gss_buffer_t	external_name;
gss_OID		*name_type;
{
    OM_uint32		status;
    gss_mechanism	mech;

    mech = get_mechanism (mech_type);
    if (mech) {
	if (mech->gss_display_name)
	    status = mech->gss_display_name (
					     mech->context,
					     minor_status,
					     internal_name,
					     external_name,
					     name_type);
	else
	    status = GSS_S_BAD_BINDINGS;

	return (status);
    }

    return (GSS_S_BAD_MECH);
}

OM_uint32 release_internal_name (minor_status, mech_type, internal_name)
OM_uint32	*minor_status;
gss_OID		mech_type;
gss_name_t	*internal_name;
{
    OM_uint32		status;
    gss_mechanism	mech;

    mech = get_mechanism (mech_type);
    if (mech) {
	if (mech->gss_release_name)
	    status = mech->gss_release_name (
					     mech->context,
					     minor_status,
					     internal_name);
	else
	    status = GSS_S_BAD_BINDINGS;

	return (status);
    }

    return (GSS_S_BAD_MECH);
}

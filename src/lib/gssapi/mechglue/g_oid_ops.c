/*
 * lib/gssapi/mechglue/g_oid_ops.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * oid_ops.c - GSS-API V2 interfaces to manipulate OIDs
 */

#include "mglueP.h"
/* should include to get protos #include "../generic/gssapiP_generic.h" */

extern gss_mechanism *__gss_mechs_array;

OM_uint32 KRB5_CALLCONV
gss_release_oid(minor_status, oid)
    OM_uint32	*minor_status;
    gss_OID	*oid;
{
    int i;
    OM_uint32   major_status;

    /* first call the gss_internal_release_oid for each mechanism
     * until one returns success. gss_internal_release_oid will only return
     * success when the OID was recognized as an internal mechanism OID.
     * if no mechanisms recognize the OID, then call the generic version.
     */

    for(i=0; __gss_mechs_array[i]->mech_type.length !=0; i++) {
        if (__gss_mechs_array[i]->gss_internal_release_oid) {
	    major_status = __gss_mechs_array[i]->gss_internal_release_oid(
					    __gss_mechs_array[i]->context,
					    minor_status,
					    oid);
	    if (major_status == GSS_S_COMPLETE) {
	        return (GSS_S_COMPLETE);
	    }
	}
    }

    return generic_gss_release_oid(minor_status, oid);
}

OM_uint32 KRB5_CALLCONV
gss_create_empty_oid_set(minor_status, oid_set)
    OM_uint32	*minor_status;
    gss_OID_set	*oid_set;
{
	return generic_gss_create_empty_oid_set(minor_status, oid_set);
}

OM_uint32 KRB5_CALLCONV
gss_add_oid_set_member(minor_status, member_oid, oid_set)
    OM_uint32	*minor_status;
    gss_OID	member_oid;
    gss_OID_set	*oid_set;
{
     return generic_gss_add_oid_set_member(minor_status, member_oid, oid_set);
}

OM_uint32 KRB5_CALLCONV
gss_test_oid_set_member(minor_status, member, set, present)
    OM_uint32	*minor_status;
    gss_OID	member;
    gss_OID_set	set;
    int		*present;
{
    return generic_gss_test_oid_set_member(minor_status, member, set, present);
}

OM_uint32 KRB5_CALLCONV
gss_oid_to_str(minor_status, oid, oid_str)
    OM_uint32		*minor_status;
    gss_OID		oid;
    gss_buffer_t	oid_str;
{
    return generic_gss_oid_to_str(minor_status, oid, oid_str);
}

OM_uint32 KRB5_CALLCONV
gss_str_to_oid(minor_status, oid_str, oid)
    OM_uint32		*minor_status;
    gss_buffer_t	oid_str;
    gss_OID		*oid;
{
    return generic_gss_str_to_oid(minor_status, oid_str, oid);
}


/* #pragma ident	"@(#)g_inquire_names.c	1.16	04/02/23 SMI" */

/*
 * Copyright 1996 by Sun Microsystems, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *  glue routine for gss_inquire_context
 */

#include "mglueP.h"

#define	MAX_MECH_OID_PAIRS 32

/* Last argument new for V2 */
OM_uint32 KRB5_CALLCONV
gss_inquire_names_for_mech(minor_status, mechanism, name_types)

OM_uint32 *	minor_status;
gss_OID 	mechanism;
gss_OID_set *	name_types;

{
    OM_uint32		status;
    gss_mechanism	mech;

    /* Initialize outputs. */

    if (minor_status != NULL)
	*minor_status = 0;

    if (name_types != NULL)
	*name_types = GSS_C_NO_OID_SET;

    /* Validate arguments. */

    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (name_types == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    mech = gssint_get_mechanism (mechanism);
    
    if (mech) {

	if (mech->gss_inquire_names_for_mech)
	    status = mech->gss_inquire_names_for_mech(
				mech->context,
				minor_status,
				mechanism,
				name_types);
	else
	    status = GSS_S_UNAVAILABLE;

	return(status);
    }
    
    return (GSS_S_BAD_MECH);
}

static OM_uint32
val_inq_mechs4name_args(
    OM_uint32 *minor_status,
    const gss_name_t input_name,
    gss_OID_set *mech_set)
{

    /* Initialize outputs. */
    if (minor_status != NULL)
	*minor_status = 0;

    if (mech_set != NULL)
	*mech_set = GSS_C_NO_OID_SET;

    /* Validate arguments.e
 */
    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (input_name == GSS_C_NO_NAME)
	return (GSS_S_BAD_NAME);

    return (GSS_S_COMPLETE);
}


OM_uint32 KRB5_CALLCONV
gss_inquire_mechs_for_name(minor_status, input_name, mech_set)

    OM_uint32 *		minor_status;
    const gss_name_t	input_name;
    gss_OID_set *		mech_set;

{
    OM_uint32		status;
    static char		*mech_list[MAX_MECH_OID_PAIRS+1];
    gss_OID_set		mech_name_types;
    int			present;
    char 			*mechanism;
    gss_OID 		mechOid;
    gss_OID 		name_type;
    gss_buffer_desc		name_buffer;
    int			i;

    status = val_inq_mechs4name_args(minor_status, input_name, mech_set);
    if (status != GSS_S_COMPLETE)
	return (status);

    status = gss_create_empty_oid_set(minor_status, mech_set);
    if (status != GSS_S_COMPLETE)
	return (status);
    *mech_list = NULL;
    status = gssint_get_mechanisms(mech_list, MAX_MECH_OID_PAIRS+1);
    if (status != GSS_S_COMPLETE)
	return (status);
    for (i = 0; i < MAX_MECH_OID_PAIRS && mech_list[i] != NULL; i++) {
	mechanism = mech_list[i];
	if (gssint_mech_to_oid(mechanism, &mechOid) == GSS_S_COMPLETE) {
	    status = gss_inquire_names_for_mech(
		minor_status,
		mechOid,
		&mech_name_types);
	    if (status == GSS_S_COMPLETE) {
		status = gss_display_name(minor_status,
					  input_name,
					  &name_buffer,
					  &name_type);

		(void) gss_release_buffer(NULL, &name_buffer);

		if (status == GSS_S_COMPLETE && name_type) {
		    status = gss_test_oid_set_member(
			minor_status,
			name_type,
			mech_name_types,
			&present);
		    if (status == GSS_S_COMPLETE &&
			present) {
			status = gss_add_oid_set_member(
			    minor_status,
			    mechOid,
			    mech_set);
			if (status != GSS_S_COMPLETE) {
			    (void) gss_release_oid_set(
				minor_status,
				&mech_name_types);
			    (void) gss_release_oid_set(
				minor_status,
				mech_set);
			    return (status);
			}
		    }
		}
		(void) gss_release_oid_set(
		    minor_status,
		    &mech_name_types);
	    }
	} else {
	    (void) gss_release_oid_set(
		minor_status,
		mech_set);
	    return (GSS_S_FAILURE);
	}
    }
    return (GSS_S_COMPLETE);
}

/* #pragma ident	"@(#)g_inquire_cred.c	1.16	04/02/23 SMI" */

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
 *  glue routine for gss_inquire_cred
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <time.h>

OM_uint32 KRB5_CALLCONV
gss_inquire_cred(minor_status,
                 cred_handle,
                 name,
                 lifetime,
		 cred_usage,
                 mechanisms)

OM_uint32 *		minor_status;
gss_cred_id_t 		cred_handle;
gss_name_t *		name;
OM_uint32 *		lifetime;
int *			cred_usage;
gss_OID_set *		mechanisms;

{
    OM_uint32		status, temp_minor_status;
    gss_union_cred_t	union_cred;
    gss_mechanism	mech;
    gss_cred_id_t	mech_cred;
    gss_name_t		mech_name;
    int			i;
    gss_OID_set		mechs = NULL;

    /* Initialize outputs. */

    if (minor_status != NULL)
	*minor_status = 0;

    if (name != NULL)
	*name = GSS_C_NO_NAME;

    if (mechanisms != NULL)
	*mechanisms = GSS_C_NO_OID_SET;

    /* Validate arguments. */
    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    /*
     * XXX We should iterate over all mechanisms in the credential and
     * aggregate the results.  This requires a union name structure containing
     * multiple mechanism names, which we don't currently have.  For now,
     * inquire the first mechanism in the credential; this is consistent with
     * our historical behavior.
     */

    /* Determine mechanism and mechanism credential. */
    if (cred_handle != GSS_C_NO_CREDENTIAL) {
	union_cred = (gss_union_cred_t) cred_handle;
	if (union_cred->count <= 0)
	    return (GSS_S_DEFECTIVE_CREDENTIAL);
	mech_cred = union_cred->cred_array[0];
	mech = gssint_get_mechanism(&union_cred->mechs_array[0]);
    } else {
	union_cred = NULL;
	mech_cred = GSS_C_NO_CREDENTIAL;
	mech = gssint_get_mechanism(GSS_C_NULL_OID);
    }
    if (mech == NULL)
	return (GSS_S_DEFECTIVE_CREDENTIAL);
    if (!mech->gss_inquire_cred)
	return (GSS_S_UNAVAILABLE);

    status = mech->gss_inquire_cred(minor_status, mech_cred,
				    name ? &mech_name : NULL,
				    lifetime, cred_usage, NULL);
    if (status != GSS_S_COMPLETE) {
	map_error(minor_status, mech);
	return(status);
    }

    if (name) {
	/* Convert mech_name into a union_name equivalent. */
	status = gssint_convert_name_to_union_name(&temp_minor_status,
						   mech, mech_name, name);
	if (status != GSS_S_COMPLETE) {
	    *minor_status = temp_minor_status;
	    map_error(minor_status, mech);
	    return (status);
	}
    }

    /*
     * copy the mechanism set in union_cred into an OID set and return in
     * the mechanisms parameter.
     */

    if(mechanisms != NULL) {
	status = GSS_S_FAILURE;
	mechs = (gss_OID_set) malloc(sizeof(gss_OID_set_desc));
	if (mechs == NULL)
	    goto error;
	mechs->count = 0;
	mechs->elements = malloc(sizeof(gss_OID_desc) *
					 (union_cred ? union_cred->count : 1));
	if (mechs->elements == NULL)
	    goto error;

	if (union_cred) {
	    for (i = 0; i < union_cred->count; i++) {
		mechs->elements[i].elements =
		    malloc(union_cred->mechs_array[i].length);
		if (mechs->elements[i].elements == NULL)
		    goto error;
		g_OID_copy(&mechs->elements[i], &union_cred->mechs_array[i]);
		mechs->count++;
	    }
	} else {
	    mechs->elements[0].elements = malloc(mech->mech_type.length);
	    g_OID_copy(&mechs->elements[0], &mech->mech_type);
	    mechs->count++;
	}
	*mechanisms = mechs;
    }

    return(GSS_S_COMPLETE);

error:
    /*
     * cleanup any allocated memory - we can just call
     * gss_release_oid_set, because the set is constructed so that
     * count always references the currently copied number of
     * elements.
     */
    if (mechs != NULL)
	(void) gss_release_oid_set(&temp_minor_status, &mechs);

    if (name && *name != NULL)
	(void) gss_release_name(&temp_minor_status, name);

    return (status);
}

OM_uint32 KRB5_CALLCONV
gss_inquire_cred_by_mech(minor_status, cred_handle, mech_type, name,
			 initiator_lifetime, acceptor_lifetime, cred_usage)
    OM_uint32		*minor_status;
    gss_cred_id_t	cred_handle;
    gss_OID		mech_type;
    gss_name_t		*name;
    OM_uint32		*initiator_lifetime;
    OM_uint32		*acceptor_lifetime;
    gss_cred_usage_t *cred_usage;
{
    gss_union_cred_t	union_cred;
    gss_cred_id_t	mech_cred;
    gss_mechanism	mech;
    OM_uint32		status, temp_minor_status;
    gss_name_t		internal_name;

    if (minor_status != NULL)
	*minor_status = 0;

    if (name != NULL)
	*name = GSS_C_NO_NAME;

    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    mech = gssint_get_mechanism (mech_type);
    if (!mech)
	return (GSS_S_BAD_MECH);
    if (!mech->gss_inquire_cred_by_mech)
	return (GSS_S_BAD_BINDINGS);

    union_cred = (gss_union_cred_t) cred_handle;
    mech_cred = gssint_get_mechanism_cred(union_cred, mech_type);

#if 0
    if (mech_cred == NULL)
	return (GSS_S_DEFECTIVE_CREDENTIAL);
#endif

    status = mech->gss_inquire_cred_by_mech(minor_status,
					    mech_cred, mech_type,
					    name ? &internal_name : NULL,
					    initiator_lifetime,
					    acceptor_lifetime, cred_usage);

    if (status != GSS_S_COMPLETE) {
	map_error(minor_status, mech);
	return (status);
    }

    if (name) {
	/*
	 * Convert internal_name into a union_name equivalent.
	 */
	status = gssint_convert_name_to_union_name(
	    &temp_minor_status, mech,
	    internal_name, name);
	if (status != GSS_S_COMPLETE) {
	    *minor_status = temp_minor_status;
	    map_error(minor_status, mech);
	    return (status);
	}
    }

    return (GSS_S_COMPLETE);
}

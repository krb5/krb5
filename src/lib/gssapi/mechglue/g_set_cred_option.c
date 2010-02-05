/*
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
 *  glue routine for gssspi_set_cred_option
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <time.h>

OM_uint32 KRB5_CALLCONV
gssspi_set_cred_option(OM_uint32 *minor_status,
	               gss_cred_id_t cred_handle,
	               const gss_OID desired_object,
	               const gss_buffer_t value)
{
    gss_union_cred_t	union_cred;
    gss_mechanism	mech;
    int			i;
    OM_uint32		status;
    OM_uint32		mech_status;
    OM_uint32		mech_minor_status;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CRED;

    *minor_status = 0;

    union_cred = (gss_union_cred_t) cred_handle;

    status = GSS_S_UNAVAILABLE;

    for (i = 0; i < union_cred->count; i++) {
	mech = gssint_get_mechanism(&union_cred->mechs_array[i]);
	if (mech == NULL) {
	    status = GSS_S_BAD_MECH;
	    break;
	}

	if (mech->gssspi_set_cred_option == NULL) {
	    continue;
	}

	mech_status = (mech->gssspi_set_cred_option)(&mech_minor_status,
						union_cred->cred_array[i],
						desired_object,
						value);
        if (mech_status == GSS_S_UNAVAILABLE) {
            continue;
        }
        else {
            status = mech_status;
            *minor_status = mech_minor_status;
        }
	if (status != GSS_S_COMPLETE) {
	    map_error(minor_status, mech);
	    break;
	}
    }

    return status;
}

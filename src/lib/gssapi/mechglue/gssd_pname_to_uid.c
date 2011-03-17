/* #pragma ident	"@(#)gssd_pname_to_uid.c	1.18	04/02/23 SMI" */

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
 *  glue routines that test the mech id either passed in to
 *  gss_init_sec_contex() or gss_accept_sec_context() or within the glue
 *  routine supported version of the security context and then call
 *  the appropriate underlying mechanism library procedure.
 *
 */

#include "mglueP.h"

OM_uint32 gss_pname_to_uid(minor, pname, mech_type, uid)
OM_uint32 *minor;
const gss_name_t pname;
const gss_OID mech_type;
uid_t *uid;
{
    OM_uint32 major, tmpMinor;
    gss_mechanism mech;
    gss_union_name_t unionName;
    gss_name_t mechName = GSS_C_NO_NAME;

    /*
     * find the appropriate mechanism specific pname_to_uid procedure and
     * call it.
     */
    if (minor == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor = 0;

    if (pname == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (uid == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    unionName = (gss_union_name_t)pname;

    if (mech_type != GSS_C_NO_OID)
        mech = gssint_get_mechanism(mech_type);
    else
        mech = gssint_get_mechanism(unionName->mech_type);

    if (mech == NULL || mech->gss_pname_to_uid == NULL)
	return GSS_S_UNAVAILABLE;

    /* may need to create a mechanism specific name */
    if (unionName->mech_type == GSS_C_NO_OID ||
        (unionName->mech_type != GSS_C_NO_OID &&
         !g_OID_equal(unionName->mech_type, &mech->mech_type))) {
        major = gssint_import_internal_name(minor, &mech->mech_type,
                                            unionName, &mechName);
        if (GSS_ERROR(major))
            return major;
    }

    major = mech->gss_pname_to_uid(minor,
                                   mechName ? mechName : unionName->mech_name,
                                   mech_type, uid);

    if (mechName != GSS_C_NO_NAME)
        gssint_release_internal_name(&tmpMinor, &mech->mech_type, &mechName);

    return major;
}

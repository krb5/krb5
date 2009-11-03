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

int gssd_pname_to_uid(pname, name_type, mech_type, uid)

char * pname;
gss_OID name_type;
gss_OID mech_type;
uid_t * uid;
{
    int status;
    gss_mechanism	mech;

    /*
     * find the appropriate mechanism specific pname_to_uid procedure and
     * call it.
     */

    mech = gssint_get_mechanism (mech_type);

    if (mech) {
	if (mech_type == GSS_C_NULL_OID)
	    mech_type = &mech->mech_type;

	if (mech->pname_to_uid) {
	    status = mech->pname_to_uid(pname, name_type, mech_type, uid);
	    if (status != GSS_S_COMPLETE)
		map_error(minor_status, mech);
	} else
	    status = GSS_S_BAD_MECH;
    } else
	status = GSS_S_BAD_MECH;

    return(status);
}

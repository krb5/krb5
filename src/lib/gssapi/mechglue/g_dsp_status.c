/* #ident  "@(#)gss_display_status.c 1.8     95/08/07 SMI" */

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
 *  glue routine gss_display_status
 *
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

OM_uint32 KRB5_CALLCONV
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

    mech = __gss_get_mechanism (mech_type);

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

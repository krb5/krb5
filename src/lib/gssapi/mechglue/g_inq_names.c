/* #ident	"@(#)g_inquire_names.c 1.1     95/12/19 SMI" */

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

/* Last argument new for V2 */
OM_uint32 KRB5_CALLCONV
gss_inquire_names_for_mech(minor_status, mechanism, name_types)

OM_uint32 *	minor_status;
gss_OID 	mechanism;
gss_OID_set *	name_types;

{
    OM_uint32		status;
    gss_mechanism	mech;
    
    gss_initialize();
    
    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    mech = __gss_get_mechanism (mechanism);
    
    if (mech) {

	if (mech->gss_inquire_names_for_mech)
	    status = mech->gss_inquire_names_for_mech(
				mech->context,
				minor_status,
				mechanism,
				name_types);
	else
	    status = GSS_S_BAD_BINDINGS;

	return(status);
    }
    
    return(GSS_S_NO_CONTEXT);
}

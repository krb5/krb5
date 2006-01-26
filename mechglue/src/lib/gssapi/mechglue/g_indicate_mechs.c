/* #ident  "@(#)gss_indicate_mechs.c 1.13     95/08/04 SMI" */

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
 *  glue routine for gss_indicate_mechs
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

extern gss_mechanism *__gss_mechs_array;

static gss_OID_set_desc	supported_mechs_desc; 
static gss_OID_set supported_mechs = NULL;

OM_uint32 KRB5_CALLCONV
gss_indicate_mechs (minor_status,
                    mech_set)

OM_uint32 *		minor_status;
gss_OID_set *		mech_set;

{
    int i;
    
    gss_initialize();

    if (minor_status)
	*minor_status = 0;

    /*
     * If we have already computed the mechanisms supported, return
     * a pointer to it. Otherwise, compute them and return the pointer.
     */
    
    if(supported_mechs == NULL) {

	supported_mechs = &supported_mechs_desc;
	supported_mechs->count = 0;

	/* Build the mech_set from the OIDs in mechs_array. */

	for(i=0; __gss_mechs_array[i]->mech_type.length != 0; i++) 
	    supported_mechs->count++;

	supported_mechs->elements =
	    (void *) malloc(supported_mechs->count *
			    sizeof(gss_OID_desc));

	for(i=0; i < supported_mechs->count; i++) {
	    supported_mechs->elements[i].length =
		__gss_mechs_array[i]->mech_type.length;
	    supported_mechs->elements[i].elements = (void *)
		malloc(__gss_mechs_array[i]->mech_type.length);
	    memcpy(supported_mechs->elements[i].elements,
		   __gss_mechs_array[i]->mech_type.elements,
		   __gss_mechs_array[i]->mech_type.length);
	}
    }
    
    if(mech_set != NULL)
	*mech_set = supported_mechs;
    
    return(GSS_S_COMPLETE);
}

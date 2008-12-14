/* #pragma ident	"@(#)g_imp_name.c	1.26	04/02/23 SMI" */

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
 *  glue routine gss_import_name_object
 *
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

static OM_uint32
val_imp_name_object_args(
    OM_uint32 *minor_status,
    void *input_name,
    gss_OID input_name_type,
    gss_name_t *output_name)
{
    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (output_name == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (input_name_type == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAMETYPE;

    if (input_name == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;

    return GSS_S_COMPLETE;    
}

OM_uint32 KRB5_CALLCONV
gss_import_name_object(minor_status,
		       input_name,
		       input_name_type,
		       output_name)
OM_uint32 *		minor_status;
void *			input_name;
gss_OID			input_name_type;
gss_name_t *		output_name;
{
    gss_union_name_t	    union_name = NULL;
    gss_mechanism	    mech = NULL;
    gss_name_t		    internal_name = GSS_C_NO_NAME;
    OM_uint32		    tmp, major_status = GSS_S_FAILURE;
    gss_OID_set		    mechlist = GSS_C_NO_OID_SET;
    int			    i;

    major_status = val_imp_name_object_args(minor_status,
					    input_name,
					    input_name_type,
					    output_name);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    major_status = gss_indicate_mechs(minor_status, &mechlist);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    major_status = GSS_S_BAD_NAMETYPE;

    for (i = 0; i < mechlist->count; i++) {
	mech = gssint_get_mechanism(&mechlist->elements[i]);
	if (mech == NULL || mech->gss_import_name_object == NULL)
	    continue;

	major_status = mech->gss_import_name_object(minor_status,
						    input_name,
						    input_name_type,
						    &internal_name);
	if (major_status != GSS_S_BAD_NAMETYPE)
	    break;
    }

    if (major_status == GSS_S_COMPLETE) {
	assert(internal_name != GSS_C_NO_NAME);

	major_status = gssint_convert_name_to_union_name(minor_status,
							 mech,
							 internal_name,
							 &union_name);
	if (major_status != GSS_S_COMPLETE) {
	    if (mech->gss_release_name != NULL)
		mech->gss_release_name(&tmp, &internal_name);
	} else
	    *output_name = (gss_name_t)union_name;
   } else
	map_error(minor_status, mech);

    generic_gss_release_oid_set(&tmp, &mechlist);

    return major_status;
}


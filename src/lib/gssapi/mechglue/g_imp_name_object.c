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
    gss_union_name_t	    union_name;
    OM_uint32		    tmp, major_status = GSS_S_FAILURE;

    major_status = val_imp_name_object_args(minor_status,
					    input_name,
					    input_name_type,
					    output_name);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    union_name = (gss_union_name_t)malloc(sizeof(*union_name));
    if (union_name == NULL)
	return GSS_S_FAILURE;

    union_name->loopback = NULL;
    union_name->mech_type = 0;
    union_name->mech_name = 0;
    union_name->name_type = 0;
    union_name->external_name = 0;

    major_status = generic_gss_copy_oid(minor_status,
					input_name_type,
					&union_name->name_type);
    if (major_status != GSS_S_COMPLETE) {
	map_errcode(minor_status);
	goto allocation_failure;
    }

    union_name->loopback = union_name;
    *output_name = (gss_name_t)union_name;

    return GSS_S_COMPLETE;

allocation_failure:
    if (union_name) {
	if (union_name->external_name) {
	    if (union_name->external_name->value)
		free(union_name->external_name->value);
	    free(union_name->external_name);
	}
	if (union_name->name_type)
	    generic_gss_release_oid(&tmp, &union_name->name_type);
	if (union_name->mech_name)
	    gssint_release_internal_name(minor_status, union_name->mech_type,
					&union_name->mech_name);
	if (union_name->mech_type)
	    generic_gss_release_oid(&tmp, &union_name->mech_type);
	free(union_name);
    }
    return major_status;
}

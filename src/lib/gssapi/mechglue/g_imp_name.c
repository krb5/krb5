/* #ident  "@(#)g_imp_name.c 1.2     96/02/06 SMI" */

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
 *  glue routine gss_import_name
 *
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

OM_uint32 KRB5_CALLCONV
gss_import_name(minor_status,
                input_name_buffer,
                input_name_type,
                output_name)

OM_uint32 *		minor_status;
gss_buffer_t		input_name_buffer;
gss_OID			input_name_type;
gss_name_t *		output_name;

{
    gss_union_name_t	union_name;
    OM_uint32		tmp, major_status = GSS_S_FAILURE;
    gss_OID		mech;

    gss_initialize();

    if (minor_status)
	*minor_status = 0;

    /* if output_name is NULL, simply return */

    if(output_name == NULL)
	return (GSS_S_COMPLETE);

    *output_name = 0;

    if (input_name_buffer == GSS_C_NO_BUFFER)
	return (GSS_S_BAD_NAME);

    /*
     * First create the union name struct that will hold the external
     * name and the name type.
     */

    union_name = (gss_union_name_t) malloc (sizeof(gss_union_name_desc));
    if (!union_name) {
	    *minor_status = ENOMEM;
	    goto allocation_failure;
    }
    union_name->mech_type = 0;
    union_name->mech_name = 0;
    union_name->name_type = 0;
    union_name->external_name = 0;

    /*
     * All we do here is record the external name and name_type.
     * When the name is actually used, the underlying gss_import_name()
     * is called for the appropriate mechanism. Note that the name type
     * is assumed to be constant, so only a pointer to it is stored in
     * union_name
     */
    union_name->external_name =
	(gss_buffer_t) malloc(sizeof(gss_buffer_desc));
    if (!union_name->external_name) {
	    *minor_status = ENOMEM;
	    goto allocation_failure;
    }
    
    union_name->external_name->length = input_name_buffer->length;
    /* we malloc length+1 to stick a NULL on the end, just in case */
    /* Note that this NULL is not included in ->length for a reason! */
    union_name->external_name->value =
	(void  *) malloc(input_name_buffer->length+1);
    if (!union_name->external_name->value) {
	*minor_status = ENOMEM;
	goto allocation_failure;
    }
	
    memcpy(union_name->external_name->value, input_name_buffer->value,
	   input_name_buffer->length);

    /* add NULL to end of external_name->value, just in case... */
    ((char *)union_name->external_name->value)
				[input_name_buffer->length] = '\0';

    major_status = generic_gss_copy_oid(minor_status, input_name_type,
					&union_name->name_type);
    if (major_status != GSS_S_COMPLETE)
	goto allocation_failure;

    /*
     * See if this is a mechanism-specific name.  If so, let's import
     * it now so we can get any error messages, and to avoid trouble
     * later...
     */
    mech = gss_find_mechanism_from_name_type(input_name_type);
    if (mech) {
	major_status = generic_gss_copy_oid(minor_status, mech,
					    &union_name->mech_type);
	if (major_status != GSS_S_COMPLETE)
	    goto allocation_failure;

	major_status = __gss_import_internal_name(minor_status, mech, 
						  union_name,
						  &union_name->mech_name);
	if (major_status)
	    goto allocation_failure;
    }

    *output_name = (gss_name_t) union_name;

    return(GSS_S_COMPLETE);

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
	    __gss_release_internal_name(minor_status, union_name->mech_type,
					&union_name->mech_name);
	if (union_name->mech_type)
	    generic_gss_release_oid(&tmp, &union_name->mech_type);
	free(union_name);
    }
    return (major_status);
}

/* #ident  "@(#)g_dsp_name.c 1.2     96/02/06 SMI" */

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
 *  glue routine for gss_display_name()
 *
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32 KRB5_CALLCONV
gss_display_name (minor_status,
                  input_name,
                  output_name_buffer,
                  output_name_type)

OM_uint32 *		minor_status;
gss_name_t		input_name;
gss_buffer_t		output_name_buffer;
gss_OID *		output_name_type;

{
    OM_uint32		major_status;
    gss_union_name_t	union_name;
    
    if (input_name == 0)
	return GSS_S_BAD_NAME;

    union_name = (gss_union_name_t) input_name;

    if (union_name->mech_type) {
	/*
	 * OK, we have a mechanism-specific name; let's use it!
	 */
	return (__gss_display_internal_name(minor_status,
					    union_name->mech_type,
					    union_name->mech_name,
					    output_name_buffer,
					    output_name_type));
    }
    
    /*
     * copy the value of the external_name component of the union
     * name into the output_name_buffer and point the output_name_type
     * to the name_type component of union_name
     */
    if (output_name_type != NULL) {
	major_status = generic_gss_copy_oid(minor_status,
					    union_name->name_type,
					    output_name_type);
	if (major_status)
	    return (major_status);
    }
    
    if (output_name_buffer != NULL) {
	output_name_buffer->length = union_name->external_name->length;

	output_name_buffer->value =
	    (void *) malloc(output_name_buffer->length);

	memcpy(output_name_buffer->value,
	       union_name->external_name->value,
	       output_name_buffer->length);
    }
    
    if (minor_status)
	*minor_status = 0;

    return(GSS_S_COMPLETE);
}

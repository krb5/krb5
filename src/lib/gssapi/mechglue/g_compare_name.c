#ident  "@(#)gss_compare_name.c 1.13     95/08/02 SMI"

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
 *  glue routine for gss_compare_name
 *
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32
gss_compare_name (minor_status,
                  name1,
                  name2,
                  name_equal)

OM_uint32 *		minor_status;
gss_name_t		name1;
gss_name_t		name2;
int *			name_equal;

{
    OM_uint32		status;
    gss_union_name_t	union_name1, union_name2;
    
    gss_initialize();

    if (name1 == 0 || name2 == 0) {
	if (name_equal)
	    *name_equal = 0;
	return GSS_S_BAD_NAME;
    }

    /*
     * All we do here is make sure the two name_types are equal and then
     * that the external_names are equal. Note the we do not take care
     * of the case where two different external names map to the same
     * internal name. We cannot determine this, since we as yet do not
     * know what mechanism to use for calling the underlying
     * gss_import_name().
     */
    
    union_name1 = (gss_union_name_t) name1;
    union_name2 = (gss_union_name_t) name2;
    
    if(name_equal != NULL)
	*name_equal = 1;
    else
	return(GSS_S_COMPLETE);	
    
    status = GSS_S_COMPLETE;

    do {
	if((union_name1->name_type->length !=
	    union_name2->name_type->length)
	   ||
	   (memcmp(union_name1->name_type->elements,
		   union_name2->name_type->elements,
		   union_name1->name_type->length) != 0)) {
	    
	    *name_equal = 0;
	    break;
	}
    
	if((union_name1->external_name->length !=
	    union_name2->external_name->length)
	   ||
	   (memcmp(union_name1->external_name->value,
		   union_name2->external_name->value,
		   union_name1->external_name->length) != 0)) {
	    
	    *name_equal = 0;
	    break;
	}

    } while (0);
    
    return(status);
}

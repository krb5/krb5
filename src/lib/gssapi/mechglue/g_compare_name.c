#ident  "@(#)gss_compare_name.c 1.13     95/08/02 SMI"
/*
 *  glue routine for gss_compare_name
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

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

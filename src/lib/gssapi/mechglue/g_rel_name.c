#ident  "@(#)gss_release_name.c 1.2     95/05/09 SMI"
/*
 *  glue routine for gss_release_name
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32
gss_release_name (minor_status,
		  input_name)

OM_uint32 *		minor_status;
gss_name_t *		input_name;

{
    gss_union_name_t	union_name;
    
    /* if input_name is NULL, return error */
    
    if (input_name == 0)
	return(GSS_S_BAD_NAME);
    
    /*
     * free up the space for the external_name and then
     * free the union_name descriptor
     */
    
    union_name = (gss_union_name_t) *input_name;
    *input_name = 0;
    *minor_status = 0;
    
    if (union_name == NULL)
	return GSS_S_BAD_NAME;
    
    free(union_name->external_name->value);
    free(union_name->external_name);
    free(union_name);

    return(GSS_S_COMPLETE);
}

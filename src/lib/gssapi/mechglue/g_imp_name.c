#ident  "%Z%%M% %I%     %E% SMI"
/*
 *  glue routine gss_import_name
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mglueP.h"

OM_uint32
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

    if (minor_status)
	*minor_status = 0;

    /* if output_name is NULL, simply return */

    if(output_name == NULL)
	return (GSS_S_COMPLETE);

    if (input_name_buffer == GSS_C_NO_BUFFER)
	return (GSS_S_BAD_NAME);

    /*
     * First create the union name struct that will hold the internal
     * name and the mech_type. Then fill in the mech_type.
     */

    union_name = (gss_union_name_t) malloc (sizeof(gss_union_name_desc));

    /*
     * All we do here is record the external name and name_type.
     * When the name is actually used, the underlying gss_import_name()
     * is called for the appropriate mechanism. Note that the name type
     * is assumed to be constant, so only a pointer to it is stored in
     * union_name
     */

    union_name->external_name =
	(gss_buffer_t) malloc(sizeof(gss_buffer_desc));
    union_name->external_name->length = input_name_buffer->length;
    union_name->external_name->value =
	(void  *) malloc(input_name_buffer->length);
    memcpy(union_name->external_name->value, input_name_buffer->value,
	   input_name_buffer->length);

    union_name->name_type = (gss_OID) input_name_type;

    *output_name = (gss_name_t) union_name;

    return(GSS_S_COMPLETE);
}

/*
 * dsp_name.c --- display_name
 * 
 * $Source$
 * $Author$
 * $Header$
 * 
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#include <gssapi.h>

OM_uint32 gss_display_name(minor_status, input_name, output_name_buffer,
			   output_name_type)
	OM_uint32	*minor_status;
	gss_name_t	input_name;
	gss_buffer_t	output_name_buffer;
	gss_OID		*output_name_type;
{
	char		*str;
	
	if (*minor_status = krb5_unparse_name(input_name, &str))
		return(GSS_S_FAILURE);
	output_name_buffer->value = str;
	output_name_buffer->length = strlen(str);
	if (output_name_type)
		*output_name_type = &gss_OID_krb5;
		
	return(GSS_S_COMPLETE);
}

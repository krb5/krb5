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
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
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

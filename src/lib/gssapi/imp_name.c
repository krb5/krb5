/*
 * imp_name.c --- import_name
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

OM_uint32 gss_service_import_name();
	
OM_uint32 gss_import_name(minor_status, input_name_buffer, input_name_type,
			  output_name)
	OM_uint32	*minor_status;
	gss_buffer_t	input_name_buffer;
	gss_OID		input_name_type;
	gss_name_t	*output_name;
{
	*minor_status = 0;

	if ((input_name_type == GSS_C_NULL_OID) ||
	    gss_compare_OID(input_name_type, &gss_OID_krb5)) {
		/*
		 * Kerberos V5 name
		 */
		if (!strncasecmp("service:", input_name_buffer->value, 8) &&
		    input_name_buffer->length >= 8) {
			return(gss_service_import_name(minor_status,
						       input_name_buffer,
						       output_name));
		}
		if (*minor_status = krb5_parse_name(input_name_buffer->value,
						    output_name))
			return(GSS_S_FAILURE);
		else 
			return(GSS_S_COMPLETE);
	}
	/*
	 * It's of an unknown type.  We don't know how to deal.
	 */
	return(GSS_S_BAD_NAMETYPE);
}
	
			     
OM_uint32 gss_service_import_name(minor_status, input_name_buffer, output_name)
	OM_uint32	*minor_status;
	gss_buffer_t	input_name_buffer;
	gss_name_t	*output_name;
{
	char	*str, *cp;
	char	*service, *kservice;
	char	*host;
	char	buf[512];
	
	if (!(str = malloc(input_name_buffer->length+1))) {
		*minor_status = ENOMEM;
		return(GSS_S_FAILURE);
	}
	memcpy(str, input_name_buffer->value, input_name_buffer->length);
	str[input_name_buffer->length] = '\0';
	
	/*
	 * Assume the first eight characters are "service:"
	 */
	service = cp = str + 8;
	if (!(cp = strchr(cp, '@'))) {
		free(str);
		return(GSS_S_BAD_NAME);
	}
	*cp++ = 0;
	host = cp;
	/*
	 * We will need to do some mapping here later... XXX
	 */
	kservice = service;
	
	sprintf(buf, "%s/%s", kservice, host);
	
	if (*minor_status = krb5_parse_name(buf, output_name)) 
		return(GSS_S_FAILURE);
	else 
		return(GSS_S_COMPLETE);
}	


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
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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
	if (!(cp = index(cp, '@'))) {
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


/*
 * make_tok.c --- Make a GSS API token
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

OM_uint32 gss_make_token(minor_status, mechanism, type, length, data,
			 output_token)
	OM_uint32	*minor_status;
	unsigned int	mechanism;
	unsigned int	type;
	size_t		length;
	Voidptr		data;
	gss_buffer_t	output_token;
{
	char	*buf;
	int	offset = 4;

	*minor_status = 0;
	/*
	 * The Kerberos initial request token needs an extra byte of
	 * flag information, so we reserve it here.
	 */
	if ((mechanism == GSS_API_KRB5_TYPE) && (type == GSS_API_KRB5_REQ))
		offset++;
	if (!(buf = malloc(length+offset))) {
		*minor_status = ENOMEM;
		return(GSS_S_FAILURE);
	}
	output_token->value = (Voidptr) buf;
	output_token->length = length+4;
	buf[0] = GSS_API_IMPL_VERSION;
	buf[1] = mechanism;		/* Authentication mechanism */
	buf[2] = type;			/* Token type */
	buf[3] = 0;			/* Reserved */
	memcpy(buf+offset, data, length);
	return(GSS_S_COMPLETE);
}

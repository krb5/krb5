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

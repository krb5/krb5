/*
 * check_tok.c --- Read a GSS API token and do error checking
 * 		checking on it.
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

OM_uint32 gss_check_token(minor_status, input_token, mechanism, type)
	OM_uint32	*minor_status;
	gss_buffer_t	input_token;
	unsigned char	mechanism;
	unsigned char	type;
{
	char	*buf;
	
	*minor_status = 0;
	
	if (!input_token)
		return(gss_make_ce(GSS_CE_CALL_INACCESSIBLE_READ));

	if (input_token->length < 4)
		return(gss_make_re(GSS_RE_DEFECTIVE_TOKEN));

	buf = input_token->value;
	
	if (buf[0] != GSS_API_IMPL_VERSION)
		return(gss_make_re(GSS_RE_DEFECTIVE_TOKEN));
	
	if (mechanism && (mechanism != buf[1]))
		return(gss_make_re(GSS_RE_BAD_MECH));

	if (type && (type != buf[2]))
		return(gss_make_re(GSS_RE_FAILURE) | GSS_SS_UNSEQ_TOKEN);

	return(GSS_S_COMPLETE);
}

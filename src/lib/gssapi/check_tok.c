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

OM_uint32 gss_check_token(DECLARG(OM_uint32 *, minor_status),
			  DECLARG(gss_buffer_t, input_token),
			  DECLARG(unsigned int, mechanism),
			  DECLARG(unsigned int, type))
OLDDECLARG(OM_uint32 *, minor_status)
OLDDECLARG(gss_buffer_t, input_token)
OLDDECLARG(unsigned int, mechanism)
OLDDECLARG(unsigned int, type)
{
	char	*buf;
	
	*minor_status = 0;
	
	if (!input_token)
		return(GSS_S_CALL_INACCESSIBLE_READ);

	if (input_token->length < 4)
		return(GSS_S_DEFECTIVE_TOKEN);

	buf = input_token->value;
	
	if (buf[0] != GSS_API_IMPL_VERSION)
		return(GSS_S_DEFECTIVE_TOKEN);
	
	if (mechanism && (mechanism != buf[1]))
		return(GSS_S_BAD_MECH);

	if (type && (type != buf[2]))
		return(GSS_S_FAILURE | GSS_S_UNSEQ_TOKEN);

	return(GSS_S_COMPLETE);
}

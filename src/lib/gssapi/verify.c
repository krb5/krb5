/*
 * verify.c --- verify  message
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
#include <krb5/asn1.h>

OM_uint32 gss_verify(minor_status, context, message_buffer,  
		   token_buffer, qop_state)
	OM_uint32	*minor_status;
	gss_ctx_id_t	context;
	gss_buffer_t	message_buffer;
	gss_buffer_t	token_buffer;
	int		*qop_state;
{
	OM_uint32	retval;
	krb5_data	inbuf, outbuf, *scratch;
	krb5_safe	*message;
	int	safe_flags = 0;

	*minor_status = 0;

	if (retval = gss_check_token(minor_status, message_buffer,
				     GSS_API_KRB5_TYPE, GSS_API_KRB5_SIGN))
		return(retval);
	inbuf.length = token_buffer->length-4;
	inbuf.data = ( (char *) token_buffer->value)+4;
	if (*minor_status = decode_krb5_safe(&inbuf, &message))
		return(GSS_S_FAILURE);
	if (message->user_data.data)
		xfree(message->user_data.data);
	message->user_data.length = message_buffer->length;
	message->user_data.data = message_buffer->value;
	if (*minor_status = encode_krb5_safe(&message,  &scratch)) {
		message->user_data.data = NULL;
		krb5_free_safe(message);
		return(GSS_S_FAILURE);
	}
	message->user_data.data = NULL;
	krb5_free_safe(message);
	if (context->flags & GSS_C_SEQUENCE_FLAG)
		safe_flags = KRB5_SAFE_DOSEQUENCE|KRB5_SAFE_NOTIME;
	if (*minor_status = krb5_rd_safe(scratch,
					 context->session_key,
					 &context->his_address,
					 &context->my_address,
					 context->his_seq_num,
					 safe_flags,
					 0, /* no rcache */
					 &outbuf)) {
		krb5_free_data(scratch);
		return(GSS_S_FAILURE);
	}
	krb5_free_data(scratch);
	if (qop_state)
		*qop_state = 0;
	return(GSS_S_COMPLETE);
}

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
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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

/*
 * seal.c --- seal message
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

OM_uint32 gss_unseal(minor_status, context, input_message_buffer,
		     output_message_buffer, conf_state, qop_state)
	OM_uint32	*minor_status;
	gss_ctx_id_t	context;
	gss_buffer_t	input_message_buffer;
	gss_buffer_t	output_message_buffer;
	int		*conf_state;
	int		*qop_state;
{
	OM_uint32	retval;
	krb5_data	inbuf, outbuf;
	int		token_type;

	*minor_status = 0;

	if (retval = gss_check_token(minor_status, input_message_buffer,
				     GSS_API_KRB5_TYPE, 0))
		return(retval);
	token_type = ((char *) input_message_buffer->value)[2];
	if ((token_type != GSS_API_KRB5_SAFE) &&
	    (token_type != GSS_API_KRB5_PRIV))
		return(GSS_S_DEFECTIVE_TOKEN);
	inbuf.length = input_message_buffer->length-4;
	inbuf.data = ( (char *) input_message_buffer->value)+4;
	if (token_type == GSS_API_KRB5_PRIV) {
		int	priv_flags = 0;
		int		eblock_size;
		char		*i_vector;

		if (context->flags & GSS_C_SEQUENCE_FLAG)
			priv_flags = KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME;
		/*
		 * Initialize the initial vector.
		 */
		eblock_size =
			krb5_keytype_array[context->session_key->keytype]->
				system->block_length;
		if (!(i_vector=malloc(eblock_size))) {
			return(GSS_S_FAILURE);
		}
		memset(i_vector, 0, eblock_size);
		if (*minor_status = krb5_rd_priv(&inbuf, 
						 context->session_key,
						 &context->his_address,
						 &context->my_address,
						 context->his_seq_num,
						 priv_flags,
						 i_vector,
						 0, /* no rcache */
						 &outbuf))
			return(GSS_S_FAILURE);
		if (conf_state)
			*conf_state = 1;
	} else {
		int	safe_flags = 0;

		if (context->flags & GSS_C_SEQUENCE_FLAG)
			safe_flags = KRB5_SAFE_DOSEQUENCE|KRB5_SAFE_NOTIME;
		if (*minor_status = krb5_rd_safe(&inbuf,
						 context->session_key,
						 &context->his_address,
						 &context->my_address,
						 context->his_seq_num,
						 safe_flags,
						 0, /* no rcache */
						 &outbuf))
			return(GSS_S_FAILURE);
		if (conf_state)
			*conf_state = 0;
	}
	if (qop_state)
		*qop_state = 0;
	output_message_buffer->length = outbuf.length;
	output_message_buffer->value = outbuf.data;
	return(GSS_S_COMPLETE);
}
	
#ifdef notdef
OM_uint32 gss_verify(minor_status, context, message_buffer,  
		   token_buffer, qop_state)
	OM_uint32	*minor_status;
	gss_ctx_id_t	context;
	gss_buffer_t	message_buffer;
	gss_buffer_t	token_buffer;
	int		*qop_state;
{
	OM_uint32 retval, ret;
	gss_buffer_desc	buf;
	gss_buffer_t	output_message_buffer = &buf;
	
	
	if (retval = gss_unseal(minor_status, context, message_buffer,
		     output_message_buffer, NULL, qop_state))
		return(retval);
	if (token_buffer->length != output_message_buffer->length)
		ret = GSS_S_BAD_SIG;
	else if (!memcmp(token_buffer->value, output_message_buffer->value,
			 token_buffer->length))
		ret = GSS_S_BAD_SIG;
	if (retval = gss_release_buffer(minor_status, output_message_buffer))
		return(retval);
	return(ret);
}

#endif

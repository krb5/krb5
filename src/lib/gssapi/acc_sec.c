/*
 * acc_sec.c --- accept security context
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

extern krb5_flags    krb5_kdc_default_options;

/*
 * To do in the future:
 *
 * 	* Support replay cache
 *
 * 	* Support delegation of credentials
 *
 * 	* Do something with time_rec
 *
 * 	* Should handle Kerberos error packets being sent back and
 * 	forth.
 */

static krb5_error_code gss_krb5_keyproc(DECLARG(krb5_pointer, cred_handle),
					DECLARG(krb5_principal, principal),
					DECLARG(krb5_kvno, vno),
					DECLARG(krb5_keyblock **, key))
OLDDECLARG(krb5_pointer, cred_handle)
OLDDECLARG(krb5_principal, principal)
OLDDECLARG(krb5_kvno, vno)
OLDDECLARG(krb5_keyblock **, key)
{
	gss_cred_id_t	*creds;
	
	creds = (gss_cred_id_t *) cred_handle;
	
	if (krb5_principal_compare(creds->principal, principal)) {
		if (creds->cred_flags & GSS_KRB_HAS_SRVTAB) {
			*key = &creds->srvtab;
			return(0);
		} else
			return(KRB5_KT_NOTFOUND);
	} else
		return(KRB5_KT_NOTFOUND);
}


OM_uint32 gss_accept_sec_context(minor_status, context_handle,
				 verifier_cred_handle, input_token,
				 channel, src_name,
				 mech_type, output_token,
				 ret_flags, time_rec,
				 delegated_cred_handle)
	OM_uint32	*minor_status;
	gss_ctx_id_t	*context_handle;
	gss_cred_id_t	verifier_cred_handle;
	gss_buffer_t	input_token;
	gss_channel_bindings	channel;
	gss_name_t	*src_name;
	gss_OID		*mech_type;
	gss_buffer_t	output_token;
	int    		*ret_flags;
	OM_uint32	*time_rec;
	gss_cred_id_t	*delegated_cred_handle;
{
	krb5_rcache		rcache;
	krb5_address		sender_addr;
	krb5_data		inbuf, outbuf;
	krb5_principal		server;
	krb5_tkt_authent	*authdat;
	OM_uint32		retval;
	gss_ctx_id_t	context;
	
	*minor_status = 0;

	if (!context_handle) {
		/*
		 * This is first call to accept_sec_context
		 *
		 * Make sure the input token is sane.
		 */
		if (retval = gss_check_token(minor_status, input_token,
					     GSS_API_KRB5_TYPE,
					     GSS_API_KRB5_REQ))
			return(retval);
		inbuf.length = input_token->length-5;
		inbuf.data = ( (char *) input_token->value)+5;
		sender_addr.addrtype = channel->initiator_addrtype;
		sender_addr.length = channel->initiator_address.length;
		sender_addr.contents = (krb5_octet *)
			channel->initiator_address.value;
		server = verifier_cred_handle.principal;
		/*
		 * Setup the replay cache.
		 */
		if (*minor_status = krb5_get_server_rcache(server[1]->data,
							   &rcache))
			return(GSS_S_FAILURE);
		/*
		 * Now let's rip apart the packet
		 */
		if (*minor_status = krb5_rd_req(&inbuf, server, &sender_addr,
						0, gss_krb5_keyproc,
						&verifier_cred_handle,
						rcache, &authdat))
			return(GSS_S_FAILURE);
		if (*minor_status = krb5_rc_close(rcache))
			return(GSS_S_FAILURE);
		
		/*
		 * Allocate the context handle structure
		 */
		if (!(context = (gss_ctx_id_t)
		      malloc(sizeof(struct gss_ctx_id_desc)))) {
			*minor_status = ENOMEM;
			return(GSS_S_FAILURE);
		}
		context->mech_type = &gss_OID_krb5;
		context->flags = 0;
		context->state =  GSS_KRB_STATE_DOWN;
		context->am_client = 0;
		context->rcache = NULL;
		
		context->my_address.addrtype = channel->initiator_addrtype;
		context->my_address.length = channel->initiator_address.length;
		if (!(context->my_address.contents = (krb5_octet *)
		      malloc(context->my_address.length))) {
			xfree(context);
			return(GSS_S_FAILURE);
		}
		memcpy((char *) context->my_address.contents,
		       (char *) channel->initiator_address.value,
		       context->my_address.length);
		context->his_address.addrtype = channel->acceptor_addrtype;
		context->his_address.length = channel->acceptor_address.length;
		if (!(context->his_address.contents = (krb5_octet *)
		      malloc(context->my_address.length))) {
			xfree(context->my_address.contents);
			xfree(context);
			return(GSS_S_FAILURE);
		}
		memcpy((char *) context->his_address.contents,
		       (char *) channel->acceptor_address.value,
		       context->his_address.length);
		
		/*
		 * Do mutual authentication if requested.
		 */
		output_token->length = 0;
		if ((authdat->ap_options & AP_OPTS_MUTUAL_REQUIRED)) {
			krb5_ap_rep_enc_part	repl;
			/*
			 * Generate a random sequence number
			 */
			if (*minor_status =
			    krb5_generate_seq_number(authdat->ticket->enc_part2->session,
						     &context->my_seq_num)) {
				xfree(context->his_address.contents);
				xfree(context->my_address.contents);
				xfree(context);
				krb5_free_tkt_authent(authdat);
				return(GSS_S_FAILURE);
			}

			repl.ctime = authdat->authenticator->ctime;
			repl.cusec = authdat->authenticator->cusec;
			repl.subkey = authdat->authenticator->subkey;
			repl.seq_number = context->my_seq_num;

			if (*minor_status =
			    krb5_mk_rep(&repl,
					authdat->ticket->enc_part2->session,
					&outbuf)) {
				xfree(context->his_address.contents);
				xfree(context->my_address.contents);
				xfree(context);
				krb5_free_tkt_authent(authdat);
				return(GSS_S_FAILURE);
			}
			if (*minor_status = gss_make_token(minor_status,
							   GSS_API_KRB5_TYPE,
							   GSS_API_KRB5_REQ,
							   outbuf.length,
							   outbuf.data,
							   output_token)) {
				xfree(context->his_address.contents);
				xfree(context->my_address.contents);
				xfree(context);
				xfree(outbuf.data);
				krb5_free_tkt_authent(authdat);
				return(GSS_S_FAILURE);
			}
		}
			
		/*
		 * Fill in context handle structure
		 */
		if (*minor_status =
		    krb5_copy_principal(verifier_cred_handle.principal,
					&context->me)) {
			xfree(context->his_address.contents);
			xfree(context->my_address.contents);
			xfree(context);
			return(GSS_S_FAILURE);
		}
		if (*minor_status =
		    krb5_copy_principal(authdat->authenticator->client,
					&context->him)) {
			krb5_free_principal(context->me);
			xfree(context->his_address.contents);
			xfree(context->my_address.contents);
			xfree(context);
			return(GSS_S_FAILURE);
		}
		if (*minor_status =
		    krb5_copy_keyblock(authdat->ticket->enc_part2->session,
				       &context->session_key)) {
			krb5_free_principal(context->me);
			krb5_free_principal(context->him);
			xfree(context->his_address.contents);
			xfree(context->my_address.contents);
			xfree(context);
			return(GSS_S_FAILURE);
		}
		context->his_seq_num = authdat->authenticator->seq_number;
		context->cusec = authdat->authenticator->cusec;
		context->ctime = authdat->authenticator->ctime;
		context->flags = ((char *) input_token->value)[4];
		/*
		 * Strip out flags we don't support (yet) XXX
		 */
		context->flags  &= ~(GSS_C_DELEG_FLAG | GSS_C_REPLAY_FLAG);
		/*
		 * Deliver output parameters
		 */
		if (src_name) {
			if (*minor_status = krb5_copy_principal(context->him,
								src_name)) {
				xfree(context->session_key->contents);
				krb5_free_principal(context->me);
				krb5_free_principal(context->him);
				xfree(context->his_address.contents);
				xfree(context->my_address.contents);
				xfree(context);
				return(GSS_S_FAILURE);
			}
		}
		if (mech_type)
			*mech_type = &gss_OID_krb5;
		*ret_flags = context->flags;
		if (time_rec)
			*time_rec = GSS_TIME_REC_INDEFINITE;
		return(GSS_S_COMPLETE);
	} else {
		/*
		 * Context is non-null, this is the second time through....
		 */
		return(GSS_S_FAILURE);
	}
}


/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id$
 */

#include "gssapiP_krb5.h"

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_accept_sec_context(minor_status, context_handle, verifier_cred_handle,
		       input_token, input_chan_bindings, src_name, mech_type, 
		       output_token, ret_flags, time_rec, delegated_cred_handle)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t FAR *context_handle;
     gss_cred_id_t verifier_cred_handle;
     gss_buffer_t input_token;
     gss_channel_bindings_t input_chan_bindings;
     gss_name_t FAR *src_name;
     gss_OID FAR *mech_type;
     gss_buffer_t output_token;
     OM_uint32 FAR *ret_flags;
     OM_uint32 FAR *time_rec;
     gss_cred_id_t FAR *delegated_cred_handle;
{
   return(krb5_gss_accept_sec_context(minor_status,
				      context_handle,
				      verifier_cred_handle,
				      input_token,
				      input_chan_bindings,
				      src_name,
				      mech_type,
				      output_token,
				      ret_flags,
				      time_rec,
				      delegated_cred_handle));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_acquire_cred(minor_status, desired_name, time_req, desired_mechs,
		 cred_usage, output_cred_handle, actual_mechs, time_rec)
     OM_uint32 FAR *minor_status;
     gss_name_t desired_name;
     OM_uint32 time_req;
     gss_OID_set desired_mechs;
     gss_cred_usage_t cred_usage;
     gss_cred_id_t FAR *output_cred_handle;
     gss_OID_set FAR *actual_mechs;
     OM_uint32 FAR *time_rec;
{
   return(krb5_gss_acquire_cred(minor_status,
				desired_name,
				time_req,
				desired_mechs,
				cred_usage,
				output_cred_handle,
				actual_mechs,
				time_rec));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_add_cred(minor_status, input_cred_handle, desired_name, desired_mech,
	     cred_usage, initiator_time_req, acceptor_time_req,
	     output_cred_handle, actual_mechs, initiator_time_rec,
	     acceptor_time_rec)
    OM_uint32		FAR *minor_status;
    gss_cred_id_t	input_cred_handle;
    gss_name_t		desired_name;
    gss_OID		desired_mech;
    gss_cred_usage_t	cred_usage;
    OM_uint32		initiator_time_req;
    OM_uint32		acceptor_time_req;
    gss_cred_id_t	FAR *output_cred_handle;
    gss_OID_set		FAR *actual_mechs;
    OM_uint32		FAR *initiator_time_rec;
    OM_uint32		FAR *acceptor_time_rec;
{
    return(krb5_gss_add_cred(minor_status, input_cred_handle, desired_name,
			     desired_mech, cred_usage, initiator_time_req,
			     acceptor_time_req, output_cred_handle,
			     actual_mechs, initiator_time_rec,
			     acceptor_time_rec));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_add_oid_set_member(minor_status, member_oid, oid_set)
    OM_uint32	FAR *minor_status;
    gss_OID	member_oid;
    gss_OID_set	FAR *oid_set;
{
    return(generic_gss_add_oid_set_member(minor_status, member_oid, oid_set));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_compare_name(minor_status, name1, name2, name_equal)
     OM_uint32 FAR *minor_status;
     gss_name_t name1;
     gss_name_t name2;
     int FAR *name_equal;
{
   return(krb5_gss_compare_name(minor_status, name1,
				name2, name_equal));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_context_time(minor_status, context_handle, time_rec)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     OM_uint32 FAR *time_rec;
{
   return(krb5_gss_context_time(minor_status, context_handle,
				time_rec));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_create_empty_oid_set(minor_status, oid_set)
    OM_uint32	FAR *minor_status;
    gss_OID_set	FAR *oid_set;
{
    return(generic_gss_create_empty_oid_set(minor_status, oid_set));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_delete_sec_context(minor_status, context_handle, output_token)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t FAR *context_handle;
     gss_buffer_t output_token;
{
   return(krb5_gss_delete_sec_context(minor_status,
				      context_handle, output_token));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_display_name(minor_status, input_name, output_name_buffer, output_name_type)
     OM_uint32 FAR *minor_status;
     gss_name_t input_name;
     gss_buffer_t output_name_buffer;
     gss_OID FAR *output_name_type;
{
   return(krb5_gss_display_name(minor_status, input_name,
				output_name_buffer, output_name_type));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_display_status(minor_status, status_value, status_type,
		   mech_type, message_context, status_string)
     OM_uint32 FAR *minor_status;
     OM_uint32 status_value;
     int status_type;
     gss_OID mech_type;
     OM_uint32 FAR *message_context;
     gss_buffer_t status_string;
{
   return(krb5_gss_display_status(minor_status, status_value,
				  status_type, mech_type, message_context,
				  status_string));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_export_sec_context(minor_status, context_handle, interprocess_token)
     OM_uint32		FAR *minor_status;
     gss_ctx_id_t	FAR *context_handle;
     gss_buffer_t	interprocess_token;
{
   return(krb5_gss_export_sec_context(minor_status,
				      context_handle,
				      interprocess_token));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_get_mic(minor_status, context_handle, qop_req,
	    message_buffer, message_token)
     OM_uint32		FAR *minor_status;
     gss_ctx_id_t	context_handle;
     gss_qop_t		qop_req;
     gss_buffer_t	message_buffer;
     gss_buffer_t	message_token;
{
    return(krb5_gss_get_mic(minor_status, context_handle,
			    qop_req, message_buffer, message_token));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_import_name(minor_status, input_name_buffer, input_name_type, output_name)
     OM_uint32 FAR *minor_status;
     gss_buffer_t input_name_buffer;
     gss_OID input_name_type;
     gss_name_t FAR *output_name;
{
   return(krb5_gss_import_name(minor_status, input_name_buffer,
			       input_name_type, output_name));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_import_sec_context(minor_status, interprocess_token, context_handle)
     OM_uint32		FAR *minor_status;
     gss_buffer_t	interprocess_token;
     gss_ctx_id_t	FAR *context_handle;
{
   return(krb5_gss_import_sec_context(minor_status,
				      interprocess_token,
				      context_handle));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_indicate_mechs(minor_status, mech_set)
     OM_uint32 FAR *minor_status;
     gss_OID_set FAR *mech_set;
{
   return(krb5_gss_indicate_mechs(minor_status, mech_set));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_init_sec_context(minor_status, claimant_cred_handle, context_handle,
		     target_name, mech_type, req_flags, time_req,
		     input_chan_bindings, input_token, actual_mech_type,
		     output_token, ret_flags, time_rec)
     OM_uint32 FAR *minor_status;
     gss_cred_id_t claimant_cred_handle;
     gss_ctx_id_t FAR *context_handle;
     gss_name_t target_name;
     gss_OID mech_type;
     OM_uint32 req_flags;
     OM_uint32 time_req;
     gss_channel_bindings_t input_chan_bindings;
     gss_buffer_t input_token;
     gss_OID FAR *actual_mech_type;
     gss_buffer_t output_token;
     OM_uint32 FAR *ret_flags;
     OM_uint32 FAR *time_rec;
{
   return(krb5_gss_init_sec_context(minor_status,
				    claimant_cred_handle, context_handle,
				    target_name, mech_type, req_flags,
				    time_req, input_chan_bindings, input_token,
				    actual_mech_type, output_token, ret_flags,
				    time_rec));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_inquire_context(minor_status, context_handle, initiator_name, acceptor_name,
		    lifetime_rec, mech_type, ret_flags,
		    locally_initiated, open)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     gss_name_t FAR *initiator_name;
     gss_name_t FAR *acceptor_name;
     OM_uint32 FAR *lifetime_rec;
     gss_OID FAR *mech_type;
     OM_uint32 FAR *ret_flags;
     int FAR *locally_initiated;
     int FAR *open;
{
   return(krb5_gss_inquire_context(minor_status, context_handle,
				   initiator_name, acceptor_name, lifetime_rec,
				   mech_type, ret_flags, locally_initiated,
				   open));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_inquire_cred(minor_status, cred_handle, name, lifetime_ret,
		 cred_usage, mechanisms)
     OM_uint32 FAR *minor_status;
     gss_cred_id_t cred_handle;
     gss_name_t FAR *name;
     OM_uint32 FAR *lifetime_ret;
     gss_cred_usage_t FAR *cred_usage;
     gss_OID_set FAR *mechanisms;
{
   return(krb5_gss_inquire_cred(minor_status, cred_handle,
				name, lifetime_ret, cred_usage, mechanisms));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_inquire_cred_by_mech(minor_status, cred_handle, mech_type, name,
			 initiator_lifetime, acceptor_lifetime, cred_usage)
     OM_uint32		FAR *minor_status;
     gss_cred_id_t	cred_handle;
     gss_OID		mech_type;
     gss_name_t		FAR *name;
     OM_uint32		FAR *initiator_lifetime;
     OM_uint32		FAR *acceptor_lifetime;
     gss_cred_usage_t	FAR *cred_usage;
{
   return(krb5_gss_inquire_cred_by_mech(minor_status, cred_handle,
					mech_type, name, initiator_lifetime,
					acceptor_lifetime, cred_usage));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_inquire_names_for_mech(minor_status, mechanism, name_types)
    OM_uint32	FAR *minor_status;
    gss_OID	mechanism;
    gss_OID_set	FAR *name_types;
{
    return(krb5_gss_inquire_names_for_mech(minor_status,
					   mechanism,
					   name_types));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_oid_to_str(minor_status, oid, oid_str)
    OM_uint32		FAR *minor_status;
    gss_OID		oid;
    gss_buffer_t	oid_str;
{
    return(generic_gss_oid_to_str(minor_status, oid, oid_str));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_process_context_token(minor_status, context_handle, token_buffer)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t token_buffer;
{
   return(krb5_gss_process_context_token(minor_status,
					 context_handle, token_buffer));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_release_cred(minor_status, cred_handle)
     OM_uint32 FAR *minor_status;
     gss_cred_id_t FAR *cred_handle;
{
   return(krb5_gss_release_cred(minor_status, cred_handle));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_release_name(minor_status, input_name)
     OM_uint32 FAR *minor_status;
     gss_name_t FAR *input_name;
{
   return(krb5_gss_release_name(minor_status, input_name));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_release_buffer(minor_status, buffer)
     OM_uint32 FAR *minor_status;
     gss_buffer_t buffer;
{
   return(generic_gss_release_buffer(minor_status,
				     buffer));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_release_oid(minor_status, oid)
     OM_uint32	FAR *minor_status;
     gss_OID	FAR *oid;
{
    return(krb5_gss_release_oid(minor_status, oid));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_release_oid_set(minor_status, set)
     OM_uint32 FAR * minor_status;
     gss_OID_set FAR *set;
{
   return(generic_gss_release_oid_set(minor_status, set));
}

/* V1 only */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_seal(minor_status, context_handle, conf_req_flag, qop_req,
	 input_message_buffer, conf_state, output_message_buffer)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     int conf_req_flag;
     int qop_req;
     gss_buffer_t input_message_buffer;
     int FAR *conf_state;
     gss_buffer_t output_message_buffer;
{
   return(krb5_gss_seal(minor_status, context_handle,
			conf_req_flag, qop_req, input_message_buffer,
			conf_state, output_message_buffer));
}

KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_sign(minor_status, context_handle,
	      qop_req, message_buffer, 
	      message_token)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     int qop_req;
     gss_buffer_t message_buffer;
     gss_buffer_t message_token;
{
   return(krb5_gss_sign(minor_status, context_handle,
			qop_req, message_buffer, message_token));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_verify_mic(minor_status, context_handle,
	       message_buffer, token_buffer, qop_state)
     OM_uint32		FAR *minor_status;
     gss_ctx_id_t	context_handle;
     gss_buffer_t	message_buffer;
     gss_buffer_t	token_buffer;
     gss_qop_t		FAR *qop_state;
{
    return(krb5_gss_verify_mic(minor_status, context_handle,
			       message_buffer, token_buffer, qop_state));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_wrap(minor_status, context_handle, conf_req_flag, qop_req,
	 input_message_buffer, conf_state, output_message_buffer)
    OM_uint32		FAR *minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    gss_buffer_t	input_message_buffer;
    int			FAR *conf_state;
    gss_buffer_t	output_message_buffer;
{
    return(krb5_gss_wrap(minor_status, context_handle, conf_req_flag, qop_req,
			 input_message_buffer, conf_state,
			 output_message_buffer));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_str_to_oid(minor_status, oid_str, oid)
    OM_uint32		FAR *minor_status;
    gss_buffer_t	oid_str;
    gss_OID		FAR *oid;
{
    return(generic_gss_str_to_oid(minor_status, oid_str, oid));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_test_oid_set_member(minor_status, member, set, present)
    OM_uint32	FAR *minor_status;
    gss_OID	member;
    gss_OID_set	set;
    int		FAR *present;
{
    return(generic_gss_test_oid_set_member(minor_status, member, set,
					   present));
}

/* V1 only */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_unseal(minor_status, context_handle, input_message_buffer,
	   output_message_buffer, conf_state, qop_state)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t input_message_buffer;
     gss_buffer_t output_message_buffer;
     int FAR *conf_state;
     int FAR *qop_state;
{
   return(krb5_gss_unseal(minor_status, context_handle,
			  input_message_buffer, output_message_buffer,
			  conf_state, qop_state));
}

/* V2 */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_unwrap(minor_status, context_handle, input_message_buffer, 
	   output_message_buffer, conf_state, qop_state)
    OM_uint32		FAR *minor_status;
    gss_ctx_id_t	context_handle;
    gss_buffer_t	input_message_buffer;
    gss_buffer_t	output_message_buffer;
    int			FAR *conf_state;
    gss_qop_t		FAR *qop_state;
{
    return(krb5_gss_unwrap(minor_status, context_handle, input_message_buffer,
			   output_message_buffer, conf_state, qop_state));
}

/* V1 only */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_verify(minor_status, context_handle, message_buffer,
	   token_buffer, qop_state)
     OM_uint32 FAR *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t message_buffer;
     gss_buffer_t token_buffer;
     int FAR *qop_state;
{
   return(krb5_gss_verify(minor_status,
			  context_handle,
			  message_buffer,
			  token_buffer,
			  qop_state));
}

/* V2 interface */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_wrap_size_limit(minor_status, context_handle, conf_req_flag,
		    qop_req, req_output_size, max_input_size)
    OM_uint32		FAR *minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    OM_uint32		req_output_size;
    OM_uint32		FAR *max_input_size;
{
   return(krb5_gss_wrap_size_limit(minor_status, context_handle,
				   conf_req_flag, qop_req,
				   req_output_size, max_input_size));
}

/* V2 interface */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_canonicalize_name(minor_status, input_name, mech_type, output_name)
	OM_uint32  *minor_status;
	const gss_name_t input_name;
	const gss_OID mech_type;
	gss_name_t *output_name;
{
	return krb5_gss_canonicalize_name(minor_status, input_name,
					  mech_type, output_name);
}


/* V2 interface */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_export_name(minor_status, input_name, exported_name)
	OM_uint32  *minor_status;
	const gss_name_t input_name;
	gss_buffer_t exported_name;
{
	return krb5_gss_export_name(minor_status, input_name, exported_name);
}

/* V2 interface */
KRB5_DLLIMP OM_uint32 KRB5_CALLCONV
gss_duplicate_name(minor_status, input_name, dest_name)
	OM_uint32  *minor_status;
	const gss_name_t input_name;
	gss_name_t *dest_name;
{
	return krb5_gss_duplicate_name(minor_status, input_name, dest_name);
}




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

#include "gssapiP_krb5.h"
#include <memory.h>
#include <stdlib.h>

/*
 * $Id$
 */

/* XXX This is for debugging only!!!  Should become a real bitfield
   at some point */
int krb5_gss_dbg_client_expcreds = 0;

static krb5_error_code
make_ap_req(context, auth_context, cred, server, now, endtime, chan_bindings, 
	    req_flags, krb_flags, mech_type, token)
    krb5_context context;
    krb5_auth_context * auth_context;
    krb5_gss_cred_id_t cred;
    krb5_principal server;
    krb5_timestamp now;
    krb5_timestamp *endtime;
    gss_channel_bindings_t chan_bindings;
    OM_uint32 *req_flags;
    krb5_flags *krb_flags;
    gss_OID mech_type;
    gss_buffer_t token;
{
    krb5_flags mk_req_flags = 0;
    krb5_error_code code;
    krb5_data checksum_data;
    krb5_checksum md5;
    krb5_creds in_creds, * out_creds = 0;
    krb5_data ap_req;
    unsigned char *ptr;
    krb5_data credmsg;
    unsigned char *t;
    int tlen;
    krb5_int32 con_flags;

    ap_req.data = 0;
    checksum_data.data = 0;
    credmsg.data = 0;

    /* build the checksum buffer */
 
    /* compute the hash of the channel bindings */

    if ((code = kg_checksum_channel_bindings(context, chan_bindings, &md5, 0)))
        return(code);

    /* get an auth_context structure and fill in checksum type */

    if ((code = krb5_auth_con_init(context, auth_context)))
	return(code);

    krb5_auth_con_set_req_cksumtype(context, *auth_context, CKSUMTYPE_KG_CB);

    /* build the checksum field */

    if (*req_flags & GSS_C_DELEG_FLAG) {
	/* first get KRB_CRED message, so we know its length */

	/* clear the time check flag that was set in krb5_auth_con_init() */
	krb5_auth_con_getflags(context, *auth_context, &con_flags);
	krb5_auth_con_setflags(context, *auth_context,
			       con_flags & ~KRB5_AUTH_CONTEXT_DO_TIME);

	code = krb5_fwd_tgt_creds(context, *auth_context, 0,
				  cred->princ, server, cred->ccache, 1,
				  &credmsg);

	/* turn KRB5_AUTH_CONTEXT_DO_TIME back on */
	krb5_auth_con_setflags(context, *auth_context, con_flags);

	if (code) {
	    /* don't fail here; just don't accept/do the delegation
               request */
	    *req_flags &= ~GSS_C_DELEG_FLAG;

	    checksum_data.length = 24;
	} else {
	    if (credmsg.length+28 > KRB5_INT16_MAX) {
		krb5_free_data_contents(context, &credmsg);
		return(KRB5KRB_ERR_FIELD_TOOLONG);
	    }

	    checksum_data.length = 28+credmsg.length;
	}
    } else {
	checksum_data.length = 24;
    }

    /* now allocate a buffer to hold the checksum data and
       (maybe) KRB_CRED msg */

    if ((checksum_data.data =
	 (char *) xmalloc(checksum_data.length)) == NULL) {
	if (credmsg.data)
	    krb5_free_data_contents(context, &credmsg);
	return(ENOMEM);
    }

    ptr = checksum_data.data;

    TWRITE_INT(ptr, md5.length, 0);
    TWRITE_STR(ptr, (unsigned char *) md5.contents, md5.length);
    TWRITE_INT(ptr, *req_flags, 0);

    /* done with this, free it */
    xfree(md5.contents);

    if (credmsg.data) {
	TWRITE_INT16(ptr, KRB5_GSS_FOR_CREDS_OPTION, 0);
	TWRITE_INT16(ptr, credmsg.length, 0);
	TWRITE_STR(ptr, (unsigned char *) credmsg.data, credmsg.length);

	/* free credmsg data */
	krb5_free_data_contents(context, &credmsg);
    }

    /* fill in the necessary fields in creds */
    memset((char *) &in_creds, 0, sizeof(krb5_creds));
    if ((code = krb5_copy_principal(context, cred->princ, &in_creds.client)))
	goto cleanup;
    if ((code = krb5_copy_principal(context, server, &in_creds.server)))
	goto cleanup;
    in_creds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    in_creds.times.endtime = *endtime;
    
    /*
     * Get the credential..., I don't know in 0 is a good value for the
     * kdcoptions
     */
    if ((code = krb5_get_credentials(context, 0, cred->ccache, 
				     &in_creds, &out_creds)))
	goto cleanup;

    /*
     * Enforce a stricter limit (without timeskew forgiveness at the
     * boundaries) because accept_sec_context code is also similarly
     * non-forgiving.
     */
    if (!krb5_gss_dbg_client_expcreds && out_creds->times.endtime < now) {
	code = KRB5KRB_AP_ERR_TKT_EXPIRED;
	goto cleanup;
    }

    /* call mk_req.  subkey and ap_req need to be used or destroyed */

    mk_req_flags = AP_OPTS_USE_SUBKEY;

    if (*req_flags & GSS_C_MUTUAL_FLAG)
	mk_req_flags |= AP_OPTS_MUTUAL_REQUIRED;

    if ((code = krb5_mk_req_extended(context, auth_context, mk_req_flags,
				     &checksum_data, out_creds, &ap_req)))
	goto cleanup;

   /* store the interesting stuff from creds and authent */
   *endtime = out_creds->times.endtime;
   *krb_flags = out_creds->ticket_flags;

   /* build up the token */

   /* allocate space for the token */
   tlen = g_token_size((gss_OID) mech_type, ap_req.length);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL) {
      code = ENOMEM;
      goto cleanup;
   }

   /* fill in the buffer */

   ptr = t;

   g_make_token_header((gss_OID) mech_type, ap_req.length,
		       &ptr, KG_TOK_CTX_AP_REQ);

   TWRITE_STR(ptr, (unsigned char *) ap_req.data, ap_req.length);

   /* pass it back */

   token->length = tlen;
   token->value = (void *) t;

   code = 0;
    
cleanup:
   if (checksum_data.data)
       free(checksum_data.data);
   krb5_free_cred_contents(context, &in_creds);
   if (out_creds)
       krb5_free_creds(context, out_creds);
   if (ap_req.data)
       xfree(ap_req.data);
   if (code)
       krb5_auth_con_free(context, *auth_context);

   return (code);
}

#define IS_KRB_ERROR(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7e ||\
				    (dat)->data[0] == 0x5e))

OM_uint32
krb5_gss_init_sec_context(minor_status, claimant_cred_handle,
			  context_handle, target_name, mech_type,
			  req_flags, time_req, input_chan_bindings,
			  input_token, actual_mech_type, output_token,
			  ret_flags, time_rec)
    OM_uint32 *minor_status;
    gss_cred_id_t claimant_cred_handle;
    gss_ctx_id_t *context_handle;
    gss_name_t target_name;
    gss_OID mech_type;
    OM_uint32 req_flags;
    OM_uint32 time_req;
    gss_channel_bindings_t input_chan_bindings;
    gss_buffer_t input_token;
    gss_OID *actual_mech_type;
    gss_buffer_t output_token;
    OM_uint32 *ret_flags;
    OM_uint32 *time_rec;
{
   krb5_context context;
   krb5_gss_cred_id_t cred;
   krb5_error_code code; 
   krb5_gss_ctx_id_rec *ctx;
   krb5_timestamp now;
   krb5_enctype enctype;
   gss_buffer_desc token;
   int i;
   int err;

   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);

   /* set up return values so they can be "freed" successfully */

   output_token->length = 0;
   output_token->value = NULL;
   if (actual_mech_type)
      *actual_mech_type = NULL;

   /* verify the credential, or use the default */
   /*SUPPRESS 29*/
   if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
      OM_uint32 major;

      if ((major = kg_get_defcred(minor_status, &claimant_cred_handle)) &&
	  GSS_ERROR(major)) {
	 return(major);
      }
   } else {
      OM_uint32 major;
	   
      major = krb5_gss_validate_cred(minor_status, claimant_cred_handle);
      if (GSS_ERROR(major))
	  return(major);
   }

   cred = (krb5_gss_cred_id_t) claimant_cred_handle;

   /* verify the mech_type */

   err = 0;
   if (mech_type == GSS_C_NULL_OID) {
       mech_type = cred->rfc_mech?gss_mech_krb5:gss_mech_krb5_old;
   } else if (g_OID_equal(mech_type, gss_mech_krb5)) {
       if (!cred->rfc_mech)
	   err = 1;
   } else if (g_OID_equal(mech_type, gss_mech_krb5_old)) {
       if (!cred->prerfc_mech)
	   err = 1;
   } else
       err = 1;
   
   if (err) {
      *minor_status = 0;
      return(GSS_S_BAD_MECH);
   }

   /* verify that the target_name is valid and usable */

   if (! kg_validate_name(target_name)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   /* is this a new connection or not? */

   /*SUPPRESS 29*/
   if (*context_handle == GSS_C_NO_CONTEXT) {
      /* make sure the cred is usable for init */

      if ((cred->usage != GSS_C_INITIATE) &&
	  (cred->usage != GSS_C_BOTH)) {
	 *minor_status = 0;
	 return(GSS_S_NO_CRED);
      }

      /* complain if the input token is non-null */

      if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
	 *minor_status = 0;
	 return(GSS_S_DEFECTIVE_TOKEN);
      }

      /* create the ctx */

      if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
	  == NULL) {
	 *minor_status = ENOMEM;
	 return(GSS_S_FAILURE);
      }

      /* fill in the ctx */
      memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));
      if (generic_gss_copy_oid(minor_status, mech_type, &ctx->mech_used)
	  != GSS_S_COMPLETE) {
	      free(ctx);
	      return (GSS_S_FAILURE);
      }
      ctx->auth_context = NULL;
      ctx->initiate = 1;
      ctx->gss_flags = KG_IMPLFLAGS(req_flags);
      ctx->seed_init = 0;
      ctx->big_endian = 0;  /* all initiators do little-endian, as per spec */
      ctx->seqstate = 0;

      if ((code = krb5_timeofday(context, &now))) {
	free(ctx);
	*minor_status = code;
	return(GSS_S_FAILURE);
      }
      if (time_req == 0 || time_req == GSS_C_INDEFINITE) {
	 ctx->endtime = 0;
      } else {
	 ctx->endtime = now + time_req;
      }

      if ((code = krb5_copy_principal(context, cred->princ, &ctx->here))) {
	 xfree(ctx);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      
      if ((code = krb5_copy_principal(context, (krb5_principal) target_name,
				      &ctx->there))) {
	 krb5_free_principal(context, ctx->here);
	 xfree(ctx);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      if ((code = make_ap_req(context, &(ctx->auth_context), cred, 
			      ctx->there, now, &ctx->endtime,
			      input_chan_bindings, 
			      &ctx->gss_flags, &ctx->krb_flags, mech_type,
			      &token))) {
	 krb5_free_principal(context, ctx->here);
	 krb5_free_principal(context, ctx->there);
	 xfree(ctx);
	 *minor_status = code;

	 if ((code == KRB5_FCC_NOFILE) || (code == KRB5_CC_NOTFOUND) ||
	     (code == KG_EMPTY_CCACHE))
	     return GSS_S_NO_CRED;
	 if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
		 return GSS_S_CREDENTIALS_EXPIRED;
	 return(GSS_S_FAILURE);
      }

      krb5_auth_con_getlocalseqnumber(context, ctx->auth_context, &ctx->seq_send);
      krb5_auth_con_getlocalsubkey(context, ctx->auth_context, &ctx->subkey);

      /* fill in the encryption descriptors */

      switch(ctx->subkey->enctype) {
      case ENCTYPE_DES_CBC_MD5:
      case ENCTYPE_DES_CBC_CRC:
	  enctype = ENCTYPE_DES_CBC_RAW;
	  ctx->signalg = 0;
	  ctx->cksum_size = 8;
	  ctx->sealalg = 0;
	  break;
#if 0
      case ENCTYPE_DES3_CBC_MD5:
	  enctype = ENCTYPE_DES3_CBC_RAW;
	  ctx->signalg = 3;
	  ctx->cksum_size = 16;
	  ctx->sealalg = 1;
	  break;
#endif
      default:
	  return GSS_S_FAILURE;
      }

      /* the encryption key is the session key XOR 0xf0f0f0f0f0f0f0f0 */

      krb5_use_enctype(context, &ctx->enc.eblock, enctype);
      ctx->enc.processed = 0;
      if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc.key)))
	 return(code); 
      for (i=0; i<ctx->enc.key->length; i++)
	 /*SUPPRESS 113*/
	 ctx->enc.key->contents[i] ^= 0xf0;

      krb5_use_enctype(context, &ctx->seq.eblock, enctype);
      ctx->seq.processed = 0;
      if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->seq.key)))
	  return(code);

      /* at this point, the context is constructed and valid,
	 hence, releaseable */

      /* intern the context handle */

      if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
	 xfree(token.value);
	 krb5_free_keyblock(context, ctx->subkey);
	 krb5_free_principal(context, ctx->here);
	 krb5_free_principal(context, ctx->there);
	 xfree(ctx);

	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
	 return(GSS_S_FAILURE);
      }

      /* compute time_rec */

      if (time_rec) {
	 if ((code = krb5_timeofday(context, &now))) {
	    xfree(token.value);
	    (void)krb5_gss_delete_sec_context(minor_status, 
					      (gss_ctx_id_t) ctx, NULL);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
	 *time_rec = ctx->endtime - now;
      }

      /* set the other returns */

      *context_handle = (gss_ctx_id_t) ctx;

      *output_token = token;

      if (ret_flags)
	 *ret_flags = ctx->gss_flags;

      if (actual_mech_type)
	 *actual_mech_type = mech_type;

      /* return successfully */

      *minor_status = 0;
      if (ctx->gss_flags & GSS_C_MUTUAL_FLAG) {
	 ctx->established = 0;
	 return(GSS_S_CONTINUE_NEEDED);
      } else {
	 ctx->seq_recv = ctx->seq_send;
	 g_order_init(&(ctx->seqstate), ctx->seq_recv,
		      (ctx->gss_flags & GSS_C_REPLAY_FLAG) != 0, 
		      (ctx->gss_flags & GSS_C_SEQUENCE_FLAG) != 0);
	 ctx->established = 1;
	 /* fall through to GSS_S_COMPLETE */
      }
   } else {
      unsigned char *ptr;
      char *sptr;
      krb5_data ap_rep;
      krb5_ap_rep_enc_part *ap_rep_data;
      krb5_error *krb_error;

      /* validate the context handle */
      /*SUPPRESS 29*/
      if (! kg_validate_ctx_id(*context_handle)) {
	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
	 return(GSS_S_NO_CONTEXT);
      }

      ctx = (gss_ctx_id_t) *context_handle;

      /* make sure the context is non-established, and that certain
	 arguments are unchanged */

      if ((ctx->established) ||
	  (((gss_cred_id_t) cred) != claimant_cred_handle) ||
	  ((ctx->gss_flags & GSS_C_MUTUAL_FLAG) == 0)) {
	 (void)krb5_gss_delete_sec_context(minor_status, 
					   context_handle, NULL);
	 /* XXX this minor status is wrong if an arg was changed */
	 *minor_status = KG_CONTEXT_ESTABLISHED;
	 return(GSS_S_FAILURE);
      }

      if (! krb5_principal_compare(context, ctx->there, 
				   (krb5_principal) target_name)) {
	 (void)krb5_gss_delete_sec_context(minor_status, 
					   context_handle, NULL);
	 *minor_status = 0;
	 return(GSS_S_BAD_NAME);
      }

      /* verify the token and leave the AP_REP message in ap_rep */

      if (input_token == GSS_C_NO_BUFFER) {
	 (void)krb5_gss_delete_sec_context(minor_status, 
					   context_handle, NULL);
	 *minor_status = 0;
	 return(GSS_S_DEFECTIVE_TOKEN);
      }

      ptr = (unsigned char *) input_token->value;

      if ((err = g_verify_token_header((gss_OID) mech_type, &(ap_rep.length),
				       &ptr, KG_TOK_CTX_AP_REP,
				       input_token->length))) {
	      if (g_verify_token_header((gss_OID) mech_type, &(ap_rep.length),
					&ptr, KG_TOK_CTX_ERROR,
					input_token->length) == 0) {

		      /* Handle a KRB_ERROR message from the server */

		      sptr = (char *) ptr;           /* PC compiler bug */
		      TREAD_STR(sptr, ap_rep.data, ap_rep.length);
		      
		      code = krb5_rd_error(context, &ap_rep, &krb_error);
		      if (code)
			      goto fail;
		      if (krb_error->error)
			      code = krb_error->error + ERROR_TABLE_BASE_krb5;
		      else
			      code = 0;
		      krb5_free_error(context, krb_error);
		      goto fail;
	      } else {
		      *minor_status = err;
		      return(GSS_S_DEFECTIVE_TOKEN);
	      }
      }

      sptr = (char *) ptr;                      /* PC compiler bug */
      TREAD_STR(sptr, ap_rep.data, ap_rep.length);

      /* decode the ap_rep */
      if ((code = krb5_rd_rep(context,ctx->auth_context,&ap_rep,
			      &ap_rep_data))) {
	      /*
	       * XXX A hack for backwards compatiblity.
	       * To be removed in 1999 -- proven 
	       */
	      krb5_auth_con_setuseruserkey(context,ctx->auth_context,ctx->subkey);
	      if ((krb5_rd_rep(context, ctx->auth_context, &ap_rep,
			     &ap_rep_data)))
		      goto fail;
      }

      /* store away the sequence number */
      ctx->seq_recv = ap_rep_data->seq_number;
      g_order_init(&(ctx->seqstate), ctx->seq_recv,
		   (ctx->gss_flags & GSS_C_REPLAY_FLAG) != 0,
		   (ctx->gss_flags & GSS_C_SEQUENCE_FLAG) !=0);

      /* free the ap_rep_data */
      krb5_free_ap_rep_enc_part(context, ap_rep_data);

      /* set established */
      ctx->established = 1;

      /* set returns */

      if (time_rec) {
	 if ((code = krb5_timeofday(context, &now)))
		 goto fail;
	 *time_rec = ctx->endtime - now;
      }

      if (ret_flags)
	 *ret_flags = KG_IMPLFLAGS(req_flags);

      if (actual_mech_type)
	 *actual_mech_type = mech_type;

      /* success */

      *minor_status = 0;
      /* fall through to GSS_S_COMPLETE */
   }

   return(GSS_S_COMPLETE);

fail:
   (void)krb5_gss_delete_sec_context(minor_status, 
				     (gss_ctx_id_t) ctx, NULL);
   *minor_status = code;
   return(GSS_S_FAILURE);
}

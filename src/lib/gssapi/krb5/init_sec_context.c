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

/*
 * $Id$
 */

static krb5_error_code
make_ap_req(krb5_gss_cred_id_t cred,
	    krb5_principal server,
	    krb5_timestamp *endtime,
	    gss_channel_bindings_t chan_bindings,
	    int do_mutual,
	    krb5_keyblock **subkey,
	    krb5_flags *flags,
	    krb5_int32 *seqnum,
	    gss_buffer_t token)
{
   krb5_error_code code;
   krb5_checksum md5, checksum;
   krb5_creds creds;
   krb5_authenticator authent;
   krb5_data ap_req;
   long tmp;
   unsigned char *ptr;
   unsigned char ckbuf[24];		/* see the token formats doc */
   unsigned char *t;
   int tlen;

   /* build the checksum buffer */

   /* compute the hash of the channel bindings */

   if (code = kg_checksum_channel_bindings(chan_bindings, &md5))
      return(code);

   ptr = ckbuf;

   TWRITE_INT(ptr, tmp, md5.length);
   TWRITE_STR(ptr, (unsigned char *) md5.contents, md5.length);
   TWRITE_INT(ptr, tmp, do_mutual?GSS_C_MUTUAL_FLAG:0);

   /* done with this, free it */
   xfree(md5.contents);

   checksum.checksum_type = CKSUMTYPE_KG_CB;
   checksum.length = sizeof(ckbuf);
   checksum.contents = (krb5_octet *) ckbuf;

   /* fill in the necessary fields in creds */

   memset((char *) &creds, 0, sizeof(creds));

   code = krb5_copy_principal(cred->princ, &creds.client);
   if (code)
	   return code;

   code = krb5_copy_principal(server, &creds.server);
   if (code)
	   return code;

   creds.times.endtime = *endtime;

   /* call mk_req.  subkey and ap_req need to be used or destroyed */

   if (code = krb5_mk_req_extended(do_mutual?AP_OPTS_MUTUAL_REQUIRED:0,
				   &checksum, 0, 0, subkey, cred->ccache,
				   &creds, &authent, &ap_req))
      return(code);

   /* store the interesting stuff from creds and authent */
   *endtime = creds.times.endtime;
   *flags = creds.ticket_flags;
   *seqnum = authent.seq_number;

   /* free stuff which was created */

   krb5_free_cred_contents(&creds);

   /* build up the token */

   /* allocate space for the token */
   tlen = g_token_size(gss_mech_krb5, ap_req.length);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL) {
      xfree(ap_req.data);
      krb5_free_keyblock(*subkey);
      return(ENOMEM);
   }

   /* fill in the buffer */

   ptr = t;

   g_make_token_header(gss_mech_krb5, ap_req.length,
		       &ptr, KG_TOK_CTX_AP_REQ);

   TWRITE_STR(ptr, (unsigned char *) ap_req.data, ap_req.length);

   /* free the ap_req */

   xfree(ap_req.data);

   /* pass it back */

   token->length = tlen;
   token->value = (void *) t;

   return(0);
}

OM_uint32
krb5_gss_init_sec_context(OM_uint32 *minor_status,
			  gss_cred_id_t claimant_cred_handle,
			  gss_ctx_id_t *context_handle,
			  gss_name_t target_name,
			  const_gss_OID mech_type,
			  int req_flags,
			  OM_uint32 time_req,
			  gss_channel_bindings_t input_chan_bindings,
			  gss_buffer_t input_token,
			  gss_OID *actual_mech_type,
			  gss_buffer_t output_token,
			  int *ret_flags,
			  OM_uint32 *time_rec)
{
   krb5_gss_cred_id_t cred;
   krb5_error_code code; 
   krb5_gss_ctx_id_rec *ctx;
   krb5_timestamp now;
   gss_buffer_desc token;
   int i;

   /* set up return values so they can be "freed" successfully */

   output_token->length = 0;
   output_token->value = NULL;
   if (actual_mech_type)
      *actual_mech_type = (gss_OID) gss_mech_krb5;

   /* verify the mech_type */

   if ((mech_type != GSS_C_NULL_OID) &&
       (! g_OID_equal(mech_type, gss_mech_krb5))) {
      *minor_status = 0;
      return(GSS_S_BAD_MECH);
   }

   /* verify the credential, or use the default */
   /*SUPPRESS 29*/
   if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
      OM_uint32 major;

      if ((major = kg_get_defcred(minor_status, &claimant_cred_handle)) &&
	  GSS_ERROR(major)) {
	 return(major);
      }
   } else {
      if (! kg_validate_cred_id(claimant_cred_handle)) {
	 *minor_status = G_VALIDATE_FAILED;
	 return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_DEFECTIVE_CREDENTIAL);
      }
   }

   cred = (krb5_gss_cred_id_t) claimant_cred_handle;

   /* verify that the target_name is valid and usable */

   if (! kg_validate_name(target_name)) {
      *minor_status = G_VALIDATE_FAILED;
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

      /* complain if the input token is nonnull */

      if (input_token != GSS_C_NO_BUFFER) {
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

      ctx->initiate = 1;
      ctx->mutual = req_flags & GSS_C_MUTUAL_FLAG;
      ctx->seed_init = 0;
      ctx->cred = cred;

      if (time_req == 0 || time_req == GSS_C_INDEFINITE) {
	 ctx->endtime = 0;
      } else {
	 if (code = krb5_timeofday(&now)) {
	    free(ctx);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
	 ctx->endtime = now + time_req;
      }

      if (code = krb5_copy_principal(cred->princ, &ctx->here)) {
	 xfree(ctx);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      
      if (code = krb5_copy_principal((krb5_principal) target_name,
				     &ctx->there)) {
	 krb5_free_principal(ctx->here);
	 xfree(ctx);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      if (code = make_ap_req(ctx->cred, ctx->there, &ctx->endtime,
			     input_chan_bindings, ctx->mutual,
			     &ctx->subkey, &ctx->flags,
			     &ctx->seq_send, &token)) {
	 krb5_free_principal(ctx->here);
	 krb5_free_principal(ctx->there);
	 xfree(ctx);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      /* fill in the encryption descriptors */

      /* the encryption key is the session key XOR 0xf0f0f0f0f0f0f0f0 */

      krb5_use_cstype(&ctx->enc.eblock, ETYPE_RAW_DES_CBC);
      ctx->enc.processed = 0;
      if (code = krb5_copy_keyblock(ctx->subkey, &ctx->enc.key))
	 return(code); 
      for (i=0; i<ctx->enc.key->length; i++)
	 /*SUPPRESS 113*/
	 ctx->enc.key->contents[i] ^= 0xf0;

      krb5_use_cstype(&ctx->seq.eblock, ETYPE_RAW_DES_CBC);
      ctx->seq.processed = 0;
      ctx->seq.key = ctx->subkey;

      /* at this point, the context is constructed and valid,
	 hence, releaseable */

      /* intern the context handle */

      if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
	 xfree(token.value);
	 krb5_free_keyblock(ctx->subkey);
	 krb5_free_principal(ctx->here);
	 krb5_free_principal(ctx->there);
	 xfree(ctx);

	 *minor_status = G_VALIDATE_FAILED;
	 return(GSS_S_FAILURE);
      }

      /* compute time_rec */

      if (time_rec) {
	 if (code = krb5_timeofday(&now)) {
	    xfree(token.value);
	    (void)krb5_gss_delete_sec_context(minor_status, (gss_ctx_id_t) ctx,
					 NULL);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
	 *time_rec = ctx->endtime - now;
      }

      /* set the other returns */

      *context_handle = (gss_ctx_id_t) ctx;

      *output_token = token;

      if (ret_flags)
	 *ret_flags = ((req_flags & GSS_C_MUTUAL_FLAG) | 
		       GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);

      /* return successfully */

      *minor_status = 0;
      if (ctx->mutual) {
	 ctx->established = 0;
	 return(GSS_S_CONTINUE_NEEDED);
      } else {
	 ctx->seq_recv = ctx->seq_send;
	 ctx->established = 1;
	 return(GSS_S_COMPLETE);
      }
   } else {
      unsigned char *ptr;
      krb5_data ap_rep;
      krb5_ap_rep_enc_part *ap_rep_data;

      /* validate the context handle */
      /*SUPPRESS 29*/
      if (! kg_validate_ctx_id(*context_handle)) {
	 *minor_status = G_VALIDATE_FAILED;
	 return(GSS_S_NO_CONTEXT);
      }

      ctx = (gss_ctx_id_t) *context_handle;

      /* make sure the context is non-established, and that certain
	 arguments are unchanged */

      if ((ctx->established) ||
	  (((gss_cred_id_t) ctx->cred) != claimant_cred_handle) ||
	  ((req_flags & GSS_C_MUTUAL_FLAG) == 0)) {
	 (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
	 *minor_status = KG_CONTEXT_ESTABLISHED;
	 return(GSS_S_FAILURE);
      }

      if (! krb5_principal_compare(ctx->there, (krb5_principal) target_name)) {
	 (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
	 *minor_status = 0;
	 return(GSS_S_BAD_NAME);
      }

      /* verify the token and leave the AP_REP message in ap_rep */

      if (input_token == GSS_C_NO_BUFFER) {
	 (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
	 *minor_status = 0;
	 return(GSS_S_DEFECTIVE_TOKEN);
      }

      ptr = (unsigned char *) input_token->value;

      if (! g_verify_token_header(gss_mech_krb5, &(ap_rep.length),
				  &ptr, KG_TOK_CTX_AP_REP,
				  input_token->length)) {
	 *minor_status = 0;
	 return(GSS_S_DEFECTIVE_TOKEN);
      }

      TREAD_STR(ptr, (unsigned char *) ap_rep.data, ap_rep.length);

      /* decode the ap_rep */
      if (code = krb5_rd_rep(&ap_rep, ctx->subkey, &ap_rep_data)) {
	 (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      /* store away the sequence number */
      ctx->seq_recv = ap_rep_data->seq_number;

      /* free the ap_rep_data */
      krb5_free_ap_rep_enc_part(ap_rep_data);

      /* set established */
      ctx->established = 1;

      /* set returns */

      if (time_rec) {
	 if (code = krb5_timeofday(&now)) {
	    (void)krb5_gss_delete_sec_context(minor_status, (gss_ctx_id_t) ctx,
					 NULL);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
	 *time_rec = ctx->endtime - now;
      }

      if (ret_flags)
	 *ret_flags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG;

      /* success */

      *minor_status = 0;
      return(GSS_S_COMPLETE);
   }
}

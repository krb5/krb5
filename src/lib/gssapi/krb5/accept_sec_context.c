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
#include <krb5/rsa-md5.h>
#include <memory.h>

static krb5_error_code 
rd_req_keyproc(context, keyprocarg, server, kvno, keytype, keyblock)
     krb5_context context;
     krb5_pointer keyprocarg;
     krb5_principal server;
     krb5_kvno kvno;
     krb5_keytype keytype;
     krb5_keyblock **keyblock;
{
   krb5_error_code code;
   krb5_keytab_entry ktentry;

   if (code = krb5_kt_get_entry(context, (krb5_keytab) keyprocarg, server, 
				kvno, keytype, &ktentry))
      return(code);

   code = krb5_copy_keyblock(context, &ktentry.key, keyblock);

   (void) krb5_kt_free_entry(context, &ktentry);

   return(code);
}

static krb5_error_code 
make_ap_rep(context, authdat, subkey, seq_send, token)
     krb5_context context;
     krb5_tkt_authent *authdat;
     krb5_keyblock *subkey;
     krb5_int32 *seq_send;
     gss_buffer_t token;
{
   krb5_error_code code;
   krb5_ap_rep_enc_part ap_rep_data;
   krb5_data ap_rep;
   int tlen;
   unsigned char *t, *ptr;

   /* make the ap_rep */

   ap_rep_data.ctime = authdat->authenticator->ctime;
   ap_rep_data.cusec = authdat->authenticator->cusec;
   ap_rep_data.subkey = authdat->authenticator->subkey;

   if (code = krb5_generate_seq_number(context, 
				       authdat->ticket->enc_part2->session,
				       &ap_rep_data.seq_number))
      return(code);

   if (code = krb5_mk_rep(context, &ap_rep_data, subkey, &ap_rep))
      return(code);

   /* build up the token */

   /* allocate space for the token */
   tlen = g_token_size(gss_mech_krb5, ap_rep.length);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL) {
      xfree(ap_rep.data);
      return(ENOMEM);
   }

   /* fill in the buffer */

   ptr = t;

   g_make_token_header(gss_mech_krb5, ap_rep.length,
		       &ptr, KG_TOK_CTX_AP_REP);

   TWRITE_STR(ptr, ap_rep.data, ap_rep.length);

   /* free the ap_rep */

   xfree(ap_rep.data);

   /* pass everything back */

   *seq_send = ap_rep_data.seq_number;

   token->length = tlen;
   token->value = (void *) t;

   return(0);
}

OM_uint32 
krb5_gss_accept_sec_context(context, minor_status, context_handle, 
			    verifier_cred_handle, input_token,
			    input_chan_bindings, src_name, mech_type,
			    output_token, ret_flags, time_rec,
			    delegated_cred_handle)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_cred_id_t verifier_cred_handle;
     gss_buffer_t input_token;
     gss_channel_bindings_t input_chan_bindings;
     gss_name_t *src_name;
     gss_OID *mech_type;
     gss_buffer_t output_token;
     int *ret_flags;
     OM_uint32 *time_rec;
     gss_cred_id_t *delegated_cred_handle;
{
   unsigned char *ptr, *ptr2;
   long tmp;
   int bigend;
   krb5_gss_cred_id_t cred;
   krb5_data ap_req;
   int i;
   krb5_error_code code;
   krb5_address addr, *paddr;
   krb5_tkt_authent *authdat;
   krb5_checksum md5;
   krb5_rcache rcache;
   krb5_principal name;
   int gss_flags;
   krb5_gss_ctx_id_rec *ctx;
   krb5_timestamp now;
   gss_buffer_desc token;

   /* set up returns to be freeable */

   if (src_name)
      *src_name = GSS_C_NO_NAME;
   output_token->length = 0;
   output_token->value = NULL;
   if (mech_type)
      *mech_type = GSS_C_NULL_OID;
   /* return a bogus cred handle */
   if (delegated_cred_handle)
      *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

   /* context handle must be unspecified */

   /*SUPPRESS 29*/
   if (*context_handle != GSS_C_NO_CONTEXT) {
      *minor_status = 0;
      return(GSS_S_NO_CONTEXT);
   }

   /* validate the cred handle - no default */

   /*SUPPRESS 29*/
   if (verifier_cred_handle == GSS_C_NO_CREDENTIAL) {
      *minor_status = 0;
      return(GSS_S_NO_CRED);
   } else {
      if (! kg_validate_cred_id(verifier_cred_handle)) {
	 *minor_status = G_VALIDATE_FAILED;
	 return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_DEFECTIVE_CREDENTIAL);
      }
   }

   cred = (krb5_gss_cred_id_t) verifier_cred_handle;

   /* make sure the supplied credentials are valid for accept */

   if ((cred->usage != GSS_C_ACCEPT) &&
       (cred->usage != GSS_C_BOTH)) {
      *minor_status = 0;
      return(GSS_S_NO_CRED);
   }

   /* verify the token's integrity, and leave the token in ap_req */

   ptr = (unsigned char *) input_token->value;

   if (! g_verify_token_header(gss_mech_krb5, &(ap_req.length),
			       &ptr, KG_TOK_CTX_AP_REQ, input_token->length)) {
      *minor_status = 0;
      return(GSS_S_DEFECTIVE_TOKEN);
   }

   TREAD_STR(ptr, ap_req.data, ap_req.length);

   /* construct the sender_addr */

   if ((input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) &&
       (input_chan_bindings->initiator_addrtype == GSS_C_AF_INET)) {
      /* XXX is this right? */
      addr.addrtype = ADDRTYPE_INET;
      addr.length = input_chan_bindings->initiator_address.length;
      addr.contents = input_chan_bindings->initiator_address.value;

      paddr = &addr;
   } else {
      paddr = NULL;
   }

   /* decode the AP_REQ message */

   /* get the rcache pointer */

   if (code =
       krb5_get_server_rcache(context, 
			      krb5_princ_component(context, cred->princ,
			      ((krb5_princ_size(context, cred->princ)>1)?1:0)),
			      &rcache)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* decode the message */

   if (code = krb5_rd_req(context, &ap_req, cred->princ, paddr, NULL, 
			  &rd_req_keyproc, (krb5_pointer) cred->keytab, 
			  rcache, &authdat)) {
      (void) krb5_rc_close(context, rcache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* close and free the rcache */

   krb5_rc_close(context, rcache);

   /* make sure the necessary parts of the authdat are present */

   if ((authdat->authenticator->subkey == NULL) ||
       (authdat->ticket->enc_part2 == NULL)) {
      krb5_free_tkt_authent(context, authdat);
      *minor_status = KG_NO_SUBKEY;
      return(GSS_S_FAILURE);
   }

   /* verify that the checksum is correct */

   /* 24 == checksum length: see token formats document */
   /* This checks for < 24 instead of != 24 in order that this implementation
      can interoperate with an implementation whcih supports negotiation */
   if ((authdat->authenticator->checksum->checksum_type != CKSUMTYPE_KG_CB) ||
       (authdat->authenticator->checksum->length < 24)) {
      krb5_free_tkt_authent(context, authdat);
      *minor_status = 0;
      return(GSS_S_BAD_BINDINGS);
   }

   /*
      "Be liberal in what you accept, and
       conservative in what you send"
		-- rfc1123

       This code will let this acceptor interoperate with an initiator
       using little-endian or big-endian integer encoding.
   */

   ptr = (unsigned char *) authdat->authenticator->checksum->contents;
   bigend = 0;

   TREAD_INT(ptr, tmp, bigend);

   if (tmp != RSA_MD5_CKSUM_LENGTH) {
      ptr = (unsigned char *) authdat->authenticator->checksum->contents;
      bigend = 1;

      TREAD_INT(ptr, tmp, bigend);

      if (tmp != RSA_MD5_CKSUM_LENGTH) {
	 xfree(md5.contents);
	 krb5_free_tkt_authent(context, authdat);
	 *minor_status = KG_BAD_LENGTH;
	 return(GSS_S_FAILURE);
      }
   }

   /* at this point, bigend is set according to the initiator's byte order */

   if (code = kg_checksum_channel_bindings(input_chan_bindings, &md5,
					   bigend)) {
      krb5_free_tkt_authent(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   TREAD_STR(ptr, ptr2, md5.length);
   if (memcmp(ptr2, md5.contents, md5.length) != 0) {
      xfree(md5.contents);
      krb5_free_tkt_authent(context, authdat);
      *minor_status = 0;
      return(GSS_S_BAD_BINDINGS);
   }

   xfree(md5.contents);

   TREAD_INT(ptr, gss_flags, bigend);

   /* create the ctx struct and start filling it in */

   if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
       == NULL) {
      *minor_status = ENOMEM;
      return(GSS_S_FAILURE);
   }

   ctx->context = context;
   ctx->initiate = 0;
   ctx->mutual = gss_flags & GSS_C_MUTUAL_FLAG;
   ctx->seed_init = 0;
   ctx->cred = cred;
   ctx->big_endian = bigend;

   if (code = krb5_copy_principal(context, cred->princ, &ctx->here)) {
      xfree(ctx);
      krb5_free_tkt_authent(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (code = krb5_copy_principal(context, authdat->authenticator->client,
				  &ctx->there)) {
      krb5_free_principal(context, ctx->here);
      xfree(ctx);
      krb5_free_tkt_authent(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (code = krb5_copy_keyblock(context, authdat->authenticator->subkey,
				 &ctx->subkey)) {
      krb5_free_principal(context, ctx->there);
      krb5_free_principal(context, ctx->here);
      xfree(ctx);
      krb5_free_tkt_authent(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* fill in the encryption descriptors */

   krb5_use_cstype(context, &ctx->enc.eblock, ETYPE_RAW_DES_CBC);
   ctx->enc.processed = 0;
   if (code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc.key))
      return(code); 
   for (i=0; i<ctx->enc.key->length; i++)
      /*SUPPRESS 113*/
      ctx->enc.key->contents[i] ^= 0xf0;

   krb5_use_cstype(context, &ctx->seq.eblock, ETYPE_RAW_DES_CBC);
   ctx->seq.processed = 0;
   ctx->seq.key = ctx->subkey;

   ctx->endtime = authdat->ticket->enc_part2->times.endtime;

   ctx->flags = authdat->ticket->enc_part2->flags;

   ctx->seq_recv = authdat->authenticator->seq_number;

   /* at this point, the entire context structure is filled in, 
      so it can be released.  */

   /* generate an AP_REP if necessary */

   if (ctx->mutual) {
      if (code = make_ap_rep(context, authdat, ctx->subkey, &ctx->seq_send,
			     &token)) {
	 (void)krb5_gss_delete_sec_context(context, minor_status, 
					   (gss_ctx_id_t *) &ctx, NULL);
	 krb5_free_tkt_authent(context, authdat);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
   } else {
      token.length = 0;
      token.value = NULL;
      ctx->seq_send = ctx->seq_recv;
   }

   /* done with authdat! */
   krb5_free_tkt_authent(context, authdat);

   /* set the return arguments */

   if (src_name) {
      if (code = krb5_copy_principal(context, ctx->there, &name)) {
	 if (token.value)
	    xfree(token.value);
	 (void)krb5_gss_delete_sec_context(context, minor_status, 
					   (gss_ctx_id_t *) &ctx, NULL);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
   }

   if (mech_type)
      *mech_type = (gss_OID) gss_mech_krb5;

   if (time_rec) {
      if (code = krb5_timeofday(context, &now)) {
	 if (src_name)
	    krb5_free_principal(context, name);
	 xfree(token.value);
	 (void)krb5_gss_delete_sec_context(context, minor_status, 
					   (gss_ctx_id_t *) &ctx, NULL);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      *time_rec = ctx->endtime - now;
   }

   if (ret_flags)
      *ret_flags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | ctx->mutual;

   ctx->established = 1;

   /* intern the src_name */

   if (src_name)
      if (! kg_save_name((gss_name_t) name)) {
	 krb5_free_principal(context, name);
	 if (token.value)
	    xfree(token.value);
	 (void)krb5_gss_delete_sec_context(context, minor_status,
					   (gss_ctx_id_t *) &ctx, NULL);
	 *minor_status = G_VALIDATE_FAILED;
	 return(GSS_S_FAILURE);
      }

   /* intern the context handle */

   if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
      if (src_name) {
	 (void) kg_delete_name((gss_name_t) name);
	 krb5_free_principal(context, name);
      }
      if (token.value)
	 xfree(token.value);
      (void)krb5_gss_delete_sec_context(context, minor_status, 
					(gss_ctx_id_t *) &ctx, NULL);
      *minor_status = G_VALIDATE_FAILED;
      return(GSS_S_FAILURE);
   }

   *context_handle = ctx;

   *output_token = token;

   if (src_name)
      *src_name = (gss_name_t) name;

   /* finally! */

   *minor_status = 0;
   return(GSS_S_COMPLETE);
}

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
#include "rsa-md5.h"
#include <memory.h>

/* Decode, decrypt and store the forwarded creds in the local ccache. */
static krb5_error_code
rd_and_store_for_creds(context, auth_context, inbuf)
    krb5_context context;
    krb5_auth_context auth_context;
    krb5_data *inbuf;
{
    krb5_creds ** creds;
    krb5_error_code retval;
    krb5_ccache ccache;

    if ((retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL))) 
	return(retval);

    if ((retval = krb5_cc_default(context, &ccache)))
       goto cleanup;
    
    if ((retval = krb5_cc_initialize(context, ccache, creds[0]->client)))
	goto cleanup;

    if ((retval = krb5_cc_store_cred(context, ccache, creds[0])))
	goto cleanup;

    if ((retval = krb5_cc_close(context, ccache)))
	goto cleanup;

cleanup:
    krb5_free_tgt_creds(context, creds);
    return retval;
}

OM_uint32
krb5_gss_accept_sec_context(ct, minor_status, context_handle, 
			    verifier_cred_handle, input_token,
			    input_chan_bindings, src_name, mech_type,
			    output_token, ret_flags, time_rec,
			    delegated_cred_handle)
     void *ct;
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_cred_id_t verifier_cred_handle;
     gss_buffer_t input_token;
     gss_channel_bindings_t input_chan_bindings;
     gss_name_t *src_name;
     gss_OID *mech_type;
     gss_buffer_t output_token;
     OM_uint32 *ret_flags;
     OM_uint32 *time_rec;
     gss_cred_id_t *delegated_cred_handle;
{
   krb5_context context = ct;
   unsigned char *ptr, *ptr2;
   char *sptr;
   long tmp;
   int bigend;
   krb5_gss_cred_id_t cred;
   krb5_data ap_req;
   int i;
   krb5_error_code code;
   krb5_address addr, *paddr;
   krb5_authenticator *authdat;
   krb5_checksum md5;
   krb5_principal name;
   int gss_flags;
   krb5_gss_ctx_id_rec *ctx;
   krb5_timestamp now;
   gss_buffer_desc token;
   krb5_auth_context auth_context = NULL;
   krb5_ticket * ticket = NULL;
   int option_id;
   krb5_data option;
   krb5_auth_context auth_context_cred = NULL;


   /* set up returns to be freeable */

   if (src_name)
      *src_name = (gss_name_t) NULL;
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
	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
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

   if (! g_verify_token_header((gss_OID) gss_mech_krb5, &(ap_req.length),
			       &ptr, KG_TOK_CTX_AP_REQ, input_token->length)) {
      *minor_status = 0;
      return(GSS_S_DEFECTIVE_TOKEN);
   }

   sptr = (char *) ptr;
   TREAD_STR(sptr, ap_req.data, ap_req.length);

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

   /* decode the message */

   if ((code = krb5_rd_req(context, &auth_context, &ap_req, cred->princ,
			  cred->keytab, NULL, &ticket))) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   krb5_auth_con_getauthenticator(context, auth_context, &authdat);

   /* verify that the checksum is correct */

   /*
      The checksum may be either exactly 24 bytes, in which case
      no options are specified, or greater than 24 bytes, in which case
      one or more options are specified. Currently, the only valid
      option is KRB5_GSS_FOR_CREDS_OPTION ( = 1 ).
   */

   if ((authdat->checksum->checksum_type != CKSUMTYPE_KG_CB) ||
       (authdat->checksum->length < 24)) {
      krb5_free_authenticator(context, authdat);
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

   ptr = (unsigned char *) authdat->checksum->contents;
   bigend = 0;

   TREAD_INT(ptr, tmp, bigend);

   if (tmp != RSA_MD5_CKSUM_LENGTH) {
      ptr = (unsigned char *) authdat->checksum->contents;
      bigend = 1;

      TREAD_INT(ptr, tmp, bigend);

      if (tmp != RSA_MD5_CKSUM_LENGTH) {
	 xfree(md5.contents);
	 krb5_free_authenticator(context, authdat);
	 *minor_status = KG_BAD_LENGTH;
	 return(GSS_S_FAILURE);
      }
   }

   /* at this point, bigend is set according to the initiator's byte order */

   if ((code = kg_checksum_channel_bindings(input_chan_bindings, &md5,
					    bigend))) {
      krb5_free_authenticator(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   TREAD_STR(ptr, ptr2, md5.length);
   if (memcmp(ptr2, md5.contents, md5.length) != 0) {
      xfree(md5.contents);
      krb5_free_authenticator(context, authdat);
      *minor_status = 0;
      return(GSS_S_BAD_BINDINGS);
   }

   xfree(md5.contents);

   TREAD_INT(ptr, gss_flags, bigend);

   /* if the checksum length > 24, there are options to process */

   if(authdat->checksum->length > 24) {

	i = authdat->checksum->length - 24;

	while(i>0) {

	    TREAD_INT16(ptr, option_id, bigend);

	    switch(option_id) {

		case KRB5_GSS_FOR_CREDS_OPTION:

		    TREAD_INT16(ptr, option.length, bigend);

		    /* have to use ptr2, since option.data is wrong type and
		       macro uses ptr as both lvalue and rvalue */

		    TREAD_STR(ptr, ptr2, bigend);
		    option.data = (char FAR *) ptr2;

		    /* get a temporary auth_context structure for the
		       call to rd_and_store_for_creds() and clear its flags */

		    if ((code = krb5_auth_con_init(context,
						   &auth_context_cred))) {
			*minor_status = code;
			return(GSS_S_FAILURE);
		    }

		    krb5_auth_con_setflags(context, auth_context_cred, 0);

		    /* store the delegated credential in the user's cache */

		    rd_and_store_for_creds(context, auth_context_cred,
					   &option);

		    i -= option.length + 4;

		    krb5_auth_con_free(context, auth_context_cred);

		    break;

		default :

		     /* any other options are unrecognized. return
			generic GSS_C_FAILURE error with a minor status
			of KRB5_PARSE_MALFORMED (XXX this is probably
			not the right error, since it is used for
			string parsing errors not token parsing errors.) */

		    *minor_status = KRB5_PARSE_MALFORMED;
		    return(GSS_S_FAILURE);
	    } /* switch */
	} /* while */
    } /* if */
			

   /* create the ctx struct and start filling it in */

   if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
       == NULL) {
      *minor_status = ENOMEM;
      return(GSS_S_FAILURE);
   }

   memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));
   ctx->auth_context = auth_context;
   ctx->initiate = 0;
   ctx->gss_flags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
	(gss_flags & (GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG));
   ctx->seed_init = 0;
   ctx->big_endian = bigend;

   if ((code = krb5_copy_principal(context, cred->princ, &ctx->here))) {
      xfree(ctx);
      krb5_free_authenticator(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if ((code = krb5_copy_principal(context, authdat->client, &ctx->there))) {
      krb5_free_principal(context, ctx->here);
      xfree(ctx);
      krb5_free_authenticator(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if ((code = krb5_auth_con_getremotesubkey(context, auth_context,
					     &ctx->subkey))) {
      krb5_free_principal(context, ctx->there);
      krb5_free_principal(context, ctx->here);
      xfree(ctx);
      krb5_free_authenticator(context, authdat);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* fill in the encryption descriptors */

   krb5_use_enctype(context, &ctx->enc.eblock, ENCTYPE_DES_CBC_RAW);
   ctx->enc.processed = 0;
   if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc.key)))
      return(code); 
   for (i=0; i<ctx->enc.key->length; i++)
      /*SUPPRESS 113*/
      ctx->enc.key->contents[i] ^= 0xf0;

   krb5_use_enctype(context, &ctx->seq.eblock, ENCTYPE_DES_CBC_RAW);
   ctx->seq.processed = 0;
   if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->seq.key)))
       return(code);
   ctx->endtime = ticket->enc_part2->times.endtime;
   ctx->flags = ticket->enc_part2->flags;

   krb5_free_ticket(context, ticket); /* Done with ticket */

   krb5_auth_con_getremoteseqnumber(context, auth_context, &ctx->seq_recv);

   /* at this point, the entire context structure is filled in, 
      so it can be released.  */

   /* generate an AP_REP if necessary */

   if (ctx->gss_flags & GSS_C_MUTUAL_FLAG) {
      krb5_data ap_rep;
      unsigned char * ptr;
      if ((code = krb5_mk_rep(context, auth_context, &ap_rep))) {
	 (void)krb5_gss_delete_sec_context(context, minor_status, 
					   (gss_ctx_id_t *) &ctx, NULL);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      krb5_auth_con_getlocalseqnumber(context, auth_context, &ctx->seq_send);
      token.length = g_token_size((gss_OID) gss_mech_krb5, ap_rep.length);

      if ((token.value = (unsigned char *) xmalloc(token.length)) == NULL) {
	 (void)krb5_gss_delete_sec_context(context, minor_status, 
					   (gss_ctx_id_t *) &ctx, NULL);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      ptr = token.value;
      g_make_token_header((gss_OID) gss_mech_krb5, ap_rep.length,
                       &ptr, KG_TOK_CTX_AP_REP);

      TWRITE_STR(ptr, ap_rep.data, ap_rep.length);
      xfree(ap_rep.data);
   } else {
      token.length = 0;
      token.value = NULL;
      ctx->seq_send = ctx->seq_recv;
   }

   /* done with authdat! */
   krb5_free_authenticator(context, authdat);

   /* set the return arguments */

   if (src_name) {
      if ((code = krb5_copy_principal(context, ctx->there, &name))) {
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
      if ((code = krb5_timeofday(context, &now))) {
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
      *ret_flags = ctx->gss_flags;

   ctx->established = 1;

   /* intern the src_name */

   if (src_name)
      if (! kg_save_name((gss_name_t) name)) {
	 krb5_free_principal(context, name);
	 if (token.value)
	    xfree(token.value);
	 (void)krb5_gss_delete_sec_context(context, minor_status,
					   (gss_ctx_id_t *) &ctx, NULL);
	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
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
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
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

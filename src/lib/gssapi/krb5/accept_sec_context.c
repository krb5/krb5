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

#include "k5-int.h"
#include "gssapiP_krb5.h"
#include <memory.h>

/*
 * $Id$
 */

#if 0

/* XXXX This widen/narrow stuff is bletcherous, but it seems to be
   necessary.  Perhaps there is a "better" way, but I don't know what it
   is */

#include <krb5/widen.h>
static krb5_error_code
rd_req_keyproc(krb5_pointer keyprocarg, krb5_principal server,
	       krb5_kvno kvno, krb5_keyblock **keyblock)
#include <krb5/narrow.h>
{
   krb5_error_code code;
   krb5_keytab_entry ktentry;

   if (code = krb5_kt_get_entry((krb5_keytab) keyprocarg, server, kvno,
				&ktentry))
      return(code);

   code = krb5_copy_keyblock(&ktentry.key, keyblock);

   (void) krb5_kt_free_entry(&ktentry);

   return(code);
}

#endif

/* Decode, decrypt and store the forwarded creds in the local ccache. */
static krb5_error_code
rd_and_store_for_creds(context, auth_context, inbuf, out_cred)
    krb5_context context;
    krb5_auth_context auth_context;
    krb5_data *inbuf;
    krb5_gss_cred_id_t *out_cred;
{
    krb5_creds ** creds;
    krb5_error_code retval;
    krb5_ccache ccache;
    krb5_gss_cred_id_t cred = NULL;

    if ((retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL))) 
	return(retval);

    if ((retval = krb5_cc_default(context, &ccache)))
       goto cleanup;
    
    if ((retval = krb5_cc_initialize(context, ccache, creds[0]->client)))
	goto cleanup;

    if ((retval = krb5_cc_store_cred(context, ccache, creds[0])))
	goto cleanup;

    /* generate a delegated credential handle */
    if (out_cred) {
      /* allocate memory for a cred_t... */
      if (!(cred =
	    (krb5_gss_cred_id_t) xmalloc(sizeof(krb5_gss_cred_id_rec)))) {
	retval = ENOMEM; /* out of memory? */
	goto cleanup;
      }

      /* zero it out... */
      memset(cred, 0, sizeof(krb5_gss_cred_id_rec));

      /* copy the client principle into it... */
      if ((retval =
	   krb5_copy_principal(context, creds[0]->client, &(cred->princ)))) {
	retval = ENOMEM; /* out of memory? */
	xfree(cred); /* clean up memory on failure */
	cred = NULL;
	goto cleanup;
      }

      cred->usage = GSS_C_INITIATE; /* we can't accept with this */
      /* cred->princ already set */
      cred->actual_mechs = gss_mech_set_krb5_both; /* both mechs work */
      cred->prerfc_mech = cred->rfc_mech = 1; /* Ibid. */
      cred->keytab = NULL; /* no keytab associated with this... */
      cred->ccache = ccache; /* but there is a credential cache */
      cred->tgt_expire = creds[0]->times.endtime; /* store the end time */
    }

    /* If there were errors, there might have been a memory leak
    if (!cred)
      if ((retval = krb5_cc_close(context, ccache)))
	goto cleanup;
	*/
cleanup:
    krb5_free_tgt_creds(context, creds);

    if (!cred && ccache)
      (void)krb5_cc_close(context, ccache);

    if (out_cred)
      *out_cred = cred; /* return credential */

    return retval;
}

OM_uint32
krb5_gss_accept_sec_context(minor_status, context_handle, 
			    verifier_cred_handle, input_token,
			    input_chan_bindings, src_name, mech_type,
			    output_token, ret_flags, time_rec,
			    delegated_cred_handle)
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
   krb5_context context;
   unsigned char *ptr, *ptr2;
   char *sptr;
   long tmp;
   int bigend;
   krb5_gss_cred_id_t cred;
   krb5_data ap_req;
   int i;
   krb5_error_code code;
   krb5_address addr, *paddr;
   krb5_authenticator *authdat = 0;
   krb5_checksum md5;
   krb5_principal name = NULL;
   int gss_flags = 0;
   int decode_req_message = 0;
   krb5_gss_ctx_id_rec *ctx = 0;
   krb5_enctype enctype;
   krb5_timestamp now;
   gss_buffer_desc token;
   int err;
   krb5_auth_context auth_context = NULL;
   krb5_ticket * ticket = NULL;
   int option_id;
   krb5_data option;
   krb5_auth_context auth_context_cred = NULL;
   const gss_OID_desc *mech_used = NULL;
   OM_uint32 major_status = GSS_S_FAILURE;
   krb5_error krb_error_data;
   krb5_data scratch;
   krb5_gss_cred_id_t deleg_cred = NULL;

   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);

   /* set up returns to be freeable */

   if (src_name)
      *src_name = (gss_name_t) NULL;
   output_token->length = 0;
   output_token->value = NULL;
   token.value = 0;
   md5.contents = 0;
   
   if (mech_type)
      *mech_type = GSS_C_NULL_OID;
   /* return a bogus cred handle */
   if (delegated_cred_handle)
      *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

   /*
    * Context handle must be unspecified.  Actually, it must be
    * non-established, but currently, accept_sec_context never returns
    * a non-established context handle.
    */
   /*SUPPRESS 29*/
   if (*context_handle != GSS_C_NO_CONTEXT) {
      *minor_status = 0;
      return(GSS_S_FAILURE);
   }

   /* validate the cred handle - no default */

   /*SUPPRESS 29*/
   if (verifier_cred_handle == GSS_C_NO_CREDENTIAL) {
      *minor_status = 0;
      return(GSS_S_NO_CRED);
   } else {
      OM_uint32 major;
	   
      major = krb5_gss_validate_cred(minor_status, verifier_cred_handle);
      if (GSS_ERROR(major))
	  return(major);
   }

   cred = (krb5_gss_cred_id_t) verifier_cred_handle;

   /* make sure the supplied credentials are valid for accept */

   if ((cred->usage != GSS_C_ACCEPT) &&
       (cred->usage != GSS_C_BOTH)) {
      *minor_status = 0;
      return(GSS_S_NO_CRED);
   }

   /* verify the token's integrity, and leave the token in ap_req.
      figure out which mech oid was used, and save it */

   ptr = (unsigned char *) input_token->value;

   if ((err = g_verify_token_header((gss_OID) gss_mech_krb5, &(ap_req.length),
				    &ptr, KG_TOK_CTX_AP_REQ,
				    input_token->length))) {
	/*
	 * Previous versions of this library used the old mech_id
	 * and some broken behavior (wrong IV on checksum
	 * encryption).  We support the old mech_id for
	 * compatibility, and use it to decide when to use the
	 * old behavior.
	 */
	if (err != G_WRONG_MECH ||
	    (err = g_verify_token_header((gss_OID) gss_mech_krb5_old,
					 &(ap_req.length), 
					 &ptr, KG_TOK_CTX_AP_REQ,
					 input_token->length))) {
	     *minor_status = err;
	     return(GSS_S_DEFECTIVE_TOKEN);
	} else {
	     if (! cred->prerfc_mech) {
		  *minor_status = G_WRONG_MECH;
		  return(GSS_S_DEFECTIVE_TOKEN);
	     }

	     mech_used = gss_mech_krb5_old;
	}
   } else {
	if (! cred->rfc_mech) {
	     *minor_status = G_WRONG_MECH;
	     return(GSS_S_DEFECTIVE_TOKEN);
	}

	mech_used = gss_mech_krb5;
   }

   sptr = (char *) ptr;
   TREAD_STR(sptr, ap_req.data, ap_req.length);
   decode_req_message = 1;

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
			  cred->keytab, NULL, &ticket)))
	   goto fail;

   krb5_auth_con_getauthenticator(context, auth_context, &authdat);

#if 0
   /* make sure the necessary parts of the authdat are present */

   if ((authdat->authenticator->subkey == NULL) ||
       (authdat->ticket->enc_part2 == NULL)) {
	   code = KG_NO_SUBKEY;
	   goto fail;
   }
#endif

   /* verify that the checksum is correct */

   /*
      The checksum may be either exactly 24 bytes, in which case
      no options are specified, or greater than 24 bytes, in which case
      one or more options are specified. Currently, the only valid
      option is KRB5_GSS_FOR_CREDS_OPTION ( = 1 ).
   */

   if ((authdat->checksum->checksum_type != CKSUMTYPE_KG_CB) ||
       (authdat->checksum->length < 24)) {
	   code = 0;
	   major_status = GSS_S_BAD_BINDINGS;
	   goto fail;
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

   if (tmp != krb5_checksum_size(context, CKSUMTYPE_RSA_MD5)) {
      ptr = (unsigned char *) authdat->checksum->contents;
      bigend = 1;

      TREAD_INT(ptr, tmp, bigend);

      if (tmp != krb5_checksum_size(context, CKSUMTYPE_RSA_MD5)) {
	 code = KG_BAD_LENGTH;
	 goto fail;
      }
   }

   /* at this point, bigend is set according to the initiator's byte order */

   if ((code = kg_checksum_channel_bindings(context, input_chan_bindings, &md5,
					    bigend))) 
	   goto fail;

   TREAD_STR(ptr, ptr2, md5.length);
   if (memcmp(ptr2, md5.contents, md5.length) != 0) {
	   code = 0;
	   major_status = GSS_S_BAD_BINDINGS;
	   goto fail;
   }

   xfree(md5.contents);
   md5.contents = 0;

   TREAD_INT(ptr, gss_flags, bigend);
   gss_flags &= ~GSS_C_DELEG_FLAG; /* mask out the delegation flag; if there's
				      a delegation, we'll set it below */
   decode_req_message = 0;

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
						   &auth_context_cred)))
			    goto fail;

		    krb5_auth_con_setflags(context, auth_context_cred, 0);

		    /* store the delegated credential in the user's cache */

		    rd_and_store_for_creds(context, auth_context_cred,
					   &option,
					   (delegated_cred_handle) ?
					   &deleg_cred : NULL);

		    i -= option.length + 4;

		    krb5_auth_con_free(context, auth_context_cred);

		    gss_flags |= GSS_C_DELEG_FLAG; /* got a delegation */

		    break;

		    /* default: */
		    /* unknown options aren't an error */

	    } /* switch */
	} /* while */
    } /* if */
			
   /* create the ctx struct and start filling it in */

   if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
       == NULL) {
	   code = ENOMEM;
	   goto fail;
   }

   memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));
   ctx->mech_used = mech_used;
   ctx->auth_context = auth_context;
   ctx->initiate = 0;
   ctx->gss_flags = KG_IMPLFLAGS(gss_flags);
   ctx->seed_init = 0;
   ctx->big_endian = bigend;

   /* Intern the ctx pointer so that delete_sec_context works */
   if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
	   code = G_VALIDATE_FAILED;
	   xfree(ctx);
	   ctx = 0;
	   goto fail;
   }
   
   if ((code = krb5_copy_principal(context, cred->princ, &ctx->here)))
	   goto fail;

   if ((code = krb5_copy_principal(context, authdat->client, &ctx->there)))
	   goto fail;

   /* done with authdat */
   krb5_free_authenticator(context, authdat);
   authdat = 0;

   if ((code = krb5_auth_con_getremotesubkey(context, auth_context,
					     &ctx->subkey)))
	   goto fail;

   /* use the session key if the subkey isn't present */

   if (ctx->subkey == NULL) {
       if ((code = krb5_auth_con_getkey(context, auth_context,
					&ctx->subkey)))
	       goto fail;
   }

   if (ctx->subkey == NULL) {
       /* this isn't a very good error, but it's not clear to me this
	  can actually happen */
       code = KRB5KDC_ERR_NULL_KEY;
       goto fail;
   }

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
       code = KRB5_BAD_ENCTYPE;
       goto fail;
   }

   /* fill in the encryption descriptors */

   krb5_use_enctype(context, &ctx->enc.eblock, enctype);
   ctx->enc.processed = 0;

   if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc.key)))
	   goto fail;

   for (i=0; i<ctx->enc.key->length; i++)
      /*SUPPRESS 113*/
      ctx->enc.key->contents[i] ^= 0xf0;

   krb5_use_enctype(context, &ctx->seq.eblock, enctype);
   ctx->seq.processed = 0;
   if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->seq.key)))
	   goto fail;

   ctx->endtime = ticket->enc_part2->times.endtime;
   ctx->krb_flags = ticket->enc_part2->flags;

   krb5_free_ticket(context, ticket); /* Done with ticket */

   krb5_auth_con_getremoteseqnumber(context, auth_context, &ctx->seq_recv);

   if ((code = krb5_timeofday(context, &now)))
	   goto fail;

   if (ctx->endtime < now) {
	   code = 0;
	   major_status = GSS_S_CREDENTIALS_EXPIRED;
	   goto fail;
   }

   g_order_init(&(ctx->seqstate), ctx->seq_recv,
		(ctx->gss_flags & GSS_C_REPLAY_FLAG) != 0,
		(ctx->gss_flags & GSS_C_SEQUENCE_FLAG) != 0);

   /* at this point, the entire context structure is filled in, 
      so it can be released.  */

   /* generate an AP_REP if necessary */

   if (ctx->gss_flags & GSS_C_MUTUAL_FLAG) {
      krb5_data ap_rep;
      unsigned char * ptr;
      if ((code = krb5_mk_rep(context, auth_context, &ap_rep)))
	      goto fail;

      krb5_auth_con_getlocalseqnumber(context, auth_context, &ctx->seq_send);
      token.length = g_token_size((gss_OID) mech_used, ap_rep.length);

      if ((token.value = (unsigned char *) xmalloc(token.length)) == NULL) {
	      code = ENOMEM;
	      goto fail;
      }
      ptr = token.value;
      g_make_token_header((gss_OID) mech_used, ap_rep.length,
			  &ptr, KG_TOK_CTX_AP_REP);

      TWRITE_STR(ptr, ap_rep.data, ap_rep.length);
      xfree(ap_rep.data);
   } else {
      token.length = 0;
      token.value = NULL;
      ctx->seq_send = ctx->seq_recv;
   }

   /* set the return arguments */

   if (src_name) {
      if ((code = krb5_copy_principal(context, ctx->there, &name)))
	      goto fail;
      /* intern the src_name */
      if (! kg_save_name((gss_name_t) name)) {
	      code = G_VALIDATE_FAILED;
	      goto fail;
      }
   }

   if (mech_type)
      *mech_type = (gss_OID) mech_used;

   if (time_rec)
      *time_rec = ctx->endtime - now;

   if (ret_flags)
      *ret_flags = ctx->gss_flags;

   ctx->established = 1;
   *context_handle = ctx;
   *output_token = token;

   if (src_name)
      *src_name = (gss_name_t) name;

   if (delegated_cred_handle && deleg_cred) {
     if (!kg_save_cred_id((gss_cred_id_t) deleg_cred)) {
       code = G_VALIDATE_FAILED;
       goto fail;
     }

     *delegated_cred_handle = (gss_cred_id_t) deleg_cred;
   }

   /* finally! */

   *minor_status = 0;
   return(GSS_S_COMPLETE);

fail:
   if (authdat)
	   krb5_free_authenticator(context, authdat);
   if (ctx)
	   (void) krb5_gss_delete_sec_context(minor_status, 
					      (gss_ctx_id_t *) &ctx, NULL);
   if (token.value)
	   xfree(token.value);
   if (name) {
	 (void) kg_delete_name((gss_name_t) name);
	 krb5_free_principal(context, name);
   }
   if (md5.contents)
	 xfree(md5.contents);
   if (deleg_cred) { /* free memory associated with the deleg credential */
     if (deleg_cred->ccache)
       (void)krb5_cc_close(context, deleg_cred->ccache);
     if (deleg_cred->princ)
       krb5_free_principal(context, deleg_cred->princ);
     xfree(deleg_cred);
   }

   *minor_status = code;

   /*
    * If decode_req_message is set, then we need to decode the ap_req
    * message to determine whether or not to send a response token.
    * We need to do this because for some errors we won't be able to
    * decode the authenticator to read out the gss_flags field.
    */
   if (decode_req_message) {
	   krb5_ap_req 	* request;
	   
	   if (decode_krb5_ap_req(&ap_req, &request))
		   return (major_status);
	   if (request->ap_options & AP_OPTS_MUTUAL_REQUIRED)
		   gss_flags |= GSS_C_MUTUAL_FLAG;
	   krb5_free_ap_req(context, request);
   }

   if (gss_flags & GSS_C_MUTUAL_FLAG) {
	   /*
	    * The client is expecting a response, so we can send an
	    * error token back
	    */
	   memset(&krb_error_data, 0, sizeof(krb_error_data));

	   code  -= ERROR_TABLE_BASE_krb5;
	   if (code < 0 || code > 128)
		   code = 60 /* KRB_ERR_GENERIC */;

	   krb_error_data.error = code;
	   (void) krb5_us_timeofday(context, &krb_error_data.stime,
				    &krb_error_data.susec);
	   krb_error_data.server = cred->princ;
	   
	   code = krb5_mk_error(context, &krb_error_data, &scratch);
	   if (code)
		   return (major_status);

	   token.length = g_token_size((gss_OID) mech_used, scratch.length);
	   token.value = (unsigned char *) xmalloc(token.length);
	   if (!token.value)
		   return (major_status);

	   ptr = token.value;
	   g_make_token_header((gss_OID) mech_used, scratch.length,
			       &ptr, KG_TOK_CTX_ERROR);

	   TWRITE_STR(ptr, scratch.data, scratch.length);
	   xfree(scratch.data);

	   *output_token = token;
   }
   return (major_status);
}

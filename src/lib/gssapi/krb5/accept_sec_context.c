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
rd_and_store_for_creds(context, inbuf, out_cred)
    krb5_context context;
    krb5_data *inbuf;
    krb5_gss_cred_id_t *out_cred;
{
    krb5_creds ** creds;
    krb5_error_code retval;
    krb5_ccache ccache;
    krb5_gss_cred_id_t cred = NULL;
    extern krb5_cc_ops krb5_mcc_ops;
    krb5_auth_context auth_context = NULL;

    if ((retval = krb5_auth_con_init(context, &auth_context)))
	return(retval);

    krb5_auth_con_setflags(context, auth_context, 0);

    if ((retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL))) 
	goto cleanup;

    /* Lots of kludging going on here... Some day the ccache interface
       will be rewritten though */

    krb5_cc_register(context, &krb5_mcc_ops, 0);
    if ((retval = krb5_cc_resolve(context, "MEMORY:GSSAPI", &ccache)))
        goto cleanup;

    if ((retval = krb5_cc_gen_new(context, &ccache)))
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
	cred->prerfc_mech = 1; /* this cred will work with all three mechs */
	cred->rfc_mech = 1;
	cred->rfcv2_mech = 1; 
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

    if (auth_context)
	krb5_auth_con_free(context, auth_context);

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
   size_t md5len;
   int bigend;
   krb5_gss_cred_id_t cred = 0;
   krb5_data ap_rep, ap_req, mic;
   int i;
   krb5_error_code code;
   krb5_address addr, *paddr;
   krb5_authenticator *authdat = 0;
   krb5_checksum reqcksum;
   krb5_principal name = NULL;
   krb5_ui_4 gss_flags = 0;
   int decode_req_message = 0;
   krb5_gss_ctx_id_rec *ctx = 0;
   krb5_enctype enctype;
   krb5_timestamp now;
   gss_buffer_desc token;
   int err;
   krb5_auth_context auth_context = NULL;
   krb5_ticket * ticket = NULL;
   int option_id;
   krb5_data option, cksumdata;
   const gss_OID_desc *mech_used = NULL;
   OM_uint32 major_status = GSS_S_FAILURE;
   krb5_error krb_error_data;
   krb5_data scratch;
   gss_cred_id_t cred_handle = NULL;
   krb5_gss_cred_id_t deleg_cred = NULL;
   int token_length;
   int gsskrb5_vers;
   int nctypes;
   krb5_cksumtype *ctypes;
   struct kg2_option fwcred;

   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);

   /* set up returns to be freeable */

   if (src_name)
      *src_name = (gss_name_t) NULL;
   output_token->length = 0;
   output_token->value = NULL;
   token.value = 0;
   reqcksum.contents = 0;
   mic.data = 0;
   ap_req.data = 0;
   ap_rep.data = 0;
   cksumdata.data = 0;
   
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

   /* handle default cred handle */
   if (verifier_cred_handle == GSS_C_NO_CREDENTIAL) {
       major_status = krb5_gss_acquire_cred(&code, GSS_C_NO_NAME,
					    GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
					    GSS_C_ACCEPT, &cred_handle,
					    NULL, NULL);
       if (major_status != GSS_S_COMPLETE)
	   goto fail;
   } else {
       cred_handle = verifier_cred_handle;
   }

   major_status = krb5_gss_validate_cred(&code, verifier_cred_handle);
   if (GSS_ERROR(major_status))
       goto fail;

   cred = (krb5_gss_cred_id_t) cred_handle;

   /* make sure the supplied credentials are valid for accept */

   if ((cred->usage != GSS_C_ACCEPT) &&
       (cred->usage != GSS_C_BOTH)) {
       code = 0;
       major_status = GSS_S_NO_CRED;
       goto fail;
   }

   /* verify the token's integrity, and leave the token in ap_req.
      figure out which mech oid was used, and save it */

   ptr = (unsigned char *) input_token->value;

   if (!(code = g_verify_token_header((gss_OID) gss_mech_krb5,
				      &(ap_req.length),
				      &ptr, KG_TOK_CTX_AP_REQ,
				      input_token->length))) {
       if (! cred->rfc_mech) {
	   code = G_WRONG_MECH;
	   major_status = GSS_S_DEFECTIVE_TOKEN;
	   goto fail;
       }
       mech_used = gss_mech_krb5;
       gsskrb5_vers = 1000;
   } else if ((code == G_WRONG_MECH) &&
	      !(code = g_verify_token_header((gss_OID) gss_mech_krb5_old,
					     &(ap_req.length), 
					     &ptr, KG_TOK_CTX_AP_REQ,
					     input_token->length))) {
       /*
	* Previous versions of this library used the old mech_id
	* and some broken behavior (wrong IV on checksum
	* encryption).  We support the old mech_id for
	* compatibility, and use it to decide when to use the
	* old behavior.
	*/
       if (! cred->prerfc_mech) {
	   code = G_WRONG_MECH;
	   major_status = GSS_S_DEFECTIVE_TOKEN;
	   goto fail;
       }
       mech_used = gss_mech_krb5_old;
       gsskrb5_vers = 1000;
   } else if ((code == G_WRONG_MECH) &&
	      !(code = g_verify_token_header((gss_OID) gss_mech_krb5_v2,
					     &token_length, 
					     &ptr, KG2_TOK_INITIAL,
					     input_token->length))) {
       if (! cred->rfcv2_mech) {
	   code = G_WRONG_MECH;
	   major_status = GSS_S_DEFECTIVE_TOKEN;
	   goto fail;
       }
       mech_used = gss_mech_krb5_v2;
       gsskrb5_vers = 2000;
   } else {
       major_status = GSS_S_DEFECTIVE_TOKEN;
       goto fail;
   }

   if (gsskrb5_vers == 2000) {
       /* gss krb5 v2 */

       fwcred.option_id = KRB5_GSS_FOR_CREDS_OPTION;
       fwcred.data = NULL;

       if (GSS_ERROR(major_status =
		     kg2_parse_token(&code, ptr, token_length,
				     &gss_flags, &nctypes, &ctypes,
				     delegated_cred_handle?1:0,
				     &fwcred, &ap_req, NULL))) {
	   goto fail;
       }

       gss_flags = (ptr[0]<<24) | (ptr[1]<<16) | (ptr[2]<<8) | ptr[3];

       gss_flags &= ~GSS_C_DELEG_FLAG; /* mask out the delegation flag;
					  if there's a delegation, we'll
					  set it below */
   } else {
       /* gss krb5 v1 */

       sptr = (char *) ptr;
       TREAD_STR(sptr, ap_req.data, ap_req.length);
       decode_req_message = 1;
   }

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

   if ((code = krb5_auth_con_init(context, &auth_context))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }
   if ((code = krb5_auth_con_setrcache(context, auth_context, cred->rcache))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }
   if ((code = krb5_auth_con_setaddrs(context, auth_context, NULL, paddr))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_rd_req(context, &auth_context, &ap_req, cred->princ,
			   cred->keytab, NULL, &ticket))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   krb5_auth_con_getauthenticator(context, auth_context, &authdat);

#if 0
   /* make sure the necessary parts of the authdat are present */

   if ((authdat->authenticator->subkey == NULL) ||
       (authdat->ticket->enc_part2 == NULL)) {
	   code = KG_NO_SUBKEY;
	   major_status = GSS_S_FAILURE;
	   goto fail;
   }
#endif

   if (gsskrb5_vers == 2000) {
       bigend = 1;
   } else {
       /* gss krb5 v1 */

       /* stash this now, for later. */
       if (code = krb5_c_checksum_length(context, CKSUMTYPE_RSA_MD5,
					 &md5len)) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

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

       if (tmp != md5len) {
	   ptr = (unsigned char *) authdat->checksum->contents;
	   bigend = 1;

	   TREAD_INT(ptr, tmp, bigend);

	   if (tmp != md5len) {
	       code = KG_BAD_LENGTH;
	       major_status = GSS_S_FAILURE;
	       goto fail;
	   }
       }

       /* at this point, bigend is set according to the initiator's
	  byte order */

       if ((code = kg_checksum_channel_bindings(context, input_chan_bindings,
						&reqcksum, bigend))) {
	   major_status = GSS_S_BAD_BINDINGS;
	   goto fail;
       }

       TREAD_STR(ptr, ptr2, reqcksum.length);
       if (memcmp(ptr2, reqcksum.contents, reqcksum.length) != 0) {
	   code = 0;
	   major_status = GSS_S_BAD_BINDINGS;
	   goto fail;
       }

       xfree(reqcksum.contents);
       reqcksum.contents = 0;

       TREAD_INT(ptr, gss_flags, bigend);
       gss_flags &= ~GSS_C_DELEG_FLAG; /* mask out the delegation flag; if
					  there's a delegation, we'll set
					  it below */
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

		   /* store the delegated credential */

		   if (code = rd_and_store_for_creds(context, &option,
						     (delegated_cred_handle) ?
						     &deleg_cred : NULL)) {
		       major_status = GSS_S_FAILURE;
		       goto fail;
		   }

		   i -= option.length + 4;

		   gss_flags |= GSS_C_DELEG_FLAG; /* got a delegation */

		   break;

		   /* default: */
		   /* unknown options aren't an error */

	       } /* switch */
	   } /* while */
       } /* if */
   }

   /* create the ctx struct and start filling it in */

   if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
       == NULL) {
       code = ENOMEM;
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));
   ctx->mech_used = mech_used;
   ctx->auth_context = auth_context;
   ctx->initiate = 0;
   ctx->gss_flags = KG_IMPLFLAGS(gss_flags);
   ctx->seed_init = 0;
   ctx->big_endian = bigend;
   ctx->gsskrb5_version = gsskrb5_vers;

   /* Intern the ctx pointer so that delete_sec_context works */
   if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
       xfree(ctx);
       ctx = 0;

       code = G_VALIDATE_FAILED;
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_copy_principal(context, cred->princ, &ctx->here))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_copy_principal(context, authdat->client, &ctx->there))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_auth_con_getremotesubkey(context, auth_context,
					     &ctx->subkey))) { 
       major_status = GSS_S_FAILURE;      
       goto fail;
   }

   /* use the session key if the subkey isn't present */

   if (ctx->subkey == NULL) {
       if ((code = krb5_auth_con_getkey(context, auth_context,
					&ctx->subkey))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
   }

   if (ctx->subkey == NULL) {
       /* this isn't a very good error, but it's not clear to me this
	  can actually happen */
       major_status = GSS_S_FAILURE;
       code = KRB5KDC_ERR_NULL_KEY;
       goto fail;
   }

   if (gsskrb5_vers == 2000) {
       int cblen;
       krb5_boolean valid;

       /* intersect the token ctypes with the local ctypes */

       if (code = krb5_c_keyed_checksum_types(context, ctx->subkey->enctype,
					      &ctx->nctypes, &ctx->ctypes))
	   goto fail;

       if (nctypes == 0) {
	   code = KRB5_CRYPTO_INTERNAL;
	   goto fail;
       }

       kg2_intersect_ctypes(&ctx->nctypes, ctx->ctypes, nctypes, ctypes);

       if (nctypes == 0) {
	   code = KG_NO_CTYPES;
	   goto fail;
       }

       /* process the delegated cred, if any */

       if (fwcred.data) {
	   krb5_data option;

	   option.length = fwcred.length;
	   option.data = fwcred.data;

	   if (code = rd_and_store_for_creds(context, &option, &deleg_cred)) {
	       major_status = GSS_S_FAILURE;
	       goto fail;
	   }

	   gss_flags |= GSS_C_DELEG_FLAG; /* got a delegation */
       }

       /* construct the checksum buffer */

       cblen = 4*5;
       if (input_chan_bindings)
	   cblen += (input_chan_bindings->initiator_address.length+
		     input_chan_bindings->acceptor_address.length+
		     input_chan_bindings->application_data.length);

       cksumdata.length = cblen + ((char *)(ap_req.data-2) - (char *)(ptr-2));

       if ((cksumdata.data = (char *) malloc(cksumdata.length)) == NULL) {
	   code = ENOMEM;
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       ptr2 = cksumdata.data;

       if (input_chan_bindings) {
	   TWRITE_INT(ptr2, input_chan_bindings->initiator_addrtype, 1);
	   TWRITE_BUF(ptr2, input_chan_bindings->initiator_address, 1);
	   TWRITE_INT(ptr2, input_chan_bindings->acceptor_addrtype, 1);
	   TWRITE_BUF(ptr2, input_chan_bindings->acceptor_address, 1);
	   TWRITE_BUF(ptr2, input_chan_bindings->application_data, 1);
       } else {
	   memset(ptr2, 0, cblen);
	   ptr2 += cblen;
       }

       memcpy(ptr2, ptr-2, ((char *)(ap_req.data-2) - (char *)(ptr-2)));

       if (code = krb5_c_verify_checksum(context, ctx->subkey,
					 KRB5_KEYUSAGE_AP_REQ_AUTH_CKSUM,
					 &cksumdata, authdat->checksum,
					 &valid)) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       free(cksumdata.data);
       cksumdata.data = 0;

       if (!valid) {
	   code = 0;
	   major_status = GSS_S_BAD_SIG;
	   goto fail;
       }
   } else {
       /* gss krb5 v1 */

       switch(ctx->subkey->enctype) {
       case ENCTYPE_DES_CBC_MD5:
       case ENCTYPE_DES_CBC_CRC:
	   ctx->subkey->enctype = ENCTYPE_DES_CBC_RAW;
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

       if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       for (i=0; i<ctx->enc->length; i++)
	   /*SUPPRESS 113*/
	   ctx->enc->contents[i] ^= 0xf0;

       if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->seq))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
   }

   ctx->endtime = ticket->enc_part2->times.endtime;
   ctx->krb_flags = ticket->enc_part2->flags;

   krb5_free_ticket(context, ticket); /* Done with ticket */

   krb5_auth_con_getremoteseqnumber(context, auth_context, &ctx->seq_recv);

   if ((code = krb5_timeofday(context, &now))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }

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
       unsigned char * ptr;
       if ((code = krb5_mk_rep(context, auth_context, &ap_rep))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       krb5_auth_con_getlocalseqnumber(context, auth_context,
				       &ctx->seq_send);

       /* the reply token hasn't been sent yet, but that's ok. */
       ctx->established = 1;

       if (ctx->gsskrb5_version == 2000) {
	   krb5_ui_4 tok_flags;

	   tok_flags =
	       (ctx->gss_flags & GSS_C_DELEG_FLAG)?KG2_RESP_FLAG_DELEG_OK:0;

	   cksumdata.length = 8 + 4*ctx->nctypes + 4;

	   if ((cksumdata.data = (char *) malloc(cksumdata.length)) == NULL) {
	       code = ENOMEM;
	       major_status = GSS_S_FAILURE;
	       goto fail;
	   }

	   /* construct the token fields */

	   ptr = cksumdata.data;

	   ptr[0] = (KG2_TOK_RESPONSE >> 8) & 0xff;
	   ptr[1] = KG2_TOK_RESPONSE & 0xff;

	   ptr[2] = (tok_flags >> 24) & 0xff;
	   ptr[3] = (tok_flags >> 16) & 0xff;
	   ptr[4] = (tok_flags >> 8) & 0xff;
	   ptr[5] = tok_flags & 0xff;

	   ptr[6] = (ctx->nctypes >> 8) & 0xff;
	   ptr[7] = ctx->nctypes & 0xff;

	   ptr += 8;

	   for (i=0; i<ctx->nctypes; i++) {
	       ptr[i] = (ctx->ctypes[i] >> 24) & 0xff;
	       ptr[i+1] = (ctx->ctypes[i] >> 16) & 0xff;
	       ptr[i+2] = (ctx->ctypes[i] >> 8) & 0xff;
	       ptr[i+3] = ctx->ctypes[i] & 0xff;

	       ptr += 4;
	   }

	   memset(ptr, 0, 4);

	   /* make the MIC token */

	   {
	       gss_buffer_desc text, token;

	       text.length = cksumdata.length;
	       text.value = cksumdata.data;

	       /* ctx->seq_send must be set before this call */

	       if (GSS_ERROR(major_status =
			     krb5_gss_get_mic(&code, ctx,
					      GSS_C_QOP_DEFAULT,
					      &text, &token)))
		   goto fail;

	       mic.length = token.length;
	       mic.data = token.value;
	   }

	   token.length = g_token_size((gss_OID) mech_used,
				       (cksumdata.length-2)+4+ap_rep.length+
				       mic.length);

	   if ((token.value = (unsigned char *) xmalloc(token.length))
	       == NULL) {
	       code = ENOMEM;
	       major_status = GSS_S_FAILURE;
	       goto fail;
	   }
	   ptr = token.value;
	   g_make_token_header((gss_OID) mech_used,
			       (cksumdata.length-2)+4+ap_rep.length+mic.length,
			       &ptr, KG2_TOK_RESPONSE);

	   memcpy(ptr, cksumdata.data+2, cksumdata.length-2);
	   ptr += cksumdata.length-2;

	   ptr[0] = (ap_rep.length >> 8) & 0xff;
	   ptr[1] = ap_rep.length & 0xff;
	   memcpy(ptr+2, ap_rep.data, ap_rep.length);

	   ptr += (2+ap_rep.length);

	   ptr[0] = (mic.length >> 8) & 0xff;
	   ptr[1] = mic.length & 0xff;
	   memcpy(ptr+2, mic.data, mic.length);

	   ptr += (2+mic.length);

	   free(cksumdata.data);
	   cksumdata.data = 0;

	   /* gss krb5 v2 */
       } else {
	   /* gss krb5 v1 */

	   token.length = g_token_size((gss_OID) mech_used, ap_rep.length);

	   if ((token.value = (unsigned char *) xmalloc(token.length))
	       == NULL) {
	       major_status = GSS_S_FAILURE;
	       code = ENOMEM;
	       goto fail;
	   }
	   ptr = token.value;
	   g_make_token_header((gss_OID) mech_used, ap_rep.length,
			       &ptr, KG_TOK_CTX_AP_REP);

	   TWRITE_STR(ptr, ap_rep.data, ap_rep.length);
	   xfree(ap_rep.data);

	   ctx->established = 1;

       }
   } else {
       token.length = 0;
       token.value = NULL;
       ctx->seq_send = ctx->seq_recv;

       ctx->established = 1;
   }

   /* set the return arguments */

   if (src_name) {
       if ((code = krb5_copy_principal(context, ctx->there, &name))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
       /* intern the src_name */
       if (! kg_save_name((gss_name_t) name)) {
	   code = G_VALIDATE_FAILED;
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
   }

   if (mech_type)
      *mech_type = (gss_OID) mech_used;

   if (time_rec)
      *time_rec = ctx->endtime - now;

   if (ret_flags)
      *ret_flags = ctx->gss_flags;

   *context_handle = ctx;
   *output_token = token;

   if (src_name)
      *src_name = (gss_name_t) name;

   if (delegated_cred_handle && deleg_cred) {
       if (!kg_save_cred_id((gss_cred_id_t) deleg_cred)) {
	   major_status = GSS_S_FAILURE;
	   code = G_VALIDATE_FAILED;
	   goto fail;
       }

       *delegated_cred_handle = (gss_cred_id_t) deleg_cred;
   }

   /* finally! */

   *minor_status = 0;
   major_status = GSS_S_COMPLETE;

 fail:
   if (ctypes)
       free(ctypes);
   if (authdat)
       krb5_free_authenticator(context, authdat);
   if (reqcksum.contents)
       xfree(reqcksum.contents);
   if (ap_rep.data)
       xfree(ap_rep.data);
   if (mic.data)
       xfree(mic.data);
   if (cksumdata.data)
       xfree(cksumdata.data);

   if (!GSS_ERROR(major_status))
       return(major_status);

   /* from here on is the real "fail" code */

   if (ctx)
       (void) krb5_gss_delete_sec_context(minor_status, 
					  (gss_ctx_id_t *) &ctx, NULL);
   if (deleg_cred) { /* free memory associated with the deleg credential */
       if (deleg_cred->ccache)
	   (void)krb5_cc_close(context, deleg_cred->ccache);
       if (deleg_cred->princ)
	   krb5_free_principal(context, deleg_cred->princ);
       xfree(deleg_cred);
   }
   if (token.value)
       xfree(token.value);
   if (name) {
       (void) kg_delete_name((gss_name_t) name);
       krb5_free_principal(context, name);
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

   if (cred && (gss_flags & GSS_C_MUTUAL_FLAG)) {
       int tmsglen, toktype;

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

       if (gsskrb5_vers == 2000) {
	   tmsglen = 12+scratch.length;
	   toktype = KG2_TOK_RESPONSE;
       } else {
	   tmsglen = scratch.length;
	   toktype = KG_TOK_CTX_ERROR;
       }

       token.length = g_token_size((gss_OID) mech_used, tmsglen);
       token.value = (unsigned char *) xmalloc(token.length);
       if (!token.value)
	   return (major_status);

       ptr = token.value;
       g_make_token_header((gss_OID) mech_used, tmsglen, &ptr, toktype);

       if (gsskrb5_vers == 2000) {
	   krb5_ui_4 flags;

	   flags = KG2_RESP_FLAG_ERROR;

	   ptr[0] = (flags << 24) & 0xff;
	   ptr[1] = (flags << 16) & 0xff;
	   ptr[2] = (flags << 8) & 0xff;
	   ptr[3] = flags & 0xff;

	   memset(ptr+4, 0, 6);

	   ptr[10] = (scratch.length << 8) & 0xff;
	   ptr[11] = scratch.length & 0xff;

	   ptr += 12;
       }

       TWRITE_STR(ptr, scratch.data, scratch.length);
       xfree(scratch.data);

       *output_token = token;
   }
   if (!verifier_cred_handle && cred_handle) {
	   krb5_gss_release_cred(&code, cred_handle);
   }
   return (major_status);
}

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
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
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

/*
 * Common code which fetches the correct krb5 credentials from the
 * ccache.
 */
static krb5_error_code get_credentials(context, cred, server, now,
				       endtime, enctype, out_creds)
    krb5_context context;
    krb5_gss_cred_id_t cred;
    krb5_principal server;
    krb5_timestamp now;
    krb5_timestamp endtime;
    krb5_enctype enctype;
    krb5_creds **out_creds;
{
    krb5_error_code	code;
    krb5_creds 		in_creds;
    
    memset((char *) &in_creds, 0, sizeof(krb5_creds));

    if ((code = krb5_copy_principal(context, cred->princ, &in_creds.client)))
	goto cleanup;
    if ((code = krb5_copy_principal(context, server, &in_creds.server)))
	goto cleanup;
    in_creds.times.endtime = endtime;
    in_creds.keyblock.enctype = enctype;

    if ((code = krb5_get_credentials(context, 0, cred->ccache, 
				     &in_creds, out_creds)))
	goto cleanup;

    /*
     * Enforce a stricter limit (without timeskew forgiveness at the
     * boundaries) because accept_sec_context code is also similarly
     * non-forgiving.
     */
    if (!krb5_gss_dbg_client_expcreds && (*out_creds)->times.endtime < now) {
	code = KRB5KRB_AP_ERR_TKT_EXPIRED;
	goto cleanup;
    }
    
cleanup:
    if (in_creds.client)
	    krb5_free_principal(context, in_creds.client);
    if (in_creds.server)
	    krb5_free_principal(context, in_creds.server);
    return code;
}


static krb5_error_code
make_ap_req_v2(context, ctx, cred, k_cred, chan_bindings, mech_type, token)
    krb5_context context;
    krb5_gss_ctx_id_rec *ctx;
    krb5_creds *k_cred;
    krb5_gss_cred_id_t cred;
    gss_channel_bindings_t chan_bindings;
    gss_OID mech_type;
    gss_buffer_t token;
{
    krb5_flags mk_req_flags = 0;
    krb5_int32 con_flags;
    krb5_error_code code;
    krb5_data credmsg, cksumdata, ap_req;
    int i, tlen, cblen, nctypes;
    krb5_cksumtype *ctypes;
    unsigned char *t, *ptr;

    credmsg.data = 0;
    cksumdata.data = 0;
    ap_req.data = 0;
    ctypes = 0;

    /* create the option data if necessary */
    if (ctx->gss_flags & GSS_C_DELEG_FLAG) {
	/* first get KRB_CRED message, so we know its length */

	/* clear the time check flag that was set in krb5_auth_con_init() */
	krb5_auth_con_getflags(context, ctx->auth_context, &con_flags);
	krb5_auth_con_setflags(context, ctx->auth_context,
			       con_flags & ~KRB5_AUTH_CONTEXT_DO_TIME);

	code = krb5_fwd_tgt_creds(context, ctx->auth_context, 0,
				  cred->princ, ctx->there, cred->ccache, 1,
				  &credmsg);

	/* turn KRB5_AUTH_CONTEXT_DO_TIME back on */
	krb5_auth_con_setflags(context, ctx->auth_context, con_flags);

	if (code) {
	    /* don't fail here; just don't accept/do the delegation
               request */
	    ctx->gss_flags &= ~GSS_C_DELEG_FLAG;
	} else {
	    if (credmsg.length > KRB5_INT16_MAX) {
		krb5_free_data_contents(context, &credmsg);
		return(KRB5KRB_ERR_FIELD_TOOLONG);
	    }
	}
    } else {
       credmsg.length = 0;
    }
       
    /* construct the list of compatible cksum types */

    if ((code = krb5_c_keyed_checksum_types(context,
					    k_cred->keyblock.enctype,
					    &nctypes, &ctypes)))
	goto cleanup;

    if (nctypes == 0) {
	code = KRB5_CRYPTO_INTERNAL;
	goto cleanup;
    }

    /* construct the checksum fields */

    cblen = 4*5;
    if (chan_bindings)
	cblen += (chan_bindings->initiator_address.length+
		  chan_bindings->acceptor_address.length+
		  chan_bindings->application_data.length);

    cksumdata.length = cblen + 8 + 4*nctypes + 4;
    if (credmsg.length)
	cksumdata.length += 4 + credmsg.length;

    if ((cksumdata.data = (char *) malloc(cksumdata.length)) == NULL)
	goto cleanup;

    /* helper macros.  This code currently depends on a long being 32
       bits, and htonl dtrt. */

    ptr = cksumdata.data;

    if (chan_bindings) {
	TWRITE_INT(ptr, chan_bindings->initiator_addrtype, 1);
	TWRITE_BUF(ptr, chan_bindings->initiator_address, 1);
	TWRITE_INT(ptr, chan_bindings->acceptor_addrtype, 1);
	TWRITE_BUF(ptr, chan_bindings->acceptor_address, 1);
	TWRITE_BUF(ptr, chan_bindings->application_data, 1);
    } else {
	memset(ptr, 0, cblen);
	ptr += cblen;
    }

    /* construct the token fields */

    ptr[0] = (KG2_TOK_INITIAL >> 8) & 0xff;
    ptr[1] = KG2_TOK_INITIAL & 0xff;

    ptr[2] = (ctx->gss_flags >> 24) & 0xff;
    ptr[3] = (ctx->gss_flags >> 16) & 0xff;
    ptr[4] = (ctx->gss_flags >> 8) & 0xff;
    ptr[5] = ctx->gss_flags & 0xff;

    ptr[6] = (nctypes >> 8) & 0xff;
    ptr[7] = nctypes & 0xff;

    ptr += 8;

    for (i=0; i<nctypes; i++) {
	ptr[0] = (ctypes[i] >> 24) & 0xff;
	ptr[1] = (ctypes[i] >> 16) & 0xff;
	ptr[2] = (ctypes[i] >> 8) & 0xff;
	ptr[3] = ctypes[i] & 0xff;

	ptr += 4;
    }

    if (credmsg.length) {
	ptr[0] = (KRB5_GSS_FOR_CREDS_OPTION >> 8) & 0xff;
	ptr[1] = KRB5_GSS_FOR_CREDS_OPTION & 0xff;

	ptr[2] = (credmsg.length >> 8) & 0xff;
	ptr[3] = credmsg.length & 0xff;

	ptr += 4;

	memcpy(ptr, credmsg.data, credmsg.length);

	ptr += credmsg.length;
    }

    memset(ptr, 0, 4);

    /* call mk_req.  subkey and ap_req need to be used or destroyed */

    mk_req_flags = AP_OPTS_USE_SUBKEY;

    if (ctx->gss_flags & GSS_C_MUTUAL_FLAG)
	mk_req_flags |= AP_OPTS_MUTUAL_REQUIRED;

    if ((code = krb5_mk_req_extended(context, &ctx->auth_context, mk_req_flags,
				     &cksumdata, k_cred, &ap_req)))
	goto cleanup;

   /* store the interesting stuff from creds and authent */
   ctx->endtime = k_cred->times.endtime;
   ctx->krb_flags = k_cred->ticket_flags;

   /* build up the token */

   /* allocate space for the token */
   tlen = g_token_size((gss_OID) mech_type,
		       (cksumdata.length-(2+cblen))+2+ap_req.length);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL) {
      code = ENOMEM;
      goto cleanup;
   }

   ptr = t;

   g_make_token_header((gss_OID) mech_type,
		       (cksumdata.length-(2+cblen))+2+ap_req.length,
		       &ptr, KG2_TOK_INITIAL);

   /* skip over the channel bindings and the token id */
   memcpy(ptr, cksumdata.data+cblen+2, cksumdata.length-(cblen+2));
   ptr += cksumdata.length-(cblen+2);
   ptr[0] = (ap_req.length >> 8) & 0xff;
   ptr[1] = ap_req.length & 0xff;
   ptr += 2;
   memcpy(ptr, ap_req.data, ap_req.length);

   /* pass allocated data back */

   ctx->nctypes = nctypes;
   ctx->ctypes = ctypes;

   token->length = tlen;
   token->value = (void *) t;

   code = 0;

cleanup:
   if (code) {
       if (ctypes)
	   krb5_free_cksumtypes(context, ctypes);
   }

   if (credmsg.data)
       free(credmsg.data);
   if (ap_req.data)
       free(ap_req.data);
   if (cksumdata.data)
       free(cksumdata.data);

   return(code);
}

static krb5_error_code
make_ap_req_v1(context, ctx, cred, k_cred, chan_bindings, mech_type, token)
    krb5_context context;
    krb5_gss_ctx_id_rec *ctx;
    krb5_gss_cred_id_t cred;
    krb5_creds *k_cred;
    gss_channel_bindings_t chan_bindings;
    gss_OID mech_type;
    gss_buffer_t token;
{
    krb5_flags mk_req_flags = 0;
    krb5_error_code code;
    krb5_data checksum_data;
    krb5_checksum md5;
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

    krb5_auth_con_set_req_cksumtype(context, ctx->auth_context,
				    CKSUMTYPE_KG_CB);

    /* build the checksum field */

    if (ctx->gss_flags & GSS_C_DELEG_FLAG) {
	/* first get KRB_CRED message, so we know its length */

	/* clear the time check flag that was set in krb5_auth_con_init() */
	krb5_auth_con_getflags(context, ctx->auth_context, &con_flags);
	krb5_auth_con_setflags(context, ctx->auth_context,
			       con_flags & ~KRB5_AUTH_CONTEXT_DO_TIME);

	code = krb5_fwd_tgt_creds(context, ctx->auth_context, 0,
				  cred->princ, ctx->there, cred->ccache, 1,
				  &credmsg);

	/* turn KRB5_AUTH_CONTEXT_DO_TIME back on */
	krb5_auth_con_setflags(context, ctx->auth_context, con_flags);

	if (code) {
	    /* don't fail here; just don't accept/do the delegation
               request */
	    ctx->gss_flags &= ~GSS_C_DELEG_FLAG;

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
    TWRITE_INT(ptr, ctx->gss_flags, 0);

    /* done with this, free it */
    xfree(md5.contents);

    if (credmsg.data) {
	TWRITE_INT16(ptr, KRB5_GSS_FOR_CREDS_OPTION, 0);
	TWRITE_INT16(ptr, credmsg.length, 0);
	TWRITE_STR(ptr, (unsigned char *) credmsg.data, credmsg.length);

	/* free credmsg data */
	krb5_free_data_contents(context, &credmsg);
    }

    /* call mk_req.  subkey and ap_req need to be used or destroyed */

    mk_req_flags = AP_OPTS_USE_SUBKEY;

    if (ctx->gss_flags & GSS_C_MUTUAL_FLAG)
	mk_req_flags |= AP_OPTS_MUTUAL_REQUIRED;

    if ((code = krb5_mk_req_extended(context, &ctx->auth_context, mk_req_flags,
				     &checksum_data, k_cred, &ap_req)))
	goto cleanup;

   /* store the interesting stuff from creds and authent */
   ctx->endtime = k_cred->times.endtime;
   ctx->krb_flags = k_cred->ticket_flags;

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
   if (ap_req.data)
       xfree(ap_req.data);

   return (code);
}

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
   krb5_creds *k_cred = 0;
   krb5_enctype enctype = 0;
   krb5_error_code code; 
   krb5_gss_ctx_id_rec *ctx, *ctx_free;
   krb5_timestamp now;
   gss_buffer_desc token;
   int gsskrb5_vers = 0;
   int i, err;
   int default_mech = 0;
   krb5_ui_4 resp_flags;
   OM_uint32 major_status;

   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);

   /* set up return values so they can be "freed" successfully */

   major_status = GSS_S_FAILURE; /* Default major code */
   output_token->length = 0;
   output_token->value = NULL;
   if (actual_mech_type)
      *actual_mech_type = NULL;
   token.value = 0;
   ctx_free = 0;

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
       default_mech = 1;
       if (cred->rfcv2_mech) {
	   mech_type = gss_mech_krb5_v2;
	   gsskrb5_vers = 2000;
       } else if (cred->rfc_mech) {
	   mech_type = gss_mech_krb5;
	   gsskrb5_vers = 1000;
	   enctype = ENCTYPE_DES_CBC_CRC;
       } else if (cred->prerfc_mech) {
	   mech_type = gss_mech_krb5_old;
	   gsskrb5_vers = 1000;
	   enctype = ENCTYPE_DES_CBC_CRC;
       } else {
	   err = 1;
       }
   } else if (g_OID_equal(mech_type, gss_mech_krb5_v2)) {
       if (!cred->rfcv2_mech)
	   err = 1;
       gsskrb5_vers = 2000;
   } else if (g_OID_equal(mech_type, gss_mech_krb5)) {
       if (!cred->rfc_mech)
	   err = 1;
       gsskrb5_vers = 1000;
   } else if (g_OID_equal(mech_type, gss_mech_krb5_old)) {
       if (!cred->prerfc_mech)
	   err = 1;
       gsskrb5_vers = 1000;
   } else {
       err = 1;
   }
   
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
      ctx_free = ctx;
      if ((code = krb5_auth_con_init(context, &ctx->auth_context)))
	  goto fail;
      ctx->initiate = 1;
      ctx->gss_flags = KG_IMPLFLAGS(req_flags);
      ctx->seed_init = 0;
      ctx->big_endian = 0;  /* all initiators do little-endian, as per spec */
      ctx->seqstate = 0;
      ctx->gsskrb5_version = gsskrb5_vers;
      ctx->nctypes = 0;
      ctx->ctypes = 0;

      if ((code = krb5_timeofday(context, &now)))
	  goto fail;

      if (time_req == 0 || time_req == GSS_C_INDEFINITE) {
	 ctx->endtime = 0;
      } else {
	 ctx->endtime = now + time_req;
      }

      if ((code = krb5_copy_principal(context, cred->princ, &ctx->here)))
	  goto fail;
      
      if ((code = krb5_copy_principal(context, (krb5_principal) target_name,
				      &ctx->there)))
	  goto fail;

      if ((code = get_credentials(context, cred, ctx->there, now,
				       ctx->endtime, enctype, &k_cred)))
	  goto fail;

      /*
       * If the default mechanism was requested, and the keytype is
       * DES_CBC, force the old mechanism
       */
      if (default_mech &&
	  ((k_cred->keyblock.enctype == ENCTYPE_DES_CBC_CRC) ||
	   (k_cred->keyblock.enctype == ENCTYPE_DES_CBC_MD4) ||
	   (k_cred->keyblock.enctype == ENCTYPE_DES_CBC_MD5))) {
	 ctx->gsskrb5_version = gsskrb5_vers = 1000;
	 mech_type = gss_mech_krb5;
	 if (k_cred->keyblock.enctype != ENCTYPE_DES_CBC_CRC) {
	     krb5_free_creds(context, k_cred);
	     enctype = ENCTYPE_DES_CBC_CRC;
	     if ((code = get_credentials(context, cred, ctx->there, now,
					 ctx->endtime, enctype, &k_cred)))
		 goto fail;
         }
     }

      if (generic_gss_copy_oid(minor_status, mech_type, &ctx->mech_used)
	  != GSS_S_COMPLETE) {
	  code = *minor_status;
	  goto fail;
      }
      /*
       * Now try to make it static if at all possible....
       */
      ctx->mech_used = krb5_gss_convert_static_mech_oid(ctx->mech_used);

      if (ctx->gsskrb5_version == 2000) {
	  /* gsskrb5 v2 */
	  if ((code = make_ap_req_v2(context, ctx,
				     cred, k_cred, input_chan_bindings, 
				     mech_type, &token))) {
	      if ((code == KRB5_FCC_NOFILE) || (code == KRB5_CC_NOTFOUND) ||
		  (code == KG_EMPTY_CCACHE))
		  major_status = GSS_S_NO_CRED;
	      if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
		  major_status = GSS_S_CREDENTIALS_EXPIRED;
	      goto fail;
	  }

	  krb5_auth_con_getlocalseqnumber(context, ctx->auth_context,
					  &ctx->seq_send);
	  krb5_auth_con_getlocalsubkey(context, ctx->auth_context,
				       &ctx->subkey);
      } else {
	  /* gsskrb5 v1 */
	  if ((code = make_ap_req_v1(context, ctx,
				     cred, k_cred, input_chan_bindings, 
				     mech_type, &token))) {
	      if ((code == KRB5_FCC_NOFILE) || (code == KRB5_CC_NOTFOUND) ||
		  (code == KG_EMPTY_CCACHE))
		  major_status = GSS_S_NO_CRED;
	      if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
		  major_status = GSS_S_CREDENTIALS_EXPIRED;
	      goto fail;
	  }

	  krb5_auth_con_getlocalseqnumber(context, ctx->auth_context,
					  &ctx->seq_send);
	  krb5_auth_con_getlocalsubkey(context, ctx->auth_context,
				       &ctx->subkey);

	  /* fill in the encryption descriptors */

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
	      return GSS_S_FAILURE;
	  }

	  /* the encryption key is the session key XOR 0xf0f0f0f0f0f0f0f0 */

	  if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc)))
	      goto fail;

	  for (i=0; i<ctx->enc->length; i++)
	      /*SUPPRESS 113*/
	      ctx->enc->contents[i] ^= 0xf0;

	  if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->seq)))
	      goto fail;
      }

      if (k_cred) {
          krb5_free_creds(context, k_cred);
	  k_cred = 0;
      }
      
      /* at this point, the context is constructed and valid,
	 hence, releaseable */

      /* intern the context handle */

      if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
	  code = G_VALIDATE_FAILED;
	  goto fail;
      }
      *context_handle = (gss_ctx_id_t) ctx;
      ctx_free = 0;

      /* compute time_rec */
      if (time_rec) {
	 if ((code = krb5_timeofday(context, &now)))
	     goto fail;
	 *time_rec = ctx->endtime - now;
      }

      /* set the other returns */
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
      krb5_data ap_rep, mic;
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
	  code = KG_CONTEXT_ESTABLISHED;
	  goto fail;
      }

      if (! krb5_principal_compare(context, ctx->there, 
				   (krb5_principal) target_name)) {
	 (void)krb5_gss_delete_sec_context(minor_status, 
					   context_handle, NULL);
	 code = 0;
	 major_status = GSS_S_BAD_NAME;
	 goto fail;
      }

      /* verify the token and leave the AP_REP message in ap_rep */

      if (input_token == GSS_C_NO_BUFFER) {
	 (void)krb5_gss_delete_sec_context(minor_status, 
					   context_handle, NULL);
	 code = 0;
	 major_status = GSS_S_DEFECTIVE_TOKEN;
	 goto fail;
      }

      ptr = (unsigned char *) input_token->value;

      if (ctx->gsskrb5_version == 2000) {
	  int token_length;
	  int nctypes;
	  krb5_cksumtype *ctypes = 0;

	  /* gsskrb5 v2 */

	  if ((code = g_verify_token_header((gss_OID) ctx->mech_used,
					   &token_length,
					   &ptr, KG2_TOK_RESPONSE,
					   input_token->length))) {
	      major_status = GSS_S_DEFECTIVE_TOKEN;
	      goto fail;
	  }

	  if (GSS_ERROR(major_status =
			kg2_parse_token(minor_status, ptr, token_length,
					&resp_flags, &nctypes, &ctypes,
					0, NULL, &ap_rep, &mic))) {
	      if (ctypes)
		  free(ctypes);
	      code = *minor_status;
	      goto fail;
	  }
	  major_status = GSS_S_FAILURE;

	  kg2_intersect_ctypes(&ctx->nctypes, ctx->ctypes, nctypes, ctypes);

	  free(ctypes);

	  if (ctx->nctypes == 0) {
	      code = KG_NO_CTYPES;
	      goto fail;
	  }

	  if (resp_flags & KG2_RESP_FLAG_ERROR) {
	      if ((code = krb5_rd_error(context, &ap_rep, &krb_error)))
		  goto fail;

	      if (krb_error->error)
		  code = krb_error->error + ERROR_TABLE_BASE_krb5;
	      else
		  code = 0;

	      krb5_free_error(context, krb_error);
	      goto fail;
	  }

	  if (resp_flags & KG2_RESP_FLAG_DELEG_OK)
	      ctx->gss_flags |= GSS_C_DELEG_FLAG;

	  /* drop through to ap_rep handling */
      } else {
	  /* gsskrb5 v1 */

	  if ((err = g_verify_token_header((gss_OID) ctx->mech_used,
					   &(ap_rep.length),
					   &ptr, KG_TOK_CTX_AP_REP,
					   input_token->length))) {
	      if (g_verify_token_header((gss_OID) ctx->mech_used,
					&(ap_rep.length),
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
		  *minor_status = 0;
		  return(GSS_S_DEFECTIVE_TOKEN);
	      }
	  }

	  sptr = (char *) ptr;                      /* PC compiler bug */
	  TREAD_STR(sptr, ap_rep.data, ap_rep.length);
      }

      /* decode the ap_rep */
      if ((code = krb5_rd_rep(context, ctx->auth_context, &ap_rep,
			      &ap_rep_data))) {
	  /*
	   * XXX A hack for backwards compatiblity.
	   * To be removed in 1999 -- proven 
	   */
	  krb5_auth_con_setuseruserkey(context, ctx->auth_context,
				       ctx->subkey);
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

      if (ctx->gsskrb5_version == 2000) {
	  gss_buffer_desc mic_data, mic_token;

	  /* start with the token id */
	  mic_data.value = ptr-2;
	  /* end before the ap-rep length */
	  mic_data.length = ((char*)(ap_rep.data-2)-(char*)(ptr-2));

	  mic_token.length = mic.length;
	  mic_token.value = mic.data;

	  if (GSS_ERROR(major_status = 
			krb5_gss_verify_mic(minor_status, *context_handle,
					    &mic_data, &mic_token, NULL))) {
	      code = *minor_status;
	      goto fail;
	  }
	  major_status = GSS_S_FAILURE;
      }

      /* set returns */

      if (time_rec) {
	 if ((code = krb5_timeofday(context, &now)))
		 goto fail;
	 *time_rec = ctx->endtime - now;
      }

      if (ret_flags)
	 *ret_flags = ctx->gss_flags;

      if (actual_mech_type)
	 *actual_mech_type = mech_type;

      /* success */

      *minor_status = 0;
      /* fall through to GSS_S_COMPLETE */
   }

   return(GSS_S_COMPLETE);

fail:
   if (ctx_free) {
       if (ctx_free->auth_context)
	   krb5_auth_con_free(context, ctx_free->auth_context);
       if (ctx_free->here)
	   krb5_free_principal(context, ctx_free->here);
       if (ctx_free->there)
	   krb5_free_principal(context, ctx_free->there);
       if (ctx_free->subkey)
	   krb5_free_keyblock(context, ctx_free->subkey);
       if (ctx_free->ctypes)
	   krb5_free_cksumtypes(context, ctx_free->ctypes);
       xfree(ctx_free);
   } else
	(void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);

   *minor_status = code;
   return (major_status);
}

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

static krb5_error_code
make_priv_token_v2 PROTOTYPE((krb5_context context,
			      krb5_keyblock *subkey,
			      krb5_int32 *seqnum,
			      int direction,
			      gss_buffer_t text,
			      gss_buffer_t token,
			      gss_OID oid));

static krb5_error_code
make_priv_token_v2(context, subkey, seqnum, direction, text, token, oid)
     krb5_context context;
     krb5_keyblock *subkey;
     krb5_int32 *seqnum;
     int direction;
     gss_buffer_t text;
     gss_buffer_t token;
     gss_OID oid;
{
   krb5_data plain;
   krb5_enc_data cipher;
   krb5_error_code code;
   size_t enclen;
   int tlen;
   unsigned char *t, *ptr;

   plain.data = 0;
   cipher.ciphertext.data = 0;
   t = 0;

   plain.length = 7+text->length;
   if ((plain.data = (void *) malloc(plain.length)) == NULL) {
       code = ENOMEM;
       goto cleanup;
   }

   plain.data[0] = (*seqnum >> 24) & 0xff;
   plain.data[1] = (*seqnum >> 16) & 0xff;
   plain.data[2] = (*seqnum >> 8) & 0xff;
   plain.data[3] = *seqnum & 0xff;

   plain.data[4] = direction?0:0xff;
   
   plain.data[5] = (text->length >> 8) & 0xff;
   plain.data[6] = text->length & 0xff;

   memcpy(plain.data+7, text->value, text->length);

   if (code = krb5_c_encrypt_length(context, subkey->enctype, 
				    plain.length, &enclen))
       goto cleanup;

   tlen = g_token_size((gss_OID) oid, 2+enclen);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL)
      return(ENOMEM);

   ptr = t;

   g_make_token_header((gss_OID) oid, 2+enclen, &ptr,
		       KG2_TOK_WRAP_PRIV);

   ptr[0] = (enclen >> 8) & 0xff;
   ptr[1] = enclen & 0xff;

   cipher.ciphertext.length = enclen;
   cipher.ciphertext.data = ptr+2;

   if (code = krb5_c_encrypt(context, subkey,
			     KRB5_KEYUSAGE_GSS_TOK_WRAP_PRIV,
			     0, &plain, &cipher))
       goto cleanup;

   /* that's it.  return the token */

   (*seqnum)++;

   token->length = tlen;
   token->value = (void *) t;

   code = 0;

cleanup:
   if (plain.data)
       free(plain.data);
   if (code) {
       if (t)
	   free(t);
   }

   return(code);
}

static krb5_error_code
make_integ_token_v2 PROTOTYPE((krb5_context context,
			       krb5_keyblock *subkey,
			       krb5_cksumtype ctype,
			       krb5_int32 *seqnum,
			       int direction,
			       gss_buffer_t text,
			       gss_buffer_t token,
			       int toktype,
			       gss_OID oid));

static krb5_error_code
make_integ_token_v2(context, subkey, ctype, seqnum, direction, text, token, 
		    toktype, oid)
     krb5_context context;
     krb5_keyblock *subkey;
     krb5_cksumtype ctype;
     krb5_int32 *seqnum;
     int direction;
     gss_buffer_t text;
     gss_buffer_t token;
     int toktype;
     gss_OID oid;
{
    krb5_error_code code;
    int tmp, tlen;
    unsigned char *t, *ptr;
    krb5_data plain;
    krb5_checksum cksum;

    plain.data = 0;
    t = 0;
    cksum.contents = 0;

    /* assemble the checksum buffer and compute the checksum */

    plain.length = 7+text->length;

    if ((plain.data = (char *) malloc(plain.length)) == NULL)
	goto cleanup;

    plain.data[0] = (*seqnum >> 24) & 0xff;
    plain.data[1] = (*seqnum >> 16) & 0xff;
    plain.data[2] = (*seqnum >> 8) & 0xff;
    plain.data[3] = *seqnum & 0xff;

    plain.data[4] = direction?0:0xff;

    plain.data[5] = (text->length >> 8) & 0xff;
    plain.data[6] = text->length & 0xff;

    memcpy(plain.data+7, text->value, text->length);

    if (code = krb5_c_make_checksum(context, ctype, subkey,
				    (toktype == KG2_TOK_WRAP_INTEG)?
				    KRB5_KEYUSAGE_GSS_TOK_WRAP_INTEG:
				    KRB5_KEYUSAGE_GSS_TOK_MIC,
				    &plain, &cksum))
	goto cleanup;

    /* assemble the token itself */

    if (toktype == KG2_TOK_WRAP_INTEG)
	tmp = 4+(7+text->length)+2+cksum.length;
    else
	tmp = 4+(5)+2+cksum.length;

    tlen = g_token_size((gss_OID) oid, tmp);

    if ((t = (unsigned char *) xmalloc(tlen)) == NULL)
	return(ENOMEM);

    ptr = t;

    g_make_token_header((gss_OID) oid, tmp, &ptr, toktype);

    ptr[0] = (ctype >> 24) & 0xff;
    ptr[1] = (ctype >> 16) & 0xff;
    ptr[2] = (ctype >> 8) & 0xff;
    ptr[3] = ctype & 0xff;

    ptr += 4;

    if (toktype == KG2_TOK_WRAP_INTEG) {
	memcpy(ptr, plain.data, 7+text->length);
	ptr += 7+text->length;
    } else {
	memcpy(ptr, plain.data, 5);
	ptr += 5;
    }

    ptr[0] = (cksum.length >> 8) & 0xff;
    ptr[1] = cksum.length & 0xff;
    ptr += 2;

    memcpy(ptr, cksum.contents, cksum.length);

    /* that's it.  return the token */

    (*seqnum)++;

    token->length = tlen;
    token->value = (void *) t;

    code = 0;

cleanup:
    if (plain.data)
	free(plain.data);
    if (cksum.contents)
	krb5_free_checksum_contents(context, &cksum);
    if (code) {
	if (t)
	    free(t);
    }

   return(code);
}

static krb5_error_code
make_seal_token_v1 PROTOTYPE((krb5_context context,
			      krb5_keyblock *enc,
			      krb5_keyblock *seq,
			      krb5_int32 *seqnum,
			      int direction,
			      gss_buffer_t text,
			      gss_buffer_t token,
			      int signalg,
			      int cksum_size,
			      int sealalg,
			      int encrypt,
			      int toktype,
			      int bigend,
			      gss_OID oid));

static krb5_error_code
make_seal_token_v1(context, enc, seq, seqnum, direction, text, token,
		   signalg, cksum_size, sealalg, encrypt, toktype,
		   bigend, oid)
     krb5_context context;
     krb5_keyblock *enc;
     krb5_keyblock *seq;
     krb5_int32 *seqnum;
     int direction;
     gss_buffer_t text;
     gss_buffer_t token;
     int signalg;
     int cksum_size;
     int sealalg;
     int encrypt;
     int toktype;
     int bigend;
     gss_OID oid;
{
   krb5_error_code code;
   size_t sumlen;
   char *data_ptr;
   krb5_data plaind;
   krb5_checksum md5cksum;
   krb5_checksum cksum;
   int conflen=0, tmsglen, tlen;
   unsigned char *t, *ptr;

   /* create the token buffer */

   if (toktype == KG_TOK_SEAL_MSG) {
      if (bigend && !encrypt) {
	 tmsglen = text->length;
      } else {
	 conflen = kg_confounder_size(context, enc);
	 /* XXX knows that des block size is 8 */
	 tmsglen = (conflen+text->length+8)&(~7);
      }
   } else {
      tmsglen = 0;
   }

   tlen = g_token_size((gss_OID) oid, 14+cksum_size+tmsglen);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL)
      return(ENOMEM);

   /*** fill in the token */

   ptr = t;

   g_make_token_header((gss_OID) oid, 14+cksum_size+tmsglen, &ptr, toktype);

   /* 0..1 SIGN_ALG */

   ptr[0] = signalg;
   ptr[1] = 0;
   
   /* 2..3 SEAL_ALG or Filler */

   if ((toktype == KG_TOK_SEAL_MSG) && encrypt) {
      ptr[2] = sealalg;
      ptr[3] = 0;
   } else {
      /* No seal */
      ptr[2] = 0xff;
      ptr[3] = 0xff;
   }

   /* 4..5 Filler */

   ptr[4] = 0xff;
   ptr[5] = 0xff;

   /* pad the plaintext, encrypt if needed, and stick it in the token */

   /* initialize the the cksum */
   if (code = krb5_c_checksum_length(context, CKSUMTYPE_RSA_MD5, &sumlen))
       return(code);

   md5cksum.checksum_type = CKSUMTYPE_RSA_MD5;
   md5cksum.length = sumlen;
   if (toktype == KG_TOK_SEAL_MSG) {
      unsigned char *plain;
      unsigned char pad;

      if (!bigend || encrypt) {
	 if ((plain = (unsigned char *) xmalloc(tmsglen)) == NULL) {
	    xfree(t);
	    return(ENOMEM);
	 }

	 if ((code = kg_make_confounder(context, enc, plain))) {
	    xfree(plain);
	    xfree(t);
	    return(code);
	 }

	 memcpy(plain+conflen, text->value, text->length);

	 /* XXX 8 is DES cblock size */
	 pad = 8-(text->length%8);

	 memset(plain+conflen+text->length, pad, pad);
      } else {
	 /* plain is never used in the bigend && !encrypt case */
	 plain = NULL;
      }

      if (encrypt) {
	 if ((code = kg_encrypt(context, enc, NULL, (krb5_pointer) plain,
				(krb5_pointer) (ptr+cksum_size+14),
				tmsglen))) {
	    if (plain)
	       xfree(plain);
	    xfree(t);
	    return(code);
	 }
      } else {
	 if (bigend)
	    memcpy(ptr+14+cksum_size, text->value, text->length);
	 else
 	    memcpy(ptr+14+cksum_size, plain, tmsglen);
      }

      /* compute the checksum */

      /* 8 = head of token body as specified by mech spec */
      if (! (data_ptr =
	     (char *) xmalloc(8 + (bigend ? text->length : tmsglen)))) {
	  if (plain)
	      xfree(plain);
	  xfree(t);
	  return(ENOMEM);
      }
      (void) memcpy(data_ptr, ptr-2, 8);
      if (bigend)
	  (void) memcpy(data_ptr+8, text->value, text->length);
      else
	  (void) memcpy(data_ptr+8, plain, tmsglen);
      plaind.length = 8 + (bigend ? text->length : tmsglen);
      plaind.data = data_ptr;
      code = krb5_c_make_checksum(context, md5cksum.checksum_type,
				  0, 0, &plaind, &md5cksum);
      xfree(data_ptr);

      if (code) {
	  if (plain)
	      xfree(plain);
	  xfree(t);
	  return(code);
	  memcpy(ptr+14+cksum_size, plain, tmsglen);
      }

      if (plain)
	 xfree(plain);
   } else {
      /* compute the checksum */

      if (! (data_ptr = (char *) xmalloc(8 + text->length))) {
	  xfree(t);
	  return(ENOMEM);
      }
      (void) memcpy(data_ptr, ptr-2, 8);
      (void) memcpy(data_ptr+8, text->value, text->length);
      plaind.length = 8 + text->length;
      plaind.data = data_ptr;
      code = krb5_c_make_checksum(context, md5cksum.checksum_type, 0, 0,
				  &plaind, &md5cksum);
      xfree(data_ptr);
      if (code) {
	  xfree(t);
	  return(code);
      }
   }

   switch(signalg) {
   case 0:
   case 3:

#if 0
       /* XXX this depends on the key being a single-des key */

       /* DES CBC doesn't use a zero IV like it should in some
	  krb5 implementations (beta5+).  So we just do the
	  DES encryption the long way, and keep the last block
	  as the MAC */

       /* XXX not converted to new api since it's inside an #if 0 */

       /* initialize the the cksum and allocate the contents buffer */
       cksum.checksum_type = CKSUMTYPE_DESCBC;
       cksum.length = krb5_checksum_size(context, CKSUMTYPE_DESCBC);
       if ((cksum.contents = (krb5_octet *) xmalloc(cksum.length)) == NULL)
	   return(ENOMEM);

       /* XXX not converted to new api since it's inside an #if 0 */
       if (code = krb5_calculate_checksum(context, cksum.checksum_type,
					  md5cksum.contents, 16,
					  seq->contents, 
					  seq->length,
					  &cksum)) {
	  xfree(cksum.contents);
	  xfree(md5cksum.contents);
	  xfree(t);
	  return(code);
       }

       memcpy(ptr+14, cksum.contents, 8);

       xfree(cksum.contents);
#else
       if ((code = kg_encrypt(context, seq,
			      (g_OID_equal(oid, gss_mech_krb5_old) ?
			       seq->contents : NULL),
			      md5cksum.contents, md5cksum.contents, 16))) {
	  xfree(md5cksum.contents);
	  xfree(t);
	  return code;
       }
       
       cksum.length = cksum_size;
       cksum.contents = md5cksum.contents + 16 - cksum.length;

       memcpy(ptr+14, cksum.contents, cksum.length);
#endif

       break;
   }

   xfree(md5cksum.contents);

   /* create the seq_num */

   if ((code = kg_make_seq_num(context, seq, direction?0:0xff, *seqnum,
			       ptr+14, ptr+6))) {
      xfree(t);
      return(code);
   }

   /* that's it.  return the token */

   (*seqnum)++;

   token->length = tlen;
   token->value = (void *) t;

   return(0);
}

/* if signonly is true, ignore conf_req, conf_state, 
   and do not encode the ENC_TYPE, MSG_LENGTH, or MSG_TEXT fields */

OM_uint32
kg_seal(context, minor_status, context_handle, conf_req_flag, qop_req, 
	input_message_buffer, conf_state, output_message_buffer, toktype)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     int conf_req_flag;
     int qop_req;
     gss_buffer_t input_message_buffer;
     int *conf_state;
     gss_buffer_t output_message_buffer;
     int toktype;
{
   krb5_gss_ctx_id_rec *ctx;
   krb5_error_code code;
   krb5_timestamp now;

   output_message_buffer->length = 0;
   output_message_buffer->value = NULL;

   /* only default qop is allowed */
   if (qop_req != GSS_C_QOP_DEFAULT) {
      *minor_status = (OM_uint32) G_UNKNOWN_QOP;
      return(GSS_S_FAILURE);
   }

   /* validate the context handle */
   if (! kg_validate_ctx_id(context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (! ctx->established) {
      *minor_status = KG_CTX_INCOMPLETE;
      return(GSS_S_NO_CONTEXT);
   }

   if ((code = krb5_timeofday(context, &now))) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (ctx->gsskrb5_version == 2000) {
       if (toktype == KG_TOK_WRAP_MSG) {
	   if (conf_req_flag)
	       toktype = KG2_TOK_WRAP_PRIV;
	   else
	       toktype = KG2_TOK_WRAP_INTEG;
       } else {
	   toktype = KG2_TOK_MIC;
       }

       if (conf_req_flag) {
	   code = make_priv_token_v2(context, ctx->subkey, &ctx->seq_send,
				     ctx->initiate, input_message_buffer,
				     output_message_buffer, ctx->mech_used);
       } else {
	   code = make_integ_token_v2(context, ctx->subkey, ctx->ctypes[0],
				      &ctx->seq_send, ctx->initiate,
				      input_message_buffer,
				      output_message_buffer, toktype,
				      ctx->mech_used);
       }
   } else {
       code = make_seal_token_v1(context, ctx->enc, ctx->seq,
				 &ctx->seq_send, ctx->initiate,
				 input_message_buffer, output_message_buffer,
				 ctx->signalg, ctx->cksum_size, ctx->sealalg,
				 conf_req_flag, toktype, ctx->big_endian,
				 ctx->mech_used);
   }

   if (code) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (conf_state)
      *conf_state = conf_req_flag;

   *minor_status = 0;
   return((ctx->endtime < now)?GSS_S_CONTEXT_EXPIRED:GSS_S_COMPLETE);
}
